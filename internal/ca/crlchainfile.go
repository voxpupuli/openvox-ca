// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"time"
)

// upstreamCRLs loads and verifies the CRLs in CRLChainFile.
//
// Whatever the file contains wins for non-self issuers, so the configuration is
// declarative: an operator refreshes the file by whatever mechanism they
// already have — a mounted Secret, a sidecar, a CronJob — and openvox-ca picks
// it up. Returning nil when no file is configured makes the whole feature a
// no-op for a self-signed root.
//
// SECURITY: every CRL is signature-verified against a certificate in the stored
// CA bundle before it is accepted, and discarded with a warning otherwise.
// openvox-ca serves this content verbatim to every agent, so an unverified file
// would be a way to inject arbitrary bytes into every agent's CRL store.
//
// Whether the check can succeed for a given CRL depends on the stored bundle
// holding that issuer's certificate, so publishing the root's CRL — the one an
// agent most needs for chain checking — requires the imported bundle to run all
// the way up to the root. Nothing enforces that yet, so a partial import shows
// up as CRLs discarded on every refresh, which crlChainDiscarded counts and the
// mixin alerts on.

// errChainFileFault marks an error as the operator's file being at fault, as
// opposed to the storage or locking beneath it. upstreamCRLs has already counted
// those on crlChainFailures, so RefreshCRLChainFile uses this to avoid counting
// the same failure again under a second, different meaning.
var errChainFileFault = errors.New("crl_chain_file fault")

// upstreamCRLs is the chokepoint both write paths call: it reads the operator's
// file, verifies every CRL in it against the stored CA bundle, deduplicates, and
// enforces monotonicity against what is already published. See the contract
// above.
//
// storedBlob is the published CRL blob when the caller already holds it, and nil
// when it does not. Passing it matters on the re-sign path: crlChainLocked is
// called under the cluster CRL lock with the blob readStoredCRL just read, so a
// nil here would send monotonicUpstream back to the backend for a byte-identical
// copy -- a second network round trip per revocation on the shared backends,
// taken while the lock that serialises revocation across every replica is held.
func (c *CA) upstreamCRLs(ctx context.Context, storedBlob []byte) (crls []*x509.RevocationList, stated bool, err error) {
	if c.CRLChainFile == "" {
		return nil, false, nil
	}

	// The path is the operator's own crl_chain_file setting. The content is
	// verified below regardless of where it came from.
	data, err := readCRLChainFile(c.CRLChainFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Absent is "no statement", not "publish nothing", and the
			// difference is everything: the file is authoritative, so treating
			// an absent one as an empty declaration writes a single block over
			// ancestor CRLs that are still there — permanently, because this CA
			// cannot re-sign another CA's list.
			//
			// It is reached far more often than a maintenance tick. This runs
			// under signCRLLocked, the single write path for every CRL
			// amendment, so one revocation on a replica whose Secret has not
			// mounted yet would truncate the chain for the whole fleet.
			//
			// A zero-byte file is a different thing entirely and is honoured:
			// that is how an operator says "publish nothing extra".
			slog.Warn("crl_chain_file does not exist; keeping the upstream CRLs already published",
				"path", c.CRLChainFile)
			return nil, false, nil
		}
		c.crlChainFailures.Add(1)
		return nil, false, fmt.Errorf("reading crl_chain_file %s: %w: %w",
			c.CRLChainFile, errChainFileFault, err)
	}

	// Stamped before verification: the question this answers is "did we read the
	// operator's file", not "did we like what was in it". A file full of CRLs we
	// discard is still a file we read, and the discard counter covers that.
	c.crlChainLastRead.Store(time.Now().Unix())

	parsed, err := decodeCRLChainStrict(data)
	if err != nil {
		c.crlChainFailures.Add(1)
		return nil, false, fmt.Errorf("crl_chain_file %s: %w: %w",
			c.CRLChainFile, errChainFileFault, err)
	}
	if len(parsed) > maxCRLChainFileEntries {
		c.crlChainFailures.Add(1)
		return nil, false, fmt.Errorf("crl_chain_file %s holds %d CRLs, more than the %d allowed: %w",
			c.CRLChainFile, len(parsed), maxCRLChainFileEntries, errChainFileFault)
	}

	issuers, err := c.bundleCertificates(ctx)
	if err != nil {
		return nil, false, err
	}

	verified := make([]*x509.RevocationList, 0, len(parsed))
	for _, crl := range parsed {
		if c.ownsCRL(crl) {
			// Ours is assembled from the inventory on every re-sign; taking it
			// from a file would let a stale copy supersede live revocations.
			slog.Warn("Ignoring a CRL in crl_chain_file that this CA issued; "+
				"its own CRL is always rebuilt from the inventory", "path", c.CRLChainFile)
			continue
		}
		if !signedByAny(issuers, crl) {
			// The chain shrinks silently here — the file is authoritative, so a
			// CRL this CA will not accept simply stops being published. Counted
			// as well as logged, because one warning per cycle is not something
			// an operator monitors.
			c.crlChainDiscarded.Add(1)
			slog.Warn("Discarding a CRL in crl_chain_file that no certificate in the CA bundle signed",
				"path", c.CRLChainFile, "issuer", crl.Issuer.String())
			continue
		}
		verified = append(verified, crl)
	}
	return c.monotonicUpstream(storedBlob, issuers, dedupeCRLs(issuers, verified, c.CRLChainFile))
}

// monotonicUpstream holds the one rule the file is not entitled to break: an
// ancestor's CRL may not move backwards.
//
// Everything reaching here is signature-valid, so an older CRL from the right
// issuer satisfies every check above -- and publishing it un-revokes, fleet-wide,
// every certificate that ancestor revoked in between. An ancestor's CRL number
// going backwards has no legitimate cause: it is a stale copy, a rolled-back
// mirror, or a replay.
//
// This lives here, in the function *both* writers call, rather than beside the
// refresh pass that first demonstrated the problem. When the check sat in
// RefreshCRLChainFile only, a rolled-back file was refused by the maintenance
// task -- loudly, with two alerts asserting the chain was protected -- and then
// published by the very next revocation, because Revoke reaches the file through
// crlChainLocked instead. The guard delayed the damage by at most one CRL
// refresh interval while reporting that it had prevented it.
//
// A regression is not a reason to fail the operation. A corrupt file is: nothing
// trustworthy is available, so refusing to publish half a chain is right, and
// blocking revocation is the price. A rollback is the opposite case -- the
// chain already published is correct -- so failing here would let anyone who can
// write the file deny revocation altogether. The published CRL is kept in place
// of the older one, counted, and the pass proceeds.
//
// c.mu must be held by the caller.
func (c *CA) monotonicUpstream(storedBlob []byte, issuers []*x509.Certificate,
	incoming []*x509.RevocationList) ([]*x509.RevocationList, bool, error) {

	published, err := c.publishedUpstream(storedBlob)
	if err != nil {
		return nil, false, err
	}
	if len(incoming) == 0 && len(published) > 0 {
		// The file is authoritative, so this is a legitimate thing for it to
		// say -- but it is also what a failed refresh produces. `cat a/*.pem >
		// bundle.pem` with an empty source directory truncates the destination
		// and writes nothing, and unlike a torn write that shape is stable, so
		// writing atomically does not prevent it. Say so at Error: the chain is
		// about to lose every ancestor, permanently, because this CA cannot
		// re-sign another CA's list.
		slog.Error("crl_chain_file declares no upstream CRLs while some are published; "+
			"dropping every ancestor CRL. If this was not deliberate, check that "+
			"whatever writes the file did not produce an empty one",
			"path", c.CRLChainFile, "dropping", len(published))
		// Each dropped ancestor is also reported and counted individually below;
		// this line survives because it names a cause -- an empty write -- that
		// the per-ancestor message cannot.
	}
	if len(published) == 0 {
		return incoming, true, nil
	}

	// Keyed on the signing certificate, not the issuer DN. See signerOf.
	//
	// Keeping the *newest* per ancestor rather than the last one encountered,
	// via the same helper dedupeCRLs uses. The published side can legitimately
	// carry two CRLs from one ancestor: orderCRLChain collapses duplicates of
	// this CA's own CRL only, and warnAboutAncestors warns about ancestor
	// duplicates while publishing "all of them as supplied". Taking whichever
	// came last in stored order made the comparison depend on how the operator
	// happened to concatenate their import -- so a stored [A#9, A#5] compared an
	// incoming A#7 against A#5, called it newer, and published the rollback.
	current := make(map[string]*x509.RevocationList, len(published))
	for _, crl := range published {
		signer := signerOf(issuers, crl)
		if signer == nil {
			continue
		}
		if prev, ok := current[string(signer.Raw)]; !ok || newerCRL(crl, prev) {
			current[string(signer.Raw)] = crl
		}
	}

	// mentioned records which published ancestors the file still lists, so the
	// ones it has stopped listing can be reported below.
	mentioned := make(map[string]bool, len(incoming))
	out := make([]*x509.RevocationList, 0, len(incoming))
	for _, crl := range incoming {
		signer := signerOf(issuers, crl)
		if signer == nil {
			// Unreachable: upstreamCRLs filters with signedByAny against this
			// same bundle before calling in. Dropping rather than publishing
			// anyway, because if that ever stops being true the wrong direction
			// to fail is "serve unattributable bytes to every agent".
			continue
		}
		mentioned[string(signer.Raw)] = true
		prev, ok := current[string(signer.Raw)]
		// Equal is the steady state between refreshes, and is not a regression.
		if !ok || !newerCRL(prev, crl) {
			out = append(out, crl)
			continue
		}
		c.crlChainRegressed.Add(1)
		slog.Error("crl_chain_file carries an upstream CRL older than the one already "+
			"published; keeping the published one",
			"path", c.CRLChainFile, "issuer", crl.Issuer.String())
		out = append(out, prev)
	}

	// Report published ancestors that are about to disappear: the ones the file
	// has stopped listing, and the ones whose signer has left the bundle.
	// Iterating published rather than the map so the order is the stored chain's
	// rather than Go's map randomisation; mentioned doubles as the seen-set so
	// each is named once.
	unattributable := make(map[string]bool)
	for _, crl := range published {
		signer := signerOf(issuers, crl)
		if signer == nil {
			// Published, but nothing in the CA bundle signs it any more -- an
			// ancestor's certificate dropped from the bundle, or a partial
			// re-import. It is about to disappear from the published chain
			// exactly as a removed one does, so it is counted the same way
			// rather than vanishing with only this line to show for it. Keyed
			// on the DN because there is no signer to key on.
			if unattributable[crl.Issuer.String()] {
				continue
			}
			unattributable[crl.Issuer.String()] = true
			c.crlChainRemoved.Add(1)
			slog.Error("A published upstream CRL is signed by no certificate in the stored "+
				"CA bundle and is being dropped; re-import the bundle with that ancestor's "+
				"certificate to keep publishing its CRL",
				"path", c.CRLChainFile, "issuer", crl.Issuer.String())
			continue
		}
		if mentioned[string(signer.Raw)] {
			continue
		}
		mentioned[string(signer.Raw)] = true
		c.crlChainRemoved.Add(1)
		slog.Error("crl_chain_file no longer lists an ancestor whose CRL is published; "+
			"dropping it. The file is authoritative, so this is honoured -- but it "+
			"cannot be undone here, because this CA cannot re-sign another CA's list",
			"path", c.CRLChainFile, "issuer", crl.Issuer.String())
	}
	return out, true, nil
}

// publishedUpstream returns the upstream CRLs in the stored chain -- every block
// this CA did not issue.
//
// blob is the stored chain the caller has already read, under the same cluster
// CRL lock this runs beneath. It is a parameter rather than a read of its own
// because both callers already hold those bytes: re-reading cost a second
// backend round trip per revocation, held while the lock that serialises
// revocation across every replica was taken.
//
// A nil blob is refused rather than read or treated as an empty set. Nothing is
// published when a caller has no bytes to offer, and "nothing published" is
// indistinguishable from "nothing could be read" once it reaches here -- which
// would disable the monotonicity check exactly when storage is unhealthy, the
// moment a stale file is most likely to be in play. An empty non-nil blob is a
// genuine "nothing published yet" and decodes to no CRLs.
//
// c.mu must be held by the caller.
func (c *CA) publishedUpstream(blob []byte) ([]*x509.RevocationList, error) {
	if blob == nil {
		return nil, errors.New("checking for CRL chain regressions: the published chain was not read")
	}
	stored, err := decodeCRLChain(blob)
	if err != nil {
		return nil, fmt.Errorf("decoding the published CRL chain: %w", err)
	}
	var upstream []*x509.RevocationList
	for _, crl := range stored {
		if !c.ownsCRL(crl) {
			upstream = append(upstream, crl)
		}
	}
	return upstream, nil
}

// maxCRLChainFileBytes bounds the read. Every CRL that survives verification is
// appended to what agents fetch and to what the Kubernetes exporter writes into
// a Secret, and it is all held in memory while both the CRL lock and c.mu are
// held — so an oversized file is not merely a large allocation, it is a large
// allocation blocking every issuance and revocation in the fleet. A real chain
// is a handful of CRLs; 4 MiB is generous for that and still small enough that
// a truncated or wrongly-mounted file fails loudly instead of stalling.
const maxCRLChainFileBytes = 4 << 20

// maxCRLChainFileEntries bounds how many CRLs the file may hold. The byte bound
// alone does not: one ancestor with a long revocation list is legitimately large
// and few, while a file of many small CRLs is what costs. Each entry has its
// signer resolved by trial verification against every certificate in the stored
// bundle, several times per evaluation (deduplication, the monotonicity check,
// and the published-side comparison), and that work runs with both the CRL lock
// and c.mu held -- so it is paid by every issuance and revocation in the fleet,
// not just by the hourly pass.
//
// A chain is one CRL per ancestor, so anything past a couple of dozen is a
// mistake rather than a deployment: a directory concatenated by accident, or a
// file appended to instead of replaced. Refusing it leaves the published chain
// as it was, which is the same fail-closed outcome as any other unusable file.
const maxCRLChainFileEntries = 64

// readCRLChainFile reads at most maxCRLChainFileBytes, and refuses a file that
// exceeds it rather than silently truncating: a half-read PEM blob would drop
// upstream CRLs with no error, which is precisely the failure mode the absent
// file case exists to prevent.
func readCRLChainFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxCRLChainFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCRLChainFileBytes {
		return nil, fmt.Errorf("crl_chain_file is larger than %d bytes", maxCRLChainFileBytes)
	}
	return data, nil
}

// dedupeCRLs keeps one CRL per ancestor: the newest, by newerCRL.
//
// Publishing two lists for the same ancestor is at best redundant and at worst
// misleading — a client that stops at the first match could be handed the older
// one, which is how a revocation gets un-revoked in the eyes of an agent. The
// case is not hypothetical: the refresh mechanisms this feature is designed
// around are file concatenation, and a CronJob that appends rather than replaces
// grows the chain by one stale copy per run.
//
// Ancestors are told apart by their signing certificate, not by issuer
// distinguished name. crlSignedBy's comment sets out why: a shared root can
// issue two sub-CAs carrying the same DN, and DN-keyed grouping would then treat
// two genuinely different ancestors as duplicates and publish only one of them —
// silently dropping a live upstream CRL. A CRL nothing in the bundle signed is
// left alone; it cannot reach here anyway, since signedByAny filters first.
//
// The comparison is newerCRL rather than an inline CRL-number check so that this
// and monotonicUpstream cannot drift apart, and so that a CRL without a
// cRLNumber falls back to ThisUpdate instead of silently keeping whichever copy
// happened to come first. `openssl ca -gencrl` omits cRLNumber unless
// crl_extensions is configured, which the stock openssl.cnf leaves commented
// out, so number-less ancestor CRLs are not exotic in this feature's audience.
//
// First-appearance order is preserved so that unchanged input keeps producing
// an unchanged chain, which is what sameCRLSet compares.
func dedupeCRLs(issuers []*x509.Certificate, crls []*x509.RevocationList,
	path string) []*x509.RevocationList {

	out := make([]*x509.RevocationList, 0, len(crls))
	at := make(map[string]int, len(crls))
	for _, crl := range crls {
		signer := signerOf(issuers, crl)
		if signer == nil {
			out = append(out, crl)
			continue
		}
		i, seen := at[string(signer.Raw)]
		if !seen {
			at[string(signer.Raw)] = len(out)
			out = append(out, crl)
			continue
		}
		kept := out[i]
		if newerCRL(crl, kept) {
			kept, out[i] = crl, crl
		}
		slog.Warn("Ignoring a duplicate CRL in crl_chain_file; keeping the newest",
			"path", path, "issuer", crl.Issuer.String(), "kept", kept.Number)
	}
	return out
}

// signedByAny reports whether any candidate's key signed crl. Most callers want
// this rather than signerOf: the usual question is whether the bundle vouches
// for this CRL at all.
func signedByAny(candidates []*x509.Certificate, crl *x509.RevocationList) bool {
	return signerOf(candidates, crl) != nil
}

// signerOf returns the certificate whose key signed crl, or nil.
//
// This was deliberately a predicate at first, on the grounds that returning the
// certificate invited a caller to do something with an identity the signature
// check had already finished establishing. monotonicUpstream is the caller that
// legitimately needs it: to ask whether an incoming CRL is older than the
// published one, it must first decide which published CRL is the *same
// ancestor's*, and that is a question about identity rather than validity.
//
// It must be answered this way and not by comparing issuer distinguished names.
// crlSignedBy's comment sets out why: a shared root can issue two sub-CAs
// carrying the same DN, so DN-keyed pairing can compare one ancestor's CRL
// against another's -- destroying a live upstream CRL, or wedging a legitimate
// one, while appearing to work.
func signerOf(candidates []*x509.Certificate, crl *x509.RevocationList) *x509.Certificate {
	for _, cert := range candidates {
		if crlSignedBy(cert, crl) {
			return cert
		}
	}
	return nil
}

// bundleCertificates parses the stored CA certificate bundle.
func (c *CA) bundleCertificates(ctx context.Context) ([]*x509.Certificate, error) {
	bundlePEM, err := c.Storage.GetCACert(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the CA bundle to verify crl_chain_file: %w", err)
	}
	var certs []*x509.Certificate
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d in the stored CA bundle: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("the stored CA bundle contains no certificates")
	}
	return certs, nil
}

// RefreshCRLChainFile re-reads crl_chain_file and, when its contents differ
// from what is stored, rewrites the CRL so the change reaches agents.
//
// Reading the file into memory would change nothing an agent can see:
// handleGetCRL serves Storage.GetCRL verbatim. So a detected change goes
// through the ordinary re-sign path — CRL lock, then c.mu, then signCRLLocked,
// the order ReissueCRL already uses — which reassembles the chain, persists it,
// refreshes the cache, fires the notification and wakes the exporter, all for
// free.
//
// One consequence, accepted deliberately: this bumps our own CRL number even
// though our revocation set is unchanged. The number need only increase, so it
// is harmless, and it is the price of having one write path rather than a
// second subtler one.
//
// Returns whether a rewrite happened.
func (c *CA) RefreshCRLChainFile(ctx context.Context) (bool, error) {
	if c.CRLChainFile == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	// The comparison runs *inside* the CRL lock, not before it. Deciding
	// outside meant every replica that noticed the same change re-signed: each
	// compared against the pre-change chain, each took the lock in turn, and
	// each wrote — one refresh producing as many CRL numbers, exporter
	// wake-ups and inventory-free re-signs as there are replicas. Inside the
	// lock, the first writer's result is what the rest compare against, so they
	// see their work already done and stop.
	rewritten := false
	countedByCRLLayer := false
	// No crlChainFailures.Add here. It is counted inside upstreamCRLs, where the
	// file is what failed, so both writers count it -- this pass and every
	// revocation through crlChainLocked. Counting it here instead gave the
	// counter the shape monotonicUpstream itself once had: present on the
	// maintenance path, absent on the path that runs far more often. It also
	// attributed this closure's *other* failures -- a lock timeout, a storage
	// read, a re-sign -- to the chain file, so a storage outage paged someone to
	// go and inspect a perfectly healthy file. See readStoredCRL's comment in
	// crl.go for the same argument made about crl_update_failures.
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()

		// One read of the stored chain serves both the regression check inside
		// upstreamCRLs and the comparison below.
		current, err := c.Storage.GetCRL(ctx)
		if err != nil {
			return fmt.Errorf("reading the stored CRL: %w", err)
		}

		wanted, stated, err := c.upstreamCRLs(ctx, current)
		if err != nil {
			return err
		}
		if !stated {
			// Nothing to reconcile against: an unreadable file is not a
			// statement that the published chain should be empty.
			return nil
		}

		stored, err := decodeCRLChain(current)
		if err != nil {
			return fmt.Errorf("decoding the stored CRL chain: %w", err)
		}

		var storedUpstream []*x509.RevocationList
		for _, crl := range stored {
			if !c.ownsCRL(crl) {
				storedUpstream = append(storedUpstream, crl)
			}
		}
		if sameCRLSet(storedUpstream, wanted) {
			return nil
		}
		// No regression check here. monotonicUpstream has already made it, inside
		// upstreamCRLs, so `wanted` cannot carry a CRL older than the published
		// one -- which is why sameCRLSet above returns true for a rolled-back
		// file and this pass does nothing. Checking again here would be the
		// arrangement this replaced: a rule enforced beside the refresh pass
		// that demonstrated it rather than at the chokepoint every writer uses,
		// so a revocation walked straight past it.
		slog.Info("Upstream CRLs changed; rewriting the published chain",
			"path", c.CRLChainFile, "stored", len(storedUpstream), "configured", len(wanted))
		rewritten = true

		// reissueCRLLocked reaches crlChainLocked, which reads the file again.
		// That second read is the one published, and it is the right one: it is
		// the freshest view, taken under the same lock, and it goes through
		// upstreamCRLs like every other read, so monotonicUpstream applies to it
		// too. The decision above can therefore be made on marginally older
		// content than what lands without the ordering guarantee depending on
		// the two reads agreeing.
		if err := c.reissueCRLLocked(ctx); err != nil {
			// Counted by signCRLLocked already; say so, so the caller does not
			// count it a second time under a different meaning.
			countedByCRLLayer = true
			return err
		}
		return nil
	})
	if err != nil {
		// Every arm above other than the file itself -- a lock this pass could
		// not take, a bundle it could not parse, a published chain it could not
		// read -- stopped the CRL being amended, which is what crlUpdateFailures
		// means and what its own field comment already claims to cover ("during
		// revoke, cleanup, reissue or refresh").
		//
		// Without this they were counted by nothing at all: moving
		// crlChainFailures to the chokepoint correctly stopped it absorbing them,
		// but nothing picked them up, so a quiet CA with wedged storage failed
		// its hourly refresh behind a log line while every series read healthy
		// until the ancestors expired a fortnight later. The two sibling
		// maintenance tasks count their own failures for the same reason.
		if !errors.Is(err, errChainFileFault) && !countedByCRLLayer {
			c.crlUpdateFailures.Add(1)
		}
		return false, err
	}
	return rewritten, nil
}

// sameCRLSet reports whether two CRL lists are byte-identical in order.
func sameCRLSet(a, b []*x509.RevocationList) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Raw, b[i].Raw) {
			return false
		}
	}
	return true
}

// UpstreamCRLStatus describes one upstream CRL for metrics reporting.
type UpstreamCRLStatus struct {
	// Issuer is the CRL issuer's distinguished name, used as a metric label.
	Issuer string
	// NextUpdate is when the CRL expires.
	NextUpdate time.Time
}

// UpstreamCRLStatuses reports the non-self CRLs in blob, for the per-issuer
// freshness metric.
//
// Deliberately separate from the existing unlabelled
// puppetca_crl_next_update_timestamp_seconds, which keeps meaning exactly what
// it means today: *this CA's own* CRL. Adding an issuer label to that series
// would multiply it and make the two shipped expiry alerts fire for upstream
// CRLs this CA cannot reissue — a real page with a wrong runbook, since the
// remedy is at the parent.
//
// One status per issuer distinguished name, carrying the *nearest* real
// NextUpdate when a DN appears more than once. The rest of this file pairs CRLs by signing
// certificate precisely because a DN does not identify an ancestor, and two
// ancestors sharing a DN are published as separate blocks -- but the metric has
// only the DN to label with, so two statuses for one DN would be two samples
// with identical label sets. prometheus.Registry.Gather rejects the second and
// records an error on every scrape, leaving the shadowed ancestor with no expiry
// series at all and PuppetCAUpstreamCRLExpired unable to fire for it. Reporting
// the nearest deadline collapses them without hiding anything: the alert exists
// to catch the ancestor closest to lapsing, and that is the one it now reports.
//
// A zero NextUpdate never wins that comparison. nextUpdate is OPTIONAL in RFC
// 5280's ASN.1, so a non-conforming ancestor parses with a zero time, and the
// collector renders that as 0 -- which the expiry alert reads as "expired in
// 1970". Letting it win would hide a real deadline behind an unusable one for
// every ancestor sharing the DN. A DN whose only CRL is zero still reports 0,
// which is the honest answer: nothing about that CRL says when it goes stale,
// and treating it as fresh would be the worse guess.
//
// blob is the stored CRL the caller has already read. Taking it as a parameter
// rather than re-reading keeps the collector's "parse the CRL once" rule true:
// it holds the bytes and has already decoded block 0, so a second read and a
// second decode of the same blob would be doing the work twice per scrape and
// could disagree with the numbers reported beside it.
func (c *CA) UpstreamCRLStatuses(blob []byte) ([]UpstreamCRLStatus, error) {
	crls, err := decodeCRLChain(blob)
	if err != nil {
		return nil, err
	}
	var out []UpstreamCRLStatus
	seen := make(map[string]int, len(crls))
	for _, crl := range crls {
		if c.ownsCRL(crl) {
			continue
		}
		issuer := crl.Issuer.String()
		if i, ok := seen[issuer]; ok {
			if crl.NextUpdate.IsZero() {
				continue
			}
			if out[i].NextUpdate.IsZero() || crl.NextUpdate.Before(out[i].NextUpdate) {
				out[i].NextUpdate = crl.NextUpdate
			}
			continue
		}
		seen[issuer] = len(out)
		out = append(out, UpstreamCRLStatus{
			Issuer:     issuer,
			NextUpdate: crl.NextUpdate,
		})
	}
	return out, nil
}
