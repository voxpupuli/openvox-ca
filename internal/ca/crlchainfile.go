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
func (c *CA) upstreamCRLs(ctx context.Context) (crls []*x509.RevocationList, stated bool, err error) {
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
		return nil, false, fmt.Errorf("reading crl_chain_file %s: %w", c.CRLChainFile, err)
	}

	parsed, err := decodeCRLChain(data)
	if err != nil {
		return nil, false, fmt.Errorf("crl_chain_file %s: %w", c.CRLChainFile, err)
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
	return dedupeCRLs(verified, c.CRLChainFile), true, nil
}

// maxCRLChainFileBytes bounds the read. Every CRL that survives verification is
// appended to what agents fetch and to what the Kubernetes exporter writes into
// a Secret, and it is all held in memory while both the CRL lock and c.mu are
// held — so an oversized file is not merely a large allocation, it is a large
// allocation blocking every issuance and revocation in the fleet. A real chain
// is a handful of CRLs; 4 MiB is generous for that and still small enough that
// a truncated or wrongly-mounted file fails loudly instead of stalling.
const maxCRLChainFileBytes = 4 << 20

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

// dedupeCRLs keeps one CRL per issuer: the one with the highest CRL number.
//
// Publishing two lists for the same issuer is at best redundant and at worst
// misleading — a client that stops at the first match could be handed the older
// one, which is how a revocation gets un-revoked in the eyes of an agent. The
// case is not hypothetical: the refresh mechanisms this feature is designed
// around are file concatenation, and a CronJob that appends rather than replaces
// grows the chain by one stale copy per run.
//
// First-appearance order is preserved so that unchanged input keeps producing
// an unchanged chain, which is what sameCRLSet compares.
func dedupeCRLs(crls []*x509.RevocationList, path string) []*x509.RevocationList {
	out := make([]*x509.RevocationList, 0, len(crls))
	at := make(map[string]int, len(crls))
	for _, crl := range crls {
		issuer := string(crl.RawIssuer)
		i, seen := at[issuer]
		if !seen {
			at[issuer] = len(out)
			out = append(out, crl)
			continue
		}
		kept := out[i]
		if crl.Number != nil && kept.Number != nil && crl.Number.Cmp(kept.Number) > 0 {
			kept, out[i] = crl, crl
		}
		slog.Warn("Ignoring a duplicate CRL in crl_chain_file; keeping the one with the highest CRL number",
			"path", path, "issuer", crl.Issuer.String(), "kept", kept.Number)
	}
	return out
}

// signedByAny reports whether any candidate's key signed crl.
//
// A predicate rather than a lookup: the only question here is whether the
// bundle vouches for this CRL at all, and returning the certificate invited a
// caller to do something with an identity that the signature check has already
// finished establishing.
func signedByAny(candidates []*x509.Certificate, crl *x509.RevocationList) bool {
	for _, cert := range candidates {
		if crlSignedBy(cert, crl) {
			return true
		}
	}
	return false
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
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()

		wanted, stated, err := c.upstreamCRLs(ctx)
		if err != nil {
			return err
		}
		if !stated {
			// Nothing to reconcile against: an unreadable file is not a
			// statement that the published chain should be empty.
			return nil
		}

		current, err := c.Storage.GetCRL(ctx)
		if err != nil {
			return fmt.Errorf("reading the stored CRL: %w", err)
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

		slog.Info("Upstream CRLs changed; rewriting the published chain",
			"path", c.CRLChainFile, "stored", len(storedUpstream), "configured", len(wanted))
		rewritten = true

		// reissueCRLLocked reaches crlChainLocked, which reads the file again.
		// That second read is the one published, and it is the right one: it is
		// the freshest view, taken under the same lock. The decision above can
		// therefore be made on marginally older content than what lands, which
		// only ever means the rewrite carries a newer file than the one that
		// justified it.
		return c.reissueCRLLocked(ctx)
	})
	if err != nil {
		c.crlChainFailures.Add(1)
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
	for _, crl := range crls {
		if c.ownsCRL(crl) {
			continue
		}
		out = append(out, UpstreamCRLStatus{
			Issuer:     crl.Issuer.String(),
			NextUpdate: crl.NextUpdate,
		})
	}
	return out, nil
}
