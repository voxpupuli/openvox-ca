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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"
)

// signCRLLocked re-signs the CRL with the given revoked entries, bumping the
// CRL number past prevNumber and stamping fresh ThisUpdate/NextUpdate. It
// writes the result to storage and refreshes the in-memory cache. The cluster
// CRL lock (lockNameCRL) and c.mu must both be held by the caller.
//
// This is the single point through which CRL re-signs are signalled to
// consumers via crlNotify/CRLUpdated(): the sole crlNotify send lives here. Any
// CRL write reachable while the server is serving must route through this
// function, or consumer wake-ups will be silently dropped. The direct
// Storage.UpdateCRL writes in init.go and caImport.go deliberately bypass it:
// they run at bootstrap/import before any consumer exists, and the exporter's
// startup reconcile covers that initial state.
func (c *CA) signCRLLocked(ctx context.Context, prev *storedCRL, revoked []x509.RevocationListEntry) error {
	// Refused rather than tolerated. A nil prev would leave the number at 1 and
	// the blob empty, so the write would regress the CRL number *and* drop every
	// ancestor -- the two failures this path exists to prevent, in one write. No
	// caller does it: all four take their storedCRL from readStoredCRL and return
	// on its error. The guard is here because the invariant used to be structural
	// -- the chain assembly fetched the blob itself -- and is now a caller
	// obligation the signature cannot express.
	if prev == nil {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("re-signing the CRL without a prior read: refusing to write a chain " +
			"that would drop every ancestor block")
	}
	nextNum := big.NewInt(1)
	prevBlob := prev.blob
	// A CRL of ours carrying no number is reachable -- openssl's V1 output cannot
	// carry one -- and the sequence then starts from 1 as it always has.
	if prev.own.Number != nil {
		nextNum.Add(prev.own.Number, big.NewInt(1))
	}

	now := time.Now()
	template := &x509.RevocationList{
		Number:                    nextNum,
		RevokedCertificateEntries: revoked,
		ThisUpdate:                now,
		NextUpdate:                now.Add(c.CRLValidityDuration()),
	}

	// Take a CA-key signing slot for the signature below. This queues rather
	// than sheds: a CRL that could not be re-signed is a revocation that did
	// not land, which is a correctness failure and not a load-shedding
	// opportunity. See signbound.go for why waiting here is bounded.
	if err := c.acquireSigningSlot(ctx); err != nil {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("waiting for a CA signing slot to re-sign the CRL: %w", err)
	}
	// Released by a deferred call inside this closure, not sequentially after
	// the signature: see releaseSigningSlot for why a panic here would
	// otherwise cost a live server a slot permanently. The closure keeps the
	// slot held for the signature alone — a function-scoped defer would hold it
	// across the storage write below, inflating occupancy far past the work the
	// bound exists to meter.
	crlBytes, err := func() ([]byte, error) {
		defer c.releaseSigningSlot()
		return x509.CreateRevocationList(rand.Reader, template, c.CACert, c.CAKey)
	}()
	if err != nil {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("failed to sign CRL: %w", err)
	}

	parsedCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("failed to parse new CRL: %w", err)
	}

	// Preserve any upstream CRLs already stored. Re-signing used to replace the
	// whole blob with a single block, which silently discarded the ancestor
	// CRLs an intermediate CA must publish for agents to do full-chain
	// revocation checking (Puppet's default). On a CA that issues its own root
	// there is nothing upstream and this is byte-for-byte what it was.
	newCRLPEM, err := c.crlChainLocked(ctx, parsedCRL, prevBlob)
	if err != nil {
		// A fault in the operator's crl_chain_file is counted by
		// crlChainFailures and not here, the same exemption RefreshCRLChainFile
		// makes. This path reaches the file too -- crlChainLocked calls
		// upstreamCRLs, which marks an unreadable, over-limit or regressing
		// file as errChainFileFault -- so without the exemption every revoke
		// and every reissue also moved crl_update_failures, the series that
		// means this CA cannot write its CRL. An operator would be paged
		// towards storage for a typo in a file, which is the confusion the two
		// separate series exist to prevent.
		if !errors.Is(err, errChainFileFault) {
			c.crlUpdateFailures.Add(1)
		}
		return err
	}
	if err := c.Storage.UpdateCRL(ctx, newCRLPEM); err != nil {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("failed to write CRL: %w", err)
	}

	// Update the in-memory CRL cache so auth checks use the new CRL
	// immediately without reading from storage. The cache holds only this CA's
	// own CRL: it answers "did we revoke this serial", which an ancestor's CRL
	// can never speak to.
	c.installCachedCRLLocked(parsedCRL)

	// Signal consumers (e.g. the Kubernetes exporter) that the CRL changed.
	// Non-blocking: a full buffer means a notification is already pending, and a
	// nil channel (CA built without New) is never ready — both fall through to
	// default so signing is never blocked. Holding c.mu here is fine; the send
	// does not contend on it.
	select {
	case c.crlNotify <- struct{}{}:
	default:
	}
	return nil
}

// installCachedCRLLocked makes next the CRL this process decides revocation
// from, and drops the pre-signed OCSP responses the outgoing one justified.
//
// Every write of c.cachedCRL goes through here, and that is the whole point.
// The two are a pair: the responder pre-signs a `good` for OCSPValidity — four
// hours — against the CRL current at the time, so any code that advances the
// CRL and forgets the cache leaves the responder affirmatively vouching for a
// certificate the CRL it is now enforcing says is revoked. Only two of the four
// install sites used to evict, and the ones that did not were reachable: a
// revocation performed on another replica reaches this one through the stored
// CRL, and whichever path installs it first wins — SyncCRLCache, which evicted,
// or the periodic re-sign in RefreshCRLIfDue, which did not. Losing that race
// left a stale `good` for the full four hours, because the sync that would have
// evicted then found the CRLs identical and returned early. Routing every
// install through one function is what makes the omission unrepeatable rather
// than merely fixed.
//
// c.mu must be held by the caller.
func (c *CA) installCachedCRLLocked(next *x509.RevocationList) {
	previous := c.cachedCRL
	c.cachedCRL = next
	c.invalidateOCSPForNewlyRevokedLocked(previous, next)
}

// invalidateOCSPForNewlyRevokedLocked drops the cached OCSP responses for
// serials that the newly installed CRL revokes and the previous one did not, so
// the responder stops handing out a pre-signed "good" for a certificate that
// has since been revoked. Without it the CRL would be current while OCSP kept
// answering from responses signed up to OCSPValidity ago.
//
// Only the newly revoked serials are dropped, mirroring what revokeSerialLocked
// does on the replica that performs a revocation. Clearing every revoked
// serial's entry instead would re-sign the whole revoked set on every
// revocation anywhere in the fleet.
//
// A nil previous means nothing was cached from it either — the startup installs
// run before the responder has answered anything — so the loop is a no-op there
// rather than a special case.
//
// c.mu must be held by the caller.
func (c *CA) invalidateOCSPForNewlyRevokedLocked(previous, current *x509.RevocationList) {
	was := make(map[string]struct{})
	if previous != nil {
		for _, entry := range previous.RevokedCertificateEntries {
			was[serialHexStr(entry.SerialNumber)] = struct{}{}
		}
	}
	for _, entry := range current.RevokedCertificateEntries {
		key := serialHexStr(entry.SerialNumber)
		if _, seen := was[key]; !seen {
			delete(c.ocspCache, key)
		}
	}
}

// newEmptyCRL signs a fresh, empty CRL for cert, valid for validity.
//
// Number 1 is correct because every caller has established that there is no CRL
// of ours to advance from — either storage is empty, or the imported chain
// carries only ancestors and nothing of ours was stored either. Re-signing an
// existing CRL goes through signCRLLocked, which bumps.
//
// validity is a parameter rather than c.crlValidity() because ImportCA has no CA
// instance at all: it works against storage directly, so there is no
// CRLValidityDays setting for it to honour, and it passes the package default.
// Bootstrap does have one and passes it.
func newEmptyCRL(cert *x509.Certificate, key crypto.Signer, validity time.Duration) (*x509.RevocationList, error) {
	now := time.Now().UTC()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(validity),
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, cert, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial CRL: %w", err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the generated CRL: %w", err)
	}
	return crl, nil
}

// withCRLLockCounted runs fn under the cluster CRL lock, counting a failure to
// take the lock at all.
//
// The lock arm was the one nobody counted. Every writer's own failures are
// counted beneath it -- readStoredCRL and signCRLLocked both increment
// crlUpdateFailures -- but if the lock cannot be taken, fn never runs, so
// nothing beneath it counts anything and the caller returns an error that only
// ever reached a log line. On etcd a lost session or an expired mu.Lock
// deadline produces exactly that, and on the SQL backends a failed advisory
// lock does; the CA's own CRL then runs to NextUpdate and is rejected
// fleet-wide with every series flat.
//
// crlUpdateFailures is the right counter by its own definition -- "a CRL that
// could not be re-signed, written or read, on any of the five paths that write
// one" -- and docs/metrics.md says so. Detecting the arm by whether fn ran,
// rather than by matching on the error, keeps this independent of how the
// storage layer words its wrapping.
func (c *CA) withCRLLockCounted(ctx context.Context, fn func() error) error {
	ran := false
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		ran = true
		return fn()
	})
	if err != nil && !ran {
		c.crlUpdateFailures.Add(1)
	}
	return err
}

// ReissueCRL re-signs the current CRL with a fresh validity window, preserving
// every existing revocation entry. It exists so the CRL can be kept current
// even when no certificates are being revoked: without periodic reissuance the
// CRL's NextUpdate eventually lapses and clients reject it as expired.
//
// It serialises on the cluster-wide CRL lock so it is safe to call from any
// replica (and concurrently with Revoke) against shared storage; the last
// writer under the lock wins and bumps the CRL number monotonically.
func (c *CA) ReissueCRL(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	return c.withCRLLockCounted(ctx, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.reissueCRLLocked(ctx)
	})
}

// reissueCRLLocked reads the stored CRL and re-signs it unchanged but for a
// bumped number and a fresh validity window. The cluster CRL lock and c.mu
// must both be held by the caller.
func (c *CA) reissueCRLLocked(ctx context.Context) error {
	stored, err := c.readStoredCRL(ctx)
	if err != nil {
		return err
	}
	return c.signCRLLocked(ctx, stored, stored.own.RevokedCertificateEntries)
}

// storedCRL is one read of the stored blob: block 0, parsed and confirmed to be
// ours, together with the bytes it came from.
//
// The blob is carried alongside because the re-sign needs both halves of the
// same read — the number and entries to carry forward, and the ancestor blocks
// to preserve. Fetching it twice was not merely a wasted round trip on an HA
// backend: the two reads could disagree, and the second one failing had its own
// error path, taken while the CRL lock was held and nothing had been written.
type storedCRL struct {
	own  *x509.RevocationList
	blob []byte
}

// readStoredCRL loads and parses the CRL currently in storage.
//
// Every caller goes on to re-sign and write, so a failure here is a failure to
// update the CRL and is counted as one. Counting it centrally rather than at
// each call site is what makes crl_update_failures cover every path that writes
// a CRL, as docs/metrics.md promises and the mixin's alert assumes. (Four call
// sites here, five write paths there: the two revoke entry points share one.)
// Three of them
// previously returned the error uncounted, so a replica that tripped this
// without revoking anything logged every tick while the counter stayed flat.
func (c *CA) readStoredCRL(ctx context.Context) (*storedCRL, error) {
	stored, err := c.parseStoredCRL(ctx)
	if err != nil {
		c.crlUpdateFailures.Add(1)
		return nil, err
	}
	return stored, nil
}

// ErrForeignStoredCRL reports that the stored CRL was not signed by the CA
// certificate this process loaded, so re-signing it would destroy a list this
// CA cannot reproduce.
//
// A sentinel because the condition is operator-fixable and the fix is not
// obvious from a status code: the HTTP layer turns it into a 409 carrying this
// message, rather than a bare 500 that leaves the diagnosis in the logs of
// whichever replica happened to serve the request.
var ErrForeignStoredCRL = errors.New("the stored CRL was not signed by the CA certificate this process is using")

// parseStoredCRL reads and parses block 0 of the stored CRL, and refuses when it
// is not one this CA signed. Split out only so readStoredCRL has a single error
// path to count; it has no other caller.
//
// Only block 0 is parsed here. The rest of the blob is decoded later, by
// crlChainLocked, and a corrupt ancestor there fails the re-sign — deliberately
// not this read, which several callers make before deciding whether a re-sign is
// needed at all.
func (c *CA) parseStoredCRL(ctx context.Context) (*storedCRL, error) {
	crlPEM, err := c.Storage.GetCRL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load CRL: %w", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CRL PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// SECURITY: refuse to re-sign over a CRL this CA did not issue. Every caller
	// of this function goes on to bump the CRL number and re-sign, so treating
	// an ancestor's CRL as our own would overwrite it and publish a chain
	// missing the entries agents need.
	//
	// The reachable cause is a CA certificate that was replaced while this
	// process was running: c.CACert is read once at startup and never reloaded,
	// so an unrestarted replica verifies against the previous certificate. The
	// error says so, because "CRL issuer mismatch" alone sends people looking at
	// the CRL rather than at the deployment. The key identifiers are reported as
	// a diagnostic aid, not as the test — see crlSignedBy.
	if !c.ownsCRL(crl) {
		return nil, fmt.Errorf("%w (CRL authority key id %x, our subject key id %x): refusing to re-sign it. "+
			"If the CA certificate was replaced, this replica needs a restart to pick it up",
			ErrForeignStoredCRL, crl.AuthorityKeyId, c.CACert.SubjectKeyId)
	}

	// Block 0 being ours is not the same as block 0 being our *newest*. A blob
	// holding a stale export ahead of the current one -- which the released
	// build's import stored verbatim -- passes the check above, and re-signing
	// from the stale block advances from its number (regressing the sequence) and
	// carries its entry list forward, while the chain assembly drops every block
	// of ours including the newer one. The newer revocations are then gone for
	// good.
	//
	// A blob that will not decode past block 0 keeps block 0, which is this
	// function's existing policy: the corrupt-ancestor failure belongs to the
	// chain assembly, after the callers that only wanted the staleness check have
	// had their answer.
	if newest, position, err := c.selectOwnCRL(crlPEM); err == nil && newest != nil && newerCRL(newest, crl) {
		slog.Warn("Stored CRL leads with a superseded copy of our own; re-signing from the newer block",
			"leading_crl_number", crl.Number, "using_crl_number", newest.Number, "position", position)
		crl = newest
	}
	return &storedCRL{own: crl, blob: crlPEM}, nil
}

// RefreshCRLIfDue re-signs the CRL only when its remaining validity has dropped
// below refreshBefore, and reports whether it re-signed. The check and the
// re-sign happen together under the cluster CRL lock, so when several replicas
// run this concurrently only the first re-signs (pushing NextUpdate far out)
// and the rest observe a fresh CRL and return (false, nil). This makes the
// background refresh job safe to run on any number of replicas sharing storage.
func (c *CA) RefreshCRLIfDue(ctx context.Context, refreshBefore time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	var reissued bool
	err := c.withCRLLockCounted(ctx, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()

		stored, err := c.readStoredCRL(ctx)
		if err != nil {
			return err
		}
		if time.Until(stored.own.NextUpdate) > refreshBefore {
			// Adopt the CRL another replica re-signed. Without this a replica
			// that never wins the re-sign race keeps the copy it cached at
			// startup, and once that window lapses everything reading the
			// cache — CRLSnapshot, and through it the service manager's status
			// text — reports a lapsed CRL indefinitely while storage holds a
			// fresh one. The parse is already paid for and c.mu is held, so
			// this costs only the comparison.
			if stored.own.Number != nil && (c.cachedCRL == nil || c.cachedCRL.Number == nil ||
				stored.own.Number.Cmp(c.cachedCRL.Number) > 0) {
				c.installCachedCRLLocked(stored.own)
			}
			return nil
		}
		if err := c.signCRLLocked(ctx, stored, stored.own.RevokedCertificateEntries); err != nil {
			return err
		}
		reissued = true
		return nil
	})
	return reissued, err
}

// CRLSnapshot describes the CRL the CA holds in memory. It is a value copy of
// the fields worth reporting, so a caller can inspect the CRL's freshness
// without holding a lock, touching storage, or being handed the live
// *x509.RevocationList the auth path reads.
type CRLSnapshot struct {
	// Number is the CRL number (RFC 5280 §5.2.3), which increases by one on
	// every re-sign.
	Number *big.Int
	// NextUpdate bounds the validity window of the CRL this process has cached.
	// Requests are answered from storage rather than from this cache, so a
	// NextUpdate in the past means this replica has not observed a re-sign
	// since the window lapsed — which RefreshCRLIfDue corrects on its next
	// pass. ThisUpdate is deliberately not carried: no caller needs it, and
	// the Prometheus collector reads its own copy straight from storage.
	NextUpdate time.Time
	// Revoked is the number of certificates listed on the CRL.
	Revoked int
}

// CRLSnapshot returns the in-memory CRL's metadata, and whether a CRL has been
// loaded at all. It reads the same cache the authentication path uses, so it
// costs a read lock and no storage round-trip — cheap enough to call on a
// timer (e.g. to refresh the service manager's status text).
func (c *CA) CRLSnapshot() (CRLSnapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cachedCRL == nil {
		return CRLSnapshot{}, false
	}
	snap := CRLSnapshot{
		NextUpdate: c.cachedCRL.NextUpdate,
		Revoked:    len(c.cachedCRL.RevokedCertificateEntries),
	}
	if c.cachedCRL.Number != nil {
		snap.Number = new(big.Int).Set(c.cachedCRL.Number)
	}
	return snap, true
}

// DefaultCRLRefreshBefore returns the default refresh window: the CRL is
// re-signed once less than a third of its validity remains (i.e. at ~2/3 of
// its lifetime), leaving ample margin to ride out replica outages before the
// CRL would lapse.
func (c *CA) DefaultCRLRefreshBefore() time.Duration {
	return c.CRLValidityDuration() / 3
}
