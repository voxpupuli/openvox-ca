// Copyright (C) 2026 Trevor Vaughan
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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ErrInternal marks a server-side failure in AnswerOCSP (and so in
// OCSPResponse, which wraps it). The HTTP handler uses it to write an OCSP
// InternalError response instead of MalformedRequest, which matters because
// MalformedRequest tells a verifier its request was at fault and not to retry.
//
// Two kinds of failure carry it, and they are not the same kind: the status
// could not be determined (a CRL read error), or the status was determined and
// the response could not be produced (the CA signature failed). The second is
// the one an external signer makes reachable under load.
var ErrInternal = errors.New("internal CA error")

// OCSPValidity is the NextUpdate window written into a definite OCSP response —
// a good or a revoked. Those are pre-signed and cached for this duration, and a
// GET carries a matching Cache-Control: max-age for downstream HTTP caches.
//
// An unknown gets neither: see AnswerOCSP for why a status that a later
// inventory read can overturn must not be given a four-hour licence to be
// replayed.
const OCSPValidity = 4 * time.Hour

// ocspCacheEntry holds a pre-signed OCSP response DER and its expiry.
type ocspCacheEntry struct {
	der       []byte
	expiresAt time.Time
}

// oidNonce is the OCSP nonce extension OID (RFC 8954 §2).
var oidNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

// maxNonceLen is the maximum allowed OCSP nonce extension Value size in bytes.
// RFC 8954 §2.1 recommends 1-32 bytes for the nonce value. We allow up to 34
// bytes in the DER-encoded Value field to account for the OCTET STRING header
// (tag + length bytes wrapping the actual nonce).
const maxNonceLen = 34

// ocspTBSReqWithExts mirrors the TBSRequest ASN.1 structure including the
// optional requestExtensions field (tag 2) not exposed by x/crypto/ocsp.
type ocspTBSReqWithExts struct {
	Version       int              `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName asn1.RawValue    `asn1:"explicit,tag:1,optional"`
	RequestList   asn1.RawValue    // SEQUENCE OF Request (opaque)
	Extensions    []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type ocspReqWithExts struct {
	TBSRequest ocspTBSReqWithExts
}

// extractNonce parses the raw DER-encoded OCSPRequest and returns the nonce
// extension (OID 1.3.6.1.5.5.7.48.1.2) if present in requestExtensions.
func extractNonce(reqDER []byte) (pkix.Extension, bool) {
	var req ocspReqWithExts
	if _, err := asn1.Unmarshal(reqDER, &req); err != nil {
		return pkix.Extension{}, false
	}
	for _, ext := range req.TBSRequest.Extensions {
		if ext.Id.Equal(oidNonce) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}

// buildSerialIndex populates c.serialIndex from the stored inventory,
// discarding whatever the index held before.
//
// Only startup calls this. Once the CA is serving, the index is reconciled by
// SyncSerialIndex instead, which keeps in-process additions a concurrent
// issuance may have made while it was reading. It must be called while c.mu is
// already held by the caller.
func (c *CA) buildSerialIndex(ctx context.Context) error {
	index, err := c.readSerialIndex(ctx)
	if err != nil {
		return err
	}
	c.serialIndex = index
	return nil
}

// readSerialIndex reads the stored inventory into a serial → subject map.
// Serials are normalised to uppercase hex without leading zeros (via
// serialHexStr) so that lookups are consistent regardless of whether the
// inventory was written by this version (random serials) or an older version
// (zero-padded sequential serials).
//
// It goes through InventoryEntries rather than ReadInventory because this runs
// on a timer. ReadInventory verifies and then fetches, and its verification
// recomputes from storage, so every call materialises the whole inventory
// twice — on both backend families, not only the structured ones, so which
// side of that line a given backend sits on does not change the answer.
// InventoryEntries fetches once and folds the integrity value over what it
// holds, so the check is still made everywhere.
//
// It touches no CA state, so it may be called without c.mu held — which
// SyncSerialIndex does, to keep a storage round-trip off the auth path.
func (c *CA) readSerialIndex(ctx context.Context) (map[string]string, error) {
	entries, err := c.Storage.InventoryEntries(ctx)
	if err != nil {
		return nil, err
	}

	index := make(map[string]string, len(entries))
	for _, e := range entries {
		n := new(big.Int)
		if _, ok := n.SetString(e.Serial, 16); !ok {
			slog.Warn("readSerialIndex: skipping malformed serial in inventory",
				"serial", e.Serial, "subject", e.Subject)
			continue
		}
		index[serialHexStr(n)] = e.Subject
	}
	return index, nil
}

// indexSerialLocked records that this process issued serial for subject, and
// counts the mutation so a SyncSerialIndex whose storage read overlapped it can
// tell. Going through a helper rather than assigning the map directly is what
// makes that counter impossible to forget at a new issuance site. c.mu must be
// held by the caller.
func (c *CA) indexSerialLocked(serial, subject string) {
	c.serialIndex[serial] = subject
	c.serialIndexEpoch++
}

// unindexSerialLocked drops serial from the index and from the OCSP response
// cache, for a certificate this process has just pruned. The twin of
// indexSerialLocked; see it for why the epoch matters. c.mu must be held by the
// caller.
func (c *CA) unindexSerialLocked(serial string) {
	c.dropSerialLocked(serial)
	c.serialIndexEpoch++
}

// dropSerialLocked forgets a serial: out of the index, and out of the response
// cache with it, because a pre-signed answer derived from an index entry must
// not outlive it.
//
// Shared with the sync's removal half, and the two counters part company here.
// serialIndexRemovalEpoch is bumped for every removal, whoever made it, because
// its question is "has anything left the index since you read storage" and a
// sync removal answers yes as much as a prune does. serialIndexEpoch is bumped
// only by unindexSerialLocked, because its question is "has this process issued
// or pruned", and a pass reconciling with storage has done neither.
//
// Keeping the pair of deletes in one place is the same argument
// installCachedCRLLocked makes about CRL installs: a third thing to forget
// later should only have to be added here. c.mu must be held by the caller.
func (c *CA) dropSerialLocked(serial string) {
	delete(c.serialIndex, serial)
	delete(c.ocspCache, serial)
	// Every removal counts, whoever made it. A reconcile whose storage read
	// predates this one must not re-add what just left, and this is the one
	// place all removals pass through — which is why the counter lives here
	// rather than at the two call sites.
	c.serialIndexRemovalEpoch++
}

// OCSPResponse builds a DER-encoded OCSPResponse for the given DER-encoded
// OCSPRequest. The CA key signs the response directly (RFC 6960 §2.6).
//
// Responses are cached by serial for OCSPValidity; the cache is bypassed when
// a nonce is present in the request (RFC 8954). The caller must NOT hold c.mu.
//
// Callers that hand the answer to an HTTP cache want AnswerOCSP instead, which
// carries how long it may be reused. This form is kept because most callers —
// the specs, and anything that only wants the bytes — do not.
func (c *CA) OCSPResponse(ctx context.Context, reqDER []byte) ([]byte, error) {
	answer, err := c.AnswerOCSP(ctx, reqDER)
	if err != nil {
		return nil, err
	}
	return answer.DER, nil
}

// OCSPAnswer is a signed OCSP response together with how long a cache may reuse
// it. MaxAge of zero means it must not be stored at all.
type OCSPAnswer struct {
	DER    []byte
	MaxAge time.Duration
}

// AnswerOCSP builds a signed response and reports how long it may be reused.
//
// The reuse window is not always OCSPValidity, and the difference is the point.
// An `unknown` is the one status this replica can be wrong about for a reason
// that resolves on its own: the serial may simply have been signed on another
// replica and not yet reached this one's index, which SyncSerialIndex corrects
// within ocsp_index_sync_interval_sec. Declining to cache it in ocspCache only
// fixes half of that — a response handed out with four hours of validity is
// kept by the verifier and by every proxy between, so an `unknown` stamped the
// usual way would go on being replayed long after this replica learned better,
// which is the symptom the index refresh exists to end.
//
// So an unknown carries no NextUpdate (RFC 6960 §4.2.2.1: an absent nextUpdate
// says newer information is always available) and a MaxAge of zero. A nonced
// request gets the same MaxAge for a different reason: an RFC 8954 response
// answers one request and must not be served to another.
//
// The caller must NOT hold c.mu. The signature is taken outside it — see the
// snapshot comment in the body — so a slow signer no longer serialises the
// process (#197).
//
// ctx is checked once, immediately before the signature, and not otherwise:
// everything the answer is built from is already in memory, so there is nothing
// else here that can block on it.
func (c *CA) AnswerOCSP(ctx context.Context, reqDER []byte) (OCSPAnswer, error) {
	// Extract nonce before acquiring any lock (pure DER parse, no shared state).
	nonce, hasNonce := extractNonce(reqDER)

	// Validate nonce length: RFC 8954 §2.1 limits the nonce to 32 bytes
	// (plus DER header). Reject oversized nonces to prevent signing DoS
	// where an attacker forces the CA to sign arbitrarily large responses.
	if hasNonce && len(nonce.Value) > maxNonceLen {
		slog.Warn("OCSP request nonce exceeds maximum length, ignoring",
			"len", len(nonce.Value), "max", maxNonceLen)
		hasNonce = false
	}

	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return OCSPAnswer{}, fmt.Errorf("parsing OCSP request: %w", err)
	}

	// Compute the cache key in the same format used by signWithDuration/revoke:
	// uppercase hex without leading zeros.
	serialHex := serialHexStr(req.SerialNumber)

	// One read-locked look does both jobs: serve a fresh cache entry if there
	// is one, and otherwise take the snapshot the answer will be built from.
	// Splitting them would take c.mu twice for a single miss, and leave the
	// cache check and the status read looking at two different moments.
	//
	// Cache returns must be defensive copies: the cached slice is shared
	// across concurrent readers, and the HTTP layer should never observe
	// a buffer that another goroutine could mutate.
	c.mu.RLock()
	if !hasNonce {
		if entry, ok := c.ocspCache[serialHex]; ok && time.Now().Before(entry.expiresAt) {
			c.mu.RUnlock()
			return OCSPAnswer{DER: bytes.Clone(entry.der), MaxAge: time.Until(entry.expiresAt)}, nil
		}
	}
	_, known := c.serialIndex[serialHex]
	crlSnapshot := c.cachedCRL
	caCert, caKey := c.CACert, c.CAKey
	c.mu.RUnlock()

	// From here until the cache write, no CA lock is held. That is the whole of
	// #197: ocsp.CreateResponse below performs a signature, and under an
	// isolated signer or ca_key_provider: openbao that is a synchronous IPC or
	// network round trip. Holding c.mu across it made the responder a
	// process-wide serialisation point — not only for other OCSP requests, but
	// for every c.mu.RLock reader, including the IsRevokedSerial call on the
	// authentication path. Nonced requests (RFC 8954) bypass the cache and so
	// took that path on every single request.
	//
	// The snapshot is safe to use unlocked, for a different reason per field:
	//
	//   - CACert/CAKey are not rewritten while the server is serving. There is
	//     no rotation and no reload — parseStoredCRL documents the same thing
	//     from the other side, that a replaced CA certificate is picked up by
	//     restarting. Two other methods do write them through the same helpers
	//     Init uses, LoadKey and LoadOrCreateCAKey, but neither is reachable
	//     from a serving process: the first has no non-test caller and the
	//     second is the `csr` and `import-ca-cert` CLI paths. The load-bearing
	//     half is anyway the next clause, which does not depend on that being
	//     true: every writer holds c.mu, and both fields are read under the one
	//     RLock above, so this cannot observe a mismatched cert/key pair even
	//     if one of those paths did run concurrently.
	//   - cachedCRL is replaced by pointer and never mutated in place — see
	//     installCachedCRLLocked — so holding the pointer is holding an
	//     immutable view of one CRL, not a window onto a changing one.
	//   - serialIndex is not consulted again while no lock is held; the bool is
	//     a value, and staleness in it is handled at the cache write, which
	//     re-reads the map under the write lock rather than trusting this.
	now := time.Now().UTC()
	template := ocsp.Response{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
	}

	status, revokedAt, err := decideOCSPStatus(crlSnapshot, req.SerialNumber, known)
	if err != nil {
		return OCSPAnswer{}, fmt.Errorf("%w: %w", ErrInternal, err)
	}
	template.Status = status
	template.RevokedAt = revokedAt
	if status != ocsp.Unknown {
		// NextUpdate stays zero for an unknown, which x/crypto/ocsp omits from
		// the encoding. That is the answer a later inventory read can overturn
		// without anything happening here, so it must not carry a four-hour
		// licence to be replayed by the verifier and every cache between.
		template.NextUpdate = now.Add(OCSPValidity)
	}

	// Echo the nonce extension into the response's singleExtensions.
	if hasNonce {
		template.ExtraExtensions = append(template.ExtraExtensions, nonce)
	}

	// Shed abandoned requests before signing rather than after. Under an
	// external signer this is the one expensive step, and a client that has
	// already disconnected — or a server deadline that has already expired —
	// makes it work whose result nobody can receive. It is the half of the
	// problem that needs no configured size, and it does not replace the bound
	// immediately below: it declines to spend a signer round trip on an answer
	// that cannot be delivered, which is a different question from how many
	// round trips may be in flight at once.
	//
	// ErrInternal, so a request cancelled by a *server* deadline is reported as
	// RFC 6960 internalError, which a verifier may retry. Nothing about the
	// request was malformed. A client that has gone away receives neither.
	if err := ctx.Err(); err != nil {
		return OCSPAnswer{}, fmt.Errorf("%w: %w", ErrInternal, err)
	}

	// Take a CA-key signing slot, or shed. Unlike the issuance and CRL paths
	// this one refuses rather than queues, because `/ocsp` is unauthenticated
	// and a cache miss signs: an anonymous caller decides how much work arrives
	// here, and queueing that would bound nothing — it would only move the
	// unbounded growth from concurrent signatures to waiting goroutines.
	//
	// This is what closes the gap the lock-scope change above opened. Signing
	// outside c.mu is what makes the responder concurrent at all; without a cap
	// the only limit is how many connections a caller can open. See #274 and
	// signbound.go.
	//
	// ErrSigningBusy is not ErrInternal. The handler answers RFC 6960
	// `tryLater`, which says exactly what happened and invites a retry; a
	// non-success OCSP response carries no signature, so refusing costs no key
	// work at all. That is what makes shedding a real relief valve here rather
	// than a slower route to the same load.
	if err := c.acquireSigningSlotOrShed(ctx); err != nil {
		if errors.Is(err, ErrSigningBusy) {
			return OCSPAnswer{}, err
		}
		// The context went away while queueing for a slot — classified exactly
		// as the ctx.Err() check above does, and for the same reason.
		return OCSPAnswer{}, fmt.Errorf("%w: %w", ErrInternal, err)
	}

	// caCert/caKey, not c.CACert/c.CAKey: no lock is held here, and the
	// snapshot taken under the single RLock above is the whole reason this can
	// sign without one.
	// Released by a deferred call inside this closure; see releaseSigningSlot.
	// This is the site where it matters most: /ocsp is unauthenticated, so a
	// panic reachable from a request an anonymous caller can shape would leak
	// slots on demand.
	respDER, err := func() ([]byte, error) {
		defer c.releaseSigningSlot()
		return ocsp.CreateResponse(caCert, caCert, template, caKey)
	}()
	if err != nil {
		// ErrInternal, so the handler answers RFC 6960 `internalError` rather
		// than `malformedRequest`. A failed CA signature is a server fault and
		// nothing about the request provoked it; `malformedRequest` tells a
		// verifier not to retry, and logs the outage as a client error.
		//
		// The classification was always wrong here, but it used to be close to
		// unreachable. Signing outside c.mu means an external signer's per-call
		// deadline is now the expected failure under load rather than a rarity,
		// so this is the routine degradation path — see #274 and the concurrency
		// gap it tracks in docs/development/locking.md.
		return OCSPAnswer{}, fmt.Errorf("%w: creating OCSP response: %w", ErrInternal, err)
	}

	// Cache the response only when there is no nonce (RFC 8954 §3), and never
	// cache an unknown. The cache stores its own copy so the slice we return to
	// the caller stays exclusively theirs even if the cache later evicts or
	// rewrites the entry.
	//
	// Unknown is excluded for two reasons, and neither is a micro-optimisation:
	//
	//   - It is the one status that a *later* read of storage can overturn
	//     without anything happening on this replica. A serial signed elsewhere
	//     reaches this process only when SyncSerialIndex next runs, and caching
	//     the unknown would pin the wrong answer for OCSPValidity — four hours —
	//     past the point the index learned better. Leaving it uncached is what
	//     makes an index refresh take effect on the next request rather than on
	//     the next restart.
	//   - The cache key is the requested serial, which is chosen by an
	//     unauthenticated caller. Every other status can only be reached for a
	//     serial this CA issued, so the cache is bounded by the inventory;
	//     caching unknowns would let anyone who can reach /ocsp grow the map
	//     without limit, an entry (and a signed response) per made-up serial.
	//
	// It costs no DoS protection to leave out, and the reason is on this path
	// rather than another one. The cache never bounded how much signing an
	// attacker could provoke: a *miss* signs, so N distinct made-up serials
	// always cost N signatures, and varying the serial is free. What it bounded
	// was repeats of one serial — and it paid for that with an entry per serial,
	// so the same attacker got unbounded memory growth thrown in. Dropping
	// unknowns from the cache removes the memory vector and leaves the signing
	// ceiling where it already was; it only means an attacker who wants that
	// ceiling no longer has to bother varying the serial. (A nonced request
	// bypasses the cache outright and always signed, which is a second route to
	// the same place, but it is not the argument — this one is.)
	//
	// Note there is no rate limit in front of /ocsp: the limiter in this package
	// is CSR-only. Putting one there, or a bounded negative cache with a TTL far
	// shorter than an index sync interval, would be a real improvement and is
	// deliberately not attempted here — a negative cache is what this commit
	// removes, and reintroducing one carelessly restores the staleness the index
	// refresh exists to end.
	//
	// One consequence for an operator running an external key provider: an
	// unnonced query about a serial this replica has not yet indexed now signs
	// every time rather than once, so for up to one sync interval after each
	// issuance those queries join the nonced ones in signing on every request.
	// Those signatures no longer serialise the process behind them (#197); they
	// are still round trips, and still a reason to keep the sync interval
	// sensible.
	//
	// The status is re-decided under the write lock before anything is stored,
	// and the entry is dropped if the answer moved while the signature was in
	// flight. Signing outside c.mu is what makes that necessary: a revocation
	// can now land in between, and it installs a new CRL and evicts the
	// responses that CRL contradicts (invalidateOCSPForNewlyRevokedLocked),
	// while a prune drops the serial from the index and the cache together
	// (dropSerialLocked). Storing unconditionally would put a pre-signed `good`
	// back *after* the eviction that removed it, and it would then be served
	// for OCSPValidity — four hours of vouching for a revoked certificate,
	// which is precisely what that eviction exists to prevent.
	//
	// The response already built is still returned to this caller. It was
	// correct when it was signed, and an OCSP response is a statement about the
	// moment in its ThisUpdate/NextUpdate window rather than a promise about
	// the future; the pre-#197 arrangement handed back an equally stale answer
	// whenever a revocation was waiting on the lock behind it. What must not
	// happen is that statement being *reused* for callers arriving after the
	// change, so a moved answer costs one dropped cache write and a re-sign on
	// the next request.
	//
	// This re-runs the predicate rather than comparing a generation counter,
	// which serialIndexEpoch would be the precedent for. "Is this still the
	// answer" is exactly the question a later reader of the cache needs settled,
	// so checking it directly cannot be satisfied by a proxy that drifts, and it
	// stays correct if a third eviction path is added later. The index sync uses
	// a counter only because it genuinely cannot re-check its own predicate — it
	// cannot tell "pruned elsewhere" from "issued here since I read".
	var cached bool
	if !hasNonce && template.Status != ocsp.Unknown {
		c.mu.Lock()
		_, stillKnown := c.serialIndex[serialHex]
		// statusErr is kept in the condition below rather than handled: it can
		// only be non-nil when the serial is known and cachedCRL is nil, and
		// nothing sets cachedCRL to nil — installCachedCRLLocked in crl.go is
		// its only writer and always installs a parsed CRL. So it cannot fire
		// today, and it earns its place by costing one comparison while
		// declining the cache write if some future path ever does install nil.
		//
		// There is deliberately no log branch of its own. An earlier round added
		// one, on the grounds that a swallowed error at this line misleads an
		// incident review; a later round pointed out the branch is unreachable
		// and so untestable. Both are right, and a comment stating why it cannot
		// happen is worth more than a branch no spec can reach or a test-only
		// seam cut into a cache-write guard.
		stillStatus, stillRevokedAt, statusErr := decideOCSPStatus(c.cachedCRL, req.SerialNumber, stillKnown)
		if statusErr == nil && stillStatus == template.Status && stillRevokedAt.Equal(template.RevokedAt) {
			c.ocspCache[serialHex] = ocspCacheEntry{
				der:       bytes.Clone(respDER),
				expiresAt: now.Add(OCSPValidity),
			}
			cached = true
		} else {
			// Info, not Debug: the default verbosity is Info, and this is the
			// record an incident review wants when reconstructing why a client
			// accepted a certificate that was revoked at the time. It cannot
			// become noisy by construction — it fires only when a revocation or
			// prune lands inside the duration of one signature.
			slog.Info("not caching an OCSP response the CA state moved under it",
				"serial", serialHex, "signed_status", template.Status,
				"current_status", stillStatus, "signed_at", now)
		}
		c.mu.Unlock()
	}

	// MaxAge is whether the response was *actually* cached, not whether it was
	// the kind of response that may be cached. The two differ on exactly one
	// path, and it is the one that matters: a response the guard above refused
	// to store because a revocation overtook it.
	//
	// Getting this wrong would leave the guard half-built. Declining to store it
	// in ocspCache stops this process replaying it; a non-zero MaxAge would then
	// hand the same answer to every shared proxy in front of the responder with
	// four hours of licence to serve it on to third parties — see the
	// Cache-Control block in internal/api/ocsp_handler.go, which reasons exactly
	// this way about `unknown`. One door closed and the other left open is not a
	// guard.
	//
	// The other two zero cases fall out of the same condition rather than being
	// restated: a nonced response answers one request and no other (RFC 8954 §3),
	// and an unknown carries no NextUpdate to derive a window from. Neither is
	// ever stored, so neither is ever reusable.
	answer := OCSPAnswer{DER: respDER}
	if cached {
		// The nominal constant, not time.Until(now.Add(OCSPValidity)). The two
		// differ by however long signing took, because `now` is sampled before
		// the signature — so this advertises a window fractionally longer than
		// the entry just stored and than the response's own NextUpdate, where
		// the cache-hit path above derives its MaxAge from the entry's expiry
		// and does not.
		//
		// Left as it was, deliberately. The asymmetry predates #197, the
		// overshoot is one signature against a four-hour window, and a verifier
		// enforces NextUpdate for itself. Against that,
		// internal/api/ocsp_test.go's "GET response carries Cache-Control" spec
		// asserts this value equals OCSPValidity *exactly* — and that spec is on
		// main, not on any branch in flight, so it states a settled intent
		// rather than one still open to negotiation. Deriving the value would be
		// a behaviour change made to satisfy a symmetry no client can observe.
		answer.MaxAge = OCSPValidity
	}
	return answer, nil
}

// decideOCSPStatus decides what an OCSP response should say about serial, given
// whether the serial index recognises it and a CRL to check it against.
//
// Named for the decision rather than the status because the sibling ca_test
// package already has an ocspStatusFor — in serialsync_test.go — which issues a
// request and parses what comes back, a different question with a confusingly
// similar name.
//
// A free function over an explicit CRL rather than a method reading
// c.cachedCRL, because AnswerOCSP asks this question twice and from different
// places: once on the snapshot it signs from, holding no lock, and again under
// the write lock to check the answer has not moved before caching it. Passing
// the CRL in is what lets the unlocked caller work from an immutable snapshot;
// two copies of the decision that drifted apart would make the guard test a
// different question from the one the response answered.
//
// Its CRL scan — and only that part — is the deliberate twin of serialInCRL in
// revoke.go, which every caller needing only a yes or no uses: the scan exists
// separately here because OCSP must return the entry's RevocationTime, which a
// bool cannot carry. **Change the revocation predicate there and change the
// scan here too.**
//
// The obligation is worth stating narrowly, because this function grew past the
// twin when it absorbed the whole status decision: the !known early return and
// the not-loaded error have no counterpart in serialInCRL and nothing about
// them needs mirroring. It is the loop, not the function, that has to stay in
// step.
//
// Returns (ocsp.Unknown, zero, nil) when the index does not recognise the
// serial — checked first, so an unrecognised serial does not depend on a CRL
// being loaded — (ocsp.Revoked, revocationTime, nil) when it appears on crl,
// (ocsp.Good, zero, nil) when it does not, and an error when the serial is
// known but no CRL is loaded, which the caller reports as ErrInternal.
func decideOCSPStatus(crl *x509.RevocationList, serial *big.Int, known bool) (int, time.Time, error) {
	if !known {
		return ocsp.Unknown, time.Time{}, nil
	}
	if crl == nil {
		return ocsp.Unknown, time.Time{}, fmt.Errorf("CRL not loaded")
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return ocsp.Revoked, entry.RevocationTime, nil
		}
	}
	return ocsp.Good, time.Time{}, nil
}

// buildAIAExtension constructs the DER-encoded value of an Authority Information
// Access extension (RFC 5280 §4.2.2.1) pointing each URL at the OCSP responder.
func buildAIAExtension(urls []string) ([]byte, error) {
	type accessDescription struct {
		AccessMethod   asn1.ObjectIdentifier
		AccessLocation asn1.RawValue
	}

	ads := make([]accessDescription, 0, len(urls))
	for _, u := range urls {
		ads = append(ads, accessDescription{
			AccessMethod: OIDAdOCSP,
			AccessLocation: asn1.RawValue{
				Class: asn1.ClassContextSpecific,
				Tag:   6, // uniformResourceIdentifier [6] IMPLICIT IA5String
				Bytes: []byte(u),
			},
		})
	}
	return asn1.Marshal(ads)
}
