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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// ErrInternal is returned by OCSPResponse when a server-side failure (e.g. a
// CRL read error) prevents determining certificate status. The HTTP handler
// uses this to write an OCSP InternalError response instead of MalformedRequest.
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
// on a timer. ReadInventory verifies and then fetches, which on an
// InventoryStore backend is two full materialisations of the inventory per call
// — and those are exactly the HA backends this sync exists for. InventoryEntries
// is one, and carries the same integrity policy SubjectForSerial settled on.
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
// Shared with the sync's removal half, which must do exactly this and must NOT
// bump the epoch — that counter means "this process issued or pruned
// something", and a pass reconciling with storage has done neither. Keeping the
// pair of deletes in one place is the same argument installCachedCRLLocked
// makes about CRL installs: the divergence between the two callers is the epoch
// and nothing else, and a third thing to forget later should only have to be
// added here. c.mu must be held by the caller.
func (c *CA) dropSerialLocked(serial string) {
	delete(c.serialIndex, serial)
	delete(c.ocspCache, serial)
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
// The caller must NOT hold c.mu.
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

	// Fast path: check cache with a read lock (only when no nonce).
	// Cache returns must be defensive copies: the cached slice is shared
	// across concurrent readers, and the HTTP layer should never observe
	// a buffer that another goroutine could mutate.
	if !hasNonce {
		c.mu.RLock()
		entry, ok := c.ocspCache[serialHex]
		c.mu.RUnlock()
		if ok && time.Now().Before(entry.expiresAt) {
			return OCSPAnswer{DER: bytes.Clone(entry.der), MaxAge: time.Until(entry.expiresAt)}, nil
		}
	}

	// Slow path: acquire write lock for status lookup + cache write.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring the write lock.
	if !hasNonce {
		if entry, ok := c.ocspCache[serialHex]; ok && time.Now().Before(entry.expiresAt) {
			return OCSPAnswer{DER: bytes.Clone(entry.der), MaxAge: time.Until(entry.expiresAt)}, nil
		}
	}

	now := time.Now().UTC()
	template := ocsp.Response{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
	}

	if _, known := c.serialIndex[serialHex]; !known {
		// NextUpdate stays zero, which x/crypto/ocsp omits from the encoding.
		// This is the answer a later inventory read can overturn without
		// anything happening here, so it must not carry a four-hour licence to
		// be replayed by the verifier and every cache between.
		template.Status = ocsp.Unknown
	} else {
		template.NextUpdate = now.Add(OCSPValidity)
		revoked, revokedAt, err := c.isRevokedSerial(ctx, req.SerialNumber)
		if err != nil {
			return OCSPAnswer{}, fmt.Errorf("%w: %w", ErrInternal, err)
		}
		if revoked {
			template.Status = ocsp.Revoked
			template.RevokedAt = revokedAt
		} else {
			template.Status = ocsp.Good
		}
	}

	// Echo the nonce extension into the response's singleExtensions.
	if hasNonce {
		template.ExtraExtensions = append(template.ExtraExtensions, nonce)
	}

	respDER, err := ocsp.CreateResponse(c.CACert, c.CACert, template, c.CAKey)
	if err != nil {
		return OCSPAnswer{}, fmt.Errorf("creating OCSP response: %w", err)
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
	// It costs no DoS protection to leave out: a request carrying a nonce
	// bypasses the cache entirely and is answered with a fresh signature, so an
	// attacker who wants to make this CA sign per request already can.
	//
	// One consequence for an operator running an external key provider: an
	// unnonced query about a serial this replica has not yet indexed now signs
	// every time rather than once, so for up to one sync interval after each
	// issuance those queries join the nonced ones in the signer-round-trip-
	// under-c.mu class that docs/development/locking.md records as #197.
	if !hasNonce && template.Status != ocsp.Unknown {
		c.ocspCache[serialHex] = ocspCacheEntry{
			der:       bytes.Clone(respDER),
			expiresAt: now.Add(OCSPValidity),
		}
	}

	// A nonced response answers one request and no other (RFC 8954 §3), and an
	// unknown carries no NextUpdate to derive a window from; both are zero, which
	// the HTTP layer turns into "do not store".
	answer := OCSPAnswer{DER: respDER}
	if !hasNonce && template.Status != ocsp.Unknown {
		answer.MaxAge = OCSPValidity
	}
	return answer, nil
}

// isRevokedSerial checks the in-memory CRL cache for the given serial number.
//
// The deliberate twin of serialInCRL in revoke.go, which every caller needing
// only a yes or no uses: this one exists because OCSP must return the entry's
// RevocationTime, which a bool cannot carry. Change the predicate there and
// change it here too.
//
// Returns (true, revocationTime, nil) if found, (false, zero, nil) if not,
// or (false, zero, error) if the CRL is not loaded.
// Must be called while c.mu is already held by the caller.
func (c *CA) isRevokedSerial(ctx context.Context, serial *big.Int) (bool, time.Time, error) {
	if c.cachedCRL == nil {
		return false, time.Time{}, fmt.Errorf("CRL not loaded")
	}
	for _, entry := range c.cachedCRL.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true, entry.RevocationTime, nil
		}
	}
	return false, time.Time{}, nil
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
