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
	"crypto/x509"
	"fmt"
	"log/slog"
	"math/big"
)

// SyncCRLCache reloads the in-memory CRL from storage when the stored CRL has
// moved ahead of the cached copy, and reports whether it replaced it.
//
// This is what makes a revocation take effect on the replicas that did not
// perform it. Every admission decision the CA makes about a presented
// certificate — IsRevokedSerial on the mTLS path, the OCSP responder, the
// re-issuance eviction check — answers from c.cachedCRL, which is otherwise
// only written when *this* process re-signs the CRL or starts up. On a shared
// backend that leaves a peer admitting a certificate another replica revoked
// until it happens to re-sign on its own, which with the default 30-day CRL
// validity is weeks away. Storage is the shared truth; this pulls from it.
//
// Cheap enough to run on a short timer: one CRL read per call and no cluster
// lock. c.mu is never held across the storage read; on the rare tick that finds
// something new it is held for the comparison, the signature check, the swap
// and the OCSP eviction, and on every other tick for the comparison alone.
// Taking the CRL lock would serialise every replica's poll against every
// revocation for no gain — the swap needs no mutual exclusion because it is
// monotonic in the CRL number, so a poll that raced a local re-sign and lost
// simply declines to install what it read.
//
// It deliberately does not signal crlNotify. That channel exists to tell this
// process's Kubernetes exporter that the published artefacts need rewriting,
// and the replica that actually re-signed has already woken its own exporter
// against the same storage. Signalling here would have every other replica
// re-apply identical content on every revocation in the fleet.
func (c *CA) SyncCRLCache(ctx context.Context) (bool, error) {
	// Read outside c.mu: a storage round-trip must not block the auth path.
	stored, err := c.readStoredCRL(ctx)
	if err != nil {
		c.crlSyncFailures.Add(1)
		return false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Nothing new: the overwhelmingly common outcome, since the job ticks far
	// more often than anything revokes. Answered before the signature check
	// below so the steady state costs a read and a comparison, not a
	// verification on every tick of every replica.
	if !crlSupersedes(stored, c.cachedCRL) {
		return false, nil
	}

	// SECURITY: only install a CRL this CA signed — see verifyOwnCRLLocked. A
	// forged CRL needs only a plausible number to be preferred by the comparison
	// above, so the comparison alone is not a gate. Keeping the CRL we already
	// hold is the fail-closed answer, and the counter says it happened.
	if err := c.verifyOwnCRLLocked(stored); err != nil {
		c.crlSyncFailures.Add(1)
		return false, err
	}

	previous := c.cachedCRL
	c.cachedCRL = stored
	c.invalidateOCSPForNewlyRevokedLocked(previous, stored)

	slog.Info("Reloaded the CRL from storage",
		"crl_number", stored.Number,
		"revoked", len(stored.RevokedCertificateEntries))
	return true, nil
}

// verifyOwnCRLLocked reports an error unless crl was issued by the CA
// certificate this process loaded.
//
// The cached CRL is the sole input to the revocation half of every admission
// decision this CA makes, so caching a list issued by some other authority
// would silently unrevoke everything this CA has revoked. Both paths that write
// c.cachedCRL from storage — SyncCRLCache and loadCRLCache — go through here,
// which is the point: gating only the sync would be theatre, because a restart
// is the documented remedy for a sync that is refusing, and the startup path
// would then install exactly the CRL the sync declined.
//
// The check is the signature rather than the issuer name or the authority key
// identifier: the name is not unique among sub-CAs under a shared root, and the
// key identifier is an optional extension that openssl omits by default.
//
// c.mu must be held by the caller.
func (c *CA) verifyOwnCRLLocked(crl *x509.RevocationList) error {
	if c.CACert == nil {
		return fmt.Errorf("cannot verify the stored CRL: CA certificate not loaded")
	}
	if err := crl.CheckSignatureFrom(c.CACert); err != nil {
		return fmt.Errorf("the stored CRL was not signed by the CA certificate this process is using, "+
			"so it is being refused rather than used to decide revocation. "+
			"If the CA certificate was replaced, re-sign the CRL with it: %w", err)
	}
	return nil
}

// crlSupersedes reports whether stored should replace cached. The CRL number
// is the ordering: RFC 5280 §5.2.3 requires it to be monotonically increasing
// for a given issuer, and signCRLLocked bumps it on every re-sign, so a higher
// number is exactly "someone re-signed after the copy we hold".
//
// Strictly greater, not "different". An equal number is the same CRL, and
// accepting a lower one would let a stale read — a replica polling a lagging
// read replica, say — undo a revocation this process has already applied.
func crlSupersedes(stored, cached *x509.RevocationList) bool {
	if cached == nil {
		return true
	}
	if stored.Number == nil || cached.Number == nil {
		// A CRL without a number cannot be ordered against one that has it.
		// Prefer the numbered copy; if neither is numbered, keep what we hold.
		return stored.Number != nil
	}
	return stored.Number.Cmp(cached.Number) > 0
}

// invalidateOCSPForNewlyRevokedLocked drops the cached OCSP responses for
// serials that the newly loaded CRL revokes and the previous one did not, so
// the responder stops handing out a pre-signed "good" for a certificate
// another replica has just revoked. Without it the CRL would be current while
// OCSP kept answering from responses signed up to OCSPValidity ago.
//
// Only the newly revoked serials are dropped, mirroring what revokeSerialLocked
// does on the replica that performs a revocation. Clearing every revoked
// serial's entry instead would re-sign the whole revoked set on every
// revocation anywhere in the fleet.
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

// CachedCRLNumber returns the CRL number of the copy this process is making
// admission decisions from, and whether a CRL is loaded at all. Comparing it
// across replicas is how an operator confirms a revocation has propagated.
func (c *CA) CachedCRLNumber() (*big.Int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cachedCRL == nil || c.cachedCRL.Number == nil {
		return nil, false
	}
	return new(big.Int).Set(c.cachedCRL.Number), true
}
