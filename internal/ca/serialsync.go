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
	"fmt"
	"log/slog"
)

// SerialIndexDelta reports what one SyncSerialIndex pass changed.
type SerialIndexDelta struct {
	// Added is the number of serials the inventory holds that this process did
	// not know about — on a shared backend, the certificates other replicas
	// have signed since the last pass.
	Added int
	// Removed is the number of serials this process held that the inventory no
	// longer does, i.e. entries another replica's cleanup has pruned.
	Removed int
	// Total is the size of the index after the pass.
	Total int
}

// Changed reports whether the pass moved the index at all.
func (d SerialIndexDelta) Changed() bool { return d.Added > 0 || d.Removed > 0 }

// SyncSerialIndex reconciles the in-memory OCSP serial index with the stored
// inventory, and reports what it changed.
//
// This is what stops the OCSP responder answering `unknown` for a certificate
// another replica signed. The index answers a single question — did this CA
// issue this serial — and OCSPResponse short-circuits to `unknown` when it says
// no, before the CRL is ever consulted. It was built once, by buildSerialIndex
// at startup, and afterwards only ever mutated in-process: this process's own
// issuances went in and its own cleanups came out, and nothing re-read the
// inventory. On a shared backend that leaves every replica answering `unknown`
// for every certificate it did not personally sign, indefinitely — the
// certificate is valid, the inventory row is in shared storage, and only a
// restart makes this process see it.
//
// It is not a revocation bypass: `unknown` is not `good`, and the mTLS
// admission path reads the CRL rather than this index. The consequence is that
// a peer's responder cannot say `revoked` either, because the index miss
// answers before the CRL lookup — so for a certificate signed elsewhere the
// responder is silent about revocation whether or not it is revoked.
//
// Polling, for the same reason SyncCRLCache polls: there is no cross-process
// signal all five backends can carry, and the alternative direction — looking
// the serial up in storage on an index miss — is worse here than it sounds.
// SubjectForSerial is a linear scan of the whole inventory (it must match on
// the normalised serial, so even the backends carrying a by-serial index cannot
// serve it; see its comment), and the miss path is the one an unauthenticated
// caller drives with arbitrary serials. That trades a read per interval for a
// full inventory scan per made-up serial.
//
// c.mu is not held across the storage read. reconcileSerialIndexLocked takes it
// afterwards, so an issuance can land between the two; the epoch counter is how
// this pass tells. Additions from the read always apply — a serial in the
// inventory was issued by someone — but the removal half is skipped when the
// count moved, because this pass cannot distinguish "pruned elsewhere" from
// "signed here, after I read". Removals are rare and one interval late is
// harmless (a pruned certificate is an expired one); dropping a serial this
// process just issued would make its own OCSP answers wrong, which is not.
func (c *CA) SyncSerialIndex(ctx context.Context) (SerialIndexDelta, error) {
	c.mu.RLock()
	epoch := c.serialIndexEpoch
	c.mu.RUnlock()

	// Read outside c.mu: a storage round-trip must not block the auth path.
	// A blob backend verifies the inventory HMAC as part of this, so a tampered
	// inventory fails the pass and is counted rather than being indexed from.
	stored, err := c.readSerialIndex(ctx)
	if err != nil {
		c.serialIndexSyncFailures.Add(1)
		return SerialIndexDelta{}, fmt.Errorf("reading the inventory to refresh the OCSP serial index: %w", err)
	}

	c.mu.Lock()
	delta := c.reconcileSerialIndexLocked(stored, epoch)
	c.mu.Unlock()

	if delta.Changed() {
		slog.Info("Refreshed the OCSP serial index from the inventory",
			"added", delta.Added, "removed", delta.Removed, "serials", delta.Total)
	}
	return delta, nil
}

// reconcileSerialIndexLocked applies an inventory read to the index, where
// readEpoch is the mutation count sampled before that read was taken.
//
// Split from SyncSerialIndex so the epoch guard can be asserted rather than
// raced: the interleaving it protects against lasts microseconds and is
// re-corrected by the following pass, so a spec built on two goroutines passes
// whether or not the guard is there — measured, not assumed; see
// serialindexepoch_test.go. Given the read and the epoch it belongs to, the
// same decision is a proposition a spec can simply state.
//
// c.mu must be held by the caller.
func (c *CA) reconcileSerialIndexLocked(stored map[string]string, readEpoch uint64) SerialIndexDelta {
	// Decided before the additions below, which move the epoch themselves.
	raced := c.serialIndexEpoch != readEpoch

	var delta SerialIndexDelta
	for serial, subject := range stored {
		if _, known := c.serialIndex[serial]; !known {
			delta.Added++
		}
		// Rewriting a known serial's subject is deliberate: storage is
		// authoritative, and the two agreeing is the normal case.
		c.serialIndex[serial] = subject
	}

	// No cached OCSP response is dropped for an added serial, because there
	// cannot be one: the only answer this process could have given for a serial
	// it did not know is `unknown`, and OCSPResponse does not cache those. That
	// is load-bearing rather than incidental — were unknowns cached, every
	// serial added here would need evicting or the responder would keep serving
	// the pre-index answer for up to OCSPValidity.
	// A pass that added something counts as a mutation for the *next* pass, even
	// though it is not an issuance. Without this two overlapping passes sample
	// the same epoch, and the one whose read is older can delete what the newer
	// one just added — dropping a live serial, which is the failure the guard
	// exists to prevent, reached by a different route. Only one goroutine runs
	// this today; SyncSerialIndex is exported, and the next caller should not
	// have to discover that.
	if delta.Added > 0 {
		c.serialIndexEpoch++
	}

	if !raced {
		for serial := range c.serialIndex {
			if _, present := stored[serial]; !present {
				delta.Removed++
				// The cached response goes with it, via the same helper the
				// prune path uses. A `good` signed before another replica
				// pruned the certificate would otherwise outlive the index
				// entry it was derived from.
				c.dropSerialLocked(serial)
			}
		}
	}

	delta.Total = len(c.serialIndex)
	return delta
}
