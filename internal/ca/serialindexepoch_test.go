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

// White-box, because the property under test is an interleaving. SyncSerialIndex
// reads storage outside c.mu so the read cannot block the auth path, which lets
// an issuance land between the read and the reconciliation; the epoch guard is
// what stops that pass deleting the serial that issuance just added.
//
// Racing it from outside proves nothing. The window is microseconds wide and
// the very next pass re-adds whatever was lost, so a spec built on two
// goroutines and a final assertion passes with the guard removed — measured,
// not assumed: with the comparison forced true, 25 signings against a
// continuous sync loop lost serials on 24 passes and still ended green, because
// the last pass put them all back. Handing the reconciliation a read and the
// epoch it was taken at makes the same decision something a spec can state.
package ca

import (
	"crypto"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("serial index epoch guard", func() {
	// A CA with an index and no storage: reconcileSerialIndexLocked touches
	// neither, and building one through Init would only add a backend whose
	// contents these specs then have to keep consistent with the map they pass
	// in by hand.
	var c *CA

	BeforeEach(func() {
		c = New(nil, AutosignConfig{Mode: "off"}, "puppet.test")
		c.mu.Lock()
		defer c.mu.Unlock()
		c.indexSerialLocked("AA", "already-known.example.com")
	})

	// The reconciliation's normal case, and the control for the spec below: an
	// undisturbed pass is what prunes serials another replica has cleaned up.
	It("removes a serial the inventory no longer holds when nothing raced the read", func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		delta := c.reconcileSerialIndexLocked(map[string]string{}, c.serialIndexEpoch, c.serialIndexRemovalEpoch)

		Expect(delta.Removed).To(Equal(1))
		Expect(c.serialIndex).NotTo(HaveKey("AA"))
	})

	// The guard. The read predates a local issuance, so the reconciliation
	// cannot tell "pruned elsewhere" from "signed here, after I read" — and
	// guessing wrong in the second direction would have this replica answer
	// unknown about a certificate it signed itself, which is worse than the bug
	// this whole change exists to fix.
	It("keeps every serial when an issuance landed after the read was taken", func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		readEpoch := c.serialIndexEpoch
		c.indexSerialLocked("BB", "signed-mid-pass.example.com")

		delta := c.reconcileSerialIndexLocked(map[string]string{}, readEpoch, c.serialIndexRemovalEpoch)

		Expect(delta.Removed).To(BeZero(), "a pass that raced an issuance must not prune")
		Expect(c.serialIndex).To(HaveKey("BB"), "the serial this process just issued")
		Expect(c.serialIndex).To(HaveKey("AA"), "and everything else it already held")
	})

	// Additions are unconditional: a serial in the inventory was issued by
	// someone, whatever raced the read. Only the removal half has to stand down.
	It("still adds what the read found even when the read was raced", func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		readEpoch := c.serialIndexEpoch
		c.indexSerialLocked("BB", "signed-mid-pass.example.com")

		delta := c.reconcileSerialIndexLocked(map[string]string{"CC": "peer-signed.example.com"}, readEpoch, c.serialIndexRemovalEpoch)

		Expect(delta.Added).To(Equal(1))
		Expect(c.serialIndex).To(HaveKey("CC"))
	})

	// The guard's other half, and the reason a pass counts its own additions as
	// a mutation. Two passes overlapping sample the same epoch; without the
	// bump, the one whose read is older would see an unmoved counter, believe
	// nothing had happened, and delete what the newer pass had just added —
	// dropping a live serial by a different route than an issuance would.
	//
	// Stated as two reconciliations sharing one stale readEpoch, because that
	// is precisely what two overlapping passes are.
	It("makes a pass that added something look like a mutation to a stale pass", func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		readEpoch := c.serialIndexEpoch

		// The newer pass: its read found a serial this process did not hold.
		first := c.reconcileSerialIndexLocked(map[string]string{"CC": "peer-signed.example.com"}, readEpoch, c.serialIndexRemovalEpoch)
		Expect(first.Added).To(Equal(1))

		// The older pass, whose read predates that serial existing, finishing
		// second and still holding the epoch it sampled before either ran.
		second := c.reconcileSerialIndexLocked(map[string]string{"AA": "already-known.example.com"}, readEpoch, c.serialIndexRemovalEpoch)

		Expect(second.Removed).To(BeZero(),
			"the addition must have moved the epoch, standing the stale pass's removals down")
		Expect(c.serialIndex).To(HaveKey("CC"), "the serial the newer pass added")
	})

	// The loop's second write condition. A serial already in the index whose
	// stored subject disagrees is not reachable in normal operation — serials
	// are unique and inventory rows are append-only — but the branch decides
	// which of the two wins, and the answer has to be storage. Stated directly
	// rather than left to inference, because the alternative reading (keep what
	// this process already believes) is the one that would let a rewritten row
	// go unnoticed for the life of the process.
	It("takes storage's answer when a known serial's subject disagrees", func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		delta := c.reconcileSerialIndexLocked(map[string]string{"AA": "renamed.example.com"}, c.serialIndexEpoch, c.serialIndexRemovalEpoch)

		Expect(c.serialIndex["AA"]).To(Equal("renamed.example.com"),
			"storage is authoritative where the two disagree")
		Expect(delta.Added).To(BeZero(), "the serial was already known; this is a rewrite, not an addition")
		Expect(delta.Removed).To(BeZero(), "and the inventory still holds it, so nothing is pruned")
	})

	// The addition half's own guard, and the mirror of the removal one above.
	// CleanupExpiredCerts can prune a serial in the window between this pass
	// reading the inventory and taking the write lock; `stored` then describes a
	// state that has stopped being true, and re-adding from it resurrects a
	// serial the CA has finished with — the responder starts speaking about a
	// certificate that was deliberately swept.
	//
	// Additions cannot re-check their own predicate the way the OCSP cache write
	// can: "is this serial still in storage" is another storage read, which is
	// the round trip this job exists to keep off the lock. So this half is
	// gated on a counter, and the removal half — which can be reasoned about
	// from state already in hand — is gated on the other one.
	It("does not re-add a serial pruned after the read", func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		// The pass read the inventory while AA was still in it.
		stored := map[string]string{"AA": "already-known.example.com"}
		readEpoch, readRemovalEpoch := c.serialIndexEpoch, c.serialIndexRemovalEpoch

		// Cleanup then prunes AA: gone from storage, gone from the index.
		c.unindexSerialLocked("AA")

		delta := c.reconcileSerialIndexLocked(stored, readEpoch, readRemovalEpoch)

		Expect(c.serialIndex).NotTo(HaveKey("AA"),
			"a serial pruned after the read must not come back through the write-back")
		Expect(delta.Added).To(BeZero(),
			"and the pass must not report having added it")
	})

	// A pruned serial's pre-signed response must go with its index entry, or a
	// good signed while the certificate was still known outlives the index that
	// justified it — the same coupling CleanupExpiredCerts maintains on the
	// replica that does the pruning.
	It("drops the cached OCSP response alongside the serial it removes", func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.ocspCache["AA"] = map[crypto.Hash]ocspCacheEntry{crypto.SHA1: {der: []byte("pre-signed good")}}

		c.reconcileSerialIndexLocked(map[string]string{}, c.serialIndexEpoch, c.serialIndexRemovalEpoch)

		Expect(c.ocspCache).NotTo(HaveKey("AA"))
	})
})
