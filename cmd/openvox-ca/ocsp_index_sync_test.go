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

package main

import (
	"context"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// signOn issues a certificate for subject on c, which is what puts a new row in
// the shared inventory for the peer's index sync to find.
func signOn(c *ca.CA, subject string) {
	GinkgoHelper()
	ctx := context.Background()
	csrPEM, err := testutil.GenerateCSR(subject)
	Expect(err).NotTo(HaveOccurred(), "GenerateCSR")
	_, err = c.SaveRequest(ctx, subject, csrPEM)
	Expect(err).NotTo(HaveOccurred(), "SaveRequest")
	_, err = c.Sign(ctx, subject)
	Expect(err).NotTo(HaveOccurred(), "Sign")
}

var _ = Describe("syncOCSPIndexOnce", func() {
	It("picks up serials issued underneath the process, and is a no-op otherwise", func() {
		c, store := newRefresherTestCA()
		peer := peerReplica(store)
		ctx := context.Background()

		before := peer.SerialIndexSize()
		syncOCSPIndexOnce(ctx, peer)
		Expect(peer.SerialIndexSize()).To(Equal(before), "nothing changed in storage")

		// The other replica signs. Its own index moves; the peer's does not,
		// until the sync job runs — which is the whole bug.
		signOn(c, "issued-elsewhere.example.com")
		Expect(peer.SerialIndexSize()).To(Equal(before))

		syncOCSPIndexOnce(ctx, peer)
		Expect(peer.SerialIndexSize()).To(Equal(before + 1))
	})

	It("swallows a failure so the job survives to its next tick", func() {
		c, store := newRefresherTestCA()
		peer := peerReplica(store)
		ctx := context.Background()

		signOn(c, "before-the-break.example.com")
		syncOCSPIndexOnce(ctx, peer)
		before := peer.SerialIndexSize()
		Expect(before).To(BeNumerically(">", 0))

		// Remove the inventory blob so the next read fails outright.
		Expect(os.Remove(store.InventoryPath())).To(Succeed())

		Expect(func() { syncOCSPIndexOnce(ctx, peer) }).NotTo(Panic())
		Expect(peer.SerialIndexSyncFailures()).To(BeNumerically(">", 0))
		Expect(peer.SerialIndexSize()).To(Equal(before), "the usable index must be kept")
	})
})

var _ = Describe("runOCSPIndexSync", func() {
	It("picks up a serial written after it started, and returns on cancellation", func() {
		c, store := newRefresherTestCA()
		peer := peerReplica(store)
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan struct{})
		go func() {
			runOCSPIndexSync(ctx, peer, 10*time.Millisecond)
			close(done)
		}()

		before := peer.SerialIndexSize()
		signOn(c, "signed-while-the-loop-runs.example.com")

		Eventually(peer.SerialIndexSize).
			WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			Should(Equal(before+1), "the sync loop did not pick the serial up within 2s")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runOCSPIndexSync did not return after context cancellation")
	})

	// Same shape as runCRLSync's: Init has just built the index from this
	// storage, so an immediate pass would re-read what cannot yet be stale. Only
	// observable when the inventory grows *before* the loop starts.
	It("does not run a pass before its first tick", func() {
		c, store := newRefresherTestCA()
		peer := peerReplica(store)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		behind := peer.SerialIndexSize()
		signOn(c, "signed-before-the-loop.example.com")
		Expect(peer.SerialIndexSize()).To(Equal(behind), "precondition: the peer has not seen it")

		go runOCSPIndexSync(ctx, peer, 750*time.Millisecond)

		// An immediate pass would install it within milliseconds. Hold for a
		// window comfortably inside the first interval and require it not to.
		Consistently(peer.SerialIndexSize).
			WithTimeout(300*time.Millisecond).WithPolling(20*time.Millisecond).
			Should(Equal(behind), "the loop must wait for its first tick")

		// ...and then it does pick it up, so this is not passing by never syncing.
		Eventually(peer.SerialIndexSize).
			WithTimeout(3 * time.Second).WithPolling(20 * time.Millisecond).
			Should(Equal(behind + 1))
	})
})
