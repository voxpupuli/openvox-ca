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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// cachedCRLNumber reports the CRL number the CA is answering revocation checks
// from, as an int64 so specs can compare it directly.
func cachedCRLNumber(c *ca.CA) int64 {
	GinkgoHelper()
	num, ok := c.CachedCRLNumber()
	Expect(ok).To(BeTrue(), "the CA has no CRL loaded")
	return num.Int64()
}

// peerReplica returns a second CA over the same storage as store, with a CRL
// cache of its own. It is the replica the sync job exists for: the one that did
// not perform the revocation.
func peerReplica(store *storage.StorageService) *ca.CA {
	GinkgoHelper()
	dir := store.CADir()
	Expect(dir).NotTo(BeEmpty(), "the test store is not filesystem-backed")
	peer := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, "puppet.test")
	Expect(peer.Init(context.Background())).To(Succeed())
	return peer
}

var _ = Describe("syncCRLOnce", func() {
	It("installs a CRL that advanced underneath the process, and is a no-op otherwise", func() {
		c, store := newRefresherTestCA()
		peer := peerReplica(store)
		ctx := context.Background()

		before := cachedCRLNumber(peer)
		syncCRLOnce(ctx, peer)
		Expect(cachedCRLNumber(peer)).To(Equal(before), "nothing changed in storage")

		// The other replica re-signs. Its own cache moves; the peer's does not,
		// until the sync job runs.
		Expect(c.ReissueCRL(ctx)).To(Succeed())
		advanced := storedCRLNumber(store)
		Expect(advanced).To(Equal(before + 1))
		Expect(cachedCRLNumber(peer)).To(Equal(before))

		syncCRLOnce(ctx, peer)
		Expect(cachedCRLNumber(peer)).To(Equal(advanced))
	})

	It("swallows a failure so the job survives to its next tick", func() {
		_, store := newRefresherTestCA()
		peer := peerReplica(store)
		ctx := context.Background()

		before := cachedCRLNumber(peer)
		Expect(store.UpdateCRL(ctx, []byte("not a CRL"))).To(Succeed())

		Expect(func() { syncCRLOnce(ctx, peer) }).NotTo(Panic())
		Expect(peer.CRLSyncFailures()).To(BeNumerically(">", 0))
		Expect(cachedCRLNumber(peer)).To(Equal(before), "the usable CRL must be kept")
	})
})

var _ = Describe("runCRLSync", func() {
	It("picks up a CRL written after it started, and returns on cancellation", func() {
		c, store := newRefresherTestCA()
		peer := peerReplica(store)
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan struct{})
		go func() {
			runCRLSync(ctx, peer, 10*time.Millisecond)
			close(done)
		}()

		Expect(c.ReissueCRL(context.Background())).To(Succeed())
		target := storedCRLNumber(store)

		Eventually(func() int64 {
			num, ok := peer.CachedCRLNumber()
			if !ok {
				return 0
			}
			return num.Int64()
		}).WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			Should(Equal(target), "the sync loop did not install the newer CRL within 2s")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runCRLSync did not return after context cancellation")
	})
})

var _ = Describe("crlSyncInterval", func() {
	It("defaults to a minute and honours an override", func() {
		Expect((&serverConfig{}).crlSyncInterval()).To(Equal(time.Minute))
		Expect((&serverConfig{CRLSyncIntervalSec: 15}).crlSyncInterval()).To(Equal(15 * time.Second))
	})
})
