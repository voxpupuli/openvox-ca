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
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// seedExpiredInventoryEntry appends an inventory entry whose NotAfter is two
// years in the past, so a cleanup pass with any modest retention removes it.
// (newRefresherTestCA is defined in crl_refresh_test.go in this package.)
func seedExpiredInventoryEntry(store *storage.StorageService, subject string) {
	GinkgoHelper()
	past := time.Now().Add(-2 * 365 * 24 * time.Hour).Format("2006-01-02T15:04:05UTC")
	entry := "ABCD " + past + " " + past + " /" + subject
	Expect(store.AppendInventory(context.Background(), entry)).To(Succeed(), "AppendInventory")
}

func inventoryHas(store *storage.StorageService, needle string) bool {
	GinkgoHelper()
	data, err := store.ReadInventory(context.Background())
	Expect(err).NotTo(HaveOccurred(), "ReadInventory")
	return strings.Contains(string(data), needle)
}

// cleanupExpiredOnce should remove an expired entry and leave a fresh one alone.
var _ = Describe("cleanupExpiredOnce", func() {
	It("removes an expired inventory entry", func() {
		c, store := newRefresherTestCA()
		ctx := context.Background()

		seedExpiredInventoryEntry(store, "expired-node")
		Expect(inventoryHas(store, "/expired-node")).To(BeTrue(), "precondition: expired-node should be in the inventory")

		cleanupExpiredOnce(ctx, c, time.Hour)
		Expect(inventoryHas(store, "/expired-node")).To(BeFalse(), "expired-node should have been removed from the inventory")
	})
})

// runCertCleaner must perform an immediate cleanup at startup and then return
// promptly once its context is cancelled.
var _ = Describe("runCertCleaner", func() {
	It("prunes at startup and returns after context cancellation", func() {
		c, store := newRefresherTestCA()
		seedExpiredInventoryEntry(store, "expired-node")

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			runCertCleaner(ctx, c, time.Hour, time.Hour)
			close(done)
		}()

		// The startup pass should prune the expired entry before we cancel; poll.
		Eventually(func() bool {
			return inventoryHas(store, "/expired-node")
		}).WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			Should(BeFalse(), "startup cleanup did not run within 2s")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runCertCleaner did not return after context cancellation")
	})
})
