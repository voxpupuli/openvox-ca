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
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// tamperInventory appends a row for a serial the CA never issued straight to
// the inventory blob, leaving its stored integrity value describing the
// inventory as it was.
func tamperInventory(store *storage.StorageService) {
	GinkgoHelper()
	data, err := os.ReadFile(store.InventoryPath())
	Expect(err).NotTo(HaveOccurred())
	forged := "0BADC0DE 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /forged.example.com\n"
	Expect(os.WriteFile(store.InventoryPath(), append(data, forged...), 0o600)).To(Succeed())
}

var _ = Describe("verifyInventoryOnce", func() {
	It("counts a tampered inventory, and swallows the failure so the job survives", func() {
		c, store := newRefresherTestCA()
		tamperInventory(store)

		Expect(func() { verifyInventoryOnce(context.Background(), c) }).NotTo(Panic())
		tampered, readErrors := c.InventoryVerifyFailures()
		Expect(tampered).To(Equal(uint64(1)))
		Expect(readErrors).To(BeZero())
	})

	It("counts an inventory it cannot read as a read error, not as tampering", func() {
		c, store := newRefresherTestCA()
		// A directory where the file was: an absent inventory would read as
		// an empty one, which is tampering, not a failed read.
		Expect(os.Remove(store.InventoryPath())).To(Succeed())
		Expect(os.Mkdir(store.InventoryPath(), 0o700)).To(Succeed())

		Expect(func() { verifyInventoryOnce(context.Background(), c) }).NotTo(Panic())
		tampered, readErrors := c.InventoryVerifyFailures()
		Expect(tampered).To(BeZero())
		Expect(readErrors).To(Equal(uint64(1)))
	})

	// The warning is the only log line for a failed pass; docs/metrics.md
	// sends operators to it. Shutdown cancels a pass mid-read, and that must
	// not be logged as a failed check on every stop.
	Context("logging", func() {
		var (
			c   *ca.CA
			buf *bytes.Buffer
		)

		BeforeEach(func() {
			var store *storage.StorageService
			c, store = newRefresherTestCA()
			Expect(os.Remove(store.InventoryPath())).To(Succeed())
			Expect(os.Mkdir(store.InventoryPath(), 0o700)).To(Succeed())

			// Captured only from here, after the fixture has logged its own.
			buf = new(bytes.Buffer)
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })
		})

		It("warns once for a failed pass", func() {
			verifyInventoryOnce(context.Background(), c)
			Expect(strings.Count(buf.String(), "Inventory verification failed")).To(Equal(1))
		})

		It("does not warn for a pass cut short by cancellation", func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			verifyInventoryOnce(ctx, c)
			Expect(buf.String()).NotTo(ContainSubstring("Inventory verification failed"))
		})
	})
})

var _ = Describe("runInventoryVerify", func() {
	tamperedCount := func(c interface{ InventoryVerifyFailures() (uint64, uint64) }) func() uint64 {
		return func() uint64 {
			tampered, _ := c.InventoryVerifyFailures()
			return tampered
		}
	}

	It("detects a tamper made after it started, and returns on cancellation", func() {
		c, store := newRefresherTestCA()
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan struct{})
		go func() {
			runInventoryVerify(ctx, c, 10*time.Millisecond)
			close(done)
		}()
		// If an assertion below fails, the loop must not run on into later
		// specs; the explicit cancel at the end is still what this spec checks.
		DeferCleanup(func() {
			cancel()
			Eventually(done).WithTimeout(2 * time.Second).Should(BeClosed())
		})

		tamperInventory(store)
		Eventually(tamperedCount(c)).
			WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			Should(BeNumerically(">=", 1), "the verification loop did not see the tamper within 2s")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runInventoryVerify did not return after context cancellation")
	})

	// CA.Init has just verified the inventory, so an immediate pass would
	// re-check what it has only just checked. Observable only when the
	// inventory changes before the loop starts.
	It("does not run a pass before its first tick", func() {
		c, store := newRefresherTestCA()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		tamperInventory(store)
		done := make(chan struct{})
		go func() {
			runInventoryVerify(ctx, c, 750*time.Millisecond)
			close(done)
		}()
		// A pass still running when the spec ends would run on against a
		// removed fixture and log into whichever spec comes next.
		DeferCleanup(func() {
			cancel()
			Eventually(done).WithTimeout(2 * time.Second).Should(BeClosed())
		})

		Consistently(tamperedCount(c)).
			WithTimeout(300*time.Millisecond).WithPolling(20*time.Millisecond).
			Should(BeZero(), "the loop must wait for its first tick")

		// ...and then it does verify, so this is not passing by never running.
		Eventually(tamperedCount(c)).
			WithTimeout(3 * time.Second).WithPolling(20 * time.Millisecond).
			Should(BeNumerically(">=", 1))
	})
})
