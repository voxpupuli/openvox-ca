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

package ca_test

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// VerifyInventory is the periodic tamper check that no longer depends on the
// OCSP responder being served. What it must get right is the split between
// its two counters: only a mismatch is a tamper signal, and a backend that is
// merely unreachable must not raise the alert that says somebody edited it.
var _ = Describe("VerifyInventory", func() {
	var myCA *ca.CA

	BeforeEach(func() {
		myCA = setupOCSPCA(GinkgoT().TempDir())
		signedCert(myCA, "verified.example.com")
	})

	It("passes a genuine inventory and counts nothing", func() {
		Expect(myCA.VerifyInventory(context.Background())).To(Succeed())
		tampered, readErrors := myCA.InventoryVerifyFailures()
		Expect(tampered).To(BeZero())
		Expect(readErrors).To(BeZero())
	})

	It("counts an inventory edited behind the CA's back as tampered", func() {
		// A row appended straight to the blob, leaving the stored MAC
		// describing the inventory as it was.
		forged := "0BADC0DE 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /forged.example.com\n"
		data, err := os.ReadFile(myCA.Storage.InventoryPath())
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(myCA.Storage.InventoryPath(), append(data, []byte(forged)...), 0o600)).To(Succeed())

		Expect(myCA.VerifyInventory(context.Background())).To(MatchError(storage.ErrInventoryTampered))
		tampered, readErrors := myCA.InventoryVerifyFailures()
		Expect(tampered).To(Equal(uint64(1)))
		Expect(readErrors).To(BeZero())
	})

	It("counts an unreadable inventory as a read error, not as tampering", func() {
		// A directory where the file was, so the read itself fails. Removing
		// the file would not do: an absent inventory reads as an empty one,
		// and an emptied inventory is exactly the tampering this counts.
		Expect(os.Remove(myCA.Storage.InventoryPath())).To(Succeed())
		Expect(os.Mkdir(myCA.Storage.InventoryPath(), 0o700)).To(Succeed())

		err := myCA.VerifyInventory(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(err).NotTo(MatchError(storage.ErrInventoryTampered))
		tampered, readErrors := myCA.InventoryVerifyFailures()
		Expect(tampered).To(BeZero())
		Expect(readErrors).To(Equal(uint64(1)))
	})

	// Shutdown cancels the job's context mid-pass. Whatever that pass then
	// returns describes the cancellation, not the inventory.
	It("counts nothing for a pass whose context was already cancelled", func() {
		Expect(os.Remove(myCA.Storage.InventoryPath())).To(Succeed())
		Expect(os.Mkdir(myCA.Storage.InventoryPath(), 0o700)).To(Succeed())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		Expect(myCA.VerifyInventory(ctx)).NotTo(Succeed())
		tampered, readErrors := myCA.InventoryVerifyFailures()
		Expect(tampered).To(BeZero())
		Expect(readErrors).To(BeZero())
	})
})
