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

package storage

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// newFilesystemInventoryService returns a StorageService over a fresh
// filesystem backend with the inventory touched, integrity initialised, and
// sampleInventoryLines appended. It mirrors newInventoryService (SQLite) so the
// prune tests can exercise both the structured and blob inventory paths.
func newFilesystemInventoryService() *StorageService {
	ctx := context.Background()
	svc := New(GinkgoT().TempDir())
	Expect(svc.EnsureDirs(ctx)).NotTo(HaveOccurred(), "EnsureDirs")
	Expect(svc.TouchInventory(ctx)).NotTo(HaveOccurred(), "TouchInventory")
	Expect(svc.InitHMAC(ctx)).NotTo(HaveOccurred(), "InitHMAC")
	for _, line := range sampleInventoryLines {
		Expect(svc.AppendInventory(ctx, line)).NotTo(HaveOccurred(), fmt.Sprintf("AppendInventory(%q)", line))
	}
	return svc
}

// keepNotSerial returns a predicate that keeps every entry except the one with
// the given serial.
func keepNotSerial(serial string) func(InventoryEntry) bool {
	return func(e InventoryEntry) bool { return e.Serial != serial }
}

// PruneInventory exercises StorageService.PruneInventory against both the
// structured (SQLite) and blob (filesystem) backends. The critical property is
// that after a prune the integrity head is rewritten so ReadInventory — which
// verifies the HMAC/hash chain — still succeeds; a stale head would surface as
// ErrInventoryTampered.
var _ = Describe("PruneInventory", func() {
	backends := map[string]func() *StorageService{
		"sqlite": func() *StorageService {
			svc, _ := newInventoryService()
			return svc
		},
		"filesystem": newFilesystemInventoryService,
	}

	for name, mk := range backends {
		Context(name, func() {
			It("removes matching entries and rewrites the integrity head", func() {
				ctx := context.Background()
				svc := mk()

				// Drop serial 0002 (node2); node1's 0001 and 0003 must survive in order.
				removed, err := svc.PruneInventory(ctx, keepNotSerial("0002"))
				Expect(err).NotTo(HaveOccurred(), "PruneInventory")
				Expect(removed).To(HaveLen(1), "want one entry serial 0002 subject node2")
				Expect(removed[0].Serial).To(Equal("0002"), "want one entry serial 0002 subject node2")
				Expect(removed[0].Subject).To(Equal("node2"), "want one entry serial 0002 subject node2")

				// ReadInventory verifies the integrity head before returning, so a
				// successful read proves the chain/HMAC was rewritten for the survivors.
				got, err := svc.ReadInventory(ctx)
				Expect(err).NotTo(HaveOccurred(), "ReadInventory after prune (head not rewritten?)")
				want := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n" +
					"0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1\n"
				Expect(got).To(Equal([]byte(want)), "inventory after prune")

				// A subsequent append must extend the rewritten chain cleanly.
				Expect(svc.AppendInventory(ctx, "0004 2024-01-04T00:00:00UTC 2029-01-04T00:00:00UTC /node3")).NotTo(HaveOccurred(), "AppendInventory after prune")
				_, err = svc.ReadInventory(ctx)
				Expect(err).NotTo(HaveOccurred(), "ReadInventory after post-prune append")
			})

			It("no match leaves inventory and head untouched", func() {
				ctx := context.Background()
				svc := mk()

				before, err := svc.ReadInventory(ctx)
				Expect(err).NotTo(HaveOccurred(), "ReadInventory")
				removed, err := svc.PruneInventory(ctx, func(InventoryEntry) bool { return true })
				Expect(err).NotTo(HaveOccurred(), "PruneInventory")
				Expect(removed).To(HaveLen(0), "want none")
				after, err := svc.ReadInventory(ctx)
				Expect(err).NotTo(HaveOccurred(), "ReadInventory after no-op prune")
				Expect(before).To(Equal(after), "inventory changed by no-op prune")
			})
		})
	}
})
