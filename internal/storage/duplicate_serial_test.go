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
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AppendInventory duplicate serial rejection", func() {
	It("rejects a duplicate serial under a different subject on the SQL backend", func() {
		ctx := context.Background()
		b := newSQLiteBackend()
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).NotTo(HaveOccurred())
		Expect(svc.InitHMAC(ctx)).NotTo(HaveOccurred())

		Expect(svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).NotTo(HaveOccurred())

		err := svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node2")
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrDuplicateSerial)).To(BeTrue(), "expected ErrDuplicateSerial, got %v", err)

		entries, err := svc.inventoryEntriesLocked(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1), "the duplicate row must not have been inserted")
	})

	It("rejects a duplicate serial under a different subject on the filesystem backend", func() {
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		be := NewFilesystemBackend(dir)
		svc := NewWithBackend(be, "")
		Expect(svc.EnsureDirs(ctx)).NotTo(HaveOccurred())
		Expect(svc.TouchInventory(ctx)).NotTo(HaveOccurred())
		Expect(svc.InitHMAC(ctx)).NotTo(HaveOccurred())

		Expect(svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).NotTo(HaveOccurred())

		err := svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node2")
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrDuplicateSerial)).To(BeTrue(), "expected ErrDuplicateSerial, got %v", err)

		inv, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(inv)).To(Equal("0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n"),
			"the duplicate line must not have been appended")
	})

	It("rejects a malformed entry on the filesystem backend instead of writing it", func() {
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		be := NewFilesystemBackend(dir)
		svc := NewWithBackend(be, "")
		Expect(svc.EnsureDirs(ctx)).NotTo(HaveOccurred())
		Expect(svc.TouchInventory(ctx)).NotTo(HaveOccurred())
		Expect(svc.InitHMAC(ctx)).NotTo(HaveOccurred())

		err := svc.AppendInventory(ctx, "too few fields")
		Expect(err).To(HaveOccurred())

		inv, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(inv)).To(BeEmpty(), "malformed entry must not have been written")
	})
})

var _ = Describe("StorageService.SerialExists", func() {
	It("reports presence and absence of a serial across the inventory", func() {
		ctx := context.Background()
		b := newSQLiteBackend()
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).NotTo(HaveOccurred())
		Expect(svc.InitHMAC(ctx)).NotTo(HaveOccurred())
		Expect(svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).NotTo(HaveOccurred())

		exists, err := svc.SerialExists(ctx, "0001")
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeTrue())

		exists, err = svc.SerialExists(ctx, "DEADBEEF")
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeFalse())
	})
})
