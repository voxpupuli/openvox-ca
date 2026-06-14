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
	"bytes"
	"context"
	"fmt"
	"io/fs"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// sampleInventoryLines is a small inventory with a repeated subject (node1
// appears twice; its later serial 0003 is the current one).
var sampleInventoryLines = []string{
	"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1",
	"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2",
	"0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1",
}

// newInventoryService returns a StorageService over a fresh SQLite backend with
// the inventory touched, integrity initialised, and sampleInventoryLines
// appended. The backend is returned so tests can tamper with rows directly.
func newInventoryService() (*StorageService, *SQLBackend) {
	ctx := context.Background()
	b := newSQLiteBackend()
	svc := NewWithBackend(b, "")
	Expect(svc.TouchInventory(ctx)).NotTo(HaveOccurred(), "TouchInventory")
	Expect(svc.InitHMAC(ctx)).NotTo(HaveOccurred(), "InitHMAC")
	for _, line := range sampleInventoryLines {
		Expect(svc.AppendInventory(ctx, line)).NotTo(HaveOccurred(), fmt.Sprintf("AppendInventory(%q)", line))
	}
	return svc, b
}

var _ = Describe("SQLiteInventoryLatestSerialForSubject", func() {
	It("returns the most recent serial per subject and errors on unknown subjects", func() {
		ctx := context.Background()
		svc, _ := newInventoryService()

		// node1 was issued twice; the most recent serial wins.
		got, err := svc.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred(), "LatestSerialForSubject(node1)")
		Expect(got).To(Equal("0003"), "LatestSerialForSubject(node1)")
		got, err = svc.LatestSerialForSubject(ctx, "node2")
		Expect(err).NotTo(HaveOccurred(), "LatestSerialForSubject(node2)")
		Expect(got).To(Equal("0002"), "LatestSerialForSubject(node2)")

		// An unknown subject wraps fs.ErrNotExist.
		_, err = svc.LatestSerialForSubject(ctx, "ghost")
		Expect(err).To(MatchError(fs.ErrNotExist), "LatestSerialForSubject(ghost)")
	})
})

var _ = Describe("SQLiteInventorySerialUnique", func() {
	It("rejects a duplicate serial via the unique index", func() {
		ctx := context.Background()
		svc, _ := newInventoryService()

		// sampleInventoryLines already issued serial 0001 to node1. Re-using it for
		// a different subject must be rejected by the unique index on serial.
		dup := "0001 2024-02-01T00:00:00UTC 2029-02-01T00:00:00UTC /someother"
		Expect(svc.AppendInventory(ctx, dup)).To(HaveOccurred(), "AppendInventory with duplicate serial succeeded; want a unique-constraint error")
	})
})

var _ = Describe("SQLiteInventoryRenderByteIdentical", func() {
	It("renders the inventory byte-for-byte", func() {
		ctx := context.Background()
		svc, _ := newInventoryService()

		var want bytes.Buffer
		for _, line := range sampleInventoryLines {
			want.WriteString(line)
			want.WriteByte('\n')
		}

		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory")
		Expect(got).To(Equal(want.Bytes()))
	})
})

// SQLiteInventoryChainTamperDetection asserts the hash chain detects every
// kind of out-of-band edit to the inventory table: modification, insertion, and
// deletion of a row. Each mutates rows directly via the backend's db handle,
// bypassing AppendEntry so the stored head is not advanced.
var _ = Describe("SQLiteInventoryChainTamperDetection", func() {
	ctx := context.Background()

	It("modified row", func() {
		svc, b := newInventoryService()
		_, err := b.db.NewUpdate().
			Model((*sqlInventoryRow)(nil)).
			Set("serial = ?", "DEAD").
			Where("subject = ?", "node2").
			Exec(ctx)
		Expect(err).NotTo(HaveOccurred(), "tamper update")
		_, err = svc.ReadInventory(ctx)
		Expect(err).To(MatchError(ErrInventoryTampered), "ReadInventory")
	})

	It("inserted row", func() {
		svc, b := newInventoryService()
		_, err := b.db.NewInsert().
			Model(&sqlInventoryRow{
				Serial:    "9999",
				Subject:   "rogue",
				NotBefore: "2024-06-01T00:00:00UTC",
				NotAfter:  "2029-06-01T00:00:00UTC",
			}).
			Exec(ctx)
		Expect(err).NotTo(HaveOccurred(), "tamper insert")
		_, err = svc.ReadInventory(ctx)
		Expect(err).To(MatchError(ErrInventoryTampered), "ReadInventory")
	})

	It("deleted row", func() {
		svc, b := newInventoryService()
		_, err := b.db.NewDelete().
			Model((*sqlInventoryRow)(nil)).
			Where("subject = ?", "node2").
			Exec(ctx)
		Expect(err).NotTo(HaveOccurred(), "tamper delete")
		_, err = svc.ReadInventory(ctx)
		Expect(err).To(MatchError(ErrInventoryTampered), "ReadInventory")
	})
})

// InventoryMigrationRoundTrip migrates an inventory filesystem → sqlite →
// filesystem and asserts entries survive byte-for-byte and integrity verifies
// at each hop, even though the filesystem backend hashes the whole blob while
// the SQL backend uses a hash chain.
var _ = Describe("InventoryMigrationRoundTrip", func() {
	It("preserves entries and integrity across fs→sqlite→fs", func() {
		ctx := context.Background()

		// Source filesystem CA with inventory + integrity.
		src := New(GinkgoT().TempDir())
		Expect(src.EnsureDirs(ctx)).NotTo(HaveOccurred(), "EnsureDirs")
		Expect(src.SaveCACert(ctx, []byte("ca-cert-pem"))).NotTo(HaveOccurred(), "SaveCACert")
		Expect(src.TouchInventory(ctx)).NotTo(HaveOccurred(), "TouchInventory")
		Expect(src.InitHMAC(ctx)).NotTo(HaveOccurred(), "InitHMAC")
		for _, line := range sampleInventoryLines {
			Expect(src.AppendInventory(ctx, line)).NotTo(HaveOccurred(), "AppendInventory")
		}
		srcText, err := src.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory(src)")

		// Migrate filesystem → sqlite.
		sqlite := NewWithBackend(newSQLiteBackend(), "")
		_, err = MigrateService(ctx, src, sqlite, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "MigrateService fs→sqlite")
		// Integrity must verify on the structured destination.
		Expect(sqlite.InitHMAC(ctx)).NotTo(HaveOccurred(), "sqlite integrity after migrate")
		got, _ := sqlite.ReadInventory(ctx)
		Expect(got).To(Equal(srcText), "sqlite inventory")
		s, err := sqlite.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred(), "sqlite LatestSerialForSubject(node1)")
		Expect(s).To(Equal("0003"), "sqlite LatestSerialForSubject(node1)")

		// Migrate sqlite → a second filesystem CA.
		dst := New(GinkgoT().TempDir())
		_, err = MigrateService(ctx, sqlite, dst, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "MigrateService sqlite→fs")
		Expect(dst.InitHMAC(ctx)).NotTo(HaveOccurred(), "fs integrity after round-trip")
		got, _ = dst.ReadInventory(ctx)
		Expect(got).To(Equal(srcText), "round-tripped inventory")
	})
})
