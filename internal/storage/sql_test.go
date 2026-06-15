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
	"path/filepath"
	"sort"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// newSQLiteBackend returns a SQLBackend over a fresh temp-file SQLite database
// with the schema migrated. The pure-Go modernc.org/sqlite driver means this
// runs in a normal `go test` with no external services and no CGO.
func newSQLiteBackend() *SQLBackend {
	dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")
	b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
	Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
	Expect(b.EnsureReady(context.Background())).NotTo(HaveOccurred(), "EnsureReady")
	DeferCleanup(func() { _ = b.Close() })
	return b
}

var _ = Describe("SQLitePutGetDelete", func() {
	It("puts, gets, overwrites, and deletes a blob", func() {
		b := newSQLiteBackend()
		ctx := context.Background()

		_, err := b.Get(ctx, KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Get on missing key")
		payload := []byte("pem-data")
		Expect(b.Put(ctx, KeyCACert, payload, BlobPublic)).NotTo(HaveOccurred(), "Put")
		got, err := b.Get(ctx, KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "Get")
		Expect(got).To(Equal(payload))

		// Overwrite replaces rather than appends.
		Expect(b.Put(ctx, KeyCACert, []byte("replaced"), BlobPublic)).NotTo(HaveOccurred(), "Put (overwrite)")
		got, _ = b.Get(ctx, KeyCACert)
		Expect(string(got)).To(Equal("replaced"))

		ok, err := b.Exists(ctx, KeyCACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())

		Expect(b.Delete(ctx, KeyCACert)).NotTo(HaveOccurred(), "Delete")
		err = b.Delete(ctx, KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Delete on missing")
		ok, _ = b.Exists(ctx, KeyCACert)
		Expect(ok).To(BeFalse(), "Exists = true after Delete")
	})
})

var _ = Describe("SQLiteEmptyBlobIsNotAbsent", func() {
	It("returns a non-nil empty slice for a present-but-empty blob", func() {
		b := newSQLiteBackend()
		ctx := context.Background()
		Expect(b.Put(ctx, KeyInventory, []byte{}, BlobPrivate)).NotTo(HaveOccurred(), "Put empty")
		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred(), "Get empty")
		Expect(got).NotTo(BeNil(), "Get returned nil for present-but-empty blob, want non-nil empty slice")
		Expect(got).To(HaveLen(0))
	})
})

var _ = Describe("SQLiteListCSR", func() {
	It("lists CSRs without leaking signed certs and errors on unsupported prefixes", func() {
		b := newSQLiteBackend()
		ctx := context.Background()
		subjects := []string{"a.example", "b.example", "c.example"}
		for _, s := range subjects {
			Expect(b.Put(ctx, CSRKey(s), []byte("csr"), BlobPublic)).NotTo(HaveOccurred(), "Put")
		}
		// A signed cert must not leak into the CSR listing.
		Expect(b.Put(ctx, CertKey("a.example"), []byte("cert"), BlobPublic)).NotTo(HaveOccurred(), "Put cert")

		csrs, err := b.List(ctx, csrPrefix)
		Expect(err).NotTo(HaveOccurred(), "List")
		sort.Strings(csrs)
		want := []string{CSRKey("a.example"), CSRKey("b.example"), CSRKey("c.example")}
		Expect(fmt.Sprint(csrs)).To(Equal(fmt.Sprint(want)))

		_, err = b.List(ctx, "bogus/")
		Expect(err).To(HaveOccurred(), "List with unsupported prefix: want error, got nil")
	})
})

var _ = Describe("SQLiteModTime", func() {
	It("reports a recent mod time after a Put and errors on a missing key", func() {
		b := newSQLiteBackend()
		ctx := context.Background()

		_, err := b.ModTime(ctx, KeyCRL)
		Expect(err).To(MatchError(fs.ErrNotExist), "ModTime on missing")
		before := time.Now().Add(-time.Second)
		Expect(b.Put(ctx, KeyCRL, []byte("crl"), BlobPublic)).NotTo(HaveOccurred(), "Put")
		mt, err := b.ModTime(ctx, KeyCRL)
		Expect(err).NotTo(HaveOccurred(), "ModTime")
		Expect(mt.Before(before)).To(BeFalse(), fmt.Sprintf("ModTime = %v, want >= %v", mt, before))
	})
})

var _ = Describe("SQLiteAppendLineConcurrent", func() {
	It("does not drop entries when two backends append concurrently", func() {
		// Two backends over the same database file simulate two replicas appending
		// inventory entries concurrently; each AppendLine inserts a row and no entry
		// may be dropped. Inventory is structured, so lines must be valid entries.
		dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")
		a, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend a")
		defer a.Close()
		Expect(a.EnsureReady(context.Background())).NotTo(HaveOccurred(), "EnsureReady")
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend b")
		defer b.Close()

		const writers = 4
		const perWriter = 25
		var wg sync.WaitGroup
		wg.Add(writers)
		for w := 0; w < writers; w++ {
			backend := a
			if w%2 == 1 {
				backend = b
			}
			go func() {
				defer wg.Done()
				for i := 0; i < perWriter; i++ {
					line := fmt.Sprintf("%04d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /w%d-i%d\n", w*perWriter+i, w, i)
					if err := backend.AppendLine(context.Background(), KeyInventory, []byte(line), BlobPrivate); err != nil {
						Expect(err).NotTo(HaveOccurred(), "AppendLine")
						return
					}
				}
			}()
		}
		wg.Wait()

		data, err := a.Get(context.Background(), KeyInventory)
		Expect(err).NotTo(HaveOccurred(), "Get")
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
		Expect(lines).To(HaveLen(writers * perWriter))
	})
})

var _ = Describe("SQLiteEnsureReadyIdempotent", func() {
	It("treats a second EnsureReady as a no-op that preserves data", func() {
		b := newSQLiteBackend()
		// Migrations already applied by the helper; a second run must be a no-op
		// and must not error or wipe data.
		Expect(b.Put(context.Background(), KeySerial, []byte("0002"), BlobPublic)).NotTo(HaveOccurred(), "Put")
		Expect(b.EnsureReady(context.Background())).NotTo(HaveOccurred(), "second EnsureReady")
		got, err := b.Get(context.Background(), KeySerial)
		Expect(err).NotTo(HaveOccurred(), "Get after re-migrate")
		Expect(string(got)).To(Equal("0002"), "data lost across re-migrate")
	})
})

var _ = Describe("SQLiteDistributedLockingUnsupported", func() {
	It("reports distributed locking unsupported and falls back to a local mutex", func() {
		b := newSQLiteBackend()
		// SQLite is single-node: it must report the lock as unsupported so
		// StorageService falls back to a process-local mutex.
		_, err := b.AcquireLock(context.Background(), "bootstrap")
		Expect(err).To(MatchError(ErrDistributedLockingUnsupported), "AcquireLock")

		// WithLock over the service must still serialise via the local fallback.
		svc := NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
		var n int
		err = svc.WithLock(context.Background(), "bootstrap", func() error {
			n++
			return nil
		})
		Expect(err).NotTo(HaveOccurred(), "WithLock")
		Expect(n).To(Equal(1), "fn ran wrong number of times")
	})
})

var _ = Describe("SQLiteEndToEndViaStorageService", func() {
	It("round-trips the content-oriented API over the SQL backend", func() {
		// Round-trip through StorageService to validate the content-oriented API
		// works over the SQL backend as it does over the filesystem backend.
		b := newSQLiteBackend()
		tmp := GinkgoT().TempDir()
		svc := NewWithBackend(b, filepath.Join(tmp, "private"))
		ctx := context.Background()

		Expect(svc.EnsureDirs(ctx)).NotTo(HaveOccurred(), "EnsureDirs")
		Expect(svc.SaveCACert(ctx, []byte("ca-cert-pem"))).NotTo(HaveOccurred(), "SaveCACert")
		ok, _ := svc.HasCACert(ctx)
		Expect(ok).To(BeTrue(), "HasCACert = false after SaveCACert")

		Expect(svc.WriteSerial(ctx, "0001")).NotTo(HaveOccurred(), "WriteSerial")
		got, _ := svc.GetSerial(ctx)
		Expect(string(got)).To(Equal("0001"), "GetSerial")

		Expect(svc.InitHMAC(ctx)).NotTo(HaveOccurred(), "InitHMAC")
		line1 := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1"
		line2 := "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2"
		Expect(svc.AppendInventory(ctx, line1)).NotTo(HaveOccurred(), "AppendInventory")
		Expect(svc.AppendInventory(ctx, line2)).NotTo(HaveOccurred(), "AppendInventory")
		inv, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory")
		Expect(string(inv)).To(Equal(line1 + "\n" + line2 + "\n"))
		serial, err := svc.LatestSerialForSubject(ctx, "node2")
		Expect(err).NotTo(HaveOccurred(), "LatestSerialForSubject(node2)")
		Expect(serial).To(Equal("0002"), "LatestSerialForSubject(node2)")

		Expect(svc.SaveCSR(ctx, "node1", []byte("csr-pem"))).NotTo(HaveOccurred(), "SaveCSR")
		Expect(svc.SaveCert(ctx, "node1", []byte("cert-pem"))).NotTo(HaveOccurred(), "SaveCert")
		csrs, _ := svc.ListCSRs(ctx)
		Expect(csrs).To(HaveLen(1), "ListCSRs")
		Expect(csrs[0]).To(Equal("node1"), "ListCSRs")
		certs, _ := svc.ListCerts(ctx)
		Expect(certs).To(HaveLen(1), "ListCerts")
		Expect(certs[0]).To(Equal("node1"), "ListCerts")
	})
})
