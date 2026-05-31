// Copyright (C) 2026 Chris Boot
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
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// newSQLiteBackend returns a SQLBackend over a fresh temp-file SQLite database
// with the schema migrated. The pure-Go modernc.org/sqlite driver means this
// runs in a normal `go test` with no external services and no CGO.
func newSQLiteBackend(t *testing.T) *SQLBackend {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "ca.db")
	b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
	if err != nil {
		t.Fatalf("NewSQLBackend: %v", err)
	}
	if err := b.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestSQLitePutGetDelete(t *testing.T) {
	b := newSQLiteBackend(t)
	ctx := context.Background()

	if _, err := b.Get(ctx, KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Get on missing key: err = %v, want fs.ErrNotExist", err)
	}
	payload := []byte("pem-data")
	if err := b.Put(ctx, KeyCACert, payload, BlobPublic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(ctx, KeyCACert)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get returned %q, want %q", got, payload)
	}

	// Overwrite replaces rather than appends.
	if err := b.Put(ctx, KeyCACert, []byte("replaced"), BlobPublic); err != nil {
		t.Fatalf("Put (overwrite): %v", err)
	}
	got, _ = b.Get(ctx, KeyCACert)
	if string(got) != "replaced" {
		t.Fatalf("after overwrite Get = %q, want %q", got, "replaced")
	}

	ok, err := b.Exists(ctx, KeyCACert)
	if err != nil || !ok {
		t.Fatalf("Exists = (%v, %v), want (true, nil)", ok, err)
	}

	if err := b.Delete(ctx, KeyCACert); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := b.Delete(ctx, KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete on missing: err = %v, want fs.ErrNotExist", err)
	}
	if ok, _ := b.Exists(ctx, KeyCACert); ok {
		t.Fatalf("Exists = true after Delete")
	}
}

func TestSQLiteEmptyBlobIsNotAbsent(t *testing.T) {
	b := newSQLiteBackend(t)
	ctx := context.Background()
	if err := b.Put(ctx, KeyInventory, []byte{}, BlobPrivate); err != nil {
		t.Fatalf("Put empty: %v", err)
	}
	got, err := b.Get(ctx, KeyInventory)
	if err != nil {
		t.Fatalf("Get empty: %v", err)
	}
	if got == nil {
		t.Fatalf("Get returned nil for present-but-empty blob, want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("Get returned %q, want empty", got)
	}
}

func TestSQLiteListCSR(t *testing.T) {
	b := newSQLiteBackend(t)
	ctx := context.Background()
	subjects := []string{"a.example", "b.example", "c.example"}
	for _, s := range subjects {
		if err := b.Put(ctx, CSRKey(s), []byte("csr"), BlobPublic); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	// A signed cert must not leak into the CSR listing.
	if err := b.Put(ctx, CertKey("a.example"), []byte("cert"), BlobPublic); err != nil {
		t.Fatalf("Put cert: %v", err)
	}

	csrs, err := b.List(ctx, csrPrefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(csrs)
	want := []string{CSRKey("a.example"), CSRKey("b.example"), CSRKey("c.example")}
	if fmt.Sprint(csrs) != fmt.Sprint(want) {
		t.Errorf("List = %v, want %v", csrs, want)
	}

	if _, err := b.List(ctx, "bogus/"); err == nil {
		t.Errorf("List with unsupported prefix: want error, got nil")
	}
}

func TestSQLiteModTime(t *testing.T) {
	b := newSQLiteBackend(t)
	ctx := context.Background()

	if _, err := b.ModTime(ctx, KeyCRL); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ModTime on missing: err = %v, want fs.ErrNotExist", err)
	}
	before := time.Now().Add(-time.Second)
	if err := b.Put(ctx, KeyCRL, []byte("crl"), BlobPublic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	mt, err := b.ModTime(ctx, KeyCRL)
	if err != nil {
		t.Fatalf("ModTime: %v", err)
	}
	if mt.Before(before) {
		t.Errorf("ModTime = %v, want >= %v", mt, before)
	}
}

func TestSQLiteAppendLineConcurrent(t *testing.T) {
	// Two backends over the same database file simulate two replicas appending
	// inventory entries concurrently; each AppendLine inserts a row and no entry
	// may be dropped. Inventory is structured, so lines must be valid entries.
	dsn := "file:" + filepath.Join(t.TempDir(), "ca.db")
	a, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
	if err != nil {
		t.Fatalf("NewSQLBackend a: %v", err)
	}
	defer a.Close()
	if err := a.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
	if err != nil {
		t.Fatalf("NewSQLBackend b: %v", err)
	}
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
					t.Errorf("AppendLine: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	data, err := a.Get(context.Background(), KeyInventory)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
	if len(lines) != writers*perWriter {
		t.Errorf("got %d lines, want %d", len(lines), writers*perWriter)
	}
}

func TestSQLiteEnsureReadyIdempotent(t *testing.T) {
	b := newSQLiteBackend(t)
	// Migrations already applied by the helper; a second run must be a no-op
	// and must not error or wipe data.
	if err := b.Put(context.Background(), KeySerial, []byte("0002"), BlobPublic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := b.EnsureReady(context.Background()); err != nil {
		t.Fatalf("second EnsureReady: %v", err)
	}
	got, err := b.Get(context.Background(), KeySerial)
	if err != nil {
		t.Fatalf("Get after re-migrate: %v", err)
	}
	if string(got) != "0002" {
		t.Errorf("data lost across re-migrate: got %q", got)
	}
}

func TestSQLiteDistributedLockingUnsupported(t *testing.T) {
	b := newSQLiteBackend(t)
	// SQLite is single-node: it must report the lock as unsupported so
	// StorageService falls back to a process-local mutex.
	if _, err := b.AcquireLock(context.Background(), "bootstrap"); !errors.Is(err, ErrDistributedLockingUnsupported) {
		t.Fatalf("AcquireLock err = %v, want ErrDistributedLockingUnsupported", err)
	}

	// WithLock over the service must still serialise via the local fallback.
	svc := NewWithBackend(b, filepath.Join(t.TempDir(), "private"))
	var n int
	err := svc.WithLock(context.Background(), "bootstrap", func() error {
		n++
		return nil
	})
	if err != nil {
		t.Fatalf("WithLock: %v", err)
	}
	if n != 1 {
		t.Fatalf("fn ran %d times, want 1", n)
	}
}

func TestSQLiteEndToEndViaStorageService(t *testing.T) {
	// Round-trip through StorageService to validate the content-oriented API
	// works over the SQL backend as it does over the filesystem backend.
	b := newSQLiteBackend(t)
	tmp := t.TempDir()
	svc := NewWithBackend(b, filepath.Join(tmp, "private"))
	ctx := context.Background()

	if err := svc.EnsureDirs(ctx); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := svc.SaveCACert(ctx, []byte("ca-cert-pem")); err != nil {
		t.Fatalf("SaveCACert: %v", err)
	}
	if ok, _ := svc.HasCACert(ctx); !ok {
		t.Errorf("HasCACert = false after SaveCACert")
	}

	if err := svc.WriteSerial(ctx, "0001"); err != nil {
		t.Fatalf("WriteSerial: %v", err)
	}
	if got, _ := svc.GetSerial(ctx); string(got) != "0001" {
		t.Errorf("GetSerial = %q, want 0001", got)
	}

	if err := svc.InitHMAC(ctx); err != nil {
		t.Fatalf("InitHMAC: %v", err)
	}
	line1 := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1"
	line2 := "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2"
	if err := svc.AppendInventory(ctx, line1); err != nil {
		t.Fatalf("AppendInventory: %v", err)
	}
	if err := svc.AppendInventory(ctx, line2); err != nil {
		t.Fatalf("AppendInventory: %v", err)
	}
	inv, err := svc.ReadInventory(ctx)
	if err != nil {
		t.Fatalf("ReadInventory: %v", err)
	}
	if string(inv) != line1+"\n"+line2+"\n" {
		t.Errorf("ReadInventory = %q, want %q", inv, line1+"\n"+line2+"\n")
	}
	if serial, err := svc.LatestSerialForSubject(ctx, "node2"); err != nil || serial != "0002" {
		t.Errorf("LatestSerialForSubject(node2) = %q, %v; want 0002, nil", serial, err)
	}

	if err := svc.SaveCSR(ctx, "node1", []byte("csr-pem")); err != nil {
		t.Fatalf("SaveCSR: %v", err)
	}
	if err := svc.SaveCert(ctx, "node1", []byte("cert-pem")); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}
	if csrs, _ := svc.ListCSRs(ctx); len(csrs) != 1 || csrs[0] != "node1" {
		t.Errorf("ListCSRs = %v, want [node1]", csrs)
	}
	if certs, _ := svc.ListCerts(ctx); len(certs) != 1 || certs[0] != "node1" {
		t.Errorf("ListCerts = %v, want [node1]", certs)
	}
}
