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

//go:build mysql_integration

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// mysqlDSNFromEnv returns the MySQL/MariaDB DSN to use for integration tests,
// or skips the test if none is configured. The DSN is the go-sql-driver form,
// e.g. "user:pass@tcp(127.0.0.1:3306)/puppetca".
func mysqlDSNFromEnv(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PUPPET_CA_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set PUPPET_CA_TEST_MYSQL_DSN=user:pass@tcp(127.0.0.1:3306)/puppetca to run mysql integration tests")
	}
	return dsn
}

// newMySQLBackend connects to a real MySQL/MariaDB, migrates the schema, and
// truncates the blobs and inventory tables so each test starts clean. Tests in
// a package run sequentially, so shared tables with a per-test truncate are
// sufficient isolation.
func newMySQLBackend(t *testing.T) *SQLBackend {
	t.Helper()
	b, err := NewSQLBackend(SQLConfig{Dialect: SQLMySQL, DSN: mysqlDSNFromEnv(t)})
	if err != nil {
		t.Fatalf("NewSQLBackend: %v", err)
	}
	if err := b.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	for _, table := range []string{"puppet_ca_blobs", "puppet_ca_inventory"} {
		if _, err := b.db.ExecContext(context.Background(), "DELETE FROM "+table); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestMySQLPutGetDelete(t *testing.T) {
	b := newMySQLBackend(t)
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
	if err := b.Put(ctx, KeyCACert, []byte("replaced"), BlobPublic); err != nil {
		t.Fatalf("Put (overwrite): %v", err)
	}
	if got, _ := b.Get(ctx, KeyCACert); string(got) != "replaced" {
		t.Fatalf("after overwrite Get = %q, want replaced", got)
	}
	if err := b.Delete(ctx, KeyCACert); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := b.Delete(ctx, KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete on missing: err = %v, want fs.ErrNotExist", err)
	}
}

func TestMySQLLargeBlob(t *testing.T) {
	// Exceed MySQL's 64 KiB BLOB cap to prove the puppet_ca_blobs.data column was
	// widened to LONGBLOB by the migration. Use KeyCRL: it is a realistic large
	// blob, whereas KeyInventory is now backed by the structured inventory table
	// (which parses writes as inventory.txt lines, not opaque bytes).
	b := newMySQLBackend(t)
	ctx := context.Background()
	big := bytes.Repeat([]byte("x"), 200*1024)
	if err := b.Put(ctx, KeyCRL, big, BlobPrivate); err != nil {
		t.Fatalf("Put large blob: %v", err)
	}
	got, err := b.Get(ctx, KeyCRL)
	if err != nil {
		t.Fatalf("Get large blob: %v", err)
	}
	if !bytes.Equal(got, big) {
		t.Fatalf("large blob round-trip mismatch: got %d bytes, want %d", len(got), len(big))
	}
}

func TestMySQLList(t *testing.T) {
	b := newMySQLBackend(t)
	ctx := context.Background()
	for _, s := range []string{"a.example", "b.example", "c.example"} {
		if err := b.Put(ctx, CSRKey(s), []byte("csr"), BlobPublic); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
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
}

func TestMySQLModTime(t *testing.T) {
	b := newMySQLBackend(t)
	ctx := context.Background()
	if _, err := b.ModTime(ctx, KeyCRL); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ModTime on missing: err = %v, want fs.ErrNotExist", err)
	}
	before := time.Now().Add(-2 * time.Second)
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

func TestMySQLAppendLineConcurrent(t *testing.T) {
	// Two backends over the same database simulate two replicas appending
	// inventory entries; each AppendLine inserts a row and none may be dropped.
	// Inventory is structured, so lines must be valid entries.
	dsn := mysqlDSNFromEnv(t)
	a := newMySQLBackend(t)
	b, err := NewSQLBackend(SQLConfig{Dialect: SQLMySQL, DSN: dsn})
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
		w := w
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

// TestMySQLAcquireLockMutualExclusion asserts that two replicas holding the
// same GET_LOCK name cannot both enter the critical section at once.
func TestMySQLAcquireLockMutualExclusion(t *testing.T) {
	dsn := mysqlDSNFromEnv(t)
	a := newMySQLBackend(t)
	b, err := NewSQLBackend(SQLConfig{Dialect: SQLMySQL, DSN: dsn})
	if err != nil {
		t.Fatalf("NewSQLBackend b: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ulA, err := a.AcquireLock(ctx, "crl")
	if err != nil {
		t.Fatalf("A AcquireLock: %v", err)
	}

	type result struct {
		got time.Time
		err error
	}
	ch := make(chan result, 1)
	startB := time.Now()
	go func() {
		ul, err := b.AcquireLock(ctx, "crl")
		res := result{got: time.Now(), err: err}
		if err == nil {
			_ = ul.Unlock()
		}
		ch <- res
	}()

	time.Sleep(400 * time.Millisecond)
	if err := ulA.Unlock(); err != nil {
		t.Fatalf("A Unlock: %v", err)
	}

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("B AcquireLock: %v", res.err)
		}
		// GET_LOCK is polled with a 1-second granularity, so B may observe the
		// release up to ~1s after A unlocks; assert it waited but don't pin the
		// upper bound tightly.
		if waited := res.got.Sub(startB); waited < 300*time.Millisecond {
			t.Errorf("B acquired after %v; expected to wait while A held the lock", waited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("B never acquired the lock")
	}
}

func TestMySQLAcquireLockDistinctNames(t *testing.T) {
	b := newMySQLBackend(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ul1, err := b.AcquireLock(ctx, "lock-one")
	if err != nil {
		t.Fatalf("AcquireLock one: %v", err)
	}
	ul2, err := b.AcquireLock(ctx, "lock-two")
	if err != nil {
		t.Fatalf("AcquireLock two (distinct name should not block): %v", err)
	}
	if err := ul2.Unlock(); err != nil {
		t.Errorf("Unlock two: %v", err)
	}
	if err := ul1.Unlock(); err != nil {
		t.Errorf("Unlock one: %v", err)
	}
}

func TestMySQLEndToEndViaStorageService(t *testing.T) {
	b := newMySQLBackend(t)
	svc := NewWithBackend(b, filepath.Join(t.TempDir(), "private"))
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
	if inv, _ := svc.ReadInventory(ctx); string(inv) != line1+"\n"+line2+"\n" {
		t.Errorf("ReadInventory = %q, want %q", inv, line1+"\n"+line2+"\n")
	}
	if serial, err := svc.LatestSerialForSubject(ctx, "node2"); err != nil || serial != "0002" {
		t.Errorf("LatestSerialForSubject(node2) = %q, %v; want 0002, nil", serial, err)
	}
	if err := svc.SaveCSR(ctx, "node1", []byte("csr-pem")); err != nil {
		t.Fatalf("SaveCSR: %v", err)
	}
	if csrs, _ := svc.ListCSRs(ctx); len(csrs) != 1 || csrs[0] != "node1" {
		t.Errorf("ListCSRs = %v, want [node1]", csrs)
	}
}
