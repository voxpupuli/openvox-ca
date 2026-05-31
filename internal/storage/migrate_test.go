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
	"os"
	"path/filepath"
	"testing"
)

// seedCA populates a backend with a representative set of CA blobs: every
// singleton plus a couple of per-subject CSRs and signed certs.
func seedCA(t *testing.T, b Backend) map[string][]byte {
	t.Helper()
	ctx := context.Background()
	if err := b.EnsureReady(ctx); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	want := map[string][]byte{
		KeyCACert:        []byte("ca-cert-pem"),
		KeyCAPubKey:      []byte("ca-pub-pem"),
		KeyCAKey:         []byte("ca-key-pem"),
		KeyCRL:           []byte("crl-pem"),
		KeySerial:        []byte("0A"),
		KeyInventory:     []byte("0xABC /CN=a\n"),
		KeyInventoryHMAC: []byte("hmac-bytes"),
		KeyHMACKey:       []byte("hmac-key-bytes"),
		CSRKey("web01"):  []byte("csr-web01"),
		CSRKey("web02"):  []byte("csr-web02"),
		CertKey("web01"): []byte("cert-web01"),
	}
	for k, v := range want {
		if err := b.Put(ctx, k, v, BlobPublic); err != nil {
			t.Fatalf("seed Put %q: %v", k, err)
		}
	}
	return want
}

func TestMigrateCopiesEverything(t *testing.T) {
	ctx := context.Background()
	src := NewFilesystemBackend(t.TempDir())
	want := seedCA(t, src)

	dst := NewFilesystemBackend(t.TempDir())

	report, err := Migrate(ctx, src, dst, MigrateOptions{})
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if report.Singletons != 8 || report.CSRs != 2 || report.Certs != 1 {
		t.Errorf("report = %+v, want 8 singletons, 2 CSRs, 1 cert", report)
	}
	if report.Total() != len(want) {
		t.Errorf("Total = %d, want %d", report.Total(), len(want))
	}

	for k, v := range want {
		got, err := dst.Get(ctx, k)
		if err != nil {
			t.Errorf("dst.Get %q: %v", k, err)
			continue
		}
		if !bytes.Equal(got, v) {
			t.Errorf("dst[%q] = %q, want %q", k, got, v)
		}
	}
}

// TestMigratePreservesVisibility verifies that private singletons land with
// 0600 and public ones with 0644 on a filesystem destination.
func TestMigratePreservesVisibility(t *testing.T) {
	ctx := context.Background()
	src := NewFilesystemBackend(t.TempDir())
	seedCA(t, src)

	dstDir := t.TempDir()
	dst := NewFilesystemBackend(dstDir)
	if _, err := Migrate(ctx, src, dst, MigrateOptions{}); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	cases := []struct {
		key  string
		perm os.FileMode
	}{
		{KeyCACert, FilePermPublic},
		{KeySerial, FilePermPublic},
		{KeyCAKey, FilePermPrivate},
		{KeyInventory, FilePermPrivate},
		{KeyHMACKey, FilePermPrivate},
	}
	for _, c := range cases {
		p := dst.Path(c.key)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %q: %v", p, err)
		}
		if got := info.Mode().Perm(); got != c.perm {
			t.Errorf("%s perm = %o, want %o", c.key, got, c.perm)
		}
	}
}

func TestMigrateRefusesNonEmptyDestination(t *testing.T) {
	ctx := context.Background()
	src := NewFilesystemBackend(t.TempDir())
	seedCA(t, src)

	dst := NewFilesystemBackend(t.TempDir())
	if err := dst.EnsureReady(ctx); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	// Pre-populate the destination with a CA cert.
	if err := dst.Put(ctx, KeyCACert, []byte("existing"), BlobPublic); err != nil {
		t.Fatalf("seed dst: %v", err)
	}

	_, err := Migrate(ctx, src, dst, MigrateOptions{})
	if !errors.Is(err, ErrDestinationNotEmpty) {
		t.Fatalf("err = %v, want ErrDestinationNotEmpty", err)
	}

	// The existing cert must be untouched (no partial copy occurred).
	got, err := dst.Get(ctx, KeyCACert)
	if err != nil || !bytes.Equal(got, []byte("existing")) {
		t.Fatalf("dst CA cert = %q (err %v), want untouched", got, err)
	}

	// --force overwrites it.
	if _, err := Migrate(ctx, src, dst, MigrateOptions{Force: true}); err != nil {
		t.Fatalf("Migrate --force: %v", err)
	}
	got, _ = dst.Get(ctx, KeyCACert)
	if !bytes.Equal(got, []byte("ca-cert-pem")) {
		t.Errorf("after force, dst CA cert = %q, want ca-cert-pem", got)
	}
}

func TestMigrateSkipsAbsentSingletons(t *testing.T) {
	ctx := context.Background()
	src := NewFilesystemBackend(t.TempDir())
	if err := src.EnsureReady(ctx); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	// Only a CA cert and one CSR exist; everything else is absent.
	if err := src.Put(ctx, KeyCACert, []byte("c"), BlobPublic); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := src.Put(ctx, CSRKey("only"), []byte("r"), BlobPublic); err != nil {
		t.Fatalf("seed: %v", err)
	}

	dst := NewFilesystemBackend(t.TempDir())
	report, err := Migrate(ctx, src, dst, MigrateOptions{})
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if report.Singletons != 1 || report.CSRs != 1 || report.Certs != 0 {
		t.Errorf("report = %+v, want 1 singleton, 1 CSR, 0 certs", report)
	}
	// An absent singleton must not be created at the destination.
	if _, err := os.Stat(dst.Path(KeySerial)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("serial unexpectedly present at destination: %v", err)
	}
}

func TestMigrateLogfReceivesEachCopiedBlob(t *testing.T) {
	ctx := context.Background()
	src := NewFilesystemBackend(t.TempDir())
	want := seedCA(t, src)
	dst := NewFilesystemBackend(t.TempDir())

	var lines int
	_, err := Migrate(ctx, src, dst, MigrateOptions{
		Logf: func(string, ...any) { lines++ },
	})
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if lines != len(want) {
		t.Errorf("Logf called %d times, want %d", lines, len(want))
	}
}

// unlockFunc adapts a func to the Unlocker interface.
type unlockFunc func() error

func (f unlockFunc) Unlock() error { return f() }

// lockingBackend wraps a filesystem backend and additionally implements Locker,
// recording every lock acquired and released so tests can assert that
// MigrateService coordinates the copy under a distributed lock.
type lockingBackend struct {
	*FilesystemBackend
	acquired []string
	released int
}

func (b *lockingBackend) AcquireLock(_ context.Context, name string) (Unlocker, error) {
	b.acquired = append(b.acquired, name)
	return unlockFunc(func() error { b.released++; return nil }), nil
}

func TestMigrateServiceLocksBothBackends(t *testing.T) {
	ctx := context.Background()
	srcB := &lockingBackend{FilesystemBackend: NewFilesystemBackend(t.TempDir())}
	want := seedCA(t, srcB)
	dstB := &lockingBackend{FilesystemBackend: NewFilesystemBackend(t.TempDir())}

	src := NewWithBackend(srcB, t.TempDir())
	dst := NewWithBackend(dstB, t.TempDir())

	report, err := MigrateService(ctx, src, dst, MigrateOptions{})
	if err != nil {
		t.Fatalf("MigrateService: %v", err)
	}
	if report.Total() != len(want) {
		t.Errorf("Total = %d, want %d", report.Total(), len(want))
	}

	for label, b := range map[string]*lockingBackend{"source": srcB, "destination": dstB} {
		if len(b.acquired) != 1 || b.acquired[0] != migrateLockName {
			t.Errorf("%s locks acquired = %v, want [%q]", label, b.acquired, migrateLockName)
		}
		if b.released != 1 {
			t.Errorf("%s locks released = %d, want 1", label, b.released)
		}
	}

	// The data was actually copied under the lock.
	got, err := dstB.Get(ctx, KeyCACert)
	if err != nil || !bytes.Equal(got, want[KeyCACert]) {
		t.Fatalf("dst CA cert = %q (err %v), want copied", got, err)
	}
}

// TestMigrateServiceWithoutLocker confirms MigrateService still works against
// backends that do not implement Locker (it falls back to a process-local
// mutex via WithLock).
func TestMigrateServiceWithoutLocker(t *testing.T) {
	ctx := context.Background()
	srcB := NewFilesystemBackend(t.TempDir())
	want := seedCA(t, srcB)
	dstB := NewFilesystemBackend(t.TempDir())

	src := NewWithBackend(srcB, t.TempDir())
	dst := NewWithBackend(dstB, t.TempDir())

	report, err := MigrateService(ctx, src, dst, MigrateOptions{})
	if err != nil {
		t.Fatalf("MigrateService: %v", err)
	}
	if report.Total() != len(want) {
		t.Errorf("Total = %d, want %d", report.Total(), len(want))
	}
}

// TestMigrateRoundTripsLocalFileLayout sanity-checks that a migrated
// filesystem destination is readable as a normal on-disk CA (paths exist where
// the filesystem backend expects them).
func TestMigrateRoundTripsLocalFileLayout(t *testing.T) {
	ctx := context.Background()
	src := NewFilesystemBackend(t.TempDir())
	seedCA(t, src)

	dstDir := t.TempDir()
	dst := NewFilesystemBackend(dstDir)
	if _, err := Migrate(ctx, src, dst, MigrateOptions{}); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Spot-check a couple of well-known on-disk paths.
	for _, rel := range []string{"ca_crt.pem", filepath.Join("private", "ca_key.pem"), filepath.Join("requests", "web01.pem")} {
		if _, err := os.Stat(filepath.Join(dstDir, rel)); err != nil {
			t.Errorf("expected %s on disk: %v", rel, err)
		}
	}
}
