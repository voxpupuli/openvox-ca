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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// overlayTestSetup returns an OverlayBackend wrapping a filesystem base, with
// KeyCACert and KeyCAKey overridden to explicit local files outside baseDir.
func overlayTestSetup(t *testing.T) (*OverlayBackend, string, string, string) {
	t.Helper()
	baseDir := t.TempDir()
	overlayDir := t.TempDir()
	certPath := filepath.Join(overlayDir, "ca_crt.pem")
	keyPath := filepath.Join(overlayDir, "ca_key.pem")

	base := NewFilesystemBackend(baseDir)
	if err := base.EnsureReady(); err != nil {
		t.Fatalf("base EnsureReady: %v", err)
	}
	ov, err := NewOverlayBackend(base, map[string]string{
		KeyCACert: certPath,
		KeyCAKey:  keyPath,
	})
	if err != nil {
		t.Fatalf("NewOverlayBackend: %v", err)
	}
	if err := ov.EnsureReady(); err != nil {
		t.Fatalf("overlay EnsureReady: %v", err)
	}
	return ov, baseDir, certPath, keyPath
}

func TestOverlayBackendPutGetDelete(t *testing.T) {
	ov, baseDir, certPath, keyPath := overlayTestSetup(t)

	// Override keys: file doesn't exist yet.
	if _, err := ov.Get(KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Get missing override: err = %v, want fs.ErrNotExist", err)
	}
	ok, err := ov.Exists(KeyCACert)
	if err != nil || ok {
		t.Fatalf("Exists missing override: ok=%v err=%v", ok, err)
	}

	// Put a cert via the override: lands on the explicit path, not baseDir.
	certData := []byte("cert-pem-data")
	if err := ov.Put(KeyCACert, certData, BlobPublic); err != nil {
		t.Fatalf("Put cert: %v", err)
	}
	onDisk, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading override path: %v", err)
	}
	if !bytes.Equal(onDisk, certData) {
		t.Errorf("override file = %q, want %q", onDisk, certData)
	}
	// Base dir should NOT contain ca_crt.pem since the cert is overridden.
	if _, err := os.Stat(filepath.Join(baseDir, "ca_crt.pem")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("base dir unexpectedly contains ca_crt.pem: err=%v", err)
	}

	// Put a key via the override: private permissions.
	keyData := []byte("key-pem-data")
	if err := ov.Put(KeyCAKey, keyData, BlobPrivate); err != nil {
		t.Fatalf("Put key: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat override key path: %v", err)
	}
	if info.Mode().Perm() != FilePermPrivate {
		t.Errorf("override key perm = %v, want %v", info.Mode().Perm(), os.FileMode(FilePermPrivate))
	}

	// Non-overridden keys are delegated to the base filesystem backend.
	if err := ov.Put(KeySerial, []byte("0001"), BlobPublic); err != nil {
		t.Fatalf("Put serial: %v", err)
	}
	baseSerial, err := os.ReadFile(filepath.Join(baseDir, "serial"))
	if err != nil {
		t.Fatalf("reading base serial: %v", err)
	}
	if string(baseSerial) != "0001" {
		t.Errorf("base serial = %q, want 0001", baseSerial)
	}

	// Delete via override.
	if err := ov.Delete(KeyCACert); err != nil {
		t.Fatalf("Delete override: %v", err)
	}
	if err := ov.Delete(KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Delete missing: err = %v, want fs.ErrNotExist", err)
	}
}

func TestOverlayBackendReadsPreexistingFile(t *testing.T) {
	// Simulate an operator who supplies a CA cert file. The server must read
	// it via Get without ever writing to it.
	baseDir := t.TempDir()
	overlayDir := t.TempDir()
	certPath := filepath.Join(overlayDir, "preexisting.pem")
	supplied := []byte("operator-supplied-cert")
	if err := os.WriteFile(certPath, supplied, 0o644); err != nil {
		t.Fatal(err)
	}

	base := NewFilesystemBackend(baseDir)
	ov, err := NewOverlayBackend(base, map[string]string{KeyCACert: certPath})
	if err != nil {
		t.Fatalf("NewOverlayBackend: %v", err)
	}

	got, err := ov.Get(KeyCACert)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, supplied) {
		t.Errorf("Get = %q, want %q", got, supplied)
	}
	ok, err := ov.Exists(KeyCACert)
	if err != nil || !ok {
		t.Errorf("Exists = %v, %v; want true, nil", ok, err)
	}
}

func TestOverlayBackendAppendLineRejectsOverride(t *testing.T) {
	ov, _, _, _ := overlayTestSetup(t)
	// KeyInventory is not overridden, so append should work and land in base.
	if err := ov.AppendLine(KeyInventory, []byte("line\n"), BlobPrivate); err != nil {
		t.Fatalf("AppendLine to non-overridden key: %v", err)
	}
	// Force an override on KeyInventory and confirm AppendLine refuses.
	ov.overrides[KeyInventory] = "/tmp/should-not-append"
	if err := ov.AppendLine(KeyInventory, []byte("line\n"), BlobPrivate); err == nil {
		t.Errorf("AppendLine on overridden key should error")
	}
}

func TestOverlayBackendPathProvider(t *testing.T) {
	ov, baseDir, certPath, _ := overlayTestSetup(t)
	if got := ov.Path(KeyCACert); got != certPath {
		t.Errorf("Path(CACert) = %q, want %q", got, certPath)
	}
	// Non-overridden key falls through to base filesystem mapping.
	if got := ov.Path(KeySerial); got != filepath.Join(baseDir, "serial") {
		t.Errorf("Path(Serial) = %q, want %q", got, filepath.Join(baseDir, "serial"))
	}
	if got := ov.BaseDir(); got != baseDir {
		t.Errorf("BaseDir = %q, want %q", got, baseDir)
	}
}

func TestOverlayBackendRequiresNonEmptyOverride(t *testing.T) {
	base := NewFilesystemBackend(t.TempDir())
	if _, err := NewOverlayBackend(base, nil); err == nil {
		t.Errorf("nil overrides should error")
	}
	if _, err := NewOverlayBackend(base, map[string]string{KeyCACert: ""}); err == nil {
		t.Errorf("all-empty overrides should error")
	}
	if _, err := NewOverlayBackend(nil, map[string]string{KeyCACert: "/tmp/x"}); err == nil {
		t.Errorf("nil base should error")
	}
}

func TestOverlayBackendImplementsBackend(t *testing.T) {
	var _ Backend = (*OverlayBackend)(nil)
	var _ PathProvider = (*OverlayBackend)(nil)
}
