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
	"io/fs"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// overlayTestSetup returns an OverlayBackend wrapping a filesystem base, with
// KeyCACert and KeyCAKey overridden to explicit local files outside baseDir.
func overlayTestSetup() (*OverlayBackend, string, string, string) {
	baseDir := GinkgoT().TempDir()
	overlayDir := GinkgoT().TempDir()
	certPath := filepath.Join(overlayDir, "ca_crt.pem")
	keyPath := filepath.Join(overlayDir, "ca_key.pem")

	base := NewFilesystemBackend(baseDir)
	err := base.EnsureReady(context.Background())
	Expect(err).NotTo(HaveOccurred(), "base EnsureReady: %v", err)
	ov, err := NewOverlayBackend(base, map[string]string{
		KeyCACert: certPath,
		KeyCAKey:  keyPath,
	})
	Expect(err).NotTo(HaveOccurred(), "NewOverlayBackend: %v", err)
	err = ov.EnsureReady(context.Background())
	Expect(err).NotTo(HaveOccurred(), "overlay EnsureReady: %v", err)
	return ov, baseDir, certPath, keyPath
}

var _ = Describe("OverlayBackendPutGetDelete", func() {
	It("routes overridden keys to explicit paths and delegates the rest", func() {
		ov, baseDir, certPath, keyPath := overlayTestSetup()

		// Override keys: file doesn't exist yet.
		_, err := ov.Get(context.Background(), KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Get missing override: err = %v, want fs.ErrNotExist", err)
		ok, err := ov.Exists(context.Background(), KeyCACert)
		Expect(err == nil && !ok).To(BeTrue(), "Exists missing override: ok=%v err=%v", ok, err)

		// Put a cert via the override: lands on the explicit path, not baseDir.
		certData := []byte("cert-pem-data")
		err = ov.Put(context.Background(), KeyCACert, certData, BlobPublic)
		Expect(err).NotTo(HaveOccurred(), "Put cert: %v", err)
		onDisk, err := os.ReadFile(certPath)
		Expect(err).NotTo(HaveOccurred(), "reading override path: %v", err)
		Expect(bytes.Equal(onDisk, certData)).To(BeTrue(), "override file = %q, want %q", onDisk, certData)
		// Base dir should NOT contain ca_crt.pem since the cert is overridden.
		_, err = os.Stat(filepath.Join(baseDir, "ca_crt.pem"))
		Expect(err).To(MatchError(fs.ErrNotExist), "base dir unexpectedly contains ca_crt.pem: err=%v", err)

		// Put a key via the override: private permissions.
		keyData := []byte("key-pem-data")
		err = ov.Put(context.Background(), KeyCAKey, keyData, BlobPrivate)
		Expect(err).NotTo(HaveOccurred(), "Put key: %v", err)
		info, err := os.Stat(keyPath)
		Expect(err).NotTo(HaveOccurred(), "stat override key path: %v", err)
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(FilePermPrivate)), "override key perm = %v, want %v", info.Mode().Perm(), os.FileMode(FilePermPrivate))

		// Non-overridden keys are delegated to the base filesystem backend.
		err = ov.Put(context.Background(), KeySerial, []byte("0001"), BlobPublic)
		Expect(err).NotTo(HaveOccurred(), "Put serial: %v", err)
		baseSerial, err := os.ReadFile(filepath.Join(baseDir, "serial"))
		Expect(err).NotTo(HaveOccurred(), "reading base serial: %v", err)
		Expect(string(baseSerial)).To(Equal("0001"), "base serial = %q, want 0001", baseSerial)

		// Delete via override.
		err = ov.Delete(context.Background(), KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "Delete override: %v", err)
		err = ov.Delete(context.Background(), KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Delete missing: err = %v, want fs.ErrNotExist", err)
	})
})

var _ = Describe("OverlayBackendReadsPreexistingFile", func() {
	It("reads an operator-supplied file via Get without writing to it", func() {
		// Simulate an operator who supplies a CA cert file. The server must read
		// it via Get without ever writing to it.
		baseDir := GinkgoT().TempDir()
		overlayDir := GinkgoT().TempDir()
		certPath := filepath.Join(overlayDir, "preexisting.pem")
		supplied := []byte("operator-supplied-cert")
		err := os.WriteFile(certPath, supplied, 0o644)
		Expect(err).NotTo(HaveOccurred())

		base := NewFilesystemBackend(baseDir)
		ov, err := NewOverlayBackend(base, map[string]string{KeyCACert: certPath})
		Expect(err).NotTo(HaveOccurred(), "NewOverlayBackend: %v", err)

		got, err := ov.Get(context.Background(), KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "Get: %v", err)
		Expect(bytes.Equal(got, supplied)).To(BeTrue(), "Get = %q, want %q", got, supplied)
		ok, err := ov.Exists(context.Background(), KeyCACert)
		Expect(err == nil && ok).To(BeTrue(), "Exists = %v, %v; want true, nil", ok, err)
	})
})

var _ = Describe("OverlayBackendAppendLineRejectsOverride", func() {
	It("appends to non-overridden keys but refuses overridden ones", func() {
		ov, _, _, _ := overlayTestSetup()
		// KeyInventory is not overridden, so append should work and land in base.
		err := ov.AppendLine(context.Background(), KeyInventory, []byte("line\n"), BlobPrivate)
		Expect(err).NotTo(HaveOccurred(), "AppendLine to non-overridden key: %v", err)
		// Force an override on KeyInventory and confirm AppendLine refuses.
		ov.overrides[KeyInventory] = "/tmp/should-not-append"
		err = ov.AppendLine(context.Background(), KeyInventory, []byte("line\n"), BlobPrivate)
		Expect(err).To(HaveOccurred(), "AppendLine on overridden key should error")
	})
})

var _ = Describe("OverlayBackendPathProvider", func() {
	It("maps overridden and non-overridden keys to paths", func() {
		ov, baseDir, certPath, _ := overlayTestSetup()
		Expect(ov.Path(KeyCACert)).To(Equal(certPath), "Path(CACert) = %q, want %q", ov.Path(KeyCACert), certPath)
		// Non-overridden key falls through to base filesystem mapping.
		Expect(ov.Path(KeySerial)).To(Equal(filepath.Join(baseDir, "serial")), "Path(Serial) = %q, want %q", ov.Path(KeySerial), filepath.Join(baseDir, "serial"))
		Expect(ov.BaseDir()).To(Equal(baseDir), "BaseDir = %q, want %q", ov.BaseDir(), baseDir)
	})
})

var _ = Describe("OverlayBackendRequiresNonEmptyOverride", func() {
	It("rejects nil, all-empty, and nil-base configurations", func() {
		base := NewFilesystemBackend(GinkgoT().TempDir())
		_, err := NewOverlayBackend(base, nil)
		Expect(err).To(HaveOccurred(), "nil overrides should error")
		_, err = NewOverlayBackend(base, map[string]string{KeyCACert: ""})
		Expect(err).To(HaveOccurred(), "all-empty overrides should error")
		_, err = NewOverlayBackend(nil, map[string]string{KeyCACert: "/tmp/x"})
		Expect(err).To(HaveOccurred(), "nil base should error")
	})
})

var _ = Describe("OverlayBackendImplementsBackend", func() {
	It("implements Backend", func() {
		var _ Backend = (*OverlayBackend)(nil)
		var _ PathProvider = (*OverlayBackend)(nil)
	})
})
