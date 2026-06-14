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

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// writeFile is a test helper that writes data to path, failing the spec on error.
func writeFile(path, data string) {
	Expect(os.WriteFile(path, []byte(data), 0600)).To(Succeed(), "write %s", path)
}

// seedFilesystemCA populates a filesystem backend rooted at dir with a minimal
// CA: a cert, key, serial and one CSR.
func seedFilesystemCA(dir string) {
	ctx := context.Background()
	b := storage.NewFilesystemBackend(dir)
	Expect(b.EnsureReady(ctx)).To(Succeed(), "EnsureReady")
	puts := []struct {
		key  string
		data string
		kind storage.BlobKind
	}{
		{storage.KeyCACert, "ca-cert", storage.BlobPublic},
		{storage.KeyCAKey, "ca-key", storage.BlobPrivate},
		{storage.KeySerial, "01", storage.BlobPublic},
		{storage.CSRKey("node1"), "csr-node1", storage.BlobPublic},
	}
	for _, p := range puts {
		Expect(b.Put(ctx, p.key, []byte(p.data), p.kind)).To(Succeed(), "seed Put %q", p.key)
	}
}

// fsConfig returns a minimal filesystem-backend config file pointing at dir.
func fsConfig(configPath, caDir string) {
	writeFile(configPath, "storage_backend: filesystem\ncadir: "+caDir+"\n")
}

var _ = Describe("migrate command", func() {
	It("migrates a filesystem CA to a filesystem destination", func() {
		srcDir := GinkgoT().TempDir()
		dstDir := GinkgoT().TempDir()
		cfgDir := GinkgoT().TempDir()
		seedFilesystemCA(srcDir)

		srcCfg := filepath.Join(cfgDir, "src.yaml")
		dstCfg := filepath.Join(cfgDir, "dst.yaml")
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)

		cmd := newMigrateCmd()
		cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})
		Expect(cmd.Execute()).To(Succeed(), "migrate")

		for _, rel := range []string{"ca_crt.pem", filepath.Join("private", "ca_key.pem"), "serial", filepath.Join("requests", "node1.pem")} {
			_, err := os.Stat(filepath.Join(dstDir, rel))
			Expect(err).NotTo(HaveOccurred(), "expected %s in destination", rel)
		}
	})

	It("refuses a non-empty destination unless forced", func() {
		srcDir := GinkgoT().TempDir()
		dstDir := GinkgoT().TempDir()
		cfgDir := GinkgoT().TempDir()
		seedFilesystemCA(srcDir)
		seedFilesystemCA(dstDir) // destination already has a CA

		srcCfg := filepath.Join(cfgDir, "src.yaml")
		dstCfg := filepath.Join(cfgDir, "dst.yaml")
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)

		cmd := newMigrateCmd()
		cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})
		Expect(cmd.Execute()).To(HaveOccurred(), "expected error migrating into a non-empty destination")

		// With --force it succeeds.
		cmd = newMigrateCmd()
		cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg, "--force"})
		Expect(cmd.Execute()).To(Succeed(), "migrate --force")
	})

	// migrates a filesystem CA into a SQLite database and back out to a second
	// directory, then asserts the exported tree is byte-for-byte identical to
	// the original — the canonical files => sqlite => files round-trip exercised
	// in CI.
	It("round-trips a filesystem CA via SQLite", func() {
		srcDir := GinkgoT().TempDir()
		sqliteCADir := GinkgoT().TempDir()
		dstDir := GinkgoT().TempDir()
		cfgDir := GinkgoT().TempDir()
		dbPath := filepath.Join(GinkgoT().TempDir(), "ca.db")
		seedFilesystemCA(srcDir)

		srcCfg := filepath.Join(cfgDir, "fs-src.yaml")
		sqlCfg := filepath.Join(cfgDir, "sqlite.yaml")
		dstCfg := filepath.Join(cfgDir, "fs-dst.yaml")
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)
		writeFile(sqlCfg, "storage_backend: sqlite\ncadir: "+sqliteCADir+"\nsql_dsn: file:"+dbPath+"\n")

		// files => sqlite
		runMigrate("--source-config", srcCfg, "--dest-config", sqlCfg)
		// sqlite => files
		runMigrate("--source-config", sqlCfg, "--dest-config", dstCfg)

		assertTreesEqual(srcDir, dstDir)
	})

	It("rejects an unknown source backend", func() {
		cfgDir := GinkgoT().TempDir()
		srcCfg := filepath.Join(cfgDir, "src.yaml")
		dstCfg := filepath.Join(cfgDir, "dst.yaml")
		writeFile(srcCfg, "storage_backend: nonsense\ncadir: "+GinkgoT().TempDir()+"\n")
		fsConfig(dstCfg, GinkgoT().TempDir())

		cmd := newMigrateCmd()
		cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})
		Expect(cmd.Execute()).To(HaveOccurred(), "expected error for unknown source backend")
	})
})

// runMigrate executes the migrate command with the given args, failing the
// spec on error.
func runMigrate(args ...string) {
	cmd := newMigrateCmd()
	cmd.SetArgs(args)
	Expect(cmd.Execute()).To(Succeed(), "migrate %v", args)
}

// assertTreesEqual fails the spec unless every regular file under want exists
// under got with identical contents (and vice versa).
func assertTreesEqual(want, got string) {
	wantFiles := collectFiles(want)
	gotFiles := collectFiles(got)

	for rel, data := range wantFiles {
		other, ok := gotFiles[rel]
		if !ok {
			Expect(ok).To(BeTrue(), "missing in exported tree: %s", rel)
			continue
		}
		Expect(bytes.Equal(data, other)).To(BeTrue(), "content differs after round-trip: %s", rel)
	}
	for rel := range gotFiles {
		_, ok := wantFiles[rel]
		Expect(ok).To(BeTrue(), "unexpected extra file in exported tree: %s", rel)
	}
}

// collectFiles returns a map of relative path => contents for every regular
// file under root.
func collectFiles(root string) map[string][]byte {
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[rel] = data
		return nil
	})
	Expect(err).NotTo(HaveOccurred(), "walk %s", root)
	return out
}
