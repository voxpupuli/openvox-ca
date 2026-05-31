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

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

// writeFile is a test helper that writes data to path, failing the test on error.
func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// seedFilesystemCA populates a filesystem backend rooted at dir with a minimal
// CA: a cert, key, serial and one CSR.
func seedFilesystemCA(t *testing.T, dir string) {
	t.Helper()
	ctx := context.Background()
	b := storage.NewFilesystemBackend(dir)
	if err := b.EnsureReady(ctx); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
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
		if err := b.Put(ctx, p.key, []byte(p.data), p.kind); err != nil {
			t.Fatalf("seed Put %q: %v", p.key, err)
		}
	}
}

// fsConfig returns a minimal filesystem-backend config file pointing at dir.
func fsConfig(t *testing.T, configPath, caDir string) {
	t.Helper()
	writeFile(t, configPath, "storage_backend: filesystem\ncadir: "+caDir+"\n")
}

func TestMigrateCommandFilesystemToFilesystem(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	cfgDir := t.TempDir()
	seedFilesystemCA(t, srcDir)

	srcCfg := filepath.Join(cfgDir, "src.yaml")
	dstCfg := filepath.Join(cfgDir, "dst.yaml")
	fsConfig(t, srcCfg, srcDir)
	fsConfig(t, dstCfg, dstDir)

	cmd := newMigrateCmd()
	cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for _, rel := range []string{"ca_crt.pem", filepath.Join("private", "ca_key.pem"), "serial", filepath.Join("requests", "node1.pem")} {
		if _, err := os.Stat(filepath.Join(dstDir, rel)); err != nil {
			t.Errorf("expected %s in destination: %v", rel, err)
		}
	}
}

func TestMigrateCommandRefusesNonEmptyDestination(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	cfgDir := t.TempDir()
	seedFilesystemCA(t, srcDir)
	seedFilesystemCA(t, dstDir) // destination already has a CA

	srcCfg := filepath.Join(cfgDir, "src.yaml")
	dstCfg := filepath.Join(cfgDir, "dst.yaml")
	fsConfig(t, srcCfg, srcDir)
	fsConfig(t, dstCfg, dstDir)

	cmd := newMigrateCmd()
	cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error migrating into a non-empty destination")
	}

	// With --force it succeeds.
	cmd = newMigrateCmd()
	cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("migrate --force: %v", err)
	}
}

// runMigrate executes the migrate command with the given args, failing the
// test on error.
func runMigrate(t *testing.T, args ...string) {
	t.Helper()
	cmd := newMigrateCmd()
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("migrate %v: %v", args, err)
	}
}

// TestMigrateCommandRoundTripViaSQLite migrates a filesystem CA into a SQLite
// database and back out to a second directory, then asserts the exported tree
// is byte-for-byte identical to the original — the canonical
// files => sqlite => files round-trip exercised in CI.
func TestMigrateCommandRoundTripViaSQLite(t *testing.T) {
	srcDir := t.TempDir()
	sqliteCADir := t.TempDir()
	dstDir := t.TempDir()
	cfgDir := t.TempDir()
	dbPath := filepath.Join(t.TempDir(), "ca.db")
	seedFilesystemCA(t, srcDir)

	srcCfg := filepath.Join(cfgDir, "fs-src.yaml")
	sqlCfg := filepath.Join(cfgDir, "sqlite.yaml")
	dstCfg := filepath.Join(cfgDir, "fs-dst.yaml")
	fsConfig(t, srcCfg, srcDir)
	fsConfig(t, dstCfg, dstDir)
	writeFile(t, sqlCfg, "storage_backend: sqlite\ncadir: "+sqliteCADir+"\nsql_dsn: file:"+dbPath+"\n")

	// files => sqlite
	runMigrate(t, "--source-config", srcCfg, "--dest-config", sqlCfg)
	// sqlite => files
	runMigrate(t, "--source-config", sqlCfg, "--dest-config", dstCfg)

	assertTreesEqual(t, srcDir, dstDir)
}

// assertTreesEqual fails the test unless every regular file under want exists
// under got with identical contents (and vice versa).
func assertTreesEqual(t *testing.T, want, got string) {
	t.Helper()
	wantFiles := collectFiles(t, want)
	gotFiles := collectFiles(t, got)

	for rel, data := range wantFiles {
		other, ok := gotFiles[rel]
		if !ok {
			t.Errorf("missing in exported tree: %s", rel)
			continue
		}
		if !bytes.Equal(data, other) {
			t.Errorf("content differs after round-trip: %s", rel)
		}
	}
	for rel := range gotFiles {
		if _, ok := wantFiles[rel]; !ok {
			t.Errorf("unexpected extra file in exported tree: %s", rel)
		}
	}
}

// collectFiles returns a map of relative path => contents for every regular
// file under root.
func collectFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
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
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func TestMigrateCommandRejectsUnknownBackend(t *testing.T) {
	cfgDir := t.TempDir()
	srcCfg := filepath.Join(cfgDir, "src.yaml")
	dstCfg := filepath.Join(cfgDir, "dst.yaml")
	writeFile(t, srcCfg, "storage_backend: nonsense\ncadir: "+t.TempDir()+"\n")
	fsConfig(t, dstCfg, t.TempDir())

	cmd := newMigrateCmd()
	cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown source backend")
	}
}
