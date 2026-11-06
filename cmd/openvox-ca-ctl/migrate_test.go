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

// seedVerifiedFilesystemCA populates a filesystem store at dir as a running
// server leaves it: a CA certificate and an inventory with entries, under an
// integrity value that verifies.
func seedVerifiedFilesystemCA(dir string) {
	ctx := context.Background()
	svc := storage.New(dir)
	Expect(svc.EnsureDirs(ctx)).To(Succeed())
	Expect(svc.SaveCACert(ctx, []byte("ca-cert"))).To(Succeed())
	Expect(svc.TouchInventory(ctx)).To(Succeed())
	Expect(svc.InitHMAC(ctx)).To(Succeed())
	Expect(svc.AppendInventory(ctx, "0002 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
}

// tamperFilesystemInventory appends an entry to the inventory at dir behind
// the integrity value's back.
func tamperFilesystemInventory(dir string) {
	f, err := os.OpenFile(filepath.Join(dir, "inventory.txt"), os.O_APPEND|os.O_WRONLY, 0)
	Expect(err).NotTo(HaveOccurred())
	_, err = f.WriteString("0x0099 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /CN=ghost\n")
	Expect(err).NotTo(HaveOccurred())
	Expect(f.Close()).To(Succeed())
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

		for _, rel := range []string{"ca_crt.pem", "ca_key.pem", "serial", filepath.Join("requests", "node1.pem")} {
			_, err := os.Stat(filepath.Join(dstDir, rel))
			Expect(err).NotTo(HaveOccurred(), "expected %s in destination", rel)
		}
	})

	// The docs promise these are ordinary server config files, so migrate
	// accepts every server setting even though it uses only the storage ones,
	// and refuses what the server would refuse (#436).
	Describe("its config files", func() {
		It("accepts a whole server config, nested blocks included", func() {
			cfg := filepath.Join(GinkgoT().TempDir(), "server.yaml")
			writeFile(cfg, `
cadir: /var/lib/openvox-ca
host: 0.0.0.0
port: 8140
tls_cert: /etc/openvox-ca/tls.crt
encrypt_ca_key: true
storage_backend: sqlite
sql_dsn: file:/var/lib/openvox-ca/ca.db
ca_key_provider: openbao
openbao:
  addr: https://bao:8200
kubernetes_export:
  targets:
    - kind: Secret
      cert: true
      metadata:
        name: trust
managed_certs:
  - certname: db
    store:
      files:
        cert: /tmp/db.crt
        key: /tmp/db.key
`)
			c, err := loadMigrateConfig(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(c.StorageBackend).To(Equal("sqlite"))
			Expect(c.SQLDSN).To(Equal("file:/var/lib/openvox-ca/ca.db"))
			Expect(c.CADir).To(Equal("/var/lib/openvox-ca"))
		})

		// A misspelt storage_backend used to fall back to the filesystem
		// backend in silence, so the copy went to cadir instead of the
		// database the file described.
		It("refuses a misspelt storage key, naming the file and the key", func() {
			cfgDir := GinkgoT().TempDir()
			srcCfg := filepath.Join(cfgDir, "src.yaml")
			dstCfg := filepath.Join(cfgDir, "dst.yaml")
			fsConfig(srcCfg, GinkgoT().TempDir())
			writeFile(dstCfg, "cadir: /tmp/x\nstorage_backnd: postgres\n")

			cmd := newMigrateCmd()
			cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})
			Expect(cmd.Execute()).To(MatchError(And(
				ContainSubstring("destination config"),
				ContainSubstring(dstCfg),
				ContainSubstring(`line 2: unknown key "storage_backnd"`))))
		})
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

	// The migrate configs share the server's storage keys, so sql_dsn_file
	// has to work here too: an operator moving a CA into PostgreSQL should not
	// have to put the password back into a config file to do it.
	It("reads the DSN from sql_dsn_file on either side", func() {
		srcDir := GinkgoT().TempDir()
		sqliteCADir := GinkgoT().TempDir()
		dstDir := GinkgoT().TempDir()
		cfgDir := GinkgoT().TempDir()
		dbPath := filepath.Join(GinkgoT().TempDir(), "ca.db")
		seedFilesystemCA(srcDir)

		srcCfg := filepath.Join(cfgDir, "fs-src.yaml")
		sqlCfg := filepath.Join(cfgDir, "sqlite.yaml")
		dstCfg := filepath.Join(cfgDir, "fs-dst.yaml")
		dsnFile := filepath.Join(cfgDir, "dsn")
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)
		writeFile(dsnFile, "file:"+dbPath+"\n")
		writeFile(sqlCfg, "storage_backend: sqlite\ncadir: "+sqliteCADir+"\nsql_dsn_file: "+dsnFile+"\n")

		// files => sqlite, with sql_dsn_file on the destination
		runMigrate("--source-config", srcCfg, "--dest-config", sqlCfg)
		Expect(dbPath).To(BeAnExistingFile(), "the CA must land in the database the file names")
		// sqlite => files, with sql_dsn_file on the source
		runMigrate("--source-config", sqlCfg, "--dest-config", dstCfg)

		assertTreesEqual(srcDir, dstDir)
	})

	Describe("source inventory verification", func() {
		var srcDir, dstDir, srcCfg, dstCfg string
		var stderr *bytes.Buffer

		BeforeEach(func() {
			srcDir = GinkgoT().TempDir()
			dstDir = GinkgoT().TempDir()
			cfgDir := GinkgoT().TempDir()
			srcCfg = filepath.Join(cfgDir, "src.yaml")
			dstCfg = filepath.Join(cfgDir, "dst.yaml")
			fsConfig(srcCfg, srcDir)
			fsConfig(dstCfg, dstDir)
			stderr = &bytes.Buffer{}
		})

		migrate := func(extra ...string) error {
			cmd := newMigrateCmd()
			cmd.SetErr(stderr)
			cmd.SetArgs(append([]string{"--source-config", srcCfg, "--dest-config", dstCfg}, extra...))
			return cmd.Execute()
		}

		It("refuses a source that does not verify, naming the remedy", func() {
			seedVerifiedFilesystemCA(srcDir)
			tamperFilesystemInventory(srcDir)

			err := migrate()

			Expect(err).To(MatchError(storage.ErrSourceUnverified))
			Expect(err.Error()).To(ContainSubstring("openvox-ca rebuild-inventory-hmac"))
			Expect(err.Error()).To(ContainSubstring("--allow-unverified-source"))
			_, statErr := os.Stat(filepath.Join(dstDir, "ca_crt.pem"))
			Expect(os.IsNotExist(statErr)).To(BeTrue(), "a refused migration copied the CA certificate")
		})

		It("migrates it with --allow-unverified-source, and warns whatever the verbosity", func() {
			seedVerifiedFilesystemCA(srcDir)
			tamperFilesystemInventory(srcDir)

			Expect(migrate("--allow-unverified-source")).To(Succeed())

			Expect(stderr.String()).To(ContainSubstring("Warning: the source inventory was not verified: " +
				"the inventory does not match its stored integrity value (scheme whole-blob-hmac), so it may " +
				"have been altered. The destination's integrity value, written now or at the server's first " +
				"start, will vouch for it as copied.\n"))
			Expect(filepath.Join(dstDir, "ca_crt.pem")).To(BeAnExistingFile())
		})

		It("migrates a source that never recorded integrity, and warns", func() {
			seedFilesystemCA(srcDir) // no HMAC key, no value

			Expect(migrate()).To(Succeed())

			Expect(stderr.String()).To(ContainSubstring("Warning: the source inventory was not verified: " +
				"the source never recorded an inventory integrity value (no HMAC key and no value are " +
				"stored), so there was nothing to verify it against. The destination's integrity value, " +
				"written now or at the server's first start, will vouch for it as copied.\n"))
		})

		It("says nothing about integrity when the source verifies", func() {
			seedVerifiedFilesystemCA(srcDir)

			Expect(migrate()).To(Succeed())

			Expect(stderr.String()).NotTo(ContainSubstring("Warning"))
		})
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

	// Guards the exclusion in collectFiles: if it ever swallowed the tree, every
	// assertion below would pass having compared nothing.
	Expect(wantFiles).NotTo(BeEmpty(),
		"nothing was compared -- the walk or its exclusion is wrong, not the migration")

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
// file under root, excluding the lock directory.
//
// locks/ is skipped deliberately, and its absence is not a weakening. Lock
// files are process-coordination artefacts rather than CA state: nothing
// migrates them, and each tree has its own only because each backend was
// opened. They used to compare equal by accident -- they were empty -- but the
// store-wide instance lock records its holder, so two trees now differ there
// whenever the two acquisitions fall either side of a second boundary. That
// made this spec fail perhaps one run in five while asserting nothing about the
// migration in the other four.
func collectFiles(root string) map[string][]byte {
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "locks" && path != root {
				return filepath.SkipDir
			}
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
