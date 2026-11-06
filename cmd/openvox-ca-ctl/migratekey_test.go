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
	"context"
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// migrate writes the CA key as --dest-config says it should be held (#516),
// reading encrypt_ca_key and ca_key_passphrase_file from each file. Each key
// it writes is checked the way the server checks it: Init on the destination
// with the destination's passphrase.
var _ = Describe("migrate command CA key encryption", func() {
	var (
		ctx                    context.Context
		dir, srcDir, dstDir    string
		srcCfg, dstCfg, ctlCfg string
		ppA, ppB               string
		ppAConfig, ppBConfig   ca.KeyPassphraseConfig
	)

	BeforeEach(func() {
		ctx = context.Background()
		// As in setup_test.go: an explicit --config keeps the host's own
		// ctl.yaml out, and the globals are restored for the next spec.
		saveCtlGlobals()
		clearCtlEnv()
		ctlCfg = writeTempCtlConfig("")
		GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "")
		dir = GinkgoT().TempDir()
		srcDir = filepath.Join(dir, "src")
		dstDir = filepath.Join(dir, "dst")
		srcCfg = filepath.Join(dir, "src.yaml")
		dstCfg = filepath.Join(dir, "dst.yaml")
		ppA = filepath.Join(dir, "pp-a")
		ppB = filepath.Join(dir, "pp-b")
		writeFile(ppA, "passphrase-a\n")
		writeFile(ppB, "passphrase-b\n")
		ppAConfig = ca.KeyPassphraseConfig{PassphraseFile: ppA}
		ppBConfig = ca.KeyPassphraseConfig{PassphraseFile: ppB}
	})

	// seedSource imports a real CA into the source, its key encrypted under
	// ppA when encrypted is set.
	seedSource := func(encrypted bool) {
		GinkgoHelper()
		keyPEM, crtPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.ImportCAWithOptions(ctx, storage.New(srcDir), crtPEM, keyPEM, nil,
			ca.ImportCAOptions{EncryptCAKey: encrypted, KeyPassphrase: ppAConfig})).To(Succeed())
	}

	dstKeyType := func() string {
		GinkgoHelper()
		key, err := storage.New(dstDir).GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(key)
		Expect(block).NotTo(BeNil())
		return block.Type
	}

	destStarts := func(cfg ca.KeyPassphraseConfig) error {
		myCA := ca.New(storage.New(dstDir), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.KeyPassphrase = cfg
		return myCA.Init(ctx)
	}

	migrate := func() (string, error) {
		return captureStdout([]string{"migrate", "--config", ctlCfg, "--source-config", srcCfg, "--dest-config", dstCfg})
	}

	It("encrypts a plaintext key when --dest-config sets encrypt_ca_key, and says so", func() {
		seedSource(false)
		fsConfig(srcCfg, srcDir)
		writeFile(dstCfg, "storage_backend: filesystem\ncadir: "+dstDir+
			"\nencrypt_ca_key: true\nca_key_passphrase_file: "+ppB+"\n")

		out, err := migrate()

		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("The CA key was written encrypted"))
		Expect(dstKeyType()).To(Equal("ENCRYPTED PRIVATE KEY"))
		Expect(destStarts(ppBConfig)).To(Succeed())
	})

	It("re-encrypts an encrypted key from the source's passphrase to the destination's", func() {
		seedSource(true)
		writeFile(srcCfg, "storage_backend: filesystem\ncadir: "+srcDir+
			"\nencrypt_ca_key: true\nca_key_passphrase_file: "+ppA+"\n")
		writeFile(dstCfg, "storage_backend: filesystem\ncadir: "+dstDir+
			"\nencrypt_ca_key: true\nca_key_passphrase_file: "+ppB+"\n")

		out, err := migrate()

		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("The CA key was written encrypted"))
		Expect(destStarts(ppBConfig)).To(Succeed())
		Expect(destStarts(ppAConfig)).To(MatchError(ContainSubstring("decrypting CA key")),
			"only the destination's passphrase opens it now")
	})

	It("refuses an encrypted key the destination has no passphrase for, writing nothing", func() {
		seedSource(true)
		writeFile(srcCfg, "storage_backend: filesystem\ncadir: "+srcDir+
			"\nca_key_passphrase_file: "+ppA+"\n")
		fsConfig(dstCfg, dstDir)

		_, err := migrate()

		Expect(err).To(MatchError(ContainSubstring("ca_key_passphrase_file in --dest-config")))
		Expect(storage.New(dstDir).HasCACert(ctx)).To(BeFalse(), "the destination holds no CA")
	})

	It("refuses an encrypted key the source has no passphrase for, writing nothing", func() {
		seedSource(true)
		fsConfig(srcCfg, srcDir)
		writeFile(dstCfg, "storage_backend: filesystem\ncadir: "+dstDir+
			"\nca_key_passphrase_file: "+ppB+"\n")

		_, err := migrate()

		Expect(err).To(MatchError(ContainSubstring("ca_key_passphrase_file in --source-config")))
		Expect(storage.New(dstDir).HasCACert(ctx)).To(BeFalse())
	})

	// The refusal for a missing passphrase names a file found at the
	// auto-passphrase path of the cadir it is about, so each end has to be
	// handed its own cadir.
	It("names the source's own cadir when the source has no passphrase", func() {
		seedSource(true)
		fsConfig(srcCfg, srcDir)
		writeFile(dstCfg, "storage_backend: filesystem\ncadir: "+dstDir+
			"\nca_key_passphrase_file: "+ppB+"\n")
		planted := filepath.Join(srcDir, "private", ".ca_key_passphrase")
		writeFile(planted, "passphrase-a\n")

		_, err := migrate()

		Expect(err).To(MatchError(ContainSubstring(planted)))
	})

	It("names the destination's own cadir when the destination has no passphrase", func() {
		seedSource(false)
		fsConfig(srcCfg, srcDir)
		writeFile(dstCfg, "storage_backend: filesystem\ncadir: "+dstDir+"\nencrypt_ca_key: true\n")
		Expect(os.MkdirAll(filepath.Join(dstDir, "private"), 0o750)).To(Succeed())
		planted := filepath.Join(dstDir, "private", ".ca_key_passphrase")
		writeFile(planted, "passphrase-b\n")

		_, err := migrate()

		Expect(err).To(MatchError(ContainSubstring(planted)))
	})

	// The two ends are told apart only by their files: the server's
	// environment overrides would apply to both. One spec per variable, each
	// with a fixture where honouring that variable alone changes the outcome.
	It("ignores OPENVOX_CA_KEY_PASSPHRASE_FILE", func() {
		seedSource(true)
		writeFile(srcCfg, "storage_backend: filesystem\ncadir: "+srcDir+
			"\nca_key_passphrase_file: "+ppA+"\n")
		writeFile(dstCfg, "storage_backend: filesystem\ncadir: "+dstDir+
			"\nca_key_passphrase_file: "+ppA+"\n")
		GinkgoT().Setenv("OPENVOX_CA_KEY_PASSPHRASE_FILE", ppB)

		out, err := migrate()

		Expect(err).NotTo(HaveOccurred(), "honoured, the variable would decrypt the source under the wrong passphrase")
		Expect(dstKeyType()).To(Equal("ENCRYPTED PRIVATE KEY"),
			"an encrypted source stays encrypted without encrypt_ca_key in --dest-config")
		Expect(out).To(ContainSubstring("The CA key was written encrypted"))
		Expect(destStarts(ppAConfig)).To(Succeed())
	})

	It("ignores OPENVOX_CA_ENCRYPT_CA_KEY", func() {
		seedSource(false)
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)
		GinkgoT().Setenv("OPENVOX_CA_ENCRYPT_CA_KEY", "true")
		GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "passphrase-from-env")

		out, err := migrate()

		Expect(err).NotTo(HaveOccurred())
		Expect(out).NotTo(ContainSubstring("The CA key was written encrypted"))
		srcKey, err := storage.New(srcDir).GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		dstKey, err := storage.New(dstDir).GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(dstKey).To(Equal(srcKey))
	})

	// docs/ca-key-security.md points a filesystem CA whose key ca_key_file
	// keeps outside the cadir at migrate, because import cannot reach it.
	// Each end's ca_key_file has to be where the key is read and written.
	It("reads and writes the key through ca_key_file at both ends", func() {
		seedSource(false)
		srcKey := filepath.Join(dir, "keys-src", "ca_key.pem")
		Expect(os.MkdirAll(filepath.Dir(srcKey), 0o700)).To(Succeed())
		Expect(os.Rename(storage.New(srcDir).CAKeyPath(), srcKey)).To(Succeed())
		dstKey := filepath.Join(dir, "keys-dst", "ca_key.pem")
		Expect(os.MkdirAll(filepath.Dir(dstKey), 0o700)).To(Succeed())
		writeFile(srcCfg, "storage_backend: filesystem\ncadir: "+srcDir+"\nca_key_file: "+srcKey+"\n")
		writeFile(dstCfg, "storage_backend: filesystem\ncadir: "+dstDir+"\nca_key_file: "+dstKey+
			"\nencrypt_ca_key: true\nca_key_passphrase_file: "+ppB+"\n")

		_, err := migrate()

		Expect(err).NotTo(HaveOccurred())
		written, err := os.ReadFile(dstKey)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(written)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("ENCRYPTED PRIVATE KEY"), "the destination's ca_key_file holds the encrypted key")
		Expect(storage.New(dstDir).CAKeyPath()).NotTo(BeAnExistingFile(), "and the cadir holds none")

		cfg, err := loadMigrateConfig(dstCfg)
		Expect(err).NotTo(HaveOccurred())
		spec, err := cfg.backendSpec()
		Expect(err).NotTo(HaveOccurred())
		svc, err := storage.NewServiceFromSpec(spec)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = svc.Backend().Close() })
		server := ca.New(svc, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		server.KeyPassphrase = ppBConfig
		Expect(server.Init(ctx)).To(Succeed(), "the server configured by --dest-config starts on it")
	})

	// docs/storage-backends.md says so, by the maintainer's ruling: migrate's
	// refusals are about missing passphrases, and --force already means
	// replacing the destination's CA. This pins the documented behaviour, so
	// that changing it also has to change the docs.
	It("writes a plaintext key over an encrypted one under --force, saying nothing", func() {
		seedSource(false)
		keyPEM, crtPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.ImportCAWithOptions(ctx, storage.New(dstDir), crtPEM, keyPEM, nil,
			ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: ppBConfig})).To(Succeed())
		Expect(dstKeyType()).To(Equal("ENCRYPTED PRIVATE KEY"), "the fixture: an encrypted destination key")
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)

		out, err := captureStdout([]string{"migrate", "--config", ctlCfg,
			"--source-config", srcCfg, "--dest-config", dstCfg, "--force"})

		Expect(err).NotTo(HaveOccurred())
		Expect(out).NotTo(ContainSubstring("The CA key was written encrypted"))
		srcKey, err := storage.New(srcDir).GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		dstKey, err := storage.New(dstDir).GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(dstKey).To(Equal(srcKey), "the plaintext source key replaced the encrypted one")
	})

	It("copies a plaintext key as it is when --dest-config does not set encrypt_ca_key", func() {
		seedSource(false)
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)

		out, err := migrate()

		Expect(err).NotTo(HaveOccurred())
		Expect(out).NotTo(ContainSubstring("The CA key was written encrypted"))
		srcKey, err := storage.New(srcDir).GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		dstKey, err := storage.New(dstDir).GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(dstKey).To(Equal(srcKey))
	})
})
