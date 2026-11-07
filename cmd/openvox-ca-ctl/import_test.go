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
	"io"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// The flags that let import encrypt the CA key it writes (#516). What the
// encryption does is specified in internal/ca; these pin that each flag reaches
// it.
var _ = Describe("import subcommand key encryption", func() {
	var (
		dir, caDir, certFile, keyFile, ppFile, ctlCfg string
	)

	BeforeEach(func() {
		// As in setup_test.go: an explicit --config keeps the host's own
		// ctl.yaml out, and the globals are restored for the next spec.
		saveCtlGlobals()
		clearCtlEnv()
		ctlCfg = writeTempCtlConfig("")
		GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "")

		dir = GinkgoT().TempDir()
		caDir = filepath.Join(dir, "cadir")
		keyPEM, crtPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		certFile = filepath.Join(dir, "ca_crt.pem")
		keyFile = filepath.Join(dir, "ca_key.pem")
		ppFile = filepath.Join(dir, "passphrase")
		Expect(os.WriteFile(certFile, crtPEM, 0o600)).To(Succeed())
		Expect(os.WriteFile(keyFile, keyPEM, 0o600)).To(Succeed())
		Expect(os.WriteFile(ppFile, []byte("ctl-passphrase\n"), 0o600)).To(Succeed())
	})

	runImport := func(extra ...string) error {
		cmd := newRootCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(append([]string{"import", "--config", ctlCfg, "--cadir", caDir, "--cert-bundle", certFile,
			"--private-key", keyFile}, extra...))
		return cmd.Execute()
	}

	storedKey := func() []byte {
		GinkgoHelper()
		key, err := os.ReadFile(storage.New(caDir).CAKeyPath())
		Expect(err).NotTo(HaveOccurred())
		return key
	}

	storedKeyType := func() string {
		GinkgoHelper()
		block, _ := pem.Decode(storedKey())
		Expect(block).NotTo(BeNil())
		return block.Type
	}

	startsWith := func(cfg ca.KeyPassphraseConfig) error {
		myCA := ca.New(storage.New(caDir), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.KeyPassphrase = cfg
		return myCA.Init(context.Background())
	}

	It("writes the key encrypted under --ca-key-passphrase-file, and the CA starts on it", func() {
		Expect(runImport("--encrypt-ca-key", "--ca-key-passphrase-file", ppFile)).To(Succeed())

		Expect(storedKeyType()).To(Equal("ENCRYPTED PRIVATE KEY"))
		Expect(startsWith(ca.KeyPassphraseConfig{PassphraseFile: ppFile})).To(Succeed())
	})

	It("accepts the encrypted key it stored as --private-key, with --ca-key-passphrase-file", func() {
		Expect(runImport("--encrypt-ca-key", "--ca-key-passphrase-file", ppFile)).To(Succeed())
		Expect(os.WriteFile(keyFile, storedKey(), 0o600)).To(Succeed())

		Expect(runImport("--ca-key-passphrase-file", ppFile)).To(Succeed(),
			"re-importing the stored key is the ancestor-refresh route under encrypt_ca_key")
		Expect(storedKeyType()).To(Equal("ENCRYPTED PRIVATE KEY"))
		Expect(startsWith(ca.KeyPassphraseConfig{PassphraseFile: ppFile})).To(Succeed())
	})

	It("refuses a plaintext key over the encrypted one, and --allow-plaintext-ca-key overrides it", func() {
		Expect(runImport("--encrypt-ca-key", "--ca-key-passphrase-file", ppFile)).To(Succeed())

		Expect(runImport()).To(MatchError(ca.ErrPlaintextOverEncrypted))
		Expect(storedKeyType()).To(Equal("ENCRYPTED PRIVATE KEY"), "the refusal changed nothing")

		Expect(runImport("--allow-plaintext-ca-key")).To(Succeed())
		Expect(storedKeyType()).NotTo(Equal("ENCRYPTED PRIVATE KEY"))
	})

	It("refuses --encrypt-ca-key together with --allow-plaintext-ca-key", func() {
		err := runImport("--encrypt-ca-key", "--ca-key-passphrase-file", ppFile, "--allow-plaintext-ca-key")

		Expect(err).To(MatchError(ContainSubstring("none of the others can be")))
		Expect(storage.New(caDir).HasCACert(context.Background())).To(BeFalse())
	})
})
