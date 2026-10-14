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

package ca_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The warning CA.Init gives when encrypt_ca_key is set but the key it loads
// from the store is plaintext (#432): a key from before the setting, which
// nothing re-encrypts.
var _ = Describe("Plaintext CA key under encrypt_ca_key", func() {
	const warningText = "the stored CA key is not encrypted"

	var (
		tmpDir string
		store  *storage.StorageService
		logBuf *bytes.Buffer
	)

	// warnings returns the captured log lines carrying the warning.
	warnings := func() []string {
		var out []string
		for line := range strings.SplitSeq(logBuf.String(), "\n") {
			if strings.Contains(line, warningText) {
				out = append(out, line)
			}
		}
		return out
	}

	// bootstrap creates a CA in tmpDir and discards what it logged, so a spec
	// sees only what the load under test says.
	bootstrap := func(encrypt bool, pp ca.KeyPassphraseConfig) *ca.CA {
		first := ca.New(storage.New(tmpDir), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		first.EncryptCAKey = encrypt
		first.KeyPassphrase = pp
		Expect(first.Init(context.Background())).To(Succeed())
		logBuf.Reset()
		return first
	}

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
		store = storage.New(tmpDir)
		// None of these specs may resolve a passphrase from the environment by
		// accident.
		GinkgoT().Setenv("PUPPET_CA_KEY_PASSPHRASE", "")

		logBuf = &bytes.Buffer{}
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	It("warns, naming the key, when the setting is on and the stored key is plaintext", func() {
		bootstrap(false, ca.KeyPassphraseConfig{})
		before, err := store.GetCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.EncryptCAKey = true
		Expect(myCA.Init(context.Background())).To(Succeed(),
			"a plaintext key loads whatever the setting says")

		Expect(warnings()).To(HaveLen(1))
		Expect(warnings()[0]).To(ContainSubstring("level=WARN"))
		Expect(warnings()[0]).To(ContainSubstring("key=" + store.CAKeyPath()))

		// The warning says the key is not re-encrypted; hold it to that.
		after, err := store.GetCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "loading must leave the stored key as it was")
	})

	// Init's slow path loads the key a second time, inside the bootstrap lock,
	// when the first attempt fails for want of a certificate. One start, one
	// warning.
	It("warns once when Init loads the key twice", func() {
		bootstrap(false, ca.KeyPassphraseConfig{})
		Expect(os.Remove(store.CACertPath())).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.EncryptCAKey = true
		// The fast path's load fails for want of a certificate, which sends
		// Init down the slow path to load the key again. This refusal comes
		// only after that second load, so matching it -- rather than any
		// error -- is what shows both loads ran.
		Expect(myCA.Init(context.Background())).To(MatchError(ContainSubstring(
			"a CA key already exists in storage but the CA certificate is missing")))

		Expect(warnings()).To(HaveLen(1))
	})

	// The key's path is an attribute only where the backend has one. A
	// database backend stores a blob, and key="" would read as a misconfigured
	// path rather than as no path at all.
	It("names no key path when the backend has none", func() {
		pathless := storage.NewWithBackend(pathlessBackend{storage.NewFilesystemBackend(tmpDir)},
			filepath.Join(tmpDir, "private"))
		Expect(pathless.CAKeyPath()).To(BeEmpty(), "the fixture must not expose a path")
		first := ca.New(pathless, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(first.Init(context.Background())).To(Succeed())
		logBuf.Reset()

		myCA := ca.New(pathless, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.EncryptCAKey = true
		Expect(myCA.Init(context.Background())).To(Succeed())

		Expect(warnings()).To(HaveLen(1))
		Expect(warnings()[0]).NotTo(ContainSubstring("key="))
	})

	// The frontend signs through the signer process and never reads the key,
	// though it has the same setting and the same store. One start, one
	// warning, and it is the signer's.
	It("does not warn from a frontend, whose key is behind an external signer", func() {
		signerCA := bootstrap(false, ca.KeyPassphraseConfig{})

		frontend := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		frontend.EncryptCAKey = true
		frontend.ExternalSigner = signerCA.CAKey
		Expect(frontend.Init(context.Background())).To(Succeed())

		Expect(warnings()).To(BeEmpty())
	})

	It("does not warn when the setting is off", func() {
		bootstrap(false, ca.KeyPassphraseConfig{})

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(context.Background())).To(Succeed())

		Expect(warnings()).To(BeEmpty())
	})

	It("does not warn when the stored key is encrypted", func() {
		ppFile := filepath.Join(tmpDir, "passphrase")
		Expect(os.WriteFile(ppFile, []byte("warning-spec-passphrase\n"), 0o600)).To(Succeed())
		pp := ca.KeyPassphraseConfig{PassphraseFile: ppFile}
		bootstrap(true, pp)

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.EncryptCAKey = true
		myCA.KeyPassphrase = pp
		Expect(myCA.Init(context.Background())).To(Succeed())

		Expect(warnings()).To(BeEmpty())
	})

	// A key at a provider is never read from the store, so a plaintext PEM
	// left there is not the CA's key and says nothing about it.
	It("does not warn when the key lives at a provider, whatever the store holds", func() {
		provider := &fakeKeyProvider{}
		first := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		first.KeyProvider = provider
		Expect(first.Init(context.Background())).To(Succeed())

		stray, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.MarshalPKCS8PrivateKey(stray)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCAKey(context.Background(),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))).To(Succeed())
		logBuf.Reset()

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.KeyProvider = provider
		myCA.EncryptCAKey = true
		Expect(myCA.Init(context.Background())).To(Succeed())

		Expect(warnings()).To(BeEmpty())
	})
})

// pathlessBackend hides the filesystem backend's PathProvider, so the store
// reports no file paths, as a database backend does.
type pathlessBackend struct{ storage.Backend }
