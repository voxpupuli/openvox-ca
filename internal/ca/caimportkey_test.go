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
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// The CA key ImportCAWithOptions writes (#516): encrypted when asked, or when
// it was given encrypted, and never a silent downgrade of an encrypted key
// already in storage.
var _ = Describe("ImportCAWithOptions: the CA key at rest", func() {
	var (
		ctx    context.Context
		dir    string
		store  *storage.StorageService
		ppFile string
		pp     ca.KeyPassphraseConfig
	)

	BeforeEach(func() {
		ctx = context.Background()
		// An ambient passphrase in the environment would satisfy the specs
		// that need there to be none. Empty counts as unset to the resolver.
		GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "")

		dir = GinkgoT().TempDir()
		store = storage.New(filepath.Join(dir, "cadir"))
		ppFile = filepath.Join(dir, "passphrase")
		Expect(os.WriteFile(ppFile, []byte("import-passphrase\n"), 0o600)).To(Succeed())
		pp = ca.KeyPassphraseConfig{PassphraseFile: ppFile}
	})

	storedKey := func(s *storage.StorageService) []byte {
		GinkgoHelper()
		key, err := s.GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		return key
	}

	storedKeyType := func(s *storage.StorageService) string {
		GinkgoHelper()
		block, _ := pem.Decode(storedKey(s))
		Expect(block).NotTo(BeNil(), "the stored key is PEM")
		return block.Type
	}

	// startCA is what the server does with the store: Init loads the key with
	// the passphrase it is configured with and pins it to the certificate.
	startCA := func(s *storage.StorageService, cfg ca.KeyPassphraseConfig) error {
		myCA := ca.New(s, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.KeyPassphrase = cfg
		return myCA.Init(ctx)
	}

	// encryptedKey returns cachedKeyPEM as this CA stores it encrypted under
	// cfg, by importing it into a scratch store.
	encryptedKey := func(cfg ca.KeyPassphraseConfig) []byte {
		GinkgoHelper()
		scratch := storage.New(filepath.Join(GinkgoT().TempDir(), "scratch"))
		Expect(ca.ImportCAWithOptions(ctx, scratch, cachedCrtPEM, cachedKeyPEM, nil,
			ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: cfg})).To(Succeed())
		return storedKey(scratch)
	}

	expectNothingWritten := func() {
		GinkgoHelper()
		Expect(store.HasCACert(ctx)).To(BeFalse(), "no certificate was written")
		Expect(store.HasCAKey(ctx)).To(BeFalse(), "no key was written")
	}

	Context("with EncryptCAKey", func() {
		It("writes the key encrypted, and the CA starts on it with the same passphrase", func() {
			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(Succeed())

			Expect(storedKeyType(store)).To(Equal("ENCRYPTED PRIVATE KEY"))
			Expect(startCA(store, pp)).To(Succeed(), "the server's load path decrypts what import wrote")
		})

		It("writes a key no other passphrase opens", func() {
			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(Succeed())

			GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "some-other-passphrase")
			Expect(startCA(store, ca.KeyPassphraseConfig{})).To(MatchError(ContainSubstring("decrypting CA key")))
		})

		It("reads the passphrase from the environment when no file is named", func() {
			GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "env-passphrase")
			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true})).To(Succeed())

			Expect(storedKeyType(store)).To(Equal("ENCRYPTED PRIVATE KEY"))
			Expect(startCA(store, ca.KeyPassphraseConfig{})).To(Succeed())
		})

		It("refuses with no passphrase source, naming import's flag, and writes nothing", func() {
			err := ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true})

			Expect(err).To(MatchError(ContainSubstring("--encrypt-ca-key is set but no passphrase source is configured")))
			Expect(err).To(MatchError(ContainSubstring("set --ca-key-passphrase-file")),
				"import has a flag, not the server's setting")
			expectNothingWritten()
		})

		// The in-place route docs/ca-key-security.md gives: stop a CA that has
		// been issuing and re-import its own certificate and key with
		// encryption on. The key changes form; nothing else the CA holds may.
		It("encrypts a working CA's key in place, keeping its serial, inventory and CRL", func() {
			Expect(ca.ImportCA(ctx, store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())
			running := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(running.Init(ctx)).To(Succeed())
			issued, err := running.Generate(ctx, "node1.test", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(running.Revoke(ctx, "node1.test")).To(Succeed())
			block, _ := pem.Decode(issued.CertificatePEM)
			Expect(block).NotTo(BeNil())
			revoked, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// openvox-ca issues random serials and never advances this file,
			// so it would still hold the 0001 import writes; a value import
			// could only keep by leaving it alone is what makes the check bite.
			Expect(store.WriteSerial(ctx, "00FF")).To(Succeed())
			serialBefore, err := store.GetSerial(ctx)
			Expect(err).NotTo(HaveOccurred())
			inventoryBefore, err := store.ReadInventory(ctx)
			Expect(err).NotTo(HaveOccurred())
			crlBefore, err := store.GetCRL(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(Succeed())

			Expect(storedKeyType(store)).To(Equal("ENCRYPTED PRIVATE KEY"))
			Expect(store.GetSerial(ctx)).To(Equal(serialBefore))
			Expect(store.ReadInventory(ctx)).To(Equal(inventoryBefore))
			crlAfter, err := store.GetCRL(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(crlAfter).To(Equal(crlBefore), "no --crl-chain, so the stored CRL is left alone")
			crlBlock, _ := pem.Decode(crlAfter)
			Expect(crlBlock).NotTo(BeNil())
			crl, err := x509.ParseRevocationList(crlBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			var revokedSerials []string
			for _, entry := range crl.RevokedCertificateEntries {
				revokedSerials = append(revokedSerials, entry.SerialNumber.String())
			}
			Expect(revokedSerials).To(ContainElement(revoked.SerialNumber.String()))

			Expect(startCA(store, pp)).To(Succeed(), "and the CA starts on the encrypted key with its passphrase")
		})

		It("re-encrypts a plaintext re-import over an encrypted key, and the CA still starts", func() {
			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(Succeed())
			first := storedKey(store)

			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(Succeed())

			Expect(storedKeyType(store)).To(Equal("ENCRYPTED PRIVATE KEY"))
			Expect(storedKey(store)).NotTo(Equal(first), "encrypted afresh, with a new salt")
			Expect(startCA(store, pp)).To(Succeed())
		})
	})

	Context("given an encrypted key", func() {
		It("decrypts it, stores it encrypted, and the CA starts on it", func() {
			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, encryptedKey(pp), nil,
				ca.ImportCAOptions{KeyPassphrase: pp})).To(Succeed())

			Expect(storedKeyType(store)).To(Equal("ENCRYPTED PRIVATE KEY"),
				"an encrypted key is never written back in plaintext, even without EncryptCAKey")
			Expect(startCA(store, pp)).To(Succeed())
		})

		It("stores it encrypted with EncryptCAKey too, and the CA starts on it", func() {
			given := encryptedKey(pp)

			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, given, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(Succeed())

			Expect(storedKeyType(store)).To(Equal("ENCRYPTED PRIVATE KEY"))
			Expect(storedKey(store)).NotTo(Equal(given), "encrypted afresh, with a new salt")
			Expect(startCA(store, pp)).To(Succeed())
		})

		// docs/ca-key-security.md tells an operator so: a key encrypted by
		// another tool carries the same PEM type, and has to be decrypted with
		// that tool first. A PKCS#8 EncryptedPrivateKeyInfo is a DER SEQUENCE,
		// so its first byte is 0x30.
		It("refuses a key encrypted by another tool, and writes nothing", func() {
			der := append([]byte{0x30, 0x82}, bytes.Repeat([]byte{0x01}, 80)...)
			foreign := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der})

			err := ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, foreign, nil,
				ca.ImportCAOptions{KeyPassphrase: pp})

			Expect(err).To(MatchError(ContainSubstring("not in openvox-ca's own encrypted form")))
			Expect(err).To(MatchError(ContainSubstring("decrypt it with `openssl pkey`")),
				"the remedy docs/ca-key-security.md gives, in the error itself")
			Expect(err).To(MatchError(ContainSubstring("--encrypt-ca-key")))
			expectNothingWritten()
		})

		It("still checks it against the certificate", func() {
			_, otherCrtPEM, _, err := testutil.GenerateTestCA()
			Expect(err).NotTo(HaveOccurred())

			err = ca.ImportCAWithOptions(ctx, store, otherCrtPEM, encryptedKey(pp), nil,
				ca.ImportCAOptions{KeyPassphrase: pp})

			Expect(err).To(MatchError(ContainSubstring("does not match")))
			expectNothingWritten()
		})

		It("refuses a key the passphrase does not open, and writes nothing", func() {
			wrong := filepath.Join(dir, "wrong")
			Expect(os.WriteFile(wrong, []byte("not-the-passphrase"), 0o600)).To(Succeed())

			err := ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, encryptedKey(pp), nil,
				ca.ImportCAOptions{KeyPassphrase: ca.KeyPassphraseConfig{PassphraseFile: wrong}})

			Expect(err).To(MatchError(ContainSubstring("decrypting CA key")))
			expectNothingWritten()
		})

		It("refuses with no passphrase source, naming the key as the reason, and writes nothing", func() {
			err := ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, encryptedKey(pp), nil, ca.ImportCAOptions{})

			Expect(err).To(MatchError(ContainSubstring("the key given to --private-key is encrypted")))
			expectNothingWritten()
		})
	})

	// The downgrade docs/migrating-from-puppet-server.md used to describe: an
	// operator re-importing under encrypt_ca_key feeds import the original
	// plaintext key, which replaced the encrypted one with nothing said.
	Context("given a plaintext key over an encrypted one", func() {
		var before []byte

		BeforeEach(func() {
			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(Succeed())
			before = storedKey(store)
		})

		It("refuses, naming both ways on, and leaves the stored key alone", func() {
			err := ca.ImportCA(ctx, store, cachedCrtPEM, cachedKeyPEM, nil)

			Expect(err).To(MatchError(ca.ErrPlaintextOverEncrypted))
			Expect(err).To(MatchError(ContainSubstring("--encrypt-ca-key")))
			Expect(err).To(MatchError(ContainSubstring("--allow-plaintext-ca-key")))
			Expect(storedKey(store)).To(Equal(before))
		})

		It("replaces it when AllowPlaintextOverEncrypted says to", func() {
			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{AllowPlaintextOverEncrypted: true})).To(Succeed())

			Expect(storedKey(store)).To(Equal(cachedKeyPEM))
			Expect(startCA(store, ca.KeyPassphraseConfig{})).To(Succeed(), "and no passphrase is needed any more")
		})
	})

	// The line says the key is encrypted at rest, so it is logged only once
	// one has been stored: import encodes before the checks that can still
	// refuse.
	Context("logging that the key is encrypted at rest", func() {
		var logBuf *bytes.Buffer

		BeforeEach(func() {
			logBuf = &bytes.Buffer{}
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo})))
			DeferCleanup(func() { slog.SetDefault(orig) })
		})

		It("says nothing when the import is refused", func() {
			_, otherCrtPEM, _, err := testutil.GenerateTestCA()
			Expect(err).NotTo(HaveOccurred())
			logBuf.Reset()

			Expect(ca.ImportCAWithOptions(ctx, store, otherCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(MatchError(ContainSubstring("does not match")))

			Expect(logBuf.String()).NotTo(ContainSubstring("encrypted at rest"))
		})

		It("says so for an encrypted key imported without EncryptCAKey", func() {
			given := encryptedKey(pp)
			logBuf.Reset()

			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, given, nil,
				ca.ImportCAOptions{KeyPassphrase: pp})).To(Succeed())

			Expect(strings.Count(logBuf.String(), "CA private key encrypted at rest")).To(Equal(1))
		})

		It("says so once the key is stored", func() {
			Expect(ca.ImportCAWithOptions(ctx, store, cachedCrtPEM, cachedKeyPEM, nil,
				ca.ImportCAOptions{EncryptCAKey: true, KeyPassphrase: pp})).To(Succeed())

			Expect(strings.Count(logBuf.String(), "CA private key encrypted at rest")).To(Equal(1))
		})
	})

	It("refuses a plaintext key when the stored key cannot be read, rather than guess", func() {
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(os.MkdirAll(store.CAKeyPath(), 0o750)).To(Succeed())

		err := ca.ImportCA(ctx, store, cachedCrtPEM, cachedKeyPEM, nil)

		Expect(err).To(MatchError(ContainSubstring("reading the stored CA key before replacing it")))
		Expect(store.HasCACert(ctx)).To(BeFalse(), "no certificate was written")
	})

	It("writes a plaintext key over a plaintext one exactly as given, as it always has", func() {
		Expect(ca.ImportCA(ctx, store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())
		Expect(ca.ImportCA(ctx, store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())

		Expect(storedKey(store)).To(Equal(cachedKeyPEM))
	})
})
