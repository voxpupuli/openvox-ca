// Copyright (C) 2026 Trevor Vaughan
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

package ca

import (
	"context"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// gcmTagLen is the AES-GCM authentication tag length appended to every
// ciphertext (crypto/cipher uses the standard 16-byte tag).
const gcmTagLen = 16

var _ = Describe("Key encryption", func() {
	Describe("encryptKeyPEM / decryptKeyDER round-trip", func() {
		It("encrypts and decrypts an RSA key", func() {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			passphrase := []byte("test-passphrase-12345")
			encPEM, err := encryptAndMarshalKey(key, passphrase)
			Expect(err).NotTo(HaveOccurred())

			block, _ := pem.Decode(encPEM)
			Expect(block).NotTo(BeNil())
			Expect(block.Type).To(Equal(encryptedPEMType))

			pkcs8DER, err := decryptKeyDER(block.Bytes, passphrase)
			Expect(err).NotTo(HaveOccurred())

			parsed, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
			Expect(err).NotTo(HaveOccurred())

			rsaKey, ok := parsed.(*rsa.PrivateKey)
			Expect(ok).To(BeTrue())
			Expect(rsaKey.D.Cmp(key.D)).To(Equal(0))
		})

		It("encrypts and decrypts an ECDSA key", func() {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			passphrase := []byte("another-passphrase")
			encPEM, err := encryptAndMarshalKey(key, passphrase)
			Expect(err).NotTo(HaveOccurred())

			block, _ := pem.Decode(encPEM)
			Expect(block).NotTo(BeNil())

			pkcs8DER, err := decryptKeyDER(block.Bytes, passphrase)
			Expect(err).NotTo(HaveOccurred())

			parsed, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
			Expect(err).NotTo(HaveOccurred())

			ecKey, ok := parsed.(*ecdsa.PrivateKey)
			Expect(ok).To(BeTrue())
			Expect(ecKey.Equal(key)).To(BeTrue())
		})

		It("fails decryption with wrong passphrase", func() {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			encPEM, err := encryptAndMarshalKey(key, []byte("correct"))
			Expect(err).NotTo(HaveOccurred())

			block, _ := pem.Decode(encPEM)
			_, err = decryptKeyDER(block.Bytes, []byte("wrong"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("wrong passphrase"))
		})

		It("fails decryption when a ciphertext byte is tampered (GCM integrity)", func() {
			// Encrypt a real key to a valid envelope.
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			passphrase := []byte("integrity-passphrase")
			encPEM, err := encryptAndMarshalKey(key, passphrase)
			Expect(err).NotTo(HaveOccurred())

			block, _ := pem.Decode(encPEM)
			Expect(block).NotTo(BeNil())

			// Sanity-check the envelope decrypts cleanly before tampering.
			_, err = decryptKeyDER(block.Bytes, passphrase)
			Expect(err).NotTo(HaveOccurred())

			// Flip one bit in the ciphertext region. The header occupies
			// keyEncMinLen-aes.BlockSize bytes (version+salt+nonce); the GCM
			// tag is the final 16 bytes. Target a byte well past the header and
			// before the tag so we mutate ciphertext, not the tag or header.
			headerLen := keyEncMinLen - aes.BlockSize // 1 + salt + nonce
			Expect(len(block.Bytes)).To(BeNumerically(">", headerLen+gcmTagLen),
				"envelope must have ciphertext between header and GCM tag")
			tamperOffset := len(block.Bytes) - gcmTagLen - 1 // last ciphertext byte before the tag
			Expect(tamperOffset).To(BeNumerically(">=", headerLen))
			block.Bytes[tamperOffset] ^= 0x01

			// GCM must fail closed: authentication detects the tamper.
			_, err = decryptKeyDER(block.Bytes, passphrase)
			Expect(err).To(HaveOccurred())
		})

		It("fails on truncated envelope", func() {
			_, err := decryptKeyDER([]byte{0x01, 0x02}, []byte("pass"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("too short"))
		})

		It("fails on unsupported version", func() {
			envelope := make([]byte, keyEncMinLen+10)
			envelope[0] = 0xFF
			_, err := decryptKeyDER(envelope, []byte("pass"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported"))
		})
	})

	Describe("resolvePassphrase", func() {
		var tmpDir string

		BeforeEach(func() {
			// Every refusal here relies on there being no passphrase in the
			// environment, which is exactly what an operator of this tool is
			// likely to have exported in their own shell. Left ambient, those
			// specs fail on the very assertion meant to prove the refusal, for a
			// reason that has nothing to do with the code. Empty counts as unset
			// to the resolver, and GinkgoT restores the original afterwards.
			GinkgoT().Setenv("OPENVOX_CA_KEY_PASSPHRASE", "")

			var err error
			tmpDir, err = os.MkdirTemp("", "keyenc-test-*")
			Expect(err).NotTo(HaveOccurred())
			Expect(os.MkdirAll(filepath.Join(tmpDir, "private"), 0750)).To(Succeed())
		})

		AfterEach(func() {
			os.RemoveAll(tmpDir)
		})

		It("reads passphrase from explicit file", func() {
			ppFile := filepath.Join(tmpDir, "pp.txt")
			Expect(os.WriteFile(ppFile, []byte("my-secret\n"), 0600)).To(Succeed())

			pp, err := resolvePassphrase(KeyPassphraseConfig{
				PassphraseFile: ppFile,
			}, tmpDir, needEncryptConfigured)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(pp)).To(Equal("my-secret"))
		})

		It("reads passphrase from environment variable", func() {
			prev, had := os.LookupEnv("OPENVOX_CA_KEY_PASSPHRASE")
			DeferCleanup(func() {
				if had {
					os.Setenv("OPENVOX_CA_KEY_PASSPHRASE", prev)
				} else {
					os.Unsetenv("OPENVOX_CA_KEY_PASSPHRASE")
				}
			})
			os.Setenv("OPENVOX_CA_KEY_PASSPHRASE", "env-secret")

			pp, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir, needEncryptConfigured)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(pp)).To(Equal("env-secret"))
		})

		// #349's hard break: a passphrase left in the pre-rename variable is not
		// read. The refusal is the one a missing passphrase gets, so an operator
		// who renamed nothing is stopped rather than handed a CA that cannot
		// unlock its key.
		It("ignores a passphrase left in the pre-rename PUPPET_CA_KEY_PASSPHRASE", func() {
			GinkgoT().Setenv(DefaultPassphraseEnvVar, "")
			GinkgoT().Setenv("PUPPET_CA_KEY_PASSPHRASE", "old-secret")

			pp, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir, needEncryptConfigured)
			Expect(err).To(HaveOccurred(), "the old variable was read")
			Expect(pp).To(BeNil())
			Expect(err.Error()).To(ContainSubstring("no passphrase source is configured"))
		})

		It("reads the variable EnvVar names when another name is configured", func() {
			// The launcher withholds cfg.EnvVar() from the frontend, so the
			// variable resolved here and the one withheld there must be one.
			cfg := KeyPassphraseConfig{PassphraseEnvVar: "SITE_CA_KEY_PASSPHRASE"}
			GinkgoT().Setenv(cfg.EnvVar(), "custom-secret")

			pp, err := resolvePassphrase(cfg, tmpDir, needEncryptConfigured)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(pp)).To(Equal("custom-secret"))
		})

		// Generating one here would mean writing it beside the key, which would
		// make docs/ca-key-security.md's backup-and-snapshot claim false: a copy
		// of the cadir would carry the ciphertext and the passphrase together
		// (#432).
		It("refuses when encryption is on and no passphrase source is configured", func() {
			pp, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir, needEncryptConfigured)

			Expect(err).To(HaveOccurred(), "a missing passphrase is not something to invent")
			// Nil alongside the error, not merely unused by the callers. They
			// check err first so a stray value is inert today, but the contract
			// is "no passphrase", and a future caller reading the value before
			// the error should get nothing rather than something plausible.
			Expect(pp).To(BeNil(), "and no passphrase came back with it")
			Expect(err.Error()).To(ContainSubstring("encrypt_ca_key is set"),
				"this call says encryption is configured, so that is what the message must name")
			Expect(err.Error()).To(ContainSubstring("no passphrase source is configured"))
			Expect(err.Error()).To(ContainSubstring("ca_key_passphrase_file"), "the remedy")
			Expect(err.Error()).To(ContainSubstring("OPENVOX_CA_KEY_PASSPHRASE"), "or the other one")

			Expect(autoPassphrasePath(tmpDir)).NotTo(BeAnExistingFile(),
				"and nothing was written in the process of refusing")
		})

		// A file at the auto-passphrase path must not be read implicitly: a
		// passphrase beside the key it protects defends nothing. But the file
		// may still be a perfectly good passphrase, so the refusal has to say
		// how to use it or the operator's CA is simply gone.
		It("refuses but names the file when one exists at the auto-passphrase path", func() {
			autoPath := autoPassphrasePath(tmpDir)
			Expect(os.WriteFile(autoPath, []byte("a-passphrase-at-the-auto-path"), 0600)).To(Succeed())

			_, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir, needEncryptConfigured)

			Expect(err).To(HaveOccurred(), "not read implicitly, even though it is there")
			Expect(err.Error()).To(ContainSubstring(autoPath), "the file it found")
			Expect(err.Error()).To(ContainSubstring("set ca_key_passphrase_file to that path"),
				"how to keep the CA working")
			// Judged without the path, which comes from TMPDIR and could
			// contain either phrase without the message's own words doing so.
			authored := strings.ReplaceAll(err.Error(), autoPath, "")
			Expect(authored).NotTo(ContainSubstring("version"),
				"no release has generated this file, so the message must not cite one (#310)")
			Expect(authored).NotTo(ContainSubstring("no longer"),
				"nor imply a behaviour openvox-ca has changed since one (#310)")
		})

		// And the remedy the refusal names actually works, which is the half a
		// message-only assertion cannot show.
		It("accepts the file at the auto-passphrase path once it is configured explicitly", func() {
			autoPath := autoPassphrasePath(tmpDir)
			Expect(os.WriteFile(autoPath, []byte("a-passphrase-at-the-auto-path"), 0600)).To(Succeed())

			pp, err := resolvePassphrase(KeyPassphraseConfig{PassphraseFile: autoPath}, tmpDir, needEncryptConfigured)

			Expect(err).NotTo(HaveOccurred(), "the remedy in the message has to work")
			Expect(string(pp)).To(Equal("a-passphrase-at-the-auto-path"))
		})

		// The load path's own reason, which had no anchor at all: the message
		// opened "encrypt_ca_key is set" wherever it was raised, and on this
		// path that is false -- loadCAKeyFromDisk resolves a passphrase because
		// the stored PEM is encrypted, whatever the setting says.
		It("names the stored key, not the setting, when that is the reason", func() {
			_, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir, needStoredKeyEncrypted)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("the CA key in the store is encrypted"))
			Expect(err.Error()).NotTo(ContainSubstring("encrypt_ca_key is set"),
				"pointing at a setting the operator may have deliberately unset is the defect")
		})

		It("names the stored key in the auto-passphrase-path remedy too", func() {
			autoPath := autoPassphrasePath(tmpDir)
			Expect(os.WriteFile(autoPath, []byte("a-passphrase-at-the-auto-path"), 0600)).To(Succeed())

			_, err := resolvePassphrase(KeyPassphraseConfig{}, tmpDir, needStoredKeyEncrypted)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("the CA key in the store is encrypted"))
			Expect(err.Error()).To(ContainSubstring(autoPath), "and still names the file")
		})

		// The contract the comments now state, pinned so that a well-meaning
		// strings.TrimSpace cannot slip in: "first line" means up to the first
		// CR or LF, and nothing else is removed. Trimming would stop an existing
		// CA decrypting if its passphrase legitimately ends in a space, which is
		// a compatibility break nobody would notice until a restart -- every
		// other spec here writes a passphrase with no trailing whitespace, so
		// all of them would stay green while it happened.
		DescribeTable("takes the first line verbatim, removing nothing else",
			func(contents, want string) {
				ppFile := filepath.Join(tmpDir, "pp.txt")
				Expect(os.WriteFile(ppFile, []byte(contents), 0600)).To(Succeed())

				pp, err := resolvePassphrase(KeyPassphraseConfig{PassphraseFile: ppFile},
					tmpDir, needEncryptConfigured)

				Expect(err).NotTo(HaveOccurred())
				Expect(string(pp)).To(Equal(want))
			},
			Entry("a trailing space survives", "pp \n", "pp "),
			Entry("a leading space survives", " pp\n", " pp"),
			Entry("CRLF is cut at the CR", "pp\r\n", "pp"),
			Entry("a bare CR ends the line", "pp\rrest", "pp"),
			Entry("a second line is dropped", "pp\nsecond", "pp"),
			Entry("no terminator at all", "pp", "pp"),
		)

		It("errors on empty passphrase file", func() {
			ppFile := filepath.Join(tmpDir, "empty.txt")
			Expect(os.WriteFile(ppFile, []byte(""), 0600)).To(Succeed())

			_, err := resolvePassphrase(KeyPassphraseConfig{
				PassphraseFile: ppFile,
			}, tmpDir, needEncryptConfigured)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("empty"))
		})
	})

	DescribeTable("KeyPassphraseConfig.EnvVar",
		func(cfg KeyPassphraseConfig, want string) {
			Expect(cfg.EnvVar()).To(Equal(want))
		},
		Entry("defaults to OPENVOX_CA_KEY_PASSPHRASE", KeyPassphraseConfig{}, "OPENVOX_CA_KEY_PASSPHRASE"),
		Entry("names a configured variable", KeyPassphraseConfig{PassphraseEnvVar: "SITE_CA_KEY_PASSPHRASE"}, "SITE_CA_KEY_PASSPHRASE"),
	)

	// PassphraseNeeded is what lets the server raise a missing-passphrase
	// refusal before it forks, so it has to answer the question CA.Init will
	// actually ask. The two conditions are independent and disagree in both
	// directions, which is why the answer cannot come from the setting alone.
	Describe("PassphraseNeeded", func() {
		var tmpDir string

		BeforeEach(func() {
			// As for resolvePassphrase: CheckKeyPassphrase's refusal below needs
			// the environment empty, not merely assumed empty.
			GinkgoT().Setenv("OPENVOX_CA_KEY_PASSPHRASE", "")

			var err error
			tmpDir, err = os.MkdirTemp("", "openvox-ca-need-test")
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })
		})

		// An encrypted PEM to feed it, made the way the CA makes one rather
		// than hand-rolled, so the predicate is tested against the real shape.
		encryptedPEM := func() []byte {
			GinkgoHelper()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			pemBytes, err := encryptAndMarshalKey(key, []byte("pp"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(pemBytes)).To(ContainSubstring("ENCRYPTED PRIVATE KEY"))
			return pemBytes
		}

		plaintextPEM := func() []byte {
			GinkgoHelper()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			pemBytes, err := marshalPrivateKeyPEM(key)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(pemBytes)).NotTo(ContainSubstring("ENCRYPTED"))
			return pemBytes
		}

		It("needs one for an encrypted stored key even with encryption off", func() {
			// The case a check written against cfg.EncryptCAKey would miss, and
			// the whole reason the preflight reads the key.
			Expect(PassphraseNeeded(false, encryptedPEM())).To(BeTrue())
		})

		It("needs none for a plaintext stored key even with encryption on", func() {
			// The other direction. Nothing re-encrypts a key that already
			// exists, so refusing here would stop a CA that works today.
			Expect(PassphraseNeeded(true, plaintextPEM())).To(BeFalse())
		})

		DescribeTable("falls back to the setting when there is no stored key",
			func(encrypt bool, stored []byte, expected bool) {
				Expect(PassphraseNeeded(encrypt, stored)).To(Equal(expected))
			},
			Entry("bootstrap with encryption", true, nil, true),
			Entry("bootstrap without encryption", false, nil, false),
			Entry("empty blob with encryption", true, []byte{}, true),
			// A blob that is not PEM at all is Init's to report, precisely;
			// refusing here on a condition it will describe better would
			// replace a good error with a worse one.
			Entry("undecodable blob with encryption", true, []byte("not a pem file"), true),
			Entry("undecodable blob without encryption", false, []byte("not a pem file"), false),
		)

		Describe("CheckKeyPassphrase", func() {
			It("refuses when one is needed and no source is configured", func() {
				err := CheckKeyPassphrase(KeyPassphraseConfig{}, tmpDir, false, encryptedPEM())

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("the CA key in the store is encrypted"))
			})

			It("passes when none is needed", func() {
				Expect(CheckKeyPassphrase(KeyPassphraseConfig{}, tmpDir, true, plaintextPEM())).To(Succeed())
			})

			// The environment is the source the pre-fork preflight exists to
			// protect: it is the one a launcher can strip from a child, and the
			// file-source spec below would stay green if CheckKeyPassphrase
			// stopped consulting it.
			It("passes when the only source is the environment", func() {
				GinkgoT().Setenv("OPENVOX_CA_KEY_PASSPHRASE", "env-secret")

				Expect(CheckKeyPassphrase(KeyPassphraseConfig{}, tmpDir, true, nil)).To(Succeed())
			})

			It("passes when one is needed and a source is configured", func() {
				ppFile := filepath.Join(tmpDir, "pp")
				Expect(os.WriteFile(ppFile, []byte("pp\n"), 0600)).To(Succeed())

				Expect(CheckKeyPassphrase(KeyPassphraseConfig{PassphraseFile: ppFile},
					tmpDir, false, encryptedPEM())).To(Succeed())
			})
		})
	})

	Describe("isEncryptedPEM", func() {
		It("returns true for encrypted PEM type", func() {
			Expect(isEncryptedPEM(&pem.Block{Type: encryptedPEMType})).To(BeTrue())
		})
		It("returns false for standard PEM types", func() {
			Expect(isEncryptedPEM(&pem.Block{Type: "RSA PRIVATE KEY"})).To(BeFalse())
			Expect(isEncryptedPEM(&pem.Block{Type: "PRIVATE KEY"})).To(BeFalse())
		})
		It("returns false for nil block", func() {
			Expect(isEncryptedPEM(nil)).To(BeFalse())
		})
	})
})

var _ = Describe("CA encrypted key integration", func() {
	BeforeEach(func() {
		// The two refusal specs below depend on there being no passphrase in the
		// environment; the bootstrap-and-reload spec does not care either way.
		GinkgoT().Setenv("OPENVOX_CA_KEY_PASSPHRASE", "")
	})

	// The resolver's refusal is pinned directly above, and the pre-fork
	// preflight is pinned in cmd/openvox-ca. Neither drives CA.Init, which is
	// where the refusal actually runs on both of its paths -- so nothing showed
	// that Init surfaces it, that the bootstrap path writes nothing on the way
	// to refusing, or that the load path passes the reason it really has.
	It("refuses to bootstrap with encryption and no passphrase source", func() {
		tmpDir := GinkgoT().TempDir()

		store := storage.New(tmpDir)
		myCA := New(store, AutosignConfig{Mode: "off"}, "puppet-enc-test")
		myCA.EncryptCAKey = true

		err := myCA.Init(context.Background())

		Expect(err).To(MatchError(ContainSubstring("resolving CA key passphrase")))
		Expect(err).To(MatchError(ContainSubstring("encrypt_ca_key is set")),
			"bootstrap needs one because encryption is configured, so that is the reason")

		// Nothing was written in the process of refusing -- in particular not
		// a plaintext key, which is what a refusal raised after the save would
		// have left behind.
		has, herr := store.HasCAKey(context.Background())
		Expect(herr).NotTo(HaveOccurred())
		Expect(has).To(BeFalse(), "no CA key of any kind may be stored on the way to refusing")
	})

	It("refuses to load an encrypted key with no source, naming the stored key", func() {
		tmpDir := GinkgoT().TempDir()
		ppFile := filepath.Join(tmpDir, "passphrase")
		Expect(os.WriteFile(ppFile, []byte("integration-passphrase\n"), 0o600)).To(Succeed())

		first := New(storage.New(tmpDir), AutosignConfig{Mode: "off"}, "puppet-enc-test")
		first.EncryptCAKey = true
		first.KeyPassphrase = KeyPassphraseConfig{PassphraseFile: ppFile}
		Expect(first.Init(context.Background())).To(Succeed(), "bootstrap an encrypted CA")

		// Reload with encryption *off* and no source. The key on disk is still
		// encrypted, so the load path needs a passphrase anyway -- and the
		// refusal has to say so, rather than blame a setting that is not set.
		second := New(storage.New(tmpDir), AutosignConfig{Mode: "off"}, "puppet-enc-test")
		err := second.Init(context.Background())

		Expect(err).To(MatchError(ContainSubstring("resolving CA key passphrase")))
		Expect(err).To(MatchError(ContainSubstring("the CA key in the store is encrypted")))
		Expect(err).NotTo(MatchError(ContainSubstring("encrypt_ca_key is set")),
			"encrypt_ca_key is not set on this load, so naming it would be false")
	})

	It("bootstraps with encrypted key and reloads successfully", func() {
		tmpDir, err := os.MkdirTemp("", "openvox-ca-keyenc-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		// A configured passphrase file, because nothing else supplies one
		// (#432). This spec is about encrypting and reloading, not about where
		// the passphrase came from.
		ppFile := filepath.Join(tmpDir, "passphrase")
		Expect(os.WriteFile(ppFile, []byte("integration-passphrase\n"), 0o600)).To(Succeed())
		ppCfg := KeyPassphraseConfig{PassphraseFile: ppFile}

		store := storage.New(tmpDir)
		myCA := New(store, AutosignConfig{Mode: "off"}, "puppet-enc-test")
		myCA.EncryptCAKey = true
		myCA.KeyPassphrase = ppCfg
		Expect(myCA.Init(context.Background())).To(Succeed())
		Expect(myCA.CACert).NotTo(BeNil())
		Expect(myCA.CAKey).NotTo(BeNil())

		// Verify the key file on disk is encrypted PEM.
		keyPEM, err := store.GetCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal(encryptedPEMType))

		// And nothing was written beside the key, which is the point of the
		// change: the passphrase lives where the operator put it.
		Expect(autoPassphrasePath(tmpDir)).NotTo(BeAnExistingFile(),
			"no passphrase generated next to the key it protects")

		// Reload the CA from disk with the same configured passphrase.
		store2 := storage.New(tmpDir)
		myCA2 := New(store2, AutosignConfig{Mode: "off"}, "puppet-enc-test")
		myCA2.EncryptCAKey = true
		myCA2.KeyPassphrase = ppCfg
		Expect(myCA2.Init(context.Background())).To(Succeed())
		Expect(myCA2.CACert).NotTo(BeNil())
		Expect(myCA2.CAKey).NotTo(BeNil())

		// Sign a cert to verify the loaded key is functional.
		csrPEM, err := generateTestCSR("enc-test-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA2.SaveRequest(context.Background(), "enc-test-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA2.Sign(context.Background(), "enc-test-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(certPEM).NotTo(BeEmpty())
	})

	It("loads unencrypted key transparently (backward compat)", func() {
		tmpDir, err := os.MkdirTemp("", "openvox-ca-keyenc-compat-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		// Bootstrap without encryption.
		store := storage.New(tmpDir)
		myCA := New(store, AutosignConfig{Mode: "off"}, "puppet-compat")
		myCA.EncryptCAKey = false
		Expect(myCA.Init(context.Background())).To(Succeed())

		// Verify key is unencrypted.
		keyPEM, err := store.GetCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).NotTo(Equal(encryptedPEMType))

		// Reload: should work without encryption config.
		store2 := storage.New(tmpDir)
		myCA2 := New(store2, AutosignConfig{Mode: "off"}, "puppet-compat")
		Expect(myCA2.Init(context.Background())).To(Succeed())
		Expect(myCA2.CACert).NotTo(BeNil())
	})

	It("fails to load encrypted key with wrong passphrase", func() {
		tmpDir, err := os.MkdirTemp("", "openvox-ca-keyenc-wrong-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		// Bootstrap with encryption and a configured passphrase.
		ppFile := filepath.Join(tmpDir, "passphrase")
		Expect(os.WriteFile(ppFile, []byte("right-passphrase\n"), 0o600)).To(Succeed())

		store := storage.New(tmpDir)
		myCA := New(store, AutosignConfig{Mode: "off"}, "puppet-wrong")
		myCA.EncryptCAKey = true
		myCA.KeyPassphrase = KeyPassphraseConfig{PassphraseFile: ppFile}
		Expect(myCA.Init(context.Background())).To(Succeed())

		// Change the configured passphrase under it by rewriting the file the
		// operator configured.
		Expect(os.WriteFile(ppFile, []byte("wrong-passphrase\n"), 0o600)).To(Succeed())

		// Reload should fail, and for the passphrase rather than for a missing
		// source -- which is why the file is still configured here.
		store2 := storage.New(tmpDir)
		myCA2 := New(store2, AutosignConfig{Mode: "off"}, "puppet-wrong")
		myCA2.KeyPassphrase = KeyPassphraseConfig{PassphraseFile: ppFile}
		err = myCA2.Init(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("wrong passphrase"))
	})
})

// generateTestCSR creates a CSR PEM for testing.
func generateTestCSR(cn string) ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}
