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
	"context"
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// How openvox-ca-ctl migrate writes the CA key into its destination (#516).
// Each key written encrypted is checked the way the server would check it:
// installed beside its certificate and loaded by Init with the destination's
// passphrase.
var _ = Describe("MigrateCAKey.Encode", func() {
	var (
		ctx          context.Context
		dir          string
		ppA, ppB     ca.KeyPassphraseConfig
		encryptedByA []byte
	)

	writePassphrase := func(name, value string) ca.KeyPassphraseConfig {
		GinkgoHelper()
		path := filepath.Join(dir, name)
		Expect(os.WriteFile(path, []byte(value), 0o600)).To(Succeed())
		return ca.KeyPassphraseConfig{PassphraseFile: path}
	}

	// startsOn installs keyPEM beside the cached certificate in a fresh store
	// and starts a CA there with cfg, as the server would on the destination.
	startsOn := func(keyPEM []byte, cfg ca.KeyPassphraseConfig) error {
		GinkgoHelper()
		store := storage.New(filepath.Join(GinkgoT().TempDir(), "dst"))
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.SaveCAKey(ctx, keyPEM)).To(Succeed())
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.KeyPassphrase = cfg
		return myCA.Init(ctx)
	}

	pemType := func(keyPEM []byte) string {
		GinkgoHelper()
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		return block.Type
	}

	BeforeEach(func() {
		ctx = context.Background()
		GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "")
		dir = GinkgoT().TempDir()
		ppA = writePassphrase("a", "passphrase-a")
		ppB = writePassphrase("b", "passphrase-b")

		var encrypted bool
		var err error
		encryptedByA, encrypted, err = ca.MigrateCAKey{Dest: ppA, DestEncrypt: true}.Encode(cachedKeyPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(encrypted).To(BeTrue())
	})

	Context("from a plaintext key", func() {
		It("copies it as it is when the destination does not set encrypt_ca_key", func() {
			out, encrypted, err := ca.MigrateCAKey{Dest: ppB}.Encode(cachedKeyPEM)

			Expect(err).NotTo(HaveOccurred())
			Expect(encrypted).To(BeFalse())
			Expect(out).To(Equal(cachedKeyPEM))
		})

		It("encrypts it under the destination's passphrase when the destination sets encrypt_ca_key", func() {
			out, encrypted, err := ca.MigrateCAKey{Dest: ppB, DestEncrypt: true}.Encode(cachedKeyPEM)

			Expect(err).NotTo(HaveOccurred())
			Expect(encrypted).To(BeTrue())
			Expect(pemType(out)).To(Equal("ENCRYPTED PRIVATE KEY"))
			Expect(startsOn(out, ppB)).To(Succeed())
		})

		It("refuses encrypt_ca_key with no destination passphrase, naming the destination's setting", func() {
			_, _, err := ca.MigrateCAKey{DestEncrypt: true}.Encode(cachedKeyPEM)

			Expect(err).To(MatchError(ContainSubstring("encrypt_ca_key is set in --dest-config")))
			Expect(err).To(MatchError(ContainSubstring("ca_key_passphrase_file in --dest-config")))
		})

		It("copies a key that is not PEM as it is, as migrate always has", func() {
			out, encrypted, err := ca.MigrateCAKey{}.Encode([]byte("not-pem"))

			Expect(err).NotTo(HaveOccurred())
			Expect(encrypted).To(BeFalse(), "migrate would otherwise say it encrypted the key")
			Expect(out).To(Equal([]byte("not-pem")))
		})

		It("refuses to encrypt a PEM key that does not parse", func() {
			corrupt := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})

			_, _, err := ca.MigrateCAKey{Dest: ppB, DestEncrypt: true}.Encode(corrupt)

			Expect(err).To(MatchError(ContainSubstring("parsing the source's CA key to encrypt it")))
		})

		It("refuses to encrypt a key that is not PEM", func() {
			_, _, err := ca.MigrateCAKey{Dest: ppB, DestEncrypt: true}.Encode([]byte("not-pem"))

			Expect(err).To(MatchError(ContainSubstring("not a PEM block")))
		})
	})

	Context("from an encrypted key", func() {
		It("re-encrypts it under the destination's passphrase, which alone then opens it", func() {
			out, encrypted, err := ca.MigrateCAKey{Source: ppA, Dest: ppB, DestEncrypt: true}.Encode(encryptedByA)

			Expect(err).NotTo(HaveOccurred())
			Expect(encrypted).To(BeTrue())
			Expect(startsOn(out, ppB)).To(Succeed())
			Expect(startsOn(out, ppA)).To(MatchError(ContainSubstring("decrypting CA key")),
				"the source's passphrase no longer opens it")
		})

		It("keeps it encrypted when the destination does not set encrypt_ca_key", func() {
			out, encrypted, err := ca.MigrateCAKey{Source: ppA, Dest: ppB}.Encode(encryptedByA)

			Expect(err).NotTo(HaveOccurred())
			Expect(encrypted).To(BeTrue())
			Expect(pemType(out)).To(Equal("ENCRYPTED PRIVATE KEY"), "never a decrypted copy")
			Expect(startsOn(out, ppB)).To(Succeed())
		})

		It("refuses when the destination has no passphrase, saying why one is needed", func() {
			_, _, err := ca.MigrateCAKey{Source: ppA}.Encode(encryptedByA)

			Expect(err).To(MatchError(ContainSubstring("migrate does not write a decrypted copy")))
			Expect(err).To(MatchError(ContainSubstring("ca_key_passphrase_file in --dest-config")))
		})

		It("names encrypt_ca_key as the reason when the destination sets it and has no passphrase", func() {
			_, _, err := ca.MigrateCAKey{Source: ppA, DestEncrypt: true}.Encode(encryptedByA)

			Expect(err).To(MatchError(ContainSubstring("encrypt_ca_key is set in --dest-config")))
			Expect(err).NotTo(MatchError(ContainSubstring("does not write a decrypted copy")))
		})

		It("refuses when the source has no passphrase, naming the source's setting", func() {
			_, _, err := ca.MigrateCAKey{Dest: ppB, DestEncrypt: true}.Encode(encryptedByA)

			Expect(err).To(MatchError(ContainSubstring("the source's CA key is encrypted")))
			Expect(err).To(MatchError(ContainSubstring("ca_key_passphrase_file in --source-config")))
		})

		It("refuses when the source's passphrase does not open it", func() {
			_, _, err := ca.MigrateCAKey{Source: ppB, Dest: ppB, DestEncrypt: true}.Encode(encryptedByA)

			Expect(err).To(MatchError(ContainSubstring("the source's CA key: decrypting CA key")))
		})

		It("reads both ends from the environment when neither names a file", func() {
			GinkgoT().Setenv(ca.DefaultPassphraseEnvVar, "passphrase-a")

			out, _, err := ca.MigrateCAKey{DestEncrypt: true}.Encode(encryptedByA)

			Expect(err).NotTo(HaveOccurred())
			Expect(startsOn(out, ca.KeyPassphraseConfig{})).To(Succeed())
		})
	})
})
