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
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The subject "ca" would have its generated key written to private/ca_key.pem,
// which is the CA key itself in a cadir an earlier openvox-ca created, and the
// CA key's legacy location in a fresh one (#495). Every path that generates a
// key refuses it; submitting a CSR for it does not.
var _ = Describe("Generating a key for the subject \"ca\"", func() {
	var (
		ctx   = context.Background()
		dir   string
		store *storage.StorageService
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		store = storage.New(dir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
	})

	initCA := func() *ca.CA {
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())
		return myCA
	}

	Context("when the cadir keeps the CA key in private/", func() {
		var keyPath string

		BeforeEach(func() {
			keyPath = filepath.Join(dir, "private", "ca_key.pem")
			Expect(os.WriteFile(keyPath, cachedKeyPEM, 0o600)).To(Succeed())
		})

		It("is refused, and leaves the CA key as it was", func() {
			_, err := initCA().Generate(ctx, "ca", nil)

			Expect(err).To(MatchError(ca.ErrReservedSubject))
			Expect(os.ReadFile(keyPath)).To(Equal(cachedKeyPEM))
		})
	})

	Context("when the cadir keeps the CA key where OpenVox Server does", func() {
		BeforeEach(func() {
			Expect(os.WriteFile(filepath.Join(dir, "ca_key.pem"), cachedKeyPEM, 0o600)).To(Succeed())
		})

		It("is refused, and writes no second CA key, so the CA still starts", func() {
			_, err := initCA().Generate(ctx, "ca", nil)

			Expect(err).To(MatchError(ca.ErrReservedSubject))
			Expect(filepath.Join(dir, "private", "ca_key.pem")).NotTo(BeAnExistingFile())
			Expect(ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test").Init(ctx)).To(Succeed())
		})
	})

	Context("on an initialised CA", func() {
		var myCA *ca.CA

		BeforeEach(func() {
			Expect(os.WriteFile(filepath.Join(dir, "ca_key.pem"), cachedKeyPEM, 0o600)).To(Succeed())
			myCA = initCA()
		})

		It("is refused before a key is generated or anything issued, even when the caller keeps the key", func() {
			// The offline CLI's --key-out shape: the key would go to the
			// caller, not to private/. Still refused, so that "ca" means one
			// thing on every path that generates a key.
			emitted := false
			_, err := myCA.GenerateWithOptions(ctx, "ca", ca.GenerateOptions{
				EmitKey: func([]byte) error { emitted = true; return nil },
			})

			Expect(err).To(MatchError(ca.ErrReservedSubject))
			Expect(emitted).To(BeFalse())
			Expect(store.HasCert(ctx, "ca")).To(BeFalse())
			Expect(store.ReadInventory(ctx)).To(BeEmpty())
		})

		It("still accepts a CSR for it, which writes no private key", func() {
			// OpenVox Server accepts "ca" as a certname, and a CSR carries the
			// requester's own public key, so there is nothing to protect here.
			csrPEM, _ := buildCSR("ca")
			_, err := myCA.SaveRequest(ctx, "ca", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.HasCSR(ctx, "ca")).To(BeTrue())
			Expect(filepath.Join(dir, "private", "ca_key.pem")).NotTo(BeAnExistingFile())
			Expect(os.ReadFile(filepath.Join(dir, "ca_key.pem"))).To(Equal(cachedKeyPEM))
		})
	})
})

var _ = Describe("A managed certificate for the subject \"ca\"", func() {
	It("is refused as configuration, before anything is issued", func() {
		spec := ca.CertSpec{
			Subject:     "ca",
			DNSNames:    []string{"ca.example.test"},
			RenewBefore: time.Hour,
		}
		err := spec.Validate()
		Expect(err).To(MatchError(ca.ErrReservedSubject))
		Expect(err).To(MatchError(ContainSubstring("managed certificate ca:")))
	})

	It("is the subject alone that is refused", func() {
		// The same spec under another certname passes, so the refusal above
		// is about the subject and not some other field of the fixture.
		spec := ca.CertSpec{
			Subject:     "ca-proxy",
			DNSNames:    []string{"ca.example.test"},
			RenewBefore: time.Hour,
		}
		Expect(spec.Validate()).To(Succeed())
	})
})
