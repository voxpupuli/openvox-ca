// Copyright (C) 2026 Trevor Vaughan
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The CA enforces the same key-strength policy on client-submitted CSRs that
// ValidateKeyConfig enforces on server-side key generation: RSA must be at
// least 2048 bits and ECDSA must use an approved NIST curve (P-256/384/521).
// Without this gate a client could obtain a long-lived certificate over a
// 1024-bit RSA or otherwise-weak key. The gate lives at the issuance
// chokepoint, so every signing path (Sign, SignMultiple, SignAll, Renew) is
// covered.
var _ = Describe("Client CSR key-strength policy", func() {
	var (
		ctx    context.Context
		tmpDir string
		store  *storage.StorageService
	)

	// csrPEMFor builds a PEM-encoded CSR for cn signed by key, exercising an
	// arbitrary (possibly weak) client key.
	csrPEMFor := func(cn string, key crypto.Signer) []byte {
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}

	newCA := func(mode string) *ca.CA {
		c := ca.New(store, ca.AutosignConfig{Mode: mode}, "puppet.test")
		Expect(c.Init(ctx)).To(Succeed())
		return c
	}

	BeforeEach(func() {
		ctx = context.Background()
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-keystrength-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
	})

	AfterEach(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

	Context("through the autosign path", func() {
		It("rejects a CSR carrying a 1024-bit RSA key", func() {
			key, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).NotTo(HaveOccurred())

			myCA := newCA("true")
			_, err = myCA.SaveRequest(ctx, "weak-rsa-node", csrPEMFor("weak-rsa-node", key))
			Expect(err).To(HaveOccurred(), "a 1024-bit RSA CSR must not be signed")

			_, certErr := store.GetCert(ctx, "weak-rsa-node")
			Expect(certErr).To(HaveOccurred(), "no certificate must be issued for a weak key")
		})

		It("rejects a CSR carrying an unapproved ECDSA curve (P-224)", func() {
			key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			myCA := newCA("true")
			_, err = myCA.SaveRequest(ctx, "weak-ec-node", csrPEMFor("weak-ec-node", key))
			Expect(err).To(HaveOccurred(), "a P-224 ECDSA CSR must not be signed")
		})

		It("issues for a compliant 2048-bit RSA key", func() {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			myCA := newCA("true")
			signed, err := myCA.SaveRequest(ctx, "good-rsa-node", csrPEMFor("good-rsa-node", key))
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeTrue(), "a compliant CSR must be autosigned")

			certPEM, err := store.GetCert(ctx, "good-rsa-node")
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).NotTo(BeEmpty())
		})

		It("issues for a compliant P-256 ECDSA key", func() {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			myCA := newCA("true")
			signed, err := myCA.SaveRequest(ctx, "good-ec-node", csrPEMFor("good-ec-node", key))
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeTrue())
		})
	})

	Context("through an explicit Sign after the CSR is stored", func() {
		It("refuses to sign a stored weak-key CSR", func() {
			key, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).NotTo(HaveOccurred())

			// Autosign off: SaveRequest stores the CSR without signing it.
			myCA := newCA("off")
			signed, err := myCA.SaveRequest(ctx, "stored-weak-node", csrPEMFor("stored-weak-node", key))
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeFalse())

			// The issuance chokepoint must reject it.
			_, err = myCA.Sign(ctx, "stored-weak-node")
			Expect(err).To(HaveOccurred(), "Sign must reject a stored weak-key CSR")
		})
	})
})
