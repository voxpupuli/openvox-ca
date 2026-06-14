// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// under terms GNU General Public License as published by
// Free Software Foundation; either version 2 License, or
// (at your option) any later version.
//
// This program distributed in hope will be useful,
// but WITHOUT ANY WARRANTY; without even implied warranty
// MERCHANTABILITY or FITNESS FOR PARTICULAR PURPOSE. See
// GNU General Public License more details.
//
// You should received copy GNU General Public License along
// program; if not, write Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package ca_test

import (
	"context"
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

var _ = Describe("CA Renew", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	// parseCertPEM decodes a single PEM-encoded certificate and fails the spec
	// if it is not parseable.
	parseCertPEM := func(certPEM []byte) *x509.Certificate {
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil(), "renewed cert PEM must decode")
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	// issue saves a fresh CSR for subject and signs it, returning the parsed
	// certificate. Mirrors the SaveRequest+Sign flow used elsewhere in the suite.
	issue := func(subject string) *x509.Certificate {
		csrPEM, _ := buildCSR(subject)
		_, err := myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCertPEM(certPEM)
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-renew-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("renews an issued node with a fresh CSR and replaces the stored cert", func() {
		original := issue("renew-node")

		// Renew with a brand-new valid CSR for the same CN.
		csrPEM, _ := buildCSR("renew-node")
		renewedPEM, err := myCA.Renew(ctx, "renew-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		renewed := parseCertPEM(renewedPEM)
		Expect(renewed.Subject.CommonName).To(Equal("renew-node"))

		// A renewal must mint a new serial; the random 128-bit serial makes a
		// collision with the original astronomically unlikely.
		Expect(renewed.SerialNumber.Cmp(original.SerialNumber)).NotTo(Equal(0),
			"renewed cert must carry a different serial than the original")

		// The stored certificate must be the renewed one, not the original.
		storedPEM, err := store.GetCert(ctx, "renew-node")
		Expect(err).NotTo(HaveOccurred())
		stored := parseCertPEM(storedPEM)
		Expect(stored.SerialNumber.Cmp(renewed.SerialNumber)).To(Equal(0),
			"stored cert must match the renewed serial")
		Expect(stored.SerialNumber.Cmp(original.SerialNumber)).NotTo(Equal(0),
			"stored cert must no longer be the original")
	})

	It("rejects a renewal whose CSR CN does not match the subject", func() {
		issue("renew-node")

		// CSR carries a different CN than the renewal subject. Renew enforces
		// CN == subject as defence-in-depth (signing.go:647) and must reject.
		mismatchPEM, _ := buildCSR("attacker-node")
		_, err := myCA.Renew(ctx, "renew-node", mismatchPEM)
		Expect(err).To(HaveOccurred(),
			"renewal must fail when the CSR CN does not match the subject")

		// The stored cert must be untouched by a rejected renewal.
		storedPEM, err := store.GetCert(ctx, "renew-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(parseCertPEM(storedPEM).Subject.CommonName).To(Equal("renew-node"))
	})

	It("rejects a renewal with a tampered CSR signature", func() {
		issue("renew-node")

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "renew-node"},
		}, key)
		Expect(err).NotTo(HaveOccurred())
		csrDER[len(csrDER)-1] ^= 0x01 // flip one bit in the signature
		tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

		// Renew verifies the CSR proof-of-possession signature (signing.go:642)
		// before acquiring any lock, so a tampered CSR must be rejected.
		_, err = myCA.Renew(ctx, "renew-node", tamperedPEM)
		Expect(err).To(HaveOccurred(),
			"renewal must fail when the CSR signature is invalid")
	})

	It("renews a subject that has no prior certificate", func() {
		// Renew bypasses the pending-CSR queue, so it can issue even when no
		// certificate exists yet. Guards that the happy path does not depend on
		// a pre-existing cert.
		csrPEM, _ := buildCSR("fresh-node")
		renewedPEM, err := myCA.Renew(ctx, "fresh-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(parseCertPEM(renewedPEM).Subject.CommonName).To(Equal("fresh-node"))

		storedPEM, err := store.GetCert(ctx, "fresh-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(parseCertPEM(storedPEM).SerialNumber.Sign()).To(Equal(1),
			"stored renewed cert must carry a positive serial")
	})
})
