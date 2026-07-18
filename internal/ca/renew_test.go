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
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"

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

// CA AutoRenew covers the wire-compatible "no CSR" renewal flow real
// Puppet/OpenVox agents use by default (hostcert_renewal_interval): the
// client presents its existing cert over mTLS and gets back a certificate
// for the SAME public key, with a fresh serial and validity. This matches
// OpenVox Server's own Clojure CA (renew-certificate!), which does not
// revoke the certificate being replaced.
var _ = Describe("CA AutoRenew", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		caKey  *rsa.PrivateKey
		caCert *x509.Certificate
	)

	parseCertPEM := func(certPEM []byte) *x509.Certificate {
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil(), "renewed cert PEM must decode")
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	issue := func(subject string) *x509.Certificate {
		csrPEM, _ := buildCSR(subject)
		_, err := myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCertPEM(certPEM)
	}

	// seedCertWithoutCSR mints a leaf certificate directly with the cached
	// test CA's key and stores it as subject's cert, without ever writing a
	// CSR to storage — simulating a certificate imported from a migration
	// (see the storage migrate command) or any other cert whose CSR has
	// since been cleaned up. AutoRenew must work from the certificate alone.
	seedCertWithoutCSR := func(subject string) *x509.Certificate {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		Expect(err).NotTo(HaveOccurred())
		now := time.Now().UTC()
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: subject},
			NotBefore:    now.Add(-24 * time.Hour),
			NotAfter:     now.Add(365 * 24 * time.Hour),
			DNSNames:     []string{subject},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		Expect(store.SaveCert(ctx, subject, certPEM)).To(Succeed())

		entry := fmt.Sprintf("%s %s %s /%s",
			serial.Text(16),
			template.NotBefore.Format("2006-01-02T15:04:05UTC"),
			template.NotAfter.Format("2006-01-02T15:04:05UTC"),
			subject)
		Expect(store.AppendInventory(ctx, entry)).To(Succeed())

		return parseCertPEM(certPEM)
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-autorenew-test")
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

		keyBlock, _ := pem.Decode(cachedKeyPEM)
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		certBlock, _ := pem.Decode(cachedCrtPEM)
		caCert, err = x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("reissues the same public key with a fresh serial, matching Clojure CA semantics", func() {
		original := issue("autorenew-node")

		renewedPEM, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())
		renewed := parseCertPEM(renewedPEM)

		Expect(renewed.Subject.CommonName).To(Equal("autorenew-node"))
		Expect(renewed.PublicKey).To(Equal(original.PublicKey),
			"auto-renewal must not rotate the key, only the serial/validity")
		Expect(renewed.SerialNumber.Cmp(original.SerialNumber)).NotTo(Equal(0),
			"auto-renewed cert must carry a different serial than the original")

		storedPEM, err := store.GetCert(ctx, "autorenew-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(parseCertPEM(storedPEM).SerialNumber.Cmp(renewed.SerialNumber)).To(Equal(0),
			"stored cert must match the auto-renewed serial")
	})

	It("carries the original certificate's SANs forward unchanged", func() {
		csrPEM, _ := buildCSR("autorenew-sans-node")
		_, err := myCA.SaveRequest(ctx, "autorenew-sans-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, "autorenew-sans-node")
		Expect(err).NotTo(HaveOccurred())
		original := parseCertPEM(certPEM)

		renewedPEM, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())
		renewed := parseCertPEM(renewedPEM)

		Expect(renewed.DNSNames).To(Equal(original.DNSNames))
	})

	It("carries non-DNS SANs (IP, email, URI) forward, e.g. from a legacy-CA cert", func() {
		// openvox-ca only ever issues DNS SANs itself, but a leaf imported
		// from a legacy CA can carry IP/email/URI SANs that services depend
		// on. Mint such a cert directly and prove auto-renewal preserves them.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		Expect(err).NotTo(HaveOccurred())
		now := time.Now().UTC()
		uri, err := url.Parse("spiffe://puppet.test/node/legacy-sans-node")
		Expect(err).NotTo(HaveOccurred())
		template := &x509.Certificate{
			SerialNumber:   serial,
			Subject:        pkix.Name{CommonName: "legacy-sans-node"},
			NotBefore:      now.Add(-24 * time.Hour),
			NotAfter:       now.Add(365 * 24 * time.Hour),
			DNSNames:       []string{"legacy-sans-node", "legacy-sans-node.puppet.test"},
			IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("fd00::1")},
			EmailAddresses: []string{"node@puppet.test"},
			URIs:           []*url.URL{uri},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		original, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())

		renewedPEM, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())
		renewed := parseCertPEM(renewedPEM)

		Expect(renewed.DNSNames).To(Equal(original.DNSNames))
		Expect(renewed.IPAddresses).To(Equal(original.IPAddresses))
		Expect(renewed.EmailAddresses).To(Equal(original.EmailAddresses))
		Expect(renewed.URIs).To(Equal(original.URIs))
	})

	It("auto-renews a certificate that has no CSR in storage, e.g. after migration import", func() {
		original := seedCertWithoutCSR("migrated-node")
		Expect(store.HasCSR(ctx, "migrated-node")).To(BeFalse(),
			"this test only proves anything if there really is no CSR to fall back on")

		renewedPEM, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())
		renewed := parseCertPEM(renewedPEM)

		Expect(renewed.PublicKey).To(Equal(original.PublicKey))
		Expect(renewed.SerialNumber.Cmp(original.SerialNumber)).NotTo(Equal(0))
	})
})
