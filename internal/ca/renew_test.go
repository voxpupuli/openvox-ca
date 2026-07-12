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
	"encoding/asn1"
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

	It("revokes the replaced certificate's serial so only the renewed one is active", func() {
		original := issue("renew-node")

		csrPEM, _ := buildCSR("renew-node")
		_, err := myCA.Renew(ctx, "renew-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		revoked, err := myCA.IsRevokedSerial(ctx, original.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(),
			"the pre-renewal serial must be revoked so it can no longer authenticate or pass OCSP/CRL checks")
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

	// mintLeaf signs a leaf certificate directly with the cached test CA key
	// from template — generating an RSA key of keyBits and a random 128-bit
	// serial when the template has none — and returns the parsed certificate.
	// It does not touch storage; callers that need the cert on disk store it
	// themselves. This collapses the key-gen / serial / CreateCertificate
	// scaffolding shared by the direct-mint specs below (which simulate certs
	// imported from a legacy CA, where AutoRenew works from the cert alone).
	mintLeaf := func(keyBits int, template *x509.Certificate) *x509.Certificate {
		key, err := rsa.GenerateKey(rand.Reader, keyBits)
		Expect(err).NotTo(HaveOccurred())
		if template.SerialNumber == nil {
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			Expect(err).NotTo(HaveOccurred())
			template.SerialNumber = serial
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		return parseCertPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	// seedCertWithoutCSR mints a leaf certificate (via mintLeaf) and stores it
	// as subject's cert, without ever writing a CSR to storage — simulating a
	// certificate imported from a migration (see the storage migrate command)
	// or any other cert whose CSR has since been cleaned up. AutoRenew must
	// work from the certificate alone.
	seedCertWithoutCSR := func(subject string) *x509.Certificate {
		now := time.Now().UTC()
		cert := mintLeaf(2048, &x509.Certificate{
			Subject:   pkix.Name{CommonName: subject},
			NotBefore: now.Add(-24 * time.Hour),
			NotAfter:  now.Add(365 * 24 * time.Hour),
			DNSNames:  []string{subject},
		})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		Expect(store.SaveCert(ctx, subject, certPEM)).To(Succeed())

		entry := fmt.Sprintf("%s %s %s /%s",
			cert.SerialNumber.Text(16),
			cert.NotBefore.Format("2006-01-02T15:04:05UTC"),
			cert.NotAfter.Format("2006-01-02T15:04:05UTC"),
			subject)
		Expect(store.AppendInventory(ctx, entry)).To(Succeed())

		return cert
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

	It("extends the validity window, not just the serial", func() {
		// The whole point of a renewal is a later expiry. Seed a nearly-expired
		// cert (a few minutes of life left) so the reissue's fresh window — even
		// after being capped to the test CA cert's own remaining lifetime — is
		// unambiguously later. This can't rely on the happy-path spec, where the
		// original and renewed windows differ only by the sub-second gap between
		// two signings and both round to the same second. Guards a regression
		// that reissued with the same or a shorter validity, leaving the agent's
		// cert to expire on its original schedule despite a "successful" renewal.
		now := time.Now().UTC()
		original := mintLeaf(2048, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "autorenew-expiry-node"},
			NotBefore: now.Add(-1 * time.Hour),
			NotAfter:  now.Add(5 * time.Minute),
			DNSNames:  []string{"autorenew-expiry-node"},
		})

		renewedPEM, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())
		renewed := parseCertPEM(renewedPEM)

		Expect(renewed.NotAfter).To(BeTemporally(">", original.NotAfter),
			"auto-renewal must extend validity, not just mint a new serial")
	})

	It("carries the original certificate's DNS SANs forward unchanged", func() {
		// A CSR-issued openvox-ca cert carries only DNS SANs, so this asserts
		// DNSNames; the IP/email/URI SAN types are covered by the next spec.
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
		now := time.Now().UTC()
		uri, err := url.Parse("spiffe://puppet.test/node/legacy-sans-node")
		Expect(err).NotTo(HaveOccurred())
		original := mintLeaf(2048, &x509.Certificate{
			Subject:        pkix.Name{CommonName: "legacy-sans-node"},
			NotBefore:      now.Add(-24 * time.Hour),
			NotAfter:       now.Add(365 * 24 * time.Hour),
			DNSNames:       []string{"legacy-sans-node", "legacy-sans-node.puppet.test"},
			IPAddresses:    []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("fd00::1")},
			EmailAddresses: []string{"node@puppet.test"},
			URIs:           []*url.URL{uri},
		})

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

	It("rejects a sub-policy key with ErrKeyPolicy rather than a generic failure", func() {
		// A legacy-CA cert may carry an RSA-1024 key that predates this CA's
		// policy. Auto-renewal must refuse to perpetuate it, and the error
		// must be classifiable so the HTTP layer answers 4xx, not 5xx.
		now := time.Now().UTC()
		original := mintLeaf(1024, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "weak-key-node"},
			NotBefore: now.Add(-24 * time.Hour),
			NotAfter:  now.Add(365 * 24 * time.Hour),
			DNSNames:  []string{"weak-key-node"},
		})

		_, err := myCA.AutoRenew(ctx, original)
		Expect(err).To(MatchError(ca.ErrKeyPolicy))
	})

	It("carries Puppet OID extensions forward, including auth OIDs the CSR path would strip", func() {
		// Unlike the CSR signing path (which strips authorization-arc OIDs such
		// as pp_cli_auth as an anti-escalation control), AutoRenew preserves
		// every Puppet-arc OID because they were already vetted when the
		// presented cert was issued. A cert legitimately carrying pp_cli_auth
		// (e.g. OpenVox Server's own cert) must keep it across auto-renewal, or
		// the puppetserver CA CLI stops authenticating. This locks in that
		// deliberate asymmetry with the CSR path.
		authVal, err := asn1.Marshal("true")
		Expect(err).NotTo(HaveOccurred())
		roleVal, err := asn1.Marshal("web")
		Expect(err).NotTo(HaveOccurred())
		// pp_role lives in the node-attribute arc (…34380.1.1.*), not the auth
		// arc, so both the CSR path and AutoRenew carry it; pp_cli_auth lives in
		// the auth arc (…34380.1.3.*) that only AutoRenew preserves.
		ppRole := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 13}

		now := time.Now().UTC()
		original := mintLeaf(2048, &x509.Certificate{
			Subject:   pkix.Name{CommonName: "autorenew-oid-node"},
			NotBefore: now.Add(-24 * time.Hour),
			NotAfter:  now.Add(365 * 24 * time.Hour),
			DNSNames:  []string{"autorenew-oid-node"},
			ExtraExtensions: []pkix.Extension{
				{Id: ca.OIDPpCliAuth, Value: authVal}, // auth-arc: CSR path would strip this
				{Id: ppRole, Value: roleVal},          // node-attr arc: always carried
			},
		})

		renewedPEM, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())
		renewed := parseCertPEM(renewedPEM)

		findExt := func(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
			for _, ext := range cert.Extensions {
				if ext.Id.Equal(oid) {
					return ext, true
				}
			}
			return pkix.Extension{}, false
		}

		authExt, ok := findExt(renewed, ca.OIDPpCliAuth)
		Expect(ok).To(BeTrue(),
			"auto-renewal must carry the pp_cli_auth auth OID forward, unlike the CSR path")
		Expect(authExt.Value).To(Equal(authVal))

		roleExt, ok := findExt(renewed, ppRole)
		Expect(ok).To(BeTrue(), "auto-renewal must carry the pp_role OID forward")
		Expect(roleExt.Value).To(Equal(roleVal))
	})

	It("revokes the replaced certificate by default, so only the newest serial is active", func() {
		Expect(myCA.RevokeOnAutoRenew).To(BeTrue(),
			"revoke-on-auto-renew must default to true (secure by default)")

		original := issue("autorenew-revoke-node")

		_, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())

		revoked, err := myCA.IsRevokedSerial(ctx, original.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(),
			"the pre-renewal serial must be revoked so it can no longer authenticate or pass OCSP/CRL checks")
	})

	It("leaves the replaced certificate valid when RevokeOnAutoRenew is disabled, matching Clojure CA", func() {
		myCA.RevokeOnAutoRenew = false

		original := issue("autorenew-no-revoke-node")

		_, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())

		revoked, err := myCA.IsRevokedSerial(ctx, original.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse(),
			"with RevokeOnAutoRenew disabled, the pre-renewal certificate must remain valid for its key, as OpenVox Server's Clojure CA does")
	})
})
