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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("ImportCertificate", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		caKey  crypto.Signer
		caCert *x509.Certificate
	)

	// leafOpts customises a leaf certificate minted for these tests.
	type leafOpts struct {
		cn        string
		dnsNames  []string
		isCA      bool
		notBefore time.Time
		notAfter  time.Time
		serial    *big.Int
	}

	// signLeaf mints a leaf certificate signed by (signerKey, signerCert),
	// entirely outside myCA's own Sign/Generate flow — exactly the scenario
	// ImportCertificate exists to handle.
	signLeaf := func(signerKey crypto.Signer, signerCert *x509.Certificate, o leafOpts) []byte {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		serial := o.serial
		if serial == nil {
			serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			Expect(err).NotTo(HaveOccurred())
		}
		notBefore := o.notBefore
		if notBefore.IsZero() {
			notBefore = time.Now().UTC().Add(-24 * time.Hour)
		}
		notAfter := o.notAfter
		if notAfter.IsZero() {
			notAfter = time.Now().UTC().Add(365 * 24 * time.Hour)
		}

		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: o.cn},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			DNSNames:              o.dnsNames,
			BasicConstraintsValid: true,
			IsCA:                  o.isCA,
		}
		if o.isCA {
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}

		der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	parseCertPEM := func(certPEM []byte) *x509.Certificate {
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil(), "cert PEM must decode")
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

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-importcert-test")
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

	It("imports a certificate signed outside the normal flow, and it can then be revoked by subject", func() {
		certPEM := signLeaf(caKey, caCert, leafOpts{cn: "imported-node", dnsNames: []string{"imported-node"}})
		leaf := parseCertPEM(certPEM)

		result, err := myCA.ImportCertificate(ctx, "imported-node", certPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Imported).To(BeTrue())
		Expect(result.Subject).To(Equal("imported-node"))
		Expect(result.Serial).To(Equal(strings.ToUpper(leaf.SerialNumber.Text(16))))

		storedPEM, err := store.GetCert(ctx, "imported-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(storedPEM).To(Equal(certPEM))

		serial, err := store.LatestSerialForSubject(ctx, "imported-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal(strings.ToUpper(leaf.SerialNumber.Text(16))))

		Expect(myCA.Revoke(ctx, "imported-node")).To(Succeed())
		revoked, err := myCA.IsRevokedSerial(ctx, leaf.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("is idempotent when the exact same certificate is resubmitted", func() {
		certPEM := signLeaf(caKey, caCert, leafOpts{cn: "idempotent-node", dnsNames: []string{"idempotent-node"}})

		first, err := myCA.ImportCertificate(ctx, "idempotent-node", certPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Imported).To(BeTrue())

		entriesBefore, err := store.LatestSerialForSubject(ctx, "idempotent-node")
		Expect(err).NotTo(HaveOccurred())

		second, err := myCA.ImportCertificate(ctx, "idempotent-node", certPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Imported).To(BeFalse())
		Expect(second.Serial).To(Equal(first.Serial))

		entriesAfter, err := store.LatestSerialForSubject(ctx, "idempotent-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(entriesAfter).To(Equal(entriesBefore), "resubmission must not write a new inventory entry")
	})

	It("rejects a serial that is already tracked under a different subject", func() {
		serial := big.NewInt(0xABCDEF)
		certA := signLeaf(caKey, caCert, leafOpts{cn: "serial-a", dnsNames: []string{"serial-a"}, serial: serial})
		_, err := myCA.ImportCertificate(ctx, "serial-a", certA)
		Expect(err).NotTo(HaveOccurred())

		certB := signLeaf(caKey, caCert, leafOpts{cn: "serial-b", dnsNames: []string{"serial-b"}, serial: serial})
		_, err = myCA.ImportCertificate(ctx, "serial-b", certB)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrSerialExists))
	})

	It("prefers ErrSerialExists over ErrCertExists when both conflicts apply", func() {
		// subject-x already has an active cert.
		activeCertX := signLeaf(caKey, caCert, leafOpts{cn: "subject-x", dnsNames: []string{"subject-x"}})
		_, err := myCA.ImportCertificate(ctx, "subject-x", activeCertX)
		Expect(err).NotTo(HaveOccurred())

		// subject-y's serial is separately already tracked.
		reusedSerial := big.NewInt(0x1234567)
		certY := signLeaf(caKey, caCert, leafOpts{cn: "subject-y", dnsNames: []string{"subject-y"}, serial: reusedSerial})
		_, err = myCA.ImportCertificate(ctx, "subject-y", certY)
		Expect(err).NotTo(HaveOccurred())

		// Now try to import a cert for subject-x that reuses subject-y's serial:
		// subject-x already has an active cert (would trip ErrCertExists), AND
		// the serial is already tracked elsewhere (would trip ErrSerialExists).
		// The documented priority order requires ErrSerialExists to win.
		conflictCert := signLeaf(caKey, caCert, leafOpts{cn: "subject-x", dnsNames: []string{"subject-x"}, serial: reusedSerial})
		_, err = myCA.ImportCertificate(ctx, "subject-x", conflictCert)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrSerialExists))
		Expect(err).NotTo(MatchError(ca.ErrCertExists))
	})

	It("rejects import over an existing active certificate for the subject", func() {
		issue("active-node")

		importCert := signLeaf(caKey, caCert, leafOpts{cn: "active-node", dnsNames: []string{"active-node"}})
		_, err := myCA.ImportCertificate(ctx, "active-node", importCert)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrCertExists))

		// The original signed cert must be untouched.
		storedPEM, err := store.GetCert(ctx, "active-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(parseCertPEM(storedPEM).Subject.CommonName).To(Equal("active-node"))
	})

	It("evicts a revoked certificate and imports the replacement", func() {
		original := issue("revoked-node")
		Expect(myCA.Revoke(ctx, "revoked-node")).To(Succeed())

		replacement := signLeaf(caKey, caCert, leafOpts{cn: "revoked-node", dnsNames: []string{"revoked-node"}})
		result, err := myCA.ImportCertificate(ctx, "revoked-node", replacement)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Imported).To(BeTrue())

		storedPEM, err := store.GetCert(ctx, "revoked-node")
		Expect(err).NotTo(HaveOccurred())
		stored := parseCertPEM(storedPEM)
		Expect(stored.SerialNumber.Cmp(original.SerialNumber)).NotTo(Equal(0))
		Expect(stored.Raw).To(Equal(parseCertPEM(replacement).Raw))
	})

	It("rejects a certificate whose signature does not chain to this CA", func() {
		altKeyPEM, altCertPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		altKeyBlock, _ := pem.Decode(altKeyPEM)
		altKey, err := x509.ParsePKCS1PrivateKey(altKeyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		altCertBlock, _ := pem.Decode(altCertPEM)
		altCert, err := x509.ParseCertificate(altCertBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		foreignCert := signLeaf(altKey, altCert, leafOpts{cn: "foreign-node", dnsNames: []string{"foreign-node"}})

		_, err = myCA.ImportCertificate(ctx, "foreign-node", foreignCert)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
		Expect(err.Error()).To(ContainSubstring("not signed by this CA"))

		Expect(store.HasCert(ctx, "foreign-node")).To(BeFalse())
	})

	It("rejects a CA certificate", func() {
		caLikeCert := signLeaf(caKey, caCert, leafOpts{cn: "ca-like-node", isCA: true})

		_, err := myCA.ImportCertificate(ctx, "ca-like-node", caLikeCert)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
		Expect(err.Error()).To(ContainSubstring("refusing to import a CA certificate"))
	})

	It("rejects a subject that fails ValidateSubject", func() {
		certPEM := signLeaf(caKey, caCert, leafOpts{cn: "bad..subject", dnsNames: []string{"bad..subject"}})

		_, err := myCA.ImportCertificate(ctx, "bad..subject", certPEM)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
	})

	It("rejects a subject that matches neither the CN nor any DNS SAN", func() {
		certPEM := signLeaf(caKey, caCert, leafOpts{cn: "actual-cn", dnsNames: []string{"actual-cn"}})

		_, err := myCA.ImportCertificate(ctx, "unrelated-subject", certPEM)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
		Expect(err.Error()).To(ContainSubstring("matches neither"))
	})

	It("accepts a subject that matches a DNS SAN but not the CN", func() {
		certPEM := signLeaf(caKey, caCert, leafOpts{cn: "primary-cn", dnsNames: []string{"primary-cn", "alt-san-name"}})

		result, err := myCA.ImportCertificate(ctx, "alt-san-name", certPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Imported).To(BeTrue())
		Expect(result.Subject).To(Equal("alt-san-name"))
	})

	It("rejects malformed PEM input", func() {
		_, err := myCA.ImportCertificate(ctx, "malformed-node", []byte("not a pem file"))
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
	})

	It("rejects a well-formed CERTIFICATE PEM block whose DER does not parse", func() {
		garbagePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-der")})

		_, err := myCA.ImportCertificate(ctx, "garbage-der-node", garbagePEM)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
		Expect(store.HasCert(ctx, "garbage-der-node")).To(BeFalse())
	})

	It("rejects input containing more than one PEM block", func() {
		certA := signLeaf(caKey, caCert, leafOpts{cn: "multi-node", dnsNames: []string{"multi-node"}})
		certB := signLeaf(caKey, caCert, leafOpts{cn: "multi-node-2", dnsNames: []string{"multi-node-2"}})

		_, err := myCA.ImportCertificate(ctx, "multi-node", append(certA, certB...))
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
	})

	It("rejects a certificate whose NotAfter is not after NotBefore", func() {
		now := time.Now().UTC()
		certPEM := signLeaf(caKey, caCert, leafOpts{
			cn:        "backwards-node",
			dnsNames:  []string{"backwards-node"},
			notBefore: now,
			notAfter:  now.Add(-1 * time.Hour),
		})

		_, err := myCA.ImportCertificate(ctx, "backwards-node", certPEM)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
		Expect(err.Error()).To(ContainSubstring("NotAfter"))
	})

	It("rejects a certificate with a non-positive serial number", func() {
		certPEM := signLeaf(caKey, caCert, leafOpts{cn: "zero-serial-node", dnsNames: []string{"zero-serial-node"}, serial: big.NewInt(0)})

		_, err := myCA.ImportCertificate(ctx, "zero-serial-node", certPEM)
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ca.ErrImportInvalid))
		Expect(err.Error()).To(ContainSubstring("non-positive serial number"))
	})

	It("returns ErrNotInitialized rather than panicking on an un-Init'd CA", func() {
		rawDir, err := os.MkdirTemp("", "openvox-ca-importcert-uninit-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(rawDir)
		rawStore := storage.New(rawDir)
		Expect(rawStore.EnsureDirs(ctx)).To(Succeed())
		rawCA := ca.New(rawStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		certPEM := signLeaf(caKey, caCert, leafOpts{cn: "uninit-node", dnsNames: []string{"uninit-node"}})

		var result *ca.ImportResult
		Expect(func() { result, err = rawCA.ImportCertificate(ctx, "uninit-node", certPEM) }).NotTo(Panic())
		Expect(err).To(MatchError(ca.ErrNotInitialized))
		Expect(result).To(BeNil())
	})
})
