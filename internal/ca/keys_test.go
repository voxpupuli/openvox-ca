// Copyright (C) 2026 Trevor Vaughan
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
	"github.com/tvaughan/puppet-ca/internal/testutil"
)

// --- ValidateKeyConfig ---

var _ = DescribeTable("ValidateKeyConfig valid configs",
	func(cfg ca.KeyConfig) { Expect(ca.ValidateKeyConfig(cfg)).To(Succeed()) },
	Entry("zero value (defaults to RSA)", ca.KeyConfig{}),
	Entry("RSA 2048", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 2048}),
	Entry("RSA 3072", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 3072}),
	Entry("RSA 4096", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 4096}),
	Entry("RSA size 0 (algo-default)", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 0}),
	Entry("ECDSA P-256", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}),
	Entry("ECDSA P-384", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 384}),
	Entry("ECDSA P-521", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 521}),
	Entry("ECDSA size 0 (default P-256)", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 0}),
)

var _ = DescribeTable("ValidateKeyConfig invalid configs",
	func(cfg ca.KeyConfig) { Expect(ca.ValidateKeyConfig(cfg)).To(HaveOccurred()) },
	Entry("RSA below minimum", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 1024}),
	Entry("RSA non-standard size", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 3000}),
	Entry("ECDSA unsupported curve size", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 192}),
	Entry("unknown algorithm", ca.KeyConfig{Algo: "ed25519", Size: 256}),
)

var _ = Describe("Default key config constants", func() {
	It("DefaultCAKeyConfig is RSA 4096", func() {
		Expect(ca.DefaultCAKeyConfig.Algo).To(Equal(ca.KeyAlgoRSA))
		Expect(ca.DefaultCAKeyConfig.Size).To(Equal(4096))
	})

	It("DefaultLeafKeyConfig is RSA 2048", func() {
		Expect(ca.DefaultLeafKeyConfig.Algo).To(Equal(ca.KeyAlgoRSA))
		Expect(ca.DefaultLeafKeyConfig.Size).To(Equal(2048))
	})
})

// --- Bootstrap with different key algorithms ---

var _ = Describe("CA Bootstrap key algorithms", func() {
	var (
		tmpDir string
		store  *storage.StorageService
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-keyalgo-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "keys.test")
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("bootstraps RSA 2048", func() {
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 2048}
		Expect(myCA.Init()).To(Succeed())

		rsaKey, ok := myCA.CAKey.(*rsa.PrivateKey)
		Expect(ok).To(BeTrue(), "expected *rsa.PrivateKey")
		Expect(rsaKey.N.BitLen()).To(Equal(2048))

		keyData, err := store.GetCAKey()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(keyData)).To(ContainSubstring("RSA PRIVATE KEY"))
	})

	It("bootstraps ECDSA P-256", func() {
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init()).To(Succeed())

		ecKey, ok := myCA.CAKey.(*ecdsa.PrivateKey)
		Expect(ok).To(BeTrue(), "expected *ecdsa.PrivateKey")
		Expect(ecKey.Curve).To(Equal(elliptic.P256()))

		keyData, err := store.GetCAKey()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(keyData)).To(ContainSubstring("EC PRIVATE KEY"))

		Expect(myCA.CACert.PublicKeyAlgorithm).To(Equal(x509.ECDSA))
	})

	It("bootstraps ECDSA P-384", func() {
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 384}
		Expect(myCA.Init()).To(Succeed())
		ecKey, ok := myCA.CAKey.(*ecdsa.PrivateKey)
		Expect(ok).To(BeTrue())
		Expect(ecKey.Curve).To(Equal(elliptic.P384()))
	})

	It("bootstraps ECDSA P-521", func() {
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 521}
		Expect(myCA.Init()).To(Succeed())
		ecKey, ok := myCA.CAKey.(*ecdsa.PrivateKey)
		Expect(ok).To(BeTrue())
		Expect(ecKey.Curve).To(Equal(elliptic.P521()))
	})

	It("reloads an ECDSA CA from disk", func() {
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init()).To(Succeed())
		origSerial := myCA.CACert.SerialNumber

		myCA2 := ca.New(store, ca.AutosignConfig{Mode: "off"}, "keys.test")
		Expect(myCA2.Init()).To(Succeed())

		Expect(myCA2.CACert.SerialNumber.Cmp(origSerial)).To(Equal(0))
		_, ok := myCA2.CAKey.(*ecdsa.PrivateKey)
		Expect(ok).To(BeTrue(), "reloaded key should be ECDSA")
	})

	It("signs CSRs with an ECDSA CA", func() {
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		// bootstrapCA creates the serial and inventory; no manual seeding needed.
		Expect(myCA.Init()).To(Succeed())

		csrPEM, err := testutil.GenerateCSR("ecdsa-leaf")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("ecdsa-leaf", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign("ecdsa-leaf")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		// Leaf cert signed by ECDSA CA must verify correctly.
		Expect(cert.CheckSignatureFrom(myCA.CACert)).To(Succeed())
	})
})

// --- CA certificate subject fields ---

var _ = Describe("CA Bootstrap subject fields", func() {
	var (
		tmpDir string
		store  *storage.StorageService
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-subject-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "subject.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 2048} // fast for tests
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("sets Organization in the CA cert subject", func() {
		myCA.CASubject = ca.CASubjectConfig{Org: "Example Corp"}
		Expect(myCA.Init()).To(Succeed())
		Expect(myCA.CACert.Subject.Organization).To(ConsistOf("Example Corp"))
	})

	It("sets all subject fields simultaneously", func() {
		myCA.CASubject = ca.CASubjectConfig{
			Org:      "Acme Inc",
			OrgUnit:  "Infrastructure",
			Country:  "US",
			Locality: "San Francisco",
			Province: "California",
		}
		Expect(myCA.Init()).To(Succeed())

		subj := myCA.CACert.Subject
		Expect(subj.Organization).To(ConsistOf("Acme Inc"))
		Expect(subj.OrganizationalUnit).To(ConsistOf("Infrastructure"))
		Expect(subj.Country).To(ConsistOf("US"))
		Expect(subj.Locality).To(ConsistOf("San Francisco"))
		Expect(subj.Province).To(ConsistOf("California"))
	})

	It("preserves default CN when no subject is set", func() {
		Expect(myCA.Init()).To(Succeed())
		Expect(myCA.CACert.Subject.CommonName).To(HavePrefix("Puppet CA: "))
	})

	It("ignores subject config when reloading an existing CA", func() {
		myCA.CASubject = ca.CASubjectConfig{Org: "First Corp"}
		Expect(myCA.Init()).To(Succeed())

		myCA2 := ca.New(store, ca.AutosignConfig{Mode: "off"}, "subject.test")
		myCA2.CASubject = ca.CASubjectConfig{Org: "Second Corp"}
		Expect(myCA2.Init()).To(Succeed())

		// The cert on disk has "First Corp"; the in-memory subject config is ignored.
		Expect(myCA2.CACert.Subject.Organization).To(ConsistOf("First Corp"))
	})
})

// --- LeafKeyConfig via Generate ---

var _ = Describe("Generate with LeafKeyConfig", func() {
	var (
		tmpDir string
		store  *storage.StorageService
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-leafkey-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "leaf.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("generates RSA 2048 by default", func() {
		result, err := myCA.Generate("leaf-rsa-default", nil)
		Expect(err).NotTo(HaveOccurred())

		keyBlock, _ := pem.Decode(result.PrivateKeyPEM)
		Expect(keyBlock.Type).To(Equal("RSA PRIVATE KEY"))

		rsaKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(rsaKey.N.BitLen()).To(Equal(2048))
	})

	It("generates ECDSA P-256 when LeafKeyConfig={ECDSA,256}", func() {
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}

		result, err := myCA.Generate("leaf-ecdsa-256", nil)
		Expect(err).NotTo(HaveOccurred())

		keyBlock, _ := pem.Decode(result.PrivateKeyPEM)
		Expect(keyBlock).NotTo(BeNil())
		Expect(keyBlock.Type).To(Equal("EC PRIVATE KEY"))

		ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(ecKey.Curve).To(Equal(elliptic.P256()))

		// Key file on disk must also be EC.
		keyData, _ := os.ReadFile(store.PrivateKeyPath("leaf-ecdsa-256"))
		Expect(string(keyData)).To(ContainSubstring("EC PRIVATE KEY"))

		// Cert must verify against the (RSA) CA.
		certBlock, _ := pem.Decode(result.CertificatePEM)
		cert, _ := x509.ParseCertificate(certBlock.Bytes)
		caCertBlock, _ := pem.Decode(cachedCrtPEM)
		caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)
		Expect(cert.CheckSignatureFrom(caCert)).To(Succeed())
	})
})

// --- CA path length constraint ---

var _ = Describe("CA Bootstrap path length constraint", func() {
	var (
		tmpDir string
		store  *storage.StorageService
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-pathlen-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "pathlen.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256} // fast
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("is unconstrained by default (no pathLenConstraint)", func() {
		Expect(myCA.Init()).To(Succeed())
		// MaxPathLen == -1 after parsing means no pathLenConstraint was set.
		Expect(myCA.CACert.MaxPathLen).To(Equal(-1))
		Expect(myCA.CACert.MaxPathLenZero).To(BeFalse())
	})

	It("sets pathLenConstraint to 0 (leaf certs only) when CAPathLength is 0", func() {
		myCA.CAPathLength = 0
		Expect(myCA.Init()).To(Succeed())
		Expect(myCA.CACert.MaxPathLen).To(Equal(0))
		Expect(myCA.CACert.MaxPathLenZero).To(BeTrue())
	})

	It("sets pathLenConstraint to 1 (one level of intermediates) when CAPathLength is 1", func() {
		myCA.CAPathLength = 1
		Expect(myCA.Init()).To(Succeed())
		Expect(myCA.CACert.MaxPathLen).To(Equal(1))
		Expect(myCA.CACert.MaxPathLenZero).To(BeFalse())
	})

	It("ignores path length config when reloading an existing CA", func() {
		// Bootstrap unconstrained.
		Expect(myCA.Init()).To(Succeed())

		// A second CA with a different CAPathLength must load from disk unchanged.
		myCA2 := ca.New(store, ca.AutosignConfig{Mode: "off"}, "pathlen.test")
		myCA2.CAPathLength = 0
		Expect(myCA2.Init()).To(Succeed())
		Expect(myCA2.CACert.MaxPathLen).To(Equal(-1), "reload must not apply new path length config")
	})
})

// --- CA certificate validity period ---

var _ = Describe("CA certificate validity period", func() {
	var (
		tmpDir string
		store  *storage.StorageService
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-cavalid-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "cavalid.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256} // fast
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("uses the built-in ~5-year default when CAValidityDays is zero", func() {
		Expect(myCA.Init()).To(Succeed())
		expected := time.Now().Add(5 * 365 * 24 * time.Hour)
		Expect(myCA.CACert.NotAfter).To(BeTemporally("~", expected, 5*time.Minute))
	})

	It("overrides CA validity with CAValidityDays", func() {
		myCA.CAValidityDays = 3650 // 10 years
		Expect(myCA.Init()).To(Succeed())
		expected := time.Now().Add(3650 * 24 * time.Hour)
		Expect(myCA.CACert.NotAfter).To(BeTemporally("~", expected, 5*time.Minute))
	})

	It("ignores CAValidityDays when reloading an existing CA", func() {
		Expect(myCA.Init()).To(Succeed())
		originalNotAfter := myCA.CACert.NotAfter

		myCA2 := ca.New(store, ca.AutosignConfig{Mode: "off"}, "cavalid.test")
		myCA2.CAValidityDays = 100
		Expect(myCA2.Init()).To(Succeed())
		Expect(myCA2.CACert.NotAfter).To(BeTemporally("==", originalNotAfter))
	})
})

// --- Leaf certificate validity period ---

var _ = Describe("Leaf certificate validity period", func() {
	var (
		tmpDir string
		store  *storage.StorageService
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-leafvalid-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "leafvalid.test")
		// Bootstrap a long-lived ECDSA CA so leaf validity is not artificially capped.
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.CAValidityDays = 7300 // 20 years
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	signAndParse := func(subject string) *x509.Certificate {
		GinkgoHelper()
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(subject)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	It("uses the built-in ~5-year default when LeafValidityDays is zero", func() {
		cert := signAndParse("leaf-default-validity")
		expected := time.Now().Add(5 * 365 * 24 * time.Hour)
		Expect(cert.NotAfter).To(BeTemporally("~", expected, 5*time.Minute))
	})

	It("overrides leaf validity with LeafValidityDays", func() {
		myCA.LeafValidityDays = 90
		cert := signAndParse("leaf-90d-validity")
		expected := time.Now().Add(90 * 24 * time.Hour)
		Expect(cert.NotAfter).To(BeTemporally("~", expected, 5*time.Minute))
	})

	It("per-request cert_ttl takes precedence over LeafValidityDays", func() {
		myCA.LeafValidityDays = 90
		subject := "leaf-ttl-override"
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())

		certPEM, err := myCA.SignWithTTL(subject, 7*24*time.Hour)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		cert, _ := x509.ParseCertificate(block.Bytes)
		expected := time.Now().Add(7 * 24 * time.Hour)
		Expect(cert.NotAfter).To(BeTemporally("~", expected, 5*time.Minute))
	})

	It("LeafValidityDays also applies to Generate", func() {
		myCA.LeafValidityDays = 45
		result, err := myCA.Generate("leaf-gen-validity", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(result.CertificatePEM)
		cert, _ := x509.ParseCertificate(block.Bytes)
		expected := time.Now().Add(45 * 24 * time.Hour)
		Expect(cert.NotAfter).To(BeTemporally("~", expected, 5*time.Minute))
	})
})

// --- loadCA key/cert mismatch detection ---

var _ = Describe("loadCA key/cert mismatch", func() {
	It("Init fails when the CA private key does not match the CA certificate", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-mismatch-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		store := storage.New(tmpDir)
		Expect(store.EnsureDirs()).To(Succeed())

		// Use a cert from one CA and a key from a different CA.
		altKeyPEM, _, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())

		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.SaveCAKey(altKeyPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "mismatch.test")
		err = myCA.Init()
		// loadCA fails → Init falls into the "files exist but could not be parsed" path.
		Expect(err).To(HaveOccurred(), "Init must fail when key does not match cert")
	})
})

// --- ImportCA with ECDSA ---

var _ = Describe("ImportCA ECDSA", func() {
	It("imports an ECDSA CA cert/key pair", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-import-ecdsa-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		ecKeyPEM, ecCertPEM, ecCrlPEM, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())

		store := storage.New(tmpDir)
		Expect(ca.ImportCA(store, ecCertPEM, ecKeyPEM, ecCrlPEM)).To(Succeed())

		// Blobs must exist.
		Expect(store.HasCACert()).To(BeTrue())
		Expect(store.HasCAKey()).To(BeTrue())
		crlBytes, err := store.GetCRL()
		Expect(err).NotTo(HaveOccurred())
		Expect(crlBytes).NotTo(BeEmpty())

		// Key blob must be an EC key.
		keyData, err := store.GetCAKey()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(keyData)).To(ContainSubstring("EC PRIVATE KEY"))

		// Loaded CA must work.
		store2 := storage.New(tmpDir)
		myCA := ca.New(store2, ca.AutosignConfig{Mode: "off"}, "ecdsa.test")
		Expect(myCA.Init()).To(Succeed())
		_, ok := myCA.CAKey.(*ecdsa.PrivateKey)
		Expect(ok).To(BeTrue(), "loaded key should be ECDSA")
	})

	It("rejects an ECDSA cert paired with a mismatched key", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-import-ecdsa-mismatch-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		_, ecCertPEM, ecCrlPEM, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		altEcKeyPEM, _, _, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())

		store := storage.New(tmpDir)
		// Pass ecCertPEM with altEcKeyPEM; these don't match.
		err = ca.ImportCA(store, ecCertPEM, altEcKeyPEM, ecCrlPEM)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not match"))
	})
})
