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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
	"github.com/tvaughan/puppet-ca/internal/testutil"
)

var (
	cachedKeyPEM []byte
	cachedCrtPEM []byte
	cachedCrlPEM []byte
)

var _ = BeforeSuite(func() {
	var err error
	cachedKeyPEM, cachedCrtPEM, cachedCrlPEM, err = testutil.GenerateTestCA()
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("CA Lifecycle", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		asCfg  ca.AutosignConfig
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		asCfg = ca.AutosignConfig{Mode: "off"}
		myCA = ca.New(store, asCfg, "puppet.test")

		// Optimization: Pre-seed the CA with keys generated in BeforeSuite
		// This avoids generating 4096-bit keys for every test case.
		err = store.EnsureDirs()
		Expect(err).NotTo(HaveOccurred())

		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())

		// Also pre-seed Serial and Inventory which are normally created by bootstrapCA
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Context("Initialization", func() {
		It("should load existing CA successfully", func() {
			err := myCA.Init()
			Expect(err).NotTo(HaveOccurred())

			// Verify they are the same
			loadedCert, err := store.GetCACert()
			Expect(err).NotTo(HaveOccurred())
			Expect(loadedCert).To(Equal(cachedCrtPEM))
		})
	})

	Context("CSR Handling", func() {
		var csrPEM []byte

		BeforeEach(func() {
			var err error
			err = myCA.Init()
			Expect(err).NotTo(HaveOccurred())
			csrPEM, err = testutil.GenerateCSR("test-node")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should save a valid CSR but not sign it when autosign is off", func() {
			saved, err := myCA.SaveRequest("test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(saved).To(BeFalse(), "Expected saved=false (autosign off)")

			_, err = os.Stat(filepath.Join(tmpDir, "requests", "test-node.pem"))
			Expect(os.IsNotExist(err)).To(BeFalse(), "CSR file should be created")
		})

		It("should sign a valid CSR", func() {
			_, err := myCA.SaveRequest("test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())

			certPEM, err := myCA.Sign("test-node")
			Expect(err).NotTo(HaveOccurred())

			// Verify Cert on disk
			_, err = os.Stat(filepath.Join(tmpDir, "signed", "test-node.pem"))
			Expect(os.IsNotExist(err)).To(BeFalse(), "Signed cert file should be created")

			// Verify Cert Validity
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil(), "Failed to decode generated cert PEM")

			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			Expect(cert.Subject.CommonName).To(Equal("test-node"))

			// Verify it is signed by CA
			caCertPEM, err := os.ReadFile(filepath.Join(tmpDir, "ca_crt.pem"))
			Expect(err).NotTo(HaveOccurred())
			caBlock, _ := pem.Decode(caCertPEM)
			caCert, _ := x509.ParseCertificate(caBlock.Bytes)

			err = cert.CheckSignatureFrom(caCert)
			Expect(err).NotTo(HaveOccurred(), "Certificate validation against CA failed")
		})
	})

	Context("Negative Tests", func() {
		BeforeEach(func() {
			err := myCA.Init()
			Expect(err).NotTo(HaveOccurred())
		})

		It("should fail to sign non-existent CSR", func() {
			_, err := myCA.Sign("ghost-node")
			Expect(err).To(HaveOccurred())
		})

		It("should fail to sign invalid subject name", func() {
			_, err := myCA.Sign("bad/name")
			Expect(err).To(HaveOccurred())
		})

		It("should fail to save invalid subject name", func() {
			csrPEM, _ := testutil.GenerateCSR("bad/name")
			_, err := myCA.SaveRequest("bad/name", csrPEM)
			Expect(err).To(HaveOccurred())
		})

		It("should fail to sign garbage CSR data", func() {
			// Save garbage manually
			err := store.SaveCSR("garbage-node", []byte("GARBAGE"))
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign("garbage-node")
			Expect(err).To(HaveOccurred())
		})

		It("should reject a subject containing ..", func() {
			_, err := myCA.Sign("a..b")
			Expect(err).To(HaveOccurred())
			_, err = myCA.SaveRequest("a..b", []byte("fake"))
			Expect(err).To(HaveOccurred())
		})
	})
})

// --- TTL capping ---

var _ = Describe("CA TTL capping", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-ttl-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("caps signed cert NotAfter to the CA cert NotAfter when TTL would exceed it", func() {
		csrPEM, err := testutil.GenerateCSR("ttl-cap-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("ttl-cap-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		// The test CA cert expires in ~1 hour (see testutil.GenerateTestCA).
		// Request a TTL far beyond that window.
		certPEM, err := myCA.SignWithTTL("ttl-cap-node", 100*365*24*time.Hour)
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Leaf cert must not outlive the CA cert.
		Expect(cert.NotAfter).To(BeTemporally("<=", myCA.CACert.NotAfter))
	})

	It("uses the requested TTL when it is shorter than the CA cert remaining lifetime", func() {
		csrPEM, err := testutil.GenerateCSR("short-ttl-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("short-ttl-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		shortTTL := 10 * time.Minute
		certPEM, err := myCA.SignWithTTL("short-ttl-node", shortTTL)
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// NotAfter should be approximately now + shortTTL (within a few seconds of clock skew).
		expectedNotAfter := time.Now().Add(shortTTL)
		Expect(cert.NotAfter).To(BeTemporally("~", expectedNotAfter, 30*time.Second))
	})
})

// --- Tampered CSR ---

var _ = Describe("CA tampered CSR rejection", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-tamper-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "true"}, "puppet.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("rejects a CSR whose signature does not match its public key", func() {
		// Build a valid CSR, then corrupt the last byte of the DER.
		// The RSA signature occupies the final 256 bytes; flipping one bit
		// produces a structurally valid but cryptographically invalid CSR.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "tampered-node"},
		}, key)
		Expect(err).NotTo(HaveOccurred())

		csrDER[len(csrDER)-1] ^= 0x01 // flip one bit in the signature

		tamperedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

		// With autosign=true, SaveRequest triggers Sign() immediately.
		// Sign() calls csr.CheckSignature() and must return an error.
		_, err = myCA.SaveRequest("tampered-node", tamperedPEM)
		Expect(err).To(HaveOccurred(), "expected signing to fail for a tampered CSR")
	})
})

// --- CA Bootstrap ---

var _ = Describe("CA Bootstrap", func() {
	It("bootstraps a new CA when no files exist", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-bootstrap-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.bootstrap.test")
		Expect(myCA.Init()).To(Succeed())

		Expect(myCA.CACert).NotTo(BeNil())
		Expect(myCA.CAKey).NotTo(BeNil())
		Expect(myCA.CACert.Subject.CommonName).To(Equal("Puppet CA: puppet.bootstrap.test"))
		Expect(myCA.CACert.IsCA).To(BeTrue())

		// All expected files should exist on disk.
		for _, path := range []string{store.CACertPath(), store.CAKeyPath(), store.CRLPath(), store.InventoryPath()} {
			_, err := os.Stat(path)
			Expect(err).NotTo(HaveOccurred(), "expected file to exist: %s", path)
		}
	})

	It("bootstraps a new ECDSA CA when configured with KeyAlgoECDSA", func() {
		tmpDir, err := os.MkdirTemp("", "puppet-ca-bootstrap-ecdsa-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.ecdsa.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init()).To(Succeed())

		Expect(myCA.CACert).NotTo(BeNil())
		_, ok := myCA.CACert.PublicKey.(*ecdsa.PublicKey)
		Expect(ok).To(BeTrue(), "bootstrapped CA should have an ECDSA public key")

		// The on-disk key must be loadable as ECDSA on a second Init call.
		myCA2 := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.ecdsa.test")
		Expect(myCA2.Init()).To(Succeed())
		_, ok = myCA2.CACert.PublicKey.(*ecdsa.PublicKey)
		Expect(ok).To(BeTrue(), "reloaded CA should still have an ECDSA public key")
	})
})

// --- Revocation ---

var _ = Describe("CA Revocation", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-revoke-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("marks a signed certificate as revoked in the CRL", func() {
		csrPEM, err := testutil.GenerateCSR("revoke-node")
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.SaveRequest("revoke-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign("revoke-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.IsRevoked("revoke-node")).To(BeFalse())

		Expect(myCA.Revoke("revoke-node")).To(Succeed())
		Expect(myCA.IsRevoked("revoke-node")).To(BeTrue())
	})

	It("IsRevoked returns false for a node that was never signed", func() {
		Expect(myCA.IsRevoked("ghost-node")).To(BeFalse())
	})

	It("returns an error when revoking a subject with no inventory entry", func() {
		Expect(myCA.Revoke("never-signed")).To(HaveOccurred())
	})

	It("IsRevokedSerial returns true for a revoked certificate's serial", func() {
		csrPEM, err := testutil.GenerateCSR("serial-revoke-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("serial-revoke-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign("serial-revoke-node")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Before revocation: serial is not in CRL.
		revoked, err := myCA.IsRevokedSerial(cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse())

		// After revocation: serial appears in CRL.
		Expect(myCA.Revoke("serial-revoke-node")).To(Succeed())
		revoked, err = myCA.IsRevokedSerial(cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("IsRevokedSerial returns false for an unknown serial", func() {
		unknownSerial := new(big.Int).SetInt64(999999)
		revoked, err := myCA.IsRevokedSerial(unknownSerial)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse())
	})

	It("IsRevokedSerial still works when the CRL file is deleted (in-memory cache)", func() {
		Expect(store.Backend().Delete(storage.KeyCRL)).To(Succeed())
		revoked, err := myCA.IsRevokedSerial(new(big.Int).SetInt64(1))
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse())
	})
})

// --- SaveRequest edge cases ---

var _ = Describe("CA SaveRequest edge cases", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-savereq-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("returns ErrCertExists when a valid cert already exists for the subject", func() {
		csrPEM, err := testutil.GenerateCSR("dup-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("dup-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign("dup-node")
		Expect(err).NotTo(HaveOccurred())

		// Second SaveRequest should fail with ErrCertExists.
		csrPEM2, err := testutil.GenerateCSR("dup-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("dup-node", csrPEM2)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ca.ErrCertExists)).To(BeTrue())

		// Malformed CSR must not be written to disk.
		Expect(store.HasCSR("dup-node")).To(BeFalse())
	})

	It("allows re-registration after a certificate is revoked", func() {
		csrPEM, err := testutil.GenerateCSR("rereg-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("rereg-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign("rereg-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.Revoke("rereg-node")).To(Succeed())

		csrPEM2, err := testutil.GenerateCSR("rereg-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("rereg-node", csrPEM2)
		Expect(err).NotTo(HaveOccurred())

		// Old cert must be gone.
		Expect(store.HasCert("rereg-node")).To(BeFalse())
		// New CSR must be on disk.
		Expect(store.HasCSR("rereg-node")).To(BeTrue())
	})

	It("rejects a malformed CSR without writing anything to disk", func() {
		_, err := myCA.SaveRequest("bad-csr-node", []byte("NOT PEM"))
		Expect(err).To(HaveOccurred())
		Expect(store.HasCSR("bad-csr-node")).To(BeFalse())
	})
})

// --- Autosign ---

var _ = Describe("CA Autosign", func() {
	var (
		tmpDir string
		store  *storage.StorageService
	)

	newCA := func(cfg ca.AutosignConfig) *ca.CA {
		myCA := ca.New(store, cfg, "puppet.test")
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
		return myCA
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-autosign-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		Expect(store.EnsureDirs()).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("autosign=true immediately signs the CSR", func() {
		myCA := newCA(ca.AutosignConfig{Mode: "true"})
		csrPEM, err := testutil.GenerateCSR("auto-node")
		Expect(err).NotTo(HaveOccurred())

		signed, err := myCA.SaveRequest("auto-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue())
		Expect(store.HasCert("auto-node")).To(BeTrue())
		Expect(store.HasCSR("auto-node")).To(BeFalse(), "CSR should be deleted after signing")
	})

	It("autosign=true strips authorization OIDs from the autosigned certificate", func() {
		myCA := newCA(ca.AutosignConfig{Mode: "true"})

		// Build a CSR carrying pp_cli_auth = "true".
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		ppCliAuthVal, err := asn1.Marshal("true")
		Expect(err).NotTo(HaveOccurred())
		oidPpCliAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:         pkix.Name{CommonName: "evil-autosign"},
			ExtraExtensions: []pkix.Extension{{Id: oidPpCliAuth, Value: ppCliAuthVal}},
		}, key)
		Expect(err).NotTo(HaveOccurred())
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

		signed, err := myCA.SaveRequest("evil-autosign", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue(), "autosign=true should sign immediately")

		// Parse the signed cert and verify pp_cli_auth is NOT present.
		certPEM, err := store.GetCert("evil-autosign")
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		for _, ext := range cert.Extensions {
			Expect(ext.Id.Equal(oidPpCliAuth)).To(BeFalse(),
				"autosigned cert must NOT carry pp_cli_auth, as this would grant CA admin access")
		}
	})

	It("autosign=file signs when CN matches a glob pattern", func() {
		autosignFile, err := os.CreateTemp(tmpDir, "autosign-*.conf")
		Expect(err).NotTo(HaveOccurred())
		_, err = autosignFile.WriteString("# comment\n*.example.com\n")
		Expect(err).NotTo(HaveOccurred())
		autosignFile.Close()

		myCA := newCA(ca.AutosignConfig{Mode: "file", FileOrPath: autosignFile.Name()})

		matchingCSR, err := testutil.GenerateCSR("host.example.com")
		Expect(err).NotTo(HaveOccurred())
		signed, err := myCA.SaveRequest("host.example.com", matchingCSR)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue())
	})

	It("autosign=file queues CSR when CN does not match any pattern", func() {
		autosignFile, err := os.CreateTemp(tmpDir, "autosign-*.conf")
		Expect(err).NotTo(HaveOccurred())
		_, err = autosignFile.WriteString("*.example.com\n")
		Expect(err).NotTo(HaveOccurred())
		autosignFile.Close()

		myCA := newCA(ca.AutosignConfig{Mode: "file", FileOrPath: autosignFile.Name()})

		noMatchCSR, err := testutil.GenerateCSR("other.org")
		Expect(err).NotTo(HaveOccurred())
		signed, err := myCA.SaveRequest("other.org", noMatchCSR)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeFalse())
		Expect(store.HasCSR("other.org")).To(BeTrue())
	})
})

// --- ValidateSubject ---

var _ = Describe("ValidateSubject", func() {
	DescribeTable("valid subjects",
		func(s string) { Expect(ca.ValidateSubject(s)).To(Succeed()) },
		Entry("simple hostname", "puppet"),
		Entry("FQDN", "node.example.com"),
		Entry("with hyphens", "my-node-01"),
		Entry("with underscores", "my_node"),
	)

	DescribeTable("invalid subjects",
		func(s string) { Expect(ca.ValidateSubject(s)).To(HaveOccurred()) },
		Entry("contains slash", "bad/name"),
		Entry("contains double-dot", "a..b"),
		Entry("double-dot only", ".."),
		Entry("uppercase letters", "BadNode"),
		Entry("empty string", ""),
	)
})

// --- CA:TRUE rejection ---

var _ = Describe("CA sign rejects CA:TRUE extension", func() {
	var (
		tmpDir string
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-catrue-test")
		Expect(err).NotTo(HaveOccurred())

		store := storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("returns an error containing the OID when BasicConstraints CA:TRUE is present", func() {
		// Build a CSR with BasicConstraints CA:TRUE (OID 2.5.29.19).
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		bcVal, err := asn1.Marshal(struct {
			IsCA bool `asn1:"optional"`
		}{IsCA: true})
		Expect(err).NotTo(HaveOccurred())

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "evil-ca"},
			ExtraExtensions: []pkix.Extension{{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Critical: true,
				Value:    bcVal,
			}},
		}, key)
		Expect(err).NotTo(HaveOccurred())

		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

		// Submit the CSR (valid for storage purposes).
		_, err = myCA.SaveRequest("evil-ca", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		// Signing must fail with a message that matches Puppet CA's response.
		_, err = myCA.Sign("evil-ca")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Found extensions"))
		Expect(err.Error()).To(ContainSubstring("2.5.29.19"))
	})
})

// --- Issue #8: cert improvements ---

// newIssuedCert is a helper that initialises a CA backed by dir, signs a
// certificate for subject, and returns the parsed certificate.
func newIssuedCert(dir, subject string) (*x509.Certificate, *ca.CA) {
	store := storage.New(dir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
	Expect(store.EnsureDirs()).To(Succeed())
	Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
	Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
	Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
	Expect(store.WriteSerial("0001")).To(Succeed())
	Expect(store.TouchInventory()).To(Succeed())
	Expect(myCA.Init()).To(Succeed())

	csrPEM, err := testutil.GenerateCSR(subject)
	Expect(err).NotTo(HaveOccurred())
	_, err = myCA.SaveRequest(subject, csrPEM)
	Expect(err).NotTo(HaveOccurred())
	certPEM, err := myCA.Sign(subject)
	Expect(err).NotTo(HaveOccurred())

	block, _ := pem.Decode(certPEM)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert, myCA
}

var _ = Describe("Issued certificate properties (issue #8)", func() {
	var tmpDir string

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-issue8-test")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	// --- Authorization OIDs stripped from CSR ---

	It("strips authorization-arc OIDs (like pp_cli_auth) from signed certificates", func() {
		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())

		// Build a CSR carrying pp_cli_auth = "true" and a non-auth Puppet OID.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		ppCliAuthVal, err := asn1.Marshal("true")
		Expect(err).NotTo(HaveOccurred())
		ppRegVal, err := asn1.Marshal("some-value")
		Expect(err).NotTo(HaveOccurred())

		oidPpCliAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39}
		oidPpRegCert := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 1} // non-auth Puppet OID

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "auth-strip-node"},
			ExtraExtensions: []pkix.Extension{
				{Id: oidPpCliAuth, Value: ppCliAuthVal},
				{Id: oidPpRegCert, Value: ppRegVal},
			},
		}, key)
		Expect(err).NotTo(HaveOccurred())

		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
		_, err = myCA.SaveRequest("auth-strip-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		certPEM, err := myCA.Sign("auth-strip-node")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// The auth OID must be stripped.
		for _, ext := range cert.Extensions {
			Expect(ext.Id.Equal(oidPpCliAuth)).To(BeFalse(),
				"signed cert must not carry the pp_cli_auth extension")
		}
		// The non-auth Puppet OID must be preserved.
		found := false
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidPpRegCert) {
				found = true
			}
		}
		Expect(found).To(BeTrue(), "signed cert must preserve non-auth Puppet OID extensions")
	})

	// --- Netscape Comment removed ---

	It("does not embed the Netscape Comment extension in issued certificates", func() {
		oidNetscapeComment := asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
		cert, _ := newIssuedCert(tmpDir, "ns-comment-node")

		for _, ext := range cert.Extensions {
			Expect(ext.Id.Equal(oidNetscapeComment)).To(BeFalse(),
				"signed cert must not carry the deprecated Netscape Comment extension (OID 2.16.840.1.113730.1.13)")
		}
	})

	// --- Randomised serial numbers ---

	It("issues certificates with random (non-sequential) serial numbers", func() {
		// Sign two certs and verify the serials are different.
		cert1, _ := newIssuedCert(tmpDir, "serial-node-1")

		tmpDir2, err := os.MkdirTemp("", "puppet-ca-issue8-serial-test2")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir2)
		cert2, _ := newIssuedCert(tmpDir2, "serial-node-2")

		Expect(cert1.SerialNumber.Cmp(cert2.SerialNumber)).NotTo(Equal(0),
			"two independently issued certs must not share the same serial number")
	})

	It("issues certificates with 128-bit random serial numbers", func() {
		cert, _ := newIssuedCert(tmpDir, "large-serial-node")

		// Serial must be positive and fit within 128 bits.
		Expect(cert.SerialNumber.Sign()).To(Equal(1),
			"serial number must be positive")
		Expect(cert.SerialNumber.BitLen()).To(BeNumerically("<=", 128),
			"serial number must fit within 128 bits")
	})

	// --- CRL Distribution Points ---

	It("embeds CRL Distribution Points when CRLURLs is configured", func() {
		crlURL := "http://puppet-ca:8140/puppet-ca/v1/certificate_revocation_list/ca"

		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CRLURLs = []string{crlURL}
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())

		csrPEM, err := testutil.GenerateCSR("cdp-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("cdp-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign("cdp-node")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		Expect(cert.CRLDistributionPoints).To(ContainElement(crlURL))
	})

	It("does not embed CRL Distribution Points when CRLURLs is not configured", func() {
		cert, _ := newIssuedCert(tmpDir, "no-cdp-node")
		Expect(cert.CRLDistributionPoints).To(BeEmpty())
	})

	// --- Configurable CRL validity ---

	It("honours CRLValidityDays when generating a CRL on revocation", func() {
		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CRLValidityDays = 90
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())

		csrPEM, err := testutil.GenerateCSR("crl-validity-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("crl-validity-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign("crl-validity-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke("crl-validity-node")).To(Succeed())

		crlPEM, err := store.GetCRL()
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(crlPEM)
		Expect(block).NotTo(BeNil())
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		window := crl.NextUpdate.Sub(crl.ThisUpdate)
		expected := 90 * 24 * time.Hour
		Expect(window).To(BeNumerically("~", expected, time.Minute),
			"CRL NextUpdate should be ~90 days after ThisUpdate")
	})
})

// --- loadCA key format support ---

var _ = Describe("loadCA key format support", func() {
	var (
		tmpDir string
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-loadca-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("loads an ECDSA CA (EC PRIVATE KEY PEM)", func() {
		keyPEM, certPEM, crlPEM, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCAKey(keyPEM)).To(Succeed())
		Expect(store.SaveCACert(certPEM)).To(Succeed())
		Expect(store.UpdateCRL(crlPEM)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init()).To(Succeed())
		Expect(myCA.CACert).NotTo(BeNil())
	})

	It("loads a PKCS8-encoded CA key (PRIVATE KEY PEM)", func() {
		// Generate an ECDSA P-256 key and re-encode it as PKCS8.
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(ecKey)
		Expect(err).NotTo(HaveOccurred())
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

		// Build a matching self-signed CA cert.
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "Puppet CA: pkcs8-test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, ecKey.Public(), ecKey)
		Expect(err).NotTo(HaveOccurred())
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		cert, err := x509.ParseCertificate(certDER)
		Expect(err).NotTo(HaveOccurred())
		crlTmpl := &x509.RevocationList{
			Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(24 * time.Hour),
		}
		crlDER, err := x509.CreateRevocationList(rand.Reader, crlTmpl, cert, ecKey)
		Expect(err).NotTo(HaveOccurred())
		crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

		Expect(store.SaveCAKey(keyPEM)).To(Succeed())
		Expect(store.SaveCACert(certPEM)).To(Succeed())
		Expect(store.UpdateCRL(crlPEM)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init()).To(Succeed())
		Expect(myCA.CACert).NotTo(BeNil())
	})

	It("returns an error when the private key does not match the certificate", func() {
		// Write a cert from one generated CA but the key from a different one.
		_, certPEM, crlPEM, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		mismatchKeyPEM, _, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())

		Expect(store.SaveCAKey(mismatchKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(certPEM)).To(Succeed())
		Expect(store.UpdateCRL(crlPEM)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		// Both files exist but don't match: Init must return an error.
		Expect(myCA.Init()).To(HaveOccurred())
	})

	It("returns an error when the CA certificate PEM is malformed", func() {
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert([]byte("NOT VALID PEM"))).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init()).To(HaveOccurred())
	})
})

// --- Expired CA cert guard ---
// signWithDuration must refuse to sign when the CA cert has expired.

var _ = Describe("CA expired cert guard", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-expired-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("refuses to sign when the CA certificate has expired", func() {
		// Save the CSR while the CA is still valid.
		csrPEM, err := testutil.GenerateCSR("expired-ca-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("expired-ca-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		// Synthesise an expired CA cert using the real CA key so the key-cert
		// check inside loadCA would pass; here we bypass loadCA and set the
		// field directly to simulate the CA running past its cert expiry.
		expiredTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(999),
			Subject:               pkix.Name{CommonName: "Expired Puppet CA"},
			NotBefore:             time.Now().Add(-48 * time.Hour),
			NotAfter:              time.Now().Add(-time.Second), // already expired
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		expiredDER, err := x509.CreateCertificate(rand.Reader, expiredTmpl, expiredTmpl, myCA.CAKey.Public(), myCA.CAKey)
		Expect(err).NotTo(HaveOccurred())
		expiredCert, err := x509.ParseCertificate(expiredDER)
		Expect(err).NotTo(HaveOccurred())

		myCA.CACert = expiredCert

		_, err = myCA.Sign("expired-ca-node")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("expired"))
	})
})

// --- CA Clean ---

var _ = Describe("CA Clean", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-clean-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("revokes the cert and removes it from disk", func() {
		csrPEM, err := testutil.GenerateCSR("clean-cert-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("clean-cert-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign("clean-cert-node")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.Clean("clean-cert-node")).To(Succeed())

		// Cert file must be gone.
		Expect(store.HasCert("clean-cert-node")).To(BeFalse())
		// Serial must appear in the CRL (revoke happened before delete).
		revoked, err := myCA.IsRevokedSerial(cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("deletes a pending CSR when no cert exists", func() {
		csrPEM, err := testutil.GenerateCSR("clean-csr-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("clean-csr-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.HasCSR("clean-csr-node")).To(BeTrue())

		Expect(myCA.Clean("clean-csr-node")).To(Succeed())

		Expect(store.HasCSR("clean-csr-node")).To(BeFalse())
	})

	It("returns ErrNotFound when the subject has neither a cert nor a CSR", func() {
		err := myCA.Clean("ghost-node")
		Expect(errors.Is(err, ca.ErrNotFound)).To(BeTrue())
	})
})

// --- CA bulk signing ---

var _ = Describe("CA bulk signing (SignMultiple and SignAll)", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-bulk-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("SignMultiple signs all subjects that have pending CSRs", func() {
		for _, sub := range []string{"bulk-1", "bulk-2"} {
			csrPEM, err := testutil.GenerateCSR(sub)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(sub, csrPEM)
			Expect(err).NotTo(HaveOccurred())
		}

		result := myCA.SignMultiple([]string{"bulk-1", "bulk-2"})
		Expect(result.Signed).To(ConsistOf("bulk-1", "bulk-2"))
		Expect(result.NoCSR).To(BeEmpty())
		Expect(result.SigningErrors).To(BeEmpty())
	})

	It("SignMultiple reports subjects with no pending CSR in NoCSR", func() {
		csrPEM, err := testutil.GenerateCSR("present-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("present-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		result := myCA.SignMultiple([]string{"present-node", "absent-node"})
		Expect(result.Signed).To(ConsistOf("present-node"))
		Expect(result.NoCSR).To(ConsistOf("absent-node"))
		Expect(result.SigningErrors).To(BeEmpty())
	})

	It("SignMultiple collects signing errors without stopping other subjects", func() {
		// Save an unparseable CSR directly so HasCSR returns true but Sign fails.
		Expect(store.SaveCSR("bad-csr-node", []byte("GARBAGE"))).To(Succeed())
		csrPEM, err := testutil.GenerateCSR("good-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest("good-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		result := myCA.SignMultiple([]string{"bad-csr-node", "good-node"})
		Expect(result.Signed).To(ConsistOf("good-node"))
		Expect(result.SigningErrors).To(ConsistOf("bad-csr-node"))
		Expect(result.NoCSR).To(BeEmpty())
	})

	It("SignAll signs every pending CSR on disk", func() {
		for _, sub := range []string{"all-1", "all-2", "all-3"} {
			csrPEM, err := testutil.GenerateCSR(sub)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(sub, csrPEM)
			Expect(err).NotTo(HaveOccurred())
		}

		result, err := myCA.SignAll()
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Signed).To(ConsistOf("all-1", "all-2", "all-3"))
		Expect(result.NoCSR).To(BeEmpty())
		Expect(result.SigningErrors).To(BeEmpty())
	})

	It("SignAll returns an empty result when no CSRs are pending", func() {
		result, err := myCA.SignAll()
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Signed).To(BeEmpty())
	})
})

// --- CA ImportCA ---

// generateNonCAKeyAndCert creates a self-signed leaf certificate (IsCA=false)
// for use in ImportCA rejection tests.
func generateNonCAKeyAndCert() (keyPEM, certPEM []byte) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "leaf-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

var _ = Describe("CA ImportCA", func() {
	var (
		tmpDir string
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-import-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("imports a valid RSA CA with a provided CRL", func() {
		keyPEM, certPEM, crlPEM, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.ImportCA(store, certPEM, keyPEM, crlPEM)).To(Succeed())
		Expect(store.HasCACert()).To(BeTrue())
		Expect(store.HasCAKey()).To(BeTrue())
		crl, err := store.GetCRL()
		Expect(err).NotTo(HaveOccurred())
		Expect(crl).NotTo(BeEmpty())
	})

	It("imports a valid ECDSA CA and generates a fresh CRL when none is provided", func() {
		keyPEM, certPEM, _, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.ImportCA(store, certPEM, keyPEM, nil)).To(Succeed())
		crlPEM, err := store.GetCRL()
		Expect(err).NotTo(HaveOccurred())
		Expect(crlPEM).NotTo(BeEmpty())
	})

	It("returns an error when the certificate is not a CA certificate", func() {
		keyPEM, certPEM := generateNonCAKeyAndCert()
		err := ca.ImportCA(store, certPEM, keyPEM, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("IsCA=false"))
	})

	It("returns an error when the private key does not match the certificate", func() {
		_, certPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		mismatchKeyPEM, _, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		err = ca.ImportCA(store, certPEM, mismatchKeyPEM, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not match"))
	})

	It("returns an error when the provided CRL is invalid PEM", func() {
		keyPEM, certPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		err = ca.ImportCA(store, certPEM, keyPEM, []byte("not valid PEM"))
		Expect(err).To(HaveOccurred())
	})

	It("does not overwrite existing serial and inventory files", func() {
		keyPEM, certPEM, crlPEM, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.WriteSerial("DEADBEEF")).To(Succeed())
		Expect(store.Backend().Put(storage.KeyInventory, []byte("existing line\n"), storage.BlobPrivate)).To(Succeed())

		Expect(ca.ImportCA(store, certPEM, keyPEM, crlPEM)).To(Succeed())

		serialData, err := store.GetSerial()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(serialData)).To(Equal("DEADBEEF"))
		invData, err := store.ReadInventory()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(invData)).To(Equal("existing line\n"))
	})

	It("imports an RSA CA whose private key is encoded as PKCS8 (PRIVATE KEY)", func() {
		// Generate an RSA CA, then re-encode its private key as PKCS8 so
		// that the "PRIVATE KEY" branch of the ImportCA key parser is exercised.
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		// Build a minimal self-signed CA cert.
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "pkcs8-import-ca"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
		Expect(err).NotTo(HaveOccurred())
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

		// Encode as PKCS8 ("PRIVATE KEY").
		pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		Expect(err).NotTo(HaveOccurred())
		pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

		Expect(ca.ImportCA(store, certPEM, pkcs8PEM, nil)).To(Succeed())
		Expect(store.HasCACert()).To(BeTrue())
		Expect(store.HasCAKey()).To(BeTrue())
	})
})

var _ = Describe("Concurrent SaveRequest", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-concurrent-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "true"}, "puppet.test")

		Expect(store.EnsureDirs()).To(Succeed())
		Expect(store.SaveCAKey(cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial("0001")).To(Succeed())
		Expect(store.TouchInventory()).To(Succeed())
		Expect(myCA.Init()).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("allows exactly one autosign when concurrent requests race for the same subject", func() {
		const goroutines = 10
		subject := "race-node"

		var wg sync.WaitGroup
		signedCount := 0
		errCount := 0
		var mu sync.Mutex

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				csrPEM, err := testutil.GenerateCSR(subject)
				Expect(err).NotTo(HaveOccurred())

				signed, err := myCA.SaveRequest(subject, csrPEM)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errCount++
				} else if signed {
					signedCount++
				}
			}()
		}
		wg.Wait()

		// Exactly one goroutine should have successfully autosigned.
		Expect(signedCount).To(Equal(1), "expected exactly one autosign success")

		// Exactly one signed cert should exist on disk.
		Expect(store.HasCert(subject)).To(BeTrue())

		// No pending CSR should remain (autosign deletes it after signing).
		Expect(store.HasCSR(subject)).To(BeFalse())
	})
})
