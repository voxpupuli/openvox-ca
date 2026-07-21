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
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		asCfg = ca.AutosignConfig{Mode: "off"}
		myCA = ca.New(store, asCfg, "puppet.test")

		// Optimization: Pre-seed the CA with keys generated in BeforeSuite
		// This avoids generating 4096-bit keys for every test case.
		err = store.EnsureDirs(context.Background())
		Expect(err).NotTo(HaveOccurred())

		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())

		// Also pre-seed Serial and Inventory which are normally created by bootstrapCA
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Context("Initialization", func() {
		It("should load existing CA successfully", func() {
			err := myCA.Init(context.Background())
			Expect(err).NotTo(HaveOccurred())

			// Verify they are the same
			loadedCert, err := store.GetCACert(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(loadedCert).To(Equal(cachedCrtPEM))
		})
	})

	// Defensive: a CA constructed by New() but never Init()-ed has a nil
	// CACert and CAKey. Internal signing helpers must surface a controlled
	// error rather than panicking the frontend with a nil dereference.
	Context("Signing on an uninitialised CA", func() {
		var (
			rawDir   string
			rawStore *storage.StorageService
			rawCA    *ca.CA
		)

		BeforeEach(func() {
			var err error
			rawDir, err = os.MkdirTemp("", "openvox-ca-uninit-test")
			Expect(err).NotTo(HaveOccurred())
			rawStore = storage.New(rawDir)
			Expect(rawStore.EnsureDirs(context.Background())).To(Succeed())
			// Note: deliberately do NOT load CA cert/key, do NOT call Init.
			rawCA = ca.New(rawStore, asCfg, "puppet.test")
		})

		AfterEach(func() {
			os.RemoveAll(rawDir)
		})

		It("returns ErrNotInitialized rather than panicking when Sign() is called", func() {
			var (
				out []byte
				err error
			)
			Expect(func() { out, err = rawCA.Sign(context.Background(), "uninit-node") }).NotTo(Panic())
			Expect(err).To(MatchError(ca.ErrNotInitialized))
			Expect(out).To(BeEmpty())
		})

		It("returns ErrNotInitialized rather than panicking when SignWithTTL() is called", func() {
			var (
				out []byte
				err error
			)
			Expect(func() { out, err = rawCA.SignWithTTL(context.Background(), "uninit-ttl-node", 24*time.Hour) }).NotTo(Panic())
			Expect(err).To(MatchError(ca.ErrNotInitialized))
			Expect(out).To(BeEmpty())
		})

		It("reports IsReady=false until Init has succeeded", func() {
			Expect(rawCA.IsReady()).To(BeFalse())
		})
	})

	// Simulates "existing cert+key mounted via overlay against an empty
	// backend": cert/key present, CRL/inventory/serial absent. Init should
	// seed the supporting state rather than failing.
	Context("Initialization with missing supporting state", func() {
		var (
			seedDir   string
			seedStore *storage.StorageService
			seedCA    *ca.CA
		)

		BeforeEach(func() {
			var err error
			seedDir, err = os.MkdirTemp("", "openvox-ca-seed-test")
			Expect(err).NotTo(HaveOccurred())
			seedStore = storage.New(seedDir)
			Expect(seedStore.EnsureDirs(context.Background())).To(Succeed())
			// Only cert + key — no CRL, no inventory, no serial.
			Expect(seedStore.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
			Expect(seedStore.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
			seedCA = ca.New(seedStore, asCfg, "puppet.test")
		})

		AfterEach(func() {
			os.RemoveAll(seedDir)
		})

		It("seeds CRL, inventory, and serial for an existing cert+key", func() {
			Expect(seedCA.Init(context.Background())).To(Succeed())

			crlPEM, err := seedStore.GetCRL(context.Background())
			Expect(err).NotTo(HaveOccurred())
			crlBlock, _ := pem.Decode(crlPEM)
			Expect(crlBlock).NotTo(BeNil())
			crl, err := x509.ParseRevocationList(crlBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(crl.RevokedCertificateEntries).To(BeEmpty())

			hasInv, err := seedStore.HasInventory(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(hasInv).To(BeTrue())

			hasSerial, err := seedStore.HasSerial(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(hasSerial).To(BeTrue())
		})

		It("is idempotent across repeated Init calls", func() {
			Expect(seedCA.Init(context.Background())).To(Succeed())
			crlBefore, err := seedStore.GetCRL(context.Background())
			Expect(err).NotTo(HaveOccurred())

			// Second Init against the same storage should load the CRL the
			// first Init seeded without rewriting it.
			seedCA2 := ca.New(seedStore, asCfg, "puppet.test")
			Expect(seedCA2.Init(context.Background())).To(Succeed())
			crlAfter, err := seedStore.GetCRL(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(crlAfter).To(Equal(crlBefore))
		})
	})

	Context("CSR Handling", func() {
		var csrPEM []byte

		BeforeEach(func() {
			var err error
			err = myCA.Init(context.Background())
			Expect(err).NotTo(HaveOccurred())
			csrPEM, err = testutil.GenerateCSR("test-node")
			Expect(err).NotTo(HaveOccurred())
		})

		It("should save a valid CSR but not sign it when autosign is off", func() {
			saved, err := myCA.SaveRequest(context.Background(), "test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(saved).To(BeFalse(), "Expected saved=false (autosign off)")

			_, err = os.Stat(filepath.Join(tmpDir, "requests", "test-node.pem"))
			Expect(os.IsNotExist(err)).To(BeFalse(), "CSR file should be created")
		})

		It("should sign a valid CSR", func() {
			_, err := myCA.SaveRequest(context.Background(), "test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())

			certPEM, err := myCA.Sign(context.Background(), "test-node")
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

	Context("CN to SAN promotion", func() {
		BeforeEach(func() {
			err := myCA.Init(context.Background())
			Expect(err).NotTo(HaveOccurred())
		})

		parseCert := func(certPEM []byte) *x509.Certificate {
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			return cert
		}

		It("promotes CN to SAN when no SANs are present (default on)", func() {
			csrPEM, err := testutil.GenerateCSR("test-node")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(context.Background(), "test-node")
			Expect(err).NotTo(HaveOccurred())
			Expect(parseCert(certPEM).DNSNames).To(ConsistOf("test-node"))
		})

		It("does not promote CN when the CSR already carries SANs", func() {
			key, _ := rsa.GenerateKey(rand.Reader, 2048)
			tmpl := &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "test-node"},
				DNSNames: []string{"alt.test-node"},
			}
			csrDER, _ := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

			_, err := myCA.SaveRequest(context.Background(), "test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(context.Background(), "test-node")
			Expect(err).NotTo(HaveOccurred())
			Expect(parseCert(certPEM).DNSNames).To(ConsistOf("alt.test-node"))
		})

		It("does not promote CN when PromoteCNToSAN is false", func() {
			myCA.PromoteCNToSAN = false
			csrPEM, err := testutil.GenerateCSR("test-node")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(context.Background(), "test-node")
			Expect(err).NotTo(HaveOccurred())
			Expect(parseCert(certPEM).DNSNames).To(BeEmpty())
		})
	})

	Context("Negative Tests", func() {
		BeforeEach(func() {
			err := myCA.Init(context.Background())
			Expect(err).NotTo(HaveOccurred())
		})

		It("should fail to sign non-existent CSR", func() {
			_, err := myCA.Sign(context.Background(), "ghost-node")
			Expect(err).To(HaveOccurred())
		})

		It("should fail to sign invalid subject name", func() {
			_, err := myCA.Sign(context.Background(), "bad/name")
			Expect(err).To(HaveOccurred())
		})

		It("should fail to save invalid subject name", func() {
			csrPEM, _ := testutil.GenerateCSR("bad/name")
			_, err := myCA.SaveRequest(context.Background(), "bad/name", csrPEM)
			Expect(err).To(HaveOccurred())
		})

		It("should fail to sign garbage CSR data", func() {
			// Save garbage manually
			err := store.SaveCSR(context.Background(), "garbage-node", []byte("GARBAGE"))
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(context.Background(), "garbage-node")
			Expect(err).To(HaveOccurred())
		})

		It("should reject a subject containing ..", func() {
			_, err := myCA.Sign(context.Background(), "a..b")
			Expect(err).To(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "a..b", []byte("fake"))
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-ttl-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("caps signed cert NotAfter to the CA cert NotAfter when TTL would exceed it", func() {
		csrPEM, err := testutil.GenerateCSR("ttl-cap-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ttl-cap-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		// The test CA cert expires in ~1 hour (see testutil.GenerateTestCA).
		// Request a TTL far beyond that window.
		certPEM, err := myCA.SignWithTTL(context.Background(), "ttl-cap-node", 100*365*24*time.Hour)
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
		_, err = myCA.SaveRequest(context.Background(), "short-ttl-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		shortTTL := 10 * time.Minute
		certPEM, err := myCA.SignWithTTL(context.Background(), "short-ttl-node", shortTTL)
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-tamper-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "true"}, "puppet.test")

		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
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
		_, err = myCA.SaveRequest(context.Background(), "tampered-node", tamperedPEM)
		Expect(err).To(HaveOccurred(), "expected signing to fail for a tampered CSR")
	})
})

// --- CA Bootstrap ---

var _ = Describe("CA Bootstrap", func() {
	It("bootstraps a new CA when no files exist", func() {
		tmpDir, err := os.MkdirTemp("", "openvox-ca-bootstrap-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.bootstrap.test")
		Expect(myCA.Init(context.Background())).To(Succeed())

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
		tmpDir, err := os.MkdirTemp("", "openvox-ca-bootstrap-ecdsa-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.ecdsa.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(context.Background())).To(Succeed())

		Expect(myCA.CACert).NotTo(BeNil())
		_, ok := myCA.CACert.PublicKey.(*ecdsa.PublicKey)
		Expect(ok).To(BeTrue(), "bootstrapped CA should have an ECDSA public key")

		// The on-disk key must be loadable as ECDSA on a second Init call.
		myCA2 := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.ecdsa.test")
		Expect(myCA2.Init(context.Background())).To(Succeed())
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-revoke-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("marks a signed certificate as revoked in the CRL", func() {
		csrPEM, err := testutil.GenerateCSR("revoke-node")
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.SaveRequest(context.Background(), "revoke-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(context.Background(), "revoke-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.IsRevoked(context.Background(), "revoke-node")).To(BeFalse())

		Expect(myCA.Revoke(context.Background(), "revoke-node")).To(Succeed())
		Expect(myCA.IsRevoked(context.Background(), "revoke-node")).To(BeTrue())
	})

	It("IsRevoked returns false for a node that was never signed", func() {
		Expect(myCA.IsRevoked(context.Background(), "ghost-node")).To(BeFalse())
	})

	It("returns an error when revoking a subject with no inventory entry", func() {
		Expect(myCA.Revoke(context.Background(), "never-signed")).To(HaveOccurred())
	})

	It("counts a CRL-update failure when a revocation cannot amend the CRL", func() {
		// The crlUpdateFailures counter is general, not renewal-specific: it must
		// move for any failed CRL amendment. Sign a cert, corrupt the stored CRL,
		// then revoke — revocation cannot parse the CRL, so it fails and the
		// failure is counted for alerting even though it is surfaced to the caller.
		csrPEM, err := testutil.GenerateCSR("revoke-count-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "revoke-count-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(context.Background(), "revoke-count-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 0))
		Expect(store.UpdateCRL(context.Background(), []byte("not a valid CRL"))).To(Succeed())

		Expect(myCA.Revoke(context.Background(), "revoke-count-node")).To(HaveOccurred())
		Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 1),
			"a failed CRL amendment must be counted regardless of the caller")
	})

	It("IsRevokedSerial returns true for a revoked certificate's serial", func() {
		csrPEM, err := testutil.GenerateCSR("serial-revoke-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "serial-revoke-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "serial-revoke-node")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Before revocation: serial is not in CRL.
		revoked, err := myCA.IsRevokedSerial(context.Background(), cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse())

		// After revocation: serial appears in CRL.
		Expect(myCA.Revoke(context.Background(), "serial-revoke-node")).To(Succeed())
		revoked, err = myCA.IsRevokedSerial(context.Background(), cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("IsRevokedSerial returns false for an unknown serial", func() {
		unknownSerial := new(big.Int).SetInt64(999999)
		revoked, err := myCA.IsRevokedSerial(context.Background(), unknownSerial)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeFalse())
	})

	It("IsRevokedSerial still works when the CRL file is deleted (in-memory cache)", func() {
		Expect(store.Backend().Delete(context.Background(), storage.KeyCRL)).To(Succeed())
		revoked, err := myCA.IsRevokedSerial(context.Background(), new(big.Int).SetInt64(1))
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-savereq-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("returns ErrCertExists when a valid cert already exists for the subject", func() {
		csrPEM, err := testutil.GenerateCSR("dup-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "dup-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(context.Background(), "dup-node")
		Expect(err).NotTo(HaveOccurred())

		// Second SaveRequest should fail with ErrCertExists.
		csrPEM2, err := testutil.GenerateCSR("dup-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "dup-node", csrPEM2)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ca.ErrCertExists)).To(BeTrue())

		// Malformed CSR must not be written to disk.
		Expect(store.HasCSR(context.Background(), "dup-node")).To(BeFalse())
	})

	It("allows re-registration after a certificate is revoked", func() {
		csrPEM, err := testutil.GenerateCSR("rereg-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "rereg-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(context.Background(), "rereg-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.Revoke(context.Background(), "rereg-node")).To(Succeed())

		csrPEM2, err := testutil.GenerateCSR("rereg-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "rereg-node", csrPEM2)
		Expect(err).NotTo(HaveOccurred())

		// Old cert must be gone.
		Expect(store.HasCert(context.Background(), "rereg-node")).To(BeFalse())
		// New CSR must be on disk.
		Expect(store.HasCSR(context.Background(), "rereg-node")).To(BeTrue())
	})

	It("rejects a malformed CSR without writing anything to disk", func() {
		_, err := myCA.SaveRequest(context.Background(), "bad-csr-node", []byte("NOT PEM"))
		Expect(err).To(HaveOccurred())
		Expect(store.HasCSR(context.Background(), "bad-csr-node")).To(BeFalse())
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
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
		return myCA
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-autosign-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("autosign=true immediately signs the CSR", func() {
		myCA := newCA(ca.AutosignConfig{Mode: "true"})
		csrPEM, err := testutil.GenerateCSR("auto-node")
		Expect(err).NotTo(HaveOccurred())

		signed, err := myCA.SaveRequest(context.Background(), "auto-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue())
		Expect(store.HasCert(context.Background(), "auto-node")).To(BeTrue())
		Expect(store.HasCSR(context.Background(), "auto-node")).To(BeFalse(), "CSR should be deleted after signing")
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

		signed, err := myCA.SaveRequest(context.Background(), "evil-autosign", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue(), "autosign=true should sign immediately")

		// Parse the signed cert and verify pp_cli_auth is NOT present.
		certPEM, err := store.GetCert(context.Background(), "evil-autosign")
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
		signed, err := myCA.SaveRequest(context.Background(), "host.example.com", matchingCSR)
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
		signed, err := myCA.SaveRequest(context.Background(), "other.org", noMatchCSR)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeFalse())
		Expect(store.HasCSR(context.Background(), "other.org")).To(BeTrue())
	})
})

// --- ValidateSubject ---

var _ = Describe("ValidateSubject", func() {
	DescribeTable("valid subjects",
		func(s string) { Expect(ca.ValidateSubject(s)).To(Succeed()) },
		Entry("simple hostname", "puppet"),
		Entry("FQDN", "foo.example.com"),
		Entry("with interior hyphens", "a-b"),
		Entry("with hyphens", "my-node-01"),
		Entry("with underscores", "my_node"),
		Entry("starts with digit", "1node"),
		Entry("ends with digit", "node1"),
		Entry("starts with underscore", "_node"),
		Entry("starts with dot", ".node"),
	)

	DescribeTable("invalid subjects",
		func(s string) { Expect(ca.ValidateSubject(s)).To(HaveOccurred()) },
		Entry("contains slash", "bad/name"),
		Entry("contains double-dot", "a..b"),
		Entry("double-dot only", ".."),
		Entry("uppercase letters", "BadNode"),
		Entry("contains space", "bad name"),
		Entry("empty string", ""),
		// SECURITY: a leading '-' could be misread as a flag by an operator's
		// autosign script, enabling argv flag injection. ValidateSubject must
		// reject it.
		Entry("leading hyphen (argv flag injection)", "-foo"),
		Entry("leading hyphen only", "-"),
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-catrue-test")
		Expect(err).NotTo(HaveOccurred())

		store := storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
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
		_, err = myCA.SaveRequest(context.Background(), "evil-ca", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		// Signing must fail with a message that matches Puppet CA's response.
		_, err = myCA.Sign(context.Background(), "evil-ca")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("found extensions"))
		Expect(err.Error()).To(ContainSubstring("2.5.29.19"))
	})
})

// --- Issue #8: cert improvements ---

// newIssuedCert is a helper that initialises a CA backed by dir, signs a
// certificate for subject, and returns the parsed certificate.
func newIssuedCert(dir, subject string) (*x509.Certificate, *ca.CA) {
	store := storage.New(dir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
	Expect(store.EnsureDirs(context.Background())).To(Succeed())
	Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
	Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
	Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
	Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
	Expect(store.TouchInventory(context.Background())).To(Succeed())
	Expect(myCA.Init(context.Background())).To(Succeed())

	csrPEM, err := testutil.GenerateCSR(subject)
	Expect(err).NotTo(HaveOccurred())
	_, err = myCA.SaveRequest(context.Background(), subject, csrPEM)
	Expect(err).NotTo(HaveOccurred())
	certPEM, err := myCA.Sign(context.Background(), subject)
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-issue8-test")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	// --- Authorization OIDs stripped from CSR ---

	It("strips authorization-arc OIDs (like pp_cli_auth) from signed certificates", func() {
		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())

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
		_, err = myCA.SaveRequest(context.Background(), "auth-strip-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		certPEM, err := myCA.Sign(context.Background(), "auth-strip-node")
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

		tmpDir2, err := os.MkdirTemp("", "openvox-ca-issue8-serial-test2")
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
		// Guard against a regression that shrinks the serial to a handful of
		// bits: a 128-bit random serial is >= 2^120 with overwhelming
		// probability, so >= 64 is a safe, non-flaky lower bound on entropy.
		Expect(cert.SerialNumber.BitLen()).To(BeNumerically(">=", 64),
			"serial number must carry real entropy, not a tiny value")
	})

	// --- CRL Distribution Points ---

	It("embeds CRL Distribution Points when CRLURLs is configured", func() {
		crlURL := "http://openvox-ca:8140/puppet-ca/v1/certificate_revocation_list/ca"

		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CRLURLs = []string{crlURL}
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())

		csrPEM, err := testutil.GenerateCSR("cdp-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "cdp-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "cdp-node")
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
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())

		csrPEM, err := testutil.GenerateCSR("crl-validity-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "crl-validity-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(context.Background(), "crl-validity-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(context.Background(), "crl-validity-node")).To(Succeed())

		crlPEM, err := store.GetCRL(context.Background())
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-loadca-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("loads an ECDSA CA (EC PRIVATE KEY PEM)", func() {
		keyPEM, certPEM, crlPEM, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCAKey(context.Background(), keyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), certPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), crlPEM)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(context.Background())).To(Succeed())
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

		Expect(store.SaveCAKey(context.Background(), keyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), certPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), crlPEM)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(context.Background())).To(Succeed())
		Expect(myCA.CACert).NotTo(BeNil())
	})

	It("returns an error when the private key does not match the certificate", func() {
		// Write a cert from one generated CA but the key from a different one.
		_, certPEM, crlPEM, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		mismatchKeyPEM, _, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())

		Expect(store.SaveCAKey(context.Background(), mismatchKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), certPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), crlPEM)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		// Both files exist but don't match: Init must return an error.
		Expect(myCA.Init(context.Background())).To(HaveOccurred())
	})

	It("returns an error when the CA certificate PEM is malformed", func() {
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), []byte("NOT VALID PEM"))).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(context.Background())).To(HaveOccurred())
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-expired-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("refuses to sign when the CA certificate has expired", func() {
		// Save the CSR while the CA is still valid.
		csrPEM, err := testutil.GenerateCSR("expired-ca-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "expired-ca-node", csrPEM)
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

		_, err = myCA.Sign(context.Background(), "expired-ca-node")
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-clean-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("revokes the cert and removes it from disk", func() {
		csrPEM, err := testutil.GenerateCSR("clean-cert-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "clean-cert-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "clean-cert-node")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.Clean(context.Background(), "clean-cert-node")).To(Succeed())

		// Cert file must be gone.
		Expect(store.HasCert(context.Background(), "clean-cert-node")).To(BeFalse())
		// Serial must appear in the CRL (revoke happened before delete).
		revoked, err := myCA.IsRevokedSerial(context.Background(), cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("deletes a pending CSR when no cert exists", func() {
		csrPEM, err := testutil.GenerateCSR("clean-csr-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "clean-csr-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.HasCSR(context.Background(), "clean-csr-node")).To(BeTrue())

		Expect(myCA.Clean(context.Background(), "clean-csr-node")).To(Succeed())

		Expect(store.HasCSR(context.Background(), "clean-csr-node")).To(BeFalse())
	})

	It("returns ErrNotFound when the subject has neither a cert nor a CSR", func() {
		err := myCA.Clean(context.Background(), "ghost-node")
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-bulk-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("SignMultiple signs all subjects that have pending CSRs", func() {
		for _, sub := range []string{"bulk-1", "bulk-2"} {
			csrPEM, err := testutil.GenerateCSR(sub)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), sub, csrPEM)
			Expect(err).NotTo(HaveOccurred())
		}

		result := myCA.SignMultiple(context.Background(), []string{"bulk-1", "bulk-2"})
		Expect(result.Signed).To(ConsistOf("bulk-1", "bulk-2"))
		Expect(result.NoCSR).To(BeEmpty())
		Expect(result.SigningErrors).To(BeEmpty())
	})

	It("SignMultiple reports subjects with no pending CSR in NoCSR", func() {
		csrPEM, err := testutil.GenerateCSR("present-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "present-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		result := myCA.SignMultiple(context.Background(), []string{"present-node", "absent-node"})
		Expect(result.Signed).To(ConsistOf("present-node"))
		Expect(result.NoCSR).To(ConsistOf("absent-node"))
		Expect(result.SigningErrors).To(BeEmpty())
	})

	It("SignMultiple collects signing errors without stopping other subjects", func() {
		// Save an unparseable CSR directly so HasCSR returns true but Sign fails.
		Expect(store.SaveCSR(context.Background(), "bad-csr-node", []byte("GARBAGE"))).To(Succeed())
		csrPEM, err := testutil.GenerateCSR("good-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "good-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		result := myCA.SignMultiple(context.Background(), []string{"bad-csr-node", "good-node"})
		Expect(result.Signed).To(ConsistOf("good-node"))
		Expect(result.SigningErrors).To(ConsistOf("bad-csr-node"))
		Expect(result.NoCSR).To(BeEmpty())
	})

	It("SignAll signs every pending CSR on disk", func() {
		for _, sub := range []string{"all-1", "all-2", "all-3"} {
			csrPEM, err := testutil.GenerateCSR(sub)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), sub, csrPEM)
			Expect(err).NotTo(HaveOccurred())
		}

		result, err := myCA.SignAll(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Signed).To(ConsistOf("all-1", "all-2", "all-3"))
		Expect(result.NoCSR).To(BeEmpty())
		Expect(result.SigningErrors).To(BeEmpty())
	})

	It("SignAll returns an empty result when no CSRs are pending", func() {
		result, err := myCA.SignAll(context.Background())
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-import-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	It("imports a valid RSA CA with a provided CRL", func() {
		keyPEM, certPEM, crlPEM, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.ImportCA(context.Background(), store, certPEM, keyPEM, crlPEM)).To(Succeed())
		Expect(store.HasCACert(context.Background())).To(BeTrue())
		Expect(store.HasCAKey(context.Background())).To(BeTrue())
		crl, err := store.GetCRL(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(crl).NotTo(BeEmpty())
	})

	It("imports a valid ECDSA CA and generates a fresh CRL when none is provided", func() {
		keyPEM, certPEM, _, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.ImportCA(context.Background(), store, certPEM, keyPEM, nil)).To(Succeed())
		crlPEM, err := store.GetCRL(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(crlPEM).NotTo(BeEmpty())
	})

	It("returns an error when the certificate is not a CA certificate", func() {
		keyPEM, certPEM := generateNonCAKeyAndCert()
		err := ca.ImportCA(context.Background(), store, certPEM, keyPEM, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("IsCA=false"))
	})

	It("returns an error when the private key does not match the certificate", func() {
		_, certPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		mismatchKeyPEM, _, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		err = ca.ImportCA(context.Background(), store, certPEM, mismatchKeyPEM, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not match"))
	})

	It("returns an error when the provided CRL is invalid PEM", func() {
		keyPEM, certPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		err = ca.ImportCA(context.Background(), store, certPEM, keyPEM, []byte("not valid PEM"))
		Expect(err).To(HaveOccurred())
	})

	It("does not overwrite existing serial and inventory files", func() {
		keyPEM, certPEM, crlPEM, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "DEADBEEF")).To(Succeed())
		Expect(store.Backend().Put(context.Background(), storage.KeyInventory, []byte("existing line\n"), storage.BlobPrivate)).To(Succeed())

		Expect(ca.ImportCA(context.Background(), store, certPEM, keyPEM, crlPEM)).To(Succeed())

		serialData, err := store.GetSerial(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(serialData)).To(Equal("DEADBEEF"))
		invData, err := store.ReadInventory(context.Background())
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

		Expect(ca.ImportCA(context.Background(), store, certPEM, pkcs8PEM, nil)).To(Succeed())
		Expect(store.HasCACert(context.Background())).To(BeTrue())
		Expect(store.HasCAKey(context.Background())).To(BeTrue())
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
		tmpDir, err = os.MkdirTemp("", "openvox-ca-concurrent-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "true"}, "puppet.test")

		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
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

		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				csrPEM, err := testutil.GenerateCSR(subject)
				Expect(err).NotTo(HaveOccurred())

				signed, err := myCA.SaveRequest(context.Background(), subject, csrPEM)
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
		Expect(store.HasCert(context.Background(), subject)).To(BeTrue())

		// No pending CSR should remain (autosign deletes it after signing).
		Expect(store.HasCSR(context.Background(), subject)).To(BeFalse())
	})
})
