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
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("ImportCA", func() {
	var tmpDir string

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-import-test")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("writes cert, key, and CRL files and initialises serial and inventory", func() {
		store := storage.New(tmpDir)
		Expect(ca.ImportCA(context.Background(), store, cachedCrtPEM, cachedKeyPEM, cachedCrlPEM)).To(Succeed())

		// All expected blobs must exist.
		Expect(store.HasCACert(context.Background())).To(BeTrue())
		Expect(store.HasCAKey(context.Background())).To(BeTrue())
		crl, err := store.GetCRL(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(crl).NotTo(BeEmpty())
		Expect(store.HasInventory(context.Background())).To(BeTrue())
		Expect(store.HasSerial(context.Background())).To(BeTrue())

		// Contents must round-trip correctly.
		certData, err := store.GetCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(certData).To(Equal(cachedCrtPEM))
		keyData, err := store.GetCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(keyData).To(Equal(cachedKeyPEM))
	})

	It("generates a fresh CRL when crlPEM is nil", func() {
		store := storage.New(tmpDir)
		Expect(ca.ImportCA(context.Background(), store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())

		crlData, err := store.GetCRL(context.Background())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(crlData)
		Expect(block).NotTo(BeNil())
		_, err = x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	It("does not overwrite an existing serial file", func() {
		store := storage.New(tmpDir)
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "00FF")).To(Succeed())

		Expect(ca.ImportCA(context.Background(), store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())

		serialData, err := store.GetSerial(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(string(serialData)).To(Equal("00FF"))
	})

	It("rejects a cert/key mismatch", func() {
		// Generate a second CA; the cert from it will not match cachedKeyPEM.
		altKeyPEM, altCertPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		_ = altKeyPEM

		store := storage.New(tmpDir)
		// Pass the alt CA cert but the original key; they don't match.
		err = ca.ImportCA(context.Background(), store, altCertPEM, cachedKeyPEM, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not match"))
	})

	It("rejects a non-CA certificate", func() {
		// Import the cached CA first so we can generate a leaf cert from it.
		store := storage.New(tmpDir)
		Expect(ca.ImportCA(context.Background(), store, cachedCrtPEM, cachedKeyPEM, nil)).To(Succeed())

		// Bootstrap a CA from the imported files and generate a leaf cert.
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(context.Background())).To(Succeed())
		leafResult, err := myCA.Generate(context.Background(), "leaf-for-import-test", nil)
		Expect(err).NotTo(HaveOccurred())

		// Now try to import the leaf cert as a CA cert.
		store2 := storage.New(tmpDir + "-v2")
		err = ca.ImportCA(context.Background(), store2, leafResult.CertificatePEM, leafResult.PrivateKeyPEM, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("IsCA"))
	})
})

// The bundle rule and the CRL-chain loop are the two user-visible behaviour
// changes ImportCA gained, and both are reached only through this entry point.
// Testing the validators in isolation leaves the calls to them unpinned.
var _ = Describe("ImportCA: what a bundle and a CRL chain must look like", func() {
	var (
		ctx   context.Context
		store *storage.StorageService
		chain *testutil.TestChain
	)

	BeforeEach(func() {
		var err error
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		chain, err = testutil.GenerateTestChain("node.example.com")
		Expect(err).NotTo(HaveOccurred())
	})

	// crlFor issues a CRL under the intermediate, so it is one the imported CA
	// could plausibly have produced.
	crlFor := func(number int64) []byte {
		GinkgoHelper()
		inter := parseFirstCert(chain.InterPEM)
		keyBlock, _ := pem.Decode(chain.InterKeyPEM)
		Expect(keyBlock).NotTo(BeNil())
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		signer, ok := key.(crypto.Signer)
		Expect(ok).To(BeTrue())

		now := time.Now().UTC()
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(number),
			ThisUpdate: now,
			NextUpdate: now.Add(24 * time.Hour),
		}, inter, signer)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}

	It("accepts a complete chain and stores both certificates, root last", func() {
		Expect(ca.ImportCA(ctx, store, chain.Bundle, chain.InterKeyPEM, nil)).To(Succeed())

		stored, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		certs, err := ca.ParseCABundle(stored)
		Expect(err).NotTo(HaveOccurred())
		Expect(certs).To(HaveLen(2))
		Expect(certs[0].Subject.CommonName).To(Equal("Test Intermediate CA"))
		Expect(certs[1].Subject.CommonName).To(Equal("Test Root CA"))
	})

	It("refuses an intermediate with no root after it", func() {
		// The migration case: a Puppet Server that ran under an external root
		// may hold only its own certificate in ca_crt.pem. That used to import
		// and produce a CA whose chain agents could not complete.
		err := ca.ImportCA(ctx, store, chain.InterPEM, chain.InterKeyPEM, nil)
		Expect(err).To(MatchError(ContainSubstring("not self-signed")))
	})

	It("refuses a bundle carrying a private key alongside the certificates", func() {
		withKey := append(append([]byte{}, chain.Bundle...), chain.InterKeyPEM...)
		err := ca.ImportCA(ctx, store, withKey, chain.InterKeyPEM, nil)
		Expect(err).To(MatchError(ContainSubstring("PRIVATE KEY")))
	})

	It("accepts several CRLs and stores them all", func() {
		twoCRLs := append(crlFor(1), crlFor(2)...)
		Expect(ca.ImportCA(ctx, store, chain.Bundle, chain.InterKeyPEM, twoCRLs)).To(Succeed())

		stored, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(countPEMBlocks(stored, "X509 CRL")).To(Equal(2))
	})

	It("reports which CRL in the chain failed to parse, not merely that one did", func() {
		// The point of validating past the first block: a bad block further
		// down would otherwise surface as a broken CRL on every agent rather
		// than as an import error here.
		bad := []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n")
		err := ca.ImportCA(ctx, store, chain.Bundle, chain.InterKeyPEM, append(crlFor(1), bad...))
		Expect(err).To(MatchError(ContainSubstring("CRL 2")))
	})

	It("refuses a CRL file that contains no CRL at all", func() {
		err := ca.ImportCA(ctx, store, chain.Bundle, chain.InterKeyPEM, chain.RootPEM)
		Expect(err).To(MatchError(ContainSubstring("supply only CRLs")))
	})

	// SECURITY: the stored CRL blob is world-readable and is served to every
	// agent on a route that requires no client certificate. A file assembled by
	// the obvious `cat key.pem crl.pem` mistake must not publish the key.
	It("refuses a CRL file with a private key concatenated into it", func() {
		withKey := append(append([]byte{}, chain.InterKeyPEM...), crlFor(1)...)
		err := ca.ImportCA(ctx, store, chain.Bundle, chain.InterKeyPEM, withKey)
		Expect(err).To(MatchError(ContainSubstring("served to every agent")))

		_, err = store.GetCRL(ctx)
		Expect(err).To(HaveOccurred(), "nothing may be published from a file we refused")
	})

	It("stores only what it validated, never the operator's file verbatim", func() {
		// Trailing commentary around the PEM blocks is common in files people
		// assemble by hand; it must not reach the blob agents fetch.
		noisy := append([]byte("# our upstream CRL, refreshed 2026-07-01\n"), crlFor(1)...)
		noisy = append(noisy, []byte("\n# end\n")...)
		Expect(ca.ImportCA(ctx, store, chain.Bundle, chain.InterKeyPEM, noisy)).To(Succeed())

		stored, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(stored)).NotTo(ContainSubstring("#"))
		Expect(countPEMBlocks(stored, "X509 CRL")).To(Equal(1))
	})
})

// parseFirstCert returns the first certificate in a PEM blob.
func parseFirstCert(blob []byte) *x509.Certificate {
	GinkgoHelper()
	block, _ := pem.Decode(blob)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// countPEMBlocks counts blocks of the given type in a PEM blob.
func countPEMBlocks(blob []byte, blockType string) int {
	n := 0
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return n
		}
		if block.Type == blockType {
			n++
		}
	}
}

var _ = Describe("ImportCAMaterial: failures after the certificate is written", func() {
	// Both annotations were previously asserted only against errors the tests
	// built themselves, which proves the annotator's predicate but not that any
	// real failure ever carries the sentinel. If the production path stopped
	// wrapping, the read-only-Secret guidance and the inconsistent-storage
	// warning would silently never appear.
	var (
		ctx   context.Context
		dir   string
		store *storage.StorageService
		chain *testutil.TestChain
		key   crypto.Signer
	)

	BeforeEach(func() {
		var err error
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		store = storage.New(dir)
		chain, err = testutil.GenerateTestChain("node.example.com")
		Expect(err).NotTo(HaveOccurred())

		keyBlock, _ := pem.Decode(chain.InterKeyPEM)
		Expect(keyBlock).NotTo(BeNil())
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		var ok bool
		key, ok = parsed.(crypto.Signer)
		Expect(ok).To(BeTrue())
	})

	It("wraps a real CA certificate write failure with ErrCACertWrite", func() {
		// A directory where the certificate blob belongs: the write fails for a
		// reason the storage layer surfaces, without any stubbing.
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(os.RemoveAll(filepath.Join(dir, "ca_crt.pem"))).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dir, "ca_crt.pem"), 0o755)).To(Succeed())

		err := ca.ImportCAMaterial(ctx, store, chain.Bundle, chain.InterKeyPEM, nil, key, ca.CRLValidity)
		Expect(err).To(MatchError(ca.ErrCACertWrite),
			"the sentinel is what annotateOverlayWriteError discriminates on")
	})

	It("tells the operator storage is inconsistent when a write after the certificate fails", func() {
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(os.RemoveAll(filepath.Join(dir, "ca_pub.pem"))).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dir, "ca_pub.pem"), 0o755)).To(Succeed())

		err := ca.ImportCAMaterial(ctx, store, chain.Bundle, chain.InterKeyPEM, nil, key, ca.CRLValidity)
		Expect(err).To(MatchError(ContainSubstring("storage is now inconsistent")))
		// ImportCA's caller has no --force, so it must not be told to use one.
		Expect(err).To(MatchError(ContainSubstring("re-run this command to finish the import")))
		Expect(err).NotTo(MatchError(ContainSubstring("--force")))
	})
})

var _ = Describe("ImportCACertificate: the --force retry hint", func() {
	// The two hints must be mutually distinguishing. Asserting only the plain
	// one leaves the split pointless: passing retryPlain at the --force call
	// site would keep every spec green while telling that operator to "re-run
	// this command", which ImportCACertificate's own ErrCACertExists check then
	// refuses, because the certificate has already been written.
	It("tells an import-ca-cert operator to use --force, not a bare re-run", func() {
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		store := storage.New(dir)
		chain, err := testutil.GenerateTestChain("node.example.com")
		Expect(err).NotTo(HaveOccurred())

		keyBlock, _ := pem.Decode(chain.InterKeyPEM)
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		signer, ok := parsed.(crypto.Signer)
		Expect(ok).To(BeTrue())

		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(os.RemoveAll(filepath.Join(dir, "ca_pub.pem"))).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dir, "ca_pub.pem"), 0o755)).To(Succeed())

		_, err = ca.ImportCACertificate(ctx, store, chain.Bundle, signer, ca.CRLValidity, false)
		Expect(err).To(MatchError(ContainSubstring("storage is now inconsistent")))
		Expect(err).To(MatchError(ContainSubstring("with --force to finish the import")))
	})
})
