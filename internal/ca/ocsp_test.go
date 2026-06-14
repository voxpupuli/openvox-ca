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
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// setupOCSPCA creates and initialises a CA backed by dir, pre-seeded with the
// suite-level key/cert/CRL.
func setupOCSPCA(dir string) *ca.CA {
	store := storage.New(dir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
	Expect(store.EnsureDirs(context.Background())).To(Succeed())
	Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
	Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
	Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
	Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
	Expect(store.TouchInventory(context.Background())).To(Succeed())
	Expect(myCA.Init(context.Background())).To(Succeed())
	return myCA
}

// decodeCert decodes a PEM certificate. Fails the test if the input is invalid.
func decodeCert(certPEM []byte) *x509.Certificate {
	block, _ := pem.Decode(certPEM)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

var _ = Describe("OCSP Responder", func() {
	var (
		tmpDir string
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-ocsp-test")
		Expect(err).NotTo(HaveOccurred())
		myCA = setupOCSPCA(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	// --- Status correctness ---

	It("returns Good for a known, non-revoked cert", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-good-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-good-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-good-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		reqDER, err := testutil.BuildOCSPRequest(cert, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())

		resp, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))
		Expect(resp.SerialNumber.Cmp(cert.SerialNumber)).To(Equal(0))
	})

	It("returns Revoked (with correct RevokedAt) after Revoke()", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-revoke-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-revoke-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-revoke-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(myCA.Revoke(context.Background(), "ocsp-revoke-node")).To(Succeed())

		cert := decodeCert(certPEM)
		reqDER, err := testutil.BuildOCSPRequest(cert, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())

		resp, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Revoked))
		Expect(resp.RevokedAt.IsZero()).To(BeFalse())
	})

	It("returns Unknown for a serial never issued by this CA", func() {
		// Use a fresh ephemeral CA cert as the "unknown" cert to query about.
		_, ephCertPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		ephCert := decodeCert(ephCertPEM)

		reqDER, err := testutil.BuildOCSPRequest(ephCert, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())

		resp, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Unknown))
	})

	// --- Caching ---

	It("serves the cached response on a second call (same serial, no nonce)", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-cache-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-cache-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-cache-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		reqDER, err := testutil.BuildOCSPRequest(cert, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		resp1, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())
		resp2, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())

		Expect(resp2).To(Equal(resp1), "second call should return the identical cached DER")
	})

	It("returns independent buffers from the cache so callers cannot corrupt cached state", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-cache-isolation-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-cache-isolation-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-cache-isolation-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		reqDER, err := testutil.BuildOCSPRequest(cert, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		// Prime the cache and snapshot the original bytes.
		first, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())
		original := append([]byte(nil), first...)

		// Mutate the returned slice. If it aliases the cache, the next
		// cached read will surface the corrupted bytes.
		for i := range first {
			first[i] ^= 0xFF
		}

		third, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())
		Expect(third).To(Equal(original), "cached OCSP DER must not be aliased with caller's slice")
	})

	It("generates a fresh response (bypasses cache) when a nonce is present", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-nonce-cache-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-nonce-cache-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-nonce-cache-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)

		nonce1 := make([]byte, 16)
		_, err = rand.Read(nonce1)
		Expect(err).NotTo(HaveOccurred())
		nonce2 := make([]byte, 16)
		_, err = rand.Read(nonce2)
		Expect(err).NotTo(HaveOccurred())

		req1, err := testutil.BuildOCSPRequestWithNonce(cert, myCA.CACert, nonce1)
		Expect(err).NotTo(HaveOccurred())
		req2, err := testutil.BuildOCSPRequestWithNonce(cert, myCA.CACert, nonce2)
		Expect(err).NotTo(HaveOccurred())

		resp1, err := myCA.OCSPResponse(context.Background(), req1)
		Expect(err).NotTo(HaveOccurred())
		resp2, err := myCA.OCSPResponse(context.Background(), req2)
		Expect(err).NotTo(HaveOccurred())

		// Different nonces produce different response bytes.
		Expect(resp1).NotTo(Equal(resp2))
	})

	It("deletes the cache entry on Revoke(); subsequent call returns Revoked", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-revoke-cache-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-revoke-cache-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-revoke-cache-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		reqDER, err := testutil.BuildOCSPRequest(cert, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		// Prime the cache.
		respDER1, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())
		resp1, _ := xocsp.ParseResponse(respDER1, myCA.CACert)
		Expect(resp1.Status).To(Equal(xocsp.Good))

		Expect(myCA.Revoke(context.Background(), "ocsp-revoke-cache-node")).To(Succeed())

		respDER2, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())
		resp2, err := xocsp.ParseResponse(respDER2, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp2.Status).To(Equal(xocsp.Revoked))
	})

	// --- Serial index ---

	It("buildSerialIndex populates the index from inventory on Init()", func() {
		// Sign a cert, then init a second CA instance backed by the same dir.
		csrPEM, err := testutil.GenerateCSR("ocsp-index-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-index-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-index-node")
		Expect(err).NotTo(HaveOccurred())

		// Re-open the same CA directory; Init() calls buildSerialIndex.
		store2 := storage.New(tmpDir)
		myCA2 := ca.New(store2, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA2.Init(context.Background())).To(Succeed())

		cert := decodeCert(certPEM)
		reqDER, err := testutil.BuildOCSPRequest(cert, myCA2.CACert)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA2.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())
		resp, err := xocsp.ParseResponse(respDER, myCA2.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))
	})

	It("serial index is updated incrementally by Sign", func() {
		// Signing without a prior Init() + inventory rebuild still works because
		// signWithDuration writes to c.serialIndex directly.
		csrPEM, err := testutil.GenerateCSR("ocsp-incr-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-incr-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-incr-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		reqDER, err := testutil.BuildOCSPRequest(cert, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())
		resp, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))
	})

	// --- Response verifiability ---

	It("produces a response verifiable by ocsp.ParseResponse with the CA cert", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-sig-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-sig-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-sig-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		reqDER, err := testutil.BuildOCSPRequest(cert, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())

		_, err = xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
	})

	It("echoes the nonce extension from the request into the response", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-nonce-echo-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-nonce-echo-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-nonce-echo-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		nonce := []byte("test-nonce-1234567")
		reqDER, err := testutil.BuildOCSPRequestWithNonce(cert, myCA.CACert, nonce)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())

		resp, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))

		oidNonce := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
		found := false
		for _, ext := range resp.Extensions {
			if ext.Id.Equal(oidNonce) {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(), "expected nonce extension in OCSP response singleExtensions")
	})

	// --- AIA extension in issued certs ---

	It("omits the AIA extension when OCSPURLs is nil", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-no-aia-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-no-aia-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-no-aia-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		Expect(cert.OCSPServer).To(BeEmpty())
	})

	It("embeds the OCSP URL in the AIA extension when OCSPURLs is set", func() {
		// Create a second CA instance in a fresh temp dir with OCSPURLs set.
		aiaDir, err := os.MkdirTemp("", "openvox-ca-aia-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(aiaDir)

		store2 := storage.New(aiaDir)
		myCA2 := ca.New(store2, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA2.OCSPURLs = []string{"http://ocsp.example.com/ocsp"}
		Expect(store2.EnsureDirs(context.Background())).To(Succeed())
		Expect(store2.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store2.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store2.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store2.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store2.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA2.Init(context.Background())).To(Succeed())

		csrPEM, err := testutil.GenerateCSR("ocsp-aia-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA2.SaveRequest(context.Background(), "ocsp-aia-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA2.Sign(context.Background(), "ocsp-aia-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)
		Expect(cert.OCSPServer).To(ConsistOf("http://ocsp.example.com/ocsp"))
	})

	// --- Nonce length validation ---

	It("ignores nonce exceeding RFC 8954 maximum length (32 bytes)", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-big-nonce-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-big-nonce-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-big-nonce-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)

		// Build an OCSP request with a 64-byte nonce (exceeds RFC 8954 limit).
		bigNonce := make([]byte, 64)
		for i := range bigNonce {
			bigNonce[i] = 0xAA
		}
		reqDER, err := testutil.BuildOCSPRequestWithNonce(cert, myCA.CACert, bigNonce)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())

		resp, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))

		// The oversized nonce must NOT be echoed in the response.
		oidNonce := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
		for _, ext := range resp.Extensions {
			Expect(ext.Id.Equal(oidNonce)).To(BeFalse(),
				"oversized nonce should not be echoed in OCSP response")
		}
	})

	It("echoes a nonce within the RFC 8954 limit", func() {
		csrPEM, err := testutil.GenerateCSR("ocsp-ok-nonce-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "ocsp-ok-nonce-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(context.Background(), "ocsp-ok-nonce-node")
		Expect(err).NotTo(HaveOccurred())

		cert := decodeCert(certPEM)

		// 32-byte nonce: maximum allowed by RFC 8954.
		okNonce := make([]byte, 32)
		for i := range okNonce {
			okNonce[i] = 0xBB
		}
		reqDER, err := testutil.BuildOCSPRequestWithNonce(cert, myCA.CACert, okNonce)
		Expect(err).NotTo(HaveOccurred())

		respDER, err := myCA.OCSPResponse(context.Background(), reqDER)
		Expect(err).NotTo(HaveOccurred())

		resp, err := xocsp.ParseResponse(respDER, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(xocsp.Good))

		// The 32-byte nonce should be echoed.
		oidNonce := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
		found := false
		for _, ext := range resp.Extensions {
			if ext.Id.Equal(oidNonce) {
				found = true
				break
			}
		}
		Expect(found).To(BeTrue(), "valid nonce should be echoed in OCSP response")
	})

	// --- Error handling ---

	It("returns an error for an unparseable OCSP request", func() {
		_, err := myCA.OCSPResponse(context.Background(), []byte("not valid DER"))
		Expect(err).To(HaveOccurred())
	})
})
