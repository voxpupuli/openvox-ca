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

package api_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// buildImportTestCSR returns a minimal, validly-signed CSR PEM for cn.
func buildImportTestCSR(cn string) []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

var _ = Describe("PUT /certificate/{subject} (import)", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		mux    http.Handler
		caKey  crypto.Signer
		caCert *x509.Certificate
	)

	signLeaf := func(signerKey crypto.Signer, signerCert *x509.Certificate, cn string, dnsNames []string, serial *big.Int, isCA bool) []byte {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		if serial == nil {
			serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			Expect(err).NotTo(HaveOccurred())
		}
		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			DNSNames:              dnsNames,
			BasicConstraintsValid: true,
			IsCA:                  isCA,
		}
		if isCA {
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}
		der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-import-api-test")
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

		server := api.New(myCA)
		mux = server.Routes()

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

	It("returns 200 with the import result on a valid certificate, and is idempotent on resubmission", func() {
		certPEM := signLeaf(caKey, caCert, "import-node", []string{"import-node"}, nil, false)

		req := httptest.NewRequest("PUT", "/certificate/import-node", bytes.NewReader(certPEM))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusOK))

		var result api.ImportResponse
		Expect(json.Unmarshal(rr.Body.Bytes(), &result)).To(Succeed())
		Expect(result.Subject).To(Equal("import-node"))
		Expect(result.Imported).To(BeTrue())
		Expect(result.Serial).NotTo(BeEmpty())
		Expect(result.NotBefore).NotTo(BeEmpty())
		Expect(result.NotAfter).NotTo(BeEmpty())
		_, err := time.Parse(time.RFC3339, result.NotBefore)
		Expect(err).NotTo(HaveOccurred(), "not_before must parse as RFC3339")
		_, err = time.Parse(time.RFC3339, result.NotAfter)
		Expect(err).NotTo(HaveOccurred(), "not_after must parse as RFC3339")

		// Resubmitting the identical certificate must be a no-op, not an error.
		req2 := httptest.NewRequest("PUT", "/certificate/import-node", bytes.NewReader(certPEM))
		rr2 := httptest.NewRecorder()
		mux.ServeHTTP(rr2, req2)
		Expect(rr2.Code).To(Equal(http.StatusOK))

		var result2 api.ImportResponse
		Expect(json.Unmarshal(rr2.Body.Bytes(), &result2)).To(Succeed())
		Expect(result2.Imported).To(BeFalse())
		Expect(result2.Serial).To(Equal(result.Serial))
	})

	It("returns 400 when the certificate CN/SANs do not match the URL subject", func() {
		certPEM := signLeaf(caKey, caCert, "actual-cn", []string{"actual-cn"}, nil, false)

		req := httptest.NewRequest("PUT", "/certificate/unrelated-subject", bytes.NewReader(certPEM))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusBadRequest))
	})

	It("returns 400 for a malformed PEM body", func() {
		req := httptest.NewRequest("PUT", "/certificate/malformed-node", bytes.NewReader([]byte("not a pem file")))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusBadRequest))
	})

	It("returns 400 for a certificate that does not chain to this CA", func() {
		altKeyPEM, altCertPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		altKeyBlock, _ := pem.Decode(altKeyPEM)
		altKey, err := x509.ParsePKCS1PrivateKey(altKeyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		altCertBlock, _ := pem.Decode(altCertPEM)
		altCert, err := x509.ParseCertificate(altCertBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		foreignCert := signLeaf(altKey, altCert, "foreign-node", []string{"foreign-node"}, nil, false)

		req := httptest.NewRequest("PUT", "/certificate/foreign-node", bytes.NewReader(foreignCert))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusBadRequest))
	})

	It("returns 409 when the serial is already tracked under a different subject", func() {
		serial := big.NewInt(0xABCDEF)
		certA := signLeaf(caKey, caCert, "serial-a", []string{"serial-a"}, serial, false)
		reqA := httptest.NewRequest("PUT", "/certificate/serial-a", bytes.NewReader(certA))
		rrA := httptest.NewRecorder()
		mux.ServeHTTP(rrA, reqA)
		Expect(rrA.Code).To(Equal(http.StatusOK))

		certB := signLeaf(caKey, caCert, "serial-b", []string{"serial-b"}, serial, false)
		reqB := httptest.NewRequest("PUT", "/certificate/serial-b", bytes.NewReader(certB))
		rrB := httptest.NewRecorder()
		mux.ServeHTTP(rrB, reqB)
		Expect(rrB.Code).To(Equal(http.StatusConflict))
	})

	It("returns 409 when the subject already has an active certificate", func() {
		csrPEM := buildImportTestCSR("active-node")
		_, err := myCA.SaveRequest(context.Background(), "active-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(context.Background(), "active-node")
		Expect(err).NotTo(HaveOccurred())

		importCert := signLeaf(caKey, caCert, "active-node", []string{"active-node"}, nil, false)
		req := httptest.NewRequest("PUT", "/certificate/active-node", bytes.NewReader(importCert))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusConflict))
	})

	It("makes the imported certificate visible via status and revocable via the normal mechanism", func() {
		certPEM := signLeaf(caKey, caCert, "e2e-node", []string{"e2e-node"}, nil, false)

		req := httptest.NewRequest("PUT", "/certificate/e2e-node", bytes.NewReader(certPEM))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusOK))

		statusReq := httptest.NewRequest("GET", "/certificate_status/e2e-node", nil)
		statusRR := httptest.NewRecorder()
		mux.ServeHTTP(statusRR, statusReq)
		Expect(statusRR.Code).To(Equal(http.StatusOK))
		var status api.CertStatusResponse
		Expect(json.Unmarshal(statusRR.Body.Bytes(), &status)).To(Succeed())
		Expect(status.State).To(Equal("signed"))

		revokeBody, _ := json.Marshal(api.PutStatusBody{DesiredState: "revoked"})
		revokeReq := httptest.NewRequest("PUT", "/certificate_status/e2e-node", bytes.NewReader(revokeBody))
		revokeRR := httptest.NewRecorder()
		mux.ServeHTTP(revokeRR, revokeReq)
		Expect(revokeRR.Code).To(Equal(http.StatusNoContent))

		statusReq2 := httptest.NewRequest("GET", "/certificate_status/e2e-node", nil)
		statusRR2 := httptest.NewRecorder()
		mux.ServeHTTP(statusRR2, statusReq2)
		var status2 api.CertStatusResponse
		Expect(json.Unmarshal(statusRR2.Body.Bytes(), &status2)).To(Succeed())
		Expect(status2.State).To(Equal("revoked"))
	})

	It("returns 503 when the CA has not been initialised", func() {
		rawDir, err := os.MkdirTemp("", "openvox-ca-import-uninit-api-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(rawDir)
		rawStore := storage.New(rawDir)
		Expect(rawStore.EnsureDirs(context.Background())).To(Succeed())
		// Deliberately no myCA.Init(): CACert/CAKey stay nil, so ImportCertificate
		// returns ca.ErrNotInitialized, which the handler maps to 503.
		rawCA := ca.New(rawStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		rawMux := api.New(rawCA).Routes()

		certPEM := signLeaf(caKey, caCert, "uninit-node", []string{"uninit-node"}, nil, false)
		req := httptest.NewRequest("PUT", "/certificate/uninit-node", bytes.NewReader(certPEM))
		rr := httptest.NewRecorder()
		rawMux.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))
	})
})
