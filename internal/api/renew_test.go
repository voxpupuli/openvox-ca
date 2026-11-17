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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("POST /renew/{subject}", func() {
	var (
		ctx   = context.Background()
		myCA  *ca.CA
		store *storage.StorageService
		mux   http.Handler
	)

	parseCert := func(certPEM []byte) *x509.Certificate {
		GinkgoHelper()
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil(), "expected a PEM certificate, got %q", certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	// issue puts subject through the ordinary request-and-sign flow.
	issue := func(subject string) *x509.Certificate {
		GinkgoHelper()
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCert(certPEM)
	}

	// mint stores a certificate for subject signed directly with the CA key
	// (or self-signed when foreign), over an RSA key of the given size, so a
	// spec can place what no issuance path produces.
	mint := func(subject string, bits int, foreign bool, notAfter time.Time, extra ...pkix.Extension) *x509.Certificate {
		GinkgoHelper()
		key, err := rsa.GenerateKey(rand.Reader, bits)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber:    big.NewInt(time.Now().UnixNano()),
			Subject:         pkix.Name{CommonName: subject},
			NotBefore:       notAfter.Add(-2 * time.Hour),
			NotAfter:        notAfter,
			ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			ExtraExtensions: extra,
		}
		parent, signer := tmpl, any(key)
		if !foreign {
			parent = parseCert(cachedCrtPEM)
			block, _ := pem.Decode(cachedKeyPEM)
			caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			signer = caKey
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCert(ctx, subject, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))).To(Succeed())
		cert, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	ppCliAuth := func() pkix.Extension {
		GinkgoHelper()
		value, err := asn1.MarshalWithParams("true", "utf8")
		Expect(err).NotTo(HaveOccurred())
		return pkix.Extension{Id: ca.OIDPpCliAuth, Value: value}
	}

	post := func(path string, body []byte) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("POST", path, bytes.NewReader(body)))
		return rr
	}

	storedSerial := func(subject string) *big.Int {
		GinkgoHelper()
		data, err := store.GetCert(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCert(data).SerialNumber
	}

	BeforeEach(func() {
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())
		mux = api.New(myCA).Routes()
	})

	It("reissues over the stored key when the body is empty", func() {
		original := issue("keep-node")

		rr := post("/puppet-ca/v1/renew/keep-node", nil)
		Expect(rr.Code).To(Equal(http.StatusOK), rr.Body.String())
		Expect(rr.Header().Get("Content-Type")).To(Equal("text/plain"))
		renewed := parseCert(rr.Body.Bytes())
		Expect(renewed.PublicKey).To(Equal(original.PublicKey))
		Expect(renewed.SerialNumber).NotTo(Equal(original.SerialNumber))
		Expect(storedSerial("keep-node")).To(Equal(renewed.SerialNumber))
	})

	It("re-keys onto the CSR in the body", func() {
		original := issue("rekey-node")
		csrPEM, err := testutil.GenerateCSR("rekey-node")
		Expect(err).NotTo(HaveOccurred())

		rr := post("/renew/rekey-node", csrPEM)
		Expect(rr.Code).To(Equal(http.StatusOK), rr.Body.String())
		renewed := parseCert(rr.Body.Bytes())
		Expect(renewed.PublicKey).NotTo(Equal(original.PublicKey))
		Expect(storedSerial("rekey-node")).To(Equal(renewed.SerialNumber))
	})

	It("treats a body of whitespace as no CSR, and reissues over the stored key", func() {
		original := issue("blank-node")

		rr := post("/renew/blank-node", []byte(" \n\t\n"))
		Expect(rr.Code).To(Equal(http.StatusOK), rr.Body.String())
		Expect(parseCert(rr.Body.Bytes()).PublicKey).To(Equal(original.PublicKey))
	})

	It("answers 503 while the CA has not finished initialising", func() {
		// Deliberately no Init: a certificate is stored, so the request gets
		// past the lookup to the provenance check, which needs the CA
		// certificate Init loads.
		uninit := storage.New(GinkgoT().TempDir())
		Expect(uninit.EnsureDirs(ctx)).To(Succeed())
		Expect(uninit.SaveCert(ctx, "early-node", cachedCrtPEM)).To(Succeed())
		early := api.New(ca.New(uninit, ca.AutosignConfig{Mode: "off"}, "puppet.test")).Routes()

		rr := httptest.NewRecorder()
		early.ServeHTTP(rr, httptest.NewRequest("POST", "/renew/early-node", nil))
		Expect(rr.Code).To(Equal(http.StatusServiceUnavailable), rr.Body.String())
		Expect(rr.Body.String()).To(ContainSubstring("CA not ready"))
	})

	It("reissues a pp_cli_auth certificate over its own key", func() {
		mint("admin-keep", 2048, false, time.Now().Add(time.Hour), ppCliAuth())

		rr := post("/renew/admin-keep", nil)
		Expect(rr.Code).To(Equal(http.StatusOK), rr.Body.String())
		Expect(parseCert(rr.Body.Bytes()).Extensions).To(ContainElement(HaveField("Id", ca.OIDPpCliAuth)))
	})

	// Every refusal leaves the stored certificate where it was, so each entry
	// returns the subject to check, or "" where nothing is stored.
	DescribeTable("refusals",
		func(setup func() (path string, body []byte, subject string), status int, bodyText string) {
			path, body, subject := setup()
			var before *big.Int
			if subject != "" {
				before = storedSerial(subject)
			}

			rr := post(path, body)
			Expect(rr.Code).To(Equal(status), rr.Body.String())
			Expect(rr.Body.String()).To(ContainSubstring(bodyText))
			if subject != "" {
				Expect(storedSerial(subject)).To(Equal(before), "a refused renewal must issue nothing")
			}
		},
		Entry("an invalid subject", func() (string, []byte, string) {
			return "/renew/bad..subject", nil, ""
		}, http.StatusBadRequest, "invalid subject"),
		Entry("a subject with no certificate", func() (string, []byte, string) {
			return "/renew/nobody", nil, ""
		}, http.StatusNotFound, "no certificate is stored"),
		Entry("a CSR for another name", func() (string, []byte, string) {
			issue("csr-owner")
			csrPEM, err := testutil.GenerateCSR("someone-else")
			Expect(err).NotTo(HaveOccurred())
			return "/renew/csr-owner", csrPEM, "csr-owner"
		}, http.StatusBadRequest, `"someone-else"`),
		Entry("a body that is not a CSR", func() (string, []byte, string) {
			issue("csr-garbage")
			return "/renew/csr-garbage", []byte("not a csr"), "csr-garbage"
		}, http.StatusBadRequest, "invalid renewal CSR"),
		Entry("a managed subject", func() (string, []byte, string) {
			issue("managed-node")
			myCA.ManagedCerts = []ca.ManagedCert{{Spec: ca.CertSpec{Subject: "managed-node"}}}
			return "/renew/managed-node", nil, "managed-node"
		}, http.StatusConflict, "managed by this CA"),
		Entry("a revoked certificate", func() (string, []byte, string) {
			issue("revoked-node")
			Expect(myCA.Revoke(ctx, "revoked-node")).To(Succeed())
			return "/renew/revoked-node", nil, "revoked-node"
		}, http.StatusConflict, "certificate is revoked"),
		Entry("a re-key of a pp_cli_auth certificate", func() (string, []byte, string) {
			mint("admin-rekey", 2048, false, time.Now().Add(time.Hour), ppCliAuth())
			csrPEM, err := testutil.GenerateCSR("admin-rekey")
			Expect(err).NotTo(HaveOccurred())
			return "/renew/admin-rekey", csrPEM, "admin-rekey"
		}, http.StatusConflict, "authorisation extensions"),
		Entry("an expired certificate", func() (string, []byte, string) {
			mint("expired-node", 2048, false, time.Now().Add(-time.Hour))
			return "/renew/expired-node", nil, "expired-node"
		}, http.StatusConflict, "certificate has expired"),
		Entry("a certificate already superseded", func() (string, []byte, string) {
			original := issue("superseded-node")
			data, err := json.Marshal([]map[string]any{{
				"serial": fmt.Sprintf("%X", original.SerialNumber), "subject": "superseded-node",
				"revoke_at": time.Now().Add(time.Hour),
			}})
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveSuperseded(ctx, data)).To(Succeed())
			return "/renew/superseded-node", nil, "superseded-node"
		}, http.StatusConflict, "already been superseded"),
		Entry("a certificate this CA did not sign", func() (string, []byte, string) {
			mint("foreign-node", 2048, true, time.Now().Add(time.Hour))
			return "/renew/foreign-node", nil, "foreign-node"
		}, http.StatusConflict, "not issued by this CA"),
		Entry("a stored key below policy", func() (string, []byte, string) {
			mint("weak-node", 1024, false, time.Now().Add(time.Hour))
			return "/renew/weak-node", nil, "weak-node"
		}, http.StatusUnprocessableEntity, "key does not meet policy"),
	)
})
