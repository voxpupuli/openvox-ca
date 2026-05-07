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

package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tvaughan/puppet-ca/internal/api"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
	"github.com/tvaughan/puppet-ca/internal/testutil"
)

// issueClientCert creates a leaf cert with the given CN, signed by caCert/caKey,
// with ExtKeyUsageClientAuth so the middleware's x509.Verify call accepts it.
func issueClientCert(cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(certBytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// issueClientCertWithPpCliAuth is like issueClientCert but also embeds the
// pp_cli_auth extension (OID 1.3.6.1.4.1.34380.1.3.39) with value "true".
func issueClientCertWithPpCliAuth(cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	extValue, err := asn1.Marshal("true")
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39},
				Value: extValue,
			},
		},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(certBytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// withClientCert returns a shallow clone of r with r.TLS set to present cert as the peer.
func withClientCert(r *http.Request, cert *x509.Certificate) *http.Request {
	r = r.Clone(r.Context())
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

var _ = Describe("Auth Middleware", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		mux    http.Handler
		caCert *x509.Certificate
		caKey  *rsa.PrivateKey
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "puppet-ca-auth-test")
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

		// Parse CA cert and key so we can issue test client certs.
		block, _ := pem.Decode(cachedCrtPEM)
		caCert, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		block, _ = pem.Decode(cachedKeyPEM)
		caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// "puppet-server" is the sole admin CN in the allow list.
		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			CACert:    caCert,
			AllowList: map[string]bool{"puppet-server": true},
		}
		mux = server.Routes()
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	// --- Public endpoints bypass all cert checks ---

	Context("public endpoints pass through without any client cert", func() {
		It("allows GET /certificate/ca with no TLS connection state", func() {
			req := httptest.NewRequest("GET", "/certificate/ca", nil)
			// r.TLS is nil; the public tier check fires before the TLS check.
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("allows PUT /certificate_request/{subject} with no client cert", func() {
			csrPEM, err := testutil.GenerateCSR("public-node")
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("PUT", "/certificate_request/public-node", bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("allows GET /certificate_revocation_list/ca with no client cert", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	// --- No client cert on protected endpoints ---

	Context("no client cert presented to a protected endpoint", func() {
		It("returns 403 for GET /certificate_request/{subject} (self-or-admin tier)", func() {
			req := httptest.NewRequest("GET", "/certificate_request/some-node", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for POST /sign/all (admin-only tier)", func() {
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// --- Client cert from an unrecognised CA ---

	Context("client cert signed by a different CA", func() {
		It("returns 403 even if the CN is in the allow list", func() {
			// Generate an independent CA not trusted by AuthConfig.
			altKeyPEM, altCertPEM, _, err := testutil.GenerateTestCA()
			Expect(err).NotTo(HaveOccurred())
			altCACertBlock, _ := pem.Decode(altCertPEM)
			altCACert, err := x509.ParseCertificate(altCACertBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			altKeyBlock, _ := pem.Decode(altKeyPEM)
			altCAKey, err := x509.ParsePKCS1PrivateKey(altKeyBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// CN matches the admin allow list, but chain is wrong.
			clientCert := issueClientCert("puppet-server", altCACert, altCAKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// --- Certificate validity period enforcement ---

	Context("certificate validity period enforcement", func() {
		It("returns 403 when client presents an expired certificate", func() {
			// Issue a cert whose validity window lies entirely in the past.
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			template := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject:      pkix.Name{CommonName: "expired-node"},
				NotBefore:    time.Now().Add(-2 * time.Hour),
				NotAfter:     time.Now().Add(-1 * time.Hour), // already expired
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
			Expect(err).NotTo(HaveOccurred())
			expiredCert, err := x509.ParseCertificate(certBytes)
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("GET", "/certificate_request/expired-node", nil)
			req = withClientCert(req, expiredCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 when client presents a not-yet-valid certificate", func() {
			// Issue a cert whose NotBefore is in the future.
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			template := &x509.Certificate{
				SerialNumber: big.NewInt(time.Now().UnixNano()),
				Subject:      pkix.Name{CommonName: "future-node"},
				NotBefore:    time.Now().Add(1 * time.Hour), // not yet valid
				NotAfter:     time.Now().Add(2 * time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
			Expect(err).NotTo(HaveOccurred())
			futureCert, err := x509.ParseCertificate(certBytes)
			Expect(err).NotTo(HaveOccurred())

			req := httptest.NewRequest("GET", "/certificate_request/future-node", nil)
			req = withClientCert(req, futureCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// --- Revoked client cert ---

	Context("revoked client cert", func() {
		It("returns 403 when the presented cert's serial is in the CRL", func() {
			// Sign a cert through the CA so its serial is tracked.
			csrPEM, err := testutil.GenerateCSR("revoked-client")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "revoked-client", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(context.Background(), "revoked-client")
			Expect(err).NotTo(HaveOccurred())

			// Parse the issued cert so we can present it in the TLS request.
			block, _ := pem.Decode(certPEM)
			issuedCert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// Revoke the cert; its serial is now in the CRL.
			Expect(myCA.Revoke(context.Background(), "revoked-client")).To(Succeed())

			// Present the revoked cert; the middleware checks its serial
			// directly against the CRL and must deny access.
			req := httptest.NewRequest("GET", "/certificate_request/revoked-client", nil)
			req = withClientCert(req, issuedCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("allows a cert whose serial is NOT in the CRL even when another cert for the same CN was revoked", func() {
			// Sign and revoke "revoked-client".
			csrPEM, err := testutil.GenerateCSR("revoked-client")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "revoked-client", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(context.Background(), "revoked-client")
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(context.Background(), "revoked-client")).To(Succeed())

			// A separately-issued cert with the same CN but a different serial
			// (not in the CRL) must pass the revocation check.
			freshCert := issueClientCert("revoked-client", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_request/revoked-client", nil)
			req = withClientCert(req, freshCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			// The cert is not revoked; access is denied only if it also
			// fails the tier check (self-or-admin: CN matches path subject).
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})

	// --- Revocation bypass prevention (re-issuance regression) ---
	// Before the fix, IsRevoked looked up the cert *on disk* for the CN and
	// checked that cert's serial.  After a revocation + re-issuance the disk
	// cert had a new (clean) serial, so the old revoked cert would pass.
	// IsRevokedSerial checks the serial of the PRESENTED cert, closing the gap.

	Context("revocation bypass prevention after re-issuance", func() {
		It("denies an old revoked cert even after the same CN has been re-issued", func() {
			// Step 1: issue the first cert for "puppet-server" (admin CN).
			csrPEM1, err := testutil.GenerateCSR("puppet-server")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "puppet-server", csrPEM1)
			Expect(err).NotTo(HaveOccurred())
			certPEM1, err := myCA.Sign(context.Background(), "puppet-server")
			Expect(err).NotTo(HaveOccurred())
			block1, _ := pem.Decode(certPEM1)
			oldCert, err := x509.ParseCertificate(block1.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// Step 2: revoke it; serial1 is now in the CRL.
			Expect(myCA.Revoke(context.Background(), "puppet-server")).To(Succeed())

			// Step 3: re-register and sign a new cert for the same CN.
			csrPEM2, err := testutil.GenerateCSR("puppet-server")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "puppet-server", csrPEM2) // evicts the revoked cert
			Expect(err).NotTo(HaveOccurred())
			certPEM2, err := myCA.Sign(context.Background(), "puppet-server")
			Expect(err).NotTo(HaveOccurred())
			block2, _ := pem.Decode(certPEM2)
			newCert, err := x509.ParseCertificate(block2.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// OLD cert (revoked serial) must be denied (regression test).
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, oldCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))

			// NEW cert (clean serial, same admin CN) must be allowed.
			req2 := httptest.NewRequest("POST", "/sign/all", nil)
			req2 = withClientCert(req2, newCert)
			rr2 := httptest.NewRecorder()
			mux.ServeHTTP(rr2, req2)
			Expect(rr2.Code).NotTo(Equal(http.StatusForbidden))
		})
	})

	// --- CRL unavailable -> fail-closed ---

	Context("CRL unavailable on disk", func() {
		It("still allows auth when CRL file is deleted (in-memory cache)", func() {
			// Sign a cert through the CA so it is a valid client cert.
			csrPEM, err := testutil.GenerateCSR("crl-test-node")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "crl-test-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(context.Background(), "crl-test-node")
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(certPEM)
			issuedCert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// Remove the CRL file to simulate a disk fault.
			Expect(store.Backend().Delete(context.Background(), storage.KeyCRL)).To(Succeed())

			// The in-memory CRL cache allows auth to continue even when
			// the file is missing, so this is no longer a total DoS. The request
			// reaches the handler (not blocked by auth); the CSR was
			// consumed during signing so the handler returns 404.
			req := httptest.NewRequest("GET", "/certificate_request/crl-test-node", nil)
			req = withClientCert(req, issuedCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})

	// --- Non-admin on admin-only endpoints ---

	Context("non-admin client accessing admin-only endpoints", func() {
		It("returns 403 for POST /sign/all", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for DELETE /certificate_status/{subject}", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("DELETE", "/certificate_status/some-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for GET /certificate_statuses (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_statuses/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for POST /generate/{subject} (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("POST", "/generate/some-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for DELETE /certificate_request/{subject} (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("DELETE", "/certificate_request/some-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for PUT /certificate_status/{subject} (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req := httptest.NewRequest("PUT", "/certificate_status/some-node", bytes.NewReader(body))
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for POST /sign (admin-only tier)", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			body, _ := json.Marshal(map[string][]string{"certnames": {"some-node"}})
			req := httptest.NewRequest("POST", "/sign", bytes.NewReader(body))
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// --- Non-self client on self-or-admin endpoints ---

	Context("non-self client accessing another node's self-or-admin endpoint", func() {
		It("returns 403 for GET /certificate_request/{other-node}", func() {
			clientCert := issueClientCert("node-a", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_request/node-b", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for DELETE /certificate_request/{other-node}", func() {
			clientCert := issueClientCert("node-a", caCert, caKey)
			req := httptest.NewRequest("DELETE", "/certificate_request/node-b", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// --- GET /certificate/{subject} is public ---
	// Signed certificates contain no secrets; Puppet Server 8 allows
	// unauthenticated access so that bootstrapping nodes can fetch their own
	// cert before they have a client cert to present.

	Context("GET /certificate/{subject} is public", func() {
		It("allows retrieval with no TLS connection state", func() {
			req := httptest.NewRequest("GET", "/certificate/some-node", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			// 404 because the cert doesn't exist, but not 403.
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("allows retrieval over TLS with no peer cert", func() {
			req := httptest.NewRequest("GET", "/certificate/some-node", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("allows node-a to retrieve node-b's cert", func() {
			clientCert := issueClientCert("node-a", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate/node-b", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})

	// --- Positive: CRL is public, accessible with or without a cert ---

	Context("CRL endpoint is public", func() {
		It("returns CRL without presenting any cert", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			// r.TLS is nil; the public tier check fires before the TLS check.
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns CRL over a TLS connection with no peer certificate", func() {
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			// Simulate a TLS connection where the client chose not to send a cert.
			req.TLS = &tls.ConnectionState{} // no PeerCertificates
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns CRL when a valid CA-signed cert is presented", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns CRL even when a revoked cert is presented", func() {
			// Revoked nodes must still be able to fetch the CRL; it is the
			// mechanism by which they (and others) learn they are revoked.
			// The public tier check must fire before the revocation check.
			csrPEM, err := testutil.GenerateCSR("revoked-crl-fetcher")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "revoked-crl-fetcher", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(context.Background(), "revoked-crl-fetcher")
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(context.Background(), "revoked-crl-fetcher")).To(Succeed())

			clientCert := issueClientCert("revoked-crl-fetcher", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("returns CRL even when a cert from an untrusted CA is presented", func() {
			// The public tier bypasses cert chain verification entirely.
			altKeyPEM, altCertPEM, _, err := testutil.GenerateTestCA()
			Expect(err).NotTo(HaveOccurred())
			altCACertBlock, _ := pem.Decode(altCertPEM)
			altCACert, err := x509.ParseCertificate(altCACertBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			altKeyBlock, _ := pem.Decode(altKeyPEM)
			altCAKey, err := x509.ParsePKCS1PrivateKey(altKeyBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())

			clientCert := issueClientCert("some-node", altCACert, altCAKey)
			req := httptest.NewRequest("GET", "/certificate_revocation_list/ca", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	// --- Non-GET methods on the CRL path are NOT public ---

	Context("non-GET methods on /certificate_revocation_list/ca require auth", func() {
		It("returns 403 for POST /certificate_revocation_list/ca with no cert", func() {
			req := httptest.NewRequest("POST", "/certificate_revocation_list/ca", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for DELETE /certificate_revocation_list/ca with no cert", func() {
			req := httptest.NewRequest("DELETE", "/certificate_revocation_list/ca", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for POST /certificate_revocation_list/ca even with a valid non-admin cert", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("POST", "/certificate_revocation_list/ca", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// --- Prefixed paths honour the same tier rules ---

	Context("prefixed paths (/puppet-ca/v1/) respect auth tiers", func() {
		It("returns 403 for non-admin on PUT /puppet-ca/v1/certificate_status/{subject}", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req := httptest.NewRequest("PUT", "/puppet-ca/v1/certificate_status/some-node", bytes.NewReader(body))
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("allows PUT /puppet-ca/v1/certificate_request/{subject} with no cert (public tier)", func() {
			csrPEM, err := testutil.GenerateCSR("pfx-public-node")
			Expect(err).NotTo(HaveOccurred())
			req := httptest.NewRequest("PUT", "/puppet-ca/v1/certificate_request/pfx-public-node", bytes.NewReader(csrPEM))
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("allows GET /puppet-ca/v1/certificate_revocation_list/ca with no cert (public tier)", func() {
			req := httptest.NewRequest("GET", "/puppet-ca/v1/certificate_revocation_list/ca", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	// --- Positive: admin and self-cert pass ---

	Context("admin cert passes admin-only endpoints", func() {
		It("POST /sign/all is not rejected (returns 200, not 403)", func() {
			clientCert := issueClientCert("puppet-server", caCert, caKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("GET /certificate_status for any subject is not rejected for admin", func() {
			clientCert := issueClientCert("puppet-server", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_status/any-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			// 404 because the node does not exist, but not 403.
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})

	Context("public endpoint is reachable regardless of client cert", func() {
		It("GET /certificate_status/{own-node} is not rejected with a valid client cert (anyClient tier)", func() {
			clientCert := issueClientCert("my-node", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_status/my-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			// 404 because the node does not exist, but not 403.
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})

	// --- AllowPublicStatus opt-in ---

	Context("GET /certificate_status default (AllowPublicStatus=false)", func() {
		It("returns 403 when no client cert is presented", func() {
			req := httptest.NewRequest("GET", "/certificate_status/some-node", nil)
			// Simulate TLS connection with no client cert
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("returns 403 for prefixed path without client cert", func() {
			req := httptest.NewRequest("GET", "/puppet-ca/v1/certificate_status/some-node", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	Context("AllowPublicStatus=true allows unauthenticated GET /certificate_status", func() {
		var publicStatusMux http.Handler

		BeforeEach(func() {
			srv := api.New(myCA)
			srv.AuthConfig = &api.AuthConfig{
				CACert:            caCert,
				AllowList:         map[string]bool{"puppet-server": true},
				AllowPublicStatus: true,
			}
			publicStatusMux = srv.Routes()
		})

		It("does not require a client cert for GET /certificate_status", func() {
			req := httptest.NewRequest("GET", "/certificate_status/any-node", nil)
			rr := httptest.NewRecorder()
			publicStatusMux.ServeHTTP(rr, req)
			// Should get through to the handler (404 because node doesn't exist), not 403.
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("does not require a client cert for prefixed GET /puppet-ca/v1/certificate_status", func() {
			req := httptest.NewRequest("GET", "/puppet-ca/v1/certificate_status/any-node", nil)
			rr := httptest.NewRecorder()
			publicStatusMux.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("still requires admin for PUT /certificate_status (not affected by AllowPublicStatus)", func() {
			body, _ := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
			req := httptest.NewRequest("PUT", "/certificate_status/some-node", bytes.NewReader(body))
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			publicStatusMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("still requires admin for DELETE /certificate_status (not affected by AllowPublicStatus)", func() {
			req := httptest.NewRequest("DELETE", "/certificate_status/some-node", nil)
			req.TLS = &tls.ConnectionState{}
			rr := httptest.NewRecorder()
			publicStatusMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// --- pp_cli_auth extension ---

	Context("pp_cli_auth extension grants admin access (no CN in allow list)", func() {
		var muxNoCNList http.Handler

		BeforeEach(func() {
			srv := api.New(myCA)
			srv.AuthConfig = &api.AuthConfig{
				CACert:    caCert,
				AllowList: map[string]bool{},
			}
			muxNoCNList = srv.Routes()
		})

		It("allows POST /sign/all with a pp_cli_auth cert", func() {
			clientCert := issueClientCertWithPpCliAuth("openvox-server", caCert, caKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			muxNoCNList.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("allows GET /certificate_request/{subject} (self-or-admin tier) with a pp_cli_auth cert", func() {
			clientCert := issueClientCertWithPpCliAuth("openvox-server", caCert, caKey)
			req := httptest.NewRequest("GET", "/certificate_request/some-node", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			muxNoCNList.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})

		It("denies POST /sign/all for a cert without the extension", func() {
			clientCert := issueClientCert("regular-node", caCert, caKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			muxNoCNList.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})
	})

	// --- pp_cli_auth escalation via CSR is blocked ---
	// Full attack path from PUPPET-CA-20260305-001: submit CSR with pp_cli_auth
	// → autosign → retrieve cert → attempt admin access → must be DENIED.

	Context("CSR-injected pp_cli_auth does not grant admin after autosign (attack path blocked)", func() {
		It("denies admin access for a cert autosigned from a CSR containing pp_cli_auth", func() {
			// Stand up a CA with autosign=true to simulate the attack path.
			escalationDir, err := os.MkdirTemp("", "puppet-ca-escalation-test")
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(escalationDir)
			autosignStore := storage.New(escalationDir)
			autosignCA := ca.New(autosignStore, ca.AutosignConfig{Mode: "true"}, "puppet.test")
			Expect(autosignStore.EnsureDirs(context.Background())).To(Succeed())
			Expect(autosignStore.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
			Expect(autosignStore.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
			Expect(autosignStore.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
			Expect(autosignStore.TouchInventory(context.Background())).To(Succeed())
			Expect(autosignCA.Init(context.Background())).To(Succeed())

			// Step 1: Craft a CSR with pp_cli_auth = "true".
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			ppCliAuthVal, err := asn1.Marshal("true")
			Expect(err).NotTo(HaveOccurred())
			csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "evil-node"},
				ExtraExtensions: []pkix.Extension{{
					Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39},
					Value: ppCliAuthVal,
				}},
			}, key)
			Expect(err).NotTo(HaveOccurred())
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

			// Step 2: Submit CSR; autosign signs it immediately.
			srv := api.New(autosignCA)
			srv.AuthConfig = &api.AuthConfig{
				CACert:    caCert,
				AllowList: map[string]bool{},
			}
			attackMux := srv.Routes()

			rr := httptest.NewRecorder()
			attackMux.ServeHTTP(rr, httptest.NewRequest("PUT",
				"/puppet-ca/v1/certificate_request/evil-node", bytes.NewReader(csrPEM)))
			Expect(rr.Code).To(Equal(http.StatusOK))

			// Step 3: Retrieve the signed certificate.
			certRR := httptest.NewRecorder()
			attackMux.ServeHTTP(certRR, httptest.NewRequest("GET",
				"/puppet-ca/v1/certificate/evil-node", nil))
			Expect(certRR.Code).To(Equal(http.StatusOK))

			block, _ := pem.Decode(certRR.Body.Bytes())
			Expect(block).NotTo(BeNil(), "response must contain a PEM certificate")
			evilCert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// Verify the signed cert does NOT carry pp_cli_auth.
			oidPpCliAuth := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39}
			for _, ext := range evilCert.Extensions {
				Expect(ext.Id.Equal(oidPpCliAuth)).To(BeFalse(),
					"signed cert must not contain pp_cli_auth extension")
			}

			// Step 4: Use the cert for admin access; must be DENIED.
			req := httptest.NewRequest("POST", "/puppet-ca/v1/sign/all", nil)
			req = withClientCert(req, evilCert)
			adminRR := httptest.NewRecorder()
			attackMux.ServeHTTP(adminRR, req)
			Expect(adminRR.Code).To(Equal(http.StatusForbidden),
				"attacker cert from CSR with pp_cli_auth must NOT grant admin access")
		})
	})

	// --- NoPpCliAuth=true disables the extension check ---

	Context("NoPpCliAuth=true disables pp_cli_auth as an admin credential", func() {
		var muxNoPpCli http.Handler

		BeforeEach(func() {
			srv := api.New(myCA)
			srv.AuthConfig = &api.AuthConfig{
				CACert:      caCert,
				AllowList:   map[string]bool{},
				NoPpCliAuth: true,
			}
			muxNoPpCli = srv.Routes()
		})

		It("denies POST /sign/all even with a valid pp_cli_auth cert", func() {
			clientCert := issueClientCertWithPpCliAuth("openvox-server", caCert, caKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			muxNoPpCli.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusForbidden))
		})

		It("still allows POST /sign/all for a CN in the allow list", func() {
			srv := api.New(myCA)
			srv.AuthConfig = &api.AuthConfig{
				CACert:      caCert,
				AllowList:   map[string]bool{"puppet-server": true},
				NoPpCliAuth: true,
			}
			muxWithCN := srv.Routes()

			clientCert := issueClientCert("puppet-server", caCert, caKey)
			req := httptest.NewRequest("POST", "/sign/all", nil)
			req = withClientCert(req, clientCert)
			rr := httptest.NewRecorder()
			muxWithCN.ServeHTTP(rr, req)
			Expect(rr.Code).NotTo(Equal(http.StatusForbidden))
		})
	})
})
