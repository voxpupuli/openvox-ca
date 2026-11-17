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
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// /ocsp is unauthenticated and a nonced request signs on every call, so one
// client could otherwise keep the CA-key signing bound full on its own.
// OCSPRateLimit caps each client address per minute, in front of the
// responder, and answers the excess with RFC 6960 tryLater over HTTP 429.
var _ = Describe("OCSP rate limit", func() {
	var (
		myCA    *ca.CA
		srv     *api.Server
		limited int
		leaf    *x509.Certificate
	)

	BeforeEach(func() {
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())
		leaf = signCert(myCA, "limited-node")

		limited = 0
		srv = api.New(myCA)
		srv.OCSPEnabled = true
		srv.OnOCSPRateLimited = func() { limited++ }
	})

	// do sends one request from addr through a handler built from srv as it
	// now stands.
	var handler http.Handler
	JustBeforeEach(func() { handler = srv.Routes() })

	do := func(method, path, addr string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	nonced := func() []byte {
		nonce := make([]byte, 16)
		_, err := rand.Read(nonce)
		Expect(err).NotTo(HaveOccurred())
		der, err := testutil.BuildOCSPRequestWithNonce(leaf, myCA.CACert, nonce)
		Expect(err).NotTo(HaveOccurred())
		return der
	}

	expectLimited := func(rec *httptest.ResponseRecorder) {
		GinkgoHelper()
		Expect(rec.Code).To(Equal(http.StatusTooManyRequests))
		Expect(rec.Header().Get("Content-Type")).To(Equal("application/ocsp-response"))
		Expect(rec.Body.Bytes()).To(Equal(xocsp.TryLaterErrorResponse),
			"an OCSP client reads the status from the body, so it must say tryLater")
	}

	Context("with a limit of two per minute", func() {
		BeforeEach(func() { srv.OCSPRateLimit = 2 })

		// The case the issue is about: a nonce skips the response cache, so
		// these are the requests that cost a signature each.
		It("refuses a client's third nonced request with tryLater over 429", func() {
			for range 2 {
				rec := do("POST", "/ocsp", "192.0.2.1:1000", nonced())
				Expect(rec.Code).To(Equal(http.StatusOK))
			}
			expectLimited(do("POST", "/ocsp", "192.0.2.1:1000", nonced()))
			Expect(limited).To(Equal(1), "each refusal is reported once")
		})

		// Keyed on the address alone: three source ports are one client.
		It("counts both methods and both path forms against one budget", func() {
			reqDER := ocspReqDER(leaf, myCA.CACert)
			encoded := base64.RawURLEncoding.EncodeToString(reqDER) // standard base64 may hold a "/"
			Expect(do("GET", "/puppet-ca/v1/ocsp/"+encoded, "192.0.2.1:1000", nil).Code).To(Equal(http.StatusOK))
			Expect(do("POST", "/puppet-ca/v1/ocsp", "192.0.2.1:1001", reqDER).Code).To(Equal(http.StatusOK))
			expectLimited(do("GET", "/ocsp/"+encoded, "192.0.2.1:1002", nil))
		})

		// In front of the responder, so a malformed request is no free pass:
		// otherwise a flood need only be malformed to go uncounted.
		It("counts a malformed request too", func() {
			Expect(do("POST", "/ocsp", "192.0.2.1:1000", nil).Code).To(Equal(http.StatusBadRequest))
			Expect(do("POST", "/ocsp", "192.0.2.1:1000", nil).Code).To(Equal(http.StatusBadRequest))
			expectLimited(do("POST", "/ocsp", "192.0.2.1:1000", nil))
		})

		It("keeps a separate budget for each client address", func() {
			for range 2 {
				do("POST", "/ocsp", "192.0.2.1:1000", nonced())
			}
			expectLimited(do("POST", "/ocsp", "192.0.2.1:1000", nonced()))
			Expect(do("POST", "/ocsp", "192.0.2.2:1000", nonced()).Code).To(Equal(http.StatusOK),
				"one client exhausting its budget must not refuse another")
		})

		// The two limits must not share a bucket: verifier traffic from an
		// address would otherwise refuse that address's agents their CSRs.
		Context("beside a CSR limit", func() {
			BeforeEach(func() { srv.CSRRateLimit = 1 })

			It("does not spend the CSR submission budget", func() {
				for range 2 {
					do("POST", "/ocsp", "192.0.2.1:1000", nonced())
				}
				csr, err := testutil.GenerateCSR("csr-node")
				Expect(err).NotTo(HaveOccurred())
				rec := do("PUT", "/certificate_request/csr-node", "192.0.2.1:1000", csr)
				Expect(rec.Code).To(Equal(http.StatusOK), "body: %s", rec.Body.String())
				Expect(do("PUT", "/certificate_request/csr-node2", "192.0.2.1:1000", csr).Code).
					To(Equal(http.StatusTooManyRequests),
						"precondition: the CSR limit is live, so the 200 above was its one allowance")
			})
		})
	})

	// The default deployment shape: a server with no metrics listener sets no
	// hook, and the refusal must not depend on one.
	Context("with no OnOCSPRateLimited hook", func() {
		BeforeEach(func() {
			srv.OCSPRateLimit = 1
			srv.OnOCSPRateLimited = nil
		})

		It("still refuses the excess with tryLater over 429", func() {
			Expect(do("POST", "/ocsp", "192.0.2.1:1000", nonced()).Code).To(Equal(http.StatusOK))
			expectLimited(do("POST", "/ocsp", "192.0.2.1:1000", nonced()))
		})
	})

	// One host with a routed /64 can source from any address in it. With the
	// prefix length set, those addresses are one client.
	Context("with RateLimitIPv6PrefixLength 64", func() {
		BeforeEach(func() {
			srv.OCSPRateLimit = 2
			srv.RateLimitIPv6PrefixLength = 64
		})

		It("counts addresses in one /64 against one budget", func() {
			Expect(do("POST", "/ocsp", "[2001:db8:1:2::1]:1000", nonced()).Code).To(Equal(http.StatusOK))
			Expect(do("POST", "/ocsp", "[2001:db8:1:2::2]:1000", nonced()).Code).To(Equal(http.StatusOK))
			expectLimited(do("POST", "/ocsp", "[2001:db8:1:2::3]:1000", nonced()))
		})

		It("keeps a separate budget for another /64", func() {
			for range 2 {
				do("POST", "/ocsp", "[2001:db8:1:2::1]:1000", nonced())
			}
			Expect(do("POST", "/ocsp", "[2001:db8:1:3::1]:1000", nonced()).Code).To(Equal(http.StatusOK))
		})
	})

	// The default, and what the setting's absence must keep meaning.
	It("keys each IPv6 address separately by default", func() {
		srv.OCSPRateLimit = 1
		handler = srv.Routes()
		Expect(do("POST", "/ocsp", "[2001:db8:1:2::1]:1000", nonced()).Code).To(Equal(http.StatusOK))
		Expect(do("POST", "/ocsp", "[2001:db8:1:2::2]:1000", nonced()).Code).To(Equal(http.StatusOK))
	})

	It("does not limit at all when OCSPRateLimit is zero", func() {
		for range 5 {
			Expect(do("POST", "/ocsp", "192.0.2.1:1000", nonced()).Code).To(Equal(http.StatusOK))
		}
		Expect(limited).To(BeZero())
	})
})
