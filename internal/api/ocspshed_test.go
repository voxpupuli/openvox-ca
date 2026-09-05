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

// The shed branch driven through the real mux.
//
// ocsperror_internal_test.go pins ocspErrorResponse's mapping in isolation,
// which says which constants belong together but executes none of the handler:
// not the 503 write, not the response body, not the log line. This is the
// security property the whole change exists for — what an unauthenticated
// caller actually receives when the CA-key bound is full — so it is worth
// asserting on the bytes that reach the wire rather than on an internal
// mapping.
//
// The sibling spec in ocsp_test.go ("answers a signer failure with 500
// internalError, not 400 malformedRequest") makes the same argument for the
// neighbouring branch, and this follows its shape.
package api_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// gatedSigner parks inside Sign until released, holding whatever signing slot
// its caller acquired — the stand-in for a slow or saturated external signer.
type gatedSigner struct {
	inner   crypto.Signer
	entered chan struct{}
	release chan struct{}
}

func (g *gatedSigner) Public() crypto.PublicKey { return g.inner.Public() }

func (g *gatedSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.release
	return g.inner.Sign(r, digest, opts)
}

var _ = Describe("OCSP handler when the CA-key signing bound is full", func() {
	var (
		myCA *ca.CA
		mux  http.Handler
		gate *gatedSigner
		leaf *x509.Certificate
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
		// One slot, so a single held signature fills the bound. This is also a
		// setting the docs recommend for a constrained remote signer.
		myCA.SigningConcurrency = 1
		Expect(myCA.Init(ctx)).To(Succeed())
		mux = api.New(myCA).Routes()

		leaf = signCert(myCA, "shed-node")

		// Gated only after issuance, so the gate covers the OCSP signatures
		// under test and nothing in the setup.
		gate = &gatedSigner{
			inner:   myCA.CAKey,
			entered: make(chan struct{}, 1),
			release: make(chan struct{}),
		}
		myCA.CAKey = gate
	})

	// A serial this CA never issued: an unknown is never cached, so each
	// request reaches the signature instead of being answered from the cache.
	unknownReq := func(serial int64) []byte {
		fake := *leaf
		fake.SerialNumber = big.NewInt(serial)
		return ocspReqDER(&fake, myCA.CACert)
	}

	post := func(reqDER []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	It("answers 503 with an RFC 6960 tryLater body, and recovers afterwards", func() {
		firstDone := make(chan int, 1)
		go func() {
			defer GinkgoRecover()
			firstDone <- post(unknownReq(0x8001)).Code
		}()

		// The first request is inside the signature now, holding the only slot.
		Eventually(gate.entered).Should(Receive())

		rr := post(unknownReq(0x8002))

		Expect(rr.Code).To(Equal(http.StatusServiceUnavailable),
			"a full signing bound is capacity, not a client error and not a server fault")
		Expect(rr.Body.Bytes()).To(Equal(xocsp.TryLaterErrorResponse))
		// The distinction that matters to a verifier: tryLater invites a retry,
		// the other two do not or report the wrong fault.
		Expect(rr.Body.Bytes()).NotTo(Equal(xocsp.MalformedRequestErrorResponse))
		Expect(rr.Body.Bytes()).NotTo(Equal(xocsp.InternalErrorErrorResponse))
		Expect(rr.Header().Get("Content-Type")).To(Equal("application/ocsp-response"))

		// Releasing the held signature frees the slot, and the responder serves
		// normally again — the refusal was capacity, not a broken responder.
		close(gate.release)
		Eventually(firstDone, 5*time.Second).Should(Receive(Equal(http.StatusOK)))

		recovered := post(unknownReq(0x8003))
		Expect(recovered.Code).To(Equal(http.StatusOK))
		Expect(recovered.Body.Bytes()).NotTo(Equal(xocsp.TryLaterErrorResponse))
	})
})
