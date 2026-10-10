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

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// White-box, because both properties sit below anything a request can reach
// today: ocsp.ParseRequest refuses every hash it cannot compute before the
// issuer check runs, and the lock is not observable from outside.
var _ = Describe("OCSP issuer check internals", func() {
	var issuer *x509.Certificate

	BeforeEach(func() {
		_, crtPEM, _, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(crtPEM)
		Expect(block).NotTo(BeNil())
		issuer, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	// The guard keeps a hash x/crypto might one day accept, but this binary
	// cannot compute, from panicking on an unauthenticated endpoint.
	It("refuses a hash it cannot compute as malformed, without panicking", func() {
		req := &ocsp.Request{HashAlgorithm: crypto.Hash(0)}

		var err error
		Expect(func() { err = checkOCSPIssuer(req, issuer) }).NotTo(Panic())
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ErrNotAuthoritative)).To(BeFalse())
		Expect(errors.Is(err, ErrInternal)).To(BeFalse())
	})

	// Constant-true today, because ocspCacheHashes matches what x/crypto parses.
	// It exists for the day x/crypto accepts another hash: an answer cached
	// under a hash evictOCSPLocked does not walk would outlive a revocation.
	It("caches only hashes eviction walks", func() {
		for _, h := range ocspCacheHashes {
			Expect(ocspCacheableHash(h)).To(BeTrue(), "%v", h)
		}
		Expect(ocspCacheableHash(crypto.SHA3_256)).To(BeFalse())
		Expect(ocspCacheableHash(crypto.MD5)).To(BeFalse())
	})

	// The check hashes with whatever algorithm the caller chose, under c.mu.
	// A panic there must not leave the lock held. A CA with no certificate
	// makes the check panic without touching any process-global state.
	It("releases c.mu when the check panics", func() {
		c := New(nil, AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(c.CACert).To(BeNil())
		reqDER, err := testutil.BuildOCSPRequest(issuer, issuer)
		Expect(err).NotTo(HaveOccurred())

		Expect(func() { _, _ = c.AnswerOCSP(context.Background(), reqDER) }).To(Panic())

		Expect(c.mu.TryLock()).To(BeTrue(), "c.mu must not be left read-held")
		c.mu.Unlock()
	})
})
