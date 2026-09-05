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

// Panic-safety of the signing slot, which is not the hygiene it looks like.
//
// A panic crossing the signing call is not self-correcting here. Two of the
// three call sites are reachable from an HTTP handler, and net/http's
// conn.serve recovers a handler panic, logs it and drops that one connection —
// the process survives. Nothing in this repository calls recover() itself, so
// it is that recovery that converts a crash into permanent capacity loss: the
// slot is never returned, and no restart happens to reclaim it.
//
// The pool is small by design. ca_signing_concurrency defaults to
// max(4, GOMAXPROCS), but operators running a remote signer are told to lower
// it to that signer's capacity, so 1 or 2 is an ordinary setting. There, one
// leaked slot wedges issuance and CRL re-signing (both queue, under c.mu) and
// sheds every OCSP request with tryLater until restart.
//
// These specs pin the deferred release. Replace any of the three
// closure-with-defer call sites with a sequential release and they fail.
package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// panickingSigner stands in for a signer that fails catastrophically rather
// than returning an error — a corrupt PKCS#11 module, a bug in a provider, or
// anything else that panics on the far side of the signing call.
type panickingSigner struct {
	crypto.Signer
	armed bool
}

func (p *panickingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if p.armed {
		panic("signer exploded")
	}
	return p.Signer.Sign(r, digest, opts)
}

var _ = Describe("The signing bound when a signature panics", func() {
	var (
		ctx    context.Context
		c      *CA
		signer *panickingSigner
		leaf   *x509.Certificate
	)

	BeforeEach(func() {
		ctx = context.Background()
		c = New(storage.New(GinkgoT().TempDir()), AutosignConfig{Mode: "off"}, "puppet.test")
		c.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		c.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		// One slot, so a single leak is total. This is also a setting the docs
		// actively recommend for a constrained remote signer.
		c.SigningConcurrency = 1
		Expect(c.Init(ctx)).To(Succeed())
		c.signWait = 20 * time.Millisecond

		res, err := c.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		Expect(block).NotTo(BeNil())
		leaf, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Armed only after setup, so the bootstrap and the issuance above run
		// against the real key.
		signer = &panickingSigner{Signer: c.CAKey}
		c.mu.Lock()
		c.CAKey = signer
		c.mu.Unlock()
	})

	// expectPanic runs fn, asserts it panicked, and recovers — standing in for
	// net/http's own per-connection recovery, which is what makes the leak
	// survivable and therefore permanent.
	expectPanic := func(fn func()) {
		panicked := func() (p bool) {
			defer func() {
				if r := recover(); r != nil {
					p = true
				}
			}()
			fn()
			return false
		}()
		Expect(panicked).To(BeTrue(), "the stand-in signer was supposed to panic")
	}

	unknownReq := func(serial int64) []byte {
		fake := *leaf
		fake.SerialNumber = big.NewInt(serial)
		reqDER, err := xocsp.CreateRequest(&fake, c.CACert, nil)
		Expect(err).NotTo(HaveOccurred())
		return reqDER
	}

	It("returns the slot when an OCSP signature panics", func() {
		signer.armed = true
		expectPanic(func() { _, _ = c.AnswerOCSP(ctx, unknownReq(0x7001)) })

		inFlight, limit := c.SigningInFlight()
		Expect(inFlight).To(BeZero(), "the slot leaked: this CA can never sign again")
		Expect(limit).To(Equal(1))

		// The responder still works, which is the property that actually
		// matters — a leaked slot would shed every request from here on.
		signer.armed = false
		answer, err := c.AnswerOCSP(ctx, unknownReq(0x7002))
		Expect(err).NotTo(HaveOccurred())
		Expect(answer.DER).NotTo(BeEmpty())
	})

	It("returns the slot when an issuance panics", func() {
		signer.armed = true
		expectPanic(func() { _, _ = c.Generate(ctx, "node2.test", nil) })

		inFlight, _ := c.SigningInFlight()
		Expect(inFlight).To(BeZero(), "the slot leaked: issuance would queue for ever")

		signer.armed = false
		_, err := c.Generate(ctx, "node3.test", nil)
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns the slot when a CRL re-sign panics", func() {
		signer.armed = true
		expectPanic(func() { _ = c.ReissueCRL(ctx) })

		inFlight, _ := c.SigningInFlight()
		Expect(inFlight).To(BeZero(), "the slot leaked: every future revocation would hang")

		signer.armed = false
		Expect(c.ReissueCRL(ctx)).To(Succeed())
	})
})
