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

// White-box, because the bound's own operations are unexported and because
// occupying a slot deliberately is the clearest way to state most of these
// properties.
//
// Holding slots by hand states the mechanism, but not that it engages on the
// real path. That is signboundrace_test.go's job: since #197 the OCSP
// responder signs *outside* `c.mu`, so two requests can genuinely be inside
// the signature at once and the bound can be shown to bound them. Read the two
// files together — these specs would all still pass if nothing ever took a
// slot during an actual signature.
package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("The CA-key signing bound", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	Describe("sizing", func() {
		It("builds a channel of the configured capacity", func() {
			c := New(nil, AutosignConfig{Mode: "off"}, "puppet.test")
			c.SigningConcurrency = 3
			c.initSigningBound()

			Expect(c.signSlots).NotTo(BeNil())
			Expect(c.signSlots).To(HaveCap(3))
		})

		// Zero is the documented "disabled", and it has to be distinguishable
		// from a bound of zero — which would refuse every signature — rather
		// than merely close to it.
		DescribeTable("leaves the bound unset for a non-positive limit",
			func(limit int) {
				c := New(nil, AutosignConfig{Mode: "off"}, "puppet.test")
				c.SigningConcurrency = limit
				c.initSigningBound()

				Expect(c.signSlots).To(BeNil())
				Expect(c.acquireSigningSlot(ctx)).To(Succeed())
				Expect(c.acquireSigningSlotOrShed(ctx)).To(Succeed())
				c.releaseSigningSlot()

				inFlight, reported := c.SigningInFlight()
				Expect(inFlight).To(BeZero())
				Expect(reported).To(BeZero())
			},
			Entry("explicitly disabled", 0),
			Entry("negative", -1),
		)
	})

	Describe("shedding", func() {
		var c *CA

		BeforeEach(func() {
			c = New(nil, AutosignConfig{Mode: "off"}, "puppet.test")
			c.SigningConcurrency = 2
			c.initSigningBound()
			// Shorten the wait so a spec that must observe a shed does not
			// spend a real second on it. The production value is a second; see
			// ocspSigningWait for why.
			c.signWait = 20 * time.Millisecond
		})

		It("reports what is in flight against the configured limit", func() {
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())

			inFlight, limit := c.SigningInFlight()
			Expect(inFlight).To(Equal(1))
			Expect(limit).To(Equal(2))

			c.releaseSigningSlot()
			inFlight, _ = c.SigningInFlight()
			Expect(inFlight).To(BeZero())
		})

		It("refuses once the bound is full, and counts the refusal", func() {
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())

			err := c.acquireSigningSlotOrShed(ctx)
			Expect(err).To(MatchError(ErrSigningBusy))
			Expect(c.SigningShedTotal()).To(Equal(uint64(1)))
		})

		// The refusal has to be transient, or the bound is an outage rather
		// than a queue depth. Without this, a spec asserting only the refusal
		// would still pass with the release side broken.
		It("admits the next caller once a slot is returned", func() {
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())
			Expect(c.acquireSigningSlotOrShed(ctx)).To(MatchError(ErrSigningBusy))

			c.releaseSigningSlot()

			Expect(c.acquireSigningSlotOrShed(ctx)).To(Succeed())
			Expect(c.SigningShedTotal()).To(Equal(uint64(1)))
		})

		// A caller that has gone away is a different event from a responder at
		// capacity, and only the second is the bound doing its job. Counting
		// both would make the metric unable to answer the question it exists
		// for — whether the limit matches the deployment's signer.
		It("reports a cancelled context as such, and does not count it as a shed", func() {
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())

			cancelled, cancel := context.WithCancel(ctx)
			cancel()

			err := c.acquireSigningSlotOrShed(cancelled)
			Expect(err).To(MatchError(context.Canceled))
			Expect(err).NotTo(MatchError(ErrSigningBusy))
			Expect(c.SigningShedTotal()).To(BeZero())
		})
	})

	// The queueing half. Issuance and CRL re-signing take this path, and both
	// hold c.mu across it — so the ctx honoured here is what stops a client
	// that has given up from leaving c.mu held on its behalf.
	Describe("queueing", func() {
		var c *CA

		BeforeEach(func() {
			c = New(nil, AutosignConfig{Mode: "off"}, "puppet.test")
			c.SigningConcurrency = 1
			c.initSigningBound()
		})

		It("waits for a slot rather than refusing", func() {
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())

			admitted := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				admitted <- c.acquireSigningSlot(ctx)
			}()

			// Still waiting: nothing has been released yet.
			Consistently(admitted, 50*time.Millisecond).ShouldNot(Receive())

			c.releaseSigningSlot()
			Eventually(admitted).Should(Receive(BeNil()))
		})

		It("gives up when its context is cancelled", func() {
			Expect(c.acquireSigningSlot(ctx)).To(Succeed())

			waiting, cancel := context.WithCancel(ctx)
			result := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				result <- c.acquireSigningSlot(waiting)
			}()

			Consistently(result, 50*time.Millisecond).ShouldNot(Receive())
			cancel()
			Eventually(result).Should(Receive(MatchError(context.Canceled)))
		})
	})

	Describe("the OCSP responder under a full bound", func() {
		var (
			c        *CA
			reqDER   []byte
			storeDir string
		)

		BeforeEach(func() {
			storeDir = GinkgoT().TempDir()
			c = New(storage.New(storeDir), AutosignConfig{Mode: "off"}, "puppet.test")
			// ECDSA throughout: this spec is about the bound, not about how
			// long an RSA-4096 bootstrap takes.
			c.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
			c.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
			c.SigningConcurrency = 1
			Expect(c.Init(ctx)).To(Succeed())
			c.signWait = 20 * time.Millisecond

			// Issuance goes through the same bound, so this also proves the
			// slot is returned after a signature rather than leaked — with a
			// limit of 1, a leak here would make every later acquisition fail.
			res, err := c.Generate(ctx, "node1.test", nil)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(res.CertificatePEM)
			Expect(block).NotTo(BeNil())
			leaf, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			reqDER, err = xocsp.CreateRequest(leaf, c.CACert, nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("answers normally while a slot is free", func() {
			answer, err := c.AnswerOCSP(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred())
			Expect(answer.DER).NotTo(BeEmpty())
			Expect(c.SigningShedTotal()).To(BeZero())
		})

		It("sheds with ErrSigningBusy when the bound is occupied", func() {
			// Occupy the only slot, as a concurrent issuance or a peer OCSP
			// signature would.
			c.signSlots <- struct{}{}

			_, err := c.AnswerOCSP(ctx, reqDER)
			Expect(err).To(MatchError(ErrSigningBusy))
			// Not an internal error: the handler must be able to tell these
			// apart to answer tryLater rather than internalError.
			Expect(errors.Is(err, ErrInternal)).To(BeFalse())
			Expect(c.SigningShedTotal()).To(Equal(uint64(1)))

			// And it recovers: the refusal is capacity, not a broken responder.
			<-c.signSlots
			answer, err := c.AnswerOCSP(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred())
			Expect(answer.DER).NotTo(BeEmpty())
		})

		// The property that keeps the bound from being felt in normal service.
		// A cached response is returned under the read lock before the bound is
		// consulted at all, so ordinary verifier traffic — which is repeat
		// queries for a handful of serials — is answered while the bound is
		// saturated. Without this, a full bound would shed every request rather
		// than only the ones that would actually sign, and the shed rate would
		// stop meaning what the metric says it means.
		It("serves a cached response while the bound is full, without shedding", func() {
			// Populate the cache: known serial, no nonce, so this signs once
			// and stores the answer.
			first, err := c.AnswerOCSP(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred())
			Expect(first.MaxAge).To(BeNumerically(">", 0), "must be cacheable for the rest to mean anything")

			// Now saturate the bound and ask again.
			c.signSlots <- struct{}{}
			DeferCleanup(func() { <-c.signSlots })

			cached, err := c.AnswerOCSP(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred(), "a cache hit must not need a signing slot")
			Expect(cached.DER).To(Equal(first.DER))
			Expect(c.SigningShedTotal()).To(BeZero(),
				"a cache hit is not a shed, and must not be counted as one")
		})
	})
})
