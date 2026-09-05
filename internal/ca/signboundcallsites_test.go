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

// The *queueing* half of the bound, driven through the two production call
// sites that use it: `signCRLLocked` and `issueLeafLocked`.
//
// signbound_test.go proves the primitive queues and honours ctx;
// signboundrace_test.go proves the OCSP responder sheds. Neither drives a CRL
// re-sign or an issuance through a full bound, so neither would notice a slot
// that is acquired and never released on those paths — which is precisely
// where a leak is silent and fatal: with a small bound, one lost slot makes
// every future revocation and CRL update hang.
//
// Note what contention is *possible* here, because it shapes every spec below.
// Two concurrent issuances cannot contend for a slot: `issueLeafLocked` runs
// under `c.mu`, so `c.mu` serialises them long before either reaches the
// bound. The contention that can really happen is cross-path — the OCSP
// responder signs without `c.mu` and can hold the only slot while an issuance
// or a CRL re-sign waits for it. That is the interaction the asymmetry was
// designed around (OCSP sheds so it cannot build a queue an issuance must join)
// and it is what these specs reproduce.
package ca

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("The signing bound on its production call sites", func() {
	var (
		ctx context.Context
		c   *CA
	)

	BeforeEach(func() {
		ctx = context.Background()
		c = New(storage.New(GinkgoT().TempDir()), AutosignConfig{Mode: "off"}, "puppet.test")
		// ECDSA throughout: these specs are about the bound, not about how long
		// an RSA-4096 bootstrap takes.
		c.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		c.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		c.SigningConcurrency = 1
		Expect(c.Init(ctx)).To(Succeed())
	})

	// occupyTheBound takes the only slot, as a concurrent OCSP signature would.
	// Returned is a release func; specs that expect the waiter to be admitted
	// call it, and specs that expect the waiter to give up do not.
	occupyTheBound := func() func() {
		c.signSlots <- struct{}{}
		released := false
		return func() {
			if !released {
				released = true
				<-c.signSlots
			}
		}
	}

	Describe("the CRL re-sign", func() {
		It("waits for a slot rather than failing, and returns it on success", func() {
			release := occupyTheBound()

			done := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				done <- c.ReissueCRL(ctx)
			}()

			// Queued, not refused: the CRL path must never shed, because a CRL
			// that could not be re-signed is a revocation that did not land.
			Consistently(done, 100*time.Millisecond).ShouldNot(Receive())

			release()
			Eventually(done, 5*time.Second).Should(Receive(BeNil()))

			// The slot came back. Without this a leak here would pass every
			// other spec in the package and hang the next revocation.
			inFlight, limit := c.SigningInFlight()
			Expect(inFlight).To(BeZero())
			Expect(limit).To(Equal(1))
		})

		It("gives up when its context is cancelled while queued, and counts the failure", func() {
			defer occupyTheBound()()

			waiting, cancel := context.WithCancel(ctx)
			before := c.CRLUpdateFailures()

			done := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				done <- c.ReissueCRL(waiting)
			}()

			// Cancel only once it is parked, so the failure is provoked at the
			// slot wait and not at some earlier ctx check on the way in.
			Consistently(done, 100*time.Millisecond).ShouldNot(Receive())
			cancel()

			var err error
			Eventually(done, 5*time.Second).Should(Receive(&err))
			Expect(err).To(MatchError(context.Canceled))
			// Pins the failure to the slot wait specifically. Without this the
			// spec would also pass if the cancellation were noticed anywhere
			// else on the CRL path.
			Expect(err.Error()).To(ContainSubstring("waiting for a CA signing slot to re-sign the CRL"))
			Expect(c.CRLUpdateFailures()).To(Equal(before + 1))
		})
	})

	Describe("leaf issuance", func() {
		It("waits for a slot rather than failing, and returns it on success", func() {
			release := occupyTheBound()

			done := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				_, err := c.Generate(ctx, "node1.test", nil)
				done <- err
			}()

			// Issuance queues. It is authenticated, and refusing a certificate
			// a client asked for to protect an unauthenticated responder would
			// be the wrong way round.
			Consistently(done, 100*time.Millisecond).ShouldNot(Receive())

			release()
			Eventually(done, 5*time.Second).Should(Receive(BeNil()))

			inFlight, limit := c.SigningInFlight()
			Expect(inFlight).To(BeZero())
			Expect(limit).To(Equal(1))
		})

		It("gives up when its context is cancelled while queued", func() {
			defer occupyTheBound()()

			waiting, cancel := context.WithCancel(ctx)

			done := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				_, err := c.Generate(waiting, "node2.test", nil)
				done <- err
			}()

			Consistently(done, 100*time.Millisecond).ShouldNot(Receive())
			cancel()

			var err error
			Eventually(done, 5*time.Second).Should(Receive(&err))
			Expect(err).To(MatchError(context.Canceled))
			// The ctx-aware wait is half of what keeps a blocking acquire under
			// c.mu safe; without it a client that has gone away would leave
			// c.mu held on its behalf.
			Expect(err.Error()).To(ContainSubstring("waiting for a CA signing slot to sign for node2.test"))
		})
	})
})
