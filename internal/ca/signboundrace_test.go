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

// The spec the bound actually exists for, and it became possible only with
// #197: the OCSP responder now signs *outside* `c.mu`, so two requests can
// genuinely be inside the signature at once. Before that change this spec
// could not have failed — `c.mu` serialised the two, so racing the responder
// against itself would have passed with the bound deleted.
//
// Nothing here touches `signSlots` directly. The first request occupies the
// slot by signing, exactly as a real one does; the sibling specs in
// signbound_test.go hold slots by hand, which states the mechanism but not
// that it engages on the real path.
//
// Barrier placement is what makes it able to fail: the second request is
// issued only after the first is observed *inside* Sign, so the slot is
// certainly held. Fire the two off together instead and they may complete in
// sequence, and the spec passes with the bound removed.
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

// gatedSigner wraps the real CA key and parks inside Sign until released, so a
// spec can hold a signature open the way a slow or saturated external signer
// does. It stands in for the deployments this bound exists for: an isolated
// signer over IPC, or an OpenBao Transit key.
type gatedSigner struct {
	crypto.Signer
	entered chan struct{}
	release chan struct{}
}

func (g *gatedSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	select {
	case g.entered <- struct{}{}:
	default: // only the first caller needs to announce itself
	}
	<-g.release
	return g.Signer.Sign(r, digest, opts)
}

// ocspRequestForUnknownSerial builds a request for a serial this CA never
// issued. An unknown is deliberately never cached (see AnswerOCSP), so every
// such request reaches the signature — which is what lets this spec provoke a
// second concurrent signature without depending on cache eviction.
//
// The certificate is a copy with the serial replaced: CreateRequest reads only
// the serial from it, plus the issuer's name and key for the hashes, so nothing
// has to be signed to build one.
func ocspRequestForUnknownSerial(leaf, issuer *x509.Certificate, serial int64) []byte {
	fake := *leaf
	fake.SerialNumber = big.NewInt(serial)
	reqDER, err := xocsp.CreateRequest(&fake, issuer, nil)
	Expect(err).NotTo(HaveOccurred())
	return reqDER
}

var _ = Describe("The CA-key signing bound under real concurrency", func() {
	var (
		ctx  context.Context
		c    *CA
		gate *gatedSigner
		leaf *x509.Certificate
	)

	BeforeEach(func() {
		ctx = context.Background()
		c = New(storage.New(GinkgoT().TempDir()), AutosignConfig{Mode: "off"}, "puppet.test")
		// ECDSA throughout: this is about the bound, not about how long an
		// RSA-4096 bootstrap takes.
		c.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		c.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		c.SigningConcurrency = 1
		Expect(c.Init(ctx)).To(Succeed())
		c.signWait = 50 * time.Millisecond

		res, err := c.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		Expect(block).NotTo(BeNil())
		leaf, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Swapped in only after issuance, so the gate covers the OCSP
		// signatures under test rather than the setup. Under c.mu because
		// AnswerOCSP snapshots the key under the read lock.
		gate = &gatedSigner{
			Signer:  c.CAKey,
			entered: make(chan struct{}, 1),
			release: make(chan struct{}),
		}
		c.mu.Lock()
		c.CAKey = gate
		c.mu.Unlock()
	})

	It("sheds a genuinely concurrent second signature, and admits it once the first completes", func() {
		firstDone := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, err := c.AnswerOCSP(ctx, ocspRequestForUnknownSerial(leaf, c.CACert, 0x5171))
			firstDone <- err
		}()

		// The first request is now inside the signature, holding the only slot.
		Eventually(gate.entered).Should(Receive())

		inFlight, limit := c.SigningInFlight()
		Expect(inFlight).To(Equal(1))
		Expect(limit).To(Equal(1))

		// The second must be refused rather than queued behind a signer that
		// may never answer.
		_, err := c.AnswerOCSP(ctx, ocspRequestForUnknownSerial(leaf, c.CACert, 0x5172))
		Expect(err).To(MatchError(ErrSigningBusy))
		Expect(c.SigningShedTotal()).To(Equal(uint64(1)))

		// Releasing the first returns the slot: the refusal was capacity, not a
		// responder that had stopped working.
		close(gate.release)
		Eventually(firstDone).Should(Receive(BeNil()))

		answer, err := c.AnswerOCSP(ctx, ocspRequestForUnknownSerial(leaf, c.CACert, 0x5173))
		Expect(err).NotTo(HaveOccurred())
		Expect(answer.DER).NotTo(BeEmpty())
		Expect(c.SigningShedTotal()).To(Equal(uint64(1)))
	})
})
