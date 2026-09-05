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

package metrics_test

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

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// gatedKey wraps the CA key and parks inside Sign until released, so a spec can
// hold a signature open and observe the bound from outside — the same shape
// internal/ca's own race spec uses, reproduced here because this package can
// only reach the CA through its exported surface.
type gatedKey struct {
	crypto.Signer
	entered chan struct{}
	release chan struct{}
}

func (g *gatedKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	<-g.release
	return g.Signer.Sign(r, digest, opts)
}

var _ = Describe("CA-key signing bound metrics", func() {
	var ctx context.Context

	BeforeEach(func() { ctx = context.Background() })

	newCA := func(limit int) *ca.CA {
		myCA := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.SigningConcurrency = limit
		Expect(myCA.Init(ctx)).To(Succeed())
		return myCA
	}

	It("reports the configured limit, with nothing in flight and nothing shed", func() {
		g := gather(metrics.NewCollector(newCA(4)))

		Expect(gaugeValue(g.findByLabels("puppetca_ca_signing_limit", nil))).To(Equal(4.0))
		Expect(gaugeValue(g.findByLabels("puppetca_ca_signing_in_flight", nil))).To(Equal(0.0))
		Expect(counterValue(g.findByLabels("puppetca_ca_signing_shed_total", nil))).To(Equal(0.0))
	})

	// Unbounded is a legitimate configured value and is indistinguishable at a
	// glance from a bound that is never reached, so the series has to be
	// emitted rather than omitted — it is what an operator alerts on to catch a
	// CA that is not bounding its signer at all.
	It("still emits the limit as 0 when signing is unbounded", func() {
		g := gather(metrics.NewCollector(newCA(0)))

		limit := g.findByLabels("puppetca_ca_signing_limit", nil)
		Expect(limit).NotTo(BeNil(), "the limit must be emitted, not omitted, when unbounded")
		Expect(gaugeValue(limit)).To(Equal(0.0))
	})

	It("reports a signature in flight, and counts an OCSP response shed behind it", func() {
		myCA := newCA(1)

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		Expect(block).NotTo(BeNil())
		leaf, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Swapped in after issuance so the gate covers only the OCSP signature.
		gate := &gatedKey{
			Signer:  myCA.CAKey,
			entered: make(chan struct{}, 1),
			release: make(chan struct{}),
		}
		myCA.CAKey = gate

		// A serial this CA never issued: an unknown is never cached, so the
		// request always reaches the signature.
		unknown := func(serial int64) []byte {
			fake := *leaf
			fake.SerialNumber = big.NewInt(serial)
			reqDER, reqErr := xocsp.CreateRequest(&fake, myCA.CACert, nil)
			Expect(reqErr).NotTo(HaveOccurred())
			return reqDER
		}

		firstDone := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, ocspErr := myCA.AnswerOCSP(ctx, unknown(0x9001))
			firstDone <- ocspErr
		}()
		Eventually(gate.entered).Should(Receive())

		g := gather(metrics.NewCollector(myCA))
		Expect(gaugeValue(g.findByLabels("puppetca_ca_signing_in_flight", nil))).To(Equal(1.0))
		Expect(gaugeValue(g.findByLabels("puppetca_ca_signing_limit", nil))).To(Equal(1.0))

		// A second request behind a full bound is shed, and the counter is the
		// only signal an operator has that it happened.
		_, err = myCA.AnswerOCSP(ctx, unknown(0x9002))
		Expect(err).To(MatchError(ca.ErrSigningBusy))

		g = gather(metrics.NewCollector(myCA))
		Expect(counterValue(g.findByLabels("puppetca_ca_signing_shed_total", nil))).To(Equal(1.0))

		close(gate.release)
		Eventually(firstDone, 5*time.Second).Should(Receive(BeNil()))

		// The slot came back, so in-flight falls again rather than staying high.
		g = gather(metrics.NewCollector(myCA))
		Expect(gaugeValue(g.findByLabels("puppetca_ca_signing_in_flight", nil))).To(Equal(0.0))
	})
})
