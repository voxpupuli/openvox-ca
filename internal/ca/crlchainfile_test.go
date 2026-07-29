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

package ca_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// writeChainFile writes blobs to a temp file and returns its path.
func writeChainFile(blobs ...[]byte) string {
	GinkgoHelper()
	path := filepath.Join(GinkgoT().TempDir(), "upstream-crls.pem")
	var joined []byte
	for _, b := range blobs {
		joined = append(joined, b...)
	}
	Expect(os.WriteFile(path, joined, 0o644)).To(Succeed())
	return path
}

var _ = Describe("crl_chain_file", func() {
	var (
		ctx      context.Context
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		upstream, upsCRL = upstreamCA("Upstream Root CA")
	})

	// trustUpstream appends the upstream certificate to the stored CA bundle,
	// which is what an imported chain looks like and what makes its CRL
	// verifiable.
	trustUpstream := func() {
		GinkgoHelper()
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...), upstreamPEM...))).To(Succeed())
	}

	It("is a no-op when unconfigured", func() {
		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("publishes an upstream CRL the CA bundle vouches for", func() {
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeTrue())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	It("discards a CRL no certificate in the bundle signed", func() {
		// SECURITY: this content is served verbatim to every agent. Without
		// the check the file would be a way to inject arbitrary bytes into
		// every agent's CRL store.
		stranger, strangerCRL := upstreamCA("Unrelated CA")
		Expect(stranger).NotTo(BeNil())
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(strangerCRL)

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse(), "nothing verified, so nothing to publish")
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("keeps the verified CRLs and drops the unverifiable ones from one file", func() {
		_, strangerCRL := upstreamCA("Unrelated CA")
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(strangerCRL, upsCRL)

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	It("ignores a CRL of our own found in the file", func() {
		// Ours is rebuilt from the inventory on every re-sign; taking it from a
		// file would let a stale copy supersede live revocations.
		trustUpstream()
		ourCRL := mustGetCRL(ctx, store)
		myCA.CRLChainFile = writeChainFile(ourCRL, upsCRL)

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2), "our own block appears once, from the inventory")
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	It("does not rewrite when the file has not changed", func() {
		// The rewrite bumps our CRL number, so doing it every pass would churn
		// the number for no reason and wake every consumer each cycle.
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeTrue())
		before := crlBlocks(mustGetCRL(ctx, store))[0].Number

		rewritten, err = myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse())
		Expect(crlBlocks(mustGetCRL(ctx, store))[0].Number).To(Equal(before))
	})

	It("removes an upstream CRL dropped from the file", func() {
		// The file is declarative: what it says is what gets published, so a
		// CRL taken out of it is meant to disappear.
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))

		myCA.CRLChainFile = writeChainFile()
		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeTrue())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("survives a configured file that does not exist yet", func() {
		// A mounted Secret may not have landed. Refusing to serve would turn a
		// slow rollout into an outage.
		trustUpstream()
		myCA.CRLChainFile = filepath.Join(GinkgoT().TempDir(), "absent.pem")

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("fails rather than publishing a file it cannot parse", func() {
		trustUpstream()
		path := filepath.Join(GinkgoT().TempDir(), "bad.pem")
		Expect(os.WriteFile(path, []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n"), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).To(HaveOccurred())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1), "the published chain is untouched")
	})

	It("keeps the file's CRLs across an ordinary revocation", func() {
		// The re-sign path and the refresh path must agree about what upstream
		// means, or a revocation would drop what the file put there.
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[0].RevokedCertificateEntries).To(HaveLen(1))
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	Describe("UpstreamCRLStatuses", func() {
		It("reports the upstream entries and not our own", func() {
			trustUpstream()
			myCA.CRLChainFile = writeChainFile(upsCRL)
			Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

			statuses, err := myCA.UpstreamCRLStatuses(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(statuses).To(HaveLen(1))
			Expect(statuses[0].Issuer).To(ContainSubstring("Upstream Root CA"))
			Expect(statuses[0].NextUpdate).NotTo(BeZero())
		})

		It("is empty on a CA with no upstream", func() {
			statuses, err := myCA.UpstreamCRLStatuses(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(statuses).To(BeEmpty())
		})
	})
})
