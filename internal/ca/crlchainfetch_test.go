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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/boundedfile"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// parseCRLPEM parses a single-block CRL PEM, as crlfetch hands one over.
func parseCRLPEM(blob []byte) *x509.RevocationList {
	GinkgoHelper()
	block, _ := pem.Decode(blob)
	Expect(block).NotTo(BeNil())
	crl, err := x509.ParseRevocationList(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

var _ = Describe("MergeFetchedUpstreamCRLs", func() {
	const (
		urlRoot = "https://pki.example/root.crl"
		urlSub  = "https://pki.example/sub.crl"
	)

	var (
		ctx     context.Context
		store   *storage.StorageService
		myCA    *ca.CA
		root    *x509.Certificate
		rootKey crypto.Signer
		sub     *x509.Certificate
		subKey  crypto.Signer
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		myCA.SetCRLChainURLs([]string{urlRoot, urlSub})

		root, rootKey, _ = upstreamCAWithKey("Upstream Root CA")
		sub, subKey, _ = upstreamCAWithKey("Upstream Sub CA")

		// Both ancestors in the stored bundle, so their CRLs verify.
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		bundle := append([]byte{}, ours...)
		for _, c := range []*x509.Certificate{root, sub} {
			bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
		}
		Expect(store.SaveCACert(ctx, bundle)).To(Succeed())
	})

	crlOf := func(cert *x509.Certificate, key crypto.Signer, number int64) *x509.RevocationList {
		return parseCRLPEM(emptyCRLNumbered(cert, key, number))
	}

	// publish seeds the stored chain with ancestors after ours, as an import
	// or an earlier round leaves it.
	publish := func(crls ...*x509.RevocationList) {
		GinkgoHelper()
		blob := append([]byte{}, crlBlocksPEM(crlBlocks(mustGetCRL(ctx, store))[:1])...)
		blob = append(blob, crlBlocksPEM(crls)...)
		Expect(store.UpdateCRL(ctx, blob)).To(Succeed())
	}

	// upstream returns the published ancestors' CRL numbers by issuer CN.
	upstream := func() map[string]int64 {
		GinkgoHelper()
		out := map[string]int64{}
		for _, crl := range crlBlocks(mustGetCRL(ctx, store))[1:] {
			out[crl.Issuer.CommonName] = crl.Number.Int64()
		}
		return out
	}

	status := func(url string) ca.UpstreamFetchStatus {
		GinkgoHelper()
		for _, st := range myCA.UpstreamFetchStatuses() {
			if st.URL == url {
				return st
			}
		}
		Fail("no status for " + url)
		return ca.UpstreamFetchStatus{}
	}

	merge := func(fetches ...ca.UpstreamFetch) (bool, []error) {
		GinkgoHelper()
		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, fetches)
		Expect(err).NotTo(HaveOccurred())
		return res.Rewritten, res.Verdicts
	}

	It("exports every configured entry at zero before any round", func() {
		Expect(myCA.UpstreamFetchStatuses()).To(ConsistOf(
			ca.UpstreamFetchStatus{URL: urlRoot},
			ca.UpstreamFetchStatus{URL: urlSub},
		))
	})

	It("publishes new ancestors and credits both entries", func() {
		rewritten, verdicts := merge(
			ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
			ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		)
		Expect(rewritten).To(BeTrue())
		Expect(verdicts).To(Equal([]error{nil, nil}))
		Expect(upstream()).To(Equal(map[string]int64{"Upstream Root CA": 3, "Upstream Sub CA": 5}))
		Expect(status(urlRoot).LastSuccess).NotTo(BeZero())
		Expect(status(urlSub).Failures).To(BeZero())
	})

	It("signals CRL consumers when it republishes the chain", func() {
		// CRLUpdated's documentation and docs/kubernetes-export.md list an
		// upstream chain change from crl_chain.urls among the re-export
		// triggers; without the signal an exported CRL blob keeps the old
		// chain until the next local re-sign.
		select {
		case <-myCA.CRLUpdated():
		default:
		}

		rewritten, _ := merge(ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)})
		Expect(rewritten).To(BeTrue())
		Eventually(myCA.CRLUpdated()).Should(Receive())
	})

	It("counts an equal CRL as current: a success, and no rewrite", func() {
		publish(crlOf(root, rootKey, 3), crlOf(sub, subKey, 5))
		before := mustGetCRL(ctx, store)
		rewritten, verdicts := merge(
			ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
			ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		)
		Expect(rewritten).To(BeFalse())
		Expect(verdicts).To(Equal([]error{nil, nil}))
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "an unchanged round must not re-sign")
		Expect(status(urlRoot).LastSuccess).NotTo(BeZero())
	})

	It("replaces an ancestor's CRL with a newer one", func() {
		publish(crlOf(root, rootKey, 3), crlOf(sub, subKey, 5))
		rewritten, verdicts := merge(
			ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 4)},
			ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		)
		Expect(rewritten).To(BeTrue())
		Expect(verdicts).To(Equal([]error{nil, nil}))
		Expect(upstream()).To(Equal(map[string]int64{"Upstream Root CA": 4, "Upstream Sub CA": 5}))
	})

	Describe("an entry that transferred but delivered nothing usable", func() {
		// Every one of these is a failure for its URL even though the fetch
		// itself worked: that is the case the per-URL alert exists for, since
		// readiness and the expiry alerts can both stay green through it.

		It("refuses an older CRL, counts a regression, and keeps the published one", func() {
			publish(crlOf(root, rootKey, 9), crlOf(sub, subKey, 5))
			regressed := myCA.CRLChainRegressed()
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 8)},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(verdicts[0]).To(MatchError(ContainSubstring("older than the one already published")))
			Expect(verdicts[1]).NotTo(HaveOccurred())
			Expect(myCA.CRLChainRegressed()).To(Equal(regressed + 1))
			Expect(upstream()).To(HaveKeyWithValue("Upstream Root CA", int64(9)))
			Expect(status(urlRoot).LastSuccess).To(BeZero())
			Expect(status(urlRoot).Failures).To(BeEquivalentTo(1))
		})

		It("refuses a CRL nothing in the bundle signed, and counts a discard", func() {
			discarded := myCA.CRLChainDiscarded()
			impostor := parseCRLPEM(crlFromImpostorNamed("Upstream Root CA"))
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: impostor},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(verdicts[0]).To(MatchError(ContainSubstring("no certificate in the CA bundle signed")))
			Expect(myCA.CRLChainDiscarded()).To(Equal(discarded + 1))
			Expect(upstream()).NotTo(HaveKey("Upstream Root CA"))
			Expect(status(urlRoot).Failures).To(BeEquivalentTo(1))
		})

		It("refuses this CA's own CRL", func() {
			own := crlBlocks(mustGetCRL(ctx, store))[0]
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: own},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(verdicts[0]).To(MatchError(ContainSubstring("this CA's own CRL")))
			Expect(status(urlRoot).Failures).To(BeEquivalentTo(1))
		})

		It("merges an expired CRL that is still newer, but fails the entry", func() {
			publish(expiredCRL(root, rootKey, 3, 2*time.Hour), crlOf(sub, subKey, 5))
			expired := expiredCRL(root, rootKey, 4, time.Hour)
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: expired},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(verdicts[0]).To(MatchError(ContainSubstring("expired")))
			Expect(upstream()).To(HaveKeyWithValue("Upstream Root CA", int64(4)),
				"newer is strictly better than what agents hold, expired or not")
			Expect(status(urlRoot).LastSuccess).To(BeZero())
			Expect(status(urlRoot).Failures).To(BeEquivalentTo(1))
		})

		It("fails an expired CRL that is merely current", func() {
			stale := expiredCRL(root, rootKey, 3, time.Hour)
			publish(stale, crlOf(sub, subKey, 5))
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: stale},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(verdicts[0]).To(MatchError(ContainSubstring("expired")))
		})

		It("fails a mirror that lags behind what is already published", func() {
			publish(crlOf(root, rootKey, 4))
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 4)},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(root, rootKey, 3)},
			)
			Expect(verdicts[0]).NotTo(HaveOccurred())
			Expect(verdicts[1]).To(MatchError(ContainSubstring("older than the one already published")))
		})
	})

	// Two entries naming one ancestor are mirrors. The newer CRL must win in
	// either order -- the guard that keeps it is invisible when the newer entry
	// happens to come second -- and the lagging mirror still succeeds when it is
	// as new as what agents already hold: that is the success rule.
	DescribeTable("uses the newer of two mirrors, in either order",
		func(first, second int64) {
			publish(crlOf(root, rootKey, 3))
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, first)},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(root, rootKey, second)},
			)
			Expect(upstream()).To(Equal(map[string]int64{"Upstream Root CA": 4}))
			Expect(verdicts).To(Equal([]error{nil, nil}),
				"a mirror as new as the published CRL is current, even if the other is newer")
		},
		Entry("newer second", int64(3), int64(4)),
		Entry("newer first", int64(4), int64(3)),
	)

	Describe("the log for two mirrors", func() {
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
			DeferCleanup(func() { slog.SetDefault(orig) })
			publish(crlOf(root, rootKey, 3))
		})

		It("says nothing when both serve the same CRL, which is a mirror working", func() {
			same := crlOf(root, rootKey, 3)
			merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: same},
				ca.UpstreamFetch{URL: urlSub, CRL: same},
			)
			Expect(buf.String()).NotTo(ContainSubstring("same ancestor"))
		})

		It("names both at Info, the newer as used, when they differ", func() {
			merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(root, rootKey, 4)},
			)
			Expect(buf.String()).To(ContainSubstring("level=INFO"))
			Expect(buf.String()).To(ContainSubstring("served different CRLs"))
			Expect(buf.String()).To(ContainSubstring("used=" + urlSub))
			Expect(buf.String()).To(ContainSubstring("other=" + urlRoot))
			Expect(buf.String()).NotTo(ContainSubstring("level=WARN"))
		})
	})

	It("reports a usable chain once a round stores an upstream CRL, even a partial one", func() {
		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
			{URL: urlSub, Err: errors.New("timeout")},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Usable).To(BeTrue(), "the condition a restart checks, so the one that releases the hold")
	})

	It("reports a usable chain when the only CRL a round stores has expired", func() {
		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: expiredCRL(root, rootKey, 3, time.Hour)},
			{URL: urlSub, Err: errors.New("timeout")},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(upstream()).To(Equal(map[string]int64{"Upstream Root CA": 3}))
		Expect(res.Usable).To(BeTrue(),
			"a restart would not hold on this store either, so the hold must not outlast it")
	})

	It("reports no usable chain when a round stores nothing", func() {
		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, Err: errors.New("timeout")},
			{URL: urlSub, Err: errors.New("timeout")},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Usable).To(BeFalse())
	})

	It("reports a usable chain on a round that finds it already current", func() {
		// How every replica but the first leaves the hold on a fresh store: the
		// first to merge rewrites, and the rest find nothing to change.
		publish(crlOf(root, rootKey, 3), crlOf(sub, subKey, 5))
		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
			{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Rewritten).To(BeFalse(), "precondition: nothing to change")
		Expect(res.Usable).To(BeTrue(), "an unchanged round still leaves an upstream CRL stored")
	})

	It("publishes one CRL per ancestor when the stored chain carries one twice", func() {
		// An import can leave [A#9, A#5]; a round keeps the newest, once.
		publish(crlOf(root, rootKey, 9), crlOf(root, rootKey, 5), crlOf(sub, subKey, 5))
		merge(
			ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 9)},
			ca.UpstreamFetch{URL: urlSub, Err: errors.New("timeout")},
		)
		var roots []int64
		for _, crl := range crlBlocks(mustGetCRL(ctx, store))[1:] {
			if crl.Issuer.CommonName == "Upstream Root CA" {
				roots = append(roots, crl.Number.Int64())
			}
		}
		Expect(roots).To(Equal([]int64{9}), "one block for the ancestor, at its newest")
	})

	// Both stored orders: newest-first catches a "last wins" comparison, the
	// bug monotonicUpstream once had, and oldest-first catches "first wins".
	DescribeTable("judges a fetch against the newest of an ancestor's published CRLs",
		func(stored ...int64) {
			var crls []*x509.RevocationList
			for _, n := range stored {
				crls = append(crls, crlOf(root, rootKey, n))
			}
			publish(crls...)
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 7)},
				ca.UpstreamFetch{URL: urlSub, Err: errors.New("timeout")},
			)
			Expect(verdicts[0]).To(MatchError(ContainSubstring("older than the one already published")),
				"#7 is older than #9, whatever order the two were stored in")
			Expect(upstream()).To(HaveKeyWithValue("Upstream Root CA", BeEquivalentTo(9)))
		},
		Entry("stored newest first", int64(9), int64(5)),
		Entry("stored oldest first", int64(5), int64(9)),
	)

	// The CRL a fetched one could stand in for must be the ancestor's whole
	// list. A delta or an IDP-scoped CRL is genuinely signed, so the signature
	// cannot tell them apart; published, it would un-revoke what it leaves out
	// and then block the real full CRL as a regression.
	DescribeTable("refuses a partial-scope CRL as an ancestor's full list",
		func(oid asn1.ObjectIdentifier) {
			publish(crlOf(root, rootKey, 3))
			discarded := myCA.CRLChainDiscarded()
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: scopedCRLNumbered(root, rootKey, 9, oid)},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(verdicts[0]).To(MatchError(ContainSubstring("not its issuer's full list")))
			Expect(verdicts[1]).NotTo(HaveOccurred())
			Expect(upstream()).To(HaveKeyWithValue("Upstream Root CA", BeEquivalentTo(3)),
				"the full CRL is kept")
			Expect(myCA.CRLChainDiscarded()).To(Equal(discarded + 1))
			Expect(status(urlRoot).Failures).To(BeEquivalentTo(1))

			// And it blocks nothing: the next full CRL is taken as usual.
			_, verdicts = merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 4)},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(verdicts).To(Equal([]error{nil, nil}))
			Expect(upstream()).To(HaveKeyWithValue("Upstream Root CA", BeEquivalentTo(4)))
		},
		Entry("a delta CRL", asn1.ObjectIdentifier{2, 5, 29, 27}),
		Entry("an issuing distribution point", asn1.ObjectIdentifier{2, 5, 29, 28}),
	)

	It("carries this CA's own revocations through a merge that rewrites the chain", func() {
		// The merge re-signs our CRL from the stored one's entries; nothing
		// rebuilds them from the inventory. A merge that dropped them would
		// un-revoke every certificate this CA has revoked, fleet-wide.
		_, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())
		before := crlBlocks(mustGetCRL(ctx, store))[0]
		Expect(before.RevokedCertificateEntries).To(HaveLen(1), "precondition: one revocation")

		rewritten, _ := merge(
			ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
			ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		)
		Expect(rewritten).To(BeTrue(), "precondition: the merge re-signed our CRL")
		after := crlBlocks(mustGetCRL(ctx, store))[0]
		Expect(after.Number.Cmp(before.Number)).To(Equal(1), "our CRL was re-signed with a new number")
		Expect(after.RevokedCertificateEntries).To(HaveLen(1))
		Expect(after.RevokedCertificateEntries[0].SerialNumber).To(Equal(before.RevokedCertificateEntries[0].SerialNumber))
	})

	It("credits an unchanged round on a stored chain already over the bound, since it writes nothing", func() {
		// The bound guards what a round would publish. An import can store a
		// chain over it; a round that changes nothing publishes nothing, so
		// failing its entries would only make every round fail until the
		// upstream next changes.
		big := bigCRL(root, rootKey, 3)
		publish(big, bigCRL(sub, subKey, 5))
		Expect(len(crlBlocksPEM(crlBlocks(mustGetCRL(ctx, store))[1:]))).To(BeNumerically(">", boundedfile.MaxCRLBytes),
			"precondition: the stored upstream chain is over the bound")
		subCRL := crlBlocks(mustGetCRL(ctx, store))[2]
		rewritten, verdicts := merge(
			ca.UpstreamFetch{URL: urlRoot, CRL: big},
			ca.UpstreamFetch{URL: urlSub, CRL: subCRL},
		)
		Expect(rewritten).To(BeFalse())
		Expect(verdicts).To(Equal([]error{nil, nil}))
	})

	Describe("removal", func() {
		// What a round decided is pinned through what an operator sees: the
		// published chain, crl_chain_removed_total and the log. A complete
		// round that may not remove says so at WARN, naming the ancestor it
		// keeps and why; a partial round says nothing (see "an ancestor no
		// entry serves, in a round that may not remove it" below).
		var buf *bytes.Buffer

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })
		})

		// The attack this guards against: over plain http, an attacker on the
		// path answers one entry with another ancestor's CRL (public, and so
		// valid). Were that round allowed to remove, the real ancestor would be
		// dropped, and with nothing published to compare against, a later round
		// could publish an older CRL of it from before a revocation.
		DescribeTable("does not let a round with an http:// entry remove an ancestor, so an older CRL cannot return",
			func(rootURL, subURL string) {
				myCA.SetCRLChainURLs([]string{rootURL, subURL})
				// A third CA in the bundle that no entry is meant to serve: its
				// CRL is public, so an attacker on the path has it. Using it
				// rather than the root's keeps the round unambiguous, so only the
				// http:// rule stands between this round and a removal.
				bystander, bystanderKey, _ := upstreamCAWithKey("Bystander CA")
				ours, err := store.GetCACert(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bystander.Raw})...))).To(Succeed())
				publish(crlOf(root, rootKey, 3), crlOf(sub, subKey, 7))
				removed := myCA.CRLChainRemoved()

				// Round 1: the sub-CA's entry is answered with the bystander's CRL.
				res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
					{URL: rootURL, CRL: crlOf(root, rootKey, 3)},
					{URL: subURL, CRL: crlOf(bystander, bystanderKey, 1)},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(res.Verdicts).To(Equal([]error{nil, nil}), "precondition: every entry named an ancestor")
				Expect(buf.String()).To(ContainSubstring("may not remove it"),
					"precondition: the round was complete, so only the http:// rule kept the ancestor")
				Expect(buf.String()).To(ContainSubstring(`issuer="CN=Upstream Sub CA"`))
				Expect(buf.String()).To(ContainSubstring("plain http://"))
				Expect(upstream()).To(HaveKeyWithValue("Upstream Sub CA", int64(7)))
				Expect(myCA.CRLChainRemoved()).To(Equal(removed))

				// Round 2: an older sub-CA CRL, from before a revocation.
				_, err = myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
					{URL: rootURL, CRL: crlOf(root, rootKey, 3)},
					{URL: subURL, CRL: crlOf(sub, subKey, 5)},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(upstream()).To(HaveKeyWithValue("Upstream Sub CA", int64(7)),
					"the published CRL must never move backwards")
			},
			Entry("when every entry is http://", "http://pki.example/root.crl", "http://pki.example/sub.crl"),
			// Every entry, not any: one https:// entry beside an http:// one
			// must not make the round authoritative.
			Entry("when one entry is https:// and the other http://", urlRoot, "http://pki.example/sub.crl"),
		)

		It("does not let a round remove when two entries name one ancestor, even over https", func() {
			publish(crlOf(root, rootKey, 3), crlOf(sub, subKey, 7))
			res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
				{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				{URL: urlSub, CRL: crlOf(root, rootKey, 3)},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Verdicts).To(Equal([]error{nil, nil}), "precondition: both entries named an ancestor")
			Expect(buf.String()).To(ContainSubstring("may not remove it"))
			Expect(buf.String()).To(ContainSubstring(`issuer="CN=Upstream Sub CA"`))
			Expect(buf.String()).To(ContainSubstring("two entries name the same ancestor"))
			Expect(upstream()).To(HaveKey("Upstream Sub CA"))
		})

		It("lets a file:/// entry take part in an authoritative round", func() {
			const fileSub = "file:///srv/crl/sub.crl"
			myCA.SetCRLChainURLs([]string{urlRoot, fileSub})
			other, otherKey, _ := upstreamCAWithKey("Retired CA")
			ours, err := store.GetCACert(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})...))).To(Succeed())
			publish(crlOf(root, rootKey, 3), crlOf(other, otherKey, 2), crlOf(sub, subKey, 5))
			removed := myCA.CRLChainRemoved()
			_, err = myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
				{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				{URL: fileSub, CRL: crlOf(sub, subKey, 5)},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(upstream()).NotTo(HaveKey("Retired CA"))
			Expect(myCA.CRLChainRemoved()).To(Equal(removed + 1))
		})

		It("does not let an entry serving this CA's own CRL stop a round being complete", func() {
			// A published ancestor no entry serves: a complete round names it
			// in a warning, and a partial one says nothing.
			retired, retiredKey, _ := upstreamCAWithKey("Retired CA")
			ours, err := store.GetCACert(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: retired.Raw})...))).To(Succeed())
			publish(crlOf(root, rootKey, 3), crlOf(retired, retiredKey, 2), crlOf(sub, subKey, 5))
			own := crlBlocks(mustGetCRL(ctx, store))[0]
			const ownURL = "https://pki.example/self.crl"
			myCA.SetCRLChainURLs([]string{urlRoot, urlSub, ownURL})
			res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
				{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
				{URL: ownURL, CRL: own},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Verdicts[2]).To(MatchError(ContainSubstring("this CA's own CRL")))
			Expect(buf.String()).To(ContainSubstring("may not remove it"),
				"the entry names no ancestor, so it is ignored and the round stays complete")
			Expect(buf.String()).To(ContainSubstring(`issuer="CN=Retired CA"`))
		})

		It("counts an entry whose CRL is older than the one published as naming its ancestor", func() {
			// Its verdict fails, but the CRL still names its ancestor, so the
			// round is complete and, every entry being https://, may remove the
			// ancestor nothing serves.
			retired, retiredKey, _ := upstreamCAWithKey("Retired CA")
			ours, err := store.GetCACert(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: retired.Raw})...))).To(Succeed())
			publish(crlOf(root, rootKey, 3), crlOf(retired, retiredKey, 2), crlOf(sub, subKey, 5))
			removed := myCA.CRLChainRemoved()
			res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
				{URL: urlRoot, CRL: crlOf(root, rootKey, 2)},
				{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Verdicts[0]).To(HaveOccurred(), "precondition: the older CRL is refused")
			Expect(upstream()).NotTo(HaveKey("Retired CA"))
			Expect(upstream()).To(HaveKeyWithValue("Upstream Root CA", int64(3)), "the published CRL is kept")
			Expect(myCA.CRLChainRemoved()).To(Equal(removed + 1))
		})

		// The same attack as over http://, by an origin that is authenticated
		// but answers with this CA's own CRL, which is public: the entry is
		// ignored, so the round stays complete without the ancestor it is
		// meant to serve.
		It("does not let an entry serving this CA's own CRL remove an ancestor, so an older CRL cannot return", func() {
			own := crlBlocks(mustGetCRL(ctx, store))[0]
			publish(crlOf(root, rootKey, 3), crlOf(sub, subKey, 7))
			removed := myCA.CRLChainRemoved()

			// Round 1: the sub-CA's entry is answered with this CA's own CRL.
			res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
				{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				{URL: urlSub, CRL: own},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Verdicts[1]).To(MatchError(ContainSubstring("this CA's own CRL")))
			Expect(buf.String()).To(ContainSubstring("may not remove it"),
				"precondition: the own-CRL entry is ignored, not partial")
			Expect(buf.String()).To(ContainSubstring(`issuer="CN=Upstream Sub CA"`))
			Expect(buf.String()).To(ContainSubstring("an entry serves this CA's own CRL"))
			Expect(upstream()).To(HaveKeyWithValue("Upstream Sub CA", int64(7)))
			Expect(myCA.CRLChainRemoved()).To(Equal(removed))

			// Round 2: an older sub-CA CRL, from before a revocation.
			_, err = myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
				{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(upstream()).To(HaveKeyWithValue("Upstream Sub CA", int64(7)),
				"the published CRL must never move backwards")
		})

		Context("with a published CRL nothing in the bundle signs", func() {
			BeforeEach(func() {
				other, otherKey, _ := upstreamCAWithKey("Departed CA")
				ours, err := store.GetCACert(ctx)
				Expect(err).NotTo(HaveOccurred())
				withOther := append(append([]byte{}, ours...),
					pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})...)
				Expect(store.SaveCACert(ctx, withOther)).To(Succeed())
				publish(crlOf(root, rootKey, 3), crlOf(other, otherKey, 2), crlOf(sub, subKey, 5))
				// The certificate leaves the bundle; its CRL stays published.
				bundle := append([]byte{}, ours...)
				for _, cert := range []*x509.Certificate{root, sub} {
					bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
				}
				Expect(store.SaveCACert(ctx, bundle)).To(Succeed())
			})

			It("keeps it through a partial round", func() {
				removed := myCA.CRLChainRemoved()
				merge(
					ca.UpstreamFetch{URL: urlRoot, Err: errors.New("timeout")},
					ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 6)},
				)
				Expect(upstream()).To(HaveKey("Departed CA"))
				Expect(myCA.CRLChainRemoved()).To(Equal(removed))
			})

			It("drops it on an authoritative round, counting it once", func() {
				removed := myCA.CRLChainRemoved()
				round := func() {
					merge(
						ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
						ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
					)
				}
				round()
				Expect(upstream()).NotTo(HaveKey("Departed CA"))
				Expect(myCA.CRLChainRemoved()).To(Equal(removed + 1))
				round()
				Expect(myCA.CRLChainRemoved()).To(Equal(removed + 1))
			})

			It("counts one removal for an issuer published twice", func() {
				// Nothing ties two blocks from an unattributable issuer to one
				// ancestor but the issuer name, so it is counted, and logged, once.
				other := crlBlocks(mustGetCRL(ctx, store))[2]
				blob := mustGetCRL(ctx, store)
				Expect(store.UpdateCRL(ctx, append(append([]byte{}, blob...),
					crlBlocksPEM([]*x509.RevocationList{other})...))).To(Succeed())
				Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(5), "precondition: the departed issuer published twice")
				removed := myCA.CRLChainRemoved()
				merge(
					ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
					ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
				)
				Expect(upstream()).NotTo(HaveKey("Departed CA"))
				Expect(myCA.CRLChainRemoved()).To(Equal(removed + 1))
			})
		})

		It("never removes an ancestor on a partial round", func() {
			publish(crlOf(root, rootKey, 3), crlOf(sub, subKey, 5))
			removed := myCA.CRLChainRemoved()
			_, verdicts := merge(
				ca.UpstreamFetch{URL: urlRoot, Err: errors.New("connection refused")},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 6)},
			)
			Expect(verdicts[0]).To(MatchError("connection refused"))
			Expect(upstream()).To(Equal(map[string]int64{"Upstream Root CA": 3, "Upstream Sub CA": 6}))
			Expect(myCA.CRLChainRemoved()).To(Equal(removed))
			Expect(status(urlRoot).Failures).To(BeEquivalentTo(1))
		})

		It("does not treat an unusable entry as completing the round", func() {
			// An impostor CRL is fetched successfully but names no ancestor, so
			// the round cannot say which ancestors the list covers.
			publish(crlOf(root, rootKey, 3), crlOf(sub, subKey, 5))
			merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: parseCRLPEM(crlFromImpostorNamed("Upstream Root CA"))},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(upstream()).To(HaveKey("Upstream Root CA"))
		})

		It("drops, once, an ancestor no entry served in a complete round", func() {
			other, otherKey, _ := upstreamCAWithKey("Retired CA")
			ours, err := store.GetCACert(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})...))).To(Succeed())
			publish(crlOf(root, rootKey, 3), crlOf(other, otherKey, 2), crlOf(sub, subKey, 5))
			removed := myCA.CRLChainRemoved()

			merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(upstream()).To(Equal(map[string]int64{"Upstream Root CA": 3, "Upstream Sub CA": 5}))
			Expect(myCA.CRLChainRemoved()).To(Equal(removed+1),
				"exactly one: the counter reports a transition, not a re-evaluation")

			merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
			)
			Expect(myCA.CRLChainRemoved()).To(Equal(removed + 1))
		})
	})

	It("keeps fetched ancestors through a revocation, which never fetches", func() {
		// Between rounds every amendment carries the stored ancestors forward:
		// the revocation path must not need, or reach, any upstream.
		merge(
			ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
			ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		)
		_, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())
		Expect(upstream()).To(Equal(map[string]int64{"Upstream Root CA": 3, "Upstream Sub CA": 5}))
	})

	It("counts a fetch failure even when the merge itself fails, and credits nothing", func() {
		refusing := &crlLockRefusingBackend{Backend: store.Backend()}
		myCA.Storage = storage.NewWithBackend(refusing, filepath.Join(GinkgoT().TempDir(), "private"))
		_, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, Err: errors.New("connection refused")},
			{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		})
		Expect(err).To(HaveOccurred())
		Expect(status(urlRoot).Failures).To(BeEquivalentTo(1), "the fetch failed whatever the merge did")
		Expect(status(urlSub).Failures).To(BeZero(), "the merge's failure is not the URL's")
		Expect(status(urlSub).LastSuccess).To(BeZero())
	})

	It("counts a CA bundle that cannot be read as a CRL update failure, not against any URL", func() {
		myCA.Storage = storage.NewWithBackend(&caCertFailingBackend{Backend: store.Backend()},
			filepath.Join(GinkgoT().TempDir(), "private"))
		before := myCA.CRLUpdateFailures()
		_, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
		})
		Expect(err).To(HaveOccurred())
		Expect(myCA.CRLUpdateFailures()).To(Equal(before + 1))
		Expect(status(urlRoot).Failures).To(BeZero())
		Expect(status(urlRoot).LastSuccess).To(BeZero())
	})

	It("records what it judged, but credits and removes nothing, when the write fails", func() {
		// The write is the last step: the round has been judged by then, so
		// its verdicts stand, but nothing it decided has landed.
		other, otherKey, _ := upstreamCAWithKey("Retired CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw})...))).To(Succeed())
		publish(crlOf(root, rootKey, 3), crlOf(other, otherKey, 2), crlOf(sub, subKey, 5))
		failing := &crlWriteFailingBackend{Backend: store.Backend()}
		myCA.Storage = storage.NewWithBackend(failing, filepath.Join(GinkgoT().TempDir(), "private"))
		removed := myCA.CRLChainRemoved()
		updateFailures := myCA.CRLUpdateFailures()

		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: crlOf(root, rootKey, 2)}, // regressed: judged a failure
			{URL: urlSub, CRL: crlOf(sub, subKey, 6)},    // newer: would have been merged
		})
		Expect(err).To(HaveOccurred())
		Expect(failing.refused).To(BeNumerically(">", 0), "the fixture must have refused the CRL write")
		Expect(res.Usable).To(BeFalse(), "nothing landed, so nothing may release the hold")
		Expect(status(urlRoot).Failures).To(BeEquivalentTo(1), "a regression is the entry's fault, whatever happened next")
		Expect(status(urlSub).Failures).To(BeZero())
		for _, st := range myCA.UpstreamFetchStatuses() {
			Expect(st.LastSuccess).To(BeZero(), st.URL)
		}
		Expect(myCA.CRLChainRemoved()).To(Equal(removed), "a removal that did not land did not happen")
		Expect(myCA.CRLUpdateFailures()).To(Equal(updateFailures+1), "a write that failed is a CRL update failure")
	})

	It("credits no entry when the merge itself fails", func() {
		// A CRL lock that cannot be taken: the fetch worked, but nothing
		// landed, and the fault is not the URL's.
		refusing := &crlLockRefusingBackend{Backend: store.Backend()}
		myCA.Storage = storage.NewWithBackend(refusing, filepath.Join(GinkgoT().TempDir(), "private"))
		before := myCA.CRLUpdateFailures()
		_, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
			{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		})
		Expect(err).To(HaveOccurred())
		Expect(refusing.refused).To(BeNumerically(">", 0), "the fixture must have refused the CRL lock")
		Expect(myCA.CRLUpdateFailures()).To(Equal(before+1), "a lock that could not be taken is a CRL update failure")
		for _, st := range myCA.UpstreamFetchStatuses() {
			Expect(st.LastSuccess).To(BeZero(), st.URL)
			Expect(st.Failures).To(BeZero(), st.URL)
		}
	})

	It("counts a published chain that cannot be decoded as a CRL update failure, not against any URL", func() {
		// Our CRL reads, so readStoredCRL passes; a trailing block that is
		// not a CRL fails the merge's own decode of the published ancestors.
		blob := append(append([]byte{}, mustGetCRL(ctx, store)...),
			pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte{1, 2, 3}})...)
		Expect(store.Backend().Put(ctx, storage.KeyCRL, blob, storage.BlobPublic)).To(Succeed())
		before := myCA.CRLUpdateFailures()
		_, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
		})
		Expect(err).To(HaveOccurred())
		Expect(myCA.CRLUpdateFailures()).To(Equal(before + 1))
		Expect(status(urlRoot)).To(Equal(ca.UpstreamFetchStatus{URL: urlRoot}), "neither credited nor failed")
	})

	Describe("an entry that delivered neither a CRL nor an error", func() {
		// Outside the producer's contract, but judged rather than trusted.
		It("fails it as having no CRL", func() {
			_, verdicts := merge(ca.UpstreamFetch{URL: urlRoot}, ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)})
			Expect(verdicts[0]).To(MatchError("no CRL"))
			Expect(status(urlRoot).Failures).To(BeEquivalentTo(1))
		})

		It("fails it even when the merge itself fails", func() {
			refusing := &crlLockRefusingBackend{Backend: store.Backend()}
			myCA.Storage = storage.NewWithBackend(refusing, filepath.Join(GinkgoT().TempDir(), "private"))
			_, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{{URL: urlRoot}})
			Expect(err).To(HaveOccurred())
			Expect(status(urlRoot).Failures).To(BeEquivalentTo(1), "it fetched nothing, whatever happened next")
		})
	})

	It("refuses a round that would publish more than crl_chain.file may, and keeps the chain", func() {
		// Each entry is within the per-entry bound; together they are not.
		big1, big2 := bigCRL(root, rootKey, 3), bigCRL(sub, subKey, 5)
		Expect(len(big1.Raw)).To(BeNumerically("<", boundedfile.MaxCRLBytes/2), "precondition: each entry alone is fine")
		Expect(len(crlBlocksPEM([]*x509.RevocationList{big1, big2}))).To(BeNumerically(">", boundedfile.MaxCRLBytes),
			"precondition: together they exceed the bound")
		publish(crlOf(root, rootKey, 2))
		before := mustGetCRL(ctx, store)

		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: big1},
			{URL: urlSub, CRL: big2},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Rewritten).To(BeFalse())
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "the published chain is kept as it was")
		for i, v := range res.Verdicts {
			Expect(v).To(MatchError(ContainSubstring("over the %d-byte bound", boundedfile.MaxCRLBytes)), "entry %d", i)
		}
		for _, st := range myCA.UpstreamFetchStatuses() {
			Expect(st.Failures).To(BeEquivalentTo(1), st.URL)
			Expect(st.LastSuccess).To(BeZero(), st.URL)
		}
		Expect(res.Usable).To(BeTrue(), "what was already published is still there")
	})

	It("publishes a large ancestor's update that keeps the chain within the bound", func() {
		// The other side of the bound: the chain as it would be after the round
		// is what is measured, not that plus what it replaces, and the bound is
		// boundedfile.MaxCRLBytes, not something tighter.
		publish(bigCRL(root, rootKey, 3))
		next := bigCRL(root, rootKey, 4)
		Expect(len(crlBlocksPEM([]*x509.RevocationList{next}))).To(BeNumerically(">", boundedfile.MaxCRLBytes/2),
			"precondition: more than half the bound, so counting the replaced CRL too would refuse it")
		rewritten, verdicts := merge(
			ca.UpstreamFetch{URL: urlRoot, CRL: next},
			ca.UpstreamFetch{URL: urlSub, CRL: crlOf(sub, subKey, 5)},
		)
		Expect(rewritten).To(BeTrue())
		Expect(verdicts).To(Equal([]error{nil, nil}))
		Expect(upstream()).To(Equal(map[string]int64{"Upstream Root CA": 4, "Upstream Sub CA": 5}))
	})

	It("keeps holding readiness when an over-bound round arrives on a store with no upstream CRL", func() {
		// Usable is what releases the hold: a round that wrote nothing must
		// not report one, or a fresh pod goes ready with no ancestor stored.
		before := mustGetCRL(ctx, store)
		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: bigCRL(root, rootKey, 3)},
			{URL: urlSub, CRL: bigCRL(sub, subKey, 5)},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Rewritten).To(BeFalse())
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "nothing is written")
		Expect(res.Usable).To(BeFalse(), "no upstream CRL is stored, so the hold must not be released")
	})

	It("fails an already-current entry too in an over-bound round, since the round as a whole is refused", func() {
		current := bigCRL(root, rootKey, 3)
		publish(current)
		res, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: current},
			{URL: urlSub, CRL: bigCRL(sub, subKey, 5)},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Rewritten).To(BeFalse())
		Expect(res.Verdicts[0]).To(MatchError(ContainSubstring("over the %d-byte bound", boundedfile.MaxCRLBytes)),
			"an entry that adds nothing still fails: the round is refused, not the entries it would add")
		Expect(status(urlRoot).LastSuccess).To(BeZero())
		Expect(status(urlRoot).Failures).To(BeEquivalentTo(1))
	})

	It("counts a stored CRL that cannot be read as one CRL update failure, not against any URL", func() {
		// readStoredCRL counts centrally, so the merge must not count again.
		Expect(store.Backend().Put(ctx, storage.KeyCRL,
			[]byte("-----BEGIN X509 CRL-----\nnot a CRL\n-----END X509 CRL-----\n"), storage.BlobPublic)).To(Succeed())
		before := myCA.CRLUpdateFailures()
		_, err := myCA.MergeFetchedUpstreamCRLs(ctx, []ca.UpstreamFetch{
			{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
		})
		Expect(err).To(HaveOccurred())
		Expect(myCA.CRLUpdateFailures()).To(Equal(before+1), "counted once, by readStoredCRL")
		Expect(status(urlRoot)).To(Equal(ca.UpstreamFetchStatus{URL: urlRoot}), "neither credited nor failed")
	})

	Describe("an ancestor no entry serves, in a round that may not remove it", func() {
		var buf *bytes.Buffer

		// A published ancestor the list has stopped serving -- most often one
		// an operator meant to retire -- beside root and sub. Each row's
		// entries serve root and, depending on the row, sub, a mirror of root,
		// or this CA's own CRL.
		BeforeEach(func() {
			buf = &bytes.Buffer{}
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })
			retired, retiredKey, _ := upstreamCAWithKey("Retired CA")
			ours, err := store.GetCACert(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: retired.Raw})...))).To(Succeed())
			publish(crlOf(root, rootKey, 3), crlOf(retired, retiredKey, 2), crlOf(sub, subKey, 5))
		})

		DescribeTable("is kept, and the log says why",
			func(urls []string, second func() *x509.RevocationList, reason string) {
				myCA.SetCRLChainURLs(urls)
				merge(
					ca.UpstreamFetch{URL: urls[0], CRL: crlOf(root, rootKey, 3)},
					ca.UpstreamFetch{URL: urls[1], CRL: second()},
				)
				Expect(upstream()).To(HaveKey("Retired CA"), "precondition: kept")
				Expect(buf.String()).To(ContainSubstring("may not remove it"))
				Expect(buf.String()).To(ContainSubstring(`issuer="CN=Retired CA"`))
				Expect(buf.String()).To(ContainSubstring(reason))
			},
			Entry("because an entry is plain http://",
				[]string{urlRoot, "http://pki.example/sub.crl"},
				func() *x509.RevocationList { return crlOf(sub, subKey, 5) },
				"plain http://"),
			Entry("because two entries name the same ancestor",
				[]string{urlRoot, "https://mirror.example/root.crl"},
				func() *x509.RevocationList { return crlOf(root, rootKey, 3) },
				"two entries name the same ancestor"),
			Entry("because an entry serves this CA's own CRL",
				[]string{urlRoot, urlSub},
				func() *x509.RevocationList { return crlBlocks(mustGetCRL(ctx, store))[0] },
				"an entry serves this CA's own CRL"),
		)

		It("says nothing of it in a partial round, which never removes anything", func() {
			merge(
				ca.UpstreamFetch{URL: urlRoot, CRL: crlOf(root, rootKey, 3)},
				ca.UpstreamFetch{URL: urlSub, Err: errors.New("connection refused")},
			)
			Expect(upstream()).To(HaveKey("Retired CA"), "precondition: kept")
			Expect(buf.String()).NotTo(ContainSubstring("may not remove it"))
		})
	})
})

// bigCRL issues a CRL from cert listing enough revocations to weigh a little
// over half of boundedfile.MaxCRLBytes as PEM, so two of them exceed it.
func bigCRL(cert *x509.Certificate, key crypto.Signer, number int64) *x509.RevocationList {
	GinkgoHelper()
	now := time.Now().UTC()
	entries := make([]x509.RevocationListEntry, 72000)
	for i := range entries {
		entries[i] = x509.RevocationListEntry{SerialNumber: big.NewInt(int64(1_000_000_000 + i)), RevocationTime: now}
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                now,
		NextUpdate:                now.Add(30 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

// expiredCRL issues an empty CRL from cert whose NextUpdate passed ago, with a
// ThisUpdate a day before that.
func expiredCRL(cert *x509.Certificate, key crypto.Signer, number int64, ago time.Duration) *x509.RevocationList {
	GinkgoHelper()
	next := time.Now().UTC().Add(-ago)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: next.Add(-24 * time.Hour),
		NextUpdate: next,
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

var _ = Describe("HoldReadinessForUpstreamChain", func() {
	var (
		ctx   context.Context
		store *storage.StorageService
		myCA  *ca.CA
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	publish := func(blob []byte) {
		GinkgoHelper()
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, mustGetCRL(ctx, store)...), blob...))).To(Succeed())
	}

	It("holds readiness on a store with no upstream CRL, until released once", func() {
		Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeTrue())
		Expect(myCA.UpstreamChainHeld()).To(BeTrue())
		Expect(myCA.ReleaseUpstreamChainHold()).To(BeTrue())
		Expect(myCA.UpstreamChainHeld()).To(BeFalse())
		Expect(myCA.ReleaseUpstreamChainHold()).To(BeFalse(), "a release reports only the first")
	})

	It("does not hold when an upstream CRL is stored", func() {
		_, upsCRL := upstreamCA("Upstream Root CA")
		publish(upsCRL)
		Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeFalse())
		Expect(myCA.UpstreamChainHeld()).To(BeFalse())
	})

	// Every merge fails on such a chain until it is repaired, so nothing could
	// release the hold, and a running pod that met it stays ready.
	DescribeTable("does not hold when the stored chain cannot be decoded, and says so",
		func(blob []byte, cause string) {
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })
			Expect(store.Backend().Put(ctx, storage.KeyCRL, blob, storage.BlobPublic)).To(Succeed())
			Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeFalse())
			Expect(myCA.UpstreamChainHeld()).To(BeFalse())
			Expect(buf.String()).To(ContainSubstring("Could not decode the stored CRL chain"))
			Expect(buf.String()).To(ContainSubstring(cause))
		},
		Entry("a CRL block that does not parse",
			pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte("not a CRL")}), "x509:"),
		// Not even this CA's own, which Init always writes: corrupt, not empty.
		Entry("no CRL at all", []byte("not PEM at all\n"), "holds no CRL"),
	)

	It("holds when the stored chain cannot be read, and says so", func() {
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(func() { slog.SetDefault(orig) })
		myCA.Storage = storage.NewWithBackend(&crlReadFailingBackend{Backend: store.Backend()},
			filepath.Join(GinkgoT().TempDir(), "private"))
		Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeTrue(), "a chain that cannot be read is treated as empty")
		Expect(myCA.UpstreamChainHeld()).To(BeTrue())
		Expect(buf.String()).To(ContainSubstring("Could not read the stored CRL chain"))
	})

	It("does not hold when every stored upstream CRL has expired", func() {
		// A running pod in this state stays ready, so a restarted one must
		// too: holding here would take a restarted CA out of its Service until
		// the upstream recovered.
		cert, key, _ := upstreamCAWithKey("Lapsed Root CA")
		publish(crlBlocksPEM([]*x509.RevocationList{expiredCRL(cert, key, 3, time.Hour)}))
		Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeFalse())
		Expect(myCA.UpstreamChainHeld()).To(BeFalse())
	})
})

// caCertFailingBackend fails every read of the CA bundle, and grants every
// lock, so a spec can reach the merge's bundle-read arm.
type caCertFailingBackend struct {
	storage.Backend
}

func (b *caCertFailingBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeyCACert {
		return nil, errors.New("bundle unavailable")
	}
	return b.Backend.Get(ctx, key)
}

func (b *caCertFailingBackend) AcquireLock(context.Context, string) (storage.Unlocker, error) {
	return grantedLock{}, nil
}

// crlReadFailingBackend fails every read of the CRL, so a spec can reach the
// readiness hold's read-error arm.
type crlReadFailingBackend struct {
	storage.Backend
}

func (b *crlReadFailingBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeyCRL {
		return nil, errors.New("CRL unavailable")
	}
	return b.Backend.Get(ctx, key)
}

// crlWriteFailingBackend refuses every write of the CRL, and grants every
// lock, so a spec can reach a merge that fails after it has judged the round.
type crlWriteFailingBackend struct {
	storage.Backend
	refused int
}

func (b *crlWriteFailingBackend) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if key == storage.KeyCRL {
		b.refused++
		return errors.New("CRL write refused")
	}
	return b.Backend.Put(ctx, key, data, kind)
}

func (b *crlWriteFailingBackend) AcquireLock(context.Context, string) (storage.Unlocker, error) {
	return grantedLock{}, nil
}

// crlBlocksPEM re-encodes parsed CRLs as a PEM chain.
func crlBlocksPEM(crls []*x509.RevocationList) []byte {
	var out []byte
	for _, crl := range crls {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw})...)
	}
	return out
}

// scopedCRLNumbered issues a CRL from cert carrying a scope-limiting extension,
// the delta CRL indicator or an issuing distribution point. The value is
// deliberately not well formed: the refusal keys on the extension's presence.
func scopedCRLNumbered(cert *x509.Certificate, key crypto.Signer, number int64, oid asn1.ObjectIdentifier) *x509.RevocationList {
	GinkgoHelper()
	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:          big.NewInt(number),
		ThisUpdate:      now,
		NextUpdate:      now.Add(30 * 24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oid, Value: []byte{0x30, 0x00}}},
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	return crl
}
