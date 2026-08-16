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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/api"
)

// numberedCRLFrom is crlFrom with the CRL number under the caller's control,
// which is what a replay test needs: two CRLs from one issuer, both valid, in a
// defined order.
//
// ThisUpdate is a constant offset before notAfter, so callers passing notAfter
// values relative to `future` keep the exact relative ordering they intend
// while every CRL is dated in the past like a real one. The offset is four days
// more than `future`'s thirty, which leaves only about a day in hand for the
// largest offset any caller uses (`future.Add(72 * time.Hour)`) -- so the
// assertion below states the invariant rather than trusting the arithmetic.
//
// Dating ThisUpdate 24 hours before a notAfter thirty days out put every
// fixture's issue date in the *future*, which is not a shape any issuer
// produces and which hid a bug where a future-dated CRL pinned an anchor's
// freshness mark for ever.
func numberedCRLFrom(cert *x509.Certificate, key *ecdsa.PrivateKey, notAfter time.Time, number int64) *x509.RevocationList {
	GinkgoHelper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: notAfter.Add(-34 * 24 * time.Hour),
		NextUpdate: notAfter,
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	Expect(crl.ThisUpdate).To(BeTemporally("<", time.Now()),
		"a fixture dated in the future exercises the not-yet-valid path instead of the "+
			"ordering it means to test, which has hidden a bug once")
	return crl
}

// scopedCRLFrom issues a CRL carrying a scope-limiting extension: either the
// delta CRL indicator (2.5.29.27) or an issuing distribution point (2.5.29.28).
// Both mean the list is a fraction of what the issuer has revoked.
func scopedCRLFrom(cert *x509.Certificate, key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier, revoked ...*big.Int) *x509.RevocationList {
	GinkgoHelper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, serial := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	// The value is deliberately not a well-formed IDP or base-CRL number. The
	// refusal keys on the extension being *present*, so a spec that supplied a
	// valid one would leave the parsing this code declines to do looking
	// necessary.
	ext := pkix.Extension{Id: oid, Value: []byte{0x30, 0x00}}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		RevokedCertificateEntries: entries,
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(time.Hour),
		ExtraExtensions:           []pkix.Extension{ext},
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

// crlFrom issues a CRL from cert covering the given serials, expiring at
// notAfter.
func crlFrom(cert *x509.Certificate, key *ecdsa.PrivateKey, notAfter time.Time, revoked ...*big.Int) *x509.RevocationList {
	GinkgoHelper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, serial := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		RevokedCertificateEntries: entries,
		// Derived from notAfter so an already-expired CRL is still
		// well-formed: x509 rejects ThisUpdate at or after NextUpdate.
		ThisUpdate: notAfter.Add(-24 * time.Hour),
		NextUpdate: notAfter,
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

// withSKI gives a certificate a Subject Key Identifier. CRL matching no longer
// needs one -- it is by signature -- but the impostor spec forges an AKI to
// prove the field is ignored, and needs a real SKI to forge it from.
func withSKI(cert *x509.Certificate) *x509.Certificate {
	GinkgoHelper()
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	sum := sha1.Sum(pubDER)
	cert.SubjectKeyId = sum[:]
	return cert
}

// reissueCert mints a second certificate over cert's existing key: what a CA
// that renews its own certificate produces, and what an operator has in the
// bundle during the overlap.
func reissueCert(cert *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	GinkgoHelper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               cert.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	Expect(err).NotTo(HaveOccurred())
	out, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return withSKI(out)
}

var _ = Describe("Client CRL checking", func() {
	var (
		root     *x509.Certificate
		rootKey  *ecdsa.PrivateKey
		serverCA *x509.Certificate
		caKey    *ecdsa.PrivateKey
		leaf     *x509.Certificate
		future   time.Time
		past     time.Time
	)

	BeforeEach(func() {
		root, rootKey = mintCert("Shared Root", nil, nil, true)
		serverCA, caKey = mintCert("Server CA", root, rootKey, true)
		leaf, _ = mintCert("agent.example.com", serverCA, caKey, false)
		withSKI(root)
		withSKI(serverCA)
		future = time.Now().Add(24 * time.Hour)
		past = time.Now().Add(-time.Hour)
	})

	// chain is what Verify returns when anchored on the root: leaf, CA, root.
	chain := func() []*x509.Certificate { return []*x509.Certificate{leaf, serverCA, root} }

	// anchorSet is what the entry trusts. NewClientCRLSet takes it because a
	// CRL is filed under the certificate that signed it, never under what its
	// Authority Key Identifier claims -- so a set cannot be built without
	// saying which keys are allowed to speak.
	anchorSet := func() []*x509.Certificate { return []*x509.Certificate{serverCA, root} }

	Describe("under require", func() {
		It("accepts a chain whose every issuer has a valid CRL", func() {
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future),
				crlFrom(root, rootKey, future),
			}, anchorSet())
			Expect(api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())).To(Succeed())
		})

		It("rejects a revoked leaf", func() {
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future, leaf.SerialNumber),
				crlFrom(root, rootKey, future),
			}, anchorSet())
			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("agent.example.com")))
		})

		It("rejects a leaf whose issuing CA the root revoked", func() {
			// The whole point of walking the chain: a sibling CA revoked by the
			// shared root must not go on authenticating its leaves. Checking
			// only the leaf is the same downgrade certificate_revocation=leaf
			// makes for agents.
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future),
				crlFrom(root, rootKey, future, serverCA.SerialNumber),
			}, anchorSet())
			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("Server CA")))
		})

		It("rejects when an issuer has no CRL at all", func() {
			set := api.NewClientCRLSet([]*x509.RevocationList{crlFrom(serverCA, caKey, future)}, anchorSet())
			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("no currently valid CRL")))
		})

		It("treats an expired CRL as absent", func() {
			// Without this, require silently degrades to skip over time: an
			// expired CRL would keep satisfying "has a CRL" while saying
			// nothing about revocations since.
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, past),
				crlFrom(root, rootKey, future),
			}, anchorSet())
			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("no currently valid CRL")))
		})

		It("still consults an expired CRL under check", func() {
			// "check" means verify against whatever CRLs are loaded and allow an
			// issuer that has none. An expired CRL is loaded, and the serials it
			// names are still revoked — discarding it would turn a stale CRL
			// into no revocation checking at all, which is the outcome check
			// exists to avoid.
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, past, leaf.SerialNumber),
			}, anchorSet())
			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationCheck, time.Now())
			Expect(err).To(MatchError(ContainSubstring("is revoked")))
		})

		It("rejects a certificate that is itself the anchor", func() {
			// A client_ca entry makes this reachable. Nothing can attest to its
			// revocation status, so require must not pass it silently.
			err := api.CheckChainRevocationForTest([]*x509.Certificate{serverCA}, api.NewClientCRLSet(nil, anchorSet()),
				api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("itself a trust anchor")))
			Expect(errors.Is(err, api.ErrNoUsableCRL)).To(BeTrue(),
				"nothing can attest to an anchor's status, so this is absence too")
		})

		It("never checks the anchor itself, even when the anchor is revoked", func() {
			// Deliberate and universal: a trust anchor is trusted by
			// configuration, not by anything it presents. The consequence is
			// that revoking a trusted domain is an operator action — remove the
			// client_ca entry — not a CRL event.
			//
			// Here the chain is anchored on the Server CA, so the root's
			// revocation of it is structurally outside the walk.
			shortChain := []*x509.Certificate{leaf, serverCA}
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future),
				crlFrom(root, rootKey, future, serverCA.SerialNumber),
			}, anchorSet())
			Expect(api.CheckChainRevocationForTest(shortChain, set, api.RevocationRequire, time.Now())).To(Succeed())
		})
	})

	Describe("under check", func() {
		It("allows an issuer with no CRL", func() {
			set := api.NewClientCRLSet([]*x509.RevocationList{crlFrom(serverCA, caKey, future)}, anchorSet())
			Expect(api.CheckChainRevocationForTest(chain(), set, api.RevocationCheck, time.Now())).To(Succeed())
		})

		It("still rejects a revocation it can see", func() {
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future, leaf.SerialNumber),
			}, anchorSet())
			Expect(api.CheckChainRevocationForTest(chain(), set, api.RevocationCheck, time.Now())).To(HaveOccurred())
		})

		It("allows a self-anchored certificate", func() {
			err := api.CheckChainRevocationForTest([]*x509.Certificate{serverCA}, api.NewClientCRLSet(nil, anchorSet()),
				api.RevocationCheck, time.Now())
			Expect(err).To(Succeed())
		})
	})

	Describe("under skip", func() {
		It("allows even a certificate it knows is revoked", func() {
			// Documented as unsafe; asserted so the setting means what it says.
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future, leaf.SerialNumber),
			}, anchorSet())
			Expect(api.CheckChainRevocationForTest(chain(), set, api.RevocationSkip, time.Now())).To(Succeed())
		})
	})

	Describe("CRL matching", func() {
		It("honours a CRL with no Authority Key Identifier, because matching is by signature", func() {
			// Matching used to be by the CRL's own AKI against the issuer's SKI,
			// which meant an issuer that omits the extension had its revocations
			// silently ignored. RFC 5280 §5.2.1 requires a conforming CRL issuer
			// to include it, but not every issuer conforms, and a CRL whose
			// signature verifies needs no field this CA does not read.
			// Filing under the certificate that actually signed the CRL removes
			// the dependence on anything the CRL asserts about itself, so this
			// revocation is seen.
			crl := crlFrom(serverCA, caKey, future, leaf.SerialNumber)
			crl.AuthorityKeyId = nil
			set := api.NewClientCRLSet([]*x509.RevocationList{crl, crlFrom(root, rootKey, future)},
				anchorSet())

			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("agent.example.com")))
		})

		It("will not let one anchor supply the CRL consulted for another", func() {
			// SECURITY: the Authority Key Identifier lives inside the signed TBS,
			// so the CA that signs a CRL chooses what it claims -- and a
			// client_ca entry may name a CA the operator does not control. When
			// the set filed by that claim, a co-anchor could mint an empty CRL
			// asserting a sibling's key identifier and satisfy `require` for the
			// sibling while saying nothing about the sibling's revocations: a
			// client the sibling had revoked was then admitted.
			//
			// root signs this one, but it claims to speak for serverCA.
			impostor := crlFrom(root, rootKey, future)
			impostor.AuthorityKeyId = serverCA.SubjectKeyId
			set := api.NewClientCRLSet([]*x509.RevocationList{
				impostor,
				crlFrom(root, rootKey, future),
			}, anchorSet())

			// serverCA still has no CRL of its own, so require must refuse.
			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("no currently valid CRL")))
			Expect(err).To(MatchError(ContainSubstring("Server CA")))
			Expect(errors.Is(err, api.ErrNoUsableCRL)).To(BeTrue(),
				"absence, not revocation -- this is what the refusals counter keys on")
		})

		It("treats a CRL with no nextUpdate as not currently valid", func() {
			// nextUpdate is OPTIONAL in the ASN.1, so ParseRevocationList leaves
			// it zero when absent. Reading absent as "never expires" handed
			// require a snapshot that satisfies it forever, so the policy decayed
			// to skip with no moment at which it decayed and no alert, which is
			// the decay the expiry rule exists to prevent.
			noExpiry := crlFrom(serverCA, caKey, future)
			noExpiry.NextUpdate = time.Time{}
			set := api.NewClientCRLSet([]*x509.RevocationList{
				noExpiry,
				crlFrom(root, rootKey, future),
			}, anchorSet())

			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("no currently valid CRL")))
			Expect(set.Usable(time.Now())).To(BeTrue(),
				"the root's CRL is still current, so the entry has material to check against")
			Expect(set.CoverageGaps(time.Now())).To(ConsistOf("Server CA"),
				"but the uncovered anchor is named, which is what an operator needs")
		})
	})

	Describe("VerifyCRLAgainst", func() {
		It("accepts a CRL its own anchor signed", func() {
			crl := crlFrom(serverCA, caKey, future)
			Expect(api.VerifyCRLAgainst(crl, []*x509.Certificate{serverCA})).To(BeTrue())
		})

		It("rejects a CRL signed by anything else", func() {
			// Without this a writable crl_file is a way to *clear* revocations,
			// not merely add them: swap a CRL naming a revoked certificate for
			// an empty one and it is valid again.
			crl := crlFrom(root, rootKey, future)
			Expect(api.VerifyCRLAgainst(crl, []*x509.Certificate{serverCA})).To(BeFalse())
		})
	})

	Describe("Usable", func() {
		It("is true when every anchor has a currently valid CRL", func() {
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future),
				crlFrom(root, rootKey, future),
			}, anchorSet())
			Expect(set.Usable(time.Now())).To(BeTrue())
		})

		It("is false once every CRL has expired", func() {
			set := api.NewClientCRLSet([]*x509.RevocationList{crlFrom(serverCA, caKey, past)}, anchorSet())
			Expect(set.Usable(time.Now())).To(BeFalse())
		})

		It("reports partial coverage through CoverageGaps, not through Usable", func() {
			// Usable answers "is there anything current to check against", which
			// is the question it can answer honestly. Whether an *uncovered*
			// anchor matters depends on chains that have not arrived: a bundle
			// holding an issuing CA and the root above it needs only the issuing
			// CA's CRL, because nobody chains to the root. Demanding one per
			// anchor made that healthy entry report 0 forever.
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future),
				crlFrom(root, rootKey, past),
			}, anchorSet())
			Expect(set.Usable(time.Now())).To(BeTrue())
			Expect(set.CoverageGaps(time.Now())).To(ConsistOf("Shared Root"))

			both := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future),
				crlFrom(root, rootKey, future),
			}, anchorSet())
			Expect(both.Usable(time.Now())).To(BeTrue())
			Expect(both.CoverageGaps(time.Now())).To(BeEmpty())
		})

		It("will not let a same-named sibling supply another's CRL", func() {
			// crlSignedBy's argument, one layer over: under a shared root two
			// sub-CAs can hold the same distinguished name. Keying on anything
			// derived from the name -- subject DN included -- would let either
			// answer for the other, which is the round-1 attack reached through a
			// different field.
			twinA, keyA := mintCert("Twin CA", root, rootKey, true)
			twinB, keyB := mintCert("Twin CA", root, rootKey, true)
			withSKI(twinA)
			withSKI(twinB)
			Expect(twinA.RawSubject).To(Equal(twinB.RawSubject))
			Expect(keyB).NotTo(BeNil())

			anchors := []*x509.Certificate{twinA, twinB}
			set := api.NewClientCRLSet([]*x509.RevocationList{crlFrom(twinA, keyA, future)}, anchors)

			Expect(set.CoverageGaps(time.Now())).To(ConsistOf("Twin CA"),
				"only one of the two is covered, and they share a name")

			twinBLeaf, _ := mintCert("agent.twin", twinB, keyB, false)
			err := api.CheckChainRevocationForTest(
				[]*x509.Certificate{twinBLeaf, twinB}, set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("no currently valid CRL")))
		})

		It("fails closed when no set has been installed", func() {
			// NewForeignTrustDomain returns a domain whose CRL holder is empty,
			// and buildTrustDomains fills it four statements later. Production is
			// safe by statement ordering alone, which is exactly why the guard is
			// worth having and worth pinning.
			var set *api.ClientCRLSet
			Expect(set.Usable(time.Now())).To(BeFalse())
			err := api.CheckChainRevocationForTest(chain(), set, api.RevocationRequire, time.Now())
			Expect(err).To(MatchError(ContainSubstring("no currently valid CRL")))
		})

		It("files a CRL under the signer's key, so a renewed certificate keeps working", func() {
			// CheckSignatureFrom establishes that a *key* signed the CRL, so
			// keying on the certificate was one level tighter than the property
			// verified. A CA that renews its certificate keeping its key -- with
			// both in the bundle during the overlap -- had its one CRL file under
			// whichever came first, and when that expired every client was
			// refused with a valid CRL sitting in crl_file.
			renewed := reissueCert(serverCA, caKey)
			Expect(renewed.Raw).NotTo(Equal(serverCA.Raw))
			Expect(renewed.RawSubjectPublicKeyInfo).To(Equal(serverCA.RawSubjectPublicKeyInfo))

			set := api.NewClientCRLSet([]*x509.RevocationList{crlFrom(serverCA, caKey, future)},
				[]*x509.Certificate{serverCA, renewed})
			Expect(set.CoverageGaps(time.Now())).To(BeEmpty(),
				"one key, one CRL: both certificates for it are covered")
		})

		It("is false for an empty set, which is the discarded-everything case", func() {
			empty := api.NewClientCRLSet(nil, anchorSet())
			Expect(empty.Usable(time.Now())).To(BeFalse())
		})
	})
})

var _ = Describe("partial-scope client CRLs", func() {
	var (
		serverCA *x509.Certificate
		caKey    *ecdsa.PrivateKey
	)

	anchorSet := func() []*x509.Certificate { return []*x509.Certificate{serverCA} }

	BeforeEach(func() {
		root, rootKey := mintCert("Shared Root", nil, nil, true)
		serverCA, caKey = mintCert("Server CA", root, rootKey, true)
		withSKI(serverCA)
	})

	// A delta CRL lists only what changed since a base it names, and an IDP-
	// scoped CRL lists only one distribution point's share. Either satisfies a
	// signature check and covers its anchor, so before this refusal one could
	// be dropped in as an issuer's whole CRL and `require` would report the
	// domain fully covered while consulting a list missing most of its
	// revocations. This CA is handed a file and never fetches a distribution
	// point, so the rest of the picture is not available to go and get.
	DescribeTable("are refused rather than treated as full coverage",
		func(oid asn1.ObjectIdentifier) {
			revoked := big.NewInt(99)
			set := api.NewClientCRLSet(
				[]*x509.RevocationList{scopedCRLFrom(serverCA, caKey, oid, revoked)},
				anchorSet(),
			)

			Expect(set.Usable(time.Now())).To(BeFalse(),
				"a partial CRL must not count as coverage for its issuer")
			Expect(set.CoverageGaps(time.Now())).To(ContainElement(ContainSubstring("Server CA")))
		},
		Entry("delta CRL indicator", asn1.ObjectIdentifier{2, 5, 29, 27}),
		Entry("issuing distribution point", asn1.ObjectIdentifier{2, 5, 29, 28}),
	)

	It("still denies the serials a partial CRL names", func() {
		// Refusing it as *coverage* must not discard the revocations it lists.
		// A bundle holding a base CRL beside its delta is what concatenating an
		// issuer's CDP and freshestCRL output gives you, and a client revoked
		// since the base was signed appears only in the delta -- so dropping it
		// re-admits exactly the clients the operator most recently excluded.
		revoked := big.NewInt(4242)
		base := crlFrom(serverCA, caKey, time.Now().Add(time.Hour))
		delta := scopedCRLFrom(serverCA, caKey, asn1.ObjectIdentifier{2, 5, 29, 27}, revoked)

		set := api.NewClientCRLSet([]*x509.RevocationList{base, delta}, anchorSet())

		// The base answers coverage; the delta is not counted towards it.
		Expect(set.Usable(time.Now())).To(BeTrue())

		leaf := &x509.Certificate{SerialNumber: revoked, Subject: pkix.Name{CommonName: "node1.test"}}
		err := api.CheckChainRevocationForTest(
			[]*x509.Certificate{leaf, serverCA}, set, api.RevocationRequire, time.Now())
		Expect(err).To(MatchError(ContainSubstring("node1.test")),
			"a serial named only by the delta must still be refused")
	})

	It("does not let a partial CRL satisfy require on its own", func() {
		// The other half: it can deny, but it can never be the reason an issuer
		// counts as covered, or a delta alone would answer for its whole issuer.
		delta := scopedCRLFrom(serverCA, caKey, asn1.ObjectIdentifier{2, 5, 29, 27})
		set := api.NewClientCRLSet([]*x509.RevocationList{delta}, anchorSet())

		leaf := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "node2.test"}}
		err := api.CheckChainRevocationForTest(
			[]*x509.Certificate{leaf, serverCA}, set, api.RevocationRequire, time.Now())
		Expect(err).To(MatchError(api.ErrNoUsableCRL))
	})

	It("counts a not-yet-issued CRL as present, so an empty reload is still refused", func() {
		// S1, the live defect. `present` answers "does this set hold a CRL for
		// this anchor", which is a question about the file and not about the
		// clock -- and losesCoverage rests on it. Filtering it emptied the
		// installed side's view, so the loop refusing an empty reload became
		// vacuous while the marks went to zero at the same moment, disarming
		// both guards together.
		//
		// NextUpdate is deliberately after T0, so the CRL is current and only
		// notYetIssued can withhold it: otherwise expiry would carry the
		// assertion and the two implementations would agree.
		T0 := time.Now()
		ahead := crlFrom(serverCA, caKey, T0.Add(48*time.Hour))
		ahead.ThisUpdate = T0.Add(24 * time.Hour)
		set := api.NewClientCRLSet([]*x509.RevocationList{ahead}, anchorSet())

		present, current := set.Coverage(T0)
		key := string(serverCA.RawSubjectPublicKeyInfo)
		Expect(present).To(HaveKey(key),
			"the file holds a CRL for this anchor whatever this host's clock says")
		Expect(current).NotTo(HaveKey(key),
			"but it is not yet anybody's word, so it cannot make the issuer current")
	})

	It("still denies the serials a not-yet-issued CRL names", func() {
		// The amendment that keeps this rule's blast radius small. A CRL the
		// host thinks is not yet issued cannot speak to coverage or currency --
		// those are claims about the issuer's timeline -- but the serials it
		// names are revoked whatever this host's clock says, and that claim the
		// signature already backs. Discarding it would let a clock difference
		// re-admit revoked clients, which is the failure the whole feature is
		// against.
		revoked := big.NewInt(4242)
		base := crlFrom(serverCA, caKey, time.Now().Add(time.Hour))
		ahead := crlFrom(serverCA, caKey, time.Now().Add(48*time.Hour), revoked)
		ahead.ThisUpdate = time.Now().Add(24 * time.Hour)

		set := api.NewClientCRLSet([]*x509.RevocationList{base, ahead}, anchorSet())

		leaf := &x509.Certificate{SerialNumber: revoked, Subject: pkix.Name{CommonName: "node1.test"}}
		err := api.CheckChainRevocationForTest(
			[]*x509.Certificate{leaf, serverCA}, set, api.RevocationRequire, time.Now())
		Expect(err).To(MatchError(ContainSubstring("node1.test")),
			"a serial named only by a not-yet-issued CRL must still be refused")
	})

	It("does not let a not-yet-issued CRL satisfy require on its own", func() {
		// The other half: it can deny, and it can never be the reason an issuer
		// counts as covered.
		ahead := crlFrom(serverCA, caKey, time.Now().Add(48*time.Hour))
		ahead.ThisUpdate = time.Now().Add(24 * time.Hour)
		set := api.NewClientCRLSet([]*x509.RevocationList{ahead}, anchorSet())

		Expect(set.Usable(time.Now())).To(BeFalse())
		// The third reader of the currency answer. Without this, an ungated
		// anyValid paired with Usable keeping its own copy of the predicate
		// passes the assertion above -- which is the "which reader" failure of
		// rounds 7 and 8 exactly.
		Expect(set.CoverageGaps(time.Now())).To(ContainElement(ContainSubstring("Server CA")))

		leaf := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "node2.test"}}
		err := api.CheckChainRevocationForTest(
			[]*x509.Certificate{leaf, serverCA}, set, api.RevocationRequire, time.Now())
		Expect(err).To(MatchError(api.ErrNoUsableCRL))
	})

	It("treats a CRL within the skew tolerance as issued", func() {
		// Signers and this CA keep separate clocks and neither is
		// authoritative, so a small forward difference is ordinary. Refusing on
		// it would make an unremarkable deployment lose coverage.
		soon := crlFrom(serverCA, caKey, time.Now().Add(time.Hour))
		soon.ThisUpdate = time.Now().Add(time.Minute)
		set := api.NewClientCRLSet([]*x509.RevocationList{soon}, anchorSet())

		Expect(set.Usable(time.Now())).To(BeTrue(),
			"a CRL a minute ahead is a clock difference, not a forgery")
	})

	It("still accepts a CRL carrying an unrelated extension", func() {
		// The refusal is on two specific OIDs, not on extensions in general.
		// A CRL with, say, an authority key identifier is entirely ordinary and
		// must not be swept up -- that would refuse most real CRLs.
		set := api.NewClientCRLSet(
			[]*x509.RevocationList{
				scopedCRLFrom(serverCA, caKey, asn1.ObjectIdentifier{2, 5, 29, 35}),
			},
			anchorSet(),
		)
		Expect(set.Usable(time.Now())).To(BeTrue())
	})
})

// A CRL that verifies, is current, and covers every anchor the installed set
// covers can still be *older* than what is installed. Nothing else on the
// reload path notices: the signature is good and coverage is unchanged. What it
// costs is every serial revoked between the two, silently re-admitted.
var _ = Describe("ClientCRLSet.PartialsDropped", func() {
	var (
		serverCA *x509.Certificate
		caKey    *ecdsa.PrivateKey
		future   time.Time
	)

	anchorSet := func() []*x509.Certificate { return []*x509.Certificate{serverCA} }

	BeforeEach(func() {
		root, rootKey := mintCert("Shared Root", nil, nil, true)
		serverCA, caKey = mintCert("Server CA", root, rootKey, true)
		withSKI(serverCA)
		future = time.Now().Add(30 * 24 * time.Hour)
	})

	delta := func(revoked ...*big.Int) *x509.RevocationList {
		return scopedCRLFrom(serverCA, caKey, asn1.ObjectIdentifier{2, 5, 29, 27}, revoked...)
	}

	// advancedOver is a conjunction, and each half needs killing on its own or
	// one can be deleted with every spec still green.
	It("does not accept a lower-numbered base as an advance", func() {
		// Date forward, number backward. Only the number-non-regression half of
		// advancedOver refuses this; the date half is satisfied.
		current := api.NewClientCRLSet([]*x509.RevocationList{
			numberedCRLFrom(serverCA, caKey, future, 9), delta(big.NewInt(7)),
		}, anchorSet())
		candidate := api.NewClientCRLSet([]*x509.RevocationList{
			numberedCRLFrom(serverCA, caKey, future.Add(time.Hour), 3),
		}, anchorSet())

		_, dropped := current.PartialsDropped(candidate, time.Now())
		Expect(dropped).To(BeTrue(),
			"a base whose number went backwards has not rotated forward")
	})

	It("does not accept an unchanged base as an advance", func() {
		// The same base, and the delta simply gone -- which is the drop this
		// guard exists to catch. Only the date-advance half refuses it: the
		// candidate is level on both axes, so it has not regressed, and a rule
		// asking merely "did it avoid going backwards" would excuse it.
		base := numberedCRLFrom(serverCA, caKey, future, 9)
		current := api.NewClientCRLSet([]*x509.RevocationList{
			base, delta(big.NewInt(7)),
		}, anchorSet())
		candidate := api.NewClientCRLSet([]*x509.RevocationList{base}, anchorSet())

		_, dropped := current.PartialsDropped(candidate, time.Now())
		Expect(dropped).To(BeTrue(),
			"a delta vanishing while its base stands still is exactly the drop to refuse")
	})

	It("reports a delta dropped where the anchor never had a full CRL", func() {
		// With no full CRL there is no base, so currentF holds no entry and the
		// zero mark would let any full CRL -- however old -- read as an advance.
		// That is enough to excuse dropping an enforced delta, which is the
		// whole guard.
		current := api.NewClientCRLSet([]*x509.RevocationList{delta(big.NewInt(7))}, anchorSet())
		candidate := api.NewClientCRLSet([]*x509.RevocationList{
			numberedCRLFrom(serverCA, caKey, future.Add(-20*24*time.Hour), 1),
		}, anchorSet())

		who, dropped := current.PartialsDropped(candidate, time.Now())
		Expect(dropped).To(BeTrue(),
			"an ancient full CRL must not excuse dropping the only revocations there were")
		Expect(who).To(Equal(serverCA.Subject.String()))
	})

	It("cannot excuse a dropped delta with an undated installed mark", func() {
		// S8. advancedOver asks whether the base moved on. With the installed
		// side undated its latest is zero, so real.After(zero) is true and any
		// full CRL at all would read as an advance -- excusing the drop of a
		// delta whose serials are enforced. Requiring both sides dated is what
		// makes "no advance can be demonstrated" the answer instead.
		T0 := time.Now()
		base := numberedCRLFrom(serverCA, caKey, future, 1)
		base.ThisUpdate = T0.Add(24 * time.Hour) // undated at T0
		current := api.NewClientCRLSet([]*x509.RevocationList{
			base, delta(big.NewInt(4242)),
		}, anchorSet())

		candidate := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 2)}, anchorSet())

		who, dropped := current.PartialsDropped(candidate, T0)
		Expect(dropped).To(BeTrue(),
			"a base this host will not date cannot be shown to have rotated")
		Expect(who).To(Equal(serverCA.Subject.String()))
	})

	It("accepts a genuine base rotation beside a reset delta", func() {
		// The legitimate case both halves must still allow.
		current := api.NewClientCRLSet([]*x509.RevocationList{
			numberedCRLFrom(serverCA, caKey, future, 9), delta(big.NewInt(7)),
		}, anchorSet())
		candidate := api.NewClientCRLSet([]*x509.RevocationList{
			numberedCRLFrom(serverCA, caKey, future.Add(time.Hour), 10),
		}, anchorSet())

		_, dropped := current.PartialsDropped(candidate, time.Now())
		Expect(dropped).To(BeFalse())
	})
})

var _ = Describe("ClientCRLSet.Regresses", func() {
	var (
		root     *x509.Certificate
		rootKey  *ecdsa.PrivateKey
		serverCA *x509.Certificate
		caKey    *ecdsa.PrivateKey
		future   time.Time
	)

	anchorSet := func() []*x509.Certificate { return []*x509.Certificate{serverCA} }

	BeforeEach(func() {
		root, rootKey = mintCert("Shared Root", nil, nil, true)
		serverCA, caKey = mintCert("Server CA", root, rootKey, true)
		withSKI(serverCA)
		future = time.Now().Add(30 * 24 * time.Hour)
	})

	It("reports an anchor whose CRL number would go backwards", func() {
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 9)}, anchorSet())
		older := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 4)}, anchorSet())

		who, back := current.Regresses(older, time.Now())
		Expect(back).To(BeTrue(), "CRL number 4 must not replace 9")

		// The name is the point of the return value: the map is keyed by raw
		// SubjectPublicKeyInfo, which is binary and cannot go in a log line, so
		// an operator holding a bundle of several upstreams would otherwise be
		// told a reload was refused and not which issuer to chase.
		Expect(who).To(Equal(serverCA.Subject.String()))
		Expect(who).NotTo(ContainSubstring(string(serverCA.RawSubjectPublicKeyInfo)),
			"the raw key must not reach a message an operator reads")
	})

	It("accepts a newer CRL for the same anchor", func() {
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 9)}, anchorSet())
		newer := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 10)}, anchorSet())

		_, back := current.Regresses(newer, time.Now())
		Expect(back).To(BeFalse())
	})

	It("does not call an equal CRL a regression, since that is the steady state", func() {
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 9)}, anchorSet())
		same := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 9)}, anchorSet())

		_, back := current.Regresses(same, time.Now())
		Expect(back).To(BeFalse(), "every unchanged reload would otherwise be refused")
	})

	// The three specs below drive the ordering rule's arms beyond plain number
	// comparison. All three describe issuers that exist: cRLNumber is OPTIONAL
	// in RFC 5280, and an issuer that publishes one is not obliged to increment
	// it correctly.
	It("falls back to ThisUpdate when the issuer did not increment its number", func() {
		// Equal numbers used to compare equal, so a reissue that kept the
		// number could install in either direction and the older one silently
		// won whenever it was the file on disk.
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 9)}, anchorSet())
		older := api.NewClientCRLSet(
			[]*x509.RevocationList{
				numberedCRLFrom(serverCA, caKey, future.Add(-24*time.Hour), 9),
			}, anchorSet())

		_, back := current.Regresses(older, time.Now())
		Expect(back).To(BeTrue(),
			"same number, earlier ThisUpdate: nothing else would have caught it")
	})

	// Where only one side carries a cRLNumber the dates decide, never the
	// presence of the extension. Deciding on presence was shipped briefly and
	// was unsafe in both directions, so both are pinned here.
	It("does not let a numbered CRL replace a newer unnumbered one", func() {
		// The downgrade direction. An installed unnumbered CRL from today,
		// against a numbered one three weeks old but still current: judged on
		// presence, the older one is "not a regression" and installs,
		// re-admitting every serial revoked in between.
		installed := numberedCRLFrom(serverCA, caKey, future, 1)
		installed.Number = nil // as an issuer omitting the extension parses
		current := api.NewClientCRLSet([]*x509.RevocationList{installed}, anchorSet())

		older := api.NewClientCRLSet(
			[]*x509.RevocationList{
				numberedCRLFrom(serverCA, caKey, future.Add(-21*24*time.Hour), 9),
			}, anchorSet())

		_, back := current.Regresses(older, time.Now())
		Expect(back).To(BeTrue(),
			"an older CRL must be refused whether or not it carries a number")
	})

	It("does not pin an anchor against an issuer that stops publishing numbers", func() {
		// The denial-of-service direction, and the more likely of the two.
		// Judged on presence, once any numbered CRL is installed an issuer that
		// drops the extension can never update the anchor again -- every
		// delivery refused, indefinitely, looking exactly like an attack.
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 9)}, anchorSet())

		newer := numberedCRLFrom(serverCA, caKey, future.Add(24*time.Hour), 1)
		newer.Number = nil
		candidate := api.NewClientCRLSet([]*x509.RevocationList{newer}, anchorSet())

		_, back := current.Regresses(candidate, time.Now())
		Expect(back).To(BeFalse(),
			"a newer CRL must install even though it publishes no number")
	})

	It("orders two unnumbered CRLs by ThisUpdate", func() {
		// An issuer that never publishes a number still must not be able to
		// replay: ThisUpdate is the only ordering it gives, so it is used.
		newer := numberedCRLFrom(serverCA, caKey, future, 1)
		older := numberedCRLFrom(serverCA, caKey, future.Add(-24*time.Hour), 1)
		newer.Number, older.Number = nil, nil

		current := api.NewClientCRLSet([]*x509.RevocationList{newer}, anchorSet())
		candidate := api.NewClientCRLSet([]*x509.RevocationList{older}, anchorSet())

		_, back := current.Regresses(candidate, time.Now())
		Expect(back).To(BeTrue())
	})

	It("refuses a higher-numbered CRL that is older by date", func() {
		// The rule this replaced trusted cRLNumber outright where both sides
		// had one. RFC 5280 requires the number to increase monotonically, but
		// a foreign issuer's compliance is not something this CA can check, and
		// assuming it is the same class of assumption that produced the
		// round-3 regression. An issuer that numbers badly -- two signers with
		// independent counters is the usual way -- would otherwise let an
		// attacker replay an old CRL that happens to carry a higher number.
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 5)}, anchorSet())
		olderButHigher := api.NewClientCRLSet(
			[]*x509.RevocationList{
				numberedCRLFrom(serverCA, caKey, future.Add(-21*24*time.Hour), 9),
			}, anchorSet())

		who, back := current.Regresses(olderButHigher, time.Now())
		Expect(back).To(BeTrue(), "a higher number must not excuse an earlier date")
		Expect(who).To(Equal(serverCA.Subject.String()))
	})

	It("refuses a later-dated CRL whose number went backwards", func() {
		// The mirror, and the reason the test is on either axis rather than
		// both: requiring both to regress would let an attacker replay using
		// whichever axis their issuer happens to keep badly.
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 9)}, anchorSet())
		laterButLower := api.NewClientCRLSet(
			[]*x509.RevocationList{
				numberedCRLFrom(serverCA, caKey, future.Add(24*time.Hour), 4),
			}, anchorSet())

		_, back := current.Regresses(laterButLower, time.Now())
		Expect(back).To(BeTrue(), "a later date must not excuse a lower number")
	})

	It("tracks the two marks independently, not one elected CRL", func() {
		// Where an anchor holds several CRLs, each axis takes its own maximum.
		// Electing one instead needs a comparator, and the comparator this
		// replaced switched axis on whether both sides published a cRLNumber,
		// which is intransitive once some CRLs carry the extension and others
		// do not -- so which CRL won depended on the order they appeared in the
		// file. See crlFreshness for the worked cycle.
		//
		// The fixture has to separate three implementations that a careless one
		// makes agree: componentwise maxima, electing one CRL as newest, and
		// keeping whichever CRL came last. So no single CRL carries both marks
		// -- otherwise electing that one agrees with taking maxima -- and the
		// CRL listed last carries neither, otherwise "last seen" agrees too.
		//
		// Two earlier versions of this fixture failed that: the first put both
		// maxima on the last CRL, the second put both on the first.
		current := api.NewClientCRLSet([]*x509.RevocationList{
			numberedCRLFrom(serverCA, caKey, future, 9),                    // highest number
			numberedCRLFrom(serverCA, caKey, future.Add(48*time.Hour), 2),  // latest date
			numberedCRLFrom(serverCA, caKey, future.Add(-24*time.Hour), 1), // neither
		}, anchorSet())

		// A candidate behind on either mark regresses, even though it is ahead
		// of the superseded CRL on both.
		behindOnDate := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future.Add(24*time.Hour), 10)},
			anchorSet())
		_, back := current.Regresses(behindOnDate, time.Now())
		Expect(back).To(BeTrue(), "the latest date seen is the mark, whichever CRL carried it")

		behindOnNumber := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future.Add(72*time.Hour), 3)},
			anchorSet())
		_, back = current.Regresses(behindOnNumber, time.Now())
		Expect(back).To(BeTrue(), "the highest number seen is the mark, whichever CRL carried it")
	})

	It("accepts a candidate that advances on both marks", func() {
		// The rule must still let an ordinary refresh through, or it is just a
		// slower way of pinning every anchor.
		current := api.NewClientCRLSet([]*x509.RevocationList{
			numberedCRLFrom(serverCA, caKey, future, 9),
			numberedCRLFrom(serverCA, caKey, future.Add(48*time.Hour), 2),
		}, anchorSet())
		ahead := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future.Add(72*time.Hour), 10)},
			anchorSet())

		_, back := current.Regresses(ahead, time.Now())
		Expect(back).To(BeFalse())
	})

	It("admits a candidate whose own CRL is dated ahead of this host's clock", func() {
		// The fifth regression, and the one this rule exists to make
		// impossible. Gating the mark inside freshness filtered both sides, so
		// a forward-skewed issuer's genuine new CRL came back with a zero mark
		// and was refused as a regression -- breaking reloads for a deployment
		// whose only fault was a clock a few minutes fast.
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 5)}, anchorSet())

		skewed := numberedCRLFrom(serverCA, caKey, future, 6)
		skewed.ThisUpdate = time.Now().Add(90 * 24 * time.Hour)
		candidate := api.NewClientCRLSet([]*x509.RevocationList{skewed}, anchorSet())

		_, back := current.Regresses(candidate, time.Now())
		Expect(back).To(BeFalse(),
			"a candidate the host thinks is not yet issued must not read as going backwards")
	})

	It("refuses a reload when the installed CRLs are neither dated nor numbered", func() {
		// Rewritten: the previous version named this case and evaluated at
		// T0+70d, by which both fixture dates were a month in the past, no CRL
		// was not-yet-issued, the filter never engaged and the ordinary date
		// arm carried the assertion. It passed under every candidate rule --
		// including the one that shipped the defect it was written to catch.
		//
		// Suppressing `latest` for an undated anchor leaves an unnumbered
		// issuer with nothing to order by, so the guard refuses rather than
		// installing a file it cannot show to be newer. Self-limiting: once the
		// clock passes those ThisUpdates the anchor is dated again.
		T0 := time.Now()

		newer := numberedCRLFrom(serverCA, caKey, future, 1)
		newer.ThisUpdate = T0.Add(24 * time.Hour) // undated at T0, by ~24h
		newer.Number = nil
		older := numberedCRLFrom(serverCA, caKey, future, 1)
		older.ThisUpdate = T0.Add(-time.Hour)
		older.Number = nil

		current := api.NewClientCRLSet([]*x509.RevocationList{newer}, anchorSet())
		candidate := api.NewClientCRLSet([]*x509.RevocationList{older}, anchorSet())

		_, back := current.Regresses(candidate, T0)
		Expect(back).To(BeTrue(),
			"with no believable date and no number there is nothing to order by")
	})

	It("does not refuse an unnumbered issuer's ordinary reload", func() {
		// S6b: the steady state for an issuer that never publishes cRLNumber.
		// Both dates are in the past at T0, so both sides are dated and the
		// arm above must not fire -- otherwise every such issuer's every
		// reload is refused for ever.
		T0 := time.Now()

		installed := numberedCRLFrom(serverCA, caKey, future, 1)
		installed.ThisUpdate = T0.Add(-2 * time.Hour)
		installed.Number = nil
		candidate := numberedCRLFrom(serverCA, caKey, future, 1)
		candidate.ThisUpdate = T0.Add(-time.Hour)
		candidate.Number = nil

		_, back := api.NewClientCRLSet([]*x509.RevocationList{installed}, anchorSet()).
			Regresses(api.NewClientCRLSet([]*x509.RevocationList{candidate}, anchorSet()), T0)
		Expect(back).To(BeFalse())
	})

	It("does not refuse an unnumbered candidate this host will not date", func() {
		// S6c: the same arm, keyed the other way round. It must test the
		// *installed* side's datedness, not the candidate's -- swapping them
		// refuses a forward-skewed issuer's genuine CRL, which is the round-5
		// and round-6 mistake ("which side of the comparison") reappearing on
		// a new arm. S6 alone cannot catch that; the two together pin it.
		T0 := time.Now()

		installed := numberedCRLFrom(serverCA, caKey, future, 1)
		installed.ThisUpdate = T0.Add(-2 * time.Hour)
		installed.Number = nil
		candidate := numberedCRLFrom(serverCA, caKey, future, 1)
		candidate.ThisUpdate = T0.Add(24 * time.Hour) // undated at T0
		candidate.Number = nil

		_, back := api.NewClientCRLSet([]*x509.RevocationList{installed}, anchorSet()).
			Regresses(api.NewClientCRLSet([]*x509.RevocationList{candidate}, anchorSet()), T0)
		Expect(back).To(BeFalse())
	})

	It("still catches a numbered replay while the anchor is undated", func() {
		// Site 9: maxNumber is raised by a CRL this host will not date. The
		// anchor deliberately holds two full CRLs -- one past-dated, so the
		// anchor is dated and the undated-installed arm cannot fire, and one
		// dated ahead carrying a higher number. That is the only shape in which
		// the number mark's placement decides the outcome on its own.
		//
		// An earlier version used a single undated CRL and passed under the
		// very mutation it named: with maxNumber suppressed the anchor had no
		// number at all, the undated-installed arm fired instead, and the
		// assertion held for a reason that had nothing to do with site 9.
		//
		// cRLNumber sits inside the signed TBS, so a replayer can only present
		// numbers the issuer really published and the issuer's own numbering is
		// monotonic. A future ThisUpdate is no reason to disbelieve a number,
		// and keeping it outside the gate is what leaves a guard standing in
		// exactly the window where the date ratchet is suppressed.
		T0 := time.Now()

		settled := numberedCRLFrom(serverCA, caKey, future, 4)
		settled.ThisUpdate = T0.Add(-2 * time.Hour) // dated: the arm cannot fire
		ahead := numberedCRLFrom(serverCA, caKey, future, 9)
		ahead.ThisUpdate = T0.Add(24 * time.Hour) // undated, and carries the mark
		installed := api.NewClientCRLSet(
			[]*x509.RevocationList{settled, ahead}, anchorSet())

		// Between the two numbers, and later than the dated CRL, so only the
		// number mark can refuse it.
		replayed := numberedCRLFrom(serverCA, caKey, future, 6)
		replayed.ThisUpdate = T0.Add(-time.Hour)
		candidate := api.NewClientCRLSet([]*x509.RevocationList{replayed}, anchorSet())

		who, back := installed.Regresses(candidate, T0)
		Expect(back).To(BeTrue(),
			"number 6 must not replace 9 merely because this host will not date 9's CRL")
		Expect(who).To(Equal(serverCA.Subject.String()))
	})

	It("is not pinned for ever by a CRL dated in the future", func() {
		// ThisUpdate is the issuer's own timestamp and nothing here can check
		// it. If it could ratchet the mark, one forward-skewed or replayed CRL
		// would refuse every later genuine one -- and fail *open*, because that
		// CRL stays current, so require goes on admitting clients while nothing
		// published afterwards is ever installed. Restarting does not help: the
		// mark is rebuilt from the same file.
		ahead := numberedCRLFrom(serverCA, caKey, future, 1)
		ahead.ThisUpdate = time.Now().Add(90 * 24 * time.Hour)
		current := api.NewClientCRLSet([]*x509.RevocationList{ahead}, anchorSet())

		// An ordinary CRL issued an hour ago, which any real issuer would send
		// next and which must not be read as going backwards.
		normal := numberedCRLFrom(serverCA, caKey, future, 2)
		normal.ThisUpdate = time.Now().Add(-time.Hour)
		candidate := api.NewClientCRLSet([]*x509.RevocationList{normal}, anchorSet())

		_, back := current.Regresses(candidate, time.Now())
		Expect(back).To(BeFalse(),
			"a future-dated CRL must not pin the anchor against every later one")
	})

	It("still ratchets on a CRL dated in the past", func() {
		// The companion: skipping future dates must not disable the mark. A
		// normal CRL raises it exactly as before, or the ratchet is gone and
		// replays install freely.
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 5)}, anchorSet())
		older := numberedCRLFrom(serverCA, caKey, future, 5)
		older.ThisUpdate = time.Now().Add(-90 * 24 * time.Hour)
		candidate := api.NewClientCRLSet([]*x509.RevocationList{older}, anchorSet())

		_, back := current.Regresses(candidate, time.Now())
		Expect(back).To(BeTrue(), "an older date must still be refused")
	})

	// An anchor the candidate drops entirely is losesCoverage's business, and
	// answering it here too would report one fault as two.
	It("says nothing about an anchor the candidate no longer covers", func() {
		current := api.NewClientCRLSet(
			[]*x509.RevocationList{numberedCRLFrom(serverCA, caKey, future, 9)}, anchorSet())
		empty := api.NewClientCRLSet(nil, anchorSet())

		_, back := current.Regresses(empty, time.Now())
		Expect(back).To(BeFalse())
	})
})
