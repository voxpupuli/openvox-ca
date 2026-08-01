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
	"errors"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/api"
)

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
			// silently ignored. RFC 5280 5.2.1 requires a conforming CRL issuer
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
