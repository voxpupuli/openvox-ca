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

// withSKI gives a certificate a Subject Key Identifier, which CRL matching
// requires. mintCert leaves it unset.
func withSKI(cert *x509.Certificate) *x509.Certificate {
	GinkgoHelper()
	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	sum := sha1.Sum(pubDER)
	cert.SubjectKeyId = sum[:]
	return cert
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
			// which meant an issuer that omits the extension -- RFC 5280 makes it
			// optional and real ones do -- had its revocations silently ignored.
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
		})

		It("treats a CRL with no nextUpdate as not currently valid", func() {
			// RFC 5280 makes nextUpdate optional, and ParseRevocationList leaves
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
			Expect(set.Usable(time.Now(), anchorSet())).To(BeFalse(),
				"one anchor without a current CRL makes the entry unusable, which is "+
					"what enforcement already did")
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
			Expect(set.Usable(time.Now(), anchorSet())).To(BeTrue())
		})

		It("is false once every CRL has expired", func() {
			set := api.NewClientCRLSet([]*x509.RevocationList{crlFrom(serverCA, caKey, past)}, anchorSet())
			Expect(set.Usable(time.Now(), anchorSet())).To(BeFalse())
		})

		It("is false when one anchor of several has no valid CRL", func() {
			// The gauge used to be "any anchor has a valid CRL" while enforcement
			// is "every issuer in the chain must". A two-anchor entry whose second
			// anchor's CRL had expired published 1 while every client of that
			// anchor was already being refused, so the alert this metric exists
			// for could not see a partial outage.
			set := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future),
				crlFrom(root, rootKey, past),
			}, anchorSet())
			Expect(set.Usable(time.Now(), anchorSet())).To(BeFalse())

			both := api.NewClientCRLSet([]*x509.RevocationList{
				crlFrom(serverCA, caKey, future),
				crlFrom(root, rootKey, future),
			}, anchorSet())
			Expect(both.Usable(time.Now(), anchorSet())).To(BeTrue())
		})

		It("is false for an empty set, which is the discarded-everything case", func() {
			empty := api.NewClientCRLSet(nil, anchorSet())
			Expect(empty.Usable(time.Now(), anchorSet())).To(BeFalse())
		})
	})
})
