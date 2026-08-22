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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/api"
)

// testPKI is a root with two sibling intermediates and a leaf under each: the
// topology the trust-domain model exists for, and the one where a merged pool
// would silently make the two siblings interchangeable.
type testPKI struct {
	root        *x509.Certificate
	serverCA    *x509.Certificate
	agentCA     *x509.Certificate
	serverLeaf  *x509.Certificate
	agentLeaf   *x509.Certificate
	serverChain []*x509.Certificate
	agentChain  []*x509.Certificate
}

// mintCert issues one certificate, self-signed when parent is nil.
func mintCert(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return cert, key
}

func buildTestPKI() *testPKI {
	GinkgoHelper()
	root, rootKey := mintCert("Shared Root", nil, nil, true)
	serverCA, serverCAKey := mintCert("Server CA", root, rootKey, true)
	agentCA, agentCAKey := mintCert("Agent CA", root, rootKey, true)
	serverLeaf, _ := mintCert("admin.example.com", serverCA, serverCAKey, false)
	agentLeaf, _ := mintCert("admin.example.com", agentCA, agentCAKey, false)

	return &testPKI{
		root: root, serverCA: serverCA, agentCA: agentCA,
		serverLeaf: serverLeaf, agentLeaf: agentLeaf,
		// What a client actually presents: its leaf, then the chain up.
		serverChain: []*x509.Certificate{serverCA, root},
		agentChain:  []*x509.Certificate{agentCA, root},
	}
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

var _ = Describe("Trust domains", func() {
	var pki *testPKI

	BeforeEach(func() { pki = buildTestPKI() })

	Describe("anchoring on an intermediate", func() {
		It("accepts what that intermediate issued", func() {
			domains := []api.TrustDomain{{Name: "server", Roots: poolOf(pki.serverCA)}}
			got := api.AttributeForTest(domains, pki.serverLeaf, pki.serverChain)
			Expect(got).NotTo(BeNil())
			Expect(got.Name).To(Equal("server"))
		})

		It("rejects a sibling's leaf even when the client supplies the whole chain", func() {
			// The property the whole design rests on: a CertPool anchor need
			// not be self-signed, and anchoring on the Server CA accepts what
			// the Server CA issued and nothing else. The client here presents
			// the shared root *and* the sibling CA as intermediates, which is
			// the strongest attempt available to it — an intermediates pool can
			// only help build a path to an already-trusted anchor, never
			// introduce one.
			domains := []api.TrustDomain{{Name: "server", Roots: poolOf(pki.serverCA)}}
			got := api.AttributeForTest(domains, pki.agentLeaf, []*x509.Certificate{pki.agentCA, pki.root, pki.serverCA})
			Expect(got).To(BeNil())
		})

		It("accepts both siblings once the shared root is the anchor", func() {
			// The footgun, demonstrated: putting the root in an entry's bundle
			// extends that entry's authority — including its admin_cns — to
			// every intermediate the root has issued or ever will.
			domains := []api.TrustDomain{{Name: "root", Roots: poolOf(pki.root)}}
			Expect(api.AttributeForTest(domains, pki.serverLeaf, pki.serverChain)).NotTo(BeNil())
			Expect(api.AttributeForTest(domains, pki.agentLeaf, pki.agentChain)).NotTo(BeNil())
		})
	})

	Describe("domain order", func() {
		It("attributes to the first domain that verifies, in configuration order", func() {
			domains := []api.TrustDomain{
				{Name: "first", Roots: poolOf(pki.serverCA)},
				{Name: "second", Roots: poolOf(pki.serverCA)},
			}
			got := api.AttributeForTest(domains, pki.serverLeaf, pki.serverChain)
			Expect(got.Name).To(Equal("first"))
		})

		It("never lets a foreign domain capture a certificate our own CA issued", func() {
			// Two domains can both verify this certificate, so without a fixed
			// order the client would choose its own attribution — and with it
			// its own admin grants. Ours is always domain zero.
			own := api.OwnTrustDomain(pki.serverCA, map[string]bool{}, false)
			domains := []api.TrustDomain{own, {Name: "foreign", Roots: poolOf(pki.serverCA)}}

			got := api.AttributeForTest(domains, pki.serverLeaf, pki.serverChain)
			Expect(got.IsOwn()).To(BeTrue())
		})
	})

	Describe("the single-domain default", func() {
		It("behaves exactly as one CA with one namespace", func() {
			// Topology A: no client_ca configured, so the list has length one.
			own := api.OwnTrustDomain(pki.serverCA, map[string]bool{}, false)
			domains := []api.TrustDomain{own}

			Expect(api.AttributeForTest(domains, pki.serverLeaf, pki.serverChain).IsOwn()).To(BeTrue())
			Expect(api.AttributeForTest(domains, pki.agentLeaf, pki.agentChain)).To(BeNil())
		})
	})

	Describe("IsOwn", func() {
		It("is not something a foreign domain can become", func() {
			// SECURITY: this predicate decides whose CRL a client is checked
			// against, whether it may renew, and whether it may read another
			// subject's CSR. It used to be Name == "", which held only because
			// configuration validation rejects a client_ca entry with no name --
			// a check two packages away, on one construction path, asserted here
			// by a comment. An entry missing its name key would have become
			// domain zero.
			//
			// The marker is now a field only OwnTrustDomain sets, so no name, and
			// no configuration input, can reach it.
			nameless := api.NewForeignTrustDomain("", nil, nil, map[string]bool{"admin": true}, true)
			Expect(nameless.IsOwn()).To(BeFalse())

			ours := api.OwnTrustDomain(pki.serverCA, nil, false)
			Expect(ours.IsOwn()).To(BeTrue())
			zero := api.TrustDomain{}
			Expect(zero.IsOwn()).To(BeFalse(), "the zero value must fail towards foreign")
		})
	})

	Describe("Describe", func() {
		It("names our own domain without a client_ca label", func() {
			own := api.OwnTrustDomain(pki.serverCA, nil, false)
			Expect(own.Describe()).To(Equal("this CA"))
		})

		It("names a configured domain by its entry", func() {
			d := api.TrustDomain{Name: "server-ca"}
			Expect(d.Describe()).To(ContainSubstring("server-ca"))
		})
	})
})

// A domain built as a struct literal rather than through a constructor has no
// CRL holder, and SetRevocationSet returns rather than allocating one -- the
// same discipline SetAdminCNs follows, for the same reason: allocating here
// writes to a value the middleware may already hold a copy of. Nothing drove
// that branch, so a change to allocate lazily would have passed.
var _ = Describe("TrustDomain.SetRevocationSet without a holder", func() {
	It("is a no-op rather than an allocation", func() {
		var d api.TrustDomain // no constructor, so no holder

		Expect(func() { d.SetRevocationSet(api.NewClientCRLSet(nil, nil)) }).NotTo(Panic())
		Expect(d.RevocationSet()).To(BeNil(),
			"a domain with no holder must stay without one, not gain a set on write")
	})

	It("installs the set when the constructor made a holder", func() {
		d := api.NewForeignTrustDomain("server-ca", nil, nil, nil, false)
		d.SetRevocationSet(api.NewClientCRLSet(nil, nil))
		Expect(d.RevocationSet()).NotTo(BeNil())
	})

	// The sibling the comment above claims follows the same discipline. It was
	// asserted about and not driven, which is how the claim and the code get to
	// disagree.
	It("refuses an admin-CN write to a domain with no holder", func() {
		var d api.TrustDomain

		var previous map[string]bool
		Expect(func() { previous = d.SetAdminCNs(map[string]bool{"ops": true}) }).NotTo(Panic())
		Expect(previous).To(BeNil())
		Expect(d.IsAdminCN("ops")).To(BeFalse(),
			"a domain with no holder must not gain administrators on write")
	})

	It("swaps admin CNs and returns the previous set when there is a holder", func() {
		d := api.NewForeignTrustDomain("server-ca", nil, nil, map[string]bool{"old": true}, false)

		previous := d.SetAdminCNs(map[string]bool{"new": true})

		Expect(previous).To(HaveKey("old"))
		Expect(d.IsAdminCN("new")).To(BeTrue())
		Expect(d.IsAdminCN("old")).To(BeFalse(),
			"a replaced admin list must not leave the old names honoured")
	})
})
