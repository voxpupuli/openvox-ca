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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// These exercise the renewal gate directly, because nothing else can reach it
// yet: the auth middleware rejects a foreign certificate before any handler
// runs, so an HTTP-level test would pass whether or not the gate existed. Once
// a second issuer can be trusted for client authentication, the middleware stops
// being that backstop and this becomes the only thing standing between a foreign
// certificate and reissue under our authority.
var _ = Describe("Renewal issuer gate", func() {
	var (
		ctx    context.Context
		myCA   *ca.CA
		store  *storage.StorageService
		ownCrt *x509.Certificate
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		ownCrt, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	// foreignCert issues a certificate from an unrelated CA, carrying a name
	// this CA's own namespace uses. That collision is the point: without the
	// gate, renewing it would produce a certificate issued by us for a name we
	// did not choose, and potentially one an agent already holds.
	foreignCert := func(cn string) *x509.Certificate {
		GinkgoHelper()
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		caTmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Unrelated CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		foreignCA, err := x509.ParseCertificate(caDER)
		Expect(err).NotTo(HaveOccurred())

		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}, foreignCA, &leafKey.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		leaf, err := x509.ParseCertificate(leafDER)
		Expect(err).NotTo(HaveOccurred())
		return leaf
	}

	Describe("AutoRenew", func() {
		It("renews a certificate this CA issued", func() {
			out, err := myCA.AutoRenew(ctx, ownCrt)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).NotTo(BeEmpty())
		})

		It("refuses a certificate issued by another CA", func() {
			_, err := myCA.AutoRenew(ctx, foreignCert("node2.test"))
			Expect(err).To(MatchError(ca.ErrForeignCertificate))
		})

		It("refuses a foreign certificate bearing a name we issued", func() {
			_, err := myCA.AutoRenew(ctx, foreignCert("node1.test"))
			Expect(err).To(MatchError(ca.ErrForeignCertificate))
		})

		It("refuses a certificate we issued but have revoked", func() {
			// CheckSignatureFrom alone would accept this: it is a pure signature
			// check with no validity semantics. Without the paired revocation
			// check a revoked certificate stays a self-renewal credential.
			Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())
			_, err := myCA.AutoRenew(ctx, ownCrt)
			Expect(err).To(MatchError(ca.ErrForeignCertificate))
		})
	})

	Describe("Renew", func() {
		csrFor := func(cn string) []byte {
			GinkgoHelper()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			der, err := x509.CreateCertificateRequest(rand.Reader,
				&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
			Expect(err).NotTo(HaveOccurred())
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		}

		It("re-keys a certificate this CA issued", func() {
			out, err := myCA.Renew(ctx, "node1.test", csrFor("node1.test"), ownCrt)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).NotTo(BeEmpty())
		})

		It("refuses when the presented certificate is foreign", func() {
			// The branch revision 2 of the design missed entirely. The handler's
			// only identity check is that the CSR's CN matches the presented
			// certificate's — which constrains the caller to a name the *foreign*
			// CA gave them, and to nothing this CA issued.
			_, err := myCA.Renew(ctx, "node1.test", csrFor("node1.test"), foreignCert("node1.test"))
			Expect(err).To(MatchError(ca.ErrForeignCertificate))
		})

		It("refuses when no certificate is presented", func() {
			_, err := myCA.Renew(ctx, "node1.test", csrFor("node1.test"), nil)
			Expect(err).To(MatchError(ca.ErrForeignCertificate))
		})

		It("refuses a certificate we issued but have revoked", func() {
			// The mirror of the AutoRenew spec above, and not redundant with it:
			// the two paths call the gate separately, so replacing this one with
			// a bare CheckSignatureFrom would leave a revoked certificate usable
			// as a re-key credential while every other Renew spec still passed.
			Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())
			_, err := myCA.Renew(ctx, "node1.test", csrFor("node1.test"), ownCrt)
			Expect(err).To(MatchError(ca.ErrForeignCertificate))
		})
	})
})
