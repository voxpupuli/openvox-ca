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
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// caCertWithKeyUsage builds a single self-signed CA certificate carrying ku,
// as a one-element chain ValidateCABundleOrder will accept structurally. A ku
// of zero omits the extension entirely.
func caCertWithKeyUsage(ku x509.KeyUsage) []*x509.Certificate {
	GinkgoHelper()
	return caCertWithProfile(ku, false)
}

// caCertWithProfile is caCertWithKeyUsage, optionally encoding pathlen:0 into
// the basicConstraints extension. Set on the template, not on the parsed
// result: assigning MaxPathLenZero after ParseCertificate leaves the DER
// without any pathLenConstraint, so a check reading the extension rather than
// the parsed convenience field would see a different certificate than the
// spec claims to be testing.
func caCertWithProfile(ku x509.KeyUsage, pathLenZero bool) []*x509.Certificate {
	GinkgoHelper()
	return caCertWithWindow(ku, pathLenZero, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// caCertWithWindow is caCertWithProfile with an explicit validity window, so the
// expiry refusals can be exercised.
func caCertWithWindow(ku x509.KeyUsage, pathLenZero bool, notBefore, notAfter time.Time) []*x509.Certificate {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Profile Test CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              ku,
		MaxPathLen:            0,
		MaxPathLenZero:        pathLenZero,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return []*x509.Certificate{cert}
}

var _ = Describe("CA bundle parsing and ordering", func() {
	var chain *testutil.TestChain

	BeforeEach(func() {
		var err error
		chain, err = testutil.GenerateTestChain("node.example.com")
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("ParseCABundle", func() {
		It("returns every certificate in file order", func() {
			certs, err := ca.ParseCABundle(chain.Bundle)
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).To(HaveLen(2))
			Expect(certs[0].Subject.CommonName).To(Equal("Test Intermediate CA"))
			Expect(certs[1].Subject.CommonName).To(Equal("Test Root CA"))
		})

		It("skips harmless non-certificate blocks rather than failing", func() {
			// Operators paste bundles exported by other tools, which carry
			// commentary and sometimes unrelated PEM. Nothing there is a secret.
			noise := []byte("-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----\n")
			certs, err := ca.ParseCABundle(append(noise, chain.Bundle...))
			Expect(err).NotTo(HaveOccurred())
			Expect(certs).To(HaveLen(2))
		})

		It("rejects a bundle carrying a private key", func() {
			// The shape `bao write pki/intermediate/generate/exported
			// format=pem_bundle` produces. The CA certificate is stored 0644 and
			// served unauthenticated, so a key that parsed through would be
			// published to anything that can reach GET /certificate/ca.
			mixed := append(append([]byte{}, chain.InterKeyPEM...), chain.Bundle...)
			_, err := ca.ParseCABundle(mixed)
			Expect(err).To(MatchError(ContainSubstring("PRIVATE KEY")))
			Expect(err).To(MatchError(ContainSubstring("world-readable")))
		})

		It("rejects input with no certificates", func() {
			_, err := ca.ParseCABundle([]byte("no PEM here\n"))
			Expect(err).To(MatchError(ContainSubstring("no CERTIFICATE blocks")))
		})

		It("rejects a malformed certificate body", func() {
			_, err := ca.ParseCABundle([]byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"))
			Expect(err).To(MatchError(ContainSubstring("parsing certificate 1")))
		})
	})

	Describe("ValidateCABundleOrder", func() {
		It("accepts a complete chain ordered nearest-first", func() {
			certs, err := ca.ParseCABundle(chain.Bundle)
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.ValidateCABundleOrder(certs)).To(Succeed())
		})

		It("accepts a lone self-signed root", func() {
			certs, err := ca.ParseCABundle(chain.RootPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.ValidateCABundleOrder(certs)).To(Succeed())
		})

		It("rejects a reversed bundle", func() {
			// Root-first is the mistake that would pass a naive check and then
			// fail at startup, because loadCA pins the key to block 0.
			reversed := append(append([]byte{}, chain.RootPEM...), chain.InterPEM...)
			certs, err := ca.ParseCABundle(reversed)
			Expect(err).NotTo(HaveOccurred())
			err = ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("ordered nearest-first")))
		})

		It("rejects a partial chain that stops at an intermediate", func() {
			certs, err := ca.ParseCABundle(chain.InterPEM)
			Expect(err).NotTo(HaveOccurred())
			err = ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("not self-signed")))
		})

		It("rejects a bundle whose first certificate is a leaf", func() {
			certs, err := ca.ParseCABundle(chain.LeafPEM)
			Expect(err).NotTo(HaveOccurred())
			err = ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("IsCA=false")))
		})

		It("rejects an empty certificate list", func() {
			Expect(ca.ValidateCABundleOrder(nil)).To(MatchError(ContainSubstring("no certificates")))
		})

		It("rejects a first certificate whose KeyUsage omits keyCertSign", func() {
			// A parent signing with the wrong profile yields a certificate that
			// installs cleanly and then cannot issue anything a conforming
			// verifier accepts — discovered fleet-wide rather than at import.
			certs := caCertWithKeyUsage(x509.KeyUsageCRLSign)
			Expect(ca.ValidateCABundleOrder(certs)).To(MatchError(ContainSubstring("without keyCertSign")))
		})

		It("rejects a first certificate whose KeyUsage omits cRLSign", func() {
			certs := caCertWithKeyUsage(x509.KeyUsageCertSign)
			Expect(ca.ValidateCABundleOrder(certs)).To(MatchError(ContainSubstring("without cRLSign")))
		})

		It("accepts a first certificate with no KeyUsage extension at all", func() {
			// RFC 5280 leaves an absent extension unconstrained; only a present
			// extension that omits the bit is a refusal.
			Expect(ca.ValidateCABundleOrder(caCertWithKeyUsage(0))).To(Succeed())
		})

		It("accepts pathlen:0, which is the correct profile for this CA", func() {
			// pathlen:0 permits issuing end-entity certificates and forbids
			// issuing further CAs. openvox-ca issues only end-entity
			// certificates, so this is a well-formed sub-CA, not a fault.
			certs := caCertWithProfile(x509.KeyUsageCertSign|x509.KeyUsageCRLSign, true)
			Expect(certs[0].MaxPathLenZero).To(BeTrue(),
				"the fixture must genuinely encode pathlen:0, not merely claim it")
			Expect(ca.ValidateCABundleOrder(certs)).To(Succeed())
		})

		It("rejects an expired leading certificate", func() {
			// The same argument the KeyUsage refusals make, and stronger: a
			// certificate outside its window installs cleanly and is then
			// rejected by every agent verifying the chain.
			certs := caCertWithWindow(x509.KeyUsageCertSign|x509.KeyUsageCRLSign, false,
				time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
			err := ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("expired at")))
			Expect(err).To(MatchError(ContainSubstring("first certificate in bundle")))
		})

		It("rejects a certificate that is not valid yet", func() {
			// Distinct wording, because the cause is usually a clock rather
			// than a stale file, and the remedy differs accordingly.
			certs := caCertWithWindow(x509.KeyUsageCertSign|x509.KeyUsageCRLSign, false,
				time.Now().Add(time.Hour), time.Now().Add(48*time.Hour))
			err := ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("is not valid until")))
			Expect(err).To(MatchError(ContainSubstring("check the clock")))
		})

		It("rejects a chain whose root has expired, not only its leading certificate", func() {
			// The whole-chain claim, which docs/operator-cli.md states as a
			// contract. Narrowing the check to certs[0] must fail this: only
			// the root is outside its window here, and nothing downstream ever
			// looks at it again.
			certs := chainWithExpiredRoot()
			Expect(certs).To(HaveLen(2))
			Expect(time.Now()).To(BeTemporally("<", certs[0].NotAfter),
				"only the root may be outside its window, or the spec proves nothing")

			err := ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("expired at")))
			Expect(err).To(MatchError(ContainSubstring("certificate 2 in bundle")),
				"the refusal must name the offending certificate, not the leading one")
		})

		It("rejects a chain whose links do not verify", func() {
			// Two unrelated roots concatenated: ordered plausibly, cryptographically
			// unrelated.
			other, err := testutil.GenerateTestChain("other.example.com")
			Expect(err).NotTo(HaveOccurred())
			mixed := append(append([]byte{}, chain.InterPEM...), other.RootPEM...)
			certs, err := ca.ParseCABundle(mixed)
			Expect(err).NotTo(HaveOccurred())
			err = ca.ValidateCABundleOrder(certs)
			Expect(err).To(MatchError(ContainSubstring("is not signed by certificate")))
		})
	})

	Describe("EncodeCABundle", func() {
		It("round-trips a chain with byte-identical DER", func() {
			// The property that makes re-encoding on the way to storage safe:
			// only PEM commentary is lost, never certificate content.
			certs, err := ca.ParseCABundle(chain.Bundle)
			Expect(err).NotTo(HaveOccurred())

			again, err := ca.ParseCABundle(ca.EncodeCABundle(certs))
			Expect(err).NotTo(HaveOccurred())
			Expect(again).To(HaveLen(2))
			Expect(again[0].Raw).To(Equal(certs[0].Raw))
			Expect(again[1].Raw).To(Equal(certs[1].Raw))
		})
	})

	Describe("ResignStoredCRL", func() {
		var (
			ctx   context.Context
			store *storage.StorageService
			myCA  *ca.CA
		)

		BeforeEach(func() {
			ctx = context.Background()
			store = storage.New(GinkgoT().TempDir())
			myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
			myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(myCA.Init(ctx)).To(Succeed())
		})

		It("carries every revocation entry across", func() {
			// The entries name serials this CA issued and stay meaningful under
			// a new certificate. Dropping them would silently un-revoke a node.
			res, err := myCA.Generate(ctx, "node1.example.com", nil)
			Expect(err).NotTo(HaveOccurred())
			certBlock, _ := pem.Decode(res.CertificatePEM)
			issued, err := x509.ParseCertificate(certBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(ctx, "node1.example.com")).To(Succeed())

			out, err := ca.ResignStoredCRL(ctx, store, myCA.CACert, myCA.CAKey, time.Hour)
			Expect(err).NotTo(HaveOccurred())

			block, _ := pem.Decode(out)
			Expect(block).NotTo(BeNil())
			crl, err := x509.ParseRevocationList(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(crl.RevokedCertificateEntries).To(HaveLen(1))
			Expect(crl.RevokedCertificateEntries[0].SerialNumber).To(Equal(issued.SerialNumber))
		})

		It("bumps the CRL number and honours the supplied validity", func() {
			before, err := store.GetCRL(ctx)
			Expect(err).NotTo(HaveOccurred())
			beforeBlock, _ := pem.Decode(before)
			old, err := x509.ParseRevocationList(beforeBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())

			out, err := ca.ResignStoredCRL(ctx, store, myCA.CACert, myCA.CAKey, 90*time.Minute)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(out)
			crl, err := x509.ParseRevocationList(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			Expect(crl.Number.Cmp(old.Number)).To(Equal(1))
			Expect(crl.NextUpdate.Sub(crl.ThisUpdate)).To(BeNumerically("~", 90*time.Minute, time.Minute))
		})

		It("returns nil when storage holds no CRL, leaving the caller to generate one", func() {
			empty := storage.New(GinkgoT().TempDir())
			out, err := ca.ResignStoredCRL(ctx, empty, myCA.CACert, myCA.CAKey, time.Hour)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(BeNil())
		})

		It("fails rather than discarding a stored CRL it cannot parse", func() {
			Expect(store.UpdateCRL(ctx, []byte("not PEM at all\n"))).To(Succeed())
			_, err := ca.ResignStoredCRL(ctx, store, myCA.CACert, myCA.CAKey, time.Hour)
			Expect(err).To(MatchError(ContainSubstring("not PEM-encoded")))
		})

		It("fails on a PEM block that is not a parseable CRL", func() {
			Expect(store.UpdateCRL(ctx, []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n"))).To(Succeed())
			_, err := ca.ResignStoredCRL(ctx, store, myCA.CACert, myCA.CAKey, time.Hour)
			Expect(err).To(MatchError(ContainSubstring("parsing the existing CRL")))
		})
	})

	Describe("AssertSignerMatchesCert", func() {
		It("accepts a signer holding the certificate's key", func() {
			store := storage.New(GinkgoT().TempDir())
			myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
			myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(myCA.Init(context.Background())).To(Succeed())

			Expect(ca.AssertSignerMatchesCert(myCA.CACert, myCA.CAKey)).To(Succeed())
		})

		It("rejects a signer holding any other key", func() {
			store := storage.New(GinkgoT().TempDir())
			myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
			myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(myCA.Init(context.Background())).To(Succeed())

			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			err = ca.AssertSignerMatchesCert(myCA.CACert, other)
			Expect(err).To(MatchError(ContainSubstring("does not match the certificate's public key")))
		})
	})

	Describe("CASubjectName", func() {
		It("derives the common name from the hostname", func() {
			name := ca.CASubjectName("puppet.example.com", ca.CASubjectConfig{})
			Expect(name.CommonName).To(Equal("Puppet CA: puppet.example.com"))
			Expect(name.Organization).To(BeEmpty())
		})

		It("applies every optional subject field", func() {
			name := ca.CASubjectName("puppet", ca.CASubjectConfig{
				Org:      "Example Ltd",
				OrgUnit:  "Infrastructure",
				Country:  "GB",
				Locality: "London",
				Province: "Greater London",
			})
			Expect(name.Organization).To(Equal([]string{"Example Ltd"}))
			Expect(name.OrganizationalUnit).To(Equal([]string{"Infrastructure"}))
			Expect(name.Country).To(Equal([]string{"GB"}))
			Expect(name.Locality).To(Equal([]string{"London"}))
			Expect(name.Province).To(Equal([]string{"Greater London"}))
		})

		It("produces the same DN a bootstrapped CA certificate carries", func() {
			// The property the shared builder exists to guarantee: a CSR and a
			// self-signed bootstrap must agree, or the parent signs the wrong name.
			cfg := ca.CASubjectConfig{Org: "Example Ltd", Country: "GB"}
			expected := ca.CASubjectName("puppet.example.com", cfg)

			store := storage.New(GinkgoT().TempDir())
			myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
			myCA.CASubject = cfg
			myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(myCA.Init(context.Background())).To(Succeed())

			Expect(myCA.CACert.Subject.CommonName).To(Equal(expected.CommonName))
			Expect(myCA.CACert.Subject.Organization).To(Equal(expected.Organization))
			Expect(myCA.CACert.Subject.Country).To(Equal(expected.Country))
		})
	})
})

// chainWithExpiredRoot builds an in-window intermediate signed by a root whose
// validity has lapsed. Only the root is expired, so a check narrowed to
// certs[0] passes while the chain is still one every agent would reject.
func chainWithExpiredRoot() []*x509.Certificate {
	GinkgoHelper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Expired Root CA"},
		NotBefore:             time.Now().Add(-96 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	Expect(err).NotTo(HaveOccurred())
	root, err := x509.ParseCertificate(rootDER)
	Expect(err).NotTo(HaveOccurred())

	// Issued inside the root's window so the signature chain still verifies;
	// it is only the root that has since lapsed.
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "Intermediate Under Expired Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	Expect(err).NotTo(HaveOccurred())
	inter, err := x509.ParseCertificate(interDER)
	Expect(err).NotTo(HaveOccurred())

	return []*x509.Certificate{inter, root}
}
