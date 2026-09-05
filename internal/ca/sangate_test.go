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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// These exercise the AllowSubjectAltNames policy, which decides whether a
// submitted CSR may name anything beyond its own certname. The gate lives on
// signWithDuration, the one function every CSR-signing path funnels through, so
// each path is covered here rather than at its own entry point — except the
// offline minting path, which does not funnel through it at all and is asserted
// to stay exempt.
//
// The fixtures deliberately never make a requested SAN equal to the subject
// unless the spec is about that equality: a CSR whose names happen to match the
// one name the gate always permits would pass whether the gate ran or not, and
// would prove nothing about it.
var _ = Describe("Subject alternative name policy", func() {
	var (
		ctx   context.Context
		myCA  *ca.CA
		store *storage.StorageService
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		// The policy is indifferent to key algorithm; ECDSA keeps each spec off
		// an RSA-2048 generation.
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	// sanCSR builds a PEM CSR for cn, with whatever SANs mutate installs.
	sanCSR := func(cn string, mutate func(*x509.CertificateRequest)) []byte {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
		if mutate != nil {
			mutate(tmpl)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}

	submit := func(subject string, csrPEM []byte) {
		GinkgoHelper()
		_, err := myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
	}

	// csrOf reparses a CSR so a failure message can name what was requested.
	csrOf := func(csrPEM []byte) *x509.CertificateRequest {
		GinkgoHelper()
		block, _ := pem.Decode(csrPEM)
		Expect(block).NotTo(BeNil())
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return csr
	}

	parse := func(certPEM []byte) *x509.Certificate {
		GinkgoHelper()
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	Describe("with the default policy (SANs not allowed)", func() {
		It("refuses a CSR requesting a DNS name that is not its own", func() {
			submit("web01", sanCSR("web01", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"puppet.example.com"}
			}))

			_, err := myCA.Sign(ctx, "web01")
			Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames),
				"a CSR requesting DNS:puppet.example.com must be refused")

			// Nothing was issued: the refusal happens before any certificate
			// reaches storage, so the impersonating name never exists.
			_, err = store.GetCert(ctx, "web01")
			Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue(), "no certificate should have been stored")
		})

		It("leaves the refused CSR pending rather than discarding it", func() {
			// Matching upstream, which saves the request and then declines to
			// sign it: an operator who turns the setting on can sign it later
			// without the agent having to submit again.
			submit("web02", sanCSR("web02", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"puppet.example.com"}
			}))
			_, err := myCA.Sign(ctx, "web02")
			Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames),
				"a CSR requesting DNS:puppet.example.com must be refused")

			Expect(store.GetCSR(ctx, "web02")).NotTo(BeEmpty())
		})

		DescribeTable("refuses non-DNS SAN types, which upstream's own gate misses",
			func(mutate func(*x509.CertificateRequest)) {
				csrPEM := sanCSR("node-x", mutate)
				submit("node-x", csrPEM)
				_, err := myCA.Sign(ctx, "node-x")
				Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames),
					"a CSR requesting %v / %v / %v must be refused",
					csrOf(csrPEM).IPAddresses, csrOf(csrPEM).EmailAddresses, csrOf(csrPEM).URIs)
			},
			Entry("an IP address", func(t *x509.CertificateRequest) {
				t.IPAddresses = []net.IP{net.ParseIP("10.0.0.1")}
			}),
			Entry("an email address", func(t *x509.CertificateRequest) {
				t.EmailAddresses = []string{"ops@example.com"}
			}),
			Entry("a URI", func(t *x509.CertificateRequest) {
				u, err := url.Parse("spiffe://example.com/ns/default/sa/node")
				Expect(err).NotTo(HaveOccurred())
				t.URIs = []*url.URL{u}
			}),
		)

		It("allows a lone DNS SAN equal to the subject, per RFC 2818", func() {
			submit("web03", sanCSR("web03", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"web03"}
			}))

			certPEM, err := myCA.Sign(ctx, "web03")
			Expect(err).NotTo(HaveOccurred())
			Expect(parse(certPEM).DNSNames).To(ConsistOf("web03"))
		})

		It("compares that exemption case-insensitively, as DNS is", func() {
			submit("web04", sanCSR("web04", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"WEB04"}
			}))

			_, err := myCA.Sign(ctx, "web04")
			Expect(err).NotTo(HaveOccurred())
		})

		It("refuses the subject's own name alongside one that is not its own", func() {
			// The exemption covers a CSR complying with RFC 2818, not a CSR
			// smuggling an extra name in beside a compliant one.
			submit("web05", sanCSR("web05", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"web05", "puppet.example.com"}
			}))

			_, err := myCA.Sign(ctx, "web05")
			Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames),
				"DNS:puppet.example.com must still be refused beside the subject's own name")
		})

		It("names the refused entries in the log but not in the error", func() {
			// The split is the point: an operator reading the CA's log can see
			// which names were refused, while the requester — who reaches this
			// endpoint before holding any certificate — learns only that the
			// request was refused, and cannot use the refusal to ask which
			// names this CA would have issued.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			submit("web07", sanCSR("web07", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"puppet.example.com"}
			}))
			_, err := myCA.Sign(ctx, "web07")
			Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames),
				"a CSR requesting DNS:puppet.example.com must be refused")

			Expect(buf.String()).To(ContainSubstring("DNS:puppet.example.com"))
			Expect(buf.String()).To(ContainSubstring("allow_subject_alt_names"))
			Expect(err.Error()).NotTo(ContainSubstring("puppet.example.com"))
		})

		It("gates the autosign path, not just explicit signing", func() {
			autoCA := ca.New(store, ca.AutosignConfig{Mode: "true"}, "puppet.test")
			autoCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			autoCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(autoCA.Init(ctx)).To(Succeed())

			_, err := autoCA.SaveRequest(ctx, "auto01", sanCSR("auto01", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"puppet.example.com"}
			}))
			Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames),
				"autosigning a CSR requesting DNS:puppet.example.com must be refused")

			_, err = store.GetCert(ctx, "auto01")
			Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue(), "autosign must not issue what signing would refuse")
		})

		It("does not gate the offline minting path", func() {
			// Deliberate: those names come from an operator's --dns flags, not
			// from a request. Generate reaches issueLeafLocked without passing
			// through signWithDuration at all, which is where GenerateWithOptions'
			// doc comment says the filtering belongs — on the path that parses
			// network input.
			res, err := myCA.Generate(ctx, "offline01", []string{"offline01.example.com"})
			Expect(err).NotTo(HaveOccurred())
			Expect(parse(res.CertificatePEM).DNSNames).To(ContainElement("offline01.example.com"))
		})
	})

	Describe("with the policy turned on", func() {
		BeforeEach(func() { myCA.AllowSubjectAltNames = true })

		It("signs a CSR requesting another name, and keeps it on the certificate", func() {
			submit("web06", sanCSR("web06", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"web06.example.com", "alt.example.com"}
			}))

			certPEM, err := myCA.Sign(ctx, "web06")
			Expect(err).NotTo(HaveOccurred())
			Expect(parse(certPEM).DNSNames).To(ConsistOf("web06.example.com", "alt.example.com"))
		})
	})

	Describe("renewal", func() {
		// A certificate that legitimately holds SANs must stay renewable after
		// the policy is turned off, or enabling the gate strands exactly the
		// nodes it was enabled for. What it must not do is let a renewal
		// introduce a name the presented certificate never had.
		var original *x509.Certificate

		BeforeEach(func() {
			myCA.AllowSubjectAltNames = true
			submit("renew01", sanCSR("renew01", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"renew01.example.com", "service.example.com"}
			}))
			certPEM, err := myCA.Sign(ctx, "renew01")
			Expect(err).NotTo(HaveOccurred())
			original = parse(certPEM)

			// The gate now applies to everything that follows.
			myCA.AllowSubjectAltNames = false
		})

		It("renews a certificate that already carries the SANs it asks for", func() {
			renewed, err := myCA.Renew(ctx, "renew01", sanCSR("renew01", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"renew01.example.com", "service.example.com"}
			}), original)
			Expect(err).NotTo(HaveOccurred())
			Expect(parse(renewed).DNSNames).To(ConsistOf("renew01.example.com", "service.example.com"))
		})

		It("refuses a renewal that adds a name the presented certificate lacks", func() {
			_, err := myCA.Renew(ctx, "renew01", sanCSR("renew01", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"renew01.example.com", "service.example.com", "puppet.example.com"}
			}), original)
			Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames),
				"renewal must not introduce DNS:puppet.example.com, which the presented certificate lacks")
		})

		It("carries SANs through auto-renewal, which carries no CSR to judge", func() {
			renewed, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			Expect(parse(renewed).DNSNames).To(ConsistOf("renew01.example.com", "service.example.com"))
		})
	})
})
