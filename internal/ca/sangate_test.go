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
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// uriStrings renders URI SANs for comparison, as ca.IPAddressStrings does
// addresses.
func uriStrings(uris []*url.URL) []string {
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		out = append(out, u.String())
	}
	return out
}

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

			certPEM, err := myCA.Sign(ctx, "web04")
			Expect(err).NotTo(HaveOccurred())
			// The gate folds case to decide; issuance does not rewrite, so the
			// requested spelling is what reaches the certificate. Asserting the
			// issued set as the sibling spec does, rather than only that Sign
			// returned, is what would catch a dropped or rewritten name.
			Expect(parse(certPEM).DNSNames).To(ConsistOf("WEB04"))
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

		It("caps the logged entries but not the count", func() {
			// A CSR can carry a great many names. The operator needs enough to
			// recognise what was asked for; the count is what tells them the
			// list was trimmed, so a cap that silently lost the total would
			// leave them reading ten of an unknown number.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			names := make([]string, 0, 12)
			for i := range 12 {
				names = append(names, fmt.Sprintf("alt%02d.example.com", i))
			}
			submit("web08", sanCSR("web08", func(t *x509.CertificateRequest) {
				t.DNSNames = names
			}))
			_, err := myCA.Sign(ctx, "web08")
			Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames))

			Expect(strings.Count(buf.String(), "DNS:")).To(Equal(10),
				"the logged list should be capped at maxLoggedSANs")
			Expect(buf.String()).To(ContainSubstring("disallowed_count=12"),
				"the count must report the whole set, not the truncated list")
		})

		It("truncates an over-long entry rather than logging it whole", func() {
			// The count cap alone leaves the record's size in the requester's
			// hands: this endpoint takes a mebibyte of body without a client
			// certificate, and one refused CSR wrote all of it.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			long := strings.Repeat("a", 4096) + ".example.com"
			submit("web09", sanCSR("web09", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{long}
			}))
			_, err := myCA.Sign(ctx, "web09")
			Expect(err).To(MatchError(ca.ErrDisallowedSubjectAltNames))

			Expect(buf.Len()).To(BeNumerically("<", 1024),
				"a 4KiB name must not reach the log record whole")
			Expect(buf.String()).To(ContainSubstring("...(truncated)"))
			Expect(buf.String()).To(ContainSubstring("disallowed_count=1"),
				"truncating the value must not lose the count")
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
			// Deliberate: Generate reaches issueLeafLocked without passing
			// through signWithDuration at all. The exemption is about where the
			// names come from — an administrator, not an agent's CSR — rather
			// than about being offline: POST /generate/{subject}?dns= shares
			// this path and is a request, admitted as tierAdminOnly.
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

		// The gate judges all four kinds, so with it on all four must reach
		// the certificate: OpenVox Server copies a CSR's SAN extension whole,
		// and a kind judged but not issued is signed and then silently missing,
		// which surfaces only as a TLS verification failure later.
		It("carries IP, email and URI SANs onto the certificate alongside DNS ones", func() {
			spiffe, err := url.Parse("spiffe://example.com/ns/default/sa/web10")
			Expect(err).NotTo(HaveOccurred())
			submit("web10", sanCSR("web10", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"web10.example.com"}
				t.IPAddresses = []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("2001:db8::1")}
				t.EmailAddresses = []string{"ops@example.com"}
				t.URIs = []*url.URL{spiffe}
			}))

			certPEM, err := myCA.Sign(ctx, "web10")
			Expect(err).NotTo(HaveOccurred())
			cert := parse(certPEM)
			Expect(cert.DNSNames).To(ConsistOf("web10.example.com"))
			Expect(ca.IPAddressStrings(cert.IPAddresses)).To(ConsistOf("10.0.0.1", "2001:db8::1"))
			Expect(cert.EmailAddresses).To(ConsistOf("ops@example.com"))
			Expect(uriStrings(cert.URIs)).To(ConsistOf("spiffe://example.com/ns/default/sa/web10"))
		})

		// One kind at a time, so a regression dropping a single kind names it.
		// Each also pins promotion beside that kind: with no DNS SAN requested
		// the CN is added whatever else the CSR carries, not only beside an IP.
		DescribeTable("carries a SAN of each non-DNS kind when it is the only one requested",
			func(mutate func(*x509.CertificateRequest), issued func(*x509.Certificate) []string, want string) {
				submit("node-y", sanCSR("node-y", mutate))
				certPEM, err := myCA.Sign(ctx, "node-y")
				Expect(err).NotTo(HaveOccurred())
				cert := parse(certPEM)
				Expect(issued(cert)).To(ConsistOf(want))
				Expect(cert.DNSNames).To(ConsistOf("node-y"),
					"the CN must still be promoted when the CSR requests no DNS SAN")
			},
			Entry("an IP address",
				func(t *x509.CertificateRequest) { t.IPAddresses = []net.IP{net.ParseIP("192.0.2.20")} },
				func(c *x509.Certificate) []string { return ca.IPAddressStrings(c.IPAddresses) },
				"192.0.2.20"),
			Entry("an email address",
				func(t *x509.CertificateRequest) { t.EmailAddresses = []string{"node-y@example.com"} },
				func(c *x509.Certificate) []string { return c.EmailAddresses },
				"node-y@example.com"),
			Entry("a URI",
				func(t *x509.CertificateRequest) {
					u, err := url.Parse("urn:example:node-y")
					Expect(err).NotTo(HaveOccurred())
					t.URIs = []*url.URL{u}
				},
				func(c *x509.Certificate) []string { return uriStrings(c.URIs) },
				"urn:example:node-y"),
		)

		It("still promotes the CN when the CSR carries several SAN kinds but no DNS one", func() {
			// promote_cn_to_san keys on DNS names, not on every kind: a
			// certificate holding only IP or email SANs cannot be verified by
			// hostname, and OpenVox Server adds the CN whatever else is there.
			// The table above covers each kind alone; this is the mix.
			submit("web11", sanCSR("web11", func(t *x509.CertificateRequest) {
				t.IPAddresses = []net.IP{net.ParseIP("10.0.0.11")}
				t.EmailAddresses = []string{"web11@example.com"}
			}))

			certPEM, err := myCA.Sign(ctx, "web11")
			Expect(err).NotTo(HaveOccurred())
			cert := parse(certPEM)
			Expect(cert.DNSNames).To(ConsistOf("web11"))
			Expect(ca.IPAddressStrings(cert.IPAddresses)).To(ConsistOf("10.0.0.11"))
			Expect(cert.EmailAddresses).To(ConsistOf("web11@example.com"))
		})

		It("carries them through the autosign path too", func() {
			autoCA := ca.New(store, ca.AutosignConfig{Mode: "true"}, "puppet.test")
			autoCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			autoCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			autoCA.AllowSubjectAltNames = true
			Expect(autoCA.Init(ctx)).To(Succeed())

			signed, err := autoCA.SaveRequest(ctx, "auto02", sanCSR("auto02", func(t *x509.CertificateRequest) {
				t.IPAddresses = []net.IP{net.ParseIP("10.0.0.2")}
			}))
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeTrue(), "autosign: true should have signed the request")

			certPEM, err := store.GetCert(ctx, "auto02")
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.IPAddressStrings(parse(certPEM).IPAddresses)).To(ConsistOf("10.0.0.2"))
		})

		It("keeps them through renewal once the policy is turned off again", func() {
			// The renewal paths already carried all four kinds; what was
			// missing was a CSR-issued certificate that held them. Renewal
			// must not lose them, nor consult the policy that admitted them.
			submit("web12", sanCSR("web12", func(t *x509.CertificateRequest) {
				t.IPAddresses = []net.IP{net.ParseIP("10.0.0.12")}
				t.EmailAddresses = []string{"web12@example.com"}
			}))
			certPEM, err := myCA.Sign(ctx, "web12")
			Expect(err).NotTo(HaveOccurred())
			original := parse(certPEM)
			myCA.AllowSubjectAltNames = false

			renewed, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			cert := parse(renewed)
			Expect(ca.IPAddressStrings(cert.IPAddresses)).To(ConsistOf("10.0.0.12"))
			Expect(cert.EmailAddresses).To(ConsistOf("web12@example.com"))
		})
	})

	// crypto/x509 refuses to parse a 16-byte ::ffff:a.b.c.d SAN, in a
	// certificate and in a request alike, so a CSR asking for one never reaches
	// the queue and cannot produce a certificate this CA, and every Go TLS peer,
	// would then be unable to read. Parsing comes before the policy, so the
	// refusal holds whatever allow_subject_alt_names says, as the docs promise;
	// both settings are entries so that neither half rests on the other. The
	// extension is built by hand because CreateCertificateRequest would write
	// the address as 4 bytes.
	DescribeTable("never issues an IPv4-mapped IP SAN, because the CSR carrying one is refused at submission",
		func(allow bool) {
			myCA.AllowSubjectAltNames = allow
			mapped, err := asn1.Marshal([]asn1.RawValue{{
				Class: asn1.ClassContextSpecific, Tag: 7, Bytes: net.ParseIP("::ffff:192.0.2.11").To16(),
			}})
			Expect(err).NotTo(HaveOccurred())
			csrPEM := sanCSR("web13", func(t *x509.CertificateRequest) {
				t.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: mapped}}
			})

			_, err = myCA.SaveRequest(ctx, "web13", csrPEM)
			Expect(err).To(MatchError(ContainSubstring("IPv4-mapped")))
			_, err = store.GetCSR(ctx, "web13")
			Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue(), "the refused CSR must not be queued")
		},
		Entry("with the policy turned on", true),
		Entry("with the policy turned off", false),
	)

	Describe("renewal", func() {
		// Renewal is outside the gate: it takes every name from the
		// certificate it renews and only the public key from its CSR, as
		// OpenVox Server's renewal does. So a certificate legitimately holding
		// SANs stays renewable after the policy is turned off, and a renewal
		// CSR asking for a new name gets the certificate's names instead,
		// rather than a refusal.
		var original *x509.Certificate

		BeforeEach(func() {
			myCA.AllowSubjectAltNames = true
			submit("renew01", sanCSR("renew01", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"renew01.example.com", "service.example.com"}
			}))
			certPEM, err := myCA.Sign(ctx, "renew01")
			Expect(err).NotTo(HaveOccurred())
			original = parse(certPEM)

			// Off for everything that follows, which is what would refuse a
			// renewal if renewal still reached the gate.
			myCA.AllowSubjectAltNames = false
		})

		It("renews a certificate that already carries the SANs it asks for", func() {
			renewed, err := myCA.Renew(ctx, "renew01", sanCSR("renew01", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"renew01.example.com", "service.example.com"}
			}), original)
			Expect(err).NotTo(HaveOccurred())
			Expect(parse(renewed).DNSNames).To(ConsistOf("renew01.example.com", "service.example.com"))
		})

		It("renews without a name the CSR adds, rather than refusing it", func() {
			renewed, err := myCA.Renew(ctx, "renew01", sanCSR("renew01", func(t *x509.CertificateRequest) {
				t.DNSNames = []string{"renew01.example.com", "service.example.com", "puppet.example.com"}
			}), original)
			Expect(err).NotTo(HaveOccurred())
			Expect(parse(renewed).DNSNames).To(ConsistOf("renew01.example.com", "service.example.com"),
				"renewal must not introduce DNS:puppet.example.com, which the presented certificate lacks")
		})

		It("carries SANs through auto-renewal, which carries no CSR to judge", func() {
			renewed, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			Expect(parse(renewed).DNSNames).To(ConsistOf("renew01.example.com", "service.example.com"))
		})
	})
})
