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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// A renewal recreates the certificate it renews, as OpenVox Server's
// renew-certificate! does: the subject and every extension come from that
// certificate, and only the key may change, through a re-key CSR. Nothing else
// a renewal CSR carries reaches the certificate.
//
// The original here is minted directly with the CA key, because no issuance
// path produces a certificate carrying everything these specs need to see
// carried: all four SAN types, a narrowed key usage and extended key usage, a
// Puppet authorisation extension and one outside the Puppet arc. Every renewal
// CSR asks for something different on each count, so a spec passes only if the
// renewal ignored the CSR's request rather than happening to agree with it.
var _ = Describe("Renewal keeps the certificate it renews", func() {
	const subject = "renew-parity"

	var (
		ctx         context.Context
		myCA        *ca.CA
		store       *storage.StorageService
		original    *x509.Certificate
		originalKey *ecdsa.PrivateKey
	)

	ppRole := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 13}
	// An authorisation-arc extension the original does not hold, so a renewal
	// CSR asking for it asks for authority the certificate was never given.
	ppAuthRole := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 13}
	// Under IANA's example enterprise number (RFC 5612), so it cannot collide
	// with an extension anything here interprets.
	oidKept := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}
	oidAsked := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 2}
	oidAKI := asn1.ObjectIdentifier{2, 5, 29, 35}
	oidBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}

	// The extensions issueLeafLocked sets afresh on every certificate, which a
	// renewal therefore does not copy: authority and subject key identifiers,
	// CRL distribution points, authority information access, basic constraints.
	refreshed := []asn1.ObjectIdentifier{
		{2, 5, 29, 35}, {2, 5, 29, 14}, {2, 5, 29, 31}, {1, 3, 6, 1, 5, 5, 7, 1, 1}, {2, 5, 29, 19},
	}
	carriedOf := func(cert *x509.Certificate) []pkix.Extension {
		var out []pkix.Extension
		for _, ext := range cert.Extensions {
			if !slices.ContainsFunc(refreshed, ext.Id.Equal) {
				out = append(out, ext)
			}
		}
		return out
	}

	extOf := func(cert *x509.Certificate, oid asn1.ObjectIdentifier) pkix.Extension {
		GinkgoHelper()
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid) {
				return ext
			}
		}
		Fail("certificate carries no " + oid.String() + " extension")
		return pkix.Extension{}
	}

	extValue := func(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid) {
				return ext.Value, true
			}
		}
		return nil, false
	}

	marshal := func(v any) []byte {
		GinkgoHelper()
		b, err := asn1.Marshal(v)
		Expect(err).NotTo(HaveOccurred())
		return b
	}

	parse := func(certPEM []byte) *x509.Certificate {
		GinkgoHelper()
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	// renewalCSR builds a CSR for subject over key, asking for a different
	// organisation, more SANs and different extensions than original carries.
	renewalCSR := func(key crypto.Signer) []byte {
		GinkgoHelper()
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:     pkix.Name{CommonName: subject, Organization: []string{"Requested Org"}},
			DNSNames:    []string{subject, "alias.example.com", "extra.example.com"},
			IPAddresses: []net.IP{net.ParseIP("10.9.9.9")},
			ExtraExtensions: []pkix.Extension{
				{Id: ppRole, Value: marshal("db")},
				{Id: ppAuthRole, Value: marshal("admin")},
				{Id: oidAsked, Value: marshal("asked")},
			},
		}, key)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}

	newKey := func() *ecdsa.PrivateKey {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		return key
	}

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		uri, err := url.Parse("spiffe://puppet.test/node/renew-parity")
		Expect(err).NotTo(HaveOccurred())
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		Expect(err).NotTo(HaveOccurred())
		originalKey = newKey()
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: serial,
			Subject: pkix.Name{
				CommonName:         subject,
				Organization:       []string{"Original Org"},
				OrganizationalUnit: []string{"Ops"},
			},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			DNSNames:              []string{subject, "alias.example.com"},
			IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
			EmailAddresses:        []string{"ops@example.com"},
			URIs:                  []*url.URL{uri},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			SubjectKeyId:          []byte{1, 2, 3, 4},
			CRLDistributionPoints: []string{"http://old.example/crl"},
			OCSPServer:            []string{"http://old.example/ocsp"},
			ExtraExtensions: []pkix.Extension{
				// An authority key identifier naming no key this CA holds, and
				// basic constraints marked non-critical, which issueLeafLocked
				// never builds: so a renewal that carried either rather than
				// setting it afresh would show it.
				{Id: oidAKI, Value: marshal(struct {
					ID []byte `asn1:"optional,tag:0"`
				}{ID: []byte{9, 9, 9, 9}})},
				{Id: oidBasicConstraints, Critical: false, Value: marshal(struct{}{})},
				{Id: ppRole, Value: marshal("web")},
				{Id: ca.OIDPpCliAuth, Value: marshal("true")},
				{Id: oidKept, Value: marshal("kept")},
			},
		}, myCA.CACert, &originalKey.PublicKey, myCA.CAKey)
		Expect(err).NotTo(HaveOccurred())
		original, err = x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())

		// Each extension a spec below says is carried must really be on the
		// original, or that spec would pass on an absence.
		Expect(carriedOf(original)).To(HaveLen(6),
			"the original must carry SANs, key usage, extended key usage, pp_role, pp_cli_auth and one non-Puppet extension")
		// Likewise each refreshed value must differ from the one the CA would
		// build, or the spec that says it is set afresh would pass on a copy.
		Expect(original.AuthorityKeyId).NotTo(Equal(myCA.CACert.SubjectKeyId))
		Expect(extOf(original, oidBasicConstraints).Critical).To(BeFalse())

		// Set after minting, so the renewed certificate's pointers can only
		// have come from here.
		myCA.CRLURLs = []string{"http://new.example/crl"}
		myCA.OCSPURLs = []string{"http://new.example/ocsp"}
	})

	Context("with a CSR (a re-key)", func() {
		var csrKey *ecdsa.PrivateKey

		BeforeEach(func() {
			csrKey = newKey()
			// The permissive value, so that the SAN policy cannot be what stops
			// the CSR's request. A CA that still built a re-key from its CSR
			// would then issue what the CSR asked for, and each spec below
			// would fail on its own assertion rather than on a refusal. The
			// table that is about the setting sets it per entry.
			myCA.AllowSubjectAltNames = true
		})

		renew := func() *x509.Certificate {
			GinkgoHelper()
			certPEM, err := myCA.Renew(ctx, subject, renewalCSR(csrKey), original)
			Expect(err).NotTo(HaveOccurred())
			return parse(certPEM)
		}

		It("certifies the CSR's key with every extension of the original", func() {
			renewed := renew()
			Expect(renewed.PublicKey).To(Equal(csrKey.Public()))
			Expect(carriedOf(renewed)).To(ConsistOf(carriedOf(original)))
		})

		DescribeTable("keeps the original SANs and ignores the CSR's, whatever allow_subject_alt_names says",
			func(allow bool) {
				myCA.AllowSubjectAltNames = allow
				renewed := renew()
				Expect(renewed.DNSNames).To(ConsistOf(subject, "alias.example.com"))
				Expect(renewed.IPAddresses).To(HaveLen(1))
				Expect(renewed.IPAddresses[0].Equal(net.ParseIP("10.0.0.1"))).To(BeTrue())
				Expect(renewed.EmailAddresses).To(ConsistOf("ops@example.com"))
				Expect(renewed.URIs).To(HaveLen(1))
				Expect(renewed.URIs[0].String()).To(Equal("spiffe://puppet.test/node/renew-parity"))
			},
			Entry("when SANs on a CSR are not allowed", false),
			Entry("when SANs on a CSR are allowed", true),
		)

		It("keeps the original subject, not the CSR's", func() {
			renewed := renew()
			Expect(renewed.Subject.CommonName).To(Equal(subject))
			Expect(renewed.Subject.Organization).To(Equal([]string{"Original Org"}))
			Expect(renewed.Subject.OrganizationalUnit).To(Equal([]string{"Ops"}))
			// The original's subject was encoded by crypto/x509, as every
			// subject this CA issues is, so it must come back byte for byte.
			Expect(renewed.RawSubject).To(Equal(original.RawSubject))
		})

		It("keeps the original Puppet extensions and takes none from the CSR", func() {
			v, ok := extValue(renew(), ppRole)
			Expect(ok).To(BeTrue())
			Expect(v).To(Equal(marshal("web")), "pp_role must be the original's, not the CSR's")
		})

		It("keeps the original's authorisation extensions", func() {
			// A certificate that holds pp_cli_auth keeps it across a re-key
			// exactly as across an auto-renewal, whatever the CSR carries.
			v, ok := extValue(renew(), ca.OIDPpCliAuth)
			Expect(ok).To(BeTrue(), "a re-key must not strip pp_cli_auth from a certificate that holds it")
			Expect(v).To(Equal(marshal("true")))
		})

		It("takes no authorisation extension from the CSR", func() {
			_, ok := extValue(renew(), ppAuthRole)
			Expect(ok).To(BeFalse(), "a re-key must not grant authority the original certificate does not hold")
		})

		It("keeps the original key usage and extended key usage", func() {
			renewed := renew()
			Expect(renewed.KeyUsage).To(Equal(x509.KeyUsageDigitalSignature))
			Expect(renewed.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageClientAuth),
				"a re-key must not widen a narrow certificate to the default pair")
		})

		It("keeps extensions outside the Puppet arc and adds none from the CSR", func() {
			renewed := renew()
			v, ok := extValue(renewed, oidKept)
			Expect(ok).To(BeTrue())
			Expect(v).To(Equal(marshal("kept")))
			_, ok = extValue(renewed, oidAsked)
			Expect(ok).To(BeFalse(), "an extension only the CSR asked for must not appear")
		})

		It("clears a request already queued for the subject", func() {
			// Left queued, it would let a later sign mint a second certificate
			// for a name that has just been renewed.
			Expect(store.SaveCSR(ctx, subject, renewalCSR(newKey()))).To(Succeed())
			renew()
			Expect(store.HasCSR(ctx, subject)).To(BeFalse())
		})

		It("renews even when it cannot remove a queued request", func() {
			// The removal is best-effort, like retiring the predecessor: by
			// the time it runs the replacement is stored, and failing the
			// renewal then would leave the agent without the certificate it
			// has just been issued.
			if os.Geteuid() == 0 {
				Skip("root ignores directory permissions")
			}
			Expect(store.SaveCSR(ctx, subject, renewalCSR(newKey()))).To(Succeed())
			Expect(os.Chmod(store.CSRDir(), 0o555)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(store.CSRDir(), 0o755) })
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })

			renewed := renew()
			Expect(renewed.PublicKey).To(Equal(csrKey.Public()))
			Expect(store.HasCSR(ctx, subject)).To(BeTrue(), "the fixture must really have made the removal fail")
			// The twin of the spec below: it asserts this line's absence, so
			// this one proves the line exists to be absent.
			Expect(buf.String()).To(ContainSubstring("Could not delete pending CSR"))
		})

		It("logs nothing about a queued request when there is none", func() {
			// The ordinary re-key has nothing queued, and the absent request
			// must not read as a failure to remove one.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })

			Expect(store.HasCSR(ctx, subject)).To(BeFalse())
			renew()
			Expect(buf.String()).NotTo(ContainSubstring("Could not delete pending CSR"))
		})

		It("stores no request when it refuses a re-key", func() {
			// A renewal CSR is not a request the queue should ever hold: an
			// administrator signing it later would issue whatever it asked for.
			weak, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Renew(ctx, subject, renewalCSR(weak), original)
			Expect(err).To(MatchError(ca.ErrKeyPolicy))
			Expect(store.HasCSR(ctx, subject)).To(BeFalse())
		})
	})

	Context("without a CSR (auto-renewal)", func() {
		It("keeps the original key and every extension of the original", func() {
			certPEM, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			renewed := parse(certPEM)
			Expect(renewed.PublicKey).To(Equal(original.PublicKey))
			Expect(carriedOf(renewed)).To(ConsistOf(carriedOf(original)))
			Expect(renewed.Subject.Organization).To(Equal([]string{"Original Org"}))
		})
	})

	It("sets the key identifiers, constraints and the CA's own pointers afresh", func() {
		myCA.AllowSubjectAltNames = true
		csrKey := newKey()
		certPEM, err := myCA.Renew(ctx, subject, renewalCSR(csrKey), original)
		Expect(err).NotTo(HaveOccurred())
		renewed := parse(certPEM)

		spki, err := x509.MarshalPKIXPublicKey(csrKey.Public())
		Expect(err).NotTo(HaveOccurred())
		ski := sha1.Sum(spki)
		Expect(renewed.SubjectKeyId).To(Equal(ski[:]), "the subject key identifier must name the key certified")
		Expect(renewed.AuthorityKeyId).To(Equal(myCA.CACert.SubjectKeyId))
		Expect(renewed.BasicConstraintsValid).To(BeTrue())
		Expect(renewed.IsCA).To(BeFalse())
		Expect(extOf(renewed, oidBasicConstraints).Critical).To(BeTrue(),
			"basic constraints must be the CA's own, not the original's non-critical copy")
		Expect(renewed.CRLDistributionPoints).To(Equal([]string{"http://new.example/crl"}))
		Expect(renewed.OCSPServer).To(Equal([]string{"http://new.example/ocsp"}))
	})

	It("drops the original's CRL and OCSP pointers when the CA publishes neither", func() {
		myCA.CRLURLs = nil
		myCA.OCSPURLs = nil
		certPEM, err := myCA.AutoRenew(ctx, original)
		Expect(err).NotTo(HaveOccurred())
		renewed := parse(certPEM)
		Expect(renewed.CRLDistributionPoints).To(BeEmpty())
		Expect(renewed.OCSPServer).To(BeEmpty())
	})

	Context("when the original carries no key usage or extended key usage", func() {
		// Both absent means unrestricted. A renewal gives it the CA's defaults
		// instead, which can only narrow it.
		var bare *x509.Certificate

		BeforeEach(func() {
			myCA.AllowSubjectAltNames = true
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			Expect(err).NotTo(HaveOccurred())
			key := newKey()
			der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
				SerialNumber: serial,
				Subject:      pkix.Name{CommonName: subject},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
				DNSNames:     []string{subject},
			}, myCA.CACert, &key.PublicKey, myCA.CAKey)
			Expect(err).NotTo(HaveOccurred())
			bare, err = x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())
			Expect(bare.KeyUsage).To(BeZero())
			Expect(bare.ExtKeyUsage).To(BeEmpty())
		})

		DescribeTable("gives it the CA's default key usage and extended key usage",
			func(renew func() ([]byte, error)) {
				certPEM, err := renew()
				Expect(err).NotTo(HaveOccurred())
				renewed := parse(certPEM)
				Expect(renewed.KeyUsage).To(Equal(x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment))
				Expect(renewed.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth))
			},
			Entry("on auto-renewal", func() ([]byte, error) { return myCA.AutoRenew(ctx, bare) }),
			Entry("on a re-key", func() ([]byte, error) { return myCA.Renew(ctx, subject, renewalCSR(newKey()), bare) }),
		)
	})

	Context("when the original carries an authorisation extension", func() {
		// The line an operator alerts on for a freshly minted administrator
		// credential must be written for a renewed one too, and must say
		// whether the grant moved to a new key.
		var logged *bytes.Buffer

		BeforeEach(func() {
			myCA.AllowSubjectAltNames = true
			logged = &bytes.Buffer{}
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })
		})

		grantRecords := func() []map[string]any {
			GinkgoHelper()
			var out []map[string]any
			for _, line := range bytes.Split(bytes.TrimSpace(logged.Bytes()), []byte("\n")) {
				if len(line) == 0 {
					continue
				}
				var rec map[string]any
				Expect(json.Unmarshal(line, &rec)).To(Succeed())
				if rec["msg"] == "Issued certificate carrying a Puppet authorisation extension" {
					out = append(out, rec)
				}
			}
			return out
		}

		DescribeTable("logs the grant at WARN, naming the kind of renewal",
			func(renew func() ([]byte, error), kind string) {
				_, err := renew()
				Expect(err).NotTo(HaveOccurred())
				recs := grantRecords()
				Expect(recs).To(HaveLen(1), logged.String())
				Expect(recs[0]).To(HaveKeyWithValue("level", "WARN"))
				Expect(recs[0]).To(HaveKeyWithValue("subject", subject))
				Expect(recs[0]).To(HaveKeyWithValue("grant", "pp_cli_auth=true"))
				Expect(recs[0]).To(HaveKeyWithValue("renewal", kind))
				// The audit event, a literal because from 1.0.0 it is public
				// API: renaming audit.CertificateAuthGrantIssued fails here.
				Expect(recs[0]).To(HaveKeyWithValue("event", "certificate.auth_grant_issued"))
			},
			Entry("on a re-key", func() ([]byte, error) { return myCA.Renew(ctx, subject, renewalCSR(newKey()), original) }, "re-key"),
			Entry("on auto-renewal", func() ([]byte, error) { return myCA.AutoRenew(ctx, original) }, "same key"),
			// The attribute follows the key, not the entry point: a renewal CSR
			// over the certificate's own key moves the grant nowhere.
			Entry("on a renewal CSR over the original's own key", func() ([]byte, error) {
				return myCA.Renew(ctx, subject, renewalCSR(originalKey), original)
			}, "same key"),
		)
	})

	Context("when the original carries no subject alternative name", func() {
		// promote_cn_to_san adds the Common Name as a DNS SAN on first issuance.
		// A renewal keeps the SAN set the certificate has, as OpenVox Server's
		// does, so a certificate issued without one is renewed without one,
		// even from a CSR that carries none, which is the case promotion
		// would act on at signing.
		var nameless *x509.Certificate

		BeforeEach(func() {
			myCA.PromoteCNToSAN = true
			serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			Expect(err).NotTo(HaveOccurred())
			key := newKey()
			der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
				SerialNumber: serial,
				Subject:      pkix.Name{CommonName: subject},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(24 * time.Hour),
			}, myCA.CACert, &key.PublicKey, myCA.CAKey)
			Expect(err).NotTo(HaveOccurred())
			nameless, err = x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())
			Expect(nameless.DNSNames).To(BeEmpty())
		})

		bareCSR := func() []byte {
			GinkgoHelper()
			der, err := x509.CreateCertificateRequest(rand.Reader,
				&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, newKey())
			Expect(err).NotTo(HaveOccurred())
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		}

		DescribeTable("renews it without promoting the Common Name, whatever promote_cn_to_san says",
			func(renew func() ([]byte, error)) {
				certPEM, err := renew()
				Expect(err).NotTo(HaveOccurred())
				Expect(parse(certPEM).DNSNames).To(BeEmpty())
			},
			Entry("on auto-renewal", func() ([]byte, error) { return myCA.AutoRenew(ctx, nameless) }),
			Entry("on a re-key", func() ([]byte, error) { return myCA.Renew(ctx, subject, bareCSR(), nameless) }),
		)
	})
})
