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

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// certStatusFromRecord is the boundary between the certificate index and the
// status API: it decides whether an index row is complete enough to answer with.
// Its four rejections are what stop a partially-projected row -- one written
// between the blob and the projection, or repaired from a certificate that did
// not match -- from being served as though the CA had asserted it.
//
// Driven in-package rather than through the handler, because a row that fails
// these checks is simply omitted from the response, so at the HTTP layer a
// rejection and an empty index look identical.
var _ = DescribeTable("certStatusFromRecord rejects a record it cannot describe",
	func(mutate func(*storage.CertRecord)) {
		rec := storage.CertRecord{
			InventoryEntry: storage.InventoryEntry{
				Subject:   "node1.example.com",
				Serial:    "a1b2c3",
				NotBefore: "2026-01-01T00:00:00UTC",
				NotAfter:  "2036-01-01T00:00:00UTC",
			},
			CertProjection: storage.CertProjection{Fingerprint: "SHA256:AA:BB"},
			State:          storage.CertStateSigned,
		}
		// The fixture itself must be acceptable, or every entry below passes for
		// the wrong reason.
		_, ok := certStatusFromRecord(rec, time.RFC3339, SerialNumberAsNumber)
		Expect(ok).To(BeTrue(), "the unmutated fixture must be answerable")

		mutate(&rec)
		_, ok = certStatusFromRecord(rec, time.RFC3339, SerialNumberAsNumber)
		Expect(ok).To(BeFalse())
	},
	Entry("no projection at all", func(r *storage.CertRecord) { r.Fingerprint = "" }),
	Entry("a serial that is not hex", func(r *storage.CertRecord) { r.Serial = "zz-not-hex" }),
	Entry("an unparseable NotBefore", func(r *storage.CertRecord) { r.NotBefore = "yesterday" }),
	Entry("an unparseable NotAfter", func(r *storage.CertRecord) { r.NotAfter = "" }),
)

var _ = Describe("certStatusFromRecord on a complete record", func() {
	It("carries the projection through to the response", func() {
		rec := storage.CertRecord{
			InventoryEntry: storage.InventoryEntry{
				Subject:   "node1.example.com",
				Serial:    "ff",
				NotBefore: "2026-01-01T00:00:00UTC",
				NotAfter:  "2036-01-01T00:00:00UTC",
			},
			CertProjection: storage.CertProjection{
				// Stored lower case, as SHA256ColonFingerprint writes it.
				Fingerprint:    "aa:bb",
				DNSAltNames:    []string{"node1.example.com"},
				AuthExtensions: map[string]string{"pp_auth_role": "webserver"},
			},
			State: storage.CertStateRevoked,
		}
		got, ok := certStatusFromRecord(rec, time.RFC3339, SerialNumberAsNumber)
		Expect(ok).To(BeTrue())
		Expect(got.Name).To(Equal("node1.example.com"))
		Expect(got.State).To(Equal(storage.CertStateRevoked))
		Expect(got.SerialNumber).NotTo(BeNil())
		Expect(got.SerialNumber.Int64()).To(Equal(int64(255)), "hex ff, parsed as the number it names")
		Expect(got.DNSAltNames).To(Equal([]string{"DNS:node1.example.com"}))
		Expect(got.AuthorizationExtensions).To(Equal(map[string]string{"pp_auth_role": "webserver"}))
		Expect(got.Fingerprint).To(Equal("AA:BB"), "upper-cased on the way out")
		Expect(got.Fingerprints).To(Equal(map[string]string{"SHA256": "AA:BB", "default": "AA:BB"}))
	})

	// The contract suite replays over the filesystem backend, which has no
	// certificate index, so this is the only spec that sees an index row's
	// stored keys re-keyed for the response.
	It("keys pp_auth_auto_renew by OID, as OpenVox Server does", func() {
		rec := storage.CertRecord{
			InventoryEntry: storage.InventoryEntry{
				Subject: "node1", Serial: "01",
				NotBefore: "2026-01-01T00:00:00UTC", NotAfter: "2036-01-01T00:00:00UTC",
			},
			CertProjection: storage.CertProjection{
				Fingerprint: "SHA256:AA",
				// Keyed as ca.AuthExtensionMap stores it.
				AuthExtensions: map[string]string{"pp_auth_auto_renew": "true", "pp_auth_role": "webserver"},
			},
			State: storage.CertStateSigned,
		}
		got, ok := certStatusFromRecord(rec, time.RFC3339, SerialNumberAsNumber)
		Expect(ok).To(BeTrue())
		Expect(got.AuthorizationExtensions).To(Equal(map[string]string{
			"1.3.6.1.4.1.34380.1.3.2": "true",
			"pp_auth_role":            "webserver",
		}))
	})

	It("leaves out an extension whose OID is the authorisation arc itself", func() {
		rec := storage.CertRecord{
			InventoryEntry: storage.InventoryEntry{
				Subject: "node1", Serial: "01",
				NotBefore: "2026-01-01T00:00:00UTC", NotAfter: "2036-01-01T00:00:00UTC",
			},
			CertProjection: storage.CertProjection{
				Fingerprint: "SHA256:AA",
				// Keyed as ca.AuthExtensionMap stores it; .3.99 is below the arc.
				AuthExtensions: map[string]string{"1.3.6.1.4.1.34380.1.3": "arc", "1.3.6.1.4.1.34380.1.3.99": "custom"},
			},
			State: storage.CertStateSigned,
		}
		got, ok := certStatusFromRecord(rec, time.RFC3339, SerialNumberAsNumber)
		Expect(ok).To(BeTrue())
		Expect(got.AuthorizationExtensions).To(Equal(map[string]string{"1.3.6.1.4.1.34380.1.3.99": "custom"}))
	})

	// responseOIDKeys is kept by hand against OpenVox Server's
	// puppet-short-names, and the contract suite notices a gap only for an OID
	// some fixture happens to record. This compares the two tables instead.
	It("re-keys exactly the authorisation short names OpenVox Server lacks", func() {
		// The authorisation-arc entries of puppet-short-names in OpenVox
		// Server's certificate_authority.clj at 8.14.1.
		upstream := []string{"pp_authorization", "pp_auth_role", "pp_cli_auth"}

		var ours []string
		for oid, name := range ca.PuppetShortNames {
			if strings.HasPrefix(oid, asn1.ObjectIdentifier(ca.PuppetAuthOIDArc).String()+".") {
				ours = append(ours, name)
			}
		}
		var unknown []string
		for _, name := range ours {
			if _, ok := responseOIDKeys[name]; !ok {
				unknown = append(unknown, name)
			}
		}
		Expect(unknown).To(ConsistOf(upstream),
			"an authorisation short name OpenVox Server lacks needs an entry in responseOIDKeys")

		for name, oid := range responseOIDKeys {
			Expect(ca.PuppetShortNames).To(HaveKeyWithValue(oid, name),
				"each responseOIDKeys entry must name the OID ca.PuppetShortNames gives it")
		}
	})

	// Driven here rather than through the handler, which falls back to the
	// stored PEM whenever this function rejects a row: an HTTP spec cannot
	// tell which of the two encoded the serial.
	DescribeTable("encodes the serial in the format it is given",
		func(format SerialNumberFormat, want string) {
			rec := storage.CertRecord{
				InventoryEntry: storage.InventoryEntry{
					Subject: "node1", Serial: "ff",
					NotBefore: "2026-01-01T00:00:00UTC", NotAfter: "2036-01-01T00:00:00UTC",
				},
				CertProjection: storage.CertProjection{Fingerprint: "SHA256:AA"},
				State:          storage.CertStateSigned,
			}
			got, ok := certStatusFromRecord(rec, time.RFC3339, format)
			Expect(ok).To(BeTrue())
			out, err := json.Marshal(got.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).To(Equal(want))
		},
		Entry("as a number by default", SerialNumberAsNumber, `255`),
		Entry("as colon-separated hex when opted in", SerialNumberAsHex, `"FF"`),
	)

	It("substitutes empty collections rather than nulls", func() {
		// The response is JSON-encoded straight to an agent, and a null where a
		// list is expected is a client-side error rather than an empty result.
		rec := storage.CertRecord{
			InventoryEntry: storage.InventoryEntry{
				Subject: "node1", Serial: "01",
				NotBefore: "2026-01-01T00:00:00UTC", NotAfter: "2036-01-01T00:00:00UTC",
			},
			CertProjection: storage.CertProjection{Fingerprint: "SHA256:AA"},
			State:          storage.CertStateSigned,
		}
		got, ok := certStatusFromRecord(rec, time.RFC3339, SerialNumberAsNumber)
		Expect(ok).To(BeTrue())
		Expect(got.DNSAltNames).NotTo(BeNil())
		Expect(got.SubjectAltNames).NotTo(BeNil())
		Expect(got.AuthorizationExtensions).NotTo(BeNil())
	})

	It("lists the projected IP SANs ahead of the DNS SANs in subject_alt_names only", func() {
		rec := storage.CertRecord{
			InventoryEntry: storage.InventoryEntry{
				Subject: "node1", Serial: "01",
				NotBefore: "2026-01-01T00:00:00UTC", NotAfter: "2036-01-01T00:00:00UTC",
			},
			CertProjection: storage.CertProjection{
				Fingerprint: "SHA256:AA",
				DNSAltNames: []string{"node1", "node1.example.com"},
				IPAltNames:  []string{"192.0.2.10", "2001:db8::1"},
			},
			State: storage.CertStateSigned,
		}
		got, ok := certStatusFromRecord(rec, time.RFC3339, SerialNumberAsNumber)
		Expect(ok).To(BeTrue())
		Expect(got.SubjectAltNames).To(Equal([]string{
			"IP:192.0.2.10", "IP:2001:db8::1", "DNS:node1", "DNS:node1.example.com",
		}))
		Expect(got.DNSAltNames).To(Equal([]string{"DNS:node1", "DNS:node1.example.com"}))
	})
})

// The certificate and CSR paths read the SANs off the parsed artefact rather
// than a projection, so each needs its own spec. The SANs are interleaved by
// type on purpose: subject_alt_names groups them, IP first, as OpenVox Server
// does, rather than keeping the order they were written in.
var _ = Describe("subject_alt_names from a parsed certificate or CSR", func() {
	var (
		key  *ecdsa.PrivateKey
		sans []byte
	)

	BeforeEach(func() {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		sans = interleavedSANs()
	})

	It("lists a certificate's IP SANs ahead of its DNS SANs", func() {
		template := &x509.Certificate{
			SerialNumber:    big.NewInt(1),
			Subject:         pkix.Name{CommonName: "node1"},
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Value: sans}},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())

		got := certStatusFromCert("node1", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			storage.CertStateSigned, time.RFC3339, SerialNumberAsNumber)
		Expect(got.SubjectAltNames).To(Equal([]string{
			"IP:192.0.2.10", "IP:2001:db8::1", "DNS:node1", "DNS:node1.example.com",
		}))
		Expect(got.DNSAltNames).To(Equal([]string{"DNS:node1", "DNS:node1.example.com"}))
	})

	It("lists a CSR's IP SANs ahead of its DNS SANs", func() {
		template := &x509.CertificateRequest{
			Subject:         pkix.Name{CommonName: "node1"},
			ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Value: sans}},
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
		Expect(err).NotTo(HaveOccurred())

		got := certStatusFromCSR("node1", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
		Expect(got.SubjectAltNames).To(Equal([]string{
			"IP:192.0.2.10", "IP:2001:db8::1", "DNS:node1", "DNS:node1.example.com",
		}))
		Expect(got.DNSAltNames).To(Equal([]string{"DNS:node1", "DNS:node1.example.com"}))
	})
})

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// interleavedSANs is a subjectAltName extension value written by hand, since
// crypto/x509 groups the SANs it writes by type: DNS, IPv4, DNS, IPv6.
func interleavedSANs() []byte {
	raw := []asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("node1")},
		{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: net.ParseIP("192.0.2.10").To4()},
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("node1.example.com")},
		{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: net.ParseIP("2001:db8::1")},
	}
	out, err := asn1.Marshal(raw)
	Expect(err).NotTo(HaveOccurred())
	return out
}
