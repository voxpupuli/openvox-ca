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
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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
		Expect(got.AuthorizationExtensions).NotTo(BeNil())
	})
})
