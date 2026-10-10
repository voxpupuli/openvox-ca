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

package storage

import (
	"context"
	"io/fs"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The lines OpenVox Server writes to its inventory.txt, as its writer
// (write-cert-to-inventory-unlocked! in certificate_authority.clj) formats
// them: a "0x" serial zero-padded to four digits, and "/" followed by the
// subject's X.500 name. The first is its own CA certificate.
const (
	ovsCALine    = "0x0001 2026-01-01T00:00:00UTC 2041-01-01T00:00:00UTC /CN=Puppet CA: puppet.example.com"
	ovsAgentLine = "0x0002 2026-01-02T00:00:00UTC 2031-01-02T00:00:00UTC /CN=agent.example.com"
	ovsWebLine   = "0x0003 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=web.example.com"
)

var _ = Describe("Reading a filesystem inventory written by OpenVox Server", func() {
	DescribeTable("parseBlobInventoryEntry normalises each form to this CA's",
		func(line, serial, subject string) {
			e, ok := parseBlobInventoryEntry(line)
			Expect(ok).To(BeTrue())
			Expect(e.Serial).To(Equal(serial))
			Expect(e.Subject).To(Equal(subject))
		},
		Entry("OpenVox Server's line", ovsAgentLine, "2", "agent.example.com"),
		Entry("this CA's line", "9F3C 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /agent.example.com",
			"9F3C", "agent.example.com"),
		Entry("an upper-case 0X prefix", "0X00ff 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=a",
			"FF", "a"),
		Entry("a zero-padded serial without a prefix", "0002 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /a",
			"2", "a"),
		// Not certnames, so never reduced: none of them can match one.
		Entry("OpenVox Server's CA certificate, whose CN has spaces", ovsCALine,
			"1", "CN=Puppet CA: puppet.example.com"),
		Entry("an X.500 name with more than a CN", "0x0004 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=a,O=b",
			"4", "CN=a,O=b"),
		Entry("an older Puppet CA's slash-separated name", "0x0005 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=a/O=b",
			"5", "CN=a/O=b"),
		Entry("an empty CN", "0x0006 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=",
			"6", "CN="),
		// Left as written, for the readers that report malformed serials.
		Entry("a serial that is not hex", "NOTHEX 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /a",
			"NOTHEX", "a"),
		Entry("a bare 0x", "0x 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /a",
			"0x", "a"),
	)

	DescribeTable("openVoxInventoryLine reproduces OpenVox Server's own lines byte for byte",
		func(line string) {
			e, ok := parseBlobInventoryEntry(line)
			Expect(ok).To(BeTrue())
			Expect(openVoxInventoryLine(e, "unused")).To(Equal(line))
		},
		Entry("an agent's certificate", ovsAgentLine),
		Entry("its own CA certificate", ovsCALine),
		Entry("a serial wider than the padding", "0x1A2B3C4D5E6F708192A3B4C5D6E7F801 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=web.example.com"),
	)

	DescribeTable("openVoxInventoryLine renders this CA's canonical line in OpenVox Server's form",
		func(canonical, want string) {
			e, ok := parseInventoryEntry(canonical)
			Expect(ok).To(BeTrue())
			Expect(openVoxInventoryLine(e, canonical)).To(Equal(want))
		},
		Entry("a small serial is padded to four digits",
			"2F 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /agent.example.com",
			"0x002F 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=agent.example.com"),
		Entry("a random 128-bit serial is not truncated",
			"9F3C4D5E6F708192A3B4C5D6E7F80112 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /agent.example.com",
			"0x9F3C4D5E6F708192A3B4C5D6E7F80112 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=agent.example.com"),
		Entry("a lower-case serial is upper-cased",
			"9f3c 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /agent.example.com",
			"0x9F3C 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=agent.example.com"),
		Entry("a subject already in X.500 form is not given a second CN",
			"1 2026-01-01T00:00:00UTC 2041-01-01T00:00:00UTC /CN=Puppet CA: puppet.example.com",
			ovsCALine),
		Entry("a serial that is not hex is left as the caller wrote the line",
			"NOTHEX 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /a",
			"NOTHEX 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /a"),
	)

	It("appends to the filesystem inventory in OpenVox Server's format", func() {
		ctx := context.Background()
		svc := New(GinkgoT().TempDir())
		Expect(svc.EnsureDirs(ctx)).To(Succeed())
		Expect(svc.TouchInventory(ctx)).To(Succeed())
		Expect(svc.InitHMAC(ctx)).To(Succeed())

		Expect(svc.AppendInventory(ctx,
			FormatInventoryLine("2F", time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
				time.Date(2031, 1, 3, 0, 0, 0, 0, time.UTC), "agent.example.com"))).To(Succeed())

		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the HMAC must cover the line as written")
		Expect(string(got)).To(Equal("0x002F 2026-01-03T00:00:00UTC 2031-01-03T00:00:00UTC /CN=agent.example.com\n"))
	})

	It("leaves the structured backends' parser reading lines as written", func() {
		// The structured backends store what parseInventoryEntry returns and
		// fold their hash chain over its rendering, so it must not normalise:
		// a store holding "0002" rows has to go on reading them as "0002".
		e, ok := parseInventoryEntry(ovsAgentLine)
		Expect(ok).To(BeTrue())
		Expect(e.Serial).To(Equal("0x0002"))
		Expect(e.Subject).To(Equal("CN=agent.example.com"))
	})

	It("keeps the whole of a subject with spaces in it", func() {
		e, ok := parseInventoryEntry(ovsCALine)
		Expect(ok).To(BeTrue())
		Expect(e.Subject).To(Equal("CN=Puppet CA: puppet.example.com"))
	})

	Context("through the StorageService", func() {
		var (
			ctx = context.Background()
			svc *StorageService
		)

		// A file holding both implementations' lines, as one does after
		// openvox-ca has run on OpenVox Server's directory: agent.example.com
		// was issued by OpenVox Server and then renewed by this CA, and
		// web.example.com by this CA and then again by OpenVox Server.
		const (
			oursAgent = "9F3C 2026-02-01T00:00:00UTC 2031-02-01T00:00:00UTC /agent.example.com"
			oursWeb   = "A1B2 2026-01-04T00:00:00UTC 2031-01-04T00:00:00UTC /web.example.com"
			ovsWebNew = "0x0004 2026-02-02T00:00:00UTC 2031-02-02T00:00:00UTC /CN=web.example.com"
		)

		BeforeEach(func() {
			svc = New(GinkgoT().TempDir())
			Expect(svc.EnsureDirs(ctx)).To(Succeed())
			blob := ovsCALine + "\n" + ovsAgentLine + "\n" + oursWeb + "\n" + oursAgent + "\n" + ovsWebNew + "\n"
			Expect(svc.Backend().Put(ctx, KeyInventory, []byte(blob), BlobPrivate)).To(Succeed())
			Expect(svc.InitHMAC(ctx)).To(Succeed())
		})

		DescribeTable("LatestSerialForSubject resolves a name whichever implementation issued it last",
			func(subject, serial string) {
				Expect(svc.LatestSerialForSubject(ctx, subject)).To(Equal(serial))
			},
			Entry("ours after OpenVox Server's", "agent.example.com", "9F3C"),
			Entry("OpenVox Server's after ours", "web.example.com", "4"),
		)

		It("resolves a name only OpenVox Server issued", func() {
			// This is the lookup revocation by name goes through. Read as
			// "CN=agent.example.com", OpenVox Server's line never matched, so
			// the certificate could not be revoked by name at all.
			Expect(svc.Backend().Put(ctx, KeyInventory, []byte(ovsAgentLine+"\n"), BlobPrivate)).To(Succeed())
			Expect(svc.RebuildInventoryHMAC(ctx)).To(Succeed())
			Expect(svc.LatestSerialForSubject(ctx, "agent.example.com")).To(Equal("2"))
		})

		It("does not resolve OpenVox Server's CA certificate as a certname", func() {
			_, err := svc.LatestSerialForSubject(ctx, "Puppet")
			Expect(err).To(MatchError(fs.ErrNotExist))
		})

		It("finds an OpenVox Server serial by its canonical form", func() {
			Expect(svc.SerialExists(ctx, "2")).To(BeTrue())
			Expect(svc.SubjectForSerial(ctx, "2")).To(Equal("agent.example.com"))
		})

		It("refuses to append a serial OpenVox Server already issued", func() {
			// The duplicate check is on the number, not the spelling.
			err := svc.AppendInventory(ctx, "2 2026-03-01T00:00:00UTC 2031-03-01T00:00:00UTC /other.example.com")
			Expect(err).To(MatchError(ErrDuplicateSerial))
		})

		It("lists every entry in this CA's form", func() {
			entries, err := svc.InventoryEntries(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(ConsistOf(
				InventoryEntry{Serial: "1", NotBefore: "2026-01-01T00:00:00UTC", NotAfter: "2041-01-01T00:00:00UTC", Subject: "CN=Puppet CA: puppet.example.com"},
				InventoryEntry{Serial: "2", NotBefore: "2026-01-02T00:00:00UTC", NotAfter: "2031-01-02T00:00:00UTC", Subject: "agent.example.com"},
				InventoryEntry{Serial: "A1B2", NotBefore: "2026-01-04T00:00:00UTC", NotAfter: "2031-01-04T00:00:00UTC", Subject: "web.example.com"},
				InventoryEntry{Serial: "9F3C", NotBefore: "2026-02-01T00:00:00UTC", NotAfter: "2031-02-01T00:00:00UTC", Subject: "agent.example.com"},
				InventoryEntry{Serial: "4", NotBefore: "2026-02-02T00:00:00UTC", NotAfter: "2031-02-02T00:00:00UTC", Subject: "web.example.com"},
			))
		})

		It("reads the mixed file without changing a byte of it", func() {
			before, err := svc.ReadInventory(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(svc.LatestSerialForSubject(ctx, "agent.example.com")).To(Equal("9F3C"))
			Expect(svc.InventoryEntries(ctx)).To(HaveLen(5))
			after, err := svc.ReadInventory(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before))
		})
	})

	Context("migrated to a structured backend", func() {
		It("lands every line of a mixed-format inventory in the canonical form", func() {
			// Migrating off the filesystem is the conversion step, so it is
			// where both forms become the structured backends' one.
			ctx := context.Background()
			src := New(GinkgoT().TempDir())
			Expect(src.EnsureDirs(ctx)).To(Succeed())
			Expect(src.Backend().Put(ctx, KeyCACert, []byte("ca-cert-pem"), BlobPublic)).To(Succeed())
			mixed := ovsCALine + "\n" + ovsAgentLine + "\n" +
				"A1B2 2026-01-04T00:00:00UTC 2031-01-04T00:00:00UTC /web.example.com\n" +
				"0002F 2026-01-05T00:00:00UTC 2031-01-05T00:00:00UTC /padded.example.com\n"
			Expect(src.Backend().Put(ctx, KeyInventory, []byte(mixed), BlobPrivate)).To(Succeed())
			Expect(src.InitHMAC(ctx)).To(Succeed())

			dst := NewWithBackend(newSQLiteBackend(), "")
			_, err := MigrateService(ctx, src, dst, MigrateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dst.InitHMAC(ctx)).To(Succeed())

			got, err := dst.ReadInventory(ctx)
			Expect(err).NotTo(HaveOccurred(), "the destination's chain must verify over the converted rows")
			Expect(string(got)).To(Equal(
				"1 2026-01-01T00:00:00UTC 2041-01-01T00:00:00UTC /CN=Puppet CA: puppet.example.com\n" +
					"2 2026-01-02T00:00:00UTC 2031-01-02T00:00:00UTC /agent.example.com\n" +
					"A1B2 2026-01-04T00:00:00UTC 2031-01-04T00:00:00UTC /web.example.com\n" +
					"2F 2026-01-05T00:00:00UTC 2031-01-05T00:00:00UTC /padded.example.com\n"))
			Expect(dst.LatestSerialForSubject(ctx, "agent.example.com")).To(Equal("2"))
		})

		It("refuses a line it cannot read rather than dropping it", func() {
			// The filesystem backend keeps a line it cannot parse, and
			// migration is where such a line meets a structured store. It
			// must fail loudly there, never arrive without it.
			ctx := context.Background()
			src := New(GinkgoT().TempDir())
			Expect(src.EnsureDirs(ctx)).To(Succeed())
			Expect(src.Backend().Put(ctx, KeyCACert, []byte("ca-cert-pem"), BlobPublic)).To(Succeed())
			Expect(src.Backend().Put(ctx, KeyInventory,
				[]byte(ovsAgentLine+"\nhalf a line\n"+ovsWebLine+"\n"), BlobPrivate)).To(Succeed())

			dst := NewWithBackend(newSQLiteBackend(), "")
			_, err := MigrateService(ctx, src, dst, MigrateOptions{})
			Expect(err).To(MatchError(ContainSubstring("malformed inventory line")))
		})

		It("copies a filesystem-to-filesystem inventory byte for byte", func() {
			ctx := context.Background()
			src := New(GinkgoT().TempDir())
			Expect(src.EnsureDirs(ctx)).To(Succeed())
			Expect(src.Backend().Put(ctx, KeyCACert, []byte("ca-cert-pem"), BlobPublic)).To(Succeed())
			mixed := ovsAgentLine + "\nA1B2 2026-01-04T00:00:00UTC 2031-01-04T00:00:00UTC /web.example.com\n"
			Expect(src.Backend().Put(ctx, KeyInventory, []byte(mixed), BlobPrivate)).To(Succeed())

			dst := New(GinkgoT().TempDir())
			_, err := MigrateService(ctx, src, dst, MigrateOptions{})
			Expect(err).NotTo(HaveOccurred())
			got, err := dst.Backend().Get(ctx, KeyInventory)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(got)).To(Equal(mixed))
		})
	})
})
