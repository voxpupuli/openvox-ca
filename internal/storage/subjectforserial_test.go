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

package storage_test

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("StorageService SubjectForSerial", func() {
	var (
		ctx   = context.Background()
		store *storage.StorageService
	)

	BeforeEach(func() {
		tmpDir, err := os.MkdirTemp("", "openvox-ca-subjectforserial-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

		store = storage.New(tmpDir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		// "00FF" is deliberately zero-padded, as an inventory written by an
		// older version with sequential serials would be; "0A" is not. Nothing
		// here goes through the CA, so both sides of the comparison are as
		// varied as a real inventory's are. The subjects are in OpenVox
		// Server's "/CN=" form, which a filesystem inventory reads as the
		// bare certname.
		Expect(store.AppendInventory(ctx,
			"0A 2026-01-01T00:00:00UTC 2027-01-01T00:00:00UTC /CN=first")).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"00FF 2026-01-02T00:00:00UTC 2027-01-02T00:00:00UTC /CN=second")).To(Succeed())
		// A row whose serial is not hex at all. parseInventoryEntry takes
		// fields[0] verbatim with no validation, so a hand-edited row or one
		// from a foreign tool produces this. It sits BEFORE the last good row
		// on purpose: what needs pinning is that the scan continues past it.
		Expect(store.AppendInventory(ctx,
			"NOTHEX 2026-01-04T00:00:00UTC 2027-01-04T00:00:00UTC /CN=malformed")).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"ZZZZ 2026-01-05T00:00:00UTC 2027-01-05T00:00:00UTC /CN=malformed-two")).To(Succeed())
		Expect(store.AppendInventory(ctx,
			"1b 2026-01-03T00:00:00UTC 2027-01-03T00:00:00UTC /CN=third")).To(Succeed())
	})

	It("skips an unparseable row and keeps scanning, and still reports the skips", func() {
		// If the skip were an abort, one bad row would make every serial after
		// it unresolvable — and so unrevokable — with nothing to say why.
		//
		// The warning is asserted on the SUCCESS path too, not just the
		// not-found one. The emission is deferred precisely so every return
		// reports the same way; moving it back inline to the not-found return
		// would leave the other spec green while an operator whose migrated
		// inventory carries bad rows got no warning on the revocation that
		// actually succeeded — the case where knowing matters most.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		Expect(store.SubjectForSerial(ctx, "1B")).To(Equal("third"))

		Expect(strings.Count(buf.String(), "unparseable serials")).To(Equal(1))
		Expect(buf.String()).To(ContainSubstring("count=2"))
	})

	It("reports the unparseable rows once, with a count", func() {
		// One line per bad row would be unbounded in inventory size, emitted
		// under the cluster CRL lock while an operator watches the log for the
		// outcome of a single revocation. The count is what makes the one line
		// useful, and it is why both emission sites were collapsed into one.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		_, err := store.SubjectForSerial(ctx, "BEEF")
		Expect(err).To(MatchError(fs.ErrNotExist))

		Expect(strings.Count(buf.String(), "unparseable serials")).To(Equal(1))
		Expect(buf.String()).To(ContainSubstring("count=2"))
	})

	// The normalisation is on both sides, which is what makes the stored
	// rendering irrelevant. A lookup that compared the strings as written would
	// pass the first of these and fail the rest.
	DescribeTable("matches regardless of how either side is written",
		func(query, subject string) {
			Expect(store.SubjectForSerial(ctx, query)).To(Equal(subject))
		},
		Entry("query and entry both canonical", "0A", "first"),
		Entry("query lowercase, entry uppercase", "0a", "first"),
		Entry("query padded, entry unpadded", "0000000A", "first"),
		Entry("query unpadded, entry padded", "FF", "second"),
		Entry("query lowercase, entry padded uppercase", "ff", "second"),
		Entry("query uppercase, entry lowercase", "1B", "third"),
		Entry("query surrounded by whitespace", "  0A\n", "first"),
		Entry("query 0x-prefixed, as inventory.txt writes it", "0x000A", "first"),
	)

	It("wraps fs.ErrNotExist for a serial no entry carries", func() {
		_, err := store.SubjectForSerial(ctx, "BEEF")
		Expect(err).To(MatchError(fs.ErrNotExist))
	})

	// The output alphabet is a property the go/log-injection exclusion in
	// .github/codeql/codeql-config.yml rests on: the value CA.RevokeSerial logs
	// is this function's output, so if it can only ever be [0-9A-F] it cannot
	// carry a newline, a quote or a separator into a log line. Asserted rather
	// than argued, so the claim is checkable by anyone who doubts it.
	//
	// This originally underwrote two per-alert dismissals on PR #213. Those are
	// history now -- the rule is excluded centrally rather than dismissed alert
	// by alert -- but the property is what makes the exclusion honest for this
	// value, so it is still worth pinning.
	DescribeTable("emits only uppercase hexadecimal, whatever it is given",
		func(in string) {
			out, err := storage.NormaliseSerial(in)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(MatchRegexp(`^[0-9A-F]+$`),
				"NormaliseSerial(%q) = %q; anything outside [0-9A-F] could reach a log line", in, out)
		},
		Entry("canonical", "0A"),
		Entry("lowercase", "0a"),
		Entry("zero-padded", "000000000A"),
		Entry("leading whitespace", "   0A"),
		Entry("trailing newline", "0A\n"),
		Entry("newline both ends", "\n0A\n"),
		Entry("tab-wrapped", "\t0A\t"),
		Entry("carriage return", "0A\r"),
		Entry("explicit plus", "+1A"),
		Entry("very large", strings.Repeat("F", 256)),
		Entry("zero", "0"),
		// strings.TrimSpace is Unicode-aware, so these are accepted and
		// canonicalised rather than rejected. They matter more than the ASCII
		// entries above: U+2028 and U+2029 are line breaks to a JSON- or
		// JS-based log viewer, which is the reading of "log injection" the
		// exclusion has to answer. What these pin is that the separator is
		// stripped rather than carried into the output.
		Entry("U+2028 line separator", "\u20280A\u2028"),
		Entry("U+2029 paragraph separator", "\u20290A\u2029"),
		Entry("U+0085 next line", "\u00850A\u0085"),
		Entry("U+00A0 no-break space", "\u00a00A\u00a0"),
	)

	// The other half of "nothing the caller typed can reach a log line": on the
	// failure path the value returned must be empty, not the raw input.
	DescribeTable("returns nothing at all when it rejects",
		func(in string) {
			out, err := storage.NormaliseSerial(in)
			Expect(err).To(MatchError(storage.ErrMalformedSerial))
			Expect(out).To(BeEmpty(),
				"a rejected serial must not be handed back to a caller that might log it")
		},
		Entry("non-hex letters", "nope"),
		Entry("interior newline", "0A\nforged"),
		Entry("interior U+2028", "0A\u2028forged"),
		Entry("a bare 0x", "0x"),
		Entry("negative", "-1A"),
		Entry("empty", ""),
	)

	DescribeTable("rejects input that is not a hexadecimal serial",
		func(bad string) {
			_, err := store.SubjectForSerial(ctx, bad)
			Expect(err).To(MatchError(storage.ErrMalformedSerial))
		},
		Entry("empty", ""),
		Entry("whitespace only", "   "),
		Entry("non-hex letters", "nope"),
		Entry("two 0x prefixes", "0x0x0A"),
		Entry("negative", "-1"),
		Entry("embedded space", "0 A"),
	)
})
