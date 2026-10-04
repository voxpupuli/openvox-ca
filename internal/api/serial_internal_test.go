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
	"math/big"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// mustHex parses a hex literal for a table entry; a typo in one is a broken
// spec, not a case to test.
func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex literal " + s)
	}
	return n
}

// The cases are the ones openssl was measured against when the hex form was
// chosen: a 128-bit serial with its top bit set (DER adds a 00 sign byte that
// openssl does not print), one with it clear, one whose top byte is zero (15
// significant bytes, which openssl does not pad back to 16), and small serials,
// which openssl pads to whole bytes.
var _ = Describe("CertSerial encoding", func() {
	DescribeTable("as a JSON number, by default",
		func(n *big.Int) {
			for _, f := range []SerialNumberFormat{"", SerialNumberAsNumber} {
				out, err := json.Marshal(newCertSerial(n, f))
				Expect(err).NotTo(HaveOccurred())
				// Compared as text, so a value that passed through a float64
				// anywhere would show as a lost digit rather than an equal number.
				Expect(string(out)).To(Equal(n.String()), "format %q", f)
			}
		},
		Entry("128 bits, top bit set", mustHex("9F3C2A1B4D5E6F708192A3B4C5D6E7F8")),
		Entry("128 bits, top bit clear", mustHex("3A5C2A1B4D5E6F708192A3B4C5D6E7F8")),
		Entry("top byte zero", mustHex("005C2A1B4D5E6F708192A3B4C5D6E7F8")),
		Entry("small", big.NewInt(10)),
	)

	DescribeTable("as colon-separated hex when opted in",
		func(n *big.Int, want string) {
			out, err := json.Marshal(newCertSerial(n, SerialNumberAsHex))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(out)).To(Equal(`"` + want + `"`))
		},
		Entry("128 bits, top bit set: no DER sign byte",
			mustHex("9F3C2A1B4D5E6F708192A3B4C5D6E7F8"), "9F:3C:2A:1B:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8"),
		Entry("128 bits, top bit clear",
			mustHex("3A5C2A1B4D5E6F708192A3B4C5D6E7F8"), "3A:5C:2A:1B:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8"),
		Entry("top byte zero: 15 bytes, not padded to 16",
			mustHex("005C2A1B4D5E6F708192A3B4C5D6E7F8"), "5C:2A:1B:4D:5E:6F:70:81:92:A3:B4:C5:D6:E7:F8"),
		Entry("odd digit count: padded to a whole byte", mustHex("A5C2"+"A1B"), "0A:5C:2A:1B"),
		Entry("single digit: padded to a whole byte", big.NewInt(10), "0A"),
		Entry("small, top bit set: still no sign byte", big.NewInt(0x80), "80"),
		Entry("two bytes", big.NewInt(0x1234), "12:34"),
		Entry("zero", big.NewInt(0), "00"),
		// Reachable from an index row: its serial is parsed with SetString,
		// which accepts a sign.
		Entry("negative: keeps its sign", big.NewInt(-0x1234), "-12:34"),
	)

	It("keeps a value's own digits rather than sharing the caller's big.Int", func() {
		n := big.NewInt(10)
		s := newCertSerial(n, SerialNumberAsNumber)
		n.SetInt64(11)
		Expect(s.Int64()).To(Equal(int64(10)))
	})
})

var _ = DescribeTable("ParseSerialNumberFormat",
	func(in string, want SerialNumberFormat, ok bool) {
		got, err := ParseSerialNumberFormat(in)
		if !ok {
			Expect(err).To(MatchError(ContainSubstring(`"number" or "hex"`)))
			return
		}
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(want))
	},
	Entry("unset selects the default", "", SerialNumberAsNumber, true),
	Entry("number", "number", SerialNumberAsNumber, true),
	Entry("hex", "hex", SerialNumberAsHex, true),
	Entry("the old decimal string is not a format", "decimal", SerialNumberFormat(""), false),
	Entry("case and surrounding space are ignored", " HEX ", SerialNumberAsHex, true),
	Entry("anything else is refused", "hexadecimal", SerialNumberFormat(""), false),
)
