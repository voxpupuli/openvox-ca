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

package config_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// A name no real binding uses, so the specs depend on nothing the host exports.
const envHelperVar = "OPENVOX_CA_TEST_ENV_HELPER"

var _ = Describe("EnvBool", func() {
	// Seeded with the opposite of what is set, so a helper that only ever
	// assigned true, or never assigned at all, fails the false rows.
	DescribeTable("overlays a value ParseBool accepts",
		func(value string, seed, want bool) {
			GinkgoT().Setenv(envHelperVar, value)
			dst := seed
			Expect(config.EnvBool(envHelperVar, &dst)).To(Succeed())
			Expect(dst).To(Equal(want))
		},
		Entry("true over false", "true", false, true),
		Entry("false over true", "false", true, false),
		Entry("0 over true", "0", true, false),
		Entry("TRUE over false", "TRUE", false, true),
	)

	DescribeTable("leaves the value alone when the variable is unset or empty",
		func(set bool, seed bool) {
			if set {
				GinkgoT().Setenv(envHelperVar, "")
			}
			dst := seed
			Expect(config.EnvBool(envHelperVar, &dst)).To(Succeed())
			Expect(dst).To(Equal(seed))
		},
		Entry("unset, seeded true", false, true),
		Entry("unset, seeded false", false, false),
		Entry("empty, seeded true", true, true),
		Entry("empty, seeded false", true, false),
	)

	DescribeTable("refuses what ParseBool does not accept, leaving the value alone",
		func(value string) {
			GinkgoT().Setenv(envHelperVar, value)
			dst := true
			Expect(config.EnvBool(envHelperVar, &dst)).To(MatchError(And(
				ContainSubstring(envHelperVar), ContainSubstring("%q", value))))
			Expect(dst).To(BeTrue())
		},
		Entry("yes", "yes"), Entry("on", "on"), Entry("off", "off"), Entry("mixed case", "tRuE"),
	)
})

var _ = Describe("EnvInt", func() {
	DescribeTable("applies what its gate keeps and ignores what it does not",
		func(value string, keep func(int) bool, want int) {
			GinkgoT().Setenv(envHelperVar, value)
			dst := 5
			Expect(config.EnvInt(envHelperVar, &dst, keep)).To(Succeed())
			Expect(dst).To(Equal(want))
		},
		Entry("nil keeps -1", "-1", nil, -1),
		Entry("nil keeps 0", "0", nil, 0),
		Entry("Positive drops -1", "-1", config.Positive, 5),
		Entry("Positive drops 0", "0", config.Positive, 5),
		Entry("Positive keeps 1", "1", config.Positive, 1),
		Entry("NonNegative drops -1", "-1", config.NonNegative, 5),
		Entry("NonNegative keeps 0", "0", config.NonNegative, 0),
		Entry("NonNegative keeps 1", "1", config.NonNegative, 1),
	)

	It("leaves the value alone when the variable is empty", func() {
		GinkgoT().Setenv(envHelperVar, "")
		dst := 5
		Expect(config.EnvInt(envHelperVar, &dst, nil)).To(Succeed())
		Expect(dst).To(Equal(5))
	})

	It("says a whole number too large to hold is out of range, not that it is no number", func() {
		GinkgoT().Setenv(envHelperVar, "99999999999999999999")
		dst := 5
		err := config.EnvInt(envHelperVar, &dst, nil)
		Expect(err).To(MatchError(And(
			ContainSubstring(envHelperVar), ContainSubstring("out of range"))))
		Expect(err.Error()).NotTo(ContainSubstring("not an integer"))
		Expect(dst).To(Equal(5))
	})

	// Refused whatever the gate, before the gate is consulted: a gate that
	// would have dropped the value is not a reason to drop it silently. Each
	// row also pins the remedy the refusal gives, and the one it must not:
	// only a service link is told about enableServiceLinks, since an operator
	// who mistyped a number may have no pod at all.
	DescribeTable("refuses a value that is not a whole number",
		func(value string, keep func(int) bool, remedy, notRemedy string) {
			GinkgoT().Setenv(envHelperVar, value)
			dst := 5
			err := config.EnvInt(envHelperVar, &dst, keep)
			Expect(err).To(MatchError(And(
				ContainSubstring(envHelperVar), ContainSubstring("%q", value),
				ContainSubstring("not an integer"), ContainSubstring(remedy))))
			Expect(err.Error()).NotTo(ContainSubstring(notRemedy))
			Expect(dst).To(Equal(5))
		},
		Entry("a duration", "0s", nil, "set it to a whole number", "service link"),
		Entry("a decimal", "1.5", config.Positive, "set it to a whole number", "service link"),
		Entry("a mistyped port", "80x0", nil, "set it to a whole number", "service link"),
		Entry("a TCP service link", "tcp://10.0.0.1:8140", config.NonNegative,
			"enableServiceLinks: false", "set it to a whole number"),
		Entry("a UDP service link", "udp://10.0.0.1:53", nil,
			"enableServiceLinks: false", "set it to a whole number"),
	)
})
