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

package config

import (
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("absIfSet", func() {
	It("passes an empty string through unchanged", func() {
		Expect(absIfSet("")).To(BeEmpty())
	})

	It("resolves a relative path to its absolute form", func() {
		got := absIfSet("certs/ca.pem")
		Expect(filepath.IsAbs(got)).To(BeTrue())
		want, err := filepath.Abs("certs/ca.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(want))
	})

	It("leaves an already-absolute, clean path unchanged", func() {
		const p = "/etc/puppet-ca/ca.pem"
		Expect(absIfSet(p)).To(Equal(p))
	})

	It("cleans an absolute path that contains redundant elements", func() {
		// filepath.Abs runs filepath.Clean, so even an absolute input is
		// normalised — the function is not a pure pass-through for absolute
		// paths, despite its name implying it only acts when "set".
		Expect(absIfSet("/etc/puppet-ca/../puppet-ca/ca.pem")).To(Equal("/etc/puppet-ca/ca.pem"))
		Expect(absIfSet("/etc/puppet-ca/")).To(Equal("/etc/puppet-ca"))
	})
})
