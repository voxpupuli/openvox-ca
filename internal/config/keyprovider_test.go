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

var _ = Describe("CAKeyProviderConfig.Validate", func() {
	DescribeTable("accepts the known providers",
		func(provider string) {
			err := config.CAKeyProviderConfig{CAKeyProvider: provider}.Validate()
			Expect(err).NotTo(HaveOccurred())
		},
		Entry("empty (defaults to file)", ""),
		Entry("file", "file"),
		Entry("openbao", "openbao"),
	)

	// An unrecognised provider must be a hard error: silently falling back to
	// local-file custody would write the CA private key to disk when the
	// operator asked for it to live in OpenBao.
	DescribeTable("rejects an unknown provider rather than falling back to file",
		func(provider string) {
			err := config.CAKeyProviderConfig{CAKeyProvider: provider}.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(provider))
		},
		Entry("a typo", "openba"),
		Entry("an anticipated-but-unimplemented backend", "pkcs11"),
		Entry("nonsense", "somewhere-else"),
	)
})
