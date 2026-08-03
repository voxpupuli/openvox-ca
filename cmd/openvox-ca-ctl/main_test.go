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

package main

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("import subcommand key requirement", func() {
	It("points at openvox-ca import-ca-cert when no key file can exist", func() {
		// A provider-held key has no PEM blob to pass. Failing with cobra's
		// generic "required flag not set" would leave an operator looking for a
		// file that will never exist, so the error names the command that can
		// actually do the job.
		// Exercised through the subcommand constructor rather than the root:
		// the root is assembled inline in main() on this branch, and extracting
		// it here would duplicate a refactor made elsewhere.
		cmd := newImportCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs([]string{"--cadir", GinkgoT().TempDir(), "--cert-bundle", "/dev/null"})
		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("openvox-ca import-ca-cert")))
	})
})
