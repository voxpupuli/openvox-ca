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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

var _ = Describe("AuthGrant", func() {
	It("renders the Puppet short name for a real grant", func() {
		// This string reaches the audit log and the operator-facing messages,
		// so it is a contract rather than a debugging aid: "pp_cli_auth=true"
		// is what an operator greps for when asking who minted an admin
		// credential.
		Expect(ca.PpCliAuth().String()).To(Equal("pp_cli_auth=true"))
	})

	It("renders a zero value without pretending it is a grant", func() {
		// ca.AuthGrant is exported, so a zero value is constructible from
		// another package even though its fields are not. It must never format
		// as something that reads like a real OID.
		Expect(ca.AuthGrant{}.String()).To(Equal("<invalid>"))
	})
})
