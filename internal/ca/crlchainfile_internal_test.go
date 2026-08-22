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

package ca

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// publishedUpstream is unexported and both its callers now hand it bytes they
// already read, so this is the only place its own contract can be stated: the
// distinction between "nothing is published" and "nothing could be read".
// Collapsing the two is what would let a rolled-back chain file through, and it
// is one nil argument away from being reintroduced.
var _ = Describe("publishedUpstream", func() {
	It("refuses to check regressions against a chain nobody read", func() {
		c := &CA{}
		_, err := c.publishedUpstream(nil)
		Expect(err).To(MatchError(ContainSubstring("the published chain was not read")),
			"a nil blob must fail closed, not read as an empty published set")
	})

	It("accepts an empty blob as a genuinely empty published chain", func() {
		// A CA whose CRL has not been written yet. Refusing this too would stop
		// it ever publishing a chain.
		c := &CA{}
		upstream, err := c.publishedUpstream([]byte{})
		Expect(err).NotTo(HaveOccurred())
		Expect(upstream).To(BeEmpty())
	})
})
