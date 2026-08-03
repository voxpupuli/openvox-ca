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

package version

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// White-box: test binaries are never VCS-stamped, so the suffix formatting in
// full() is unreachable through Full(); it is exercised directly here.
var _ = DescribeTable("full",
	func(revision, commitTime string, dirty bool, want string) {
		Expect(full("1.2.3", revision, commitTime, dirty)).To(Equal(want))
	},
	Entry("no VCS metadata yields the bare version",
		"", "", false,
		"1.2.3"),
	Entry("no VCS revision suppresses the whole suffix even when dirty",
		"", "2026-07-25T09:00:00Z", true,
		"1.2.3"),
	Entry("full 40-char revision is truncated to 12",
		"0123456789abcdef0123456789abcdef01234567", "", false,
		"1.2.3 (commit 0123456789ab)"),
	Entry("short revision is kept as-is",
		"abc123", "", false,
		"1.2.3 (commit abc123)"),
	Entry("exactly-12-char revision is kept unmodified",
		"0123456789ab", "", false,
		"1.2.3 (commit 0123456789ab)"),
	Entry("commit time is appended after the revision",
		"0123456789abcdef0123456789abcdef01234567", "2026-07-25T09:00:00Z", false,
		"1.2.3 (commit 0123456789ab, 2026-07-25T09:00:00Z)"),
	Entry("dirty marker comes last",
		"0123456789abcdef0123456789abcdef01234567", "2026-07-25T09:00:00Z", true,
		"1.2.3 (commit 0123456789ab, 2026-07-25T09:00:00Z, dirty)"),
	Entry("dirty without commit time still gets the marker",
		"abc123", "", true,
		"1.2.3 (commit abc123, dirty)"),
)
