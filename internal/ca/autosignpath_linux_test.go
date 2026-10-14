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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// mountPoints reads /proc/self/mountinfo and returns every mount point this
// process can see, and the read-only directories among them, unescaping the
// octal escapes it uses for spaces and the like. It is the specs' independent
// oracle for what readOnlyMountRoot asks the kernel. A later line for the same
// point is a mount stacked on top of the earlier one and hides it, so the last
// line for each point decides.
func mountPoints() (all map[string]bool, readOnly []string) {
	GinkgoHelper()
	data, err := os.ReadFile("/proc/self/mountinfo")
	Expect(err).NotTo(HaveOccurred())
	all = map[string]bool{}
	var order []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		point, err := strconv.Unquote(`"` + fields[4] + `"`)
		if err != nil {
			continue
		}
		if _, seen := all[point]; !seen {
			order = append(order, point)
		}
		all[point] = false
		for _, opt := range strings.Split(fields[5], ",") {
			if opt == "ro" {
				all[point] = true
			}
		}
	}
	for _, point := range order {
		if fi, err := os.Lstat(point); all[point] && err == nil && fi.IsDir() {
			readOnly = append(readOnly, point)
		}
	}
	return all, readOnly
}

// The real kernel answer, which the white-box hook specs stand in for. Where
// the host offers no read-only mount (a bare CI runner may not), the spec says
// so and skips rather than passing on nothing.
var _ = Describe("readOnlyMountRoot on Linux", func() {
	It("recognises the root of a read-only mount", func() {
		_, roots := mountPoints()
		if len(roots) == 0 {
			Skip("no read-only mount is visible to this process")
		}
		Expect(readOnlyMountRoot(roots[0])).To(BeTrue(), "mount point %q", roots[0])
	})

	// The narrowing the exemption depends on: under a read-only root
	// filesystem, or a service manager's ProtectSystem=strict, every directory
	// is on a read-only mount, and only the mount's root may be exempt.
	It("does not extend that to a directory beneath the root", func() {
		all, roots := mountPoints()
		for _, root := range roots {
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, e := range entries {
				sub := filepath.Join(root, e.Name())
				fi, err := os.Lstat(sub)
				if _, isMount := all[sub]; err != nil || !fi.IsDir() || isMount {
					continue // not a directory, or a mount point of its own
				}
				Expect(readOnlyMountRoot(sub)).To(BeFalse(), "%q is on read-only %q but is not its root", sub, root)
				return
			}
		}
		Skip("no read-only mount with an ordinary subdirectory is visible to this process")
	})
})
