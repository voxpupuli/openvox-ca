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
	"slices"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// visibleMount is one mount point from /proc/self/mountinfo, and whether
// statfs(2) would call it read-only.
type visibleMount struct {
	point    string
	readOnly bool
}

// mountPoints reads /proc/self/mountinfo and returns, in the order the kernel
// lists them, the mount points this process can actually reach, with every
// point it lists in all. It is the specs' independent oracle for what
// readOnlyMountRoot asks the kernel.
//
// Three details keep it honest. A mount is read-only if either its per-mount
// options or its superblock options say "ro", because statfs ORs the two.
// A later line for the same point is a mount stacked on top that hides the
// earlier one, so the last line for a point decides. And a later mount on an
// ancestor hides everything beneath it, so such a point is left out.
func mountPoints() (all map[string]bool, visible []visibleMount) {
	GinkgoHelper()
	data, err := os.ReadFile("/proc/self/mountinfo")
	Expect(err).NotTo(HaveOccurred())

	type entry struct {
		point    string
		readOnly bool
	}
	var entries []entry
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		sep := slices.Index(fields, "-")
		if len(fields) < 6 || sep < 6 || len(fields) < sep+4 {
			continue
		}
		point, err := strconv.Unquote(`"` + fields[4] + `"`)
		if err != nil {
			continue
		}
		ro := slices.Contains(strings.Split(fields[5], ","), "ro") ||
			slices.Contains(strings.Split(fields[sep+3], ","), "ro")
		entries = append(entries, entry{point, ro})
	}

	all = map[string]bool{}
	for i, e := range entries {
		all[e.point] = true
		hidden := false
		for _, later := range entries[i+1:] {
			if later.point == e.point || later.point == "/" ||
				strings.HasPrefix(e.point, later.point+"/") {
				hidden = true
				break
			}
		}
		if fi, err := os.Lstat(e.point); !hidden && err == nil && fi.IsDir() {
			visible = append(visible, visibleMount{e.point, e.readOnly})
		}
	}
	return all, visible
}

// The real kernel answer, which the white-box hook specs stand in for. Where
// the host offers no read-only mount (a bare CI runner may not), the spec says
// so and skips rather than passing on nothing.
var _ = Describe("readOnlyMountRoot on Linux", func() {
	It("recognises the root of a read-only mount", func() {
		_, visible := mountPoints()
		for _, m := range visible {
			if m.readOnly {
				Expect(readOnlyMountRoot(m.point)).To(BeTrue(), "mount point %q", m.point)
				return
			}
		}
		Skip("no read-only mount is visible to this process")
	})

	// Being a mount root is not enough: the mount has to be read-only.
	It("does not call the root of a read-write mount read-only", func() {
		_, visible := mountPoints()
		for _, m := range visible {
			if !m.readOnly {
				Expect(readOnlyMountRoot(m.point)).To(BeFalse(), "%q is a read-write mount", m.point)
				return
			}
		}
		Skip("no read-write mount is visible to this process")
	})

	// The narrowing the exemption depends on: under a read-only root
	// filesystem, or a service manager's ProtectSystem=strict, every directory
	// is on a read-only mount, and only the mount's root may be exempt.
	It("does not extend that to a directory beneath the root", func() {
		all, visible := mountPoints()
		for _, m := range visible {
			if !m.readOnly {
				continue
			}
			entries, err := os.ReadDir(m.point)
			if err != nil {
				continue
			}
			for _, e := range entries {
				sub := filepath.Join(m.point, e.Name())
				fi, err := os.Lstat(sub)
				if err != nil || !fi.IsDir() || all[sub] {
					continue // not a directory, or a mount point of its own
				}
				Expect(readOnlyMountRoot(sub)).To(BeFalse(), "%q is on read-only %q but is not its root", sub, m.point)
				return
			}
		}
		Skip("no read-only mount with an ordinary subdirectory is visible to this process")
	})
})
