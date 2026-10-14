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

import "golang.org/x/sys/unix"

// readOnlyMount reports whether the directory at path is on a filesystem
// mounted read-only. statfs(2) reports the flags of the mount the path was
// reached through, so a read-only bind mount -- which is how the kubelet
// presents a ConfigMap or Secret volume -- counts even when the filesystem
// beneath it is writable elsewhere. An error is "no": the exemption is never
// granted on a guess.
func readOnlyMount(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Flags&unix.ST_RDONLY != 0
}
