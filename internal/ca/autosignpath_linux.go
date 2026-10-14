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

// readOnlyMountRoot reports whether the directory at path is the root of a
// mount that is read-only, which is how the kubelet presents a ConfigMap or
// Secret volume. Both questions are about the mount as this process sees it:
// statx(2) says whether path is a mount root, and statfs(2) reports the flags
// of the mount it was reached through.
//
// Being the root of a read-only mount is necessary for the exemption, and not
// sufficient: under a service manager's ProtectSystem=strict every host mount
// point is one too. kubeletVolumeRoot asks the rest. statx only reports mount
// roots from Linux 5.8, and an older kernel answers "no": the exemption is
// never granted on a guess, and neither is it granted on an error.
func readOnlyMountRoot(path string) bool {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, 0, &stx); err != nil {
		return false
	}
	if stx.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || stx.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return false
	}
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	return st.Flags&unix.ST_RDONLY != 0
}
