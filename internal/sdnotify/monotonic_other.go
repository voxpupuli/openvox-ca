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

//go:build !linux

package sdnotify

// monotonicUsec reports that no systemd-comparable monotonic clock is
// available. Only Linux hosts run a service manager that speaks this protocol;
// on every other platform (developer workstations running the test suite)
// RELOADING=1 is simply sent without MONOTONIC_USEC.
func monotonicUsec() (uint64, bool) {
	return 0, false
}
