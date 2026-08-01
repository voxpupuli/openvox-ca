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

package sdnotify

import (
	"time"

	"golang.org/x/sys/unix"
)

// monotonicUsec returns the current CLOCK_MONOTONIC reading in microseconds.
//
// This is the clock systemd timestamps its own events with, so a
// MONOTONIC_USEC field built from it is directly comparable with the moment
// the service manager sent SIGHUP — which is exactly what `Type=notify-reload`
// uses to tell a genuine reload acknowledgement from a stale one. Go's time
// package keeps its monotonic reading private, hence the syscall.
func monotonicUsec() (uint64, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, false
	}
	nsec := ts.Nano()
	if nsec < 0 {
		return 0, false
	}
	return uint64(nsec) / uint64(time.Microsecond), true
}
