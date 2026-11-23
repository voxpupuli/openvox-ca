//go:build unix

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
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// killProcessGroupOnCancel starts cmd in a process group of its own, and makes
// cancelling it -- the timeout -- kill the whole group rather than cmd alone.
//
// SECURITY: exec.CommandContext's own Cancel kills the direct child and
// nothing else. When the executable is a shell script, the shell dies and
// whatever it started -- a curl to an inventory service, a helper it put in
// the background -- runs on as the CA's user after the CA has given up on the
// decision. The group's id is the child's pid, so the negative pid names the
// group.
//
// Only cancellation kills the group. A run that ends by itself leaves what it
// put in the background alone, because a script may start a helper on purpose.
// A descendant that leaves the group (setsid, or its own setpgid) escapes the
// kill; autosignWaitDelay still stops it holding up the run.
// NIST 800-53: SC-5 (Denial-of-Service Protection)
func killProcessGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
