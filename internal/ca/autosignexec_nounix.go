//go:build !unix

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

import "os/exec"

// killProcessGroupOnCancel leaves cmd as exec.CommandContext made it. There is
// no process group to start the executable in on this platform, so the timeout
// kills the executable alone, and autosignWaitDelay is all that stops
// something it started from holding up the run.
func killProcessGroupOnCancel(*exec.Cmd) {}
