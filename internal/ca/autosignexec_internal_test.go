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

//go:build unix

// White-box: the branch under test is reachable through CheckAutosign only by
// a race between the timeout and the executable's own exit, which no spec can
// arrange. Calling the Cancel func directly reaches it every time.
package ca

import (
	"context"
	"os"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("killProcessGroupOnCancel", func() {
	It("reports a group that has already gone as a finished process", func() {
		// The timeout can fire after the executable has exited but before
		// Wait has noticed, and the group is gone by then. os/exec treats
		// os.ErrProcessDone from Cancel as "it had already finished" and
		// reports the exit status; any other error it reports instead, which
		// would turn an approval that won the race into a timeout.
		cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 0")
		killProcessGroupOnCancel(cmd)
		Expect(cmd.Run()).To(Succeed())

		Expect(cmd.Cancel()).To(MatchError(os.ErrProcessDone))
	})
})
