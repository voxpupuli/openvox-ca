//go:build mage

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

package main

import (
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// AGENTS.md and CONTRIBUTING.md document `go run mage.go <Target>`, and for a
// long time there was no mage.go behind it (#636). Its `ignore` build tag keeps
// it out of every build, vet and lint run, and CI installs the mage binary
// instead, so nothing else would notice the file going missing or failing to
// compile against a bumped mage module.
var _ = Describe("the zero-install bootstrap", func() {
	It("lists the targets through `go run mage.go`", func(ctx SpecContext) {
		// mage runs `go build`, which may run git for VCS stamping, so specEnv
		// strips GIT_* as for any spec that shells out. A developer's
		// MAGEFILE_ENABLE_COLOR would wrap each target name in ANSI codes,
		// which the match below cannot see past, so colour is forced off.
		cmd := exec.CommandContext(ctx, "go", "run", "mage.go", "-l")
		cmd.Env = specEnv("MAGEFILE_ENABLE_COLOR=false")
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "go run mage.go -l:\n%s", out)
		Expect(string(out)).To(MatchRegexp(`(?m)^\s+test:magefile\s`),
			"the target list should name test:magefile:\n%s", out)
	}, SpecTimeout(5*time.Minute))
})
