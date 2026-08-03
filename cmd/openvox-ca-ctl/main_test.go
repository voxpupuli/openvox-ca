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
	"bytes"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/version"
)

var _ = Describe("Root command", func() {
	It("prints the release version for --version", func() {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetArgs([]string{"--version"})
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("openvox-ca-ctl version " + version.Version))
	})

	// --version is root-only (cobra registers it on the root's local flag
	// set), unlike the persistent global flags; the CLI reference documents
	// this, so pin it.
	It("rejects --version after a subcommand", func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"list", "--version"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("unknown flag: --version")))
	})

	// Positive half of the documented "global flags may be placed before or
	// after the subcommand name" contract (the negative half being that
	// --version may not). --help returns before PersistentPreRunE, keeping
	// the spec hermetic — no config loading or network.
	It("accepts a persistent flag after the subcommand", func() {
		DeferCleanup(func(orig bool) { globalVerbose = orig }, globalVerbose)
		cmd := newRootCmd()
		cmd.SetArgs([]string{"list", "-v", "--help"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(Succeed())
		flag := cmd.PersistentFlags().Lookup("verbose")
		Expect(flag).NotTo(BeNil())
		Expect(flag.Changed).To(BeTrue())
	})

	// -v must stay the shorthand for --verbose, mirroring the server binary
	// (where -v is --verbosity): cobra would otherwise claim it for the
	// synthesised --version flag, giving the two siblings opposite -v
	// semantics.
	It("keeps -v as the shorthand for --verbose", func() {
		cmd := newRootCmd()
		flag := cmd.PersistentFlags().ShorthandLookup("v")
		Expect(flag).NotTo(BeNil())
		Expect(flag.Name).To(Equal("verbose"))
	})
})
