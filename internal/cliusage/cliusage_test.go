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

package cliusage_test

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/voxpupuli/openvox-ca/internal/cliusage"
)

var _ = Describe("MarkRequired", func() {
	var root, leaf *cobra.Command

	BeforeEach(func() {
		root = &cobra.Command{Use: "root"}
		root.PersistentFlags().String("config", "", "Path to a config file")
		leaf = &cobra.Command{Use: "leaf", RunE: func(*cobra.Command, []string) error { return nil }}
		leaf.Flags().String("name", "", "A name")
		leaf.Flags().String("serial", "", "A serial")
		leaf.Flags().String("ttl", "", "A lifetime")
		leaf.Flags().Bool("all", false, "Everything")
		leaf.Flags().String("extra", "", "An optional flag")
		root.AddCommand(leaf)
	})

	usage := func(name string) string {
		GinkgoHelper()
		f := leaf.Flags().Lookup(name)
		Expect(f).NotTo(BeNil())
		return f.Usage
	}

	It("marks a flag cobra requires, in --help", func() {
		Expect(leaf.MarkFlagRequired("ttl")).To(Succeed())
		cliusage.MarkRequired(root)
		Expect(usage("ttl")).To(Equal("A lifetime (required)"))

		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"leaf", "--help"})
		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).To(MatchRegexp(`--ttl string\s+A lifetime \(required\)`))
	})

	// The annotation key for a group is unexported in cobra; this is what
	// fails if cobra renames it, since the group would then go unmarked.
	It("marks each flag of a one-required group with the others", func() {
		leaf.MarkFlagsOneRequired("name", "serial")
		cliusage.MarkRequired(root)
		Expect(usage("name")).To(Equal("A name (required unless --serial is given)"))
		Expect(usage("serial")).To(Equal("A serial (required unless --name is given)"))
	})

	It("names every other flag in a larger group", func() {
		leaf.MarkFlagsOneRequired("name", "serial", "all")
		cliusage.MarkRequired(root)
		Expect(usage("all")).To(Equal("Everything (required unless --name or --serial is given)"))
	})

	It("leaves optional flags alone, including a mutually exclusive pair", func() {
		leaf.MarkFlagsMutuallyExclusive("extra", "ttl")
		cliusage.MarkRequired(root)
		Expect(usage("extra")).To(Equal("An optional flag"))
		Expect(usage("ttl")).To(Equal("A lifetime"))
	})

	// cobra merges a command's persistent flags into its Flags() lazily, so
	// a walk of Flags() alone would miss one that was never merged.
	It("marks a required persistent flag that was never merged", func() {
		Expect(root.MarkPersistentFlagRequired("config")).To(Succeed())
		Expect(root.Flags().Lookup("config")).To(BeNil(),
			"the fixture must leave the flag unmerged, or it tests the merged case")

		cliusage.MarkRequired(root)
		Expect(root.PersistentFlags().Lookup("config").Usage).To(Equal("Path to a config file (required)"))
	})

	// A persistent flag reaches every command under the one that declares it,
	// by pointer, so a walk that visited it per command would annotate it once
	// for each.
	It("marks an inherited required flag once", func() {
		Expect(root.MarkPersistentFlagRequired("config")).To(Succeed())
		// LocalFlags merges a command's persistent flags, its own and those
		// it inherits, into its flag set, as cobra does before running it and
		// as MarkFlagsOneRequired does. On both commands, that puts the same
		// flag in front of the walk twice.
		_ = root.LocalFlags()
		_ = leaf.LocalFlags()
		Expect(root.Flags().Lookup("config")).To(BeIdenticalTo(leaf.Flags().Lookup("config")),
			"the fixture must share the flag by pointer, or it cannot catch a double mark")

		cliusage.MarkRequired(root)
		Expect(root.PersistentFlags().Lookup("config").Usage).To(Equal("Path to a config file (required)"))
	})
})
