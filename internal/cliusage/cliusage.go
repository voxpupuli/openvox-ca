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

// Package cliusage makes --help say which flags a command requires, for both
// binaries.
//
// cobra enforces MarkFlagRequired and MarkFlagsOneRequired but renders those
// flags exactly like optional ones, so an operator found out by failing.
// Reading the requirement back off the annotations cobra stores, rather than
// writing "(required)" into each usage string by hand, keeps help and
// enforcement from drifting apart when a flag is added.
package cliusage

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// oneRequiredAnnotation is the key MarkFlagsOneRequired stores each group
// under. cobra does not export it, unlike cobra.BashCompOneRequiredFlag, so it
// is spelled out here, and a spec fails if cobra stops using it.
const oneRequiredAnnotation = "cobra_annotation_one_required"

// MarkRequired appends to the usage of every flag that root, or any command
// under it, requires: "(required)" for MarkFlagRequired, and "(required
// unless --other is given)" for each MarkFlagsOneRequired group the flag is
// in. Call it once the whole tree is built.
func MarkRequired(root *cobra.Command) {
	markRequired(root, map[*pflag.Flag]bool{})
}

// markRequired walks the tree. A command's persistent flags join its Flags()
// only once cobra merges them, which it does lazily, so both sets are visited.
// A persistent flag is then shared by pointer with every command that has
// merged it, so seen keeps each flag annotated once.
func markRequired(cmd *cobra.Command, seen map[*pflag.Flag]bool) {
	mark := func(f *pflag.Flag) {
		if seen[f] {
			return
		}
		seen[f] = true
		if req := f.Annotations[cobra.BashCompOneRequiredFlag]; len(req) > 0 && req[0] == "true" {
			f.Usage += " (required)"
		}
		for _, group := range f.Annotations[oneRequiredAnnotation] {
			var others []string
			for _, name := range strings.Fields(group) {
				if name != f.Name {
					others = append(others, "--"+name)
				}
			}
			f.Usage += " (required unless " + strings.Join(others, " or ") + " is given)"
		}
	}
	cmd.PersistentFlags().VisitAll(mark)
	cmd.Flags().VisitAll(mark)
	for _, sub := range cmd.Commands() {
		markRequired(sub, seen)
	}
}
