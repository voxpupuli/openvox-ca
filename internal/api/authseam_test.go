// Copyright (C) 2026 Trevor Vaughan
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

package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// SECURITY: the CSR signing path strips Puppet authorisation-arc OIDs from
// submitted requests, so no agent can ask for pp_cli_auth. ca.AuthGrant is the
// deliberate in-process exception, and ca.GenerateWithOptions is how it is
// reached. Neither may be named from this package: an HTTP handler that
// constructed a grant would put the escalation back exactly where the filter
// exists to prevent it, and one that reached the options form could turn
// POST /generate into a revoke-and-replace over the network.
//
// ca.Generate -- the narrow wrapper with no extension parameter -- is what this
// package is meant to call, and is not in the forbidden set.
//
// This is a real gate rather than a convention, because the type system cannot
// be one here: AuthGrant's fields are unexported and it has a single
// constructor, which stops a value arriving from JSON or a query parameter, but
// PpCliAuth and GenerateWithOptions are exported and this package already
// imports internal/ca. Three lines in a handler would be enough.
//
// Scoped to this package's own files on purpose. Walking the transitive import
// graph would need golang.org/x/tools (an indirect dependency today) or a Go
// toolchain at test time, and would not catch anything this does not: the
// escalation has to be written here to be reachable from a request.
//
// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
var _ = Describe("The authorisation-grant seam", func() {
	forbidden := map[string]string{
		"AuthGrant":           "constructing a grant here reintroduces the escalation the CSR filter prevents",
		"PpCliAuth":           "only an operator at a terminal may mint an admin credential, never a request",
		"GenerateOptions":     "the options form is the offline command's, not the API's",
		"GenerateWithOptions": "use ca.Generate, which has no extension parameter by design",
	}

	It("is not reachable from any handler in this package", func() {
		fset := token.NewFileSet()
		entries, err := os.ReadDir(".")
		Expect(err).NotTo(HaveOccurred())

		var checked int
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			checked++

			file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
			Expect(err).NotTo(HaveOccurred(), name)

			ast.Inspect(file, func(n ast.Node) bool {
				// Both forms, because either would work in a handler:
				//   ca.PpCliAuth()          -> SelectorExpr
				//   s.CA.GenerateWithOptions -> SelectorExpr (receiver is s.CA,
				//                               not the package, so match on Sel)
				//   PpCliAuth()             -> bare Ident, under a dot-import
				// The Ident case cannot arise today -- a dot-import of
				// internal/ca into this package does not compile, because both
				// export New -- so it is unexercised. It costs three lines and
				// closes the hole that a future rename would open, which is
				// cheaper than remembering to revisit this then.
				var name string
				var pos token.Pos
				switch node := n.(type) {
				case *ast.SelectorExpr:
					name, pos = node.Sel.Name, node.Sel.Pos()
				case *ast.Ident:
					name, pos = node.Name, node.Pos()
				default:
					return true
				}
				why, isForbidden := forbidden[name]
				if !isForbidden {
					return true
				}

				Fail(strings.Join([]string{
					fset.Position(pos).String() + " references " + name,
					"Reason it is forbidden: " + why + ".",
					"If this is deliberate, the security argument in internal/ca/authgrant.go",
					"has to be revisited first -- not this test.",
				}, "\n"))
				return true
			})
		}

		Expect(checked).To(BeNumerically(">", 0), "no source files were examined; the walk is not working")
	})
})
