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

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// The gate below matches identifiers by name, which a rename would silently
// void: the strings would stop matching anything and the spec would stay green
// while the escalation became writable again. These bindings make that a
// compile error instead. If one of them stops compiling, the corresponding
// entry in `forbidden` needs the new name -- do not simply delete the binding.
//
// They live in a _test.go file, which the walk skips, so the gate cannot trip
// on them.
var (
	_ = ca.PpCliAuth
	_ = ca.AuthGrant{}
	_ = ca.GenerateOptions{}
	_ = (*ca.CA).GenerateWithOptions
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
// toolchain at test time. That scope is a judgement, not a proof: internal/metrics
// also imports internal/ca, holds a *ca.CA and serves HTTP, so it is an importer
// this gate does not cover. It is considered out of reach because it exposes
// only a Prometheus collector with no issuance surface -- if that ever changes,
// this gate needs to grow rather than be trusted as-is.
//
// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
var _ = Describe("The authorisation-grant seam", func() {
	forbidden := map[string]string{
		"AuthGrant":           "constructing a grant here reintroduces the escalation the CSR filter prevents",
		"PpCliAuth":           "only an operator at a terminal may mint an admin credential, never a request",
		"GenerateOptions":     "the options form is the offline command's, not the API's",
		"GenerateWithOptions": "use ca.Generate, which has no extension parameter by design",
	}

	// forbiddenRefs reports every forbidden identifier referenced by file, as
	// "name@position". Extracted from the spec so a negative control can drive
	// the same matcher over source that is known to contain a violation --
	// without it, a matcher broken into never matching anything would leave
	// this gate green forever.
	//
	// Both node forms are matched, because either would work in a handler:
	//   ca.PpCliAuth()           -> SelectorExpr
	//   s.CA.GenerateWithOptions -> SelectorExpr whose receiver is s.CA rather
	//                               than the package, hence matching on Sel
	//   PpCliAuth()              -> bare Ident, under a dot-import
	// The Ident case cannot arise today -- a dot-import of internal/ca into this
	// package does not compile, because both export New -- so it is unexercised
	// against real source. It costs three lines and closes the hole a future
	// rename would open.
	forbiddenRefs := func(fset *token.FileSet, file *ast.File) []string {
		var found []string
		ast.Inspect(file, func(n ast.Node) bool {
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
			if _, isForbidden := forbidden[name]; isForbidden {
				found = append(found, name+"@"+fset.Position(pos).String())
			}
			return true
		})
		return found
	}

	It("catches a violation when one is present", func() {
		// The negative control. parser.ParseFile works on a string and never
		// compiles it, so a synthetic handler that would not build for real is
		// still a valid subject -- which is what makes this feasible at all.
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "synthetic.go", `package api

import "github.com/voxpupuli/openvox-ca/internal/ca"

func handler(s *Server) { _ = ca.PpCliAuth() }
`, 0)
		Expect(err).NotTo(HaveOccurred())

		Expect(forbiddenRefs(fset, file)).To(ContainElement(ContainSubstring("PpCliAuth")),
			"the matcher must actually match; otherwise the gate below is green by accident")
	})

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

			for _, ref := range forbiddenRefs(fset, file) {
				refName := strings.SplitN(ref, "@", 2)[0]
				Fail(strings.Join([]string{
					strings.SplitN(ref, "@", 2)[1] + " references " + refName,
					"Reason it is forbidden: " + forbidden[refName] + ".",
					"If this is deliberate, the security argument in internal/ca/authgrant.go",
					"has to be revisited first -- not this test.",
				}, "\n"))
			}
		}

		Expect(checked).To(BeNumerically(">", 0), "no source files were examined; the walk is not working")
	})
})
