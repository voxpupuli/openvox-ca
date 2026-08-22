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

package api_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
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
// on them. This file is package api_test rather than package api: it reaches no
// unexported identifier of the package it guards, and AGENTS.md asks for
// black-box unless internals are genuinely needed. The walk reads the same
// directory either way.
var (
	_ = ca.PpCliAuth
	_ = ca.AuthGrant{}
	_ = ca.GenerateOptions{}
	_ = (*ca.CA).GenerateWithOptions
)

// caImportPath is the package the gate guards. Matched by path so an aliased
// import cannot walk past the qualified rules.
const caImportPath = "github.com/voxpupuli/openvox-ca/internal/ca"

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

	// GenerateWithOptions is matched on the selected name alone, whatever the
	// receiver, because it is a method on *CA: a handler would reach it as
	// s.CA.GenerateWithOptions(...), whose receiver is s.CA rather than the
	// package, so a package-qualified rule would never see it.
	//
	// The other three are package-level in internal/ca -- a type, a constructor
	// and a struct type -- so they cannot be named without naming the package or
	// dot-importing it. Matching those on the selected name alone would be
	// strictly broader than the escalation being prevented, and the breadth is
	// not free: internal/api may legitimately hold its own field called
	// PpCliAuth (a per-trust-domain policy flag is exactly that), and reading it
	// is not the same act as calling ca.PpCliAuth().
	//
	// The compile-time bindings at the top of this file already draw that line,
	// and are the quickest way to check it: `_ = ca.PpCliAuth` is a function
	// value, `_ = (*ca.CA).GenerateWithOptions` is a method expression. Only the
	// latter can sit behind a receiver that is not the package. Before moving a
	// name between these two sets, confirm against those bindings -- generalising
	// from GenerateWithOptions to PpCliAuth without checking they are the same
	// kind of thing is the specific mistake this split exists to prevent, and it
	// has been made more than once.
	matchAnyReceiver := map[string]bool{"GenerateWithOptions": true}

	// caQualifier reports the local name internal/ca is imported under, and
	// whether it is dot-imported.
	//
	// Resolved by import *path*, never by the literal identifier "ca": an
	// aliased import (pca "…/internal/ca") would otherwise walk straight through
	// the qualified rules below, which is the one way a gate keyed on a name
	// rather than a package can be dodged deliberately.
	caQualifier := func(file *ast.File) (name string, dotImported bool) {
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || path != caImportPath {
				continue
			}
			switch {
			case imp.Name == nil:
				return "ca", false // no alias: the package name
			case imp.Name.Name == ".":
				return "", true
			case imp.Name.Name == "_":
				return "", false // blank: nothing can be named through it
			default:
				return imp.Name.Name, false
			}
		}
		return "", false
	}

	// forbiddenRefs reports every forbidden identifier referenced by file, as
	// "name@position". Extracted from the spec so the table below can drive the
	// same matcher over source known to contain a violation -- without that, a
	// matcher broken into never matching anything would leave this gate green
	// forever.
	forbiddenRefs := func(fset *token.FileSet, file *ast.File) []string {
		qualifier, dotImported := caQualifier(file)

		// Every SelectorExpr's Sel position. ast.Inspect visits the selected
		// identifier as a bare *ast.Ident too, so without this the Ident arm
		// below would re-match the half of a selector the SelectorExpr arm has
		// already judged -- and judge it by the wrong rule.
		selected := map[token.Pos]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				selected[sel.Sel.Pos()] = true
			}
			return true
		})

		var found []string
		record := func(name string, pos token.Pos) {
			found = append(found, name+"@"+fset.Position(pos).String())
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				name := node.Sel.Name
				if _, isForbidden := forbidden[name]; !isForbidden {
					return true
				}
				if matchAnyReceiver[name] {
					record(name, node.Sel.Pos())
					return true
				}
				// Qualified only: the receiver must be the ca import itself.
				if x, ok := node.X.(*ast.Ident); ok && qualifier != "" && x.Name == qualifier {
					record(name, node.Sel.Pos())
				}
			case *ast.Ident:
				// A bare identifier can only name one of these under a
				// dot-import. That cannot arise today -- dot-importing
				// internal/ca into package api does not compile, because both
				// export New -- so it is unexercised against real source. It
				// costs three lines and closes the hole a future rename opens.
				if selected[node.Pos()] || !dotImported {
					return true
				}
				if _, isForbidden := forbidden[node.Name]; isForbidden {
					record(node.Name, node.Pos())
				}
			}
			return true
		})
		return found
	}

	// The negative controls, and the boundary between the two rules.
	// parser.ParseFile works on a string and never compiles it, so a synthetic
	// handler that would not build for real is still a valid subject -- which is
	// what makes this feasible at all.
	//
	// One Entry per shape rather than a loop: a loop stops at the first failed
	// Expect, and the whole point here is that some shapes must match and others
	// must not. A regression that made the matcher fire on everything, or on
	// nothing, has to be visible as a specific row.
	DescribeTable("distinguishes reaching the seam from merely sharing a name",
		func(src string, wantMatch bool, matched string) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synthetic.go", src, 0)
			Expect(err).NotTo(HaveOccurred())

			refs := forbiddenRefs(fset, file)
			if wantMatch {
				Expect(refs).To(ContainElement(ContainSubstring(matched)),
					"the matcher must actually match; otherwise the gate is green by accident")
				return
			}
			Expect(refs).To(BeEmpty(),
				"a false positive here forces unrelated code to rename around this gate")
		},

		Entry("the package-qualified constructor", `package api

import "github.com/voxpupuli/openvox-ca/internal/ca"

func handler(s *Server) { _ = ca.PpCliAuth() }
`, true, "PpCliAuth"),

		// The dodge a name-keyed gate is open to: same call, different qualifier.
		Entry("the constructor behind an import alias", `package api

import pca "github.com/voxpupuli/openvox-ca/internal/ca"

func handler(s *Server) { _ = pca.PpCliAuth() }
`, true, "PpCliAuth"),

		Entry("the options type, package-qualified", `package api

import "github.com/voxpupuli/openvox-ca/internal/ca"

func handler(s *Server) { _ = ca.GenerateOptions{} }
`, true, "GenerateOptions"),

		// Why GenerateWithOptions is matched on the name alone: the receiver is
		// s.CA, so no package-qualified rule would ever see it.
		Entry("the options form, reached through a receiver", `package api

func handler(s *Server) { _, _ = s.CA.GenerateWithOptions(nil, "n", nil) }
`, true, "GenerateWithOptions"),

		Entry("the constructor under a dot-import", `package api

import . "github.com/voxpupuli/openvox-ca/internal/ca"

func handler(s *Server) { _ = PpCliAuth() }
`, true, "PpCliAuth"),

		// The case this rule exists for. internal/api may hold its own field
		// called PpCliAuth -- a per-trust-domain flag for whether the extension
		// is honoured when presented. Reading it is a policy check, not an
		// issuance, and forbidding it would make unrelated work rename around a
		// gate that has no claim on the name.
		Entry("an api-local field that happens to share the name", `package api

func admin(domain TrustDomain, cn string) bool {
	return domain.IsAdminCN(cn) || domain.PpCliAuth
}
`, false, ""),

		// Near-misses: neither is the forbidden identifier, and an exact map
		// lookup is what keeps them out.
		Entry("identifiers that merely contain the name", `package api

import "github.com/voxpupuli/openvox-ca/internal/ca"

func check(c *x509.Certificate) bool { return hasPpCliAuth(c) && ca.OIDPpCliAuth != nil }
`, false, ""),
	)

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
