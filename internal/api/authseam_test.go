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
	"io/fs"
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

// caImportPath is the package whose identifiers the gate forbids. Matched by
// path so an aliased import cannot walk past the qualified rules.
const caImportPath = "github.com/voxpupuli/openvox-ca/internal/ca"

// guardedPackages are the directories the gate walks, relative to this one.
//
// The gate began as a rule about internal/api alone, and it is not one any
// more: what it enforces is that an admin credential is minted only by an
// operator at a terminal, and that claim is about a set of packages rather than
// about one. Each entry here is a package that imports internal/ca and offers a
// surface something other than an operator can reach.
//
//   - "." is internal/api itself, the HTTP surface. A handler that constructed
//     a grant would put the escalation back exactly where the CSR filter exists
//     to prevent it.
//   - "../certstore" is the component-certificate stores added by #243. It is a
//     new issuance surface importing internal/ca, and a managed certificate for
//     a certname listed in puppet_server is already an admin credential by that
//     listing -- which is the mechanism, and needs no extension. pp_cli_auth on
//     a managed certificate was considered and rejected, and this is what holds
//     that decision in place rather than leaving it to memory.
//
// Adding a directory is how this gate grows. It is deliberately a list and not
// a glob: a package arrives here because somebody decided it was reachable, and
// a glob would enrol packages nobody had thought about, which is the opposite
// of the property wanted.
//
// A list is also the failure mode this repository keeps paying for -- working
// from an enumeration misses sites -- so the list is not trusted on its own.
// The spec below sweeps every package that imports internal/ca and requires
// each to be either guarded or in exemptPackages, which turns "somebody
// remembered" into "somebody decided".
var guardedPackages = []string{".", "../certstore"}

// exemptPackages are the other importers of internal/ca, each with the reason
// it is not guarded. Being here is a decision, not an oversight; the sweep
// below fails on an importer that is in neither list.
//
// Paths are relative to this directory, matching guardedPackages.
var exemptPackages = map[string]string{
	"../metrics": "exposes only a Prometheus collector, with no issuance surface. " +
		"If that changes it belongs in guardedPackages rather than here",
	"../signer/openbao": "signs with a CA key it holds; it issues nothing and serves nothing",
	"../../cmd/openvox-ca": "the server binary, which assembles the CA. It reaches no " +
		"grant constructor, but it is not guarded because it is the composition root " +
		"and a rule about it would be a rule about the whole binary",
	"../../cmd/openvox-ca-ctl": "the operator CLI, which is the ONE caller that may mint " +
		"an admin credential -- `generate --allow-authorization-extensions` is exactly " +
		"the operator-at-a-terminal case the gate exists to confine this to",
}

// caImporters returns every package directory under internal/ and cmd/ whose
// non-test source imports internal/ca, at any depth, relative to this
// directory.
//
// Measured rather than listed, which is the whole point: an enumeration is what
// misses a new importer, and a new importer of internal/ca is precisely the
// event this gate has to notice.
func caImporters() []string {
	GinkgoHelper()
	seen := map[string]bool{}
	var found []string
	// The module root, walked to any depth. Two earlier versions narrowed this
	// and both were tuned to the tree as it stood: the first stopped one
	// directory below internal/ and cmd/, the second walked those two subtrees
	// in full but no others. A package importing internal/ca from anywhere
	// else -- a new top-level directory, a tools package, an example -- was
	// swept by neither, so it needed no recorded decision and the gate stayed
	// green while the surface grew. A sweep whose own reach is an enumeration
	// fails exactly the way the list it audits would.
	for _, root := range []string{"../.."} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				return nil
			}
			// Dot directories are skipped as a class rather than by name:
			// .git, .github, and -- the one that matters here -- .claude,
			// which holds this repository's sibling worktrees. Walking into
			// those would sweep other branches' source as though it were this
			// one's, and report importers that do not exist on this branch.
			if name := d.Name(); name != "." && name != ".." && strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			switch d.Name() {
			case "testdata", "vendor", "node_modules":
				return filepath.SkipDir
			}
			if importsCA(path) && !seen[path] {
				seen[path] = true
				found = append(found, path)
			}
			return nil
		})
		// A root that cannot be walked is a sweep that did not run, not a tree
		// with no importers in it.
		Expect(err).NotTo(HaveOccurred(), root)
	}
	return found
}

// importsCA reports whether any non-test file in dir imports internal/ca.
//
// Every failure here is fatal rather than absorbed. A directory that cannot be
// read, or a file that will not parse, would otherwise read as "does not import
// internal/ca" -- which silently removes a package from the set this gate
// requires a decision for, and is the one outcome a guard must never produce
// quietly.
func importsCA(dir string) bool {
	GinkgoHelper()
	entries, err := os.ReadDir(dir)
	Expect(err).NotTo(HaveOccurred(), dir)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		Expect(err).NotTo(HaveOccurred(), path)
		for _, imp := range file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			Expect(err).NotTo(HaveOccurred(), path)
			if p == caImportPath {
				return true
			}
		}
	}
	return false
}

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
// Scoped to an enumerated list of packages on purpose -- see guardedPackages.
// Walking the transitive import graph would need golang.org/x/tools (an
// indirect dependency today) or a Go toolchain at test time. That scope is a
// judgement, not a proof, and the list is what makes the judgement reviewable:
// a new importer of internal/ca is covered when somebody adds it here, and not
// before. internal/metrics also imports internal/ca, holds a *ca.CA and serves
// HTTP, and is still out of the list because it exposes only a Prometheus
// collector with no issuance surface -- if that ever changes it belongs in
// guardedPackages rather than being trusted as-is.
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

		// AuthGrant is the identifier this gate exists for: the SECURITY note
		// above calls it the deliberate in-process exception, so a rule that
		// silently stopped matching it would be the one failure here that
		// mattered. Nothing else exercises it -- the compile-time binding at
		// the top of this file proves only that the identifier exists, and the
		// whole-package walk below passes vacuously while no handler names it.
		// A mistyped map key would leave both of those green.
		Entry("the grant type, package-qualified", `package api

import "github.com/voxpupuli/openvox-ca/internal/ca"

func handler(s *Server) { _ = ca.AuthGrant{} }
`, true, "AuthGrant"),

		// Same identifier behind an alias, because the map key is shared with
		// the qualified-receiver rule and a regression could be specific to
		// either path.
		Entry("the grant type behind an import alias", `package api

import pca "github.com/voxpupuli/openvox-ca/internal/ca"

func handler(s *Server) { _ = pca.AuthGrant{} }
`, true, "AuthGrant"),

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

		// The known breadth of the name-only rule, pinned rather than left to
		// be discovered. GenerateWithOptions is matched whatever the receiver,
		// so an unrelated api-local type exposing that name is caught too. That
		// is deliberate and fail-safe -- it over-blocks, costing a rename
		// rather than reopening the seam -- but it is a real cost, and this
		// entry is where someone hitting it will find out it was a choice.
		Entry("an api-local method that happens to share the name", `package api

type exporter struct{}

func (e *exporter) GenerateWithOptions(o Options) error { return nil }

func run(e *exporter) { _ = e.GenerateWithOptions(Options{}) }
`, true, "GenerateWithOptions"),

		// Near-misses: neither is the forbidden identifier, and an exact map
		// lookup is what keeps them out.
		Entry("identifiers that merely contain the name", `package api

import "github.com/voxpupuli/openvox-ca/internal/ca"

func check(c *x509.Certificate) bool { return hasPpCliAuth(c) && ca.OIDPpCliAuth != nil }
`, false, ""),
	)

	// One spec per guarded package rather than one loop inside a single spec,
	// so that a package whose walk stops working is named in the failure. A
	// loop would report "the gate is not working" without saying for which
	// package, and the likeliest cause -- a directory renamed out from under
	// guardedPackages -- is precisely the one that needs naming.
	//
	// The entries are generated from guardedPackages rather than written out,
	// so adding a package to that list cannot be half-done: there is no second
	// place to remember to update.
	tableArgs := []any{
		func(dir string) {
			fset := token.NewFileSet()
			entries, err := os.ReadDir(dir)
			Expect(err).NotTo(HaveOccurred(),
				"guardedPackages names %s, which cannot be read. If that package moved or "+
					"was renamed, follow it -- do not delete the entry, or its issuance "+
					"surface stops being guarded silently", dir)

			var checked int
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
					continue
				}
				checked++

				path := filepath.Join(dir, name)
				file, err := parser.ParseFile(fset, path, nil, 0)
				Expect(err).NotTo(HaveOccurred(), path)

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

			// Per package, not once for the walk as a whole. A single count
			// across every directory is satisfied by this package alone, so a
			// sibling that had been emptied, renamed, or spelled wrongly would
			// contribute nothing and the gate would still pass -- green because
			// it examined the one package that was never the question.
			Expect(checked).To(BeNumerically(">", 0),
				"no non-test source files were examined in %s; this package is not being guarded", dir)
		},
	}
	for _, dir := range guardedPackages {
		tableArgs = append(tableArgs, Entry(dir, dir))
	}
	DescribeTable("is not reachable from any of the guarded packages", tableArgs...)

	// What makes guardedPackages authoritative rather than remembered.
	//
	// Without this, adding a package that imports internal/ca and forgetting
	// this file leaves the new package unguarded and every spec above green --
	// which is exactly how an enumeration fails, and this repository has a
	// recorded history of it. The sweep does not decide anything: it requires a
	// decision to have been recorded, in one list or the other.
	//
	// Both sides are reduced to one spelling before they are compared. The
	// lists are written relative to this package, because that is where a
	// contributor reads them; the sweep walks from the module root and yields
	// paths relative to that. Left alone, "." and "../../internal/api" are the
	// same package under two names, and the sweep would report this very
	// package as unguarded.
	modulePath := func(dir string) string {
		if rel, err := filepath.Rel("../..", filepath.Join("../../internal/api", dir)); err == nil {
			return filepath.Clean(rel)
		}
		return filepath.Clean(dir)
	}
	It("has a recorded decision for every package that imports internal/ca", func() {
		known := map[string]bool{}
		for _, dir := range guardedPackages {
			known[modulePath(dir)] = true
		}
		for dir := range exemptPackages {
			known[modulePath(dir)] = true
		}

		// The translation must actually reach this package, whose own entry is
		// "." -- if it did not, every swept path would look unknown and the
		// failure below would name the wrong defect.
		Expect(known).To(HaveKey("internal/api"),
			"precondition: guardedPackages' own entry must normalise to internal/api")

		importers := caImporters()
		Expect(importers).NotTo(BeEmpty(),
			"no importer of internal/ca was found at all; the sweep is not working, "+
				"and a sweep that finds nothing agrees with every list")

		for _, dir := range importers {
			rel, err := filepath.Rel("../..", dir)
			Expect(err).NotTo(HaveOccurred(), dir)
			Expect(known).To(HaveKey(filepath.Clean(rel)), strings.Join([]string{
				dir + " imports " + caImportPath + " and is in neither guardedPackages nor exemptPackages.",
				"That is a decision nobody has recorded, not a test to silence.",
				"If the package offers a surface something other than an operator at a",
				"terminal can reach, add it to guardedPackages. If it does not, add it to",
				"exemptPackages with the reason -- which is what makes the next reader able",
				"to check the judgement rather than inherit it.",
			}, "\n"))
		}
	})
})
