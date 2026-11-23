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

package audit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/audit"
)

// The audit events are a closed set and public API: releasing.md (item 9)
// covers each event value and the attributes documented beside it, and points
// at the table in docs/configuration.md#audit-events as the list. These hold
// the places that name the set to one another: the constants audit.go
// declares, the table, and every call that emits one. That each emission site
// carries its event is pinned beside the site: internal/ca's renewal specs,
// cmd/openvox-ca's generate specs and internal/signer's refusal spec.
var _ = Describe("the audit event set", func() {
	// event is one declared event constant: its identifier and its value.
	type event struct{ name, value string }

	// declared parses audit.go for the string constants it declares, the
	// attribute key aside, in source order: every one of them is an event.
	declared := func() []event {
		GinkgoHelper()
		f, err := parser.ParseFile(token.NewFileSet(), "audit.go", nil, 0)
		Expect(err).NotTo(HaveOccurred())
		var events []event
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if name.Name == "Key" {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					Expect(ok).To(BeTrue(), "constant %s is not a string literal", name.Name)
					v, err := strconv.Unquote(lit.Value)
					Expect(err).NotTo(HaveOccurred())
					events = append(events, event{name.Name, v})
				}
			}
		}
		Expect(events).NotTo(BeEmpty(), "audit.go declares no event constants")
		return events
	}
	values := func(events []event) []string {
		out := make([]string, 0, len(events))
		for _, e := range events {
			out = append(out, e.value)
		}
		return out
	}

	// documented reads the event column of the table under "### Audit events".
	documented := func() []string {
		GinkgoHelper()
		raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
		Expect(err).NotTo(HaveOccurred())
		_, section, found := strings.Cut(string(raw), "\n### Audit events\n")
		Expect(found).To(BeTrue(), "docs/configuration.md has no ### Audit events section")
		if end := strings.Index(section, "\n#"); end >= 0 {
			section = section[:end]
		}
		var names []string
		for _, m := range regexp.MustCompile("(?m)^\\| `([a-z_]+\\.[a-z_]+)` \\|").FindAllStringSubmatch(section, -1) {
			names = append(names, m[1])
		}
		Expect(names).NotTo(BeEmpty(), "the table's event column was not found")
		return names
	}

	It("is the set the documentation's table lists, in its order", func() {
		Expect(values(declared())).To(Equal(documented()),
			"the table in docs/configuration.md#audit-events is the published list: an event added, "+
				"renamed or removed in the code changes it too, and a rename or removal needs a major release")
	})

	It("names every event <subject>.<action>", func() {
		for _, e := range declared() {
			Expect(e.value).To(MatchRegexp(`^[a-z]+\.[a-z_]+$`), "the grammar the webhook event types share")
		}
	})

	It("keeps the values releasing.md's coverage was given", func() {
		// Literals, so a rename of a constant's value fails here as well as
		// at the emission sites.
		Expect(values(declared())).To(Equal([]string{"certificate.auth_grant_issued", "signer.request_refused"}))
		Expect(audit.Key).To(Equal("event"))
	})

	// The set is closed only if nothing emits an event the constants do not
	// name. So every audit.Event call outside this package must pass one of
	// them, and no other call may pass the "event" key itself, as a literal
	// or as audit.Key, which would be an audit record the table cannot list.
	//
	// inspect reports a file's audit.Event calls and its problems. "Any other
	// call", not "any slog call": a record logged through a *slog.Logger, or
	// through slog.Default(), has a receiver that is not the slog package.
	inspect := func(path string, f *ast.File) (calls int, problems []string) {
		names := map[string]bool{}
		for _, e := range declared() {
			names[e.name] = true
		}
		// auditSel reports whether e is audit.<name>, and which name.
		auditSel := func(e ast.Expr) (string, bool) {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return "", false
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok || x.Name != "audit" {
				return "", false
			}
			return sel.Sel.Name, true
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if name, ok := auditSel(call.Fun); ok && name == "Event" {
				calls++
				if c, ok := auditSel(call.Args[0]); !ok || !names[c] {
					problems = append(problems, path+": audit.Event is not passed one of audit's event constants")
				}
				return true
			}
			for _, a := range call.Args {
				if lit, ok := a.(*ast.BasicLit); ok && lit.Value == `"event"` {
					problems = append(problems, path+`: a call passes the "event" key itself; use audit.Event`)
				}
				if name, ok := auditSel(a); ok && name == "Key" {
					problems = append(problems, path+": a call passes audit.Key itself; use audit.Event")
				}
			}
			return true
		})
		return calls, problems
	}

	It("is emitted only through audit.Event and its constants", func() {
		root := filepath.Join("..", "..")
		var calls int
		var problems []string
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", ".claude", "node_modules", "vendor", "testdata", ".test-output", "dist":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			c, p := inspect(path, f)
			calls += c
			problems = append(problems, p...)
			return nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(problems).To(BeEmpty())
		// The floor: the three emission sites #666 added are found, so a walk
		// that reads nothing cannot pass.
		Expect(calls).To(BeNumerically(">=", 3), "the sweep found too few audit.Event calls to be reading the tree")
	})

	// The tree is clean, so the sweep above passes whether or not inspect can
	// see a fault at all. These plant one of each kind.
	DescribeTable("inspect refuses a record the table cannot list",
		func(body, want string) {
			src := "package p\nfunc f() {\n" + body + "\n}\n"
			f, err := parser.ParseFile(token.NewFileSet(), "planted.go", src, 0)
			Expect(err).NotTo(HaveOccurred())
			_, problems := inspect("planted.go", f)
			Expect(problems).To(ConsistOf(ContainSubstring(want)))
		},
		Entry("through the slog package", `slog.Info("x", "event", "made.up")`, `passes the "event" key itself`),
		Entry("through a *slog.Logger", `logger.Info("x", "event", "made.up")`, `passes the "event" key itself`),
		Entry("through slog.Default()", `slog.Default().Warn("x", "event", "made.up")`, `passes the "event" key itself`),
		Entry("through slog.String", `logger.Info("x", slog.String("event", "made.up"))`, `passes the "event" key itself`),
		Entry("with audit.Key", `logger.Info("x", audit.Key, "made.up")`, "passes audit.Key itself"),
		Entry("with a literal event name", `logger.Info("x", audit.Event("made.up"))`, "not passed one of audit's event constants"),
	)

	It("inspect accepts an event logged through audit.Event and a constant", func() {
		src := "package p\nfunc f() {\nlogger.Info(\"x\", audit.Event(audit.SignerRequestRefused), \"events\", 2)\n}\n"
		f, err := parser.ParseFile(token.NewFileSet(), "planted.go", src, 0)
		Expect(err).NotTo(HaveOccurred())
		calls, problems := inspect("planted.go", f)
		Expect(problems).To(BeEmpty())
		Expect(calls).To(Equal(1))
	})
})
