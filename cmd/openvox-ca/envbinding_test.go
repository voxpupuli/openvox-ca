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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// Every boolean and integer environment variable used to be parsed in place,
// as `if b, err := strconv.ParseBool(v); err == nil { ... }`, which drops a
// value that does not parse without a word (#436). They now go through
// config.EnvBool and config.EnvInt, which refuse one instead. The specs in
// config_test.go pin that for the variables they name; this pins it for the
// ones they do not, including any added later, by refusing the old shape
// itself: a function that binds the environment may not call strconv.
//
// The CLI's binding lives in another package, but it is read here as source,
// so one guard covers both binaries.
var _ = Describe("environment bindings", func() {
	DescribeTable("parse no value themselves",
		func(file, fn string, floor int) {
			src, err := os.ReadFile(file)
			Expect(err).NotTo(HaveOccurred())
			problems, helpers := bindingProblems(string(src), fn)
			Expect(problems).To(BeEmpty())
			// The floor: a function that bound nothing through the helpers
			// would pass the check above vacuously.
			Expect(helpers).To(BeNumerically(">=", floor),
				"%s binds only %d variables through config.EnvBool/EnvInt", fn, helpers)
		},
		Entry("the server", "config.go", "applyServerEnv", 40),
		Entry("the CLI", "../openvox-ca-ctl/config.go", "applyCtlEnv", 2),
	)

	// The must-fail twins: the real functions are correct, so without these
	// nothing would show the check above can fail at all.
	DescribeTable("refuse a binding that would drop a bad value",
		func(body, want string) {
			src := "package p\nfunc bind(cfg *C) error {\n\tvar errs []error\n" + body + "\n\treturn nil\n}\n"
			problems, _ := bindingProblems(src, "bind")
			Expect(problems).To(ContainElement(ContainSubstring(want)))
		},
		Entry("the old shape", "\tif b, err := strconv.ParseBool(v); err == nil { cfg.B = b }", "calls strconv.ParseBool"),
		Entry("a discarded error", "\t_ = config.EnvBool(\"X\", &cfg.B)", "discards the error"),
		Entry("a bare call", "\tconfig.EnvInt(\"X\", &cfg.N, nil)", "discards the error"),
		Entry("an append whose result is dropped", "\t_ = append(errs, config.EnvBool(\"X\", &cfg.B))", "discards the error"),
		Entry("a Join whose result is dropped", "\t_ = errors.Join(config.EnvBool(\"X\", &cfg.B))", "discards the error"),
		Entry("the error as append's slice", "\terrs = append([]error{config.EnvBool(\"X\", &cfg.B)})", "discards the error"),
		// Kept, but by a call the guard cannot vouch for: only append and
		// errors.Join are known to hand the error on.
		Entry("the error handed to another function", "\terrs = wrap(config.EnvBool(\"X\", &cfg.B))", "discards the error"),
	)

	It("accepts the two shapes the bindings use", func() {
		src := "package p\nfunc bind(cfg *C) error {\n\tvar errs []error\n" +
			"\terrs = append(errs, config.EnvBool(\"X\", &cfg.B))\n" +
			"\treturn errors.Join(errs...)\n}\n" +
			"func bind2(cfg *C) error {\n\treturn errors.Join(config.EnvInt(\"Y\", &cfg.N, nil))\n}\n"
		problems, helpers := bindingProblems(src, "bind")
		Expect(problems).To(BeEmpty())
		Expect(helpers).To(Equal(1))
		problems, helpers = bindingProblems(src, "bind2")
		Expect(problems).To(BeEmpty())
		Expect(helpers).To(Equal(1))
	})
})

// bindingProblems parses src and reports, for the function named fn, every
// direct strconv call and every config.EnvBool/EnvInt call whose error is not
// kept, with the number of helper calls it found. A helper's error is kept when
// it is an argument to append (after the slice) or errors.Join, and that call's
// own result is assigned to something other than _ or returned: a binding
// written as `_ = config.EnvBool(...)` passes lint and would drop a bad value as
// silently as the old shape did.
func bindingProblems(src, fn string) ([]string, int) {
	GinkgoHelper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	Expect(err).NotTo(HaveOccurred())

	var decl *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == fn {
			decl = fd
		}
	}
	Expect(decl).NotTo(BeNil(), "no function %s; update this guard to follow it", fn)

	var problems []string
	helpers := 0
	var stack []ast.Node
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)

		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		switch {
		case pkg.Name == "strconv":
			problems = append(problems, fmt.Sprintf("%s: %s calls strconv.%s; parse environment "+
				"values with config.EnvBool or config.EnvInt, which refuse a value that does not "+
				"parse instead of ignoring it", fset.Position(sel.Pos()), fn, sel.Sel.Name))
		case pkg.Name == "config" && (sel.Sel.Name == "EnvBool" || sel.Sel.Name == "EnvInt"):
			helpers++
			// stack ends [..., consumer, collector, call, sel].
			if len(stack) < 4 || !collectsError(stack[len(stack)-3], stack[len(stack)-2]) ||
				!keepsResult(stack[len(stack)-4], stack[len(stack)-3]) {
				problems = append(problems, fmt.Sprintf("%s: %s discards the error from config.%s; "+
					"collect it with errs = append(errs, ...) or return errors.Join(...) so a value "+
					"that does not parse refuses startup", fset.Position(sel.Pos()), fn, sel.Sel.Name))
			}
		}
		return true
	})
	return problems, helpers
}

// collectsError reports whether collector hands call's error on: as an
// argument to append (after the slice) or to errors.Join.
func collectsError(collector, call ast.Node) bool {
	c, ok := collector.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fun := c.Fun.(type) {
	case *ast.Ident:
		if fun.Name != "append" || len(c.Args) < 2 {
			return false
		}
		for _, arg := range c.Args[1:] {
			if arg == call {
				return true
			}
		}
		return false
	case *ast.SelectorExpr:
		pkg, ok := fun.X.(*ast.Ident)
		return ok && pkg.Name == "errors" && fun.Sel.Name == "Join"
	default:
		return false
	}
}

// keepsResult reports whether consumer keeps collector's result: by returning
// it, or by assigning it to something other than the blank identifier.
func keepsResult(consumer, collector ast.Node) bool {
	switch c := consumer.(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.AssignStmt:
		for i, rhs := range c.Rhs {
			if rhs != collector || i >= len(c.Lhs) {
				continue
			}
			id, ok := c.Lhs[i].(*ast.Ident)
			return !ok || id.Name != "_"
		}
		return false
	default:
		return false
	}
}

// minServerEnvVars is a floor under every list of the server's variables
// below. Each check compares two lists, and two lists emptied together (a
// parser that stops matching, a table rewritten in another shape) agree
// perfectly; the floor is what fails then. applyServerEnv read 115 when it
// was set.
const minServerEnvVars = 100

// The variables applyServerEnv reads are published configuration: an operator
// sets one by name, and a binding spelt otherwise leaves the setting at its
// default without a word (#508). serverEnvBindings pins each to its field in
// config_test.go; these hold that list, the code and the docs to the same
// names, in both directions.
var _ = Describe("the server's environment variables", func() {
	It("each have one binding spec, and the specs name no other", func() {
		read := serverEnvNamesRead()
		var pinned []string
		seen := map[string]bool{}
		for _, b := range serverEnvBindings() {
			Expect(seen[b.name]).To(BeFalse(), "%s has two entries in serverEnvBindings", b.name)
			seen[b.name] = true
			pinned = append(pinned, b.name)
		}
		Expect(len(pinned)).To(BeNumerically(">=", minServerEnvVars),
			"serverEnvBindings has only %d entries", len(pinned))
		Expect(namesMissing(read, pinned)).To(BeEmpty(),
			"applyServerEnv reads these, and serverEnvBindings in config_test.go has no entry for them")
		Expect(namesMissing(pinned, read)).To(BeEmpty(),
			"serverEnvBindings has entries for these, and applyServerEnv does not read them")
	})

	It("are each in the configuration reference", func() {
		read := serverEnvNamesRead()
		// configuration.md's tables, and the two pages it sends the reader to
		// for the OpenBao and storage-backend variables.
		var documented []string
		for _, f := range []string{"configuration.md", "openbao-transit.md", "storage-backends.md"} {
			md, err := os.ReadFile(filepath.Join("..", "..", "docs", f))
			Expect(err).NotTo(HaveOccurred())
			documented = append(documented, envTableNames(string(md))...)
		}
		Expect(len(documented)).To(BeNumerically(">=", minServerEnvVars),
			"the configuration reference lists only %d variables; has a table changed shape?", len(documented))
		Expect(namesMissing(read, documented)).To(BeEmpty(),
			"applyServerEnv reads these, and no table in docs/configuration.md, "+
				"docs/openbao-transit.md or docs/storage-backends.md lists them")
	})

	// Every table in docs/ and in the chart's README, which is published with
	// the chart, not just the reference, and every cell of it, since an
	// operator copies a name from wherever they found it: an example row's
	// `NAME=value` as much as a reference row's `NAME`.
	It("are all that any table in the docs names", func() {
		read := serverEnvNamesRead()
		md, err := os.ReadFile(filepath.Join("..", "..", "charts", "openvox-ca", "README.md"))
		Expect(err).NotTo(HaveOccurred())
		documented := envTableMentions(string(md))
		Expect(filepath.WalkDir(filepath.Join("..", "..", "docs"), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(path) != ".md" {
				return err
			}
			md, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			documented = append(documented, envTableMentions(string(md))...)
			return nil
		})).To(Succeed())
		Expect(len(documented)).To(BeNumerically(">=", minServerEnvVars),
			"the tables in docs/ and the chart README name only %d variables; has a table changed shape?", len(documented))
		Expect(envNamesNotRead(documented, read)).To(BeEmpty(),
			"a table in docs/ or the chart README names these, and the server does not read them: not in applyServerEnv, "+
				"and not in serverEnvReadElsewhere, which lists the ones it reads elsewhere")
	})

	// The must-fail twins for the two parsers, so a version of either that
	// finds nothing, or finds the wrong thing, cannot hide behind the lists
	// agreeing.
	It("finds every name a binding function reads, and refuses one it cannot see", func() {
		src := "package p\nfunc bind(cfg *C) error {\n" +
			"\tif v := os.Getenv(\"OPENVOX_CA_A\"); v != \"\" { cfg.A = v }\n" +
			"\tif v, ok := os.LookupEnv(\"OPENVOX_CA_B\"); ok { cfg.B = v }\n" +
			"\terrs = append(errs, config.EnvBool(\"OPENVOX_CA_C\", &cfg.C))\n" +
			"\terrs = append(errs, config.EnvInt(\"OPENVOX_CA_D\", &cfg.D, nil))\n" +
			"\tif v := os.Getenv(name); v != \"\" { cfg.E = v }\n" +
			"\terrs = append(errs, config.EnvString(\"OPENVOX_CA_F\", &cfg.F))\n" +
			"\treturn nil\n}\n"
		names, problems := envNamesRead(src, "bind")
		// OPENVOX_CA_F is counted although its reader is unknown, so it still
		// needs a binding spec and a docs row, and it is refused until the
		// reader is added to the guard.
		Expect(names).To(ConsistOf("OPENVOX_CA_A", "OPENVOX_CA_B", "OPENVOX_CA_C", "OPENVOX_CA_D", "OPENVOX_CA_F"))
		Expect(problems).To(ConsistOf(
			ContainSubstring("os.Getenv by a name that is not a string literal"),
			ContainSubstring("names OPENVOX_CA_F outside a reader this guard knows")))
	})

	It("names any table cell's variable, in any form, and not prose's", func() {
		md := "Prose naming `OPENVOX_CA_PROSE` is not a table.\n\n" +
			"| Flag | Variable | Config |\n| --- | --- | --- |\n" +
			"| `--a 1` | `OPENVOX_CA_A=1` | `a: 1` |\n" +
			"| `OPENVOX_CA_B` in `env` | set from a Secret |\n" +
			"| `c` | mentions `OPENVOX_CA_C` and `OPENVOX_CA_OPENBAO_*` |\n"
		Expect(envTableMentions(md)).To(ConsistOf("OPENVOX_CA_A", "OPENVOX_CA_B", "OPENVOX_CA_C"))
	})

	// The server reads these two outside applyServerEnv, and the operator CLI
	// reads its own prefix, so a table may name any of them; anything else it
	// names that applyServerEnv does not read is refused.
	It("allows a table to name what the server reads elsewhere, and nothing more", func() {
		documented := []string{"OPENVOX_CA_A", configEnvVar, ca.DefaultPassphraseEnvVar, "OPENVOX_CA_CTL_X", "OPENVOX_CA_NOPE"}
		Expect(envNamesNotRead(documented, []string{"OPENVOX_CA_A"})).To(ConsistOf("OPENVOX_CA_NOPE"))
	})

	It("reads a variable from a table's second column only", func() {
		md := "Prose naming `OPENVOX_CA_PROSE` is not a table.\n\n" +
			"| Flag | Environment variable |\n| --- | --- |\n" +
			"| `--a` | `OPENVOX_CA_A` |\n" +
			"| Key | Variable | Flag | Description |\n| --- | --- | --- | --- |\n" +
			"| `b` | `OPENVOX_CA_B` (comma-separated) | `--b` | mentions `OPENVOX_CA_DESC` |\n" +
			"| `OPENVOX_CA_FIRST` | not a variable |\n"
		Expect(envTableNames(md)).To(ConsistOf("OPENVOX_CA_A", "OPENVOX_CA_B"))
	})
})

// serverEnvNamesRead returns the variables applyServerEnv reads, refusing a
// read it cannot name and a count under the floor. The parser twins call
// envNamesRead directly, so they pass or fail on their own input rather than
// on whatever config.go holds.
func serverEnvNamesRead() []string {
	GinkgoHelper()
	src, err := os.ReadFile("config.go")
	Expect(err).NotTo(HaveOccurred())
	read, problems := envNamesRead(string(src), "applyServerEnv")
	Expect(problems).To(BeEmpty())
	Expect(len(read)).To(BeNumerically(">=", minServerEnvVars),
		"applyServerEnv reads only %d variables; has the guard stopped seeing them?", len(read))
	return read
}

// envNamesRead parses src and returns, for the function named fn, every
// variable it reads, with a problem for each read the guard cannot vouch for.
//
// A read is a call to one of envReaders with the name as a string literal, and
// a reader called with any other name is a problem, since the guard cannot
// tell what it reads. Any other OPENVOX_CA_ literal in fn is counted as well,
// and is a problem until its reader is added to envReaders: keyed on the
// callee alone, a variable bound through a new helper would need neither a
// binding spec nor a docs row. A variable read in a function fn calls is
// beyond this, and is caught only if the docs name it.
func envNamesRead(src, fn string) ([]string, []string) {
	GinkgoHelper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "src.go", src, 0)
	Expect(err).NotTo(HaveOccurred())

	var decl *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == fn {
			decl = fd
		}
	}
	Expect(decl).NotTo(BeNil(), "no function %s; update this guard to follow it", fn)

	envReaders := map[string]bool{"os.Getenv": true, "os.LookupEnv": true, "config.EnvBool": true, "config.EnvInt": true}
	var names, problems []string
	// The literals a reader was called with. ast.Inspect visits a call before
	// its arguments, so each is marked here before the literal case sees it.
	read := map[*ast.BasicLit]bool{}
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || !envReaders[pkg.Name+"."+sel.Sel.Name] {
				return true
			}
			if len(n.Args) > 0 {
				if lit, ok := n.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					read[lit] = true
					return true
				}
			}
			problems = append(problems, fmt.Sprintf("%s: %s reads a variable through %s.%s by a name "+
				"that is not a string literal; this guard cannot see which, so name it literally",
				fset.Position(n.Pos()), fn, pkg.Name, sel.Sel.Name))
		case *ast.BasicLit:
			if n.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(n.Value)
			Expect(err).NotTo(HaveOccurred())
			switch {
			case read[n]:
				names = append(names, name)
			case strings.HasPrefix(name, "OPENVOX_CA_"):
				names = append(names, name)
				problems = append(problems, fmt.Sprintf("%s: %s names %s outside a reader this guard "+
					"knows; add the function that reads it to envReaders", fset.Position(n.Pos()), fn, name))
			}
		}
		return true
	})
	return names, problems
}

// envTableRow matches a Markdown table row whose second cell starts with an
// OPENVOX_CA_ variable: the column every environment-variable table in docs/
// puts it in.
var envTableRow = regexp.MustCompile("^\\|[^|]*\\|\\s*`(OPENVOX_CA_[A-Z0-9_]+)`")

// envTableNames returns the variables md's tables list, by envTableRow.
func envTableNames(md string) []string {
	var names []string
	for _, line := range strings.Split(md, "\n") {
		if m := envTableRow.FindStringSubmatch(line); m != nil {
			names = append(names, m[1])
		}
	}
	return names
}

// envName matches an OPENVOX_CA_ variable, or a prefix of several such as
// OPENVOX_CA_OPENBAO_, which ends in an underscore.
var envName = regexp.MustCompile(`OPENVOX_CA_[A-Z0-9_]+`)

// envTableMentions returns every OPENVOX_CA_ variable md's table rows name, in
// any cell and in any form: `NAME`, `NAME=value` or within a sentence. A
// prefix standing for several variables is not one of them.
func envTableMentions(md string) []string {
	var names []string
	for _, line := range strings.Split(md, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		for _, name := range envName.FindAllString(line, -1) {
			if !strings.HasSuffix(name, "_") {
				names = append(names, name)
			}
		}
	}
	return names
}

// serverEnvReadElsewhere is what the server reads outside applyServerEnv that
// an operator sets, named by the constants the code reads so that a rename
// moves both. OPENVOX_CA_ROLE, OPENVOX_CA_DAEMON and OPENVOX_CA_SIGNER_PSK are
// read elsewhere too, but they are the launcher's own and no table should
// offer them to an operator, so they are left out.
func serverEnvReadElsewhere() []string {
	return []string{configEnvVar, ca.DefaultPassphraseEnvVar}
}

// envNamesNotRead returns, sorted and once each, the names in documented that
// the server does not read: not in read, not in serverEnvReadElsewhere, and
// not under OPENVOX_CA_CTL_, the operator CLI's prefix, which applyCtlEnv
// reads.
func envNamesNotRead(documented, read []string) []string {
	var server []string
	for _, name := range documented {
		if !strings.HasPrefix(name, "OPENVOX_CA_CTL_") {
			server = append(server, name)
		}
	}
	return namesMissing(server, append(slices.Clone(read), serverEnvReadElsewhere()...))
}

// namesMissing returns, sorted and once each, the names in want that are not
// in have.
func namesMissing(want, have []string) []string {
	in := map[string]bool{}
	for _, n := range have {
		in[n] = true
	}
	var missing []string
	for _, n := range want {
		if !in[n] && !slices.Contains(missing, n) {
			missing = append(missing, n)
		}
	}
	slices.Sort(missing)
	return missing
}
