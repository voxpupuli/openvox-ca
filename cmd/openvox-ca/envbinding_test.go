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
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
