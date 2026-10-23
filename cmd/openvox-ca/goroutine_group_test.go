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
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("goroutineGroup", func() {
	It("does not return from Stop while a goroutine is still running", func() {
		g := newGoroutineGroup(context.Background())
		release := make(chan struct{})
		g.Go(func(ctx context.Context) {
			<-ctx.Done()
			<-release
		})

		stopped := make(chan struct{})
		go func() {
			g.Stop()
			close(stopped)
		}()

		Consistently(stopped, "200ms").ShouldNot(BeClosed(),
			"Stop returned while a goroutine it started was still running")
		close(release)
		Eventually(stopped).Should(BeClosed())
	})

	It("cancels the context its goroutines see when Stop is called", func() {
		g := newGoroutineGroup(context.Background())
		seen := make(chan context.Context, 1)
		g.Go(func(ctx context.Context) {
			seen <- ctx
			<-ctx.Done()
		})

		var ctx context.Context
		Eventually(seen).Should(Receive(&ctx))
		Expect(ctx.Err()).NotTo(HaveOccurred())
		g.Stop()
		Expect(ctx.Err()).To(MatchError(context.Canceled))
	})

	It("passes on the parent's cancellation", func() {
		parent, cancel := context.WithCancel(context.Background())
		g := newGoroutineGroup(parent)
		DeferCleanup(g.Stop)

		done := make(chan struct{})
		g.Go(func(ctx context.Context) {
			<-ctx.Done()
			close(done)
		})
		Consistently(done, "50ms").ShouldNot(BeClosed())
		cancel()
		Eventually(done).Should(BeClosed())
	})

	It("can be stopped more than once", func() {
		g := newGoroutineGroup(context.Background())
		g.Go(func(ctx context.Context) { <-ctx.Done() })
		g.Stop()

		stopped := make(chan struct{})
		go func() {
			g.Stop()
			close(stopped)
		}()
		Eventually(stopped, time.Second).Should(BeClosed())
	})
})

// The serve command's RunE, held to the group by its shape.
//
// servingcert_serve_test.go checks the behaviour: after the command returns,
// nothing it started is still running. That spec runs the bind-failure path
// only, and an early return between the group's creation and the bind --
// a TLS keypair that will not load, say -- is a different path. These pin
// the two properties every path depends on, so a new goroutine cannot be added
// to RunE outside the group without failing here.
var _ = Describe("the serve command's goroutines", func() {
	var runE *ast.FuncLit

	BeforeEach(func() {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "main.go", nil, 0)
		Expect(err).NotTo(HaveOccurred())

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "newRootCmd" {
				return true
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				kv, ok := n.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "RunE" {
					runE, _ = kv.Value.(*ast.FuncLit)
				}
				return runE == nil
			})
			return false
		})
		Expect(runE).NotTo(BeNil(), "precondition: no RunE function literal in newRootCmd")
	})

	It("starts no goroutine with a bare go statement", func() {
		var bare []string
		ast.Inspect(runE, func(n ast.Node) bool {
			if g, ok := n.(*ast.GoStmt); ok {
				bare = append(bare, exprName(g.Call.Fun))
			}
			return true
		})
		Expect(bare).To(BeEmpty(),
			"RunE starts a goroutine outside serveGoroutines, so nothing waits for it "+
				"and it can still be running after the store's teardown (#546). "+
				"Start it with serveGoroutines.Go instead")
	})

	It("defers stopping the group after every other teardown it defers", func() {
		// Deferred calls run last-in, first-out, so the group's Stop runs before
		// the instance lock is released and the runtime closed only if it is
		// deferred after them. Defers inside nested function literals belong
		// to those functions, not to RunE, so they are not counted.
		var defers []*ast.DeferStmt
		ast.Inspect(runE.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.DeferStmt:
				defers = append(defers, n)
			}
			return true
		})
		Expect(len(defers)).To(BeNumerically(">", 1),
			"precondition: RunE defers less than this spec expects to order")

		last := defers[len(defers)-1]
		sel, ok := last.Call.Fun.(*ast.SelectorExpr)
		Expect(ok && sel.Sel.Name == "Stop" && exprName(sel.X) == "serveGoroutines").To(BeTrue(),
			"RunE's last defer is not serveGoroutines.Stop(), so some teardown it "+
				"defers runs while the command's goroutines may still be using it")
	})
})

// exprName names a call target well enough for a failure message.
func exprName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprName(e.X) + "." + e.Sel.Name
	case *ast.FuncLit:
		return "func literal"
	default:
		return "expression"
	}
}
