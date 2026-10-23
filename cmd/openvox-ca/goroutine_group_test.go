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
	"os"
	"strings"
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

// The serve command's goroutines, held to the group by the shape of the code.
//
// servingcert_serve_test.go checks the behaviour: after the command returns,
// nothing it started is still running. That spec runs the bind-failure path
// only, and an early return between the group's creation and the bind --
// a TLS keypair that will not load, say -- is a different path. These pin
// what every path depends on: no go statement in this package's code outside
// the places accounted for below, the group stopped before any other teardown,
// and the metrics exporter started only once something will stop it.
//
// The go-statement check covers this package only. A helper in another package
// that RunE calls, and that starts a goroutine of its own, is beyond it.
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

	It("starts no goroutine with a bare go statement outside the files accounted for", func() {
		// The whole package rather than RunE alone, because a helper RunE
		// calls is where one hides: startK8sExport started its job with a
		// bare go until #546. Each entry says how its goroutines are joined
		// instead, which is the claim a reviewer has to check.
		accounted := map[string]string{
			"goroutine_group.go": "the group itself: Go is where every serve goroutine starts",
			"launcher.go": "the launcher's child-exit watchers, joined through the supervisor's " +
				"exit channel; the launcher never opens the store",
		}

		entries, err := os.ReadDir(".")
		Expect(err).NotTo(HaveOccurred())
		found := map[string][]string{}
		parsed := 0
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, name, nil, 0)
			Expect(err).NotTo(HaveOccurred())
			parsed++
			ast.Inspect(file, func(n ast.Node) bool {
				if g, ok := n.(*ast.GoStmt); ok {
					found[name] = append(found[name], fset.Position(g.Pos()).String())
				}
				return true
			})
		}
		Expect(parsed).To(BeNumerically(">", 10),
			"precondition: the package's source files were not found to parse")

		for name, at := range found {
			_, ok := accounted[name]
			Expect(ok).To(BeTrue(),
				"%s starts a goroutine with a bare go statement (%s), so nothing waits for "+
					"it and it can still be running after the store's teardown (#546). Start "+
					"it with the group's Go, or account for it here with how it is joined",
				name, strings.Join(at, ", "))
		}
		for name := range accounted {
			Expect(found).To(HaveKey(name),
				"%s is accounted for but starts no goroutine; remove the entry so it "+
					"cannot excuse one added later", name)
		}
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

	It("starts the metrics exporter only once the goroutine that stops it exists", func() {
		// The exporter's ListenAndServe does not watch the group's context; it
		// returns when the shutdown goroutine calls Shutdown. Started before
		// that goroutine exists, an early return in between -- an invalid
		// kubernetes_export block, say -- would leave Stop waiting on it for
		// ever.
		var shutdownAt, metricsAt token.Pos
		ast.Inspect(runE.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || exprName(call.Fun) != "serveGoroutines.Go" || len(call.Args) != 1 {
				return true
			}
			lit, ok := call.Args[0].(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(lit.Body, func(m ast.Node) bool {
				inner, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch exprName(inner.Fun) {
				case "close":
					if len(inner.Args) == 1 && exprName(inner.Args[0]) == "shutdownDone" {
						shutdownAt = call.Pos()
					}
				case "metricsServer.ListenAndServe":
					metricsAt = call.Pos()
				}
				return true
			})
			return true
		})
		Expect(shutdownAt).NotTo(BeZero(),
			"precondition: no serveGoroutines.Go call in RunE closes shutdownDone")
		Expect(metricsAt).NotTo(BeZero(),
			"precondition: no serveGoroutines.Go call in RunE runs metricsServer.ListenAndServe")
		Expect(metricsAt > shutdownAt).To(BeTrue(),
			"RunE starts the metrics exporter before the shutdown goroutine that stops it, "+
				"so an early return in between leaves serveGoroutines.Stop waiting for ever")
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
