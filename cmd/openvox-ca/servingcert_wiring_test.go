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
	"go/ast"
	"go/parser"
	"go/token"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The serve command's serving-certificate wiring.
//
// servingcert_test.go drives buildServingCert and provisionServingCert
// directly, and its `provision` helper does the append into ca.CA.ManagedCerts
// itself -- so it reproduces main.go rather than exercising it, and every spec
// in it stays green when the serve command stops doing any of those things.
// That was demonstrated by mutation rather than assumed.
//
// The three edits that hole differs on are not equally loud, which is why each
// is pinned separately:
//
//   - Drop the append and the certificate is issued once at startup and then
//     never renewed: the reconcile loop never walks it, and the failure surfaces
//     as an expired listener certificate one TTL later.
//   - Drop the provisionServingCert call and startup succeeds with an empty
//     holder, so every handshake fails with "no serving certificate has been
//     issued yet" while CI stays green.
//   - Revert one of the TLS predicate's call sites to tls_cert/tls_key and a
//     self-provisioned CA comes up serving HTTPS with no client-authentication
//     middleware at all.
//
// The same technique as managed_certs_wiring_test.go, which exists because the
// identical mutation was found against attachManagedCerts, and as
// internal/api/authseam_test.go. It is a weaker guarantee than behaviour -- it
// pins that the calls are written, not that they run -- but a behavioural spec
// would have to start the server and bind its listeners, which is the compose
// integration suite's job.
var _ = Describe("the serve command's serving-certificate wiring", func() {
	var file *ast.File

	BeforeEach(func() {
		fset := token.NewFileSet()
		var err error
		file, err = parser.ParseFile(fset, "main.go", nil, 0)
		Expect(err).NotTo(HaveOccurred())

		// The parse must have found something to judge. A file that yielded no
		// function literals would agree with every claim below.
		var funcsSeen int
		ast.Inspect(file, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				funcsSeen++
			}
			return true
		})
		Expect(funcsSeen).To(BeNumerically(">", 0),
			"precondition: main.go parsed but contains no function literals")
	})

	It("calls buildServingCert and honours its refusal", func() {
		called, checked := callWithCheckedError(file, "buildServingCert")
		Expect(called).To(BeTrue(),
			"main.go does not call buildServingCert, so serving_cert would be "+
				"inert and every spec in servingcert_test.go would still pass")
		Expect(checked).To(BeTrue(),
			"main.go calls buildServingCert without checking its error, so a "+
				"configuration it has just refused -- serving_cert alongside "+
				"tls_cert, or a certificate that cannot serve -- would start the server")
	})

	It("calls provisionServingCert and honours its refusal", func() {
		called, checked := callWithCheckedError(file, "provisionServingCert")
		Expect(called).To(BeTrue(),
			"main.go does not call provisionServingCert, so the listener would bind "+
				"with an empty holder and fail every handshake")
		Expect(checked).To(BeTrue(),
			"main.go calls provisionServingCert without checking its error, so an "+
				"unreadable serving store would bind a listener with nothing to present "+
				"instead of refusing to start")
	})

	// Position, not only presence. The call sits between myCA.Init and the
	// listener setup, and both directions of moving it are silent in CI:
	// above Init, ReconcileManaged returns ErrNotInitialized for every entry
	// and every self-provisioning deployment refuses to start; below ServeTLS,
	// the listener binds with an empty holder and every handshake fails with
	// "no serving certificate has been issued yet" -- which is the failure the
	// presence spec above says it exists to prevent.
	It("provisions after the CA is initialised and before the listener serves", func() {
		// Offsets rather than statement indices, because the three calls are
		// not siblings in one block: Init and provisionServingCert are, but
		// ServeTLS is nested inside the serve-mode branch. Source position is
		// the one ordering that holds across all three.
		// The FIRST occurrence of each. myCA.Init is called twice in main.go --
		// once by the serve command and once by an offline subcommand further
		// down -- and taking the last match put Init after the provisioning
		// call and failed this spec against correct code. The serve command is
		// the first of the two, and provisionServingCert and ServeTLS appear
		// only there, so first-match is the comparison that means what this
		// spec claims.
		pos := func(name string) int {
			at := 0
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var got string
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					got = fn.Name
				case *ast.SelectorExpr:
					got = fn.Sel.Name
				}
				if got == name && at == 0 {
					at = int(call.Pos())
				}
				return true
			})
			return at
		}

		init, provision, serve := pos("Init"), pos("provisionServingCert"), pos("ServeTLS")
		Expect(init).To(BeNumerically(">", 0), "precondition: main.go must call myCA.Init")
		Expect(provision).To(BeNumerically(">", 0), "precondition: main.go must call provisionServingCert")
		Expect(serve).To(BeNumerically(">", 0), "precondition: main.go must call ServeTLS")

		Expect(provision).To(BeNumerically(">", init),
			"main.go provisions the serving certificate before the CA is initialised, so "+
				"every entry's reconcile returns ErrNotInitialized and a self-provisioning "+
				"CA refuses to start")
		Expect(provision).To(BeNumerically("<", serve),
			"main.go provisions the serving certificate after the listener is serving, so "+
				"the listener binds with an empty holder and every handshake fails")
	})

	It("puts the serving entry into the reconcile set, ahead of the rest", func() {
		// Two claims, and the ordering is not cosmetic. ReconcileManaged walks
		// the slice in order and provisionServingCert bounds the whole startup
		// pass with one budget, so an entry placed after the component
		// certificates can have that budget spent before it gets a turn --
		// leaving the store empty and the startup fatal because of some other
		// certificate whose own failure is meant to be routine.
		//
		// Dropping the statement entirely is the quieter edit and the one with
		// the longer fuse: the certificate is issued once at startup and then
		// never renewed.
		var present, first bool
		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ManagedCerts" {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "append" {
				return true
			}
			if !mentionsServingEntry(call) {
				return true
			}
			present = true
			// Ahead of the rest means the serving entry is in the literal being
			// appended TO, and the existing slice is what follows -- the
			// prepend shape, not the append one.
			if lit, ok := call.Args[0].(*ast.CompositeLit); ok && mentionsServingEntry(lit) {
				first = true
			}
			return true
		})
		Expect(present).To(BeTrue(),
			"main.go does not put the serving entry into ca.CA.ManagedCerts, so the "+
				"certificate is issued once at startup and never renewed -- the reconcile "+
				"loop never walks it, and the listener's certificate expires one TTL later")
		Expect(first).To(BeTrue(),
			"main.go appends the serving entry after the component certificates instead of "+
				"prepending it, so the startup pass can spend its whole budget on their "+
				"stores before reaching the one the listener needs")
	})

	// The edit that actually points the listener at the holder, and the one
	// whose failure is loudest in production and quietest in CI.
	//
	// servingcert_test.go drives the holder directly and its handshake spec
	// builds its own tls.Config, so nothing observes which callback main.go
	// installs. Restoring `GetCertificate: certs.GetCertificate` compiles, and
	// certs is nil for a self-provisioned CA -- so the listener binds and every
	// handshake panics dereferencing it, with the whole suite green. Verified
	// by mutation rather than assumed.
	It("gives the listener the certificate source it selected", func() {
		var bound string
		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) != 1 {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "getCertificate" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "serving" {
				if lhs, ok := assign.Lhs[0].(*ast.Ident); ok {
					bound = lhs.Name
				}
			}
			return true
		})
		Expect(bound).NotTo(BeEmpty(),
			"main.go never calls serving.getCertificate(), so the listener cannot be "+
				"reading the self-provisioned holder")

		// And that name, rather than anything else, is what tls.Config gets.
		var installed bool
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Config" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "tls" {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "GetCertificate" {
					continue
				}
				// An Ident equal to the bound name. A SelectorExpr here --
				// certs.GetCertificate -- is the mutation this exists to catch,
				// and it is nil whenever the CA self-provisions.
				if v, ok := kv.Value.(*ast.Ident); ok && v.Name == bound {
					installed = true
				}
			}
			return true
		})
		Expect(installed).To(BeTrue(),
			"main.go builds its tls.Config with a GetCertificate that is not the source it "+
				"selected, so a self-provisioned CA binds a listener backed by a nil "+
				"certReloader and panics on the first handshake")
	})

	// The predicate's call sites, which servingcert_test.go's own spec cannot
	// reach: it asserts what tlsEnabled returns, not that anything reads it.
	//
	// Five sites read it, and the mTLS one is the reason this is a spec rather
	// than a comment: a residual `cfg.TLSCert != "" && cfg.TLSKey != ""` there
	// leaves a self-provisioned CA serving HTTPS with no client authentication,
	// which is a security regression that nothing else in the suite notices.
	It("reads the TLS predicate rather than tls_cert/tls_key directly", func() {
		var predicateReads, rawReads int
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "tlsEnabled" {
					predicateReads++
				}
				return true
			}
			// `cfg.TLSCert != "" && cfg.TLSKey != ""`, in any order.
			bin, ok := n.(*ast.BinaryExpr)
			if !ok || bin.Op != token.LAND {
				return true
			}
			if mentionsTLSField(bin.X, "TLSCert") && mentionsTLSField(bin.Y, "TLSKey") {
				rawReads++
			}
			if mentionsTLSField(bin.X, "TLSKey") && mentionsTLSField(bin.Y, "TLSCert") {
				rawReads++
			}
			return true
		})

		Expect(predicateReads).To(BeNumerically(">", 0),
			"main.go never calls cfg.tlsEnabled(), so nothing in the serve command "+
				"knows a self-provisioned CA serves TLS")

		// The predicate is called once and its result read through a local at
		// every gate, so counting calls proves one assignment and nothing else
		// -- which is weaker than this spec's own claim. Count the reads of
		// that local instead, and hold them to the number of gates
		// cfg.tlsEnabled's doc comment enumerates: the plain-HTTP refusal, the
		// mTLS config, the listener's TLS config, ServeTLS, and the status
		// line. Deleting a gate now fails here rather than only its raw-pair
		// spelling.
		var gateReads int
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "tlsConfigured" {
				gateReads++
			}
			return true
		})
		// Eight, measured: the assignment, the plain-HTTP refusal and its
		// puppet_server warning, srv.PlainHTTP, the mTLS middleware, the
		// listener's TLS config, the status line, and ServeTLS. The floor is
		// the measured count rather than a round number below it -- set one
		// lower, a mutation that replaced a single gate with an open-coded
		// equivalent still passed.
		Expect(gateReads).To(BeNumerically(">=", 8),
			"main.go reads the TLS predicate at fewer sites than it did: a gate has "+
				"been deleted or open-coded, and cfg.tlsEnabled's doc comment enumerates "+
				"which ones must read it -- the plain-HTTP refusal, the mTLS middleware, "+
				"the listener's TLS config, ServeTLS and the status line")
		Expect(rawReads).To(Equal(0),
			"main.go still tests cfg.TLSCert and cfg.TLSKey together instead of "+
				"cfg.tlsEnabled(); a self-provisioned CA satisfies tlsEnabled but not "+
				"that pair, so whichever site this is would be skipped -- and on the "+
				"mTLS middleware that means HTTPS with no client authentication")
	})
})

// callWithCheckedError reports whether file calls name and acts on the error
// it returns.
//
// Two shapes, because the two call sites take different ones and neither is
// more correct:
//
//	if err := provisionServingCert(...); err != nil { ... }
//	serving, err := buildServingCert(...)
//	if err != nil { ... }
//
// The second is forced wherever the call also returns a value the caller keeps,
// so a guard matching only the first would fail on correct code -- which is how
// this spec first behaved, and a guard that fails on correct code gets widened
// until it matches nothing.
//
// Checked rather than merely counted, because the call being present says
// nothing about its error being honoured: writing `_ = name(...)` leaves a CA
// that starts happily with a configuration it has just decided cannot work.
func callWithCheckedError(file *ast.File, name string) (called, checked bool) {
	// The if-init form.
	ast.Inspect(file, func(n ast.Node) bool {
		stmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		assign, ok := stmt.Init.(*ast.AssignStmt)
		if !ok || !callsFunc(assign, name) {
			return true
		}
		called = true
		if condChecksAssignedError(stmt.Cond, assign) {
			checked = true
		}
		return true
	})

	// The assign-then-if form: the call, and the very next statement testing
	// the error it assigned. Adjacency is required on purpose -- a check
	// several statements later has let intervening code run on a value the
	// call may not have produced.
	ast.Inspect(file, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i := 0; i+1 < len(block.List); i++ {
			assign, ok := block.List[i].(*ast.AssignStmt)
			if !ok || !callsFunc(assign, name) {
				continue
			}
			called = true
			next, ok := block.List[i+1].(*ast.IfStmt)
			if !ok || next.Init != nil {
				continue
			}
			if condChecksAssignedError(next.Cond, assign) {
				checked = true
			}
		}
		return true
	})
	return called, checked
}

// callsFunc reports whether assign's sole right-hand side is a call to name.
func callsFunc(assign *ast.AssignStmt, name string) bool {
	if len(assign.Rhs) != 1 {
		return false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == name
}

// condChecksAssignedError reports whether cond is `<err> != nil` for the last
// name assign binds -- which is the error, by Go convention. Comparing against
// the assigned name rather than the literal "err" is what stops a check of some
// other error in scope counting as this one.
func condChecksAssignedError(cond ast.Expr, assign *ast.AssignStmt) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	lhs, lok := bin.X.(*ast.Ident)
	rhs, rok := bin.Y.(*ast.Ident)
	assigned, aok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	return lok && rok && aok && rhs.Name == "nil" && lhs.Name == assigned.Name
}

// mentionsTLSField reports whether expr is `<something>.<field> != ""`.
func mentionsTLSField(expr ast.Expr, field string) bool {
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	sel, ok := bin.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == field
}

// mentionsServingEntry reports whether the node's subtree names `serving.entry`.
func mentionsServingEntry(n ast.Node) bool {
	var found bool
	ast.Inspect(n, func(x ast.Node) bool {
		sel, ok := x.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "entry" {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "serving" {
			found = true
		}
		return true
	})
	return found
}
