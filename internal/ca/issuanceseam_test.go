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

package ca_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// SECURITY: the subject-alternative-name policy is enforced in one place --
// checkSubjectAltNames, called from signWithDuration -- and its completeness
// rests entirely on a call-graph property: every path that takes names from a
// *submitted CSR* goes through that function. Nothing in the type system says
// so. A new path that called issueLeafLocked directly, exactly as the generate
// paths legitimately do, would issue certificates carrying whatever names a
// request asked for, and every existing spec would stay green, because each one
// drives a caller that does pass through the gate.
//
// So the property is asserted here instead: issueLeafLocked has exactly the
// callers listed below and no others. Adding one is not forbidden -- it means
// answering, in review, which side of the boundary the new path sits on. The
// boundary is where the names come from, not whether a CSR is involved: names
// arriving on a submitted request are gated, names an administrator supplies
// directly are not, and a renewal takes its names from the certificate it
// renews even when a re-key CSR supplies the key.
//
// reissueLeafLocked is pinned the same way, one level up. It copies every
// extension of the certificate it is handed, the authorisation arc included,
// which is safe only for a certificate its caller has established this CA
// issued and has not revoked. A third caller would inherit that copy without
// necessarily having made those checks, so its callers are an argued set too.
//
// This cannot use the compile-time bindings internal/api/authseam_test.go has,
// because both methods are unexported and this file is package ca_test. A
// rename would leave the walk matching nothing -- which is why each assertion
// is an exact set comparison rather than a check that no unexpected caller
// exists: renaming a method empties its found set, and an empty set is not the
// expected one, so the spec fails and names what it could no longer find.
//
// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
var _ = Describe("The issuance seam", func() {
	// callersOf returns, for every function in this package's non-test source
	// that calls method, the "file:line" of each call.
	callersOf := func(method string) map[string][]string {
		GinkgoHelper()
		fset := token.NewFileSet()
		entries, err := os.ReadDir(".")
		Expect(err).NotTo(HaveOccurred())

		found := map[string][]string{} // enclosing function -> "file:line"
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, name, nil, 0)
			Expect(err).NotTo(HaveOccurred(), "parsing %s", name)

			// Walk each function separately so a call can be attributed to the
			// function containing it rather than to the file.
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					// Matched on the selected name alone, whatever the receiver:
					// these are methods on *CA, so a caller reaches one as
					// c.issueLeafLocked(...) and a receiver-qualified rule would
					// see nothing.
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != method {
						return true
					}
					pos := fset.Position(call.Pos())
					found[fn.Name.Name] = append(found[fn.Name.Name],
						filepath.Base(pos.Filename)+":"+strconv.Itoa(pos.Line))
					return true
				})
			}
		}
		return found
	}

	It("has exactly the callers whose exemption has been argued", func() {
		// Why each caller is allowed to be here.
		expected := map[string]string{
			"signWithDuration":             "the gated path: calls checkSubjectAltNames before it issues anything",
			"GenerateWithOptions":          "offline and admin-only minting; names come from an operator's flags or an admin-tier query parameter, never from an agent's CSR",
			"reissueLeafLocked":            "every renewal path (Renew, AutoRenew, RenewStored); takes the subject and every SAN from the certificate being renewed and only the public key from a CSR, so there is nothing for the gate to judge",
			"issueManagedUnderSubjectLock": "managed certificates take their names from server configuration, fixed before the process serves anything; no request reaches this path, so there is nothing for the gate to judge",
		}

		got := keysOf(callersOf("issueLeafLocked"))
		want := keysOf(expected)
		Expect(got).To(Equal(want),
			"issueLeafLocked's callers have changed.\n"+
				"  found:    %v\n"+
				"  expected: %v\n"+
				"A new caller bypasses checkSubjectAltNames. If it takes names from a submitted CSR it "+
				"belongs behind signWithDuration; if its names come from an administrator, from "+
				"configuration or from a certificate this CA already issued, add it above with the reason. "+
				"An empty found set means the method was renamed and this gate stopped matching "+
				"anything -- update the name here rather than deleting the spec.",
			got, want)
	})

	It("reissues a certificate's extensions only for callers that vetted it", func() {
		// Why each caller is allowed to be here.
		expected := map[string]string{
			"Renew":     "re-key; assertOwnCertificate, refuseIfRevoked (before and under the subject lock) and the subject match all run before it",
			"AutoRenew": "same-key renewal; assertOwnCertificate and refuseIfRevoked (before and under the subject lock) run before it, and the subject is the certificate's own",
			"RenewStored": "operator renewal of the stored certificate; it is read under the subject lock, and assertOwnCertificate and refuseIfRevoked run on it there, " +
				"and a re-key of one carrying authorisation-arc extensions is refused before it",
		}

		got := keysOf(callersOf("reissueLeafLocked"))
		want := keysOf(expected)
		Expect(got).To(Equal(want),
			"reissueLeafLocked's callers have changed.\n"+
				"  found:    %v\n"+
				"  expected: %v\n"+
				"It copies every extension of the certificate it is given, pp_cli_auth included. A new "+
				"caller must first establish that this CA issued that certificate (assertOwnCertificate) "+
				"and that it is not revoked (refuseIfRevoked); add it above with the reason once it does. "+
				"An empty found set means the method was renamed -- update the name here rather than "+
				"deleting the spec.",
			got, want)
	})
})

// keysOf returns a map's keys, sorted, so a failure message is stable.
func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
