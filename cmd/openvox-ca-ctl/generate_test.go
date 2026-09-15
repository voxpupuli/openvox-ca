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
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Both binaries ship the same flag name on the same subcommand name, so an
// operator who has used `openvox-ca generate --dns a --dns b` reaches for the
// same gesture here. `--dns` was bound to a scalar on this side, and pflag's
// scalar is last-wins: the repeat was accepted and every value but the final
// one discarded -- exit 0, no warning, and a certificate that fails TLS for
// half the names asked for. A CA's answer to an ambiguous request must not be
// a successful-looking wrong artefact.
//
// What this CLI owns is the request it sends, so these specs assert on the
// query the server receives rather than on a minted certificate. They pin the
// arity and not only the comma path that always worked; the comma path is here
// as a control, because a fix that broke it would otherwise pass unnoticed.
var _ = Describe("generate subcommand --dns", func() {
	var (
		gotDNS    []string
		gotQuery  string
		gotMethod string
		gotPath   string
		srv       *httptest.Server
		cfg       string
		outDir    string
	)

	BeforeEach(func() {
		saveCtlGlobals()
		// As in revoke's specs: without these the resolver falls back to the
		// host's own /etc/puppet-ca/ctl.yaml and to any PUPPET_CA_CTL_* in the
		// environment, which on a machine that actually runs openvox-ca fails
		// these for reasons that have nothing to do with --dns.
		clearCtlEnv()
		cfg = writeTempCtlConfig("")
		outDir = GinkgoT().TempDir()
		gotDNS, gotQuery, gotMethod, gotPath = nil, "", "", ""

		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotDNS = r.URL.Query()["dns"]
			gotQuery = r.URL.RawQuery
			// The query is appended to the same string that carries the route
			// and the certname, so recording only the query would let a
			// mutation of either survive every spec here. The stub answers 200
			// to any request, and the specs below assert nothing but the error
			// being nil, so nothing else would notice.
			gotMethod, gotPath = r.Method, r.URL.Path
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"private_key":"KEY","certificate":"CERT"}`))
		}))
		DeferCleanup(srv.Close)
	})

	// run drives the subcommand through the root, the way an operator does.
	// captureStdout keeps the certificate PEM off the suite's own stdout.
	run := func(args ...string) {
		GinkgoHelper()
		_, err := captureStdout(append([]string{
			"generate", "--config", cfg, "--server-url", srv.URL,
			"--out-dir", outDir, "--certname", "node1.example.com",
		}, args...))
		Expect(err).NotTo(HaveOccurred(), "generate")
	}

	It("sends every name when --dns is repeated", func() {
		run("--dns", "a.example.com", "--dns", "b.example.com")

		// Equal rather than ContainElements: the defect kept exactly one of the
		// two, so an assertion that tolerated a short list could not have
		// failed against it.
		Expect(gotDNS).To(Equal([]string{"a.example.com", "b.example.com"}),
			"a repeated --dns must not discard earlier values; raw query was %q", gotQuery)

		// The route the query was appended to, pinned once here rather than in
		// every spec: the certname belongs in the path, and this is a POST.
		Expect(gotMethod).To(Equal("POST"))
		Expect(gotPath).To(Equal("/puppet-ca/v1/generate/node1.example.com"))
	})

	It("still splits the comma-separated form", func() {
		run("--dns", "a.example.com,b.example.com")

		Expect(gotDNS).To(Equal([]string{"a.example.com", "b.example.com"}),
			"raw query was %q", gotQuery)
	})

	It("accepts repeats and commas in the same invocation", func() {
		run("--dns", "a.example.com,b.example.com", "--dns", "c.example.com")

		Expect(gotDNS).To(Equal([]string{"a.example.com", "b.example.com", "c.example.com"}),
			"raw query was %q", gotQuery)
	})

	It("sends no dns parameter at all when the flag is absent", func() {
		// The control for the three above. With no --dns the server must see a
		// bare path: an empty dns= is not the same request, because supplying
		// any --dns suppresses promotion of the certname into the SAN set, so a
		// stray parameter would quietly change what a plain `generate` mints.
		run()

		// The positive fact first. gotQuery and gotDNS are reset to their zero
		// values in the BeforeEach, so on their own they are satisfied by the
		// recorder's initial state and cannot tell a bare-path request from no
		// request at all. Asserting the path says the stub was actually
		// reached, which is what makes the two emptiness checks mean something.
		Expect(gotPath).To(Equal("/puppet-ca/v1/generate/node1.example.com"))
		Expect(gotQuery).To(BeEmpty())
		Expect(gotDNS).To(BeEmpty())
	})

	It("escapes a name that would otherwise inject a second dns parameter", func() {
		// The old query was built by textual substitution of "," for "&dns=",
		// which left a separator inside a name indistinguishable from one
		// between names. Building it with url.Values closes that, and this pins
		// it: one flag, one name, whatever the name contains.
		const hostile = "a.example.com&dns=evil.example.com"
		run("--dns", hostile)

		Expect(gotDNS).To(Equal([]string{hostile}),
			"one --dns must yield one name; raw query was %q", gotQuery)
	})
})
