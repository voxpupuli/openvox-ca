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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The exit statuses are published in docs/operator-cli.md, and follow
// puppetserver ca's: 0 for done, 1 for failed, 24 for nothing to act on. Every
// spec below asserts the status main would exit with, through exitStatus, so
// a case that loses its exitError is caught as the 1 it would become.
var _ = Describe("exitStatus", func() {
	DescribeTable("maps Execute's error to the process exit status",
		func(err error, want int) {
			Expect(exitStatus(err)).To(Equal(want))
		},
		Entry("success", nil, 0),
		Entry("any other error", errors.New("boom"), 1),
		Entry("nothing to do", &exitError{code: exitNothingToDo, err: errors.New("idle")}, 24),
		Entry("nothing to do, wrapped", fmt.Errorf("outer: %w",
			&exitError{code: exitNothingToDo, err: errors.New("idle")}), 24),
	)
})

// stubCA answers each "METHOD path" from a table, recording every request it
// receives, so a spec can tell which requests the CLI sent as well as what it
// made of the answers.
type stubCA struct {
	mu       sync.Mutex
	answers  map[string]stubAnswer
	received []string
}

type stubAnswer struct {
	status int
	body   string
}

func newStubCA(answers map[string]stubAnswer) (*stubCA, *httptest.Server) {
	s := &stubCA{answers: answers}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		s.mu.Lock()
		s.received = append(s.received, key)
		s.mu.Unlock()
		a, ok := s.answers[key]
		if !ok {
			a = stubAnswer{status: http.StatusTeapot, body: "unexpected request " + key}
		}
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(a.body))
	}))
	DeferCleanup(srv.Close)
	return s, srv
}

func (s *stubCA) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.received...)
}

var _ = Describe("Exit status", func() {
	var cfg string

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		cfg = writeTempCtlConfig("")
	})

	// run executes args through the root, as main does, and returns the
	// command's stdout and the status main would exit with.
	run := func(srv *httptest.Server, args ...string) (string, int, error) {
		GinkgoHelper()
		out, err := captureStdout(append(append([]string{}, args...),
			"--config", cfg, "--server-url", srv.URL))
		return out, exitStatus(err), err
	}

	Describe("sign --all", func() {
		const route = "POST /puppet-ca/v1/sign/all"

		DescribeTable("exits as puppetserver ca does",
			func(body string, wantStatus int, wantStdout string) {
				_, srv := newStubCA(map[string]stubAnswer{route: {http.StatusOK, body}})
				out, status, err := run(srv, "sign", "--all")
				Expect(status).To(Equal(wantStatus), "error: %v", err)
				Expect(out).To(Equal(wantStdout))
			},
			Entry("signing everything", `{"signed":["a","b"]}`, 0, "Signed: \"a\", \"b\"\n"),
			// Nothing was pending: not a failure, and not a success either.
			Entry("with nothing pending", `{"signed":[]}`, 24, ""),
			Entry("with nothing pending, as a null list", `{"signed":null}`, 24, ""),
			// A request left unsigned fails the run, as upstream decides it,
			// even beside one that was signed; what was signed is still said.
			Entry("when policy refuses a request", `{"signed":[],"signing-errors":["b"]}`, 1, ""),
			Entry("when policy refuses one of two", `{"signed":["a"],"signing-errors":["b"]}`, 1,
				"Signed: \"a\"\n"),
			Entry("when a listed request has gone", `{"signed":["a"],"no-csr":["c"]}`, 1,
				"Signed: \"a\"\n"),
		)

		It("names the requests it could not sign", func() {
			_, srv := newStubCA(map[string]stubAnswer{
				route: {http.StatusOK, `{"signed":[],"signing-errors":["b"],"no-csr":["c"]}`},
			})
			_, _, err := run(srv, "sign", "--all")
			Expect(err).To(MatchError(And(
				ContainSubstring(`could not sign "b"`),
				ContainSubstring(`no certificate request found for "c"`))))
		})

		It("says why it did nothing", func() {
			_, srv := newStubCA(map[string]stubAnswer{route: {http.StatusOK, `{"signed":[]}`}})
			_, _, err := run(srv, "sign", "--all")
			Expect(err).To(MatchError("no certificate requests are waiting to be signed"))
		})

		It("still fails on an HTTP error", func() {
			_, srv := newStubCA(map[string]stubAnswer{route: {http.StatusInternalServerError, "boom"}})
			_, status, _ := run(srv, "sign", "--all")
			Expect(status).To(Equal(1))
		})
	})

	Describe("revoke", func() {
		const (
			put = "PUT /puppet-ca/v1/certificate_status/node1"
			get = "GET /puppet-ca/v1/certificate_status/node1"
		)

		// Puppet Server's revocation answers 409 only for a subject holding an
		// unsigned request, which puppetserver ca reports as 24. openvox-ca
		// also answers 409 when the stored CRL was not signed by its CA, and
		// then nothing can be revoked at all: only the state read back decides.
		DescribeTable("by subject name, refused with a 409",
			func(getAnswer stubAnswer, wantStatus int) {
				stub, srv := newStubCA(map[string]stubAnswer{
					put: {http.StatusConflict, "could not revoke unsigned csr for node1"},
					get: getAnswer,
				})
				_, status, err := run(srv, "revoke", "--certname", "node1")
				Expect(err).To(MatchError(ContainSubstring("HTTP 409")),
					"the server's refusal is still reported, whatever the status")
				Expect(status).To(Equal(wantStatus))
				Expect(stub.requests()).To(Equal([]string{put, get}))
			},
			Entry("exits 24 when the subject holds only a request",
				stubAnswer{http.StatusOK, `{"name":"node1","state":"requested"}`}, 24),
			Entry("exits 1 when it holds a certificate",
				stubAnswer{http.StatusOK, `{"name":"node1","state":"signed"}`}, 1),
			Entry("exits 1 when its state cannot be read",
				stubAnswer{http.StatusServiceUnavailable, "unavailable"}, 1),
			Entry("exits 1 when the state does not parse",
				stubAnswer{http.StatusOK, `not json`}, 1),
		)

		It("exits 1 for a 409 by serial, without asking for a state", func() {
			stub, srv := newStubCA(map[string]stubAnswer{
				"PUT /puppet-ca/v1/certificate_status_by_serial/AB": {http.StatusConflict, "still live"},
			})
			_, status, _ := run(srv, "revoke", "--serial", "AB")
			Expect(status).To(Equal(1))
			Expect(stub.requests()).To(Equal([]string{"PUT /puppet-ca/v1/certificate_status_by_serial/AB"}))
		})

		It("exits 1 for an unknown subject, without asking for a state", func() {
			stub, srv := newStubCA(map[string]stubAnswer{put: {http.StatusNotFound, "not found"}})
			_, status, _ := run(srv, "revoke", "--certname", "node1")
			Expect(status).To(Equal(1))
			Expect(stub.requests()).To(Equal([]string{put}))
		})

		It("exits 0 having revoked", func() {
			_, srv := newStubCA(map[string]stubAnswer{put: {http.StatusNoContent, ""}})
			_, status, _ := run(srv, "revoke", "--certname", "node1")
			Expect(status).To(Equal(0))
		})
	})

	// A deliberate divergence from puppetserver ca, which exits 24 for a
	// subject holding only a request because its revoke step had nothing to
	// revoke. The request the operator wanted gone is gone, so this is 0.
	Describe("clean", func() {
		It("exits 0 having cleaned, without asking for a state first", func() {
			stub, srv := newStubCA(map[string]stubAnswer{
				"DELETE /puppet-ca/v1/certificate_status/node1": {http.StatusNoContent, ""},
			})
			out, status, _ := run(srv, "clean", "--certname", "node1")
			Expect(status).To(Equal(0))
			Expect(out).To(Equal("Cleaned node1\n"))
			Expect(stub.requests()).To(Equal([]string{"DELETE /puppet-ca/v1/certificate_status/node1"}))
		})
	})
})
