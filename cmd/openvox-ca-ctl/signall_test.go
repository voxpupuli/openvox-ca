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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// SECURITY: pins the per-element quoting on `sign --all`'s summary.
//
// This is the one confirmation line in the CLI whose contents the server
// chooses rather than the operator: result.Signed is decoded from the
// POST /sign/all response body. The sibling sign/clean/revoke lines echo the
// operator's own --certname/--serial and are deliberately left at %s.
var _ = Describe("sign --all output escaping", func() {
	var (
		srv      *httptest.Server
		respBody string
		cfg      string
	)

	const forged = "evil\r\nSigned: \"everything\" -- all good"

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		cfg = writeTempCtlConfig("")
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(respBody))
		}))
		DeferCleanup(srv.Close)
	})

	runCapturingStdout := func() string {
		GinkgoHelper()
		out, execErr := captureStdout([]string{
			"sign", "--config", cfg, "--server-url", srv.URL, "--all",
		})
		Expect(execErr).NotTo(HaveOccurred(), "sign --all")
		return out
	}

	It("quotes each server-returned name so one cannot forge a line", func() {
		respBody = fmt.Sprintf(`{"signed":[%s,"web02"]}`, strconv.Quote(forged))
		out := runCapturingStdout()

		// The consequence first, so a revert to the joined %s fails for the
		// reason this spec is named for.
		Expect(strings.Count(out, "\n")).To(Equal(1),
			"the summary is one line; a second means a name's newline reached "+
				"stdout unescaped:\n%s", out)
		Expect(out).NotTo(ContainSubstring("\r"),
			"a bare carriage return rewrites the line on a terminal:\n%s", out)

		// Per-element quoting, not a quoted join: the separator has to stay
		// outside the quotes or two names read as one.
		Expect(out).To(ContainSubstring(strconv.Quote(forged)),
			"the hostile name must appear, quoted in its own right")
		Expect(out).To(ContainSubstring(`"web02"`),
			"the second name must be separately quoted, not folded into the first")
	})

	// The refusals are operator-facing too, and their names come out of the
	// same body. cobra prints a returned error verbatim, so the quoting has to
	// be in the error itself.
	DescribeTable("quotes each server-returned name in a refusal",
		func(key string) {
			respBody = fmt.Sprintf(`{%q:[%s,"web02"]}`, key, strconv.Quote(forged))
			_, execErr := captureStdout([]string{
				"sign", "--config", cfg, "--server-url", srv.URL, "--all",
			})
			Expect(execErr).To(HaveOccurred())
			msg := execErr.Error()
			Expect(msg).NotTo(ContainSubstring("\n"),
				"a name's newline reached the error unescaped: %q", msg)
			Expect(msg).NotTo(ContainSubstring("\r"),
				"a bare carriage return reached the error unescaped: %q", msg)
			Expect(msg).To(ContainSubstring(strconv.Quote(forged)))
			Expect(msg).To(ContainSubstring(`"web02"`))
		},
		Entry("signing-errors", "signing-errors"),
		Entry("no-csr", "no-csr"),
	)
})
