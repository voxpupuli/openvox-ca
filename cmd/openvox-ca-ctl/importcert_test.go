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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// SECURITY: pins the %q on import-cert's summary lines.
//
// The subject printed here is decoded from the server's response body and
// nothing re-validates it on the way out, so a compromised or hostile CA can
// choose it freely. These lines go to a terminal through fmt.Printf, which
// escapes nothing, and .github/codeql/codeql-config.yml names this call site
// as one the go/log-injection exclusion's security property rests on. Neither
// guard that file lists reaches it: the depguard rule restricts which logging
// packages may be imported and cannot see a printf verb, and
// cmd/openvox-ca/main_test.go pins slog's handlers, which are not involved.
// Without this spec a revert of %q to %s would pass lint and the whole suite.
var _ = Describe("import-cert output escaping", func() {
	var (
		srv      *httptest.Server
		respBody string
		cfg      string
		certFile string
		lastErr  error
		status   int
	)

	// A subject a hostile server could return: both terminators, and a tail
	// shaped to look like a second, reassuring line of CLI output.
	const forged = "evil\r\nImported \"node1\" (serial 01, valid then to later)"

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		cfg = writeTempCtlConfig("")

		certFile = filepath.Join(GinkgoT().TempDir(), "cert.pem")
		Expect(os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"), 0o600)).
			To(Succeed())

		status = http.StatusOK
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(respBody))
		}))
		DeferCleanup(srv.Close)
	})

	// runCapturingStdout drives import-cert against the stub and returns what
	// it printed. fmt.Printf resolves os.Stdout at call time, so swapping a
	// pipe in around Execute is enough to read back what an operator sees.
	runCapturingStdout := func() string {
		GinkgoHelper()
		out, execErr := captureStdout([]string{
			"import-cert", "--config", cfg, "--server-url", srv.URL,
			"--certname", "node1", "--cert-file", certFile,
		})
		lastErr = execErr
		return out
	}

	// runOK is the common case; the error-path specs read lastErr instead.
	runOK := func() string {
		GinkgoHelper()
		out := runCapturingStdout()
		Expect(lastErr).NotTo(HaveOccurred(), "import-cert")
		return out
	}

	// Every field here comes out of one json.Unmarshal of one untrusted body,
	// so each is exercised in turn. Quoting the subject alone was the defect a
	// review found: the reasoning is "the server chose this", and that covers
	// the serial and the timestamps exactly as much as the name.
	DescribeTable("renders every server-chosen field quoted, so none can forge a line",
		func(field string, imported bool) {
			fields := map[string]string{
				"subject": "node1", "serial": "0A",
				"not_before": "a", "not_after": "b",
			}
			fields[field] = forged
			respBody = fmt.Sprintf(
				`{"subject":%s,"serial":%s,"not_before":%s,"not_after":%s,"imported":%t}`,
				strconv.Quote(fields["subject"]), strconv.Quote(fields["serial"]),
				strconv.Quote(fields["not_before"]), strconv.Quote(fields["not_after"]),
				imported)
			out := runOK()

			// The consequence a terminator would buy, asserted first so a
			// revert to %s fails for the reason this spec is named for.
			Expect(strings.Count(out, "\n")).To(Equal(1),
				"import-cert prints one summary line; a second means the field's "+
					"newline reached the terminal unescaped:\n%s", out)
			Expect(out).NotTo(ContainSubstring("\r"),
				"a bare carriage return rewrites the line on an operator's terminal:\n%s", out)

			// Non-vacuity, last: the assertions above hold trivially for a run
			// that printed nothing at all.
			Expect(out).To(ContainSubstring(strconv.Quote(forged)),
				"the server-supplied %s must reach the summary, quoted", field)
		},
		Entry("subject, imported branch", "subject", true),
		Entry("subject, already-tracked branch", "subject", false),
		Entry("serial, imported branch", "serial", true),
		Entry("serial, already-tracked branch", "serial", false),
		Entry("not_before", "not_before", true),
		Entry("not_after", "not_after", true),
	)
	// The error paths. import-cert's only previous spec asserted the happy
	// path; each of these pins a distinct failure and the message it produces,
	// rather than merely that something went wrong.
	Describe("error paths", func() {
		// SECURITY: checkHTTP renders the server's error body, and cobra
		// prints a returned error to stderr because nothing here sets
		// SilenceErrors. The body has less provenance
		// than anything else the CLI prints -- it is chosen entirely by the
		// server -- so it is quoted, and this is what would notice it
		// reverting to %s. TrimSpace would not save it: it strips only
		// leading and trailing whitespace, leaving an embedded terminator.
		It("quotes the server's error body so it cannot forge a line", func() {
			status = http.StatusInternalServerError
			respBody = "boom\r\nRevoked \"node1\" -- nothing to worry about"
			_ = runCapturingStdout()

			Expect(lastErr).To(HaveOccurred())
			msg := lastErr.Error()
			Expect(strings.Count(msg, "\n")).To(Equal(0),
				"the error is one line; a newline in the body reached it unescaped:\n%s", msg)
			Expect(msg).NotTo(ContainSubstring("\r"),
				"a bare carriage return rewrites the line on a terminal:\n%s", msg)
			// Non-vacuity: the body must actually have reached the message.
			Expect(msg).To(ContainSubstring(strconv.Quote(respBody)),
				"the server's body must appear, quoted")
			Expect(msg).To(ContainSubstring("PUT"), "the error names the method")
		})

		It("reports a malformed response body", func() {
			respBody = "{not json"
			_ = runCapturingStdout()
			Expect(lastErr).To(MatchError(ContainSubstring("could not parse response")))
		})

		It("reports an unreadable --cert-file", func() {
			certFile = filepath.Join(GinkgoT().TempDir(), "does-not-exist.pem")
			respBody = `{"subject":"n","serial":"0A","imported":true}`
			_ = runCapturingStdout()
			Expect(lastErr).To(MatchError(ContainSubstring("reading --cert-file")))
		})
	})
})
