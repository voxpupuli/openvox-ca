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
	"os"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// SECURITY: every subcommand that puts --certname into a request path, and
// generate, which also builds its key file name from it.
//
// The certname is the operator's own input, so this is robustness rather than
// a defence against an attacker, but the two halves were reachable in
// different ways. A "/" or ".." in a request path needed nothing hostile: the
// server's router cleans the path and redirects, and the client followed the
// redirect to a different route. The key file name could leave --out-dir only
// once the server had answered 2xx for such a name, which needs a broken or
// hostile server. What the CLI owns is that neither can happen.
//
// There is no spec for a valid certname arriving percent-escaped, because none
// can be written: every name ca.ValidateSubject accepts is made of unreserved
// characters, so url.PathEscape leaves it unchanged. The control table below
// pins that such a name still arrives verbatim, as one segment.
var _ = Describe("certname in request and file paths", func() {
	var (
		hits       int
		gotMethod  string
		gotRawPath string
		onRequest  func()
		srv        *httptest.Server
		cfg        string
		outDir     string
		escapeDir  string
		certFile   string
	)

	// One body that every subcommand here can parse: generate reads the key
	// and certificate, import-cert the summary, and the rest ignore it.
	const okBody = `{"private_key":"KEY","certificate":"CERT",` +
		`"subject":"x","serial":"01","imported":true}`

	// hostile climbs out of --out-dir into a sibling directory that exists, so
	// a key file built from it would land somewhere a spec can look.
	const hostile = "../sign/all"

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		cfg = writeTempCtlConfig("")
		root := GinkgoT().TempDir()
		outDir = filepath.Join(root, "out")
		escapeDir = filepath.Join(root, "sign")
		Expect(os.Mkdir(outDir, 0o700)).To(Succeed())
		Expect(os.Mkdir(escapeDir, 0o700)).To(Succeed())
		certFile = filepath.Join(GinkgoT().TempDir(), "cert.pem")
		Expect(os.WriteFile(certFile, []byte("PEM"), 0o600)).To(Succeed())

		hits, gotMethod, gotRawPath = 0, "", ""
		onRequest = nil
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			gotMethod, gotRawPath = r.Method, r.URL.EscapedPath()
			if onRequest != nil {
				onRequest()
			}
			_, _ = w.Write([]byte(okBody))
		}))
		DeferCleanup(srv.Close)
	})

	// argsFor returns the arguments that drive one subcommand at certname.
	argsFor := func(subcommand, certname string) []string {
		args := []string{subcommand, "--config", cfg, "--server-url", srv.URL, "--certname", certname}
		switch subcommand {
		case "generate":
			args = append(args, "--out-dir", outDir)
		case "import-cert":
			args = append(args, "--cert-file", certFile)
		}
		return args
	}

	run := func(subcommand, certname string) error {
		GinkgoHelper()
		_, err := captureStdout(argsFor(subcommand, certname))
		return err
	}

	emptyDir := func(dir string) {
		GinkgoHelper()
		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty(), "nothing is written to %s for a refused certname", dir)
	}

	// The empty name is here because it used to address the collection
	// route, /certificate_status/ with nothing after it. sign is absent from
	// those entries because it refuses an empty --certname with its own
	// message before reaching certnamePath.
	DescribeTable("refuses an invalid certname before sending any request",
		func(subcommand, certname string) {
			err := run(subcommand, certname)

			Expect(err).To(HaveOccurred(), "%s must refuse %q", subcommand, certname)
			Expect(hits).To(BeZero(),
				"%s sent a request for an invalid certname, to %s %s", subcommand, gotMethod, gotRawPath)
			Expect(err.Error()).To(ContainSubstring("--certname"), "the error names the flag")
			Expect(err.Error()).To(ContainSubstring(strconv.Quote(certname)), "the error names the certname, quoted")
			Expect(err.Error()).To(ContainSubstring("path traversal"), "the error says why")

			emptyDir(outDir)
			emptyDir(escapeDir)
		},
		Entry("sign", "sign", hostile),
		Entry("revoke", "revoke", hostile),
		Entry("clean", "clean", hostile),
		Entry("generate", "generate", hostile),
		Entry("import-cert", "import-cert", hostile),
		Entry("revoke, empty", "revoke", ""),
		Entry("clean, empty", "clean", ""),
		Entry("generate, empty", "generate", ""),
		Entry("import-cert, empty", "import-cert", ""),
	)

	// The control for the table above: validation must not refuse a valid
	// name, and the escape must not alter one. The name carries every
	// punctuation character a subject may contain.
	DescribeTable("sends a valid certname verbatim, as one path segment",
		func(subcommand, method, route string) {
			const valid = "node_1.example-a.com"
			Expect(run(subcommand, valid)).To(Succeed())

			Expect(hits).To(Equal(1))
			Expect(gotMethod).To(Equal(method))
			Expect(gotRawPath).To(Equal(route + valid))
		},
		Entry("sign", "sign", "PUT", "/puppet-ca/v1/certificate_status/"),
		Entry("revoke", "revoke", "PUT", "/puppet-ca/v1/certificate_status/"),
		Entry("clean", "clean", "DELETE", "/puppet-ca/v1/certificate_status/"),
		Entry("generate", "generate", "POST", "/puppet-ca/v1/generate/"),
		Entry("import-cert", "import-cert", "PUT", "/puppet-ca/v1/certificate/"),
	)
})
