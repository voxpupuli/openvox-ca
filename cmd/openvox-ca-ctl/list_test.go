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
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// SECURITY: pins the quoting of certnames in `list`'s table.
//
// An earlier version of this change exempted the table on the grounds that
// quoting would wreck its column alignment. That was false: printTable derives
// its width from the strings it is handed, so quoting before the row is built
// leaves the columns correct. These specs pin both halves of that -- the names
// are escaped, and the table still lines up -- so the exemption cannot come
// back on a rationale that does not hold.
var _ = Describe("list output escaping", func() {
	var (
		srv      *httptest.Server
		respBody string
		cfg      string
	)

	const forged = "evil\r\nnode99                      signed"

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

	run := func() string {
		GinkgoHelper()
		out, err := captureStdout([]string{"list", "--config", cfg, "--server-url", srv.URL})
		Expect(err).NotTo(HaveOccurred(), "list")
		return out
	}

	It("quotes a server-supplied certname so it cannot forge a row", func() {
		respBody = `[{"name":` + strconv.Quote(forged) + `,"state":"requested"},` +
			`{"name":"web01","state":"signed"}]`
		out := run()

		// Two certificates, so two rows -- and no more. A third line means the
		// payload's newline reached the table unescaped and forged a row.
		Expect(strings.Count(out, "\n")).To(Equal(2),
			"one row per certificate; extra lines mean a name forged a row:\n%s", out)
		Expect(out).NotTo(ContainSubstring("\r"),
			"a bare carriage return rewrites the row on a terminal:\n%s", out)
		Expect(out).To(ContainSubstring(strconv.Quote(forged)),
			"the hostile name must appear, quoted")
	})

	It("still aligns the columns once names are quoted", func() {
		// The half the old rationale got wrong. printTable pads to the widest
		// first column, so with quoting applied before the row the states must
		// still start at the same offset.
		respBody = `[{"name":"a","state":"signed"},{"name":"much-longer-name","state":"requested"}]`
		lines := strings.Split(strings.TrimRight(run(), "\n"), "\n")
		Expect(lines).To(HaveLen(2))
		Expect(strings.Index(lines[0], "signed")).
			To(Equal(strings.Index(lines[1], "requested")),
				"states must start at the same column:\n%s", strings.Join(lines, "\n"))
	})

	It("says there is nothing to list, and succeeds, when the server returns none", func() {
		// docs/operator-cli.md publishes this line and the exit status 0, so a
		// script may branch on them.
		respBody = `[]`
		Expect(run()).To(Equal("(no certificates)\n"))
	})
})
