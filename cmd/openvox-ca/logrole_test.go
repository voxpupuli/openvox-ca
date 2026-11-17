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
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// captureStderr runs install with os.Stderr swapped for a pipe, so a text
// handler it constructs writes there; emit then logs through that handler, and
// what it wrote is returned. The handler binds os.Stderr when it is built, which
// is why the swap need only cover install.
func captureStderr(install, emit func()) string {
	GinkgoHelper()
	r, w, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _, _ = r.Close(), w.Close() })
	origStderr := os.Stderr
	defer func() { os.Stderr = origStderr }()
	os.Stderr = w
	install()
	os.Stderr = origStderr
	emit()
	Expect(w.Close()).To(Succeed())
	out, err := io.ReadAll(r)
	Expect(err).NotTo(HaveOccurred())
	return string(out)
}

// textRole extracts the role attribute from one text-handler record, or "" when
// it has none. Anchored on a space so a key that merely ends in "role" does not
// count.
var textRole = regexp.MustCompile(` role=(\S+)`)

var _ = Describe("the role on every log record", func() {
	BeforeEach(func() {
		orig := slog.Default()
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	DescribeTable("names the server process by how it was started",
		func(envRole string, singleProcess bool, want string) {
			Expect(processRole(envRole, singleProcess)).To(Equal(want))
		},
		Entry("the process the operator started is the launcher", "", false, roleLauncher),
		Entry("unless it was told to do everything itself", "", true, roleSingleProcess),
		Entry("the signer child", "signer", false, roleSigner),
		Entry("the frontend child", "frontend", false, roleFrontend),
	)

	// Every role a process can install its logger as, in both encodings an
	// operator can configure. The JSON case reads the record back as JSON so
	// the attribute is a field a jq filter can select on, not a substring
	// somewhere in the line.
	everyRole := []TableEntry{
		Entry("the launcher", roleLauncher),
		Entry("the signer", roleSigner),
		Entry("the frontend", roleFrontend),
		Entry("the single-process server", roleSingleProcess),
		Entry("an offline mint", "generate"),
		Entry("an offline inventory rebuild", "rebuild-inventory-hmac"),
	}

	DescribeTable("labels the record in the JSON logfile",
		func(role string) {
			path := filepath.Join(GinkgoT().TempDir(), "ca.log")
			f, err := setupLogger(&serverConfig{LogFile: path}, role)
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = f.Close() })

			slog.Warn("a record", "subject", "web01.example.com")
			Expect(f.Close()).To(Succeed())

			data, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			var entry map[string]any
			Expect(json.Unmarshal(data, &entry)).To(Succeed(), "one JSON record:\n%s", data)
			Expect(entry).To(HaveKeyWithValue("role", role))
			Expect(entry).To(HaveKeyWithValue("subject", "web01.example.com"),
				"the role is added to the record, not substituted for its own attributes")
		},
		everyRole,
	)

	DescribeTable("labels the record on stderr",
		func(role string) {
			out := captureStderr(func() {
				f, err := setupLogger(&serverConfig{}, role)
				Expect(err).NotTo(HaveOccurred())
				Expect(f).To(BeNil())
			}, func() { slog.Warn("a record", "subject", "web01.example.com") })

			Expect(strings.Count(out, "\n")).To(Equal(1), "one record:\n%s", out)
			m := textRole.FindStringSubmatch(out)
			Expect(m).NotTo(BeNil(), "no role attribute in:\n%s", out)
			Expect(m[1]).To(Equal(role))
		},
		everyRole,
	)

	// The attribute names the process that writes the record. The launcher
	// already uses process= for the child a message is about, so the two must
	// stay distinct keys: on the launcher's own report of a crashed frontend,
	// process=frontend and role=launcher are both true and both needed.
	It("keeps process= free for the child a launcher message describes", func() {
		path := filepath.Join(GinkgoT().TempDir(), "ca.log")
		f, err := setupLogger(&serverConfig{LogFile: path}, roleLauncher)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = f.Close() })

		slog.Error("CA child process exited unexpectedly", "process", "frontend")
		Expect(f.Close()).To(Succeed())

		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		var entry map[string]any
		Expect(json.Unmarshal(data, &entry)).To(Succeed())
		Expect(entry).To(HaveKeyWithValue("role", roleLauncher))
		Expect(entry).To(HaveKeyWithValue("process", "frontend"))
	})

	Describe("the signer's logger", func() {
		It("labels its records in the configured logfile", func() {
			path := filepath.Join(GinkgoT().TempDir(), "ca.log")
			closeLog := openSignerLog(&serverConfig{LogFile: path})
			slog.Info("Signer process ready")
			closeLog()

			data, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			var entry map[string]any
			Expect(json.Unmarshal(data, &entry)).To(Succeed(), "one JSON record:\n%s", data)
			Expect(entry).To(HaveKeyWithValue("role", roleSigner))
		})

		// The fallback builds its own handler rather than going through
		// setupLogger, so it needs labelling separately: without it, exactly
		// the signer whose logfile failed would be the one line in the stream
		// that cannot be attributed.
		It("labels its records when it falls back to stderr", func() {
			unopenable := GinkgoT().TempDir() // a directory cannot be opened for append
			var closeLog func()
			out := captureStderr(func() {
				closeLog = openSignerLog(&serverConfig{LogFile: unopenable})
			}, func() { slog.Info("Signer process ready") })
			closeLog()

			lines := strings.Split(strings.TrimSpace(out), "\n")
			Expect(lines).To(HaveLen(2), "the fallback warning and the record:\n%s", out)
			for _, line := range lines {
				m := textRole.FindStringSubmatch(line)
				Expect(m).NotTo(BeNil(), "no role attribute in %q", line)
				Expect(m[1]).To(Equal(roleSigner))
			}
			Expect(lines[0]).To(ContainSubstring("Failed to open log file, using stderr"))
		})
	})
})
