// Copyright (C) 2026 Trevor Vaughan
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
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/version"
)

// The root command must reject stray positional arguments instead of silently
// ignoring them. The bug fix sets Args: cobra.NoArgs on the root command.
var _ = Describe("Root command", func() {
	It("rejects unexpected positional arguments", func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"stray-arg", "--cadir", GinkgoT().TempDir()})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(HaveOccurred(), "expected error for unexpected positional arg, got nil")
	})

	It("prints the release version for --version", func() {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetArgs([]string{"--version"})
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("openvox-ca version " + version.Version))
	})

	// -v must stay the shorthand for --verbosity: cobra would otherwise claim
	// it for the synthesised --version flag, silently changing what -v does.
	It("keeps -v as the shorthand for --verbosity", func() {
		cmd := newRootCmd()
		flag := cmd.Flags().ShorthandLookup("v")
		Expect(flag).NotTo(BeNil())
		Expect(flag.Name).To(Equal("verbosity"))
	})
})

// The migration guide tells operators the denial log renders as
// reason="route requires admin access" on stderr and
// "reason":"route requires admin access" when logfile is set, attributing the
// difference to the handler this function picks. The API suite pins the fields;
// this pins the half of the claim that lives here.
var _ = Describe("setupLogger handler selection", func() {
	var orig *slog.Logger

	BeforeEach(func() {
		orig = slog.Default()
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	It("writes JSON to the log file when one is configured", func() {
		path := filepath.Join(GinkgoT().TempDir(), "ca.log")
		f, err := setupLogger(&serverConfig{LogFile: path})
		Expect(err).NotTo(HaveOccurred())
		Expect(f).NotTo(BeNil())
		DeferCleanup(func() { Expect(f.Close()).To(Succeed()) })

		Expect(slog.Default().Handler()).To(BeAssignableToTypeOf(&slog.JSONHandler{}))

		slog.Warn("Request denied by authorisation middleware",
			"reason", "route requires admin access")

		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(ContainSubstring(`"reason":"route requires admin access"`))
	})

	It("writes text to stderr when no log file is configured", func() {
		// Both halves of the guide's claim: the text rendering, and that it
		// goes to stderr. The handler captures whatever os.Stderr names when
		// it is constructed, so swapping in a pipe around the call is enough
		// to read back what an operator's journal would receive.
		r, w, err := os.Pipe()
		Expect(err).NotTo(HaveOccurred())
		origStderr := os.Stderr
		defer func() { os.Stderr = origStderr }()
		os.Stderr = w
		f, err := setupLogger(&serverConfig{})
		os.Stderr = origStderr
		Expect(err).NotTo(HaveOccurred())
		Expect(f).To(BeNil(), "nothing to close when logging to stderr")

		Expect(slog.Default().Handler()).To(BeAssignableToTypeOf(&slog.TextHandler{}))

		slog.Warn("Request denied by authorisation middleware",
			"reason", "route requires admin access")
		Expect(w.Close()).To(Succeed())
		out, err := io.ReadAll(r)
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Close()).To(Succeed())
		Expect(string(out)).To(ContainSubstring(`reason="route requires admin access"`))
	})

	// The other half of what setupLogger decides. Nothing else observes it:
	// the config suite checks only that the field parses, so transposing the
	// Debug and Trace arms would break -v with every spec green.
	DescribeTable("maps verbosity to a level",
		func(verbosity int, enabled, notEnabled []slog.Level) {
			_, err := setupLogger(&serverConfig{Verbosity: verbosity})
			Expect(err).NotTo(HaveOccurred())
			for _, lvl := range enabled {
				Expect(slog.Default().Enabled(context.Background(), lvl)).To(BeTrue(),
					"level %v should be enabled at verbosity %d", lvl, verbosity)
			}
			for _, lvl := range notEnabled {
				Expect(slog.Default().Enabled(context.Background(), lvl)).To(BeFalse(),
					"level %v should be disabled at verbosity %d", lvl, verbosity)
			}
		},
		Entry("default is Info", 0,
			[]slog.Level{slog.LevelInfo}, []slog.Level{slog.LevelDebug}),
		Entry("-v is Debug", 1,
			[]slog.Level{slog.LevelDebug}, []slog.Level{levelTrace}),
		Entry("-vv is Trace", 2,
			[]slog.Level{slog.LevelDebug, levelTrace}, nil),
	)

	// SECURITY: the property the CodeQL go/log-injection exclusion rests on.
	//
	// That query reports every untrusted value that reaches a log call --
	// certnames off the request path, serials, r.URL.Path -- because it models
	// log *sinks* and cannot see what the handler does with the bytes. Its only
	// recognised sanitisers are strings.ReplaceAll against "\n"/"\r" and the %q
	// verb, neither of which suits structured logging, so the finding recurs for
	// every new attribute forever. Thirty-eight were dismissed by hand before
	// .github/codeql/codeql-config.yml excluded the rule.
	//
	// What makes that exclusion honest is that both handlers setupLogger can
	// install escape control characters, so a newline in attacker-supplied data
	// renders as the two characters \ and n rather than terminating the record.
	// Verified against Go 1.26.6; a stdlib change that stopped escaping would
	// invalidate the exclusion silently, which is what these specs exist to
	// catch. The companion guard is the depguard `only-slog-logs` rule in
	// .golangci.yml, which keeps slog the only logger in non-test code -- this
	// pins that slog escapes, that pins that nothing else does the logging.
	//
	// The assertion is deliberately "one record renders as one line" rather
	// than a substring match: forging a second entry is precisely what an
	// injected newline would buy, so counting lines tests the consequence
	// instead of the mechanism.
	Describe("control characters in logged data cannot forge a second entry", func() {
		// A payload that would open a fake ERROR record if the newline reached
		// the output raw. Shaped for the text handler; the JSON handler would
		// need a different tail, but the newline is what matters to both.
		const forged = "ok\nlevel=ERROR msg=\"CA key stolen\" subject=forged"

		expectSingleRecord := func(out string) {
			GinkgoHelper()
			Expect(out).NotTo(BeEmpty(), "the record must actually have been written")
			Expect(out).To(HaveSuffix("\n"), "a record is terminated by a newline")
			Expect(strings.Count(out, "\n")).To(Equal(1),
				"one log call must render as exactly one line; a second line means the "+
					"payload's newline reached the output unescaped:\n%s", out)
			Expect(out).To(ContainSubstring(`\n`),
				"the newline must survive as the escape sequence \\n; if it were dropped "+
					"instead the entry would be safe but lossy, and that is a change worth "+
					"noticing:\n%s", out)
		}

		DescribeTable("escapes the newline wherever attacker data lands",
			func(emit func()) {
				By("the JSON handler, which a configured log file selects")
				path := filepath.Join(GinkgoT().TempDir(), "ca.log")
				f, err := setupLogger(&serverConfig{LogFile: path})
				Expect(err).NotTo(HaveOccurred())
				Expect(slog.Default().Handler()).To(BeAssignableToTypeOf(&slog.JSONHandler{}))
				emit()
				Expect(f.Close()).To(Succeed())
				data, err := os.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())
				expectSingleRecord(string(data))

				By("the text handler, which stderr logging selects")
				r, w, err := os.Pipe()
				Expect(err).NotTo(HaveOccurred())
				origStderr := os.Stderr
				os.Stderr = w
				stderrFile, err := setupLogger(&serverConfig{})
				os.Stderr = origStderr
				Expect(err).NotTo(HaveOccurred())
				Expect(stderrFile).To(BeNil())
				Expect(slog.Default().Handler()).To(BeAssignableToTypeOf(&slog.TextHandler{}))
				emit()
				Expect(w.Close()).To(Succeed())
				out, err := io.ReadAll(r)
				Expect(err).NotTo(HaveOccurred())
				Expect(r.Close()).To(Succeed())
				expectSingleRecord(string(out))
			},
			// The five positions attacker-influenced data can occupy. Values and
			// slices are the shapes the dismissed alerts actually flagged; the
			// message, key and group cases are forward defence, since nothing in
			// the tree puts untrusted data there today and this is what would
			// notice if something started to.
			Entry("in the message", func() { slog.Warn("boundary " + forged) }),
			Entry("in an attribute value", func() { slog.Warn("boundary", "subject", forged) }),
			Entry("in an attribute key", func() { slog.Warn("boundary", forged, "v") }),
			Entry("in a group attribute", func() {
				slog.Warn("boundary", slog.Group("g", "subject", forged))
			}),
			Entry("in a []string element", func() {
				slog.Warn("boundary", "subjects", []string{forged})
			}),
		)
	})

	It("refuses to start when the log file cannot be opened", func() {
		// What the two callers do with this differs — the server command
		// returns it and refuses to start, while runSignerMode logs it and
		// falls back to stderr — so what is pinned here is the contract they
		// both depend on: an error that names the path, and no file handle.
		missing := filepath.Join(GinkgoT().TempDir(), "no-such-dir", "ca.log")
		f, err := setupLogger(&serverConfig{LogFile: missing})
		Expect(err).To(MatchError(ContainSubstring("failed to open log file")))
		Expect(err).To(MatchError(ContainSubstring(missing)))
		Expect(f).To(BeNil())
	})
})
