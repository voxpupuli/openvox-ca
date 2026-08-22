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
	"encoding/base64"
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
	// Verified against the Go version in go.mod, which is what every workflow
	// builds with (go-version-file: go.mod); a stdlib change that stopped
	// escaping would invalidate the exclusion silently, which is what these
	// specs exist to catch. The companion guard is the depguard
	// `only-slog-logs` rule in .golangci.yml, which denies the loggers most
	// likely to be reached for instead. That rule is a denylist, so it cannot
	// prove slog is the only logger -- AGENTS.md carries the convention for the
	// cases it cannot see. These specs pin the other half: that slog, which is
	// what does the logging, escapes.
	//
	// The primary assertion is "one record renders as one line" rather than a
	// substring match: forging a second entry is precisely what an injected
	// newline would buy, so counting lines tests the consequence instead of the
	// mechanism. The tail check below is secondary, and covers the different
	// failure of dropping the bytes rather than escaping them.
	Describe("control characters in logged data cannot forge a second entry", func() {
		// A payload that would open a fake ERROR record if a terminator reached
		// the output raw. It carries both terminators: CodeQL's own sanitiser
		// model recognises \r as well as \n, and a lone \r still starts a fresh
		// line for terminal and journal consumers, so escaping one and not the
		// other would leave the invariant false with these specs green.
		// The forged record body is shaped for the text handler, but what is
		// asserted -- one line out, no bare terminator -- holds for both.
		const forged = "ok\r\nlevel=ERROR msg=\"CA key stolen\" subject=forged"

		// The substring that proves the payload's tail survived the escaping
		// rather than being truncated at the terminator. Both handlers keep it
		// verbatim for every position except a []byte under the JSON handler,
		// which base64-encodes the value -- still lossless, just spelled
		// differently, which is why the table carries the JSON tail per entry.
		const textTail = "level=ERROR"
		jsonTailForBytes := base64.StdEncoding.EncodeToString([]byte(forged))

		expectSingleRecord := func(out, tail string) {
			GinkgoHelper()
			Expect(out).NotTo(BeEmpty(), "the record must actually have been written")
			Expect(out).To(HaveSuffix("\n"), "a record is terminated by a newline")
			Expect(strings.Count(out, "\n")).To(Equal(1),
				"one log call must render as exactly one line; a second line means the "+
					"payload's newline reached the output unescaped:\n%s", out)
			Expect(strings.Count(out, "\r")).To(Equal(0),
				"a bare carriage return starts a fresh line for terminal and journal "+
					"consumers, so it must be escaped too:\n%s", out)
			// Deliberately not asserting how the escape is spelled. A handler may
			// render a control character as a short two-character escape or as a
			// six-character Unicode one, and both are correct; pinning either
			// spelling would fail a stdlib change that is still safe. What must
			// hold is that the bytes were escaped rather than discarded, and the
			// tail proves that.
			Expect(out).To(ContainSubstring(tail),
				"the payload's tail must survive; if the terminator were dropped rather "+
					"than escaped the entry would be safe but lossy, and that is a change "+
					"worth noticing:\n%s", out)
		}

		DescribeTable("escapes the terminators wherever attacker data lands",
			func(emit func(), jsonTail string) {
				By("the JSON handler, which a configured log file selects")
				path := filepath.Join(GinkgoT().TempDir(), "ca.log")
				f, err := setupLogger(&serverConfig{LogFile: path})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = f.Close() })
				Expect(slog.Default().Handler()).To(BeAssignableToTypeOf(&slog.JSONHandler{}))
				emit()
				Expect(f.Close()).To(Succeed())
				data, err := os.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())
				expectSingleRecord(string(data), jsonTail)

				By("the text handler, which stderr logging selects")
				r, w, err := os.Pipe()
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _, _ = r.Close(), w.Close() })
				origStderr := os.Stderr
				// Belt and braces with the inline restore below: if anything
				// panics or the suite is interrupted while os.Stderr points at
				// this pipe, the run's own diagnostics would vanish into it.
				defer func() { os.Stderr = origStderr }()
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
				expectSingleRecord(string(out), textTail)
			},
			// The positions attacker-influenced data can occupy. Values and
			// slices are the shapes the dismissed alerts actually flagged; the
			// rest are forward defence, since nothing in the tree puts untrusted
			// data there today and this is what would notice if something did.
			//
			// These are distinct as positions, but mostly not as code paths:
			// message, plain key, plain value and group value all funnel into
			// handleState.appendString. Three reach a separately-written
			// escaper, and those are the ones earning their lines:
			//
			//   - a key inside a group, and a group name, both reach
			//     handleState.appendTwoStrings *under the text handler only* --
			//     JSON never populates the key prefix, so there they collapse
			//     back into appendString with the rest. The group name is the
			//     sharper of the two: text-mode openGroup writes it into the
			//     key prefix entirely unescaped, leaving appendTwoStrings the
			//     only thing standing between it and the output.
			//   - a []string element takes the JSON handler through
			//     encoding/json rather than appendEscapedJSONString.
			//   - a []byte value takes the text handler through strconv.Quote
			//     directly, bypassing appendString and needsQuoting, and the
			//     JSON handler through base64. Nothing logs a []byte today;
			//     it is here because this is a CA and DER is a plausible thing
			//     for someone to reach for.
			Entry("in the message", func() { slog.Warn("boundary " + forged) }, textTail),
			Entry("in an attribute value", func() { slog.Warn("boundary", "subject", forged) }, textTail),
			Entry("in an attribute key", func() { slog.Warn("boundary", forged, "v") }, textTail),
			Entry("in a value inside a group", func() {
				slog.Warn("boundary", slog.Group("g", "subject", forged))
			}, textTail),
			Entry("in a key inside a group", func() {
				slog.Warn("boundary", slog.Group("g", forged, "v"))
			}, textTail),
			Entry("in a group name", func() {
				slog.Warn("boundary", slog.Group(forged, "k", "v"))
			}, textTail),
			Entry("in a []string element", func() {
				slog.Warn("boundary", "subjects", []string{forged})
			}, textTail),
			Entry("in a []byte value", func() {
				slog.Warn("boundary", "der", []byte(forged))
			}, jsonTailForBytes),
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
