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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The startup decision on key-material permissions, and the reporting that
// follows it. World access is refused, because a CA private key every local
// account can read is one to treat as exposed. Group access never refuses: it is
// the mode the store is created with, so a correct deployment has it. A path
// whose permissions could not be read refuses on its own terms, since "chmod
// o-rwx" would be a remedy for a condition nobody established.
//
// The two halves are separate functions because they run at different points:
// the refusal happens in the parent before any logger exists, and the reporting
// once one does, so that it reaches a configured logfile.
var _ = Describe("key-material permissions at startup", func() {
	// captureAt installs a handler at the given level and returns what was
	// written, the idiom this package already uses for log assertions.
	captureAt := func(level slog.Level) *bytes.Buffer {
		GinkgoHelper()
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
		DeferCleanup(func() { slog.SetDefault(orig) })
		return &buf
	}
	captureWarnings := func() *bytes.Buffer { GinkgoHelper(); return captureAt(slog.LevelWarn) }
	captureAll := func() *bytes.Buffer { GinkgoHelper(); return captureAt(slog.LevelInfo) }

	// Distinct paths, and the realistic pairing: SQLite keeps the key across a
	// database and its sidecars, each with its own mode. Sharing one path between
	// the fixtures would make it impossible for any assertion here to catch the
	// refusal naming the wrong file.
	worldReadable := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca.db-wal", Mode: os.FileMode(0o644)}
	// Deliberately not a prefix of the world-accessible path: "ca.db" is a
	// substring of "ca.db-wal", so a NotTo(ContainSubstring) over the pair could
	// never pass and the spec below would be unfailable in the wrong direction.
	groupReadable := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/private/ca_key.pem", Mode: os.FileMode(0o640)}

	It("starts with nothing to report", func() {
		buf := captureAll()

		Expect(refuseOnKeyPermissions(nil, false)).To(Succeed(), "no findings")
		logKeyPermissions(nil, false)
		Expect(buf.String()).To(BeEmpty(), "nothing logged")
	})

	It("refuses to start on world-accessible key material", func() {
		err := refuseOnKeyPermissions([]storage.KeyPermWarning{worldReadable}, false)

		Expect(err).To(HaveOccurred(), "world-accessible key material")
		Expect(err.Error()).To(ContainSubstring("refusing to start"), "the refusal")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Path), "the file at fault")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Mode.String()), "the mode that made it a finding")
		Expect(err.Error()).To(ContainSubstring("chmod o-rwx"), "the remedy")
		Expect(err.Error()).To(ContainSubstring("rotated"), "what to do about a key that was exposed")
	})

	// Group access must not be a refusal. Under the chart's default fsGroup the
	// kubelet ORs group access back into the volume at every mount, so refusing
	// would stop the CA starting on the project's own recommended deployment.
	It("starts when key material is only group-accessible", func() {
		buf := captureWarnings()

		Expect(refuseOnKeyPermissions([]storage.KeyPermWarning{groupReadable}, false)).To(Succeed(),
			"group access must not stop the CA starting")
		Expect(buf.String()).To(BeEmpty(), "group access is not a warning-level condition")
	})

	// The group report itself, at Info. Asserted against a handler that admits
	// Info: a Warn-level buffer is empty on this path by construction, so a
	// NotTo(ContainSubstring) over it could never fail and the report could be
	// deleted with nothing noticing.
	It("reports group access once, at Info, naming the files", func() {
		buf := captureAll()

		logKeyPermissions([]storage.KeyPermWarning{groupReadable}, false)

		Expect(buf.String()).To(ContainSubstring("accessible to its group"), "the report")
		Expect(buf.String()).To(ContainSubstring(groupReadable.Path), "the file named")
		Expect(buf.String()).To(ContainSubstring(groupReadable.Mode.String()), "the mode")
		Expect(buf.String()).To(ContainSubstring("level=INFO"), "at Info, not Warn")
	})

	// The opt-out downgrades the refusal, and shouts. An operator who reaches for
	// it should be in no doubt what they have turned off.
	It("starts on world-accessible key material when told to, shouting about it", func() {
		buf := captureWarnings()

		Expect(refuseOnKeyPermissions([]storage.KeyPermWarning{worldReadable}, true)).To(Succeed(),
			"the opt-out downgrades the refusal")

		logKeyPermissions([]storage.KeyPermWarning{worldReadable}, true)
		Expect(buf.String()).To(ContainSubstring("INSECURE"), "the shouting")
		Expect(buf.String()).To(ContainSubstring("EVERY LOCAL ACCOUNT CAN READ THESE FILES"), "the shouting")
		Expect(buf.String()).To(ContainSubstring("ROTATE IT"), "what the operator must now do")
		Expect(buf.String()).To(ContainSubstring(worldReadable.Path), "the file named")
	})

	// 0700 grants nobody anything, and is a finding only because
	// CheckKeyPermissions reports everything wider than 0600. Classifying the
	// group arm by elimination announced it as "accessible to its group" with
	// "(mode -rwx------)" in the same string, which the mode itself contradicts.
	It("does not call an owner-only mode group access", func() {
		buf := captureAll()
		ownerOnly := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/private/ca_key.pem", Mode: os.FileMode(0o700)}

		logKeyPermissions([]storage.KeyPermWarning{ownerOnly}, false)

		Expect(buf.String()).NotTo(ContainSubstring("accessible to its group"), "it is not")
		Expect(buf.String()).To(ContainSubstring("grants no group or world access"), "what it is")
		Expect(buf.String()).To(ContainSubstring(ownerOnly.Path), "the file named")
	})

	// The record must not name a cause that holds on one backend only. Group
	// access is created by openvox-ca on SQLite and ORed in by a Kubernetes
	// fsGroup; on the default filesystem backend everything under private/ is
	// written 0600, so group access there is the deployment's doing, and telling
	// the operator it "is the default" told them their CA had done it.
	It("does not blame the CA for group access it did not create", func() {
		buf := captureAll()

		logKeyPermissions([]storage.KeyPermWarning{groupReadable}, false)

		Expect(buf.String()).To(ContainSubstring("accessible to its group"), "the report")
		Expect(buf.String()).NotTo(ContainSubstring("which is the default"), "not on every backend")
		Expect(buf.String()).To(ContainSubstring("came from the deployment"),
			"where filesystem-backend group access comes from")
	})

	// The Info record repeats on every start, and the finding set is not bounded
	// by the backend: under a Kubernetes fsGroup every retained per-subject key
	// is a finding. Unbounded, a CA with a few thousand subjects emits a
	// several-hundred-kilobyte line each start, which a field-capping pipeline
	// truncates -- discarding the tail of the enumeration the record is for.
	It("bounds the steady-state record rather than naming thousands of files", func() {
		buf := captureAll()
		many := make([]storage.KeyPermWarning, 0, 25)
		for i := range 25 {
			many = append(many, storage.KeyPermWarning{
				Path: fmt.Sprintf("/var/lib/puppet-ca/private/node-%02d_key.pem", i),
				Mode: os.FileMode(0o640),
			})
		}

		logKeyPermissions(many, false)

		Expect(buf.String()).To(ContainSubstring("node-00_key.pem"), "the first")
		Expect(buf.String()).To(ContainSubstring("and 15 more"), "and a count for the rest")
		Expect(buf.String()).NotTo(ContainSubstring("node-24_key.pem"), "not all of them")
		Expect(buf.String()).To(ContainSubstring("count=25"), "the total is still reported")
	})

	// The refusal is deliberately not capped: it happens once, and a remedy
	// missing half its paths leaves the CA refusing after the restart.
	It("does not cap the refusal, which the operator has to act on", func() {
		many := make([]storage.KeyPermWarning, 0, 25)
		for i := range 25 {
			many = append(many, storage.KeyPermWarning{
				Path: fmt.Sprintf("/var/lib/puppet-ca/private/node-%02d_key.pem", i),
				Mode: os.FileMode(0o644),
			})
		}

		err := refuseOnKeyPermissions(many, false)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("node-24_key.pem"), "every path, so one chmod clears it")
		Expect(err.Error()).NotTo(ContainSubstring("more"), "nothing elided")
	})

	// Under --daemon the child's stderr is /dev/null and the parent returns
	// before any logger exists, so with no log_file configured the opt-out's
	// warning had nowhere to go: the operator was told the CA started and never
	// that its key is readable by every local account.
	Describe("the opt-out's notice for the terminal", func() {
		It("renders the shouting and the remedy", func() {
			notice := keyPermInsecureNotice([]storage.KeyPermWarning{worldReadable}, true)

			Expect(notice).To(ContainSubstring("INSECURE"), "the shouting")
			Expect(notice).To(ContainSubstring("ROTATE IT"), "what to do")
			Expect(notice).To(ContainSubstring(worldReadable.Path), "the file")
			Expect(notice).To(ContainSubstring("chmod o-rwx -- "), "the remedy")
		})

		It("says nothing without the opt-out, since the refusal already stopped startup", func() {
			Expect(keyPermInsecureNotice([]storage.KeyPermWarning{worldReadable}, false)).To(BeEmpty())
		})

		It("says nothing when only group access was found", func() {
			Expect(keyPermInsecureNotice([]storage.KeyPermWarning{groupReadable}, true)).To(BeEmpty())
		})

		// An unjudgeable path is refused before this is reached and is not a
		// world-access finding; including it would put a mode nobody established
		// and a chmod that clears nothing into the shouting.
		It("says nothing for an unjudgeable path", func() {
			unjudgeable := storage.KeyPermWarning{
				Path:       "/var/lib/puppet-ca/private",
				Unreadable: true,
				Err:        errors.New("permission denied"),
			}
			Expect(keyPermInsecureNotice([]storage.KeyPermWarning{unjudgeable}, true)).To(BeEmpty())
		})
	})

	// The cap boundary, which is where an off-by-one lives: at exactly the limit
	// nothing is elided, one past it the tail is summarised.
	DescribeTable("the steady-state record caps at ten",
		func(n int, elided bool) {
			buf := captureAll()
			many := make([]storage.KeyPermWarning, 0, n)
			for i := range n {
				many = append(many, storage.KeyPermWarning{
					Path: fmt.Sprintf("/var/lib/puppet-ca/private/node-%02d_key.pem", i),
					Mode: os.FileMode(0o640),
				})
			}

			logKeyPermissions(many, false)

			last := fmt.Sprintf("node-%02d_key.pem", n-1)
			if elided {
				Expect(buf.String()).NotTo(ContainSubstring(last), "the tail is summarised")
				Expect(buf.String()).To(ContainSubstring("more"), "and counted")
			} else {
				Expect(buf.String()).To(ContainSubstring(last), "every path fits")
				Expect(buf.String()).NotTo(ContainSubstring("more"), "so nothing is elided")
			}
		},
		Entry("exactly the limit", 10, false),
		Entry("one past the limit", 11, true),
	)

	// The opt-out warns about every world-accessible file, not just the first.
	// Only the refusal path had a multi-finding spec, so the loop that is supposed
	// to iterate was never proven to get past element one.
	It("shouts about every world-accessible file, not just the first", func() {
		buf := captureWarnings()
		second := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca.db-shm", Mode: os.FileMode(0o644)}

		logKeyPermissions([]storage.KeyPermWarning{worldReadable, second}, true)

		Expect(buf.String()).To(ContainSubstring(worldReadable.Path), "the first file")
		Expect(buf.String()).To(ContainSubstring(second.Path), "the second file")
	})

	// The percent-decoding this change adds makes a space-containing database
	// name reachable, so the remedy has to survive one. Unquoted, "chmod o-rwx
	// /var/lib/ca b.db" is a command against two files that do not exist.
	It("quotes a path with a space so the suggested chmod is runnable", func() {
		spaced := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca b.db", Mode: os.FileMode(0o644)}

		err := refuseOnKeyPermissions([]storage.KeyPermWarning{spaced}, false)

		Expect(err).To(HaveOccurred(), "world-accessible key material")
		Expect(err.Error()).To(ContainSubstring(`chmod o-rwx -- '/var/lib/puppet-ca/ca b.db'`),
			"the remedy must be one shell word")
	})

	// The embedded-quote escape, which is the only part of shellQuote that can be
	// wrong: the wrap is obvious, and a wrong escape is worse than no quoting at
	// all, because an unterminated quoted string leaves the operator's shell at a
	// continuation prompt rather than erroring. Reachable by the same route a
	// space is -- the DSN parser decodes escapes, so file:ca%27b.db is ca'b.db.
	It("escapes an embedded single quote rather than ending the quoted string", func() {
		quoted := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca'b.db", Mode: os.FileMode(0o644)}

		err := refuseOnKeyPermissions([]storage.KeyPermWarning{quoted}, false)

		Expect(err).To(HaveOccurred(), "world-accessible key material")
		Expect(err.Error()).To(ContainSubstring(`chmod o-rwx -- '/var/lib/puppet-ca/ca'\''b.db'`),
			"close the quote, escape the quote, reopen it")
	})

	// And an ordinary path is left alone, so the common case does not grow quotes
	// it does not need. The "--" is there whatever the path, since a path may also
	// begin with a dash and quoting does not stop chmod reading it as options.
	It("does not quote a path that needs no quoting", func() {
		err := refuseOnKeyPermissions([]storage.KeyPermWarning{worldReadable}, false)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("chmod o-rwx -- "+worldReadable.Path), "unquoted")
	})

	// A path beginning with a dash is what the "--" is for: shell-quoting makes it
	// one word, and chmod still reads that word as options.
	It("ends chmod's options so a path beginning with a dash reaches it", func() {
		dashed := storage.KeyPermWarning{Path: "-ca.db", Mode: os.FileMode(0o644)}

		err := refuseOnKeyPermissions([]storage.KeyPermWarning{dashed}, false)

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("chmod o-rwx -- -ca.db"), "the separator")
	})

	// A path whose permissions could not be read is refused too, and separately:
	// "world-accessible, chmod o-rwx" would be a false statement and a remedy
	// that cannot clear it. The opt-out deliberately does not cover it -- nobody
	// can have weighed a risk whose mode is unknown.
	Describe("a path whose permissions cannot be read", func() {
		unreadable := storage.KeyPermWarning{
			Path:       "/var/lib/puppet-ca/private",
			Unreadable: true,
			Err:        errors.New("permission denied"),
		}

		It("refuses, naming the path and the real error", func() {
			err := refuseOnKeyPermissions([]storage.KeyPermWarning{unreadable}, false)

			Expect(err).To(HaveOccurred(), "an unjudgeable path")
			Expect(err.Error()).To(ContainSubstring("could not be read"), "the real condition")
			Expect(err.Error()).To(ContainSubstring(unreadable.Path), "the path")
			Expect(err.Error()).To(ContainSubstring("permission denied"), "the underlying error")
			Expect(err.Error()).NotTo(ContainSubstring("chmod o-rwx"), "a remedy that could not clear it")
			Expect(err.Error()).NotTo(ContainSubstring("world-accessible"), "a mode nobody established")
		})

		It("refuses even under the opt-out", func() {
			err := refuseOnKeyPermissions([]storage.KeyPermWarning{unreadable}, true)

			Expect(err).To(HaveOccurred(), "the opt-out is about world access, not about not knowing")
		})

		// Every unjudgeable path, for the reason the world-accessible branch
		// names every one of its own: the causes are independent -- a private/
		// directory on one mount, a database directory on another -- so naming
		// the first would have the operator fix it, restart, and be refused by
		// the second.
		It("names every unjudgeable path, not just the first", func() {
			second := storage.KeyPermWarning{
				Path:       "/srv/sqlite/ca.db",
				Unreadable: true,
				Err:        errors.New("no such file or directory"),
			}

			err := refuseOnKeyPermissions([]storage.KeyPermWarning{unreadable, second}, false)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(unreadable.Path), "the first path")
			Expect(err.Error()).To(ContainSubstring("permission denied"), "its error")
			Expect(err.Error()).To(ContainSubstring(second.Path), "the second path")
			Expect(err.Error()).To(ContainSubstring("no such file or directory"), "its error")
		})

		// logKeyPermissions carries the same case. Today nothing reaches it --
		// the refusal above returns first, whatever the opt-out says -- so this
		// pins the intent rather than a live path: if the refusal is ever
		// narrowed, the finding must still be reported rather than dropped.
		It("reports an unjudgeable path if one ever reaches the logger", func() {
			buf := captureWarnings()

			logKeyPermissions([]storage.KeyPermWarning{unreadable}, false)

			Expect(buf.String()).To(ContainSubstring("Could not check the permissions"), "the report")
			Expect(buf.String()).To(ContainSubstring(unreadable.Path), "the path")
			Expect(buf.String()).To(ContainSubstring("permission denied"), "the error")
		})
	})

	// The opt-out is for world access only; it does not silence anything else,
	// and it does not turn a group finding into a scream.
	It("does not scream about group access under the opt-out", func() {
		buf := captureAll()

		Expect(refuseOnKeyPermissions([]storage.KeyPermWarning{groupReadable}, true)).To(Succeed())
		logKeyPermissions([]storage.KeyPermWarning{groupReadable}, true)

		Expect(buf.String()).To(ContainSubstring("accessible to its group"), "still reported")
		Expect(buf.String()).NotTo(ContainSubstring("INSECURE"), "no scream for group access")
	})

	// Several findings, and the refusal has to fire on the world one wherever it
	// sits in the list rather than only when it happens to come first.
	It("refuses when a world-accessible file follows a group-accessible one", func() {
		_ = captureWarnings()

		err := refuseOnKeyPermissions([]storage.KeyPermWarning{groupReadable, worldReadable}, false)

		Expect(err).To(HaveOccurred(), "the world-accessible file is not first")
		Expect(err.Error()).To(ContainSubstring("refusing to start"), "the refusal")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Path), "names the world-accessible file")
		Expect(err.Error()).NotTo(ContainSubstring(groupReadable.Path),
			"does not send the operator to chmod a file that is merely group-accessible")
	})

	// Every world-accessible path, not just the first. SQLite keeps the key in
	// four files whose modes move together, so naming one would have the operator
	// fix it, restart, and be refused again by the next.
	It("names every world-accessible file in one refusal", func() {
		second := storage.KeyPermWarning{Path: "/var/lib/puppet-ca/ca.db-shm", Mode: os.FileMode(0o644)}

		err := refuseOnKeyPermissions([]storage.KeyPermWarning{worldReadable, second}, false)

		Expect(err).To(HaveOccurred(), "two world-accessible files")
		Expect(err.Error()).To(ContainSubstring(worldReadable.Path), "the first")
		Expect(err.Error()).To(ContainSubstring(second.Path), "the second")
	})
})

// The startup path itself, through the command an operator actually runs. The
// specs above drive the decision as a function; these drive the wiring -- that
// it is called at all, that it is called before anything forks or writes a key,
// and that the config field reaches it. Each of those is a mutation the
// function-level specs cannot see.
var _ = Describe("the server's own startup, on key-material permissions", func() {
	// These drive whole commands, so the loader reads PUPPET_CA_* out of the
	// developer's own environment unless it is cleared: PUPPET_CA_ROLE or
	// PUPPET_CA_INSECURE_ALLOW_WORLD_READABLE_KEYS set outside the suite would
	// change what these specs assert without failing them.
	BeforeEach(func() { clearServerEnv() })

	// worldReadableCADir bootstraps a CA and then widens its private key, which
	// is the condition the check exists to refuse.
	worldReadableCADir := func() string {
		GinkgoHelper()
		caDir := GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "puppet.example.com")
		keyPath := filepath.Join(caDir, "private", "ca_key.pem")
		Expect(keyPath).To(BeAnExistingFile(), "the bootstrapped CA key")
		Expect(os.Chmod(keyPath, 0o644)).To(Succeed(), "make it world-readable")
		return caDir
	}

	It("refuses to start, through the command an operator actually runs", func() {
		caDir := worldReadableCADir()

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0"})

		// Bounded, for the same reason the instance-lock spec is: if the check
		// regressed, the next thing this command does is fork the launcher and
		// supervise it for ever. A spec that hangs on regression is worse than
		// one that fails.
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()

		var err error
		Eventually(done, "30s").Should(Receive(&err),
			"the refusal must come before the launcher forks; a hang here means it does not")
		Expect(err).To(MatchError(ContainSubstring("refusing to start")),
			"world-readable key material must be refused at the top level")
		Expect(err).To(MatchError(ContainSubstring("chmod o-rwx -- ")), "the remedy")
	})

	It("refuses under --daemon instead of reporting success", func() {
		// --daemon discards the child's stdout and stderr, so a refusal raised
		// past the fork reaches nobody: the operator is told the CA started, gets
		// exit 0, and the child dies in silence.
		caDir := worldReadableCADir()

		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon"})

		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("refusing to start")))
		// Load-bearing only because main.go writes that line to cmd.OutOrStdout();
		// while it went to os.Stdout through fmt.Printf this buffer was empty
		// under every behaviour and the assertion could not fail.
		Expect(out.String()).NotTo(ContainSubstring("started in background"),
			"reporting a background start for a process that was refused is the failure")
	})

	// The wiring, not the rendering. keyPermInsecureNotice has its own specs
	// above; what had none was the one call site that reaches an operator when
	// no log_file is configured -- the terminal, before the fork. Delete that
	// Fprintln and the suite stayed green while the only warning telling
	// somebody their CA key is world-readable went to a /dev/null stderr.
	//
	// The fork is stubbed rather than allowed: under `go test` the child is this
	// test binary re-executed with the test flags, which re-runs the suite
	// inside itself.
	It("shouts to the terminal before forking under --daemon", func() {
		caDir := worldReadableCADir()

		// The stub refuses rather than succeeding: on success the caller reads
		// c.Process.Pid to report the child, and a stub cannot set that. What
		// this spec is about happens before either.
		var forked bool
		stubErr := errors.New("stubbed fork")
		orig := startDaemonChild
		startDaemonChild = func(*exec.Cmd) error { forked = true; return stubErr }
		DeferCleanup(func() { startDaemonChild = orig })

		cmd := newRootCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs([]string{
			"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon",
			"--insecure-allow-world-readable-keys",
		})

		err := cmd.Execute()

		Expect(err).To(MatchError(ContainSubstring("failed to start daemon")),
			"the opt-out let it through to the fork, which the stub refused")
		Expect(forked).To(BeTrue(), "and it did reach the fork")
		Expect(errOut.String()).To(ContainSubstring("INSECURE"), "the shouting reached the terminal")
		Expect(errOut.String()).To(ContainSubstring("ROTATE IT"), "what to do about it")
		Expect(errOut.String()).To(ContainSubstring("chmod o-rwx -- "), "the remedy")
	})

	// The same path without the opt-out refuses, and must say nothing about
	// having started: the ordering is what makes the refusal visible at all.
	It("says nothing and does not fork when the opt-out is absent", func() {
		caDir := worldReadableCADir()

		var forked bool
		orig := startDaemonChild
		startDaemonChild = func(*exec.Cmd) error { forked = true; return nil }
		DeferCleanup(func() { startDaemonChild = orig })

		cmd := newRootCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon"})

		err := cmd.Execute()

		Expect(err).To(MatchError(ContainSubstring("refusing to start")))
		Expect(forked).To(BeFalse(), "the refusal has to come before the fork")
		Expect(errOut.String()).NotTo(ContainSubstring("INSECURE"),
			"no opt-out means no start, so nothing to shout about")
	})

	// What connects cfg.InsecureAllowWorldReadableKeys to the decision. Driven
	// through preflightKeyPermissions rather than the whole command, because the
	// opt-out's success path starts a server: under --daemon the binary re-execs
	// itself, which in a test is the test binary, and without it the command
	// serves until killed. Neither belongs in a suite. The two specs above
	// already pin that the check runs at all and runs before the fork; this pins
	// that the config field reaches it.
	It("lets the opt-out through to the decision", func() {
		caDir := worldReadableCADir()
		cfg := &serverConfig{CADir: caDir}

		_, err := preflightKeyPermissions(context.Background(), cfg)
		Expect(err).To(MatchError(ContainSubstring("refusing to start")),
			"without the opt-out, world-readable key material is refused")

		cfg.InsecureAllowWorldReadableKeys = true
		warnings, err := preflightKeyPermissions(context.Background(), cfg)
		Expect(err).NotTo(HaveOccurred(), "the opt-out must reach the decision")
		Expect(warnings).NotTo(BeEmpty(), "the findings still come back, to be logged")
	})

	// The other end of the same wiring, and the only thing making an
	// operator-supplied passphrase file subject to the refusal. The callee half
	// is pinned in internal/storage; nothing drove the caller, so dropping
	// cfg.CAKeyPassphraseFile from the call left every spec green while a
	// world-readable file that unlocks the encrypted CA key stopped being judged.
	It("passes ca_key_passphrase_file through to the check", func() {
		caDir := GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "puppet.example.com")

		passPath := filepath.Join(GinkgoT().TempDir(), "key-passphrase")
		Expect(os.WriteFile(passPath, []byte("hunter2\n"), 0o600)).To(Succeed(), "seed the passphrase file")
		Expect(os.Chmod(passPath, 0o644)).To(Succeed(), "world-readable, whatever the umask")

		cfg := &serverConfig{CADir: caDir, CAKeyPassphraseFile: passPath}

		_, err := preflightKeyPermissions(context.Background(), cfg)

		Expect(err).To(MatchError(ContainSubstring("refusing to start")),
			"a world-readable passphrase file unlocks the key, so it is refused like the key")
		Expect(err).To(MatchError(ContainSubstring(passPath)), "and the refusal names it")
	})

	// The check runs for every role, which is published to operators. Folding
	// the call into the `if role == ""` block above -- the natural tidy-up,
	// since the instance lock two blocks earlier is role-gated on purpose --
	// left the suite green while the signer, the process that loads the key,
	// bootstrapped into and served from a world-accessible store.
	DescribeTable("refuses whichever role is started",
		func(role string) {
			caDir := worldReadableCADir()
			GinkgoT().Setenv("PUPPET_CA_ROLE", role)

			cmd := newRootCmd()
			cmd.SetOut(GinkgoWriter)
			cmd.SetErr(GinkgoWriter)
			cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0"})

			done := make(chan error, 1)
			go func() { done <- cmd.Execute() }()

			var err error
			Eventually(done, "30s").Should(Receive(&err),
				"the refusal must come before the role does any work")
			Expect(err).To(MatchError(ContainSubstring("refusing to start")))
		},
		Entry("signer", "signer"),
		Entry("frontend", "frontend"),
	)
})
