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
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// autosignFixture writes an autosign executable with exactly mode into its
// own directory, also with exactly mode dirMode, and returns its path.
func autosignFixture(mode, dirMode os.FileMode) string {
	GinkgoHelper()
	dir := filepath.Join(GinkgoT().TempDir(), "plugins")
	Expect(os.Mkdir(dir, 0o700)).To(Succeed())
	Expect(os.Chmod(dir, dirMode)).To(Succeed())
	DeferCleanup(os.Chmod, dir, os.FileMode(0o700))
	exe := filepath.Join(dir, "autosign.sh")
	Expect(os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o700)).To(Succeed())
	Expect(os.Chmod(exe, mode)).To(Succeed())
	return exe
}

var _ = Describe("autosignConfigFrom", func() {
	DescribeTable("derives the mode from the file, not from the setting",
		func(perm os.FileMode, want string) {
			path := filepath.Join(GinkgoT().TempDir(), "autosign")
			Expect(os.WriteFile(path, []byte("*.example.com\n"), 0o600)).To(Succeed())
			Expect(os.Chmod(path, perm)).To(Succeed())

			asCfg, err := autosignConfigFrom(&serverConfig{AutosignConfig: path})
			Expect(err).NotTo(HaveOccurred())
			Expect(asCfg.Mode).To(Equal(want))
			Expect(asCfg.FileOrPath).To(Equal(path))
		},
		Entry("no execute bit is an allowlist", os.FileMode(0o644), "file"),
		Entry("any execute bit is an executable", os.FileMode(0o744), "executable"),
	)

	It("carries the opt-out through to the CA", func() {
		asCfg, err := autosignConfigFrom(&serverConfig{AutosignConfig: "true", InsecureAllowUnsafeAutosignPath: true})
		Expect(err).NotTo(HaveOccurred())
		Expect(asCfg.AllowUnsafePath).To(BeTrue())
	})

	It("refuses a path that does not exist", func() {
		_, err := autosignConfigFrom(&serverConfig{AutosignConfig: "/nonexistent/path/autosign.sh"})
		Expect(err).To(MatchError(ContainSubstring("autosign config invalid")))
	})
})

var _ = Describe("checkAutosignExecutable", func() {
	executable := func(path string, allowUnsafe bool) ca.AutosignConfig {
		return ca.AutosignConfig{Mode: "executable", FileOrPath: path, AllowUnsafePath: allowUnsafe}
	}

	It("accepts an executable only this user can change", func() {
		exe := autosignFixture(0o755, 0o755)

		resolved, findings, err := checkAutosignExecutable(executable(exe, false))
		Expect(err).NotTo(HaveOccurred())
		Expect(findings).To(BeEmpty())
		want, err := filepath.EvalSymlinks(exe)
		Expect(err).NotTo(HaveOccurred())
		Expect(resolved).To(Equal(want))
	})

	It("accepts a symlink to such an executable", func() {
		exe := autosignFixture(0o755, 0o755)
		link := filepath.Join(filepath.Dir(exe), "autosign-link.sh")
		Expect(os.Symlink(exe, link)).To(Succeed())

		_, findings, err := checkAutosignExecutable(executable(link, false))
		Expect(err).NotTo(HaveOccurred())
		Expect(findings).To(BeEmpty())
	})

	DescribeTable("refuses to start on an executable someone else could replace",
		func(mode, dirMode os.FileMode, reason string) {
			exe := autosignFixture(mode, dirMode)

			_, _, err := checkAutosignExecutable(executable(exe, false))
			Expect(err).To(MatchError(ContainSubstring(reason)))
			Expect(err).To(MatchError(ContainSubstring("refusing to start")))
			Expect(err).To(MatchError(ContainSubstring("insecure_allow_unsafe_autosign_path")),
				"the refusal names the way out")
		},
		Entry("a world-writable file", os.FileMode(0o757), os.FileMode(0o755), "world-writable"),
		// Tolerated before #438, and deliberately not now: unlike key
		// material, this is code the CA runs.
		Entry("a group-writable file", os.FileMode(0o775), os.FileMode(0o755), "group-writable"),
		Entry("a group-writable directory", os.FileMode(0o755), os.FileMode(0o775), "group-writable"),
		Entry("a world-writable directory", os.FileMode(0o755), os.FileMode(0o757), "world-writable"),
	)

	It("hands the findings back instead of refusing when the operator has opted out", func() {
		exe := autosignFixture(0o775, 0o755)

		_, findings, err := checkAutosignExecutable(executable(exe, true))
		Expect(err).NotTo(HaveOccurred())
		Expect(findings).To(ConsistOf(HaveField("Reason", "group-writable")))
	})

	It("refuses a path that does not lead to a file, opt-out or not", func() {
		_, _, err := checkAutosignExecutable(executable("/nonexistent/path/autosign.sh", true))
		Expect(err).To(MatchError(os.ErrNotExist))
	})

	It("checks nothing for an allowlist", func() {
		_, _, err := checkAutosignExecutable(ca.AutosignConfig{Mode: "file", FileOrPath: "/nonexistent"})
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("logAutosignExecutable", func() {
	var buf bytes.Buffer

	BeforeEach(func() {
		buf.Reset()
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		DeferCleanup(slog.SetDefault, orig)
	})

	It("logs the file it will run, with its SHA-256", func() {
		exe := autosignFixture(0o755, 0o755)
		logAutosignExecutable(exe, exe, nil)
		// sha256("#!/bin/sh\nexit 0\n")
		Expect(buf.String()).To(ContainSubstring("sha256=306c6ca7407560340797866e077e053627ad409277d1b9da58106fce4cf717cb"))
		Expect(buf.String()).NotTo(ContainSubstring("INSECURE"))
	})

	It("warns about each finding the opt-out let through", func() {
		exe := autosignFixture(0o775, 0o777)
		_, findings, err := checkAutosignExecutable(ca.AutosignConfig{Mode: "executable", FileOrPath: exe, AllowUnsafePath: true})
		Expect(err).NotTo(HaveOccurred())
		Expect(findings).To(HaveLen(2))

		logAutosignExecutable(exe, exe, findings)
		Expect(buf.String()).To(ContainSubstring("level=WARN msg=\"INSECURE: insecure_allow_unsafe_autosign_path is set"))
		// Each WARN names its own entry, by its real path, followed by its
		// mode -- which the INFO record about the executable never does.
		realDir, err := filepath.EvalSymlinks(filepath.Dir(exe))
		Expect(err).NotTo(HaveOccurred())
		Expect(buf.String()).To(ContainSubstring("path=" + realDir + " mode=drwxrwxrwx problem=\"group- and world-writable\""))
		Expect(buf.String()).To(ContainSubstring("path=" + filepath.Join(realDir, "autosign.sh") + " mode=-rwxrwxr-x problem=group-writable"))
	})

	// The hash is logged, not enforced, so a file that cannot be read for it
	// costs the hash and nothing else; the check before each run still
	// decides whether it runs.
	It("says why there is no hash when the file cannot be read", func() {
		exe := autosignFixture(0o755, 0o755)
		logAutosignExecutable(exe, exe+".missing", nil)
		Expect(buf.String()).To(ContainSubstring("sha256_error="))
		Expect(buf.String()).NotTo(ContainSubstring("sha256="))
	})
})

var _ = Describe("autosignInsecureNotice", func() {
	It("has nothing to say when the opt-out let nothing through", func() {
		Expect(autosignInsecureNotice(nil)).To(BeEmpty())
	})

	It("names each finding, quoted", func() {
		notice := autosignInsecureNotice([]ca.AutosignPathFinding{
			{Path: "/srv/plug\nINFO forged", Mode: os.ModeDir | 0o775, Reason: "group-writable"},
		})
		Expect(notice).To(HavePrefix("INSECURE: insecure_allow_unsafe_autosign_path is set"))
		Expect(notice).To(ContainSubstring(`"/srv/plug\nINFO forged" (drwxrwxr-x) is group-writable`))
		Expect(notice).NotTo(ContainSubstring("\n"))
	})
})

// The refusal has to be raised before the --daemon fork: past it the child's
// stderr is /dev/null, so the operator would be told the CA started in the
// background and watch it never serve. The fork is stubbed, and fails, for the
// reasons keypassphrase_test.go's stubFork gives.
var _ = Describe("the autosign executable preflight under --daemon", func() {
	var forked bool

	// These drive whole commands, so pin the environment and the config file
	// the way keyperms_test.go's startup specs do, for the reasons given
	// there: none of them passes --config, and an ambient PUPPET_CA_* or a
	// host /etc/puppet-ca/config.yaml would change what they assert.
	BeforeEach(func() {
		clearServerEnv()
		empty := filepath.Join(GinkgoT().TempDir(), "empty-config.yaml")
		Expect(os.WriteFile(empty, []byte("{}\n"), 0o600)).To(Succeed(), "pin an empty config")
		GinkgoT().Setenv("PUPPET_CA_CONFIG", empty)
	})

	BeforeEach(func() {
		forked = false
		orig := startDaemonChild
		startDaemonChild = func(*exec.Cmd) error { forked = true; return errStubbedFork }
		DeferCleanup(func() { startDaemonChild = orig })
	})

	run := func(extra ...string) (string, string, error) {
		cmd := newRootCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(append([]string{
			"--cadir", GinkgoT().TempDir(), "--host", "127.0.0.1", "--port", "0", "--daemon",
		}, extra...))
		err := cmd.Execute()
		return out.String(), errOut.String(), err
	}

	It("refuses before forking", func() {
		exe := autosignFixture(0o775, 0o755)

		out, _, err := run("--autosign-config", exe)
		Expect(err).To(MatchError(ContainSubstring("refusing to start: autosign executable")))
		Expect(forked).To(BeFalse(), "the refusal has to come before the fork")
		Expect(out).NotTo(ContainSubstring("started in background"))
	})

	// autosign_config naming nothing was refused only past the fork too, and
	// the preflight derives the mode through the same function the server
	// does, so it refuses that as well.
	It("refuses an autosign_config that names nothing, before forking", func() {
		out, _, err := run("--autosign-config", filepath.Join(GinkgoT().TempDir(), "missing"))
		Expect(err).To(MatchError(ContainSubstring("autosign config invalid")))
		Expect(forked).To(BeFalse(), "the refusal has to come before the fork")
		Expect(out).NotTo(ContainSubstring("started in background"))
	})

	It("tells the terminal what the opt-out let through, and forks", func() {
		exe := autosignFixture(0o775, 0o755)

		_, errOut, err := run("--autosign-config", exe, "--insecure-allow-unsafe-autosign-path")
		Expect(err).To(MatchError(errStubbedFork), "the opt-out let it through to the fork")
		Expect(forked).To(BeTrue())
		real, evalErr := filepath.EvalSymlinks(exe)
		Expect(evalErr).NotTo(HaveOccurred())
		// Literal text, not the renderer's output: a renderer that returned ""
		// would otherwise pass as ContainSubstring("").
		Expect(errOut).To(ContainSubstring("INSECURE: insecure_allow_unsafe_autosign_path is set"))
		Expect(errOut).To(ContainSubstring(strconv.Quote(real) + " (-rwxrwxr-x) is group-writable"))
	})

	It("forks without a word for an executable nobody else can change", func() {
		exe := autosignFixture(0o755, 0o755)

		_, errOut, err := run("--autosign-config", exe)
		Expect(err).To(MatchError(errStubbedFork))
		Expect(forked).To(BeTrue())
		Expect(errOut).NotTo(ContainSubstring("INSECURE"))
	})
})

// Without --daemon the server process checks for itself before it serves.
// --single-process keeps the spec in this process: the launcher would fork
// the test binary. The spec context bounds it, because without the check the
// server would start serving and never return.
var _ = Describe("the autosign executable check at startup", func() {
	// These drive whole commands, so pin the environment and the config file
	// the way keyperms_test.go's startup specs do, for the reasons given
	// there: none of them passes --config, and an ambient PUPPET_CA_* or a
	// host /etc/puppet-ca/config.yaml would change what they assert.
	BeforeEach(func() {
		clearServerEnv()
		empty := filepath.Join(GinkgoT().TempDir(), "empty-config.yaml")
		Expect(os.WriteFile(empty, []byte("{}\n"), 0o600)).To(Succeed(), "pin an empty config")
		GinkgoT().Setenv("PUPPET_CA_CONFIG", empty)
	})

	It("refuses to serve", func(ctx SpecContext) {
		exe := autosignFixture(0o775, 0o755)

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{
			"--cadir", GinkgoT().TempDir(), "--host", "127.0.0.1", "--port", "0", "--single-process",
			"--autosign-config", exe,
		})
		Expect(cmd.ExecuteContext(ctx)).To(MatchError(ContainSubstring("refusing to start: autosign executable")))
	}, SpecTimeout(30*time.Second))

	// Under a service manager there is no --daemon notice, so the startup log
	// is the only place the opt-out's findings are reported. Driven through
	// the command, so dropping the call fails here and not only in the
	// function's own spec. The server is stopped once the record is seen.
	It("logs what the opt-out let through, and the executable it will run", func(ctx SpecContext) {
		exe := autosignFixture(0o775, 0o755)
		logfile := filepath.Join(GinkgoT().TempDir(), "ca.log")

		// --logfile makes the server point the process-wide slog default at
		// that file, and nothing puts it back. Registered first so that it
		// runs last, after the server has stopped.
		DeferCleanup(slog.SetDefault, slog.Default())

		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			cmd := newRootCmd()
			cmd.SetOut(GinkgoWriter)
			cmd.SetErr(GinkgoWriter)
			cmd.SetArgs([]string{
				"--cadir", GinkgoT().TempDir(), "--host", "127.0.0.1", "--port", "0", "--single-process",
				"--logfile", logfile, "--autosign-config", exe, "--insecure-allow-unsafe-autosign-path",
			})
			done <- cmd.ExecuteContext(runCtx)
		}()
		DeferCleanup(func() {
			cancel()
			Eventually(done).WithTimeout(20 * time.Second).Should(Receive())
		})

		readLog := func() string {
			data, _ := os.ReadFile(logfile)
			return string(data)
		}
		Eventually(readLog).WithContext(ctx).Should(SatisfyAll(
			ContainSubstring("INSECURE: insecure_allow_unsafe_autosign_path is set"),
			ContainSubstring("group-writable"),
			ContainSubstring("Autosign executable configured"),
		))
	}, SpecTimeout(60*time.Second))
})
