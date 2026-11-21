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

//go:build unix

package ca_test

import (
	"bytes"
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// What the autosign executable leaves behind once a run is over (#660): the
// timeout takes everything the executable started with it, and nothing the
// executable started can hold the run open past the timeout plus the wait
// delay. Unix-only because the scripts are shell scripts, and the process
// group behind the first property exists only there.
var _ = Describe("Autosign executable descendants", func() {
	var (
		tmpDir string
		csrPEM []byte
		csr    *x509.CertificateRequest
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-autosign-exec-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(os.RemoveAll, tmpDir)
		csrPEM, csr = buildCSR("test-node.example.com")
	})

	writeScript := func(content string) string {
		path := filepath.Join(tmpDir, "autosign.sh")
		Expect(os.WriteFile(path, []byte(content), 0o755)).To(Succeed())
		return path
	}

	// killRecorded kills the process whose pid the script wrote to pidFile,
	// so a sleeping descendant the CA did not kill does not outlive the spec.
	killRecorded := func(pidFile string) {
		data, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}

	It("kills what the executable started when the timeout fires", func() {
		// The subshell is the descendant: it outlives a kill of the script
		// alone, and proves it did by creating the marker two seconds later.
		// The pid file is written once the subshell exists, so the spec can
		// tell a descendant that was killed from one that never started.
		marker := filepath.Join(tmpDir, "descendant-survived")
		pidFile := filepath.Join(tmpDir, "descendant.pid")
		script := writeScript("#!/bin/sh\n(sleep 2; touch '" + marker + "') &\necho $! > '" + pidFile + "'\nsleep 30\n")
		DeferCleanup(killRecorded, pidFile)

		_, err := ca.CheckAutosign(ca.AutosignConfig{
			Mode:              "executable",
			FileOrPath:        script,
			ExecutableTimeout: 500 * time.Millisecond,
		}, csr, csrPEM)
		Expect(err).To(MatchError(ContainSubstring("timed out")))
		// Without this the absence below proves nothing: a script killed
		// before it reached the & started no descendant, and leaves no marker
		// whether or not the group was killed.
		Expect(pidFile).To(BeAnExistingFile(),
			"the timeout fired before the script started its descendant, so this run tests nothing")

		// Consistently, because the property is an absence: the marker is due
		// two seconds after the script started, so four seconds of nothing is
		// the descendant being gone rather than merely slow.
		Consistently(func() bool {
			_, err := os.Stat(marker)
			return os.IsNotExist(err)
		}, 4*time.Second, 100*time.Millisecond).Should(BeTrue(),
			"a process the autosign executable started outlived the timeout")
	})

	It("leaves what the executable started alone when it exits by itself", func() {
		// The other half of the rule: only the timeout kills the group. A
		// script may put a helper in the background on purpose, and a run that
		// finishes on its own must not take it down.
		marker := filepath.Join(tmpDir, "helper-ran")
		script := writeScript("#!/bin/sh\n(sleep 1; touch '" + marker + "') &\nexit 0\n")

		ok, err := ca.CheckAutosign(ca.AutosignConfig{
			Mode:              "executable",
			FileOrPath:        script,
			ExecutableTimeout: 10 * time.Second,
		}, csr, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())

		Eventually(func() error {
			_, err := os.Stat(marker)
			return err
		}, 10*time.Second, 100*time.Millisecond).Should(Succeed(),
			"a helper the autosign executable put in the background was killed after a normal exit")
	})

	// captureWarnings routes WARN and above into a buffer for the rest of the
	// spec, so a spec can assert on what the run logged.
	captureWarnings := func() *bytes.Buffer {
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(slog.SetDefault, orig)
		return &buf
	}

	type outcome struct {
		ok  bool
		err error
	}

	// checkWithin runs CheckAutosign with a request far larger than a pipe
	// buffer, so a descendant that holds stdin without reading it keeps the
	// copy into it blocked. It fails the spec, with why, if the run takes
	// longer than bound: on its own goroutine, because the failure being
	// guarded against is a run that does not return at all.
	checkWithin := func(bound time.Duration, script string, timeout time.Duration, why string) outcome {
		GinkgoHelper()
		large := append(bytes.Repeat([]byte("#"), 1<<20), csrPEM...)
		done := make(chan outcome, 1)
		go func() {
			defer GinkgoRecover()
			ok, err := ca.CheckAutosign(ca.AutosignConfig{
				Mode:              "executable",
				FileOrPath:        script,
				ExecutableTimeout: timeout,
			}, csr, large)
			done <- outcome{ok, err}
		}()
		var got outcome
		Eventually(done, bound).Should(Receive(&got), why)
		return got
	}

	// The descendant inherits stdin and never reads it, so without a wait
	// delay the run lasts as long as the descendant does. Through fd 3,
	// because dash gives a background job /dev/null before applying its
	// redirections, so `<&0` there would hand it /dev/null.
	//
	// Both exits matter. The wait delay running out is turned into an
	// approval, which is right only because os/exec reports it for a
	// successful exit alone; a refusal that a descendant held open must stay
	// a refusal.
	DescribeTable("when it exits by itself while a descendant holds its stdin",
		func(exit string, signed bool) {
			pidFile := filepath.Join(tmpDir, "holder.pid")
			script := writeScript("#!/bin/sh\nexec 3<&0\nsleep 30 <&3 &\necho $! > '" + pidFile + "'\n" + exit + "\n")
			DeferCleanup(killRecorded, pidFile)
			logBuf := captureWarnings()

			// The bound is well inside the descendant's 30 seconds and the
			// 20-second timeout, so neither of those can be what ends the run.
			got := checkWithin(10*time.Second, script, 20*time.Second,
				"a descendant holding stdin kept the autosign run open")
			Expect(pidFile).To(BeAnExistingFile())
			Expect(got.err).NotTo(HaveOccurred())
			Expect(got.ok).To(Equal(signed))
			if signed {
				Expect(logBuf.String()).To(ContainSubstring("left a process holding its stdin"))
			} else {
				Expect(logBuf.String()).NotTo(ContainSubstring("left a process holding its stdin"))
			}
		},
		Entry("signs within the wait delay on exit zero", "exit 0", true),
		Entry("refuses within the wait delay on a non-zero exit", "exit 1", false),
	)

	It("still times out within the wait delay when an escaped descendant holds its stdin", func() {
		// The group kill cannot reach a descendant that has left the group,
		// so the wait delay is all that bounds this run. set -m puts every
		// job in a group of its own -- bash, because dash refuses job control
		// without a terminal -- so the script execs its last command, which
		// keeps that one in the executable's group for the kill to reach.
		// A timed-out run is refused, never signed, whatever happens to its
		// stdin afterwards.
		pidFile := filepath.Join(tmpDir, "escaped.pid")
		script := writeScript("#!/bin/bash\nset -m\nexec 3<&0\nsleep 30 <&3 &\necho $! > '" + pidFile + "'\nexec sleep 30\n")
		DeferCleanup(killRecorded, pidFile)
		logBuf := captureWarnings()

		got := checkWithin(10*time.Second, script, 500*time.Millisecond,
			"a descendant outside the process group kept a timed-out run open")
		Expect(pidFile).To(BeAnExistingFile(),
			"the timeout fired before the script started its descendant, so this run tests nothing")
		Expect(got.err).To(MatchError(ContainSubstring("timed out")))
		Expect(got.ok).To(BeFalse())
		Expect(logBuf.String()).NotTo(ContainSubstring("left a process holding its stdin"))

		// The holder outlived the group kill, which is what makes the wait
		// delay the only bound here. Were job control to leave it in the
		// group, the kill would close the pipe and the run would end without
		// the delay ever mattering.
		data, err := os.ReadFile(pidFile)
		Expect(err).NotTo(HaveOccurred())
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		Expect(err).NotTo(HaveOccurred())
		Expect(syscall.Kill(pid, 0)).To(Succeed(),
			"the descendant did not leave the process group, so this run does not test the wait delay")
	})
})
