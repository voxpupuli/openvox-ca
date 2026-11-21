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

package ca

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// defaultExecutableTimeout is the maximum time allowed for an autosign
// executable to run.  A hung script would otherwise block the CA indefinitely.
const defaultExecutableTimeout = 30 * time.Second

// autosignWaitDelay bounds how long a run goes on waiting for the executable's
// stdin once the executable has exited or been killed. Something it started can
// inherit the pipe and hold it without reading, and the CSR is copied into it
// from a goroutine that Wait would otherwise wait on for as long as that
// descendant lives. A run therefore takes at most the timeout plus this.
const autosignWaitDelay = 2 * time.Second

// autosignConcurrency caps how many autosign executables one CA runs at once.
//
// SaveRequest used to run the policy under c.mu, which serialised every run in
// the process and stalled everything else with it (#664). Running the policy
// outside c.mu removed that cap as well, and the endpoint that starts a run
// needs no authentication: every in-flight CSR for a different certname would
// start an executable of its own, bounded only by the per-address
// csr_rate_limit, and put as many calls at once on whatever the policy
// consults. Eight lets a fleet enrol in parallel against a policy that answers
// within a second or so, while keeping the processes, and the load on an
// inventory service, small. It is a constant until someone needs to tune it.
const autosignConcurrency = 8

// autosignSigningMargin is the time a request keeps back for the signature
// that follows an approval, on top of the policy's longest run. See
// acquireAutosignSlot.
const autosignSigningMargin = 5 * time.Second

type AutosignConfig struct {
	Mode              string        // "true", "file", "executable" (or "off" implicitly)
	FileOrPath        string        // Path to autosign.conf or executable
	ExecutableTimeout time.Duration // 0 → defaultExecutableTimeout
	// AllowUnsafePath runs the executable even when ResolveAutosignExecutable
	// reports entries on its path that a third party could replace. Set from
	// insecure_allow_unsafe_autosign_path; the server warns about each finding
	// at startup instead, and the check before each run lets findings through
	// without logging them -- including ones that appeared after startup.
	AllowUnsafePath bool
}

func CheckAutosign(cfg AutosignConfig, csr *x509.CertificateRequest, csrPEM []byte) (bool, error) {
	switch cfg.Mode {
	case "true":
		return true, nil
	case "file":
		return checkAutosignFile(cfg.FileOrPath, csr.Subject.CommonName)
	case "executable":
		return checkAutosignExecutable(cfg, csr.Subject.CommonName, csrPEM)
	default:
		return false, nil
	}
}

// autosignNeedsSlot reports whether running this CA's autosign policy takes
// one of the autosignConcurrency slots: only an executable does, since the
// other modes decide without starting a process.
func (c *CA) autosignNeedsSlot() bool {
	return c.AutosignConfig.Mode == "executable" && c.autosignSlots != nil
}

// acquireAutosignSlot takes one of autosignConcurrency slots for an autosign
// run and returns the function that gives it back. When the policy needs no
// slot it takes none and returns a no-op.
//
// A free slot is taken at once. Otherwise the wait ends early enough to leave
// the run and the signature their time: the run's timeout, autosignWaitDelay
// and autosignSigningMargin come off ctx's deadline. The wait, the run and the
// signature share that deadline, and the CSR is saved once the slot is held,
// so a request let in with too little left would be approved, fail to sign,
// and leave its CSR pending, where the agent's next submission is refused as a
// duplicate. Better that it gives up in the queue, having saved nothing.
//
// The caller must hold the subject lock and must NOT hold c.mu: a full set of
// slots is a queue, and queueing under c.mu is the stall #664 removed. The
// caller must defer the release, so a panic in the run cannot keep the slot
// for good.
func (c *CA) acquireAutosignSlot(ctx context.Context) (func(), error) {
	if !c.autosignNeedsSlot() {
		return func() {}, nil
	}
	release := func() { <-c.autosignSlots }
	select {
	case c.autosignSlots <- struct{}{}:
		return release, nil
	default:
	}

	waitCtx := ctx
	if deadline, ok := ctx.Deadline(); ok {
		timeout := c.AutosignConfig.ExecutableTimeout
		if timeout == 0 {
			timeout = defaultExecutableTimeout
		}
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithDeadline(ctx, deadline.Add(-(timeout + autosignWaitDelay + autosignSigningMargin)))
		defer cancel()
	}
	select {
	case c.autosignSlots <- struct{}{}:
		return release, nil
	case <-waitCtx.Done():
		return nil, fmt.Errorf("waiting to run the autosign executable: %w", waitCtx.Err())
	}
}

func checkAutosignFile(path, commonName string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Simple glob matching
		matched, err := filepath.Match(line, commonName)
		if err != nil {
			// If pattern is bad, just ignore or log? Standard Match doesn't handle some complex globs
			// but Puppet's autosign usually uses standard shell globs.
			continue
		}
		if matched {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// autosignBeforeExec runs between judging the executable and running it. It
// does nothing in production; it is a variable so that a white-box spec can
// stand in for the kubelet replacing a volume's files in that gap.
var autosignBeforeExec = func() {}

func checkAutosignExecutable(cfg AutosignConfig, commonName string, csrPEM []byte) (bool, error) {
	timeout := cfg.ExecutableTimeout
	if timeout == 0 {
		timeout = defaultExecutableTimeout
	}

	// The file judged can vanish before it is run: when a ConfigMap changes,
	// the kubelet repoints the volume's ..data at a new directory and deletes
	// the old one, which is where the path just resolved to. Running the
	// configured path instead would dodge that, but would run a file nobody
	// judged. So resolve, judge and run once more, and only then give up --
	// the CSR is already saved, and an error here leaves it for an operator.
	for attempt := 0; ; attempt++ {
		resolved, err := judgeAutosignExecutable(cfg)
		if err != nil {
			return false, err
		}
		autosignBeforeExec()
		ok, err := runAutosignExecutable(cfg, resolved, timeout, commonName, csrPEM)
		if attempt == 0 && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return ok, err
	}
}

// judgeAutosignExecutable resolves the executable's path and judges it,
// returning the file to run.
//
// SECURITY: Re-resolve and re-judge the path before every run, and run the
// file that was judged. The startup check alone left the window this closes:
// a file, symlink or directory swapped after startup ran with no check at all,
// and whoever can replace the executable decides which certificates are
// signed. An unsafe path is an error rather than a deny, so the operator sees
// why in the log instead of watching every CSR wait.
// NIST 800-53: CM-5 (Access Restrictions for Change), SI-7 (Software, Firmware, and Information Integrity)
func judgeAutosignExecutable(cfg AutosignConfig) (string, error) {
	resolved, findings, err := ResolveAutosignExecutable(cfg.FileOrPath)
	if err != nil {
		return "", fmt.Errorf("autosign executable %s: %w", cfg.FileOrPath, err)
	}
	if len(findings) > 0 && !cfg.AllowUnsafePath {
		return "", fmt.Errorf("refusing to run autosign executable %s: %s",
			cfg.FileOrPath, FormatAutosignPathFindings(findings))
	}
	return resolved, nil
}

// runAutosignExecutable runs the resolved executable once and interprets its
// exit status: zero signs, anything else denies.
func runAutosignExecutable(cfg AutosignConfig, resolved string, timeout time.Duration, commonName string, csrPEM []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolved, commonName) //nolint:gosec // G204: operator-configured executable, resolved and judged by judgeAutosignExecutable; commonName allowlist-validated by ValidateSubject and passed as a separate argv (no shell)
	// SECURITY: Environment sanitization: only allowlisted variables are
	// passed to the autosign subprocess. Prevents leaking secrets (API keys,
	// cloud tokens, DB credentials) from the CA process environment to
	// user-supplied scripts.
	// NIST 800-53: CM-7 (Least Functionality), SC-4 (Information in Shared System Resources)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + os.Getenv("HOME"),
	}
	if lang := os.Getenv("LANG"); lang != "" {
		cmd.Env = append(cmd.Env, "LANG="+lang)
	}
	cmd.Stdin = bytes.NewReader(csrPEM)
	killProcessGroupOnCancel(cmd)
	cmd.WaitDelay = autosignWaitDelay

	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		// The executable exited zero, and something it started was still
		// holding its stdin when the delay ran out. The exit status is the
		// decision; a descendant's grip on the pipe does not change it.
		// exec reports this only for a successful exit that was not
		// cancelled, so it is never a timeout.
		slog.Warn("Autosign executable approved the request but left a process holding its stdin; signing as its exit status says",
			"path", cfg.FileOrPath, "realpath", resolved, "common_name", commonName, "wait_delay", autosignWaitDelay)
		return true, nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return false, fmt.Errorf("autosign executable timed out after %s", timeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Non-zero exit code means deny (fail-closed). Exit codes >=126
			// conventionally indicate the command could not execute or crashed
			// (126 = not executable, 127 = not found, 128+n = killed by signal n)
			// rather than a deliberate policy deny. Warn so an operator can tell a
			// misconfigured script apart from an intentional rejection; the deny
			// semantics are unchanged.
			if code := exitErr.ExitCode(); code >= 126 {
				slog.Warn("Autosign executable exited with a crash/not-executable code; the script may be misconfigured (treating as deny)",
					"path", cfg.FileOrPath, "realpath", resolved, "common_name", commonName, "exit_code", code)
			}
			return false, nil
		}
		// Named both ways: the configured path is what the operator knows,
		// and the resolved one may be a kubelet generation directory that
		// has since gone. A file that is present but whose #! interpreter is
		// not fails with the same error as a file that is missing, and in a
		// container image that is the likelier of the two.
		if errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("running autosign executable %s (resolved to %q): it, or the interpreter its #! line names, does not exist: %w",
				cfg.FileOrPath, resolved, err)
		}
		return false, fmt.Errorf("running autosign executable %s (resolved to %q): %w", cfg.FileOrPath, resolved, err)
	}

	return true, nil
}
