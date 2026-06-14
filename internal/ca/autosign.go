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
	"fmt"
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

type AutosignConfig struct {
	Mode              string        // "true", "file", "executable" (or "off" implicitly)
	FileOrPath        string        // Path to autosign.conf or executable
	ExecutableTimeout time.Duration // 0 → defaultExecutableTimeout
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

func checkAutosignExecutable(cfg AutosignConfig, commonName string, csrPEM []byte) (bool, error) {
	timeout := cfg.ExecutableTimeout
	if timeout == 0 {
		timeout = defaultExecutableTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cfg.FileOrPath, commonName) //nolint:gosec // G204: operator-configured executable; commonName allowlist-validated by ValidateSubject and passed as a separate argv (no shell)
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

	if err := cmd.Run(); err != nil {
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
					"path", cfg.FileOrPath, "common_name", commonName, "exit_code", code)
			}
			return false, nil
		}
		return false, err
	}

	return true, nil
}
