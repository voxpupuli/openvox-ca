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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// autosignConfigFrom derives the autosign policy from autosign_config. A path
// is an executable or an allowlist according to the file it names -- any
// execute bit makes it an executable -- so the mode is a property of the file
// on disk and not of the setting. The pre-fork preflight and the server both
// derive it here, so they cannot disagree about whether there is an
// executable to check.
func autosignConfigFrom(cfg *serverConfig) (ca.AutosignConfig, error) {
	asCfg := ca.AutosignConfig{Mode: "off", AllowUnsafePath: cfg.InsecureAllowUnsafeAutosignPath}
	switch cfg.AutosignConfig {
	case "", "false":
		// leave as off
	case "true":
		asCfg.Mode = "true"
	default:
		info, err := os.Stat(cfg.AutosignConfig)
		if err != nil {
			return asCfg, fmt.Errorf("autosign config invalid (path %s): %w", cfg.AutosignConfig, err)
		}
		if info.Mode().IsRegular() {
			if info.Mode().Perm()&0111 != 0 {
				asCfg.Mode = "executable"
			} else {
				asCfg.Mode = "file"
			}
			asCfg.FileOrPath = cfg.AutosignConfig
		}
	}
	return asCfg, nil
}

// checkAutosignExecutable judges the autosign executable's path at startup,
// with the rules the CA applies again before every run (see
// ca.ResolveAutosignExecutable). It refuses on any finding unless
// insecure_allow_unsafe_autosign_path is set, in which case the findings come
// back for the caller to report. It is a no-op for every mode but
// "executable".
func checkAutosignExecutable(asCfg ca.AutosignConfig) (resolved string, findings []ca.AutosignPathFinding, err error) {
	if asCfg.Mode != "executable" {
		return "", nil, nil
	}
	resolved, findings, err = ca.ResolveAutosignExecutable(asCfg.FileOrPath)
	if err != nil {
		return "", nil, fmt.Errorf("autosign executable %s: %w", asCfg.FileOrPath, err)
	}
	if len(findings) > 0 && !asCfg.AllowUnsafePath {
		return resolved, findings, fmt.Errorf("refusing to start: autosign executable %s could be replaced by "+
			"someone other than root or the CA's own user: %s. Make every entry named owned by root or by "+
			"the CA's user, and not group- or world-writable (chmod go-w), or set "+
			"insecure_allow_unsafe_autosign_path to start anyway",
			asCfg.FileOrPath, ca.FormatAutosignPathFindings(findings))
	}
	return resolved, findings, nil
}

// preflightAutosign raises the autosign executable refusal before the
// --daemon fork, for the reason preflightKeyMaterial gives: past it the
// child's stderr is discarded, so the operator would be told the CA started
// and watch it never serve. The launcher needs no such call, because its
// children share its stderr and the frontend refuses there before serving.
// The returned findings are those the opt-out let through.
func preflightAutosign(cfg *serverConfig) ([]ca.AutosignPathFinding, error) {
	asCfg, err := autosignConfigFrom(cfg)
	if err != nil {
		return nil, err
	}
	_, findings, err := checkAutosignExecutable(asCfg)
	return findings, err
}

// autosignInsecureNotice renders, for a terminal, what
// insecure_allow_unsafe_autosign_path let through. Empty when there is nothing
// to say.
func autosignInsecureNotice(findings []ca.AutosignPathFinding) string {
	if len(findings) == 0 {
		return ""
	}
	return "INSECURE: insecure_allow_unsafe_autosign_path is set, so the autosign executable runs although " +
		"someone other than root or the CA's own user could replace it: " + ca.FormatAutosignPathFindings(findings)
}

// logAutosignExecutable logs the executable the server will run, with a
// SHA-256 of it for change detection (logged, not enforced), and a warning for
// each finding the opt-out let through. A file that cannot be read for the hash
// is reported in place of it and does not stop startup: the hash decides
// nothing, and the check before each run is what decides whether it runs.
func logAutosignExecutable(path, resolved string, findings []ca.AutosignPathFinding) {
	for _, f := range findings {
		slog.Warn("INSECURE: insecure_allow_unsafe_autosign_path is set; the autosign executable could be replaced "+
			"by someone other than root or the CA's own user",
			"path", f.Path, "mode", f.Mode.String(), "problem", f.Reason)
	}
	attrs := []any{"path", path, "realpath", resolved}
	if data, err := os.ReadFile(resolved); err == nil {
		hash := sha256.Sum256(data)
		attrs = append(attrs, "sha256", hex.EncodeToString(hash[:]))
	} else {
		attrs = append(attrs, "sha256_error", err.Error())
	}
	slog.Info("Autosign executable configured", attrs...)
}
