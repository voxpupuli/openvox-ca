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
	"fmt"
	"os"
	"path/filepath"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// writePublicFile writes public PEM material to an operator-supplied --out path,
// atomically and at a mode that does not depend on the caller's umask.
//
// Mode 0644 because everything written this way — a certificate signing request,
// a validated CA bundle — is public by construction and is about to be handed to
// a third party or loaded into a Kubernetes Secret served to every agent.
// Restricting it would imply a confidentiality it does not have. The explicit
// Chmod is needed because os.WriteFile applies the umask, so the mode would
// otherwise be whatever the invoking shell happened to have set.
//
// Temp file plus rename because a truncating write that fails part-way — ENOSPC,
// an interrupted process — leaves a partial chain at a path an automation step
// may go on to deploy fleet-wide. The storage layer writes CA material the same
// way, and docs/storage-backends.md advertises that property; a file destined for
// the same place should not be weaker.
func writePublicFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("creating a temporary file beside %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// No-op once the rename has succeeded; cleans up on every failure path.
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Chmod(tmpName, storage.FilePermPublic); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// roleMayReachCAKey reports whether a process running as role is permitted to
// construct a CA key provider of its own.
//
// Only the frontend is not. It proxies every signature to the isolated signer
// process, so opening its own authenticated session to the key backend would
// give it reach over a key it is specifically not allowed to use. Every other
// role — the signer, and the empty single-process role — needs the key.
//
// A named function rather than an inline `role != "frontend"` so the predicate
// can be tested directly. The half that can regress is the mapping, not
// resolveRuntime's handling of the boolean, and an inverted or mistyped
// comparison at the call site would silently hand the frontend the key.
func roleMayReachCAKey(role string) bool {
	return role != "frontend"
}
