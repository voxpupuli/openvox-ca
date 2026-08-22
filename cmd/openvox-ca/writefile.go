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
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// writePublicFile writes public PEM material to an operator-supplied --out path,
// atomically and at a mode that does not depend on the caller's umask.
//
// Mode 0644 because everything written this way — a certificate signing request,
// a validated CA bundle — is public by construction and is about to be handed to
// a third party or loaded into a Kubernetes Secret served to every agent.
// Restricting it would imply a confidentiality it does not have. Passing the
// mode explicitly is what makes it so: os.WriteFile would apply the umask
// instead, leaving whatever the invoking shell happened to have set, and the
// helper below applies the mode to the descriptor before the rename.
//
// Temp file plus rename because a truncating write that fails part-way — ENOSPC,
// an interrupted process — leaves a partial chain at a path an automation step
// may go on to deploy fleet-wide. The storage layer writes CA material the same
// way, and docs/storage-backends.md advertises that property; a file destined for
// the same place should not be weaker. It is the storage layer's own helper
// rather than a copy of it, so the crash-safety of a written bundle cannot drift
// from the crash-safety of the blob in storage.
func writePublicFile(path string, data []byte) error {
	return storage.AtomicWriteFile(path, data, storage.FilePermPublic)
}

// writePrivateFile writes private key material to an operator-supplied path.
//
// Mode 0600, and the difference from writePublicFile is not only the number.
// AtomicWriteFile applies the mode to the descriptor before the rename, so a
// private key never exists at the target path under a permissive umask, not
// even briefly.
//
// The temporary-file cleanup the shared helper performs also matters more here:
// a leftover public certificate is litter, a leftover private key is a leaked
// credential sitting beside the path the operator chose.
func writePrivateFile(path string, data []byte) error {
	return storage.AtomicWriteFile(path, data, storage.FilePermPrivate)
}
