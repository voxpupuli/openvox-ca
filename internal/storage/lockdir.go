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

package storage

import (
	"os"
	"path/filepath"
)

// makeDir creates the lock directory if it is missing: any missing parent at
// DirPerm, and only the lock directory itself at lockDirPerm, so that a store
// root created on the way is not made group-writable too.
//
// An existing directory is left exactly as it is, whatever its mode. One made
// 0750 by an earlier version keeps working for the uid that owns it and stays
// unreachable to any other, because this package never changes the mode of a
// file it did not just create. MkdirAll rather than Mkdir for the second step
// because it already answers the two cases that matter: nil for a directory
// that exists, and ENOTDIR for a plain file in its place, which the lock
// callers report as a hard error rather than as an unwritable store.
//
// In a file of its own, not in filelock.go, because of the directives below.
// gosec reports both calls as G703 on every run, reaching them through
// acquireInstance (30 of 30 with a clean cache, golangci-lint v2.14.0), so
// unlike the two in filelock.go they are not part of the #313 flake. Kept out
// of that file, nolintlint stays fully in force for them: the carve-out in
// .golangci.yml is scoped to filelock.go, and magefile_test.go pins that it
// covers exactly the two directives there.
func (l *fileLocks) makeDir() error {
	//nolint:gosec // G703: the parent of the lock directory, derived from the operator-configured store root and no request-supplied value
	if err := os.MkdirAll(filepath.Dir(l.dir), DirPerm); err != nil {
		return err
	}
	//nolint:gosec // G703: the lock directory itself, derived from the operator-configured store root and no request-supplied value
	return os.MkdirAll(l.dir, lockDirPerm)
}
