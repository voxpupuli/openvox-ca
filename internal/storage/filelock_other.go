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

//go:build !(linux || darwin || dragonfly || freebsd || netbsd || openbsd)

package storage

import (
	"errors"
	"io/fs"
	"os"
)

// Platforms where the standard library declares no syscall.Flock — Windows,
// AIX, Solaris, js/wasm and friends. Same-host locking reports itself
// unsupported, so StorageService.WithLock falls back to the process-local mutex
// it used before this capability existed: no behaviour is lost relative to the
// previous release, and none is claimed that the platform cannot deliver.
//
// Only Linux is a supported deployment target (see magefile.go), so this file
// exists to keep `go build` honest on a contributor's machine rather than to
// support running there.

// fileLockingSupported reports that this platform has no flock(2).
const fileLockingSupported = false

// tryLockFile is unreachable: acquire returns ErrSameHostLockingUnsupported
// before it can be called when fileLockingSupported is false. It returns an
// error rather than a refusal so that a future caller which forgets that guard
// fails loudly instead of spinning in the retry loop forever.
func tryLockFile(_ *os.File) (bool, error) {
	return false, errors.New("flock(2) is not available on this platform")
}

// isReadOnlyFSError is likewise unreachable — nothing here ever creates a lock
// file — and answers false so that, if it ever became reachable, a failure
// would be reported rather than quietly downgraded.
func isReadOnlyFSError(_ error) bool { return false }

// statUID has no portable answer off Unix, so it declines rather than guessing;
// the caller degrades its diagnostic message accordingly.
func statUID(_ fs.FileInfo) (uint32, bool) { return 0, false }
