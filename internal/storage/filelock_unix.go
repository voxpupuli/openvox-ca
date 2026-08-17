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

//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package storage

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// The platform list above is the set for which the standard library declares
// syscall.Flock, rather than the broader `unix` constraint: `unix` also covers
// AIX and Solaris, where it is not declared and this file would not build.
// Everything outside the list gets filelock_other.go, which reports the
// capability as unsupported and leaves WithLock on the process-local mutex it
// used before same-host locking existed. Only Linux is a supported deployment
// target (see the build targets in magefile.go); darwin and the BSDs are here
// so a contributor's workstation behaves the same way CI does.

// fileLockingSupported reports that this platform has flock(2).
const fileLockingSupported = true

// tryLockFile takes a non-blocking exclusive flock(2) on f, reporting whether
// it was granted. A refusal is not an error — the caller retries until its
// context expires — and neither is an interrupted call.
func tryLockFile(f *os.File) (bool, error) {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.EWOULDBLOCK):
		// EAGAIN on the platforms where the two differ: another open file
		// description holds the lock.
		return false, nil
	case errors.Is(err, syscall.EINTR):
		// A signal arrived before the lock was decided. Retrying is the whole
		// of the recovery.
		return false, nil
	default:
		return false, err
	}
}

// isUnwritableStoreError reports whether err says the store cannot be written
// by this process at all, as opposed to something having gone wrong while
// writing it. Only these two: the filesystem is mounted read-only, or the
// process lacks permission on the directory. See fileLocks.classify for why
// they are treated as "no lock needed" rather than as failures.
func isUnwritableStoreError(err error) bool {
	return errors.Is(err, syscall.EROFS) || errors.Is(err, fs.ErrPermission)
}
