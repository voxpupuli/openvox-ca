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
	case isLockingUnavailableError(err):
		return false, errLockingUnavailable
	default:
		return false, err
	}
}

// isLockingUnavailableError reports whether err says this filesystem or kernel
// cannot do BSD locks at all, as opposed to refusing this particular one.
//
// The three of them are the "the platform cannot deliver" case arriving at
// runtime rather than at compile time: a store on a mount whose filesystem
// rejects flock(2) (EOPNOTSUPP, ENOSYS on some FUSE and network filesystems),
// or a kernel out of lock records (ENOLCK). Treating those as hard errors would
// fail every WithLock caller — bootstrap, signing, revocation, CRL refresh —
// and so take down a CA that worked before this capability existed, on a store
// nobody can lock and where the previous release simply did not try. That is
// the same trade filelock_other.go makes for a platform with no flock(2) at
// all, and it is made the same way: report the capability absent.
func isLockingUnavailableError(err error) bool {
	return errors.Is(err, syscall.ENOLCK) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOSYS)
}

// isReadOnlyFSError reports whether err says the filesystem itself is mounted
// read-only. Deliberately narrower than "this process cannot write here":
// EROFS admits no writer at all, whereas a permission error only says *this*
// process cannot write, which is a different claim and safe to act on in only
// one of the two places it can arise. See fileLocks.inaccessibleLockFile.
func isReadOnlyFSError(err error) bool {
	return errors.Is(err, syscall.EROFS)
}

// statUID extracts the owning uid from a FileInfo. The stat structure is
// platform-specific, so it lives beside the other shims; the second return is
// false where the platform does not carry one.
func statUID(info fs.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
