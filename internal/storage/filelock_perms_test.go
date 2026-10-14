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

// Not built on Windows: these specs set syscall.Umask, which does not exist
// there, and file modes do not carry the meaning they are about.
//go:build !windows

package storage

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The modes the same-host locks are created with, on the filesystem backend.
// SQLite's are pinned against its database's in sql_sqlite_perms_test.go; the
// two backends share fileLocks, but the filesystem backend has a second path
// that creates the lock directory, EnsureReady, which SQLite does not.
//
// Group access is the point (#493). A platform that gives the pod a fresh uid
// per start reaches the store through its group, and has to reacquire these
// locks before it touches any data: the lock files need group read and write,
// and the directory group write, since a subject never signed before has no
// lock file yet. The modes are asserted exactly rather than as "no world bits",
// because 0600 has no world bits either and is the bug.
var _ = Describe("Same-host lock file modes", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
		// Nothing masked, so what is asserted is the mode the code asks for
		// rather than whatever umask the suite happened to run under.
		old := syscall.Umask(0)
		DeferCleanup(func() { syscall.Umask(old) })
	})

	permOfPath := func(path string) os.FileMode {
		GinkgoHelper()
		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred(), "stat %s", path)
		return info.Mode().Perm()
	}

	acquireNamed := func(b *FilesystemBackend) {
		GinkgoHelper()
		ul, err := b.AcquireSameHostLock(ctx, "subject:node1.test")
		Expect(err).NotTo(HaveOccurred())
		Expect(ul.Unlock()).To(Succeed())
	}
	acquireInstance := func(b *FilesystemBackend) {
		GinkgoHelper()
		ul, err := b.AcquireInstanceLock()
		Expect(err).NotTo(HaveOccurred())
		Expect(ul.Unlock()).To(Succeed())
	}

	// Each path that can be first to create the lock directory, because the
	// first one to run decides its mode for the life of the store: EnsureReady
	// creates it eagerly, and acquire and acquireInstance each create it lazily
	// for a process that never called EnsureReady -- an `openvox-ca-ctl`
	// command, or the instance lock, which is taken before the store is opened
	// for use.
	DescribeTable("creates the lock directory 0770 and its lock files 0660",
		func(first func(*FilesystemBackend)) {
			cadir := filepath.Join(GinkgoT().TempDir(), "ca")
			b := NewFilesystemBackend(cadir)

			first(b)
			acquireNamed(b)
			acquireInstance(b)

			locks := filepath.Join(cadir, fsLockDir)
			Expect(permOfPath(locks)).To(Equal(os.FileMode(0o770)),
				"lock directory: group write is what lets another uid create a lock in it")
			for _, name := range []string{"subject:node1.test", instanceLockName} {
				Expect(permOfPath(filepath.Join(locks, fileLockFileName(name)))).To(Equal(os.FileMode(0o660)),
					"lock file for "+name)
			}

			// Only the lock directory is widened. A store root created on the
			// way to it keeps the mode every other store directory has, or
			// locking would have made the whole cadir group-writable.
			Expect(permOfPath(cadir)).To(Equal(os.FileMode(DirPerm)),
				"the store root is not the lock directory, and keeps DirPerm")
		},
		Entry("when EnsureReady creates it", func(b *FilesystemBackend) {
			GinkgoHelper()
			Expect(b.EnsureReady(context.Background())).To(Succeed())
		}),
		Entry("when a named lock creates it", acquireNamed),
		Entry("when the instance lock creates it", acquireInstance),
	)

	// A store an earlier version created has its lock directory at 0750 and
	// its lock files at 0600. The uid that made them must keep locking exactly
	// as before, and nothing here may widen them: this package never changes
	// the mode of a file it did not just create, so a store that wants group
	// access to existing locks has to be given it by the operator.
	DescribeTable("keeps using owner-only locks an earlier version left, without widening them",
		func(acquire func(*FilesystemBackend), name string) {
			cadir := GinkgoT().TempDir()
			locks := filepath.Join(cadir, fsLockDir)
			Expect(os.Mkdir(locks, 0o750)).To(Succeed())
			lockFile := filepath.Join(locks, fileLockFileName(name))
			Expect(os.WriteFile(lockFile, nil, 0o600)).To(Succeed())

			b := NewFilesystemBackend(cadir)
			Expect(b.EnsureReady(ctx)).To(Succeed(), "EnsureReady over the existing lock directory")
			acquire(b)

			Expect(permOfPath(locks)).To(Equal(os.FileMode(0o750)), "the existing lock directory's mode")
			Expect(permOfPath(lockFile)).To(Equal(os.FileMode(0o600)), "the existing lock file's mode")
		},
		Entry("for a named lock", acquireNamed, "subject:node1.test"),
		Entry("for the instance lock", acquireInstance, instanceLockName),
	)
})
