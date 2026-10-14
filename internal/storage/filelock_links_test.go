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

// Not built on Windows: these specs plant symbolic links, hard links and FIFOs,
// and no lock file is ever opened there.
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

// The lock directory can be group-writable (lockDirPerm, #493), so a member of
// the store's group can put something other than a lock file at a lock file's
// name before the CA next starts. Each case plants one where a lock file
// belongs and asserts two things: the acquisition is refused, loudly rather
// than as the capability being absent, and the thing planted is untouched.
//
// The second is the one that matters. The instance lock truncates the file it
// opens and writes its holder record into it, so a lock path that reaches
// ca_key.pem through a link destroys the CA key: that is what the sentinel
// stands for. A named lock writes nothing, so for it the refusal is the whole
// assertion -- but a followed dangling link would have created a file at the
// link's target, which is asserted as well.
var _ = Describe("Same-host lock files planted by someone else", func() {
	const sentinelContent = "-----BEGIN PRIVATE KEY----- stands in for ca_key.pem"

	var (
		cadir    string
		locks    string
		sentinel string
	)

	BeforeEach(func() {
		cadir = GinkgoT().TempDir()
		locks = filepath.Join(cadir, fsLockDir)
		Expect(NewFilesystemBackend(cadir).EnsureReady(context.Background())).To(Succeed())
		sentinel = filepath.Join(cadir, "ca_key.pem")
		Expect(os.WriteFile(sentinel, []byte(sentinelContent), 0o600)).To(Succeed())
	})

	acquireNamed := func(b *FilesystemBackend) error {
		ul, err := b.AcquireSameHostLock(context.Background(), "subject:node1.test")
		if err == nil {
			Expect(ul.Unlock()).To(Succeed())
		}
		return err
	}
	acquireInstance := func(b *FilesystemBackend) error {
		ul, err := b.AcquireInstanceLock()
		if err == nil {
			Expect(ul.Unlock()).To(Succeed())
		}
		return err
	}

	expectSentinelIntact := func() {
		GinkgoHelper()
		got, err := os.ReadFile(sentinel)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(sentinelContent), "the file the planted name reached must be untouched")
	}

	// why is a clause of openvox-ca's own message, never the OS's: ELOOP's own
	// text ("too many levels of symbolic links") would otherwise satisfy a
	// looser match with the explanation removed.
	expectRefused := func(err error, why string) {
		GinkgoHelper()
		Expect(err).To(HaveOccurred(), "a planted lock file must be refused")
		Expect(err).NotTo(MatchError(ErrSameHostLockingUnsupported),
			"and refused loudly: reporting the capability absent would run without the lock")
		Expect(err.Error()).To(ContainSubstring(why))
	}

	DescribeTable("refuses a symbolic link at a lock file's name",
		func(acquire func(*FilesystemBackend) error, name string) {
			Expect(os.Symlink(sentinel, filepath.Join(locks, fileLockFileName(name)))).To(Succeed())

			expectRefused(acquire(NewFilesystemBackend(cadir)), "it is a symbolic link")
			expectSentinelIntact()
		},
		Entry("for a named lock", acquireNamed, "subject:node1.test"),
		Entry("for the instance lock, which would truncate its target", acquireInstance, instanceLockName),
	)

	DescribeTable("refuses a dangling symbolic link rather than creating its target",
		func(acquire func(*FilesystemBackend) error, name string) {
			target := filepath.Join(cadir, "created-through-the-link")
			Expect(os.Symlink(target, filepath.Join(locks, fileLockFileName(name)))).To(Succeed())

			expectRefused(acquire(NewFilesystemBackend(cadir)), "it is a symbolic link")
			_, err := os.Lstat(target)
			Expect(os.IsNotExist(err)).To(BeTrue(), "nothing may be created where the link points")
		},
		Entry("for a named lock", acquireNamed, "subject:node1.test"),
		Entry("for the instance lock", acquireInstance, instanceLockName),
	)

	// O_NOFOLLOW says nothing about a hard link: it is the file itself under a
	// second name. The link count is the only thing that tells it apart.
	DescribeTable("refuses a hard link at a lock file's name",
		func(acquire func(*FilesystemBackend) error, name string) {
			Expect(os.Link(sentinel, filepath.Join(locks, fileLockFileName(name)))).To(Succeed())

			expectRefused(acquire(NewFilesystemBackend(cadir)), "hard links")
			expectSentinelIntact()
		},
		Entry("for a named lock", acquireNamed, "subject:node1.test"),
		Entry("for the instance lock, which would truncate the linked file", acquireInstance, instanceLockName),
	)

	// Without O_NONBLOCK the open would block until a writer appeared, so this
	// spec would hang rather than fail; the suite's timeout is what would
	// report that.
	DescribeTable("refuses a FIFO at a lock file's name without blocking on it",
		func(acquire func(*FilesystemBackend) error, name string) {
			Expect(syscall.Mkfifo(filepath.Join(locks, fileLockFileName(name)), 0o660)).To(Succeed())

			expectRefused(acquire(NewFilesystemBackend(cadir)), "not a regular file")
		},
		Entry("for a named lock", acquireNamed, "subject:node1.test"),
		Entry("for the instance lock", acquireInstance, instanceLockName),
	)

	// The complement, so the refusals above cannot be satisfied by refusing
	// everything: a lock file left by an earlier acquisition is a plain file
	// with one link, and is reused.
	DescribeTable("reuses a lock file it created itself",
		func(acquire func(*FilesystemBackend) error) {
			b := NewFilesystemBackend(cadir)
			Expect(acquire(b)).To(Succeed(), "first acquisition creates the lock file")
			Expect(acquire(b)).To(Succeed(), "second acquisition reopens it")
		},
		Entry("for a named lock", acquireNamed),
		Entry("for the instance lock", acquireInstance),
	)
})
