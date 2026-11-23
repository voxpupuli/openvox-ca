//go:build !windows

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

// Not built on Windows: the umask spec below needs syscall.Umask, which does
// not exist there, and file modes do not carry the meaning these specs are
// about. The build system tolerates a Windows target but nothing ships one.

package storage

import (
	"context"
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// AtomicWriteFile is exported for the offline subcommands, which write CA
// bundles and signing requests to operator-supplied paths. These specs pin the
// contract that export advertises, in the package that owns it: the mode does
// not depend on the caller's umask, and a failure leaves neither a partial
// target nor a temporary file behind.
var _ = Describe("AtomicWriteFile", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	It("writes the content at the requested mode, whatever the umask", func() {
		// 0077 would reduce 0644 to 0600 under a plain os.WriteFile, which is
		// what the explicit mode exists to prevent: material that is public by
		// construction must not arrive looking confidential.
		old := syscall.Umask(0o077)
		defer syscall.Umask(old)

		target := filepath.Join(dir, "bundle.pem")
		Expect(AtomicWriteFile(target, []byte("payload"), FilePermPublic)).To(Succeed())

		Expect(os.ReadFile(target)).To(Equal([]byte("payload")))
		info, err := os.Stat(target)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(FilePermPublic)))
	})

	It("removes the temporary file when the rename cannot complete", func() {
		// A directory at the target: the temp file is created and written, and
		// only the rename fails. Without the cleanup the CA directory would
		// accumulate a .tmp-* file per attempt, each holding a full copy of
		// whatever was being written.
		target := filepath.Join(dir, "occupied")
		Expect(os.Mkdir(target, DirPerm)).To(Succeed())

		err := AtomicWriteFile(target, []byte("payload"), FilePermPublic)
		Expect(err).To(MatchError(ContainSubstring(target)),
			"the error must name the target the caller asked for, not the temporary file")

		leftovers, err := filepath.Glob(filepath.Join(dir, ".tmp-*"))
		Expect(err).NotTo(HaveOccurred())
		Expect(leftovers).To(BeEmpty(), "a failed write must not leave a temporary file behind")
	})

	It("names the target when no temporary file can be created", func() {
		// The path the offline subcommands hit most often: --out pointing into
		// a directory that does not exist. The message has to name the path the
		// operator typed, since the temporary file's name is an implementation
		// detail they never asked for.
		target := filepath.Join(dir, "no-such-dir", "bundle.pem")
		err := AtomicWriteFile(target, []byte("payload"), FilePermPublic)
		Expect(err).To(MatchError(ContainSubstring("creating a temporary file beside " + target)))
	})
})

var _ = Describe("SavePrivateKey", func() {
	It("replaces a permissive key and does not follow a symlink", func() {
		dir := GinkgoT().TempDir()
		store := New(dir)
		Expect(store.EnsureDirs(context.Background())).To(Succeed())

		path := store.PrivateKeyPath("node")
		Expect(os.WriteFile(path, []byte("old"), 0o644)).To(Succeed())
		Expect(store.SavePrivateKey(context.Background(), "node", []byte("new-key"))).To(Succeed())
		Expect(os.ReadFile(path)).To(Equal([]byte("new-key")))
		info, err := os.Lstat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(FilePermPrivate)))

		outside := filepath.Join(dir, "outside")
		Expect(os.WriteFile(outside, []byte("secret"), 0o600)).To(Succeed())
		Expect(os.Remove(path)).To(Succeed())
		Expect(os.Symlink(outside, path)).To(Succeed())
		Expect(store.SavePrivateKey(context.Background(), "node", []byte("replaced"))).To(Succeed())
		Expect(os.ReadFile(outside)).To(Equal([]byte("secret")))
		info, err = os.Lstat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode() & os.ModeSymlink).To(Equal(os.FileMode(0)))
		Expect(os.ReadFile(path)).To(Equal([]byte("replaced")))
	})
})
