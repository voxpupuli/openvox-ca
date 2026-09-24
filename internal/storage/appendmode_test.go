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

// AppendLine creates the file it appends to, and O_CREATE's mode argument is
// masked by the umask, so the mode it landed on was the operator's rather than
// ours. AtomicWriteFile defeats the umask deliberately; these are the same
// operation on the same blobs, and this is the other half.
//
// No caller is exposed by the difference today -- AppendInventory, the only
// non-test caller, passes BlobPrivate, and no realistic umask moves 0600. What
// these specs pin is that a BlobPublic caller gets the mode the kind names
// rather than the one the umask leaves, and that an existing file's mode is
// still not ours to touch.
var _ = Describe("AppendLine file modes", func() {
	var dir string
	var b *FilesystemBackend

	BeforeEach(func() {
		// 0077 is the umask a hardened service manager would set. Under it a
		// public file created from the umask alone lands at 0600.
		old := syscall.Umask(0o077)
		DeferCleanup(func() { syscall.Umask(old) })

		dir = GinkgoT().TempDir()
		b = NewFilesystemBackend(dir)
	})

	inventoryPath := func() string {
		GinkgoHelper()
		p, err := b.pathFor(KeyInventory)
		Expect(err).NotTo(HaveOccurred(), "pathFor")
		return p
	}

	It("creates a public blob at its declared mode, whatever the umask", func() {
		Expect(b.AppendLine(context.Background(), KeyInventory, []byte("0001 na nb /CN=a\n"), BlobPublic)).
			To(Succeed(), "AppendLine")

		info, err := os.Stat(inventoryPath())
		Expect(err).NotTo(HaveOccurred(), "stat the inventory")
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)), "inventory mode under umask 0077")
	})

	It("creates a private blob at its declared mode", func() {
		Expect(b.AppendLine(context.Background(), KeyInventory, []byte("0001 na nb /CN=a\n"), BlobPrivate)).
			To(Succeed(), "AppendLine")

		info, err := os.Stat(inventoryPath())
		Expect(err).NotTo(HaveOccurred(), "stat the inventory")
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)), "inventory mode for private material")
	})

	// The mode is set on creation only. A file that is already there belongs to
	// the operator, and reasserting a mode on it is the one thing this package
	// does not do -- on an arbitrary-uid platform it may not even own it.
	It("leaves the mode of an existing file alone", func() {
		p := inventoryPath()
		Expect(os.MkdirAll(filepath.Dir(p), DirPerm)).To(Succeed(), "make the parent")
		Expect(os.WriteFile(p, nil, 0o640)).To(Succeed(), "seed a file the operator narrowed")
		// WriteFile's mode is masked by the umask too, and this block runs under
		// 0077, so the seed would otherwise land at 0600 and the spec would pass
		// without proving anything.
		Expect(os.Chmod(p, 0o640)).To(Succeed(), "give the seed the mode it claims")

		Expect(b.AppendLine(context.Background(), KeyInventory, []byte("0001 na nb /CN=a\n"), BlobPublic)).
			To(Succeed(), "AppendLine")

		info, err := os.Stat(p)
		Expect(err).NotTo(HaveOccurred(), "stat the inventory")
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o640)), "the mode the operator set")
	})

	// O_EXCL fails on a dangling symlink as well as on a file, so the fallback
	// has to keep O_CREATE: without it, appending through a link planted for a
	// path that does not exist yet -- which the plain O_APPEND|O_CREATE this
	// replaced handled -- fails ENOENT and the CA cannot write its inventory.
	It("appends through a symlink planted before the file exists", func() {
		p := inventoryPath()
		Expect(os.MkdirAll(filepath.Dir(p), DirPerm)).To(Succeed(), "make the parent")
		target := filepath.Join(GinkgoT().TempDir(), "inventory.txt")
		Expect(os.Symlink(target, p)).To(Succeed(), "point the inventory at a file that is not there yet")

		Expect(b.AppendLine(context.Background(), KeyInventory, []byte("0001 na nb /CN=a\n"), BlobPublic)).
			To(Succeed(), "AppendLine through the dangling link")

		data, err := os.ReadFile(target)
		Expect(err).NotTo(HaveOccurred(), "the target was created through the link")
		Expect(string(data)).To(Equal("0001 na nb /CN=a\n"), "the line went through the link")
	})

	// Appending to an existing file must still append rather than truncate or
	// fail: the create is only an attempt, and losing the race to it is normal.
	It("appends to an existing file rather than replacing it", func() {
		ctx := context.Background()
		Expect(b.AppendLine(ctx, KeyInventory, []byte("first\n"), BlobPublic)).To(Succeed(), "first append")
		Expect(b.AppendLine(ctx, KeyInventory, []byte("second\n"), BlobPublic)).To(Succeed(), "second append")

		data, err := os.ReadFile(inventoryPath())
		Expect(err).NotTo(HaveOccurred(), "read the inventory")
		Expect(string(data)).To(Equal("first\nsecond\n"), "both lines, in order")
	})
})
