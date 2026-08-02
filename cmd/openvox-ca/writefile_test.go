// Copyright (C) 2026 Trevor Vaughan
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
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Atomic file writers", func() {
	var dir string

	BeforeEach(func() { dir = GinkgoT().TempDir() })

	// The two wrappers differ only in the mode they pass, so the regression
	// worth guarding is calling the wrong one -- which would either publish a
	// private key at 0644 or hand a third party a request they cannot read.
	It("writes public material at 0644", func() {
		path := filepath.Join(dir, "request.pem")
		Expect(writePublicFile(path, []byte("public"))).To(Succeed())

		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)))
	})

	It("writes private material at 0600", func() {
		path := filepath.Join(dir, "node_key.pem")
		Expect(writePrivateFile(path, []byte("private"))).To(Succeed())

		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
	})

	It("sets the mode explicitly rather than inheriting it", func() {
		// os.CreateTemp creates at 0600 whatever the umask, so what the Chmod
		// actually guards is inheritance from *that*, not from the shell: drop
		// it and the public path stays 0600 under any umask. The hostile umask
		// here is belt and braces -- it pins that neither source of inheritance
		// wins over the explicit mode.
		old := syscall.Umask(0o077)
		defer syscall.Umask(old)

		path := filepath.Join(dir, "umask.pem")
		Expect(writePublicFile(path, []byte("public"))).To(Succeed())

		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)),
			"the mode must not depend on the invoking shell")
	})

	It("leaves no temporary file behind on success", func() {
		Expect(writePrivateFile(filepath.Join(dir, "clean.pem"), []byte("x"))).To(Succeed())

		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1), "a leftover temporary private key is a leaked credential")
	})

	It("leaves no temporary file behind when the rename cannot happen", func() {
		// A directory at the target path makes the rename fail after the
		// temporary file has been written -- the failure mode the deferred
		// cleanup exists for.
		path := filepath.Join(dir, "occupied")
		Expect(os.Mkdir(path, 0o755)).To(Succeed())

		Expect(writePrivateFile(path, []byte("x"))).NotTo(Succeed())

		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1), "only the directory should remain; the temp file must be cleaned up")
	})

	It("does not disturb an existing file when the write fails", func() {
		path := filepath.Join(dir, "existing.pem")
		Expect(os.WriteFile(path, []byte("original"), 0o600)).To(Succeed())

		// An unwritable directory fails at CreateTemp, before anything touches
		// the target.
		Expect(os.Chmod(dir, 0o500)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(dir, 0o700) })

		if os.Geteuid() == 0 {
			Skip("root ignores directory permissions")
		}

		Expect(writePrivateFile(path, []byte("replacement"))).NotTo(Succeed())

		Expect(os.Chmod(dir, 0o700)).To(Succeed())
		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(Equal("original"))
	})
})
