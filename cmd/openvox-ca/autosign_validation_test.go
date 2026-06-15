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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("validateAutosignExecutable", func() {
	It("accepts a valid file owned by the current user, mode 0755 (not world-writable)", func() {
		tmp := GinkgoT().TempDir()
		exe := filepath.Join(tmp, "autosign.sh")
		Expect(os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0755)).To(Succeed(), "setup")

		Expect(validateAutosignExecutable(exe)).To(Succeed(), "expected no error for valid executable")
	})

	It("rejects a world-writable file", func() {
		tmp := GinkgoT().TempDir()
		exe := filepath.Join(tmp, "autosign.sh")
		// Create file then explicitly chmod to 0757 (world-writable).
		// os.WriteFile alone may be affected by umask.
		Expect(os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0700)).To(Succeed(), "setup")
		Expect(os.Chmod(exe, 0757)).To(Succeed(), "chmod")

		err := validateAutosignExecutable(exe)
		Expect(err).To(HaveOccurred(), "expected error for world-writable file, got nil")
		Expect(err.Error()).To(ContainSubstring("world-writable"), "expected error containing 'world-writable'")
	})

	It("rejects a non-existent file", func() {
		err := validateAutosignExecutable("/nonexistent/path/autosign.sh")
		Expect(err).To(HaveOccurred(), "expected error for non-existent file, got nil")
	})

	It("accepts a symlink to a valid file", func() {
		tmp := GinkgoT().TempDir()
		exe := filepath.Join(tmp, "autosign.sh")
		Expect(os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0755)).To(Succeed(), "setup")

		link := filepath.Join(tmp, "autosign-link.sh")
		Expect(os.Symlink(exe, link)).To(Succeed(), "setup symlink")

		Expect(validateAutosignExecutable(link)).To(Succeed(), "expected no error for symlink to valid file")
	})

	It("accepts a group-writable (non-world-writable) file", func() {
		tmp := GinkgoT().TempDir()
		exe := filepath.Join(tmp, "autosign.sh")
		// Mode 0770: group-writable but not world-writable.
		Expect(os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0770)).To(Succeed(), "setup")

		Expect(validateAutosignExecutable(exe)).To(Succeed(), "expected no error for group-writable (non-world-writable) file")
	})
})
