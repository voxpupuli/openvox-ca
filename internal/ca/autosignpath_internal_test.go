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

// Unix-only: these judge unix ownership and mode bits, and make a FIFO.

//go:build unix

package ca

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// White-box, for the two things an unprivileged spec cannot arrange on a real
// filesystem: an entry owned by somebody else, and a directory on a read-only
// mount. Both are stood in for through the platform hooks.
var _ = Describe("ResolveAutosignExecutable platform judgements", func() {
	var dir, sub, script string

	BeforeEach(func() {
		var err error
		dir, err = filepath.EvalSymlinks(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		sub = filepath.Join(dir, "sub")
		Expect(os.Mkdir(sub, 0o700)).To(Succeed())
		Expect(os.Chmod(sub, 0o755)).To(Succeed())
		script = filepath.Join(sub, "autosign")
		Expect(os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700)).To(Succeed())
		Expect(os.Chmod(script, 0o755)).To(Succeed())
	})

	// ownedBy makes every entry named name report owner, and leaves the rest
	// to the real platform.
	ownedBy := func(name string, owner uint32, readable bool) {
		orig := autosignFileOwner
		autosignFileOwner = func(fi os.FileInfo) (uint32, bool) {
			if fi.Name() == name {
				return owner, readable
			}
			return orig(fi)
		}
		DeferCleanup(func() { autosignFileOwner = orig })
	}

	Describe("ownership", func() {
		It("accepts entries owned by root", func() {
			ownedBy("autosign", 0, true)
			ownedBy("sub", 0, true)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(BeEmpty())
		})

		It("reports a file owned by another user, whatever its mode", func() {
			other := uint32(os.Geteuid()) + 1
			ownedBy("autosign", other, true)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(SatisfyAll(
				HaveField("Path", script),
				HaveField("Reason", ContainSubstring("owned by uid")),
			)))
		})

		// The owner of a directory can chmod it writable, or rename the
		// script out of it, whenever they like.
		It("reports a directory owned by another user", func() {
			ownedBy("sub", uint32(os.Geteuid())+1, true)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", sub)))
		})

		It("reports a symlink owned by another user", func() {
			link := filepath.Join(dir, "link")
			Expect(os.Symlink(script, link)).To(Succeed())
			ownedBy("link", uint32(os.Geteuid())+1, true)

			_, findings, err := ResolveAutosignExecutable(link)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", link)))
		})

		// "/" is judged before the walk starts, and is the one entry no
		// fixture can create: Lstat("/").Name() is "/".
		It("judges the root directory too", func() {
			ownedBy("/", uint32(os.Geteuid())+1, true)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", "/")))
		})

		It("reports an entry whose owner cannot be read", func() {
			ownedBy("autosign", 0, false)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", script)))
		})
	})

	Describe("the root of a read-only mount", func() {
		readOnly := func(path string) {
			orig := autosignReadOnlyMountRoot
			autosignReadOnlyMountRoot = func(p string) bool { return p == path || orig(p) }
			DeferCleanup(func() { autosignReadOnlyMountRoot = orig })
		}

		// The shape of a Kubernetes ConfigMap or Secret volume: a 0777 root,
		// not sticky, mounted read-only. Whether a real directory is such a
		// root is readOnlyMountRoot's question, pinned in
		// autosignpath_linux_test.go.
		It("exempts a world-writable directory from the writable test", func() {
			Expect(os.Chmod(sub, 0o777)).To(Succeed())
			readOnly(sub)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(BeEmpty())
		})

		It("does not exempt it from the ownership test", func() {
			Expect(os.Chmod(sub, 0o777)).To(Succeed())
			readOnly(sub)
			ownedBy("sub", uint32(os.Geteuid())+1, true)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(SatisfyAll(
				HaveField("Path", sub),
				HaveField("Reason", ContainSubstring("owned by uid")),
			)))
		})

		// The exemption is for directories, as ruled; a writable script is
		// refused wherever it lives, and a ConfigMap's defaultMode can say 0555.
		It("does not exempt the file itself", func() {
			Expect(os.Chmod(script, 0o777)).To(Succeed())
			readOnly(script)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", script)))
		})
	})

	Describe("readOnlyMountRoot", func() {
		It("does not call a writable temporary directory a read-only mount root", func() {
			Expect(readOnlyMountRoot(dir)).To(BeFalse())
		})

		It("never grants the exemption for a path it cannot examine", func() {
			Expect(readOnlyMountRoot(filepath.Join(dir, "missing"))).To(BeFalse())
		})
	})
})
