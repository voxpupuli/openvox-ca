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

// Unix-only: these judge unix ownership and mode bits.

//go:build unix

package ca

import (
	"os"
	"path/filepath"
	"strconv"

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

	Describe("a kubelet volume root", func() {
		readOnly := func(path string) {
			orig := autosignReadOnlyMountRoot
			autosignReadOnlyMountRoot = func(p string) bool { return p == path || orig(p) }
			DeferCleanup(func() { autosignReadOnlyMountRoot = orig })
		}
		// kubeletVolume dresses dir as the kubelet's atomic writer leaves a
		// ConfigMap or Secret volume: the root of a read-only mount, holding
		// a root-owned ..data symlink. Whether a real directory is the root
		// of a read-only mount is readOnlyMountRoot's question, pinned in
		// autosignpath_linux_test.go.
		kubeletVolume := func(dir string) {
			readOnly(dir)
			Expect(os.Symlink("..2026_10_14_12_00_00.000000000", filepath.Join(dir, "..data"))).To(Succeed())
			ownedBy("..data", 0, true)
		}

		// The shape of a Kubernetes ConfigMap or Secret volume: a 0777 root,
		// not sticky, mounted read-only.
		It("exempts its world-writable root from the writable test", func() {
			kubeletVolume(sub)
			Expect(os.Chmod(sub, 0o777)).To(Succeed())

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(BeEmpty())
		})

		It("does not exempt it from the ownership test", func() {
			kubeletVolume(sub)
			Expect(os.Chmod(sub, 0o777)).To(Succeed())
			ownedBy("sub", uint32(os.Geteuid())+1, true)

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(SatisfyAll(
				HaveField("Path", sub),
				HaveField("Reason", ContainSubstring("owned by uid")),
			)))
		})

		// A writable script is refused wherever it lives, and a ConfigMap's
		// defaultMode can say 0555. That the exemptions are for directories
		// at all is pinned with a sticky script, in autosignpath_linux_test.go.
		It("still judges a file inside the volume", func() {
			kubeletVolume(sub)
			Expect(os.Chmod(script, 0o777)).To(Succeed())

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", script)))
		})

		// What ProtectSystem=strict makes of every separate host mount point:
		// the root of a read-only mount, as the CA sees it, that host users
		// can still write. Without the kubelet's ..data it is judged as usual.
		DescribeTable("judges the root of a read-only mount that is not one",
			func(dress func()) {
				readOnly(sub)
				dress()
				Expect(os.Chmod(sub, 0o777)).To(Succeed())

				_, findings, err := ResolveAutosignExecutable(script)
				Expect(err).NotTo(HaveOccurred())
				Expect(findings).To(ConsistOf(SatisfyAll(
					HaveField("Path", sub),
					HaveField("Reason", "group- and world-writable"),
				)))
			},
			Entry("with no ..data at all", func() {}),
			Entry("with a ..data somebody else planted", func() {
				Expect(os.Symlink("elsewhere", filepath.Join(sub, "..data"))).To(Succeed())
				ownedBy("..data", uint32(os.Geteuid())+1, true)
			}),
			Entry("with a ..data that is a directory, not a symlink", func() {
				Expect(os.Mkdir(filepath.Join(sub, "..data"), 0o755)).To(Succeed())
				ownedBy("..data", 0, true)
			}),
		)

		It("needs the read-only mount root as well as the ..data", func() {
			Expect(os.Symlink("elsewhere", filepath.Join(sub, "..data"))).To(Succeed())
			ownedBy("..data", 0, true)
			Expect(os.Chmod(sub, 0o777)).To(Succeed())

			_, findings, err := ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", sub)))
		})
	})

	// The sticky exemption is from the writable test only: the owner of a
	// sticky directory can still rename anything in it.
	It("still judges a sticky directory's owner", func() {
		Expect(os.Chmod(sub, os.ModeSticky|0o777)).To(Succeed())
		ownedBy("sub", uint32(os.Geteuid())+1, true)

		_, findings, err := ResolveAutosignExecutable(script)
		Expect(err).NotTo(HaveOccurred())
		Expect(findings).To(ConsistOf(SatisfyAll(
			HaveField("Path", sub),
			HaveField("Reason", ContainSubstring("owned by uid")),
		)))
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

// White-box, because the gap it covers -- between judging the executable and
// running it -- is one only the autosignBeforeExec seam can reach.
var _ = Describe("checkAutosignExecutable when the judged file vanishes", func() {
	var dir, link string

	BeforeEach(func() {
		var err error
		dir, err = filepath.EvalSymlinks(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		link = filepath.Join(dir, "autosign")
	})

	// volume writes a directory holding an autosign script that exits with
	// code, as one generation of a ConfigMap volume.
	volume := func(name string, code int) string {
		gen := filepath.Join(dir, name)
		Expect(os.Mkdir(gen, 0o700)).To(Succeed())
		Expect(os.Chmod(gen, 0o755)).To(Succeed())
		script := filepath.Join(gen, "autosign")
		Expect(os.WriteFile(script, []byte("#!/bin/sh\nexit "+strconv.Itoa(code)+"\n"), 0o700)).To(Succeed())
		Expect(os.Chmod(script, 0o755)).To(Succeed())
		return script
	}

	beforeExec := func(hook func()) {
		orig := autosignBeforeExec
		autosignBeforeExec = hook
		DeferCleanup(func() { autosignBeforeExec = orig })
	}

	// What the kubelet does on a ConfigMap update, landing between the check
	// and the exec: repoint, then delete the old generation.
	It("resolves, judges and runs the new file once", func() {
		old := volume("old", 1)
		replacement := volume("new", 0)
		Expect(os.Symlink(old, link)).To(Succeed())
		calls := 0
		beforeExec(func() {
			calls++
			if calls == 1 {
				Expect(os.Remove(link)).To(Succeed())
				Expect(os.Symlink(replacement, link)).To(Succeed())
				Expect(os.RemoveAll(filepath.Dir(old))).To(Succeed())
			}
		})

		ok, err := checkAutosignExecutable(AutosignConfig{FileOrPath: link}, "node.example.com", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue(), "the replacement, which exits 0, is what ran")
		Expect(calls).To(Equal(2))
	})

	// The retry judges the new generation before running it, like the first
	// attempt: a replacement somebody else could have written is refused, and
	// never runs.
	It("judges the new file before running it", func() {
		old := volume("old", 1)
		marker := filepath.Join(dir, "ran")
		unsafeGen := filepath.Join(dir, "unsafe")
		Expect(os.Mkdir(unsafeGen, 0o700)).To(Succeed())
		Expect(os.Chmod(unsafeGen, 0o755)).To(Succeed())
		replacement := filepath.Join(unsafeGen, "autosign")
		Expect(os.WriteFile(replacement, []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 0\n"), 0o700)).To(Succeed())
		Expect(os.Chmod(replacement, 0o775)).To(Succeed())
		Expect(os.Symlink(old, link)).To(Succeed())
		calls := 0
		beforeExec(func() {
			calls++
			Expect(os.Remove(link)).To(Succeed())
			Expect(os.Symlink(replacement, link)).To(Succeed())
			Expect(os.RemoveAll(filepath.Dir(old))).To(Succeed())
		})

		ok, err := checkAutosignExecutable(AutosignConfig{FileOrPath: link}, "node.example.com", nil)
		Expect(err).To(MatchError(ContainSubstring("group-writable")))
		Expect(ok).To(BeFalse())
		Expect(calls).To(Equal(1), "the second judgement refuses before anything runs")
		Expect(marker).NotTo(BeAnExistingFile(), "the unsafe replacement must not have run")
	})

	// One retry, not a loop: a second swap in the same gap is an error even
	// though a third generation is sitting there ready to run.
	It("retries once, not again", func() {
		gens := []string{volume("first", 0), volume("second", 0), volume("third", 0)}
		Expect(os.Symlink(gens[0], link)).To(Succeed())
		calls := 0
		beforeExec(func() {
			calls++
			if calls >= len(gens) {
				Fail("checkAutosignExecutable retried more than once")
			}
			Expect(os.Remove(link)).To(Succeed())
			Expect(os.Symlink(gens[calls], link)).To(Succeed())
			Expect(os.RemoveAll(filepath.Dir(gens[calls-1]))).To(Succeed())
		})

		ok, err := checkAutosignExecutable(AutosignConfig{FileOrPath: link}, "node.example.com", nil)
		Expect(err).To(MatchError(os.ErrNotExist))
		Expect(ok).To(BeFalse())
		Expect(calls).To(Equal(2))
	})
})
