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

package ca_test

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// realTempDir returns a fresh temporary directory by its real path, so that
// expectations compare against what ResolveAutosignExecutable returns: on
// macOS the temporary directory lives under /var, which is a symlink.
func realTempDir() string {
	GinkgoHelper()
	dir, err := filepath.EvalSymlinks(GinkgoT().TempDir())
	Expect(err).NotTo(HaveOccurred())
	return dir
}

// mkdirMode creates dir with exactly mode, whatever the umask.
func mkdirMode(dir string, mode os.FileMode) string {
	GinkgoHelper()
	Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
	Expect(os.Chmod(dir, mode)).To(Succeed())
	return dir
}

// writeExecutable writes an autosign script with exactly mode, whatever the
// umask.
func writeExecutable(path, content string, mode os.FileMode) string {
	GinkgoHelper()
	Expect(os.WriteFile(path, []byte(content), 0o700)).To(Succeed())
	Expect(os.Chmod(path, mode)).To(Succeed())
	return path
}

const allowScript = "#!/bin/sh\nexit 0\n"

var _ = Describe("ResolveAutosignExecutable", func() {
	var dir string

	BeforeEach(func() { dir = realTempDir() })

	It("resolves a script owned by this user, with nothing to report", func() {
		script := writeExecutable(filepath.Join(dir, "autosign"), allowScript, 0o755)

		resolved, findings, err := ca.ResolveAutosignExecutable(script)
		Expect(err).NotTo(HaveOccurred())
		Expect(findings).To(BeEmpty())
		Expect(resolved).To(Equal(script))
	})

	It("follows relative and absolute symlinks to the file they lead to", func() {
		script := writeExecutable(filepath.Join(mkdirMode(filepath.Join(dir, "bin"), 0o755), "autosign"),
			allowScript, 0o755)
		Expect(os.Symlink("bin/autosign", filepath.Join(dir, "relative"))).To(Succeed())
		Expect(os.Symlink(filepath.Join(dir, "relative"), filepath.Join(dir, "absolute"))).To(Succeed())

		resolved, findings, err := ca.ResolveAutosignExecutable(filepath.Join(dir, "absolute"))
		Expect(err).NotTo(HaveOccurred())
		Expect(findings).To(BeEmpty())
		Expect(resolved).To(Equal(script))
	})

	It("resolves a relative path against the working directory", func() {
		script := writeExecutable(filepath.Join(dir, "autosign"), allowScript, 0o755)
		GinkgoT().Chdir(dir)

		resolved, findings, err := ca.ResolveAutosignExecutable("autosign")
		Expect(err).NotTo(HaveOccurred())
		Expect(findings).To(BeEmpty())
		Expect(resolved).To(Equal(script))
	})

	// "link/.." is the directory above where link leads, not the directory
	// link sits in. Cleaning the path lexically first would look in the wrong
	// place -- and judge the wrong directories.
	DescribeTable("resolves '..' after a symlink against where the symlink led",
		func(relative bool) {
			target := mkdirMode(filepath.Join(dir, "a", "b"), 0o755)
			script := writeExecutable(filepath.Join(target, "autosign"), allowScript, 0o755)
			Expect(os.Symlink("a/b", filepath.Join(dir, "link"))).To(Succeed())

			path := filepath.Join(dir, "link") + "/../b/autosign"
			if relative {
				GinkgoT().Chdir(dir)
				path = "link/../b/autosign"
			}
			resolved, _, err := ca.ResolveAutosignExecutable(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(resolved).To(Equal(script))
		},
		Entry("in an absolute path", false),
		// filepath.Abs would clean this one to "b/autosign" before a single
		// symlink was read.
		Entry("in a relative path", true),
	)

	Describe("reporting what a third party could replace", func() {
		DescribeTable("a writable entry on the way",
			func(fileMode, dirMode os.FileMode, faulty, reason string) {
				sub := mkdirMode(filepath.Join(dir, "sub"), dirMode)
				script := writeExecutable(filepath.Join(sub, "autosign"), allowScript, fileMode)
				DeferCleanup(os.Chmod, sub, os.FileMode(0o700))

				_, findings, err := ca.ResolveAutosignExecutable(script)
				Expect(err).NotTo(HaveOccurred())
				want := map[string]string{"file": script, "dir": sub}[faulty]
				Expect(findings).To(ConsistOf(SatisfyAll(
					HaveField("Path", want),
					HaveField("Reason", reason),
				)))
			},
			Entry("a group-writable file", os.FileMode(0o775), os.FileMode(0o755), "file", "group-writable"),
			Entry("a world-writable file", os.FileMode(0o757), os.FileMode(0o755), "file", "world-writable"),
			Entry("a group- and world-writable file", os.FileMode(0o777), os.FileMode(0o755), "file", "group- and world-writable"),
			Entry("a group-writable directory", os.FileMode(0o755), os.FileMode(0o775), "dir", "group-writable"),
			Entry("a world-writable directory", os.FileMode(0o755), os.FileMode(0o757), "dir", "world-writable"),
		)

		It("judges the directory a symlink sits in, which decides where it points", func() {
			safe := mkdirMode(filepath.Join(dir, "safe"), 0o755)
			script := writeExecutable(filepath.Join(safe, "autosign"), allowScript, 0o755)
			open := mkdirMode(filepath.Join(dir, "open"), 0o777)
			Expect(os.Symlink(script, filepath.Join(open, "autosign"))).To(Succeed())

			resolved, findings, err := ca.ResolveAutosignExecutable(filepath.Join(open, "autosign"))
			Expect(err).NotTo(HaveOccurred())
			Expect(resolved).To(Equal(script))
			Expect(findings).To(ConsistOf(HaveField("Path", open)))
		})

		It("judges the directories a symlink's target passes through", func() {
			open := mkdirMode(filepath.Join(dir, "open"), 0o770)
			script := writeExecutable(filepath.Join(open, "autosign"), allowScript, 0o755)
			safe := mkdirMode(filepath.Join(dir, "safe"), 0o755)
			Expect(os.Symlink(script, filepath.Join(safe, "autosign"))).To(Succeed())

			_, findings, err := ca.ResolveAutosignExecutable(filepath.Join(safe, "autosign"))
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", open)))
		})

		// The sticky bit stops other users renaming or removing what they do
		// not own, which is the whole of what a writable directory threatens.
		It("accepts a sticky world-writable directory, as /tmp is", func() {
			sticky := mkdirMode(filepath.Join(dir, "tmp"), os.ModeSticky|0o777)
			script := writeExecutable(filepath.Join(sticky, "autosign"), allowScript, 0o755)

			_, findings, err := ca.ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(BeEmpty())
		})

		// Path is built from symlink targets, which the owner of a symlink
		// chooses; AGENTS.md has such values quoted wherever they reach a
		// terminal, which the startup refusal does.
		It("quotes a path, so a newline in a name cannot forge a line", func() {
			open := mkdirMode(filepath.Join(dir, "evil\nINFO all is well"), 0o777)
			script := writeExecutable(filepath.Join(open, "autosign"), allowScript, 0o755)

			_, findings, err := ca.ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(HaveLen(1))
			Expect(findings[0].String()).NotTo(ContainSubstring("\n"))
			Expect(ca.FormatAutosignPathFindings(findings)).To(HavePrefix(strconv.Quote(open)))
		})

		It("quotes a path in the error when it cannot be followed", func() {
			missing := filepath.Join(dir, "gone\nINFO all is well")
			Expect(os.Symlink(missing, filepath.Join(dir, "autosign"))).To(Succeed())

			_, _, err := ca.ResolveAutosignExecutable(filepath.Join(dir, "autosign"))
			Expect(err).To(MatchError(os.ErrNotExist), "quoting must keep the error inspectable")
			Expect(err.Error()).NotTo(ContainSubstring("\n"))
			Expect(err.Error()).To(ContainSubstring(strconv.Quote(missing)))
		})

		It("still judges the file inside a sticky directory", func() {
			sticky := mkdirMode(filepath.Join(dir, "tmp"), os.ModeSticky|0o777)
			script := writeExecutable(filepath.Join(sticky, "autosign"), allowScript, 0o757)

			_, findings, err := ca.ResolveAutosignExecutable(script)
			Expect(err).NotTo(HaveOccurred())
			Expect(findings).To(ConsistOf(HaveField("Path", script)))
		})
	})

	Describe("a path that does not lead to a regular file", func() {
		// Without its own guard "" would become the working directory and be
		// refused as a directory, so the message is what proves the guard.
		It("refuses an empty path", func() {
			_, _, err := ca.ResolveAutosignExecutable("")
			Expect(err).To(MatchError("no autosign executable configured"))
		})

		It("refuses a path that does not exist", func() {
			_, _, err := ca.ResolveAutosignExecutable(filepath.Join(dir, "missing"))
			Expect(err).To(MatchError(os.ErrNotExist))
		})

		It("refuses a dangling symlink", func() {
			Expect(os.Symlink("missing", filepath.Join(dir, "dangling"))).To(Succeed())
			_, _, err := ca.ResolveAutosignExecutable(filepath.Join(dir, "dangling"))
			Expect(err).To(MatchError(os.ErrNotExist))
		})

		It("refuses a symlink loop rather than following it for ever", func() {
			Expect(os.Symlink("b", filepath.Join(dir, "a"))).To(Succeed())
			Expect(os.Symlink("a", filepath.Join(dir, "b"))).To(Succeed())
			_, _, err := ca.ResolveAutosignExecutable(filepath.Join(dir, "a"))
			Expect(err).To(MatchError(ContainSubstring("more than 40 symlinks")))
		})

		// The kernel's own limit for a path lookup is 40, so a chain the kernel
		// would follow is followed here too, and one link more is not.
		DescribeTable("follows a chain of up to 40 symlinks, and no more",
			func(links int, ok bool) {
				script := writeExecutable(filepath.Join(dir, "autosign"), allowScript, 0o755)
				target := "autosign"
				for i := range links {
					name := "link" + strconv.Itoa(i)
					Expect(os.Symlink(target, filepath.Join(dir, name))).To(Succeed())
					target = name
				}

				resolved, _, err := ca.ResolveAutosignExecutable(filepath.Join(dir, target))
				if ok {
					Expect(err).NotTo(HaveOccurred())
					Expect(resolved).To(Equal(script))
				} else {
					Expect(err).To(MatchError(ContainSubstring("more than 40 symlinks")))
				}
			},
			Entry("40 links", 40, true),
			Entry("41 links", 41, false),
		)

		It("refuses a directory", func() {
			_, _, err := ca.ResolveAutosignExecutable(dir)
			Expect(err).To(MatchError(ContainSubstring("not a regular file")))
		})

		It("refuses a file used as a directory", func() {
			script := writeExecutable(filepath.Join(dir, "autosign"), allowScript, 0o755)
			_, _, err := ca.ResolveAutosignExecutable(filepath.Join(script, "more"))
			Expect(err).To(MatchError(ContainSubstring("is not a directory")))
		})

		It("refuses a FIFO", func() {
			fifo := filepath.Join(dir, "fifo")
			Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
			_, _, err := ca.ResolveAutosignExecutable(fifo)
			Expect(err).To(MatchError(ContainSubstring("not a regular file, directory or symlink")))
		})
	})
})

var _ = Describe("CheckAutosign re-checks the executable before every run", func() {
	var (
		dir    string
		csrPEM = []byte("unused")
	)

	BeforeEach(func() { dir = realTempDir() })

	check := func(cfg ca.AutosignConfig) (bool, error) {
		_, csr := buildCSR("node.example.com")
		return ca.CheckAutosign(cfg, csr, csrPEM)
	}

	// The startup check resolved the path once, and every later run executed
	// the configured path afresh: a symlink repointed after startup ran
	// whatever it now named. Re-resolving each time means it is judged first.
	It("follows a symlink repointed since the last run", func() {
		deny := writeExecutable(filepath.Join(dir, "deny"), "#!/bin/sh\nexit 1\n", 0o755)
		allow := writeExecutable(filepath.Join(dir, "allow"), allowScript, 0o755)
		link := filepath.Join(dir, "autosign")
		Expect(os.Symlink(deny, link)).To(Succeed())
		cfg := ca.AutosignConfig{Mode: "executable", FileOrPath: link}

		Expect(check(cfg)).To(BeFalse())

		Expect(os.Remove(link)).To(Succeed())
		Expect(os.Symlink(allow, link)).To(Succeed())
		Expect(check(cfg)).To(BeTrue())
	})

	// The file that runs is the file that was judged: the resolved path is
	// what is executed, and so what a script sees as $0, not the link the
	// operator configured.
	It("executes the resolved file, not the configured symlink", func() {
		marker := filepath.Join(dir, "argv0")
		script := writeExecutable(filepath.Join(dir, "autosign"),
			"#!/bin/sh\nprintf '%s' \"$0\" > '"+marker+"'\nexit 0\n", 0o755)
		link := filepath.Join(dir, "configured")
		Expect(os.Symlink(script, link)).To(Succeed())

		Expect(check(ca.AutosignConfig{Mode: "executable", FileOrPath: link})).To(BeTrue())
		Expect(os.ReadFile(marker)).To(BeEquivalentTo(script))
	})

	Context("when the path has become replaceable since the last run", func() {
		var (
			script, marker string
			cfg            ca.AutosignConfig
		)

		BeforeEach(func() {
			marker = filepath.Join(dir, "ran")
			sub := mkdirMode(filepath.Join(dir, "sub"), 0o755)
			DeferCleanup(os.Chmod, sub, os.FileMode(0o755))
			script = writeExecutable(filepath.Join(sub, "autosign"),
				"#!/bin/sh\ntouch '"+marker+"'\nexit 0\n", 0o755)
			cfg = ca.AutosignConfig{Mode: "executable", FileOrPath: script}

			Expect(check(cfg)).To(BeTrue(), "the fixture must run while it is safe")
			Expect(os.Remove(marker)).To(Succeed())
		})

		It("refuses a script that became group-writable, without running it", func() {
			Expect(os.Chmod(script, 0o775)).To(Succeed())

			ok, err := check(cfg)
			Expect(err).To(MatchError(ContainSubstring("group-writable")))
			Expect(ok).To(BeFalse())
			Expect(marker).NotTo(BeAnExistingFile(), "a refused script must not have run")
		})

		It("refuses a script whose directory became writable, without running it", func() {
			Expect(os.Chmod(filepath.Dir(script), 0o777)).To(Succeed())

			ok, err := check(cfg)
			Expect(err).To(MatchError(ContainSubstring("group- and world-writable")))
			Expect(ok).To(BeFalse())
			Expect(marker).NotTo(BeAnExistingFile(), "a refused script must not have run")
		})

		It("runs it anyway when the operator has opted out", func() {
			Expect(os.Chmod(script, 0o777)).To(Succeed())
			cfg.AllowUnsafePath = true

			Expect(check(cfg)).To(BeTrue())
			Expect(marker).To(BeAnExistingFile())
		})
	})

	It("refuses a configured path that no longer exists", func() {
		ok, err := check(ca.AutosignConfig{Mode: "executable", FileOrPath: filepath.Join(dir, "gone")})
		Expect(err).To(MatchError(os.ErrNotExist))
		Expect(ok).To(BeFalse())
	})
})
