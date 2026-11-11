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

package fileexport

import (
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The swap between syncTarget's Lstat and sameContent's read, which a spec
// through SyncAll cannot hit on demand. Each case takes the FileInfo of a
// regular file of the right size -- what the Lstat saw -- and then replaces
// the path, as someone with write access to the export directory could, before
// sameContent reads it.
var _ = Describe("sameContent when the path changes after it was classified", func() {
	const want = "0123456789"
	var (
		dir, path string
		seen      os.FileInfo
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		path = filepath.Join(dir, "crl.pem")
		Expect(os.WriteFile(path, []byte(want), 0o644)).To(Succeed())
		var err error
		seen, err = os.Lstat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(seen.Mode().IsRegular()).To(BeTrue(), "precondition: the Lstat saw a regular file")
		Expect(os.Remove(path)).To(Succeed())
	})

	It("refuses a FIFO without waiting on it", func() {
		Expect(syscall.Mkfifo(path, 0o644)).To(Succeed())

		done := make(chan error, 1)
		go func() {
			_, err := sameContent(path, seen, []byte(want))
			done <- err
		}()
		var err error
		Eventually(done).WithTimeout(5*time.Second).Should(Receive(&err),
			"opening a FIFO with no writer must not block the export loop")
		Expect(err).To(MatchError(ContainSubstring("no longer a regular file")))
	})

	It("refuses a link rather than reading through it", func() {
		// A link to a file holding exactly the material: following it would
		// report "current" and leave the link in place.
		other := filepath.Join(dir, "other.pem")
		Expect(os.WriteFile(other, []byte(want), 0o644)).To(Succeed())
		Expect(os.Symlink(other, path)).To(Succeed())

		current, err := sameContent(path, seen, []byte(want))
		Expect(err).To(MatchError(ContainSubstring("to compare it")))
		Expect(current).To(BeFalse())
	})

	It("reports a difference when the file it opens is not the size the Lstat saw", func() {
		Expect(os.WriteFile(path, []byte(want+want), 0o644)).To(Succeed())

		current, err := sameContent(path, seen, []byte(want))
		Expect(err).NotTo(HaveOccurred())
		Expect(current).To(BeFalse())
	})

	It("still finds a regular file of the same content current", func() {
		// The twin: the descriptor checks must not refuse the ordinary case.
		Expect(os.WriteFile(path, []byte(want), 0o644)).To(Succeed())

		current, err := sameContent(path, seen, []byte(want))
		Expect(err).NotTo(HaveOccurred())
		Expect(current).To(BeTrue())
	})
})
