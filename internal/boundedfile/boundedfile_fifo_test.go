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

package boundedfile

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A FIFO with no writer is the cheapest faithful stand-in for a wedged mount:
// os.Open on it blocks until a writer appears, which is a read that never
// returns. Not on Windows, which has no syscall.Mkfifo.
var _ = Describe("Read on a path that never answers", func() {
	var dir string

	BeforeEach(func() { dir = GinkgoT().TempDir() })

	It("gives up on a read that never returns, and frees its slot once it does", func() {
		fifo := filepath.Join(dir, "wedged.fifo")
		Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
		// Unwedge it whatever happens below: a writer lets the open return and
		// the read complete, so a failing assertion cannot leave the goroutine
		// blocked for the rest of the suite. Non-blocking, so this cannot wedge
		// in turn once the reader has gone.
		DeferCleanup(func() {
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
		})
		strandedReads := func() int {
			mu.Lock()
			defer mu.Unlock()
			return stranded[fifo]
		}

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := Read(ctx, fifo, MaxCRLBytes)
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(time.Since(start)).To(BeNumerically("<", 5*time.Second))
		Expect(strandedReads()).To(Equal(1), "the stranded read still holds its slot")

		// A writer lets the open return, the read completes, and the slot
		// comes back.
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(w.Close()).To(Succeed())
		Eventually(strandedReads).WithTimeout(5 * time.Second).Should(BeZero())
	})

	It("never refuses healthy reads of one path in flight together, however many", func() {
		// The HTTP client re-reads a credentials file on every request, and
		// requests run concurrently: more than Slots reads of one path can be
		// in flight without any of them having outlived its deadline.
		fifo := filepath.Join(dir, "shared.fifo")
		Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
		DeferCleanup(func() {
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		const readers = Slots + 2
		errs := make(chan error, readers)
		for range readers {
			go func() {
				_, err := Read(ctx, fifo, MaxCRLBytes)
				errs <- err
			}()
		}
		// A read refused here never reaches inflight, so check for one on every
		// poll: otherwise a refusal surfaces as this wait timing out rather
		// than as the refusal it is.
		Eventually(func() int {
			select {
			case err := <-errs:
				Expect(err).NotTo(HaveOccurred(), "no healthy read may be refused")
			default:
			}
			mu.Lock()
			defer mu.Unlock()
			return inflight[fifo]
		}).WithTimeout(5*time.Second).Should(Equal(readers), "precondition: every read is in flight at once")

		// Release them. A writer that opens and closes lets every reader then
		// blocked in open through to EOF; one that reached open a moment later
		// would wait for the next writer, so keep opening one until all have
		// returned.
		returned := 0
		Eventually(func() int {
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
			for {
				select {
				case err := <-errs:
					Expect(err).NotTo(HaveOccurred(), "no healthy read may be refused")
					returned++
				default:
					return returned
				}
			}
		}).WithTimeout(5 * time.Second).WithPolling(10 * time.Millisecond).Should(Equal(readers))
	})
})
