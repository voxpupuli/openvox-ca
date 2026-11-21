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
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// White-box: the ceiling is driven by filling a path's count directly, so the
// refusal is pinned on every platform -- the FIFO specs that strand real reads
// are !windows -- and without waiting out Slots deadlines to get there.
var _ = Describe("Read", func() {
	var dir string

	BeforeEach(func() { dir = GinkgoT().TempDir() })

	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		Expect(os.WriteFile(p, data, 0o600)).To(Succeed())
		return p
	}

	It("reads a file", func() {
		data, err := Read(context.Background(), write("a.pem", []byte("hello")), MaxCRLBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(Equal([]byte("hello")))
	})

	It("reports an absent file as fs.ErrNotExist, which callers rely on", func() {
		_, err := Read(context.Background(), filepath.Join(dir, "absent.pem"), MaxCRLBytes)
		Expect(err).To(MatchError(os.ErrNotExist))
	})

	DescribeTable("accepts exactly the limit and refuses one more, rather than truncating",
		func(limit int64) {
			_, err := Read(context.Background(), write("max.pem", bytes.Repeat([]byte("a"), int(limit))), limit)
			Expect(err).NotTo(HaveOccurred())
			_, err = Read(context.Background(), write("over.pem", bytes.Repeat([]byte("a"), int(limit)+1)), limit)
			Expect(err).To(MatchError(ContainSubstring("larger than %d bytes", limit)))
		},
		Entry("MaxCRLBytes", int64(MaxCRLBytes)),
		Entry("a caller's own, smaller limit", int64(64<<10)),
	)

	It("refuses a path that opens but cannot be read, rather than reading it as empty", func() {
		// A directory mounted where crl_chain.file belongs opens and then
		// fails to read. Taken as empty, it would read as the file
		// deliberately listing nothing, and every published ancestor would
		// be dropped.
		data, err := Read(context.Background(), dir, MaxCRLBytes)
		Expect(err).To(HaveOccurred())
		Expect(data).To(BeNil())
	})

	Describe("the stranded-read ceiling", func() {
		It("refuses a path with Slots reads stranded, at once, and only that path", func() {
			wedged := write("wedged.pem", []byte("x"))
			mu.Lock()
			stranded[wedged] = Slots
			mu.Unlock()
			DeferCleanup(func() {
				mu.Lock()
				delete(stranded, wedged)
				mu.Unlock()
			})

			// A deadline that a queued read would reach: refusing at once is
			// what keeps the result from being DeadlineExceeded.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			start := time.Now()
			_, err := Read(ctx, wedged, MaxCRLBytes)
			Expect(err).To(MatchError(ContainSubstring("outlived their deadline")))
			Expect(err).To(MatchError(ContainSubstring(wedged)), "the refusal names the path at fault")
			Expect(err).NotTo(MatchError(context.DeadlineExceeded))
			Expect(time.Since(start)).To(BeNumerically("<", 500*time.Millisecond), "refused, not queued")

			// Another path is untouched: a wedged mount refuses only itself.
			data, err := Read(context.Background(), write("healthy.pem", []byte("ok")), MaxCRLBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(data).To(Equal([]byte("ok")))
		})

		It("holds no slot once a read has returned", func() {
			p := write("done.pem", []byte("x"))
			for range Slots + 2 {
				_, err := Read(context.Background(), p, MaxCRLBytes)
				Expect(err).NotTo(HaveOccurred())
			}
			mu.Lock()
			defer mu.Unlock()
			Expect(inflight).NotTo(HaveKey(p))
			Expect(stranded).NotTo(HaveKey(p))
		})

		It("counts no stranded read when the deadline arrives after the read has finished", func() {
			// The race the deadline arm's `!finished` guard is for: a read that
			// has already returned, and given back nothing because nobody had
			// abandoned it, must not then be counted as stranded, or the slot
			// leaks for good. finishedFirst hands over its Done channel only once
			// the read has marked itself finished, so whenever the deadline arm
			// runs, it runs against a finished read.
			p := write("racy.pem", []byte("x"))
			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			for range 20 {
				_, _ = Read(finishedFirst{Context: cancelled, path: p}, p, MaxCRLBytes)
			}
			mu.Lock()
			defer mu.Unlock()
			Expect(stranded).NotTo(HaveKey(p), "a read that finished before its deadline must not hold a stranded slot")
		})

		It("leaves another read's stranded slot alone when a read finishes on time", func() {
			// Only a read whose caller gave up on it gives a slot back. One that
			// returned in time must not, or a healthy read beside a wedged one
			// would free the wedged read's slot and let the leak grow past Slots.
			p := write("shared.pem", []byte("x"))
			mu.Lock()
			stranded[p] = 1
			mu.Unlock()
			DeferCleanup(func() {
				mu.Lock()
				delete(stranded, p)
				mu.Unlock()
			})

			_, err := Read(context.Background(), p, MaxCRLBytes)
			Expect(err).NotTo(HaveOccurred())
			mu.Lock()
			defer mu.Unlock()
			Expect(stranded[p]).To(Equal(1), "a read that finished on time must not give back a stranded read's slot")
		})
	})
})

// finishedFirst is a context that is already done, but whose Done channel is
// handed over only once every read of path has marked itself finished: the
// result may or may not be waiting yet, but whichever arm of Read's select
// runs, the deadline arm can only ever see a finished read.
//
// The wait is bounded, so a fault that stops the read finishing fails the spec
// rather than hanging the suite. Done runs on the spec's goroutine, from Read's
// select, so Fail is safe there.
type finishedFirst struct {
	context.Context
	path string
}

func (c finishedFirst) Done() <-chan struct{} {
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := inflight[c.path]
		mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			Fail(fmt.Sprintf("%d reads of %s still in flight after 5s", n, c.path))
		}
		time.Sleep(time.Millisecond)
	}
	ch := make(chan struct{})
	close(ch)
	return ch
}
