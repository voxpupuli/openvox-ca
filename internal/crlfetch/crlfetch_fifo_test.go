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

package crlfetch_test

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/boundedfile"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/crlfetch"
)

// A FIFO with no writer stands in for a file:/// entry on a wedged mount. Not
// on Windows, which has no syscall.Mkfifo.
var _ = Describe("Fetcher with a file:/// entry that never answers", func() {
	It("gives up on it within the timeout, without failing a healthy file entry beside it", func() {
		dir := GinkgoT().TempDir()
		fifo := filepath.Join(dir, "wedged.crl")
		Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
		// Unwedge it afterwards, so the stranded read returns and its slot is
		// freed for any later spec.
		DeferCleanup(func() {
			if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
		})
		healthy := filepath.Join(dir, "healthy.crl")
		Expect(os.WriteFile(healthy, newCRLDER(4), 0o600)).To(Succeed())

		f, err := crlfetch.New(context.Background(), []string{"file://" + fifo, "file://" + healthy},
			config.HTTPClientConfig{}, 200*time.Millisecond)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)

		// Several rounds: a shared pool would fill with the wedged entry's
		// stranded reads and start refusing the healthy one. The first Slots
		// rounds each strand a read and give up at the timeout; after that the
		// path refuses at once.
		for round := range boundedfile.Slots + 2 {
			start := time.Now()
			res := f.Fetch(context.Background())
			Expect(time.Since(start)).To(BeNumerically("<", 3*time.Second), "round %d must not wait on the mount", round)
			if round < boundedfile.Slots {
				Expect(res[0].Err).To(MatchError(context.DeadlineExceeded), "round %d", round)
			} else {
				Expect(res[0].Err).To(MatchError(ContainSubstring("outlived their deadline")), "round %d", round)
			}
			Expect(res[1].Err).NotTo(HaveOccurred(), "a wedged entry must refuse only itself")
		}
	})

	It("gives up building the client within the timeout when tls_config.ca_file never answers", func() {
		dir := GinkgoT().TempDir()
		caFile := filepath.Join(dir, "ca.pem")
		Expect(syscall.Mkfifo(caFile, 0o600)).To(Succeed())
		DeferCleanup(func() {
			if w, err := os.OpenFile(caFile, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
		})
		start := time.Now()
		f, err := crlfetch.New(context.Background(), []string{"https://pki.example/root.crl"},
			config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: caFile}}, 200*time.Millisecond)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		Expect(time.Since(start)).To(BeNumerically("<", 3*time.Second), "a hung mount must not wedge the round")
		Expect(f.Fetch(context.Background())[0].Err).To(MatchError(context.DeadlineExceeded))
	})
})
