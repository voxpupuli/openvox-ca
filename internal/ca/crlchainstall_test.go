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

//go:build !windows

package ca_test

import (
	"context"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// A crl_chain.file whose read never returns must not hold the cluster CRL lock.
//
// Both call sites reach this read under lockNameCRL and c.mu, and that lock
// serialises revocation across every replica -- so one replica stuck inside
// os.Open or io.ReadAll wedges CRL maintenance fleet-wide, with every other
// replica timing out against LockTimeout while this one never releases.
//
// The size caps do not help: they bound how much the file may contain, not how
// long reading it may take. A FIFO with no writer is the cheapest faithful
// stand-in for the real cause -- a wedged CSI driver, an NFS volume whose
// server has gone, a sidecar that stopped writing -- because os.Open on it
// blocks until a writer appears, which is exactly a read that never returns.
var _ = Describe("crl_chain.file: a read that never returns", func() {
	It("gives up rather than holding the CRL lock, and leaves it usable", func() {
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		store := storage.New(dir)

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		fifo := filepath.Join(dir, "wedged.pem")
		Expect(syscall.Mkfifo(fifo, 0o600)).To(Succeed())
		myCA.CRLChainFile = fifo

		// A second deadline below crlChainReadTimeout, so the spec does not wait
		// out the production bound. readCRLChainFile honours whichever is
		// sooner, so this exercises the same select.
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()

		start := time.Now()
		_, err := myCA.RefreshCRLChainFile(bounded)
		Expect(err).To(HaveOccurred(), "a read that cannot complete is a failed refresh")
		Expect(time.Since(start)).To(BeNumerically("<", 30*time.Second),
			"the read must be abandoned, not waited on")

		// The point of abandoning it: the lock is free for the next writer. A
		// spec that only asserted the error would pass with the lock still held
		// by a goroutine nobody is waiting for.
		done := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			myCA.CRLChainFile = ""
			done <- myCA.ReissueCRL(ctx)
		}()
		Eventually(done, 10*time.Second).Should(Receive(BeNil()),
			"the CRL lock must be available to the next writer")
	})
})
