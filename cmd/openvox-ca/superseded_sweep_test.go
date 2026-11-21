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

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// seedDueSupersession writes a pending-revocation list holding one entry whose
// due time has already passed, so any sweep pass revokes it.
// (newRefresherTestCA is defined in crl_refresh_test.go in this package.)
func seedDueSupersession(store *storage.StorageService, subject string, serial *big.Int) {
	GinkgoHelper()
	entry := []map[string]any{{
		"serial":    fmt.Sprintf("%X", serial),
		"subject":   subject,
		"revoke_at": time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
	}}
	data, err := json.Marshal(entry)
	Expect(err).NotTo(HaveOccurred(), "marshal pending entry")
	Expect(store.SaveSuperseded(context.Background(), data)).To(Succeed(), "SaveSuperseded")
}

// crlLists reports whether the stored CRL carries serial. Read from storage
// rather than from the CA's in-memory copy, so a sweep that never wrote through
// cannot pass.
func crlLists(store *storage.StorageService, serial *big.Int) bool {
	GinkgoHelper()
	crlPEM, err := store.GetCRL(context.Background())
	Expect(err).NotTo(HaveOccurred(), "GetCRL")
	block, _ := pem.Decode(crlPEM)
	Expect(block).NotTo(BeNil(), "CRL is not PEM")
	crl, err := x509.ParseRevocationList(block.Bytes)
	Expect(err).NotTo(HaveOccurred(), "ParseRevocationList")
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

var _ = Describe("sweepSupersededOnce", func() {
	It("revokes an entry whose window has elapsed", func() {
		c, store := newRefresherTestCA()
		serial := big.NewInt(0xABCDEF)
		seedDueSupersession(store, "due-node", serial)

		sweepSupersededOnce(context.Background(), c)
		Expect(crlLists(store, serial)).To(BeTrue(),
			"a due entry should be on the CRL once the sweep has run")
	})

	It("logs a pass that failed as failed", func() {
		c, store, be := newPutFailingTestCA(storage.KeySuperseded)
		seedDueSupersession(store, "due-node", big.NewInt(0xABCDF1))
		be.fail.Store(true)

		out := captureLogs(slog.LevelInfo, func() { sweepSupersededOnce(context.Background(), c) })
		Expect(out).To(ContainSubstring("Superseded-certificate revocation sweep failed"))
		Expect(out).NotTo(ContainSubstring("stopped by shutdown"))
	})

	// The OpenVoxCASupersedeFailing runbook reads the sweep's warning as a
	// storage fault, so a pass that a shutdown ended must not emit it.
	It("logs a pass that a shutdown ended as stopped, not failed", func() {
		c, store := newRefresherTestCA()
		seedDueSupersession(store, "due-node", big.NewInt(0xABCDF0))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		out := captureLogs(slog.LevelInfo, func() { sweepSupersededOnce(ctx, c) })
		Expect(out).To(ContainSubstring("stopped by shutdown"))
		Expect(crlLists(store, big.NewInt(0xABCDF0))).To(BeFalse(),
			"a pass the shutdown ended before its first step revoked nothing")
		Expect(out).NotTo(ContainSubstring("sweep failed"))
	})
})

// runSupersededSweeper must drain at startup rather than waiting a full
// interval, and return promptly once its context is cancelled. The startup pass
// is the one that matters most: it is what clears a backlog that came due while
// every replica was down, which for this feature means certificates that have
// been outliving their window the longest.
var _ = Describe("runSupersededSweeper", func() {
	It("sweeps at startup and returns after context cancellation", func() {
		c, store := newRefresherTestCA()
		serial := big.NewInt(0x123456)
		seedDueSupersession(store, "due-node", serial)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			// An interval far longer than the spec's lifetime, so anything
			// observed here came from the startup pass and not from a tick.
			runSupersededSweeper(ctx, c, time.Hour)
			close(done)
		}()

		Eventually(func() bool {
			return crlLists(store, serial)
		}).WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			Should(BeTrue(), "startup sweep did not run within 2s")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runSupersededSweeper did not return after context cancellation")
	})

	// The default configuration reaches time.NewTicker with whatever
	// supersededCertSweepInterval() returns, and NewTicker panics on a
	// non-positive duration. Nothing else in the suite runs the sweeper with the
	// real default, so this is what stops a resolver regression taking every
	// deployment down at startup.
	It("survives the interval the default configuration resolves to", func() {
		c, _ := newRefresherTestCA()
		interval := (&serverConfig{}).supersededCertSweepInterval()
		Expect(interval).To(BeNumerically(">", 0),
			"the default sweep interval must be positive; time.NewTicker panics otherwise")

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			runSupersededSweeper(ctx, c, interval)
			close(done)
		}()
		cancel()
		Eventually(done).WithTimeout(2 * time.Second).Should(BeClosed())
	})
})
