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

package storage

import (
	"bytes"
	"context"
	"log/slog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The re-baseline on a missing integrity value is the cheapest bypass the
// inventory MAC has, so how loudly it happens is the operator's only signal
// that it did. These specs pin the level on each branch, on both schemes: the
// branch reads the inventory differently for each, and a test on one would
// leave the other free to call every store new.
var _ = Describe("Establishing an inventory baseline when none is stored", func() {
	ctx := context.Background()

	const infoLine = `level=INFO msg="No inventory HMAC found; initializing integrity baseline"`
	const warnLine = `level=WARN msg="No inventory HMAC found on an established CA`

	var logs *bytes.Buffer

	BeforeEach(func() {
		logs = &bytes.Buffer{}
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	// A store as CA.Init finds it on its very first start: the inventory
	// touched and empty, no CRL yet, and the HMAC key just minted.
	freshFilesystem := func() *StorageService {
		svc := New(GinkgoT().TempDir())
		Expect(svc.EnsureDirs(ctx)).To(Succeed())
		Expect(svc.TouchInventory(ctx)).To(Succeed())
		return svc
	}
	freshSQLite := func() *StorageService {
		svc := NewWithBackend(newSQLiteBackend(), "")
		Expect(svc.TouchInventory(ctx)).To(Succeed())
		return svc
	}

	// verifyAndExpectBaseline runs the verifier against a store with no stored
	// value and checks that it wrote one which verifies, so that a spec pinning
	// a level cannot pass on a branch that has stopped writing the baseline.
	verifyAndExpectBaseline := func(svc *StorageService) {
		_, err := svc.backend.Get(ctx, KeyInventoryHMAC)
		Expect(err).To(HaveOccurred(), "fixture: an integrity value is already stored")

		key, err := svc.EnsureHMACKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(Succeed())

		rep, err := svc.InventoryIntegrityReport(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rep.Verifies).To(BeTrue(), "the baseline written does not verify")
	}

	DescribeTable("logs at Info on a first bootstrap: no CRL and an empty inventory",
		func(fresh func() *StorageService) {
			svc := fresh()
			verifyAndExpectBaseline(svc)

			Expect(logs.String()).To(ContainSubstring(infoLine))
			Expect(logs.String()).NotTo(ContainSubstring("level=WARN"),
				"a first bootstrap warned: %s", logs.String())
		},
		Entry("whole-blob scheme (filesystem)", freshFilesystem),
		Entry("hash-chain scheme (SQLite)", freshSQLite),
	)

	DescribeTable("warns when the inventory holds entries",
		func(fresh func() *StorageService) {
			svc := fresh()
			// Entries recorded under a baseline, which is then removed: the
			// bypass itself. No CRL, so the entries alone must decide it.
			Expect(svc.InitHMAC(ctx)).To(Succeed())
			for _, line := range sampleInventoryLines {
				Expect(svc.AppendInventory(ctx, line)).To(Succeed())
			}
			Expect(svc.backend.Delete(ctx, KeyInventoryHMAC)).To(Succeed())
			exists, err := svc.backend.Exists(ctx, KeyCRL)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse(), "fixture: a CRL is stored, so the entries are not what decides")
			logs.Reset()

			verifyAndExpectBaseline(svc)

			Expect(logs.String()).To(ContainSubstring(warnLine))
			Expect(logs.String()).To(ContainSubstring("inventory_empty=false"))
			Expect(logs.String()).NotTo(ContainSubstring(infoLine))
		},
		Entry("whole-blob scheme (filesystem)", freshFilesystem),
		Entry("hash-chain scheme (SQLite)", freshSQLite),
	)

	DescribeTable("warns when a CRL is stored, even over an empty inventory",
		func(fresh func() *StorageService) {
			// A CA that has signed nothing: bootstrapped (so a CRL exists) but
			// its inventory is empty, since the CA's own certificate is never
			// recorded there. Emptying the inventory and deleting the value
			// must not make an established CA look new.
			svc := fresh()
			Expect(svc.UpdateCRL(ctx, []byte("-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n"))).To(Succeed())

			verifyAndExpectBaseline(svc)

			Expect(logs.String()).To(ContainSubstring(warnLine))
			Expect(logs.String()).To(ContainSubstring("inventory_empty=true"))
			Expect(logs.String()).To(ContainSubstring("crl_present=true"))
			Expect(logs.String()).NotTo(ContainSubstring(infoLine))
		},
		Entry("whole-blob scheme (filesystem)", freshFilesystem),
		Entry("hash-chain scheme (SQLite)", freshSQLite),
	)
})
