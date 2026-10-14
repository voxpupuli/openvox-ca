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

package ca_test

import (
	"bytes"
	"context"
	"log/slog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The storage layer classes a missing inventory value as a first bootstrap
// only when the store has no CRL and an empty inventory. That is true of a new
// CA only because CA.Init verifies the inventory before bootstrapCA writes the
// CRL. The storage specs pin the classification over hand-built stores; these
// pin the premise, through Init itself, in both directions: a reordering would
// make every new CA warn, and a bootstrap that stopped writing the CRL would
// let a CA that has signed nothing re-baseline a deleted value at Info.
var _ = Describe("Inventory baseline level across CA.Init", func() {
	const infoLine = `level=INFO msg="No inventory HMAC found; initializing integrity baseline"`
	const warnLine = `level=WARN msg="No inventory HMAC found on an established CA`

	var (
		ctx  context.Context
		dir  string
		logs *bytes.Buffer
	)

	BeforeEach(func() {
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		logs = &bytes.Buffer{}
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	initCA := func() {
		myCA := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
	}

	It("logs at Info, not Warn, when it bootstraps a brand-new CA", func() {
		initCA()

		Expect(logs.String()).To(ContainSubstring("No existing CA found, bootstrapping new CA"),
			"fixture: this start did not bootstrap")
		Expect(logs.String()).To(ContainSubstring(infoLine))
		Expect(logs.String()).NotTo(ContainSubstring(warnLine))
	})

	It("warns on a later start when the value has gone, though the CA has signed nothing", func() {
		initCA()
		Expect(storage.New(dir).Backend().Delete(ctx, storage.KeyInventoryHMAC)).To(Succeed())
		logs.Reset()

		initCA()

		Expect(logs.String()).To(ContainSubstring(warnLine))
		Expect(logs.String()).To(ContainSubstring("inventory_empty=true"))
		Expect(logs.String()).To(ContainSubstring("crl_present=true"))
		Expect(logs.String()).NotTo(ContainSubstring(infoLine))
	})
})
