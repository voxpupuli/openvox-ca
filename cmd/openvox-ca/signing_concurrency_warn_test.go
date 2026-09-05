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
	"bytes"
	"log/slog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// The whole value of this warning is that it fires on exactly one combination
// and stays quiet on the others, so each case is asserted rather than the
// happy path alone. A warning that fired for the isolated signer — the default
// topology, where a CPU-derived ceiling is the right shape — would be noise on
// every start, and noise is how a real warning stops being read.
var _ = Describe("the CPU-derived signing bound warning", func() {
	var buf bytes.Buffer

	BeforeEach(func() {
		buf.Reset()
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	cfgWith := func(provider string, configured int) *serverConfig {
		cfg := &serverConfig{CASigningConcurrency: configured}
		cfg.CAKeyProviderConfig = config.CAKeyProviderConfig{CAKeyProvider: provider}
		return cfg
	}

	It("warns when a Transit key gets a bound derived from CPU count", func() {
		warnIfSigningBoundIsCPUDerived(cfgWith("openbao", -1), 8)

		Expect(buf.String()).To(ContainSubstring("ca_signing_concurrency"))
		Expect(buf.String()).To(ContainSubstring("CPU count"))
		// The derived value is named, so an operator can see what they are
		// being asked to reconsider without going looking for it.
		Expect(buf.String()).To(ContainSubstring("ca_signing_concurrency=8"))
	})

	It("stays quiet when the operator set a value explicitly", func() {
		warnIfSigningBoundIsCPUDerived(cfgWith("openbao", 3), 3)
		Expect(buf.String()).To(BeEmpty(),
			"an operator who chose a number does not need to be told it was chosen")
	})

	// An explicit 0 is a deliberate opt-out of the bound entirely. It is still
	// a decision, so it must not be nagged about either.
	It("stays quiet when the bound was explicitly disabled", func() {
		warnIfSigningBoundIsCPUDerived(cfgWith("openbao", 0), 0)
		Expect(buf.String()).To(BeEmpty())
	})

	// The isolated signer is the default deployment. Signing is CPU-bound in
	// the signer child there, so GOMAXPROCS is the right shape and there is
	// nothing to correct.
	DescribeTable("stays quiet for a signer that is not reached over the network",
		func(provider string) {
			warnIfSigningBoundIsCPUDerived(cfgWith(provider, -1), 8)
			Expect(buf.String()).To(BeEmpty())
		},
		Entry("explicit file provider", "file"),
		Entry("unset provider, which means file", ""),
	)
})
