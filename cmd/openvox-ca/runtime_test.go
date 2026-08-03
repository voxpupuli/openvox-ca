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
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("resolveRuntime", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("requires a cadir", func() {
		_, err := resolveRuntime(ctx, &serverConfig{}, false)
		Expect(err).To(MatchError(ContainSubstring("cadir is required")))
	})

	It("builds a storage service that Close releases", func() {
		rt, err := resolveRuntime(ctx, &serverConfig{CADir: GinkgoT().TempDir()}, true)
		Expect(err).NotTo(HaveOccurred())
		Expect(rt.Store).NotTo(BeNil())
		Expect(rt.Close()).To(Succeed())
	})

	It("leaves KeyProvider nil when no provider is configured", func() {
		// A nil provider means the CA key is a local PEM blob reached through
		// Store; nothing should fabricate one.
		rt, err := resolveRuntime(ctx, &serverConfig{CADir: GinkgoT().TempDir()}, true)
		Expect(err).NotTo(HaveOccurred())
		defer func() { Expect(rt.Close()).To(Succeed()) }()
		Expect(rt.KeyProvider).To(BeNil())
	})

	It("builds no key provider when withKeyProvider is false, even with OpenBao configured", func() {
		// This is the refactor's security contract. The frontend role proxies
		// every signature to the isolated signer process; constructing a
		// provider here would open a second authenticated session to the key
		// backend for a key this process is specifically not allowed to use.
		//
		// The address is deliberately unreachable: if the gate ever stops
		// holding, this spec fails on a connection error rather than passing
		// quietly, which is the right way round.
		cfg := &serverConfig{CADir: GinkgoT().TempDir()}
		cfg.CAKeyProvider = "openbao"
		cfg.OpenBao.Addr = "http://127.0.0.1:1"
		cfg.OpenBao.KeyName = "openvox-ca"
		cfg.OpenBao.AuthMethod = "token"
		Expect(cfg.UsesOpenBao()).To(BeTrue())

		rt, err := resolveRuntime(ctx, cfg, false)
		Expect(err).NotTo(HaveOccurred())
		defer func() { Expect(rt.Close()).To(Succeed()) }()
		Expect(rt.KeyProvider).To(BeNil())
	})

	It("rejects an invalid key provider configuration", func() {
		dir := GinkgoT().TempDir()
		cfg := &serverConfig{CADir: dir}
		cfg.CAKeyProvider = "nonsense"
		_, err := resolveRuntime(ctx, cfg, true)
		Expect(err).To(MatchError(ContainSubstring("nonsense")),
			"the error must name the provider that was rejected")

		// Deliberately no assertion that "nothing was opened". There is no
		// observable side effect to hang one on: the filesystem backend only
		// constructs a struct, and even sqlite does not touch its DSN until
		// first use, so any such assertion passes whether validation runs
		// before or after storage construction. Claiming to pin the ordering
		// while proving nothing is worse than not claiming it.
	})
})

var _ = Describe("roleMayReachCAKey", func() {
	// The gate itself is asserted against resolveRuntime elsewhere; this pins
	// the mapping feeding it, which is the half a typo or an inversion breaks.
	DescribeTable("decides which roles may construct a key provider",
		func(role string, want bool) {
			Expect(roleMayReachCAKey(role)).To(Equal(want))
		},
		Entry("the frontend proxies signatures and must never hold the key", "frontend", false),
		Entry("the signer is the process the key exists for", "signer", true),
		Entry("the empty role is single-process, which signs for itself", "", true),
		Entry("an unrecognised role is not the frontend, so it is not the special case", "worker", true),
	)
})

var _ = Describe("reportResolvedConfig", func() {
	// The whole point is that an operator can see a mismatch before the parent
	// signs anything, so the line has to name what was resolved -- including
	// when nothing was found, which is the case that bites.
	It("names the resolved file, backend and provider", func() {
		cfg := &serverConfig{CADir: "/var/lib/ca"}
		cfg.StorageBackend = "postgres"
		cfg.CAKeyProvider = "openbao"

		var out bytes.Buffer
		reportResolvedConfig(&out, "/etc/puppet-ca/config.yaml", cfg)
		Expect(out.String()).To(ContainSubstring("/etc/puppet-ca/config.yaml"))
		Expect(out.String()).To(ContainSubstring("postgres"))
		Expect(out.String()).To(ContainSubstring("openbao"))
		Expect(out.String()).To(ContainSubstring("/var/lib/ca"))
	})

	It("says so when no config file was found, and names the defaults it fell back to", func() {
		// The dangerous case: a server configured entirely by flags leaves these
		// commands on defaults, and "file" instead of "openbao" here is the
		// signal that the request would be bound to the wrong key.
		cfg := &serverConfig{CADir: "/var/lib/ca"}

		var out bytes.Buffer
		reportResolvedConfig(&out, "", cfg)
		Expect(out.String()).To(ContainSubstring("none found"))
		Expect(out.String()).To(ContainSubstring("filesystem"))
		Expect(out.String()).To(ContainSubstring("CA key provider: file"))
	})
})
