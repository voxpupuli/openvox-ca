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
	"os"

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

	It("rejects an invalid key provider configuration before opening anything", func() {
		dir := GinkgoT().TempDir()
		cfg := &serverConfig{CADir: dir}
		cfg.CAKeyProvider = "nonsense"
		_, err := resolveRuntime(ctx, cfg, true)
		Expect(err).To(MatchError(ContainSubstring("nonsense")),
			"the error must name the provider that was rejected")

		// "before opening anything" is half the claim, and the half a later
		// refactor is most likely to break by moving Validate() below the
		// storage construction. Nothing may have been created in the cadir.
		entries, readErr := os.ReadDir(dir)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty(), "validation must run before any backend is opened")
	})
})
