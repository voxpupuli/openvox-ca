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
	"crypto"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
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

// stubProvider stands in for a reachable key backend. resolveRuntime only ever
// stores the provider, so neither method is called from these specs; they exist
// to satisfy ca.KeyProvider, and they fail rather than return a usable key so
// that a spec which starts exercising them cannot pass by accident.
type stubProvider struct{}

func (stubProvider) Load(context.Context) (crypto.Signer, error) {
	return nil, errors.New("stubProvider.Load must not be called")
}

func (stubProvider) Generate(context.Context, ca.KeyConfig) (crypto.Signer, error) {
	return nil, errors.New("stubProvider.Generate must not be called")
}

var _ = Describe("resolveRuntime's key-provider branch", func() {
	// The one line the whole store/key split rests on, and the one nothing
	// could execute. resolveRuntime files the key session's closer in the
	// key-lifetime group; file it under storeClosers instead and CloseStore --
	// which the signer calls the moment ca.Init returns -- tears down the token
	// manager every subsequent signature goes through.
	//
	// Until newKeyProvider became a seam, no test in this repository reached
	// that assignment with a nil error. The two specs below that configure
	// OpenBao point at an unreachable address deliberately, so the provider
	// fails first; the OpenBao integration suite is behind a build tag and
	// never calls resolveRuntime at all. A mutation moving the append to
	// storeClosers therefore compiled and passed everything, while breaking
	// Transit in production on the first signature.

	openBaoCfg := func() *serverConfig {
		cfg := &serverConfig{CADir: GinkgoT().TempDir()}
		cfg.CAKeyProvider = "openbao"
		cfg.OpenBao.Addr = "http://127.0.0.1:1"
		cfg.OpenBao.KeyName = "openvox-ca"
		cfg.OpenBao.AuthMethod = "token"
		return cfg
	}

	// Substitutes the seam for the duration of one spec. The stub stands in for
	// a *reachable* key backend, which is the state no real configuration can
	// produce here -- not for a different kind of provider.
	stubKeyProvider := func(ran *bool) {
		original := newKeyProvider
		DeferCleanup(func() { newKeyProvider = original })
		newKeyProvider = func(_ context.Context, _ *serverConfig) (func() error, ca.KeyProvider, error) {
			return func() error {
				*ran = true
				return nil
			}, stubProvider{}, nil
		}
	}

	It("files the key session's closer where CloseStore will not reach it", func() {
		var closed bool
		stubKeyProvider(&closed)

		rt, err := resolveRuntime(context.Background(), openBaoCfg(), true)
		Expect(err).NotTo(HaveOccurred())
		Expect(rt.KeyProvider).NotTo(BeNil(), "the branch under test must actually have run")

		Expect(rt.CloseStore()).To(Succeed())
		Expect(closed).To(BeFalse(),
			"CloseStore must not release the key session the signer signs with")

		Expect(rt.Close()).To(Succeed())
		Expect(closed).To(BeTrue(), "Close must still release it")
	})

	It("does not build one when the role may not reach the key", func() {
		// Without this, the spec above passes just as well against a
		// resolveRuntime that ignores withKeyProvider and always builds a
		// provider -- which is the frontend holding the CA key.
		var closed bool
		stubKeyProvider(&closed)

		rt, err := resolveRuntime(context.Background(), openBaoCfg(), false)
		Expect(err).NotTo(HaveOccurred())
		defer func() { Expect(rt.Close()).To(Succeed()) }()
		Expect(rt.KeyProvider).To(BeNil())
		Expect(closed).To(BeFalse(), "nothing was opened, so nothing is closed")
	})
})

var _ = Describe("caRuntime closer groups", func() {
	// The split exists for one caller in one deployment shape: the isolated
	// signer under an OpenBao Transit provider, which is finished with the
	// store the moment ca.Init returns and is not finished with the token
	// manager backing its key until the process exits.
	//
	// Everything here is about which group a closer lands in and when it runs,
	// because a closer filed in the wrong group is invisible in every
	// configuration that has no key provider at all -- which is every
	// configuration in this suite except the ones that say otherwise.

	// Closers that record, so the assertions are about order rather than about
	// side effects some backend happens to have.
	recorded := func(log *[]string) *caRuntime {
		note := func(name string) func() error {
			return func() error {
				*log = append(*log, name)
				return nil
			}
		}
		return &caRuntime{
			// Two store closers, because a single one cannot tell "reverse
			// order" from "any order".
			storeClosers: []func() error{note("store-first"), note("store-second")},
			keyClosers:   []func() error{note("key")},
		}
	}

	It("preserves the order a single reversed list produced", func() {
		// resolveRuntime registers the backend before the key provider, so the
		// one list it used to build released the provider's session first and
		// the backend handle second. This is a regrouping and not a reordering:
		// a provider torn down after the store it was resolved alongside would
		// be a change to shutdown that nobody asked for and nothing else here
		// would notice.
		var log []string
		rt := recorded(&log)
		Expect(rt.Close()).To(Succeed())
		Expect(log).To(Equal([]string{"key", "store-second", "store-first"}))
	})

	It("leaves the key group running when only the store is closed", func() {
		// The Transit case in miniature, and the whole reason CloseStore is a
		// split rather than an earlier Close. Get it wrong and the signer still
		// comes up, still passes this suite, and fails on its first signature
		// in the one deployment that configures a key provider.
		var log []string
		rt := recorded(&log)
		Expect(rt.CloseStore()).To(Succeed())
		Expect(log).To(Equal([]string{"store-second", "store-first"}))
	})

	It("does not run the store group twice when Close follows CloseStore", func() {
		// The signer's actual sequence: CloseStore once Init returns, Close on
		// the way out. Closing a backend handle twice is usually harmless;
		// unlocking an instance lock twice is not, and holdInstanceLock files
		// one in this very group.
		var log []string
		rt := recorded(&log)
		Expect(rt.CloseStore()).To(Succeed())
		Expect(rt.Close()).To(Succeed())
		Expect(log).To(Equal([]string{"store-second", "store-first", "key"}))
	})

	It("runs every closer even when one fails, and reports the first failure", func() {
		// A backend that fails to close must not strand the key provider's
		// session, which is the resource that costs something to leak.
		var log []string
		boom := errors.New("backend close failed")
		rt := &caRuntime{
			storeClosers: []func() error{
				func() error { log = append(log, "store"); return boom },
			},
			keyClosers: []func() error{
				func() error { log = append(log, "key"); return nil },
			},
		}
		Expect(rt.Close()).To(MatchError(boom))
		Expect(log).To(Equal([]string{"key", "store"}))
	})

	It("is safe to close a runtime that was never built", func() {
		// resolveRuntime's own failure paths call Close on a partially
		// constructed runtime, and the zero value is the furthest that goes.
		rt := &caRuntime{}
		Expect(rt.CloseStore()).To(Succeed())
		Expect(rt.Close()).To(Succeed())
	})
})

var _ = Describe("resolveRuntimeForRole", func() {
	// The composition, not either half. resolveRuntime honouring its boolean and
	// roleMayReachCAKey's mapping are pinned separately; what neither can catch
	// is the two being wired together the wrong way round -- an inverted
	// argument, or a hardcoded true -- which is what would hand the frontend an
	// authenticated session to the key backend.
	//
	// The address is deliberately unreachable, so a role that *should* build a
	// provider fails loudly here rather than passing quietly.
	openBaoCfg := func() *serverConfig {
		cfg := &serverConfig{CADir: GinkgoT().TempDir()}
		cfg.CAKeyProvider = "openbao"
		cfg.OpenBao.Addr = "http://127.0.0.1:1"
		cfg.OpenBao.KeyName = "openvox-ca"
		cfg.OpenBao.AuthMethod = "token"
		return cfg
	}

	It("builds no key provider for the frontend role", func() {
		rt, err := resolveRuntimeForRole(context.Background(), openBaoCfg(), "frontend")
		Expect(err).NotTo(HaveOccurred())
		defer func() { Expect(rt.Close()).To(Succeed()) }()
		Expect(rt.KeyProvider).To(BeNil())
	})

	It("does try to build one for a role that may reach the key", func() {
		// Without this the spec above passes just as well against a call site
		// that never builds a provider for anyone.
		_, err := resolveRuntimeForRole(context.Background(), openBaoCfg(), "signer")
		Expect(err).To(MatchError(ContainSubstring("OpenBao")))
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
