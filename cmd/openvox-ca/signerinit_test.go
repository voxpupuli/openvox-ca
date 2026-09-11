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
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// What the isolated signer keeps once it is running, which is the whole of
// #306. It opens a storage backend because bootstrapping the CA is its job --
// it is the process holding the key -- and then answers one RPC,
// Sign(digest), for the rest of the process lifetime. Between those two facts
// sits a backend handle, a connection pool and the indexes ca.Init builds, and
// nothing reads any of them again.
var _ = Describe("initSignerKeyWith", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})

	// SQLite rather than the filesystem backend, and the choice is load-bearing
	// rather than incidental: FilesystemBackend.Close is `return nil`, so a
	// closed filesystem store is indistinguishable from an open one and every
	// assertion below would pass against a version of initSignerKeyWith that
	// closed nothing at all. SQLBackend.Close releases the pool, and the pool
	// is what #306 is actually about -- a signer that keeps one spends the
	// database's max_connections, not this process's memory.
	//
	// ECDSA P-256 because bootstrap mints a real CA key here and the default is
	// RSA; the algorithm has no bearing on what is being asserted.
	signerConfig := func() *serverConfig {
		dir := GinkgoT().TempDir()
		cfg := &serverConfig{
			CADir:    dir,
			Hostname: "ca.example.test",
			StorageConfig: config.StorageConfig{
				StorageBackend: "sqlite",
				SQLDSN:         filepath.Join(dir, "ca.db"),
			},
		}
		cfg.CAKeyAlgo = "ecdsa"
		cfg.CAKeySize = 256
		return cfg
	}

	// The real resolver, with one closer added to the key-lifetime group so a
	// spec can watch it. There is nothing in that group under a local PEM key,
	// which is exactly why the Transit regression is invisible: with no key
	// closer to run, closing the whole runtime and closing only its store half
	// produce identical observable behaviour.
	resolverNoting := func(ran *bool) runtimeResolver {
		return func(ctx context.Context, cfg *serverConfig) (*caRuntime, error) {
			rt, err := resolveRuntime(ctx, cfg, true)
			if err != nil {
				return nil, err
			}
			rt.keyClosers = append(rt.keyClosers, func() error {
				*ran = true
				return nil
			})
			return rt, nil
		}
	}

	It("has closed the store by the time it returns the key", func() {
		// The claim in the issue, stated as something that can fail. Before the
		// change the backend stayed open until runSignerMode returned, which
		// for a signer that is serving means until the process exits.
		//
		// A closed *sql.DB reports it on use, so this reads the state rather
		// than a flag standing in for it.
		var keyCloserRan bool
		cfg := signerConfig()

		key, rt, err := initSignerKeyWith(ctx, cfg, resolverNoting(&keyCloserRan))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = rt.Close() })
		Expect(key).NotTo(BeNil())

		_, err = rt.Store.HasCACert(ctx)
		Expect(err).To(MatchError(ContainSubstring("database is closed")),
			"the signer must not still be holding an open backend handle once Init has returned")
	})

	It("leaves the key provider's session open", func() {
		// The other half, and the half that a simpler fix gets wrong. Moving
		// the deferred Close earlier would release the store *and* the token
		// manager an OpenBao Transit key is signed through, producing a signer
		// that comes up, announces itself ready, and fails on its first
		// signature -- in the one deployment shape no test here configures.
		var keyCloserRan bool
		cfg := signerConfig()

		_, rt, err := initSignerKeyWith(ctx, cfg, resolverNoting(&keyCloserRan))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = rt.Close() })

		Expect(keyCloserRan).To(BeFalse(),
			"a key-lifetime closer must outlive initialisation; the signer signs with it")
	})

	It("returns a key that still signs with no store behind it", func() {
		// "The store is closed" is only worth having if the process can still
		// do its job afterwards. signer.Serve takes a crypto.Signer and nothing
		// else, so this is the entire steady state of the signer process.
		var keyCloserRan bool
		cfg := signerConfig()

		key, rt, err := initSignerKeyWith(ctx, cfg, resolverNoting(&keyCloserRan))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = rt.Close() })

		digest := sha256.Sum256([]byte("a certificate to be"))
		sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
		Expect(err).NotTo(HaveOccurred())
		Expect(sig).NotTo(BeEmpty())
	})

	It("still runs the key-lifetime closers on Close", func() {
		// CloseStore empties the store group; Close must not be left with
		// nothing to do. Without this, "the key closer did not run" above is
		// satisfied just as well by a runtime that never runs it at all.
		var keyCloserRan bool
		cfg := signerConfig()

		_, rt, err := initSignerKeyWith(ctx, cfg, resolverNoting(&keyCloserRan))
		Expect(err).NotTo(HaveOccurred())

		Expect(rt.Close()).To(Succeed())
		Expect(keyCloserRan).To(BeTrue())
	})

	It("serves anyway when the store will not close, and says so", func() {
		// The branch the code itself calls out as consequential: refusing to
		// serve because a handle nobody will use again closed untidily would
		// turn a leak into an outage. Nothing drove it -- signerinit's backend
		// is a working SQLite pool whose Close always succeeds -- so a
		// regression making the failure fatal would have gone unnoticed.
		//
		// A closer that fails, prepended so it runs before the real backend's
		// and supplies the first error runClosers returns.
		var keyCloserRan bool
		cfg := signerConfig()
		boom := errors.New("backend refused to close")
		resolve := func(ctx context.Context, cfg *serverConfig) (*caRuntime, error) {
			rt, err := resolverNoting(&keyCloserRan)(ctx, cfg)
			if err != nil {
				return nil, err
			}
			rt.storeClosers = append(rt.storeClosers, func() error { return boom })
			return rt, nil
		}

		var key crypto.Signer
		var rt *caRuntime
		var err error
		logs := captureLogs(slog.LevelDebug, func() {
			key, rt, err = initSignerKeyWith(ctx, cfg, resolve)
		})

		Expect(err).NotTo(HaveOccurred(), "a failed store close must not stop the signer serving")
		Expect(key).NotTo(BeNil())
		DeferCleanup(func() { _ = rt.Close() })

		Expect(logs).To(ContainSubstring("Failed to close the signer's storage backend"),
			"the failure must not be swallowed silently")
		Expect(logs).To(ContainSubstring("store_closed=false"),
			"the release line must report what actually happened, not a constant")
	})

	It("reports the store as closed when it closed", func() {
		// The other half. Without it, "store_closed=false" above is satisfied
		// just as well by a field wired to a constant false.
		var keyCloserRan bool
		cfg := signerConfig()

		var rt *caRuntime
		var err error
		logs := captureLogs(slog.LevelDebug, func() {
			_, rt, err = initSignerKeyWith(ctx, cfg, resolverNoting(&keyCloserRan))
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = rt.Close() })

		Expect(logs).To(ContainSubstring("store_closed=true"))
		Expect(logs).NotTo(ContainSubstring("Failed to close the signer's storage backend"))
	})

	It("closes the runtime when initialisation fails", func() {
		// The error path owns the runtime it resolved: nothing else has a
		// reference to hand back, so a return without a Close here leaks both
		// groups.
		var keyCloserRan bool
		cfg := signerConfig()
		// Rejected by applyCAConfig before anything is initialised, so the
		// failure lands after the runtime exists and before the CA does.
		cfg.CAKeyAlgo = "nonsense"

		key, rt, err := initSignerKeyWith(ctx, cfg, resolverNoting(&keyCloserRan))
		Expect(err).To(HaveOccurred())
		Expect(key).To(BeNil())
		Expect(rt).To(BeNil())
		Expect(keyCloserRan).To(BeTrue(), "a failed initialisation must not strand the key provider's session")
	})
})
