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
	"fmt"
	"path/filepath"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// caRuntime is the storage and key-provider pair described by a resolved
// server configuration: everything an operation needs to reach this CA's
// material, short of running an HTTP listener.
//
// It exists so that offline subcommands reach the configured backend and key
// provider through exactly the same code the server uses. The alternative —
// each subcommand assembling its own storage and provider — is how a CLI ends
// up quietly supporting a different subset of backends from the daemon, which
// is the failure mode openvox-ca-ctl already has (it can only ever address a
// local filesystem directory).
type caRuntime struct {
	// Store is the storage service for the configured backend.
	Store *storage.StorageService
	// KeyProvider is non-nil only when ca_key_provider names one. A nil
	// provider means the CA key is a local PEM blob reached through Store.
	KeyProvider ca.KeyProvider

	closers []func() error
}

// Close releases everything resolveRuntime opened, in reverse order. Safe to
// call on a partially-constructed runtime.
func (r *caRuntime) Close() error {
	var firstErr error
	for i := len(r.closers) - 1; i >= 0; i-- {
		if err := r.closers[i](); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// resolveRuntime builds the storage service and, when one is configured, the CA
// key provider, from an already-resolved server configuration.
//
// Configuration *loading* is deliberately not part of this: the server and each
// subcommand expose different flag sets, so they resolve cfg themselves and
// hand the result here. What this owns is the part that must not vary —
// backend-spec construction and provider wiring.
//
// withKeyProvider is explicit at every call site rather than inferred, because
// the distinction is security-relevant: the frontend role must not reach the CA
// key, and a caller that silently got a provider it should not have would open
// an authenticated session to the key backend without anything failing.
//
// The caller must Close the returned runtime.
func resolveRuntime(ctx context.Context, cfg *serverConfig, withKeyProvider bool) (*caRuntime, error) {
	if cfg.CADir == "" {
		return nil, fmt.Errorf("cadir is required (set --cadir, PUPPET_CA_CADIR, or cadir in the config file)")
	}
	absCADir, err := filepath.Abs(cfg.CADir)
	if err != nil {
		return nil, fmt.Errorf("resolving cadir: %w", err)
	}

	if err := cfg.CAKeyProviderConfig.Validate(); err != nil {
		return nil, err
	}

	rt := &caRuntime{}

	backendSpec, err := buildBackendSpec(cfg, absCADir)
	if err != nil {
		return nil, fmt.Errorf("invalid storage backend config: %w", err)
	}
	store, err := storage.NewServiceFromSpec(backendSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to initialise storage backend: %w", err)
	}
	rt.Store = store
	rt.closers = append(rt.closers, store.Backend().Close)

	if withKeyProvider && cfg.UsesOpenBao() {
		tm, provider, err := newOpenBaoKeyProvider(ctx, cfg)
		if err != nil {
			_ = rt.Close()
			return nil, fmt.Errorf("initialising OpenBao key provider: %w", err)
		}
		rt.KeyProvider = provider
		rt.closers = append(rt.closers, tm.Close)
	}

	return rt, nil
}

// roleMayReachCAKey reports whether a process running as role is permitted to
// construct a CA key provider of its own.
//
// Only the frontend is not. It proxies every signature to the isolated signer
// process, so opening its own authenticated session to the key backend would
// give it reach over a key it is specifically not allowed to use. Every other
// role — the signer, and the empty single-process role — needs the key.
//
// A named function rather than an inline `role != "frontend"` so the predicate
// can be tested directly. The half that can regress is the mapping, not
// resolveRuntime's handling of the boolean, and an inverted or mistyped
// comparison at the call site would silently hand the frontend the key.
func roleMayReachCAKey(role string) bool {
	return role != "frontend"
}
