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
	"log/slog"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

// newOpenBaoKeyProvider builds an OpenBao Transit-backed ca.KeyProvider from
// cfg's openbao.* settings: it authenticates to OpenBao (AppRole, a static
// token file, or Kubernetes auth per openbao.auth_method) and starts the
// background token-renewal loop (internal/signer/openbao.TokenManager)
// before the CA ever calls Init.
//
// This is only ever called in a process that actually holds/reaches the CA
// key: the isolated signer child (runSignerMode) or the single-process role.
// The frontend role never calls this — it talks to whichever of those two
// via the existing signer.RemoteSigner RPC instead, exactly as it does for a
// local (file-backed) key.
//
// The returned TokenManager must be closed by the caller (deferred) so its
// background renewal goroutine and OpenBao client are cleaned up on
// shutdown.
func newOpenBaoKeyProvider(ctx context.Context, cfg *serverConfig) (*openbao.TokenManager, ca.KeyProvider, error) {
	openBaoCfg, err := cfg.ToOpenBaoConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("invalid OpenBao configuration: %w", err)
	}

	slog.Info("Authenticating to OpenBao",
		"addr", openBaoCfg.Addr, "auth_method", string(openBaoCfg.AuthMethod), "key", openBaoCfg.KeyName)
	tm, err := openbao.NewTokenManager(ctx, openBaoCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to OpenBao: %w", err)
	}

	provider := openbao.NewKeyProvider(tm, openBaoCfg.EffectiveTransitMount(), openBaoCfg.KeyName)
	return tm, provider, nil
}
