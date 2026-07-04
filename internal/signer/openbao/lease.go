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

package openbao

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/openbao/openbao/api/v2"
)

// reauthRetryInterval bounds how often run() retries a failed
// re-authentication (e.g. OpenBao is temporarily unreachable — restarting,
// a network blip) before trying again, so a transient outage self-heals
// without busy-looping requests at OpenBao.
const reauthRetryInterval = 5 * time.Second

// TokenManager owns an OpenBao client's token lifecycle: it logs in once at
// construction, then runs a background goroutine that proactively renews the
// token via the SDK's LifetimeWatcher and, when renewal ends (expiry,
// revocation, hitting max_ttl, or a persistent error), immediately
// re-authenticates from source credentials rather than giving up. Sign/Public
// callers can also force an immediate re-authentication via Reauth when a
// request fails with 403, so a token revoked out-of-band is recovered from
// without waiting for the watcher to notice.
//
// This is the piece that specifically avoids the failure mode of reading an
// OpenBao token once at startup and never refreshing or re-deriving it.
type TokenManager struct {
	client *api.Client
	login  func(ctx context.Context) (*api.Secret, error)

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex // serialises login/watcher swaps
	watcher *api.LifetimeWatcher

	doneCh chan struct{} // closed once the background loop has exited
}

// NewTokenManager builds an OpenBao client from cfg, performs the initial
// login (bounded by cfg.loginTimeout()), and starts the background renewal
// loop. The manager's internal context is derived from ctx but outlives the
// call to NewTokenManager; callers must call Close when done to release it.
func NewTokenManager(ctx context.Context, cfg Config) (*TokenManager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}

	loginFn, err := newLoginFunc(client, cfg)
	if err != nil {
		return nil, err
	}

	tmCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	tm := &TokenManager{
		client: client,
		login:  loginFn,
		ctx:    tmCtx,
		cancel: cancel,
		doneCh: make(chan struct{}),
	}

	loginCtx, loginCancel := context.WithTimeout(tmCtx, cfg.loginTimeout())
	defer loginCancel()
	secret, err := tm.login(loginCtx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("initial OpenBao login failed: %w", err)
	}

	watcher, err := client.NewLifetimeWatcher(&api.LifetimeWatcherInput{Secret: secret})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("starting OpenBao token lifetime watcher: %w", err)
	}
	tm.watcher = watcher

	go tm.run()
	return tm, nil
}

// newLoginFunc returns the auth-method-specific login step. AppRole and
// Kubernetes go through a fresh AuthMethod (see authMethodFactory) and
// client.Auth().Login, which also sets the client's token on success. Token
// auth has no /login exchange: it reads the token file directly, sets it on
// the client, and looks itself up to obtain lease/renewable metadata for the
// LifetimeWatcher.
func newLoginFunc(client *api.Client, cfg Config) (func(ctx context.Context) (*api.Secret, error), error) {
	switch cfg.AuthMethod {
	case AuthToken:
		tokenFile := cfg.TokenFile
		return func(ctx context.Context) (*api.Secret, error) {
			tok, err := readFirstLine(tokenFile)
			if err != nil {
				return nil, fmt.Errorf("reading openbao.token_file: %w", err)
			}
			client.SetToken(tok)
			secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
			if err != nil {
				return nil, fmt.Errorf("looking up OpenBao token: %w", err)
			}
			return secret, nil
		}, nil
	case AuthAppRole, AuthKubernetes:
		factory, err := newAuthMethodFactory(cfg)
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context) (*api.Secret, error) {
			method, err := factory()
			if err != nil {
				return nil, fmt.Errorf("building OpenBao auth method: %w", err)
			}
			secret, err := client.Auth().Login(ctx, method)
			if err != nil {
				return nil, fmt.Errorf("logging in to OpenBao: %w", err)
			}
			return secret, nil
		}, nil
	default:
		return nil, fmt.Errorf("unknown openbao.auth_method %q", cfg.AuthMethod)
	}
}

// run is the background loop. The outer iteration owns one watcher: it
// starts it once, then keeps selecting on RenewCh (proactive renewals, which
// don't change the underlying watcher) until DoneCh fires (renewal ended for
// any reason), at which point it re-authenticates and loops to start a fresh
// watcher around the new secret. Exits when Close cancels tm.ctx.
func (tm *TokenManager) run() {
	defer close(tm.doneCh)
	for {
		tm.mu.Lock()
		watcher := tm.watcher
		tm.mu.Unlock()

		go watcher.Start()

		if !tm.watchOne(watcher) {
			return
		}

		for {
			err := tm.reauthAndRewatch(tm.ctx)
			if err == nil {
				break
			}
			if tm.ctx.Err() != nil {
				return
			}
			slog.Error("OpenBao re-authentication failed, retrying",
				"error", err, "retry_in", reauthRetryInterval)
			if !sleepOrDone(tm.ctx, reauthRetryInterval) {
				return
			}
		}
	}
}

// sleepOrDone waits for d or until ctx is cancelled, reporting which
// happened first (true = the timer fired, false = ctx was cancelled).
func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// watchOne selects on watcher's channels until either DoneCh fires (returns
// true: caller should re-authenticate and start a new watcher) or tm.ctx is
// cancelled (returns false: caller should exit).
func (tm *TokenManager) watchOne(watcher *api.LifetimeWatcher) bool {
	for {
		select {
		case <-tm.ctx.Done():
			watcher.Stop()
			return false
		case renewal := <-watcher.RenewCh():
			slog.Debug("OpenBao token renewed", "lease_duration", renewal.Secret.LeaseDuration)
		case err := <-watcher.DoneCh():
			if err != nil {
				slog.Warn("OpenBao token renewal ended, re-authenticating", "error", err)
			} else {
				slog.Info("OpenBao token renewal window closed, re-authenticating")
			}
			return true
		}
	}
}

// reauthAndRewatch performs a fresh login and replaces the current watcher.
// Safe to call concurrently with itself (e.g. a reactive Reauth racing the
// background loop's own re-auth); only one login/watcher swap proceeds at a
// time.
func (tm *TokenManager) reauthAndRewatch(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	loginCtx, cancel := context.WithTimeout(ctx, defaultLoginTimeout)
	defer cancel()

	secret, err := tm.login(loginCtx)
	if err != nil {
		return err
	}

	if tm.watcher != nil {
		tm.watcher.Stop()
	}
	watcher, err := tm.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{Secret: secret})
	if err != nil {
		return fmt.Errorf("starting OpenBao token lifetime watcher: %w", err)
	}
	tm.watcher = watcher
	return nil
}

// Reauth forces an immediate re-authentication, bypassing the proactive
// renewal schedule. Callers use this when a Transit request itself fails
// with 403 (token revoked out-of-band, clock skew causing early expiry,
// etc.) so the CA recovers within a single retried request rather than
// waiting for the background watcher to notice on its own schedule.
//
// Note this races with (and may duplicate work done by) run()'s own
// re-authentication if both trigger around the same time; reauthAndRewatch's
// lock makes that safe, just occasionally redundant.
func (tm *TokenManager) Reauth(ctx context.Context) error {
	return tm.reauthAndRewatch(ctx)
}

// Client returns the managed OpenBao client. Its token is kept current by
// the background renewal loop and by Reauth.
func (tm *TokenManager) Client() *api.Client {
	return tm.client
}

// Close stops the background renewal loop and the current watcher, and
// waits for the loop to exit.
func (tm *TokenManager) Close() error {
	tm.cancel()
	<-tm.doneCh
	return nil
}
