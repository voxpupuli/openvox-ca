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
	"errors"
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

// minReauthInterval is the minimum spacing between successive background
// watcher (re)starts. It bounds the pathological case where a token's
// LifetimeWatcher ends the instant it starts — e.g. a non-renewable token
// with no expiry (TTL 0), which has nothing to wait for — so run()
// re-authenticates on a steady cadence instead of busy-looping requests at
// OpenBao. A healthy token renews for far longer than this, so the throttle
// only ever engages when a watcher keeps ending immediately.
//
// It is also the minimum spacing between a request-path Reauth and the
// previous login attempt of any kind. A persistent 403 — a policy that no
// longer grants Transit access, say — is not cured by logging in again, and
// without this every signing attempt would become a fresh login against
// OpenBao and a fresh entry in its audit log.
const minReauthInterval = 30 * time.Second

// revokeTimeout bounds Close's best-effort revocation of a token this process
// minted. It is deliberately much shorter than the launcher's 5-second budget
// for a surviving child, so an unreachable OpenBao can delay exit by no more
// than this.
const revokeTimeout = 2 * time.Second

// ErrReauthThrottled is returned (wrapped) by Reauth when the previous login
// attempt was less than minReauthInterval ago. The request that saw the 403
// fails with it rather than waiting the interval out.
var ErrReauthThrottled = errors.New("OpenBao re-authentication throttled")

// errTokenManagerClosed is returned by Reauth after Close. Logging in then
// would mint a token that nothing will ever revoke.
var errTokenManagerClosed = errors.New("OpenBao token manager is closed")

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

	// ownsToken reports whether login mints the token (AppRole, Kubernetes),
	// as opposed to adopting one the operator supplied (token file). Only a
	// minted token is this process's to revoke: an operator's token may be
	// shared with other processes or replicas, and revoking it at shutdown
	// would cut every one of them off.
	ownsToken bool

	// loginTimeout bounds a single login/renew round trip (and, via
	// Signer.Sign, a single Transit sign round trip). Captured from
	// cfg.loginTimeout() at construction so every code path — the initial
	// login, background re-authentication, and reactive Reauth — honours the
	// operator's configured value rather than the built-in default.
	loginTimeout time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex // serialises login/watcher swaps
	watcher *api.LifetimeWatcher
	// lastLogin is when the most recent login attempt started, successful or
	// not; Reauth refuses to start another within minReauthInterval of it.
	// Guarded by mu.
	lastLogin time.Time
	// closed is set by Close, under mu, before it revokes the token.
	closed bool

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

	loginFn, ownsToken, err := newLoginFunc(client, cfg)
	if err != nil {
		return nil, err
	}

	tmCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	tm := &TokenManager{
		client:       client,
		login:        loginFn,
		ownsToken:    ownsToken,
		loginTimeout: cfg.loginTimeout(),
		ctx:          tmCtx,
		cancel:       cancel,
		doneCh:       make(chan struct{}),
	}

	loginCtx, loginCancel := context.WithTimeout(tmCtx, tm.loginTimeout)
	defer loginCancel()
	tm.lastLogin = time.Now()
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

// newLoginFunc returns the auth-method-specific login step, and whether the
// tokens it yields are minted by this process (see TokenManager.ownsToken).
// AppRole and Kubernetes go through a fresh AuthMethod (see
// authMethodFactory) and client.Auth().Login, which also sets the client's
// token on success. Token auth has no /login exchange: it reads the token
// file directly, sets it on the client, and looks itself up to obtain
// lease/renewable metadata for the LifetimeWatcher.
//
// Each case states ownership explicitly, so a method added later has to
// decide rather than inherit revocation by default.
func newLoginFunc(client *api.Client, cfg Config) (func(ctx context.Context) (*api.Secret, error), bool, error) {
	switch cfg.AuthMethod {
	case AuthToken:
		tokenFile := cfg.TokenFile
		return func(ctx context.Context) (*api.Secret, error) {
			tok, err := readFirstLine(tokenFile)
			if err != nil {
				return nil, fmt.Errorf("reading openbao.token_file: %w", err)
			}
			client.SetToken(tok)
			info, err := client.Auth().Token().LookupSelfWithContext(ctx)
			if err != nil {
				return nil, fmt.Errorf("looking up OpenBao token: %w", err)
			}
			// LookupSelf reports the token's lifetime in its Data map, not in
			// the auth/lease envelope NewLifetimeWatcher renews on: a raw
			// LookupSelf secret has no Auth block and an empty LeaseID, so the
			// watcher treats it as un-renewable, fires DoneCh immediately, and
			// run() busy-loops re-reading the file. Re-shape it into an auth
			// secret carrying the real TTL and renewable flag so the watcher
			// actually renews a renewable token and, for a non-renewable one,
			// waits until near expiry before we re-read the file.
			ttl, err := info.TokenTTL()
			if err != nil {
				return nil, fmt.Errorf("reading OpenBao token TTL: %w", err)
			}
			renewable, err := info.TokenIsRenewable()
			if err != nil {
				return nil, fmt.Errorf("reading OpenBao token renewability: %w", err)
			}
			return &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   tok,
					LeaseDuration: int(ttl.Seconds()),
					Renewable:     renewable,
				},
			}, nil
		}, false, nil
	case AuthAppRole, AuthKubernetes:
		factory, err := newAuthMethodFactory(cfg)
		if err != nil {
			return nil, false, err
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
		}, true, nil
	default:
		return nil, false, fmt.Errorf("unknown openbao.auth_method %q", cfg.AuthMethod)
	}
}

// run is the background loop. The outer iteration owns one watcher: it
// starts it once, then keeps selecting on RenewCh (proactive renewals, which
// don't change the underlying watcher) until DoneCh fires (renewal ended for
// any reason), at which point it re-authenticates and loops to start a fresh
// watcher around the new secret — unless a request-path Reauth has already
// done so, in which case it starts that watcher instead of logging in again.
// Exits when Close cancels tm.ctx.
func (tm *TokenManager) run() {
	defer close(tm.doneCh)
	var lastWatch time.Time
	for {
		// Never (re)start a watcher more often than minReauthInterval, so a
		// watcher that ends immediately (see minReauthInterval) throttles into
		// a steady re-auth cadence rather than a busy loop.
		if !lastWatch.IsZero() {
			if wait := minReauthInterval - time.Since(lastWatch); wait > 0 {
				if !sleepOrDone(tm.ctx, wait) {
					return
				}
			}
		}
		lastWatch = time.Now()

		tm.mu.Lock()
		watcher := tm.watcher
		tm.mu.Unlock()

		go watcher.Start()

		if !tm.watchOne(watcher) {
			return
		}

		// A request-path Reauth stops the watcher it replaces, which is what
		// ended this one. It has already logged in and left a fresh watcher in
		// tm.watcher, so start that rather than logging in a second time — and
		// start it now: the throttle above guards against a watcher that ends
		// on its own, and Reauth is throttled already.
		tm.mu.Lock()
		swapped := tm.watcher != watcher
		tm.mu.Unlock()
		if swapped {
			lastWatch = time.Time{}
			continue
		}

		attempts := 0
		for {
			err := tm.reauthAndRewatch(tm.ctx)
			if err == nil {
				if attempts > 0 {
					slog.Info("OpenBao re-authentication recovered", "attempts", attempts+1)
				}
				break
			}
			if tm.ctx.Err() != nil {
				return
			}
			attempts++
			// Log the first failure at Error so an outage is visible, then drop
			// to Debug for the sustained-retry stream: a prolonged outage
			// otherwise floods the log at Error every reauthRetryInterval. The
			// recovery is logged at Info above.
			if attempts == 1 {
				slog.Error("OpenBao re-authentication failed, retrying",
					"error", err, "retry_in", reauthRetryInterval)
			} else {
				slog.Debug("OpenBao re-authentication still failing, retrying",
					"error", err, "attempt", attempts, "retry_in", reauthRetryInterval)
			}
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
	return tm.reauthLocked(ctx)
}

// reauthLocked is reauthAndRewatch's body; the caller holds tm.mu.
func (tm *TokenManager) reauthLocked(ctx context.Context) error {
	loginCtx, cancel := context.WithTimeout(ctx, tm.loginTimeout)
	defer cancel()

	tm.lastLogin = time.Now()
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

// Reauth re-authenticates ahead of the proactive renewal schedule. Callers use
// this when a Transit request fails with 403 (token revoked out-of-band, clock
// skew causing early expiry, etc.) so the CA recovers within a single retried
// request rather than waiting for the background watcher to notice.
//
// rejected is the token the failed request was sent with. If the client
// already holds a different one, another request or the background loop has
// re-authenticated since, and Reauth returns nil without logging in so the
// caller simply retries — which is what keeps a burst of concurrent 403s to a
// single login.
//
// Otherwise it logs in, unless the previous login attempt of any kind started
// less than minReauthInterval ago. Then it returns an error wrapping
// ErrReauthThrottled straight away rather than waiting: a token that was
// minted moments ago and is already refused points at policy, not at the
// token, and another login would not help.
//
// Note this races with (and may duplicate work done by) run()'s own
// re-authentication if both trigger around the same time; tm.mu makes that
// safe, just occasionally redundant.
func (tm *TokenManager) Reauth(ctx context.Context, rejected string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.closed {
		return errTokenManagerClosed
	}
	if tm.client.Token() != rejected {
		return nil
	}
	if since := time.Since(tm.lastLogin); since < minReauthInterval {
		return fmt.Errorf("%w: the previous login attempt was %s ago, and the minimum interval is %s",
			ErrReauthThrottled, since.Round(time.Second), minReauthInterval)
	}
	return tm.reauthLocked(ctx)
}

// Client returns the managed OpenBao client. Its token is kept current by
// the background renewal loop and by Reauth.
func (tm *TokenManager) Client() *api.Client {
	return tm.client
}

// Close stops the background renewal loop and the current watcher, waits for
// the loop to exit, and then revokes the current token if this process minted
// it (see ownsToken), so a stopped or rolled process leaves no live token
// behind for the rest of its TTL.
//
// Revocation is best effort. It is bounded by revokeTimeout, and a failure is
// logged at WARN rather than returned: nothing a caller does at shutdown would
// act on it, and an unreachable OpenBao must not hold up exit. It needs the
// token's policies to permit auth/token/revoke-self, which OpenBao's built-in
// default policy does.
//
// Close holds tm.mu while it revokes and marks the manager closed first, so a
// Reauth in flight finishes before the revoke (and its token is the one
// revoked), and a Reauth after it refuses rather than minting a token nothing
// would revoke. Calling Close again does nothing.
func (tm *TokenManager) Close() error {
	tm.cancel()
	<-tm.doneCh

	tm.mu.Lock()
	defer tm.mu.Unlock()
	if tm.closed {
		return nil
	}
	tm.closed = true
	if !tm.ownsToken {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
	defer cancel()
	if err := tm.client.Auth().Token().RevokeSelfWithContext(ctx, ""); err != nil {
		slog.Warn("Failed to revoke the OpenBao token at shutdown; it stays valid until its TTL expires",
			"error", err)
		return nil
	}
	slog.Info("Revoked the OpenBao token at shutdown")
	return nil
}
