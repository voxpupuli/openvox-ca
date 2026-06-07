// Copyright (C) 2026 Chris Boot
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
	"log/slog"
	"time"

	"github.com/tvaughan/puppet-ca/internal/ca"
)

// runCRLRefresher periodically re-signs the CRL before its validity lapses, so
// a low-churn CA (one that simply hasn't revoked anything in a while) never
// ends up serving an expired CRL. It runs in the frontend process, which signs
// via the isolated signer over IPC.
//
// Replica safety: CA.RefreshCRLIfDue performs its expiry check and re-sign
// together under the shared cluster CRL lock, so when this runs on multiple
// replicas only the first to acquire the lock re-signs (pushing NextUpdate far
// out); the others observe a fresh CRL and do nothing. No leader election is
// required.
//
// It returns when ctx is cancelled (i.e. on shutdown).
func runCRLRefresher(ctx context.Context, c *ca.CA, interval, refreshBefore time.Duration) {
	slog.Info("Starting CRL refresh job", "interval", interval, "refresh_before", refreshBefore)

	// Check immediately at startup so a CRL that already lapsed while every
	// replica was down is refreshed without waiting a full interval.
	refreshCRLOnce(ctx, c, refreshBefore)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("CRL refresh job stopping")
			return
		case <-ticker.C:
			refreshCRLOnce(ctx, c, refreshBefore)
		}
	}
}

// refreshCRLOnce runs a single refresh check, logging the outcome. Errors are
// logged and swallowed so a transient storage/lock failure does not stop the
// job; the next tick will retry.
func refreshCRLOnce(ctx context.Context, c *ca.CA, refreshBefore time.Duration) {
	reissued, err := c.RefreshCRLIfDue(ctx, refreshBefore)
	switch {
	case err != nil:
		slog.Warn("CRL refresh check failed", "error", err)
	case reissued:
		slog.Info("CRL refreshed (validity window renewed)")
	default:
		slog.Debug("CRL refresh check: still current, no action")
	}
}
