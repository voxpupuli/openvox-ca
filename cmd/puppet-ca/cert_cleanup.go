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

// runCertCleaner periodically removes certificates that expired more than
// retain ago from the inventory and the CRL (and deletes their stored signed
// certificate). It is an optional, opt-in job for operators who want their
// inventory and CRL to shed long-dead nodes automatically rather than growing
// without bound. It runs in the frontend process, which signs the rebuilt CRL
// via the isolated signer over IPC.
//
// Replica safety: CA.CleanupExpiredCerts does its inventory prune and CRL
// re-sign under the shared cluster CRL lock, so when this runs on multiple
// replicas only the first to acquire the lock prunes; the others observe an
// already-clean inventory and remove nothing. No leader election is required.
//
// It returns when ctx is cancelled (i.e. on shutdown).
func runCertCleaner(ctx context.Context, c *ca.CA, interval, retain time.Duration) {
	slog.Info("Starting expired-certificate cleanup job", "interval", interval, "retention", retain)

	// Run immediately at startup so a backlog that accrued while every replica
	// was down is cleared without waiting a full interval.
	cleanupExpiredOnce(ctx, c, retain)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Expired-certificate cleanup job stopping")
			return
		case <-ticker.C:
			cleanupExpiredOnce(ctx, c, retain)
		}
	}
}

// cleanupExpiredOnce runs a single cleanup pass, logging the outcome. Errors are
// logged and swallowed so a transient storage/lock failure does not stop the
// job; the next tick will retry.
func cleanupExpiredOnce(ctx context.Context, c *ca.CA, retain time.Duration) {
	removed, err := c.CleanupExpiredCerts(ctx, retain)
	switch {
	case err != nil:
		slog.Warn("Expired-certificate cleanup failed", "error", err)
	case removed > 0:
		slog.Info("Expired certificates cleaned up", "removed", removed)
	default:
		slog.Debug("Expired-certificate cleanup: nothing to remove")
	}
}
