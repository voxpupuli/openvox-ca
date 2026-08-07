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
	"log/slog"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// runCRLSync polls storage for a CRL newer than the one this process is making
// admission decisions from, and installs it when there is one. It is what
// bounds how long a certificate revoked on one replica keeps working against
// the others: without it a replica refreshes its in-memory CRL only when it
// re-signs or restarts, which on the default 30-day validity is weeks.
//
// Polling rather than a notification because there is no cross-process signal
// every backend can carry. crlNotify is in-process only, and the four shared
// backends each want a different mechanism — etcd watches, Redis pub/sub,
// Postgres LISTEN/NOTIFY, and MySQL nothing at all short of polling — so a
// notification path would have to be built and tested per backend and would
// still need this loop underneath it for the one that cannot carry a signal. A
// read of a single small blob on a short timer costs little and behaves the
// same everywhere.
//
// Deliberately separate from runCRLRefresher and not gated by
// disable_crl_refresh. That switch is about whether this deployment re-signs
// the CRL on a timer, which an operator may reasonably drive externally
// instead; it must not also decide whether revocations reach this replica.
//
// Every replica runs it. Nothing is written and no lock is taken, so there is
// no leader to elect and no contention to serialise. It returns when ctx is
// cancelled (i.e. on shutdown).
//
// Unlike the other background jobs this one does not run a pass before its
// first tick: CA.Init has just loaded the CRL from the same storage, so an
// immediate pass would re-read a blob that cannot yet be stale.
func runCRLSync(ctx context.Context, c *ca.CA, interval time.Duration) {
	slog.Info("Starting CRL sync job", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("CRL sync job stopping")
			return
		case <-ticker.C:
			syncCRLOnce(ctx, c)
		}
	}
}

// syncCRLOnce runs a single sync, logging the outcome. Errors are logged and
// swallowed so a transient storage failure does not stop the job; the next tick
// retries, and CA.SyncCRLCache has already counted the failure into
// puppetca_crl_sync_failures_total for anyone alerting on a replica that stays
// behind.
//
// The reload itself logs at info when it installs a newer CRL, so this reports
// only the two quiet outcomes.
func syncCRLOnce(ctx context.Context, c *ca.CA) {
	updated, err := c.SyncCRLCache(ctx)
	switch {
	case err != nil:
		slog.Warn("CRL sync failed; continuing with the CRL already in memory", "error", err)
	case !updated:
		slog.Debug("CRL sync: already current, no action")
	}
}
