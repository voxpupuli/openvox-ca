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

// runSupersededSweeper periodically revokes the certificates that renewals
// have replaced and whose delay (superseded_cert_revoke_after_sec) has since
// elapsed.
//
// It runs whatever that delay is set to, including zero, and that is the point.
// The switch that fills the list is not the switch that drains it: an operator
// who grants a window, accrues entries and then sets the delay back to zero
// still has certificates on the list, each with its own recorded due time. A
// sweep gated on the delay would strand exactly those — every one of them a
// credential the operator believes was retired, kept valid for its full
// remaining life by the setting change that was meant to tighten things up.
//
// The idle cost that makes running it unconditionally reasonable is one
// absent-key read per replica per interval, and no cluster lock at all:
// ReconcileSuperseded rules the work out before acquiring one, precisely so
// that the deployments which never enable a window do not take a cluster-wide
// lock four times an hour forever to discover there is nothing to do.
//
// Replica safety: CA.ReconcileSuperseded does each step's list
// read-modify-write and revocations under the shared cluster CRL lock,
// releasing it between steps, so when this runs on multiple replicas they share
// a large backlog step by step without revoking any entry twice, and a replica
// that arrives once it is gone observes an already-drained list and revokes
// nothing. No leader election is required.
//
// It returns when ctx is cancelled (i.e. on shutdown).
func runSupersededSweeper(ctx context.Context, c *ca.CA, interval time.Duration) {
	// The configured window is deliberately not a parameter here. It would be
	// log-only — the sweep honours each entry's own recorded revoke_at, not a
	// current setting — and a second copy of a value this function does not act
	// on can only ever drift from the one that is actually in force.
	slog.Info("Starting superseded-certificate revocation sweep", "interval", interval)

	// Run immediately at startup so a backlog that came due while every replica
	// was down is cleared without waiting a full interval — that backlog is the
	// case where certificates have been outliving their window the longest.
	sweepSupersededOnce(ctx, c)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Superseded-certificate revocation sweep stopping")
			return
		case <-ticker.C:
			sweepSupersededOnce(ctx, c)
		}
	}
}

// sweepSupersededOnce runs a single sweep, logging the outcome. Errors are
// logged and swallowed so a transient storage/lock failure does not stop the
// job; the next tick retries, and ReconcileSuperseded leaves anything it could
// not revoke on the list for exactly that.
func sweepSupersededOnce(ctx context.Context, c *ca.CA) {
	revoked, err := c.ReconcileSuperseded(ctx)
	switch {
	case ca.StoppedByShutdown(ctx, err):
		// Not a failure, and not worded like one: the runbook for
		// OpenVoxCASupersedeFailing reads the warning below as a storage
		// fault. A pass the shutdown ended left every entry it did not reach on
		// the list, and ReconcileSuperseded does not count it either.
		slog.Info("Superseded-certificate revocation sweep stopped by shutdown; "+
			"the next pass resumes it", "revoked", revoked)
	case err != nil:
		// revoked can be non-zero here: a pass works in steps, and reports
		// what the steps before the failing one revoked.
		slog.Warn("Superseded-certificate revocation sweep failed", "revoked", revoked, "error", err)
	case revoked > 0:
		slog.Info("Superseded certificates revoked", "revoked", revoked)
	default:
		slog.Debug("Superseded-certificate revocation sweep: nothing due")
	}
}
