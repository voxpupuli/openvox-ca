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

// runManagedCertReconciler reconciles the CA's managed certificates on a timer
// until ctx is cancelled.
//
// # Observability, and what is deliberately absent
//
// This loop publishes no metric of its own, and that is a decision rather than
// an oversight. Every reconcile outcome an operator can currently reach is
// either a log line here or an ordinary certificate fact: a managed certificate
// is a certificate at cert/<subject> with an inventory row, so once one exists
// puppetca_leaf_certificate_not_after_timestamp_seconds covers its expiry and
// the shipped expiry alerts cover it with no new series.
//
// One outcome that reasoning does not reach: an entry that has never issued at
// all -- a store that never accepts a write. There is no series for a
// certificate that does not exist, so no PromQL comparison can match its
// absence; the Kubernetes exporter has the same hole and closes it with a
// dedicated "not running" rule. The managed mechanism needs the equivalent.
//
// Displacement is NOT a second such outcome, though it reads like one. When a
// managed issuance replaces a certificate the CA already held for that name,
// the subject keeps its expiry series without interruption -- the new
// certificate is at cert/<subject> and in the inventory like any other, so
// ListCerts finds it and the shipped expiry alerts apply to it as normal. What
// stops being exported is the *displaced* certificate's own expiry series, and
// that is not a loss: an expiry alert for a certificate an operator has
// deliberately replaced is noise, not signal. It is supposed to expire.
//
// What displacement does leave is narrower and not a metrics problem. The
// displaced certificate stays valid, keeps its inventory row, and is no longer
// what `revoke --certname` resolves to -- so retiring it early needs its
// serial, which warnIfDisplacingUnderSubjectLock logs at the time along with
// the remedy. An operator who missed that line can still find it as a second
// inventory row under one subject. That is a discoverability wrinkle in a
// situation the operator configured and was warned about, which is why it gets
// a log line rather than a series.
//
// It is not added here because nothing configures a managed certificate yet: a
// counter would be permanently zero on every deployment, and docs/metrics.md
// would gain a row nothing can move. It belongs with the first instance, which
// is also the first change that can say what a useful value looks like. See
// #243.
//
// A timer, deliberately, and not the Kubernetes exporter's CRLUpdated() channel:
// that channel fires on revocation, and renewal is driven by the clock. A CA
// that revokes nothing for a fortnight would otherwise let every managed
// certificate expire without a single pass. See the exporter, which has no
// timer at all and does not need one, because an export is only ever stale
// with respect to something that changed.
func runManagedCertReconciler(ctx context.Context, c *ca.CA, interval time.Duration) {
	slog.Info("Starting managed-certificate reconcile loop",
		"interval", interval, "certificates", len(c.ManagedCerts))

	// Immediately at startup, before the first tick: on a fresh deployment
	// nothing is in the store yet, and waiting an interval to issue would mean
	// waiting an interval for whatever depends on that certificate.
	reconcileManagedOnce(ctx, c)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Managed-certificate reconcile loop stopping")
			return
		case <-ticker.C:
			reconcileManagedOnce(ctx, c)
		}
	}
}

// reconcileManagedOnce runs a single pass, logging the outcome. Errors are
// logged and swallowed so a transient store or lock failure does not stop the
// job; the next tick retries, and ReconcileManaged already leaves each failed
// entry for exactly that.
func reconcileManagedOnce(ctx context.Context, c *ca.CA) {
	issued, err := c.ReconcileManaged(ctx)
	switch {
	case err != nil:
		// issued can be non-zero here: entries are independent and the pass
		// reports what it managed alongside the first failure.
		slog.Warn("Managed-certificate reconcile pass had failures", "issued", issued, "error", err)
	case issued > 0:
		slog.Info("Managed certificates issued", "issued", issued)
	default:
		slog.Debug("Managed-certificate reconcile pass: nothing due")
	}
}
