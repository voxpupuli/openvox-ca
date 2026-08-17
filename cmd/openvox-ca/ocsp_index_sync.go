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

// runOCSPIndexSync polls the inventory for certificates this process does not
// know about and adds them to the serial index the OCSP responder answers from.
// It is what stops a replica reporting `unknown` for a certificate one of its
// peers signed: the index is built once at startup and otherwise only records
// this process's own issuances, so on a shared backend every certificate signed
// elsewhere is invisible to it until a restart.
//
// Polling for the same reason runCRLSync polls — no cross-process signal all
// five backends can carry — and see CA.SyncSerialIndex for why the alternative
// of looking a serial up on an index miss is worse rather than better here.
//
// Every replica runs it, unconditionally. Nothing is written and no lock is
// taken, so there is no leader to elect and no contention to serialise. It is
// deliberately not gated on ocsp_url: that setting decides whether issued
// certificates *advertise* this responder, not whether the /ocsp endpoint
// answers, and an operator distributing the responder URL by any other means
// would otherwise silently keep the bug.
//
// It returns when ctx is cancelled (i.e. on shutdown). Like runCRLSync it does
// not run a pass before its first tick: CA.Init has just built the index from
// the same inventory, so an immediate pass would re-read what cannot yet be
// stale.
func runOCSPIndexSync(ctx context.Context, c *ca.CA, interval time.Duration) {
	slog.Info("Starting OCSP serial index sync job", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("OCSP serial index sync job stopping")
			return
		case <-ticker.C:
			syncOCSPIndexOnce(ctx, c)
		}
	}
}

// syncOCSPIndexOnce runs a single pass, logging the outcome. Errors are logged
// and swallowed so a transient storage failure does not stop the job; the next
// tick retries, and CA.SyncSerialIndex has already counted the failure into
// puppetca_ocsp_index_sync_failures_total for anyone alerting on a replica that
// stays behind.
//
// The pass itself logs at info when it changes the index, so this reports only
// the two quiet outcomes.
func syncOCSPIndexOnce(ctx context.Context, c *ca.CA) {
	delta, err := c.SyncSerialIndex(ctx)
	switch {
	case err != nil:
		slog.Warn("OCSP serial index sync failed; continuing with the index already in memory", "error", err)
	case !delta.Changed():
		slog.Debug("OCSP serial index sync: already current, no action")
	}
}
