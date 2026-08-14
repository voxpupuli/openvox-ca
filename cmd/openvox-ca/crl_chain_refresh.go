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

// runCRLChainRefresher re-reads crl_chain_file and rewrites the published CRL
// when the upstream CRLs it names have changed.
//
// The file is the operator's declarative statement of which ancestor CRLs to
// publish, refreshed by whatever mechanism already delivers it — a mounted
// Secret, a config-management run, a cron job fetching a CDP. Nothing in this
// process writes it, so without a job that re-reads it the ancestors would be
// read once at startup and never again, and an ancestor CRL that expired
// afterwards would keep being served until a restart. Under Puppet's default
// certificate_revocation = chain that is not stale data but a scheduled
// fleet-wide verification failure.
//
// Polling rather than watching, for the same reason runCRLSync polls: the file
// may arrive by any mechanism on any filesystem, and a watch that works on a
// local path does not work on a projected volume that swaps a symlinked
// directory underneath it.
//
// Runs a pass immediately rather than waiting out the first tick, and that pass
// is load-bearing rather than a recovery nicety: nothing else publishes the
// file. CA.Init does not -- finishLoadExisting only reloads the CRL cache, and
// bootstrap writes through Storage.UpdateCRL, which bypasses signCRLLocked and
// so never reaches crlChainLocked -- so until this runs, a configured chain
// file has had no effect at all. Deleting the immediate pass would leave a
// freshly started CA serving no ancestor CRLs for a whole interval, and make a
// slow rollout look like a broken one.
//
// Every replica runs it: the rewrite is serialised on the shared CRL lock, so
// concurrent passes converge rather than conflict. It returns when ctx is
// cancelled (i.e. on shutdown).
func runCRLChainRefresher(ctx context.Context, c *ca.CA, path string, interval time.Duration) {
	slog.Info("Starting CRL chain refresh job", "path", path, "interval", interval)

	refreshCRLChainOnce(ctx, c, path)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("CRL chain refresh job stopping")
			return
		case <-ticker.C:
			refreshCRLChainOnce(ctx, c, path)
		}
	}
}

// refreshCRLChainOnce runs a single pass, logging the outcome. Errors are
// logged and swallowed so a transient read failure — or a file mid-rewrite —
// does not stop the job; the next tick retries, and CA.RefreshCRLChainFile has
// already counted the failure for anyone alerting on a chain that stays stale.
func refreshCRLChainOnce(ctx context.Context, c *ca.CA, path string) {
	rewritten, err := c.RefreshCRLChainFile(ctx)
	switch {
	case err != nil:
		slog.Error("Could not refresh the upstream CRL chain", "path", path, "error", err)
	case rewritten:
		slog.Info("Published an updated CRL chain", "path", path)
	default:
		slog.Debug("Upstream CRL chain unchanged", "path", path)
	}
}
