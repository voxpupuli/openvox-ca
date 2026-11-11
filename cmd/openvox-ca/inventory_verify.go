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

// runInventoryVerify re-checks the inventory's integrity value on every tick,
// so that an edit made behind the CA's back is reported within an interval
// rather than at the next restart. See CA.VerifyInventory for what a pass
// reads and why it runs on every backend.
//
// It returns when ctx is cancelled (i.e. on shutdown). Like the sync jobs it
// does not run a pass before its first tick: CA.Init has just verified the
// same inventory.
func runInventoryVerify(ctx context.Context, c *ca.CA, interval time.Duration) {
	slog.Info("Starting inventory verification job", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Inventory verification job stopping")
			return
		case <-ticker.C:
			verifyInventoryOnce(ctx, c)
		}
	}
}

// verifyInventoryOnce runs a single pass. A failure is logged and swallowed so
// the next tick tries again; CA.VerifyInventory has already counted it into
// openvoxca_inventory_verify_failures_total. A mismatch has also been logged by
// the storage layer, with the scheme and the repair hint, which is the line to
// alert on in a log pipeline.
func verifyInventoryOnce(ctx context.Context, c *ca.CA) {
	if err := c.VerifyInventory(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("Inventory verification failed", "error", err)
	}
}
