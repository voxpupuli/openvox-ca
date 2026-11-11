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

package ca

import (
	"context"
	"errors"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// VerifyInventory reads the whole inventory through the verifying path and
// reports whether its integrity value still matches: the whole-blob HMAC or
// the hash-chain head, whichever the backend keeps.
//
// It exists for the periodic inventory-verify job, which runs on every backend.
// Before that job, the only re-check after startup was the OCSP serial-index
// sync, which reads the inventory the same way; that job runs only on the
// shared backends and only while the responder is served, so a CA with OCSP
// off, the default, verified its inventory at startup and on whatever
// verifying reads revocation and pruning happened to drive.
//
// Read-only: it takes the storage read lock and no cluster lock, and writes
// nothing. A stored integrity value that is missing altogether verifies clean
// with a warning and counts nothing, so deleting it along with an edit evades
// this pass and its alert, leaving only that repeating warning. That is the
// scheme's accepted limit against an actor who can write the store (out-of-scope
// item 1 in docs/development/inventory-store.md; the reasoning is on
// StorageService.compareInventoryMACLocked), kept rather than narrowed here. A
// failure is counted, by reason, unless ctx was cancelled first, which is
// shutdown rather than a failed check.
func (c *CA) VerifyInventory(ctx context.Context) error {
	_, err := c.Storage.InventoryEntries(ctx)
	if err == nil || ctx.Err() != nil {
		return err
	}
	if errors.Is(err, storage.ErrInventoryTampered) {
		c.inventoryVerifyTampered.Add(1)
	} else {
		c.inventoryVerifyReadErrors.Add(1)
	}
	return err
}

// InventoryVerifyFailures returns how many periodic inventory verifications
// found the integrity value mismatched (tampered) and how many could not read
// the inventory at all (readErrors). The metrics exporter surfaces them as
// openvoxca_inventory_verify_failures_total{reason}.
func (c *CA) InventoryVerifyFailures() (tampered, readErrors uint64) {
	return c.inventoryVerifyTampered.Load(), c.inventoryVerifyReadErrors.Load()
}
