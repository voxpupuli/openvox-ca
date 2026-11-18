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

package storage

import (
	"context"

	"github.com/uptrace/bun"
)

// Migration 20261118000000 (fingerprints): add the certificate index's column
// for fingerprints in digests other than SHA-256 (CertProjection.Fingerprints).
//
// Existing rows get NULL, which reads as a projection holding no other
// digests rather than as a missing projection, so this migration needs no data
// backfill of its own.
func init() {
	sqlMigrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		return migrationDDL(ctx, db, func(ctx context.Context, idb bun.IDB) error {
			return addColumnIfMissing(ctx, idb, inventoryTableV1, "fingerprints", "TEXT")
		})
	}, func(ctx context.Context, db *bun.DB) error {
		return migrationDDL(ctx, db, func(ctx context.Context, idb bun.IDB) error {
			return dropColumnIfPresent(ctx, idb, inventoryTableV1, "fingerprints")
		})
	})
}
