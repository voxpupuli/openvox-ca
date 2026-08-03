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

// inventoryTableV1 is the name this migration gave the inventory table. Later
// migrations that ALTER the same table address it through this constant, so
// they keep targeting the table as created here even if a future migration
// renames it.
const inventoryTableV1 = "puppet_ca_inventory"

// sqlInventoryRowV1 is the inventory table exactly as this migration created
// it, frozen so later schema changes to the live sqlInventoryRow model cannot
// leak into this migration's DDL. A fresh database must create this shape and
// then replay the follow-up migrations (which ALTER it forward), identically
// to a database that upgraded in place.
type sqlInventoryRowV1 struct {
	bun.BaseModel `bun:"table:puppet_ca_inventory,alias:inv"`

	ID        int64  `bun:"id,pk,autoincrement"`
	Serial    string `bun:"serial,notnull,type:varchar(128)"`
	Subject   string `bun:"subject,notnull,type:varchar(512)"`
	NotBefore string `bun:"not_before,notnull,type:varchar(64)"`
	NotAfter  string `bun:"not_after,notnull,type:varchar(64)"`
}

// Migration 20260201000000 (inventory): create the structured inventory table
// that backs the InventoryStore capability. Each issued certificate is one row,
// ordered by the autoincrement id (issuance order); the subject index serves
// LatestSerialForSubject. The legacy KeyInventory row in puppet_ca_blobs is
// retained as an empty presence marker (see sql_inventory.go), so this
// migration does not move existing blob data — operators with an inventory blob
// migrate it via the storage migrate command, which parses it into rows.
func init() {
	sqlMigrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		return migrationDDL(ctx, db, func(ctx context.Context, idb bun.IDB) error {
			if _, err := idb.NewCreateTable().
				Model((*sqlInventoryRowV1)(nil)).
				IfNotExists().
				Exec(ctx); err != nil {
				return err
			}
			// Index subject for LatestSerialForSubject.
			if err := createIndexIfMissing(ctx, idb, inventoryTableV1,
				"idx_puppet_ca_inventory_subject", false, "subject"); err != nil {
				return err
			}
			// Serials are unique per issuance (random 128-bit, fresh on every
			// (re-)issuance), so enforce it: a duplicate signals a serial collision
			// or a double insert, which AppendEntry should fail on rather than
			// silently record two certs under one serial.
			return createIndexIfMissing(ctx, idb, inventoryTableV1,
				"idx_puppet_ca_inventory_serial", true, "serial")
		})
	}, func(ctx context.Context, db *bun.DB) error {
		return migrationDDL(ctx, db, func(ctx context.Context, idb bun.IDB) error {
			_, err := idb.NewDropTable().
				Model((*sqlInventoryRowV1)(nil)).
				IfExists().
				Exec(ctx)
			return err
		})
	})
}
