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
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

// sqlBlobV1 is the blob table exactly as this migration created it, frozen so
// later schema changes to the live sqlBlob model cannot leak into this
// migration's DDL. Same reasoning as sqlInventoryRowV1.
type sqlBlobV1 struct {
	bun.BaseModel `bun:"table:puppet_ca_blobs,alias:b"`

	Key        string    `bun:"blob_key,pk,type:varchar(512)"`
	Data       []byte    `bun:"data"`
	Kind       int       `bun:"kind,notnull"`
	ModifiedAt time.Time `bun:"modified_at,notnull"`
}

// Migration 20260101000000 (init): create the single key-value table backing
// every logical storage key. bun derives the migration name and version
// "20260101000000" from this file's name, so the file must keep its numeric
// prefix. The table is created from a model so each dialect gets the
// appropriate column types.
func init() {
	sqlMigrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		return migrationDDL(ctx, db, func(ctx context.Context, idb bun.IDB) error {
			if _, err := idb.NewCreateTable().
				Model((*sqlBlobV1)(nil)).
				IfNotExists().
				Exec(ctx); err != nil {
				return err
			}
			// bun maps []byte to BLOB, which on MySQL/MariaDB caps at 64 KiB — too
			// small for the append-only inventory. Widen it to LONGBLOB. SQLite and
			// PostgreSQL store blobs without a practical size limit, so they need no
			// adjustment.
			if idb.Dialect().Name() == dialect.MySQL {
				if _, err := idb.ExecContext(ctx, "ALTER TABLE puppet_ca_blobs MODIFY data LONGBLOB"); err != nil {
					return err
				}
			}
			return nil
		})
	}, func(ctx context.Context, db *bun.DB) error {
		return migrationDDL(ctx, db, func(ctx context.Context, idb bun.IDB) error {
			_, err := idb.NewDropTable().
				Model((*sqlBlobV1)(nil)).
				IfExists().
				Exec(ctx)
			return err
		})
	})
}
