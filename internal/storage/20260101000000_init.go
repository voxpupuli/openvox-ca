// Copyright (C) 2026 Chris Boot
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
	"github.com/uptrace/bun/dialect"
)

// Migration 20260101000000 (init): create the single key-value table backing
// every logical storage key. bun derives the migration name and version
// "20260101000000" from this file's name, so the file must keep its numeric
// prefix. The table is created from the sqlBlob model so each dialect gets the
// appropriate column types.
func init() {
	sqlMigrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		if _, err := db.NewCreateTable().
			Model((*sqlBlob)(nil)).
			IfNotExists().
			Exec(ctx); err != nil {
			return err
		}
		// bun maps []byte to BLOB, which on MySQL/MariaDB caps at 64 KiB — too
		// small for the append-only inventory. Widen it to LONGBLOB. SQLite and
		// PostgreSQL store blobs without a practical size limit, so they need no
		// adjustment.
		if db.Dialect().Name() == dialect.MySQL {
			if _, err := db.ExecContext(ctx, "ALTER TABLE puppet_ca_blobs MODIFY data LONGBLOB"); err != nil {
				return err
			}
		}
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		_, err := db.NewDropTable().
			Model((*sqlBlob)(nil)).
			IfExists().
			Exec(ctx)
		return err
	})
}
