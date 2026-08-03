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
	"fmt"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
	"github.com/uptrace/bun/migrate"
)

// sqlMigrations is the ordered set of schema migrations applied by every
// SQLBackend on EnsureReady. bun records applied versions in its own
// bun_migrations table, but it does NOT serialise concurrent runners: Migrator
// exposes Lock/Unlock and Migrate never calls them. EnsureReady therefore takes
// the backend's own distributed lock around the whole run, which is what makes
// it safe for multiple CA replicas — and for the signer and frontend processes
// of a single replica — to start against the same database at once.
//
// Each migration is registered from a file whose name carries the version (a
// numeric prefix); see the 2026..._init.go file in this package. Migrations are
// Go functions rather than static .sql so a single definition emits
// dialect-correct DDL for SQLite, PostgreSQL, and MySQL/MariaDB.
//
// Migrations must be written to two rules, both enforced by convention rather
// than by the compiler:
//
//   - Run the DDL through migrationDDL, so it is atomic wherever the dialect
//     allows it.
//   - Address tables by a pinned name (or a frozen model, as
//     sqlInventoryRowV1 does) rather than the live model, so a later rename
//     cannot retarget an already-shipped migration.
var sqlMigrations = migrate.NewMigrations()

// migrationDDL runs one migration's statements as a unit. On PostgreSQL and
// SQLite, whose DDL is transactional, that unit is a transaction: the migration
// either applies whole or not at all, and a cancelled context can no longer
// leave the schema half-changed. MySQL/MariaDB commit implicitly on every DDL
// statement, so a transaction there would be a comforting lie — its migrations
// stay recoverable by being idempotent instead (addColumnIfMissing and friends),
// so a re-run completes a partial application rather than failing on the work
// already done.
//
// Idempotence is applied on every dialect, not just MySQL: it is what lets an
// operator whose schema drifted (see the concurrent-runner history above) clear
// the stale bun_migrations rows and have the migration finish the job.
func migrationDDL(ctx context.Context, db *bun.DB, fn func(ctx context.Context, idb bun.IDB) error) error {
	if db.Dialect().Name() == dialect.MySQL {
		return fn(ctx, db)
	}
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		return fn(ctx, tx)
	})
}

// addColumnIfMissing adds column to table with the given type/constraint
// definition, unless the column is already present. bun's AddColumnQuery has
// IfNotExists, but it errors on every dialect without native ADD COLUMN IF NOT
// EXISTS support (SQLite and MySQL both lack it), so the check is made against
// the catalogue instead.
func addColumnIfMissing(ctx context.Context, idb bun.IDB, table, column, definition string) error {
	exists, err := columnExists(ctx, idb, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = idb.NewAddColumn().
		Table(table).
		ColumnExpr(column + " " + definition).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("adding column %s.%s: %w", table, column, err)
	}
	return nil
}

// createIndexIfMissing creates a (optionally unique) index over columns unless
// an index of that name already exists. CREATE INDEX IF NOT EXISTS is not
// available on MySQL, so this too goes via the catalogue.
func createIndexIfMissing(ctx context.Context, idb bun.IDB, table, index string, unique bool, columns ...string) error {
	exists, err := indexExists(ctx, idb, table, index)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	q := idb.NewCreateIndex().Table(table).Index(index).Column(columns...)
	if unique {
		q = q.Unique()
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("creating index %s on %s: %w", index, table, err)
	}
	return nil
}

// dropIndexIfPresent drops index when it exists. bun's DropIndexQuery emits a
// bare "DROP INDEX <name>", which MySQL rejects (it requires "... ON <table>"),
// so the statement is built per dialect.
func dropIndexIfPresent(ctx context.Context, idb bun.IDB, table, index string) error {
	exists, err := indexExists(ctx, idb, table, index)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	stmt := "DROP INDEX " + index
	if idb.Dialect().Name() == dialect.MySQL {
		stmt += " ON " + table
	}
	if _, err := idb.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("dropping index %s on %s: %w", index, table, err)
	}
	return nil
}

// dropColumnIfPresent drops column when it exists.
func dropColumnIfPresent(ctx context.Context, idb bun.IDB, table, column string) error {
	exists, err := columnExists(ctx, idb, table, column)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if _, err := idb.NewDropColumn().Table(table).ColumnExpr(column).Exec(ctx); err != nil {
		return fmt.Errorf("dropping column %s.%s: %w", table, column, err)
	}
	return nil
}

// columnExists reports whether table has a column named column. PostgreSQL and
// MySQL both expose the standard information_schema; each scopes the lookup to
// the connection's own schema so a same-named table elsewhere in the instance
// cannot answer for ours. SQLite has no information_schema and answers from the
// table-valued pragma instead.
func columnExists(ctx context.Context, idb bun.IDB, table, column string) (bool, error) {
	var query string
	switch idb.Dialect().Name() {
	case dialect.PG:
		query = `SELECT COUNT(*) FROM information_schema.columns
		         WHERE table_schema = CURRENT_SCHEMA() AND table_name = ? AND column_name = ?`
	case dialect.MySQL:
		query = `SELECT COUNT(*) FROM information_schema.columns
		         WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?`
	default: // SQLite
		query = `SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`
	}

	var n int
	if err := idb.NewRaw(query, table, column).Scan(ctx, &n); err != nil {
		return false, fmt.Errorf("checking for column %s.%s: %w", table, column, err)
	}
	return n > 0, nil
}

// indexExists reports whether an index named index exists on table. Index names
// are schema-scoped on PostgreSQL and table-scoped on MySQL/SQLite; each lookup
// is scoped the way its dialect names things.
func indexExists(ctx context.Context, idb bun.IDB, table, index string) (bool, error) {
	var query string
	switch idb.Dialect().Name() {
	case dialect.PG:
		query = `SELECT COUNT(*) FROM pg_indexes
		         WHERE schemaname = CURRENT_SCHEMA() AND tablename = ? AND indexname = ?`
	case dialect.MySQL:
		query = `SELECT COUNT(*) FROM information_schema.statistics
		         WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`
	default: // SQLite
		query = `SELECT COUNT(*) FROM sqlite_master
		         WHERE type = 'index' AND tbl_name = ? AND name = ?`
	}

	var n int
	if err := idb.NewRaw(query, table, index).Scan(ctx, &n); err != nil {
		return false, fmt.Errorf("checking for index %s on %s: %w", index, table, err)
	}
	return n > 0, nil
}
