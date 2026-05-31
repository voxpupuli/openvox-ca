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

import "github.com/uptrace/bun/migrate"

// sqlMigrations is the ordered set of schema migrations applied by every
// SQLBackend on EnsureReady. bun records applied versions in its own
// bun_migrations table and serialises concurrent runners with a lock table, so
// it is safe for multiple CA replicas to start against the same database.
//
// Each migration is registered from a file whose name carries the version (a
// numeric prefix); see the 2026..._init.go file in this package. Migrations are
// Go functions rather than static .sql so a single definition emits
// dialect-correct DDL for SQLite, PostgreSQL, and MySQL/MariaDB.
var sqlMigrations = migrate.NewMigrations()
