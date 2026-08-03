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
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// certIndexVersion is the migration whose half-application these tests
// reproduce; it is the name bun derives from 20260725000000_certindex.go.
const certIndexVersion = "20260725000000"

// certIndexColumns are the columns the certindex migration adds, in the order
// it adds them.
var certIndexColumns = []string{
	"fingerprint_sha256", "dns_alt_names", "auth_extensions", "state", "revoked_at",
}

var certIndexIndices = []string{
	"idx_puppet_ca_inventory_state", "idx_puppet_ca_inventory_not_after",
}

var _ = Describe("SQL schema migrations", func() {
	ctx := context.Background()

	Describe("catalogue lookups", func() {
		It("reports columns and indices that do and do not exist", func() {
			b := newSQLiteBackend()

			for _, col := range certIndexColumns {
				exists, err := columnExists(ctx, b.db, inventoryTableV1, col)
				Expect(err).NotTo(HaveOccurred())
				Expect(exists).To(BeTrue(), "column %s should exist after migrating", col)
			}
			exists, err := columnExists(ctx, b.db, inventoryTableV1, "no_such_column")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse())

			for _, idx := range certIndexIndices {
				exists, err := indexExists(ctx, b.db, inventoryTableV1, idx)
				Expect(err).NotTo(HaveOccurred())
				Expect(exists).To(BeTrue(), "index %s should exist after migrating", idx)
			}
			exists, err = indexExists(ctx, b.db, inventoryTableV1, "no_such_index")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse())
		})

		It("does not confuse a column for an index of the same name", func() {
			b := newSQLiteBackend()

			exists, err := indexExists(ctx, b.db, inventoryTableV1, "state")
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse(), "state is a column, not an index")
		})
	})

	Describe("recovering a half-applied migration", func() {
		// Reproduces the schema drift seen in the field: the certindex migration
		// was recorded as applied but only its first two ALTERs ran, so every
		// later start failed reading the inventory and nothing ever retried the
		// migration. Re-running it must finish the job rather than fail on the
		// columns already there.
		It("completes the remaining DDL when re-run", func() {
			b := newSQLiteBackend()

			// Rewind to the broken state: drop both indices and the last three
			// columns (indices first, since SQLite will not drop a column one
			// depends on), then forget the migration was ever applied.
			dropCertIndexSchema(ctx, b, certIndexColumns[2:])
			_, err := b.db.ExecContext(ctx, "DELETE FROM bun_migrations WHERE name = ?", certIndexVersion)
			Expect(err).NotTo(HaveOccurred())

			Expect(b.EnsureReady(ctx)).To(Succeed())
			expectCertIndexSchema(ctx, b)
		})

		It("leaves an already-complete schema alone", func() {
			b := newSQLiteBackend()

			_, err := b.db.ExecContext(ctx, "DELETE FROM bun_migrations")
			Expect(err).NotTo(HaveOccurred())

			// Every migration re-runs against the schema it already produced;
			// each must be a no-op rather than an "already exists" failure.
			Expect(b.EnsureReady(ctx)).To(Succeed())
		})
	})

	Describe("concurrent runners", func() {
		It("serialises callers sharing a backend", func() {
			b := newSQLiteBackend()

			_, err := b.db.ExecContext(ctx, "DELETE FROM bun_migrations")
			Expect(err).NotTo(HaveOccurred())

			const runners = 4
			errs := make([]error, runners)
			var wg sync.WaitGroup
			wg.Add(runners)
			for i := range runners {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					errs[i] = b.EnsureReady(ctx)
				}()
			}
			wg.Wait()

			for i, err := range errs {
				Expect(err).NotTo(HaveOccurred(), "runner %d", i)
			}
			expectOneRowPerMigration(ctx, b)
		})
	})

	// The floor is the only thing between a small sql_max_open_conns and a
	// startup deadlock: the distributed locks are session-scoped, so each one
	// held occupies a connection while the work under it needs another. A
	// deadlock is the worst failure to find in production, and no other spec
	// would notice the clamp disappearing — the concurrency specs run with the
	// default pool. Both networked dialects open lazily, so these construct a
	// backend against an unreachable DSN and never connect.
	Describe("the connection pool floor", func() {
		DescribeTable("raises a pool too small for the locks to hold",
			func(d SQLDialect, dsn string) {
				b, err := NewSQLBackend(SQLConfig{Dialect: d, DSN: dsn, MaxOpenConns: 1})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = b.Close() })
				Expect(b.db.Stats().MaxOpenConnections).To(Equal(sqlMinOpenConns))
			},
			Entry("postgres", SQLPostgres, "postgres://u:p@127.0.0.1:1/db?sslmode=disable"),
			Entry("mysql", SQLMySQL, "u:p@tcp(127.0.0.1:1)/db"),
		)

		It("leaves a pool above the floor as configured", func() {
			b, err := NewSQLBackend(SQLConfig{
				Dialect:      SQLPostgres,
				DSN:          "postgres://u:p@127.0.0.1:1/db?sslmode=disable",
				MaxOpenConns: 25,
			})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })
			Expect(b.db.Stats().MaxOpenConnections).To(Equal(25))
		})

		It("does not apply to SQLite, which is pinned to one connection", func() {
			// SQLite reports ErrDistributedLockingUnsupported, so no connection
			// is ever tied up by a lock and the single-writer pin still holds.
			b := newSQLiteBackend()
			Expect(b.db.Stats().MaxOpenConnections).To(Equal(1))
		})
	})

	Describe("the inventory integrity read", func() {
		// The startup integrity check reads the inventory before anything else
		// touches the table. It must not depend on columns it has no use for, or
		// unrelated schema drift surfaces as a bogus tampering error.
		It("does not select the certificate index columns", func() {
			b := newSQLiteBackend()

			Expect(b.AppendEntry(ctx, CertRecord{
				InventoryEntry: InventoryEntry{
					Serial:    "0x1",
					Subject:   "/CN=node.example.com",
					NotBefore: "2026-01-01T00:00:00UTC",
					NotAfter:  "2031-01-01T00:00:00UTC",
				},
				State: CertStateSigned,
			}, nil)).To(Succeed())

			dropCertIndexSchema(ctx, b, certIndexColumns)

			entries, err := b.Entries(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Serial).To(Equal("0x1"))
			Expect(entries[0].Subject).To(Equal("/CN=node.example.com"))
		})
	})
})

// dropCertIndexSchema removes the certindex indices and the named columns,
// undoing part or all of that migration so a re-run has something to do. Indices
// go first: SQLite refuses to drop a column an index is built on. The drops go
// through the migrations' own dialect-aware helpers, then are verified, so a
// helper that quietly did nothing cannot leave the caller asserting against a
// schema that was never disturbed.
func dropCertIndexSchema(ctx context.Context, b *SQLBackend, columns []string) {
	GinkgoHelper()

	for _, idx := range certIndexIndices {
		Expect(dropIndexIfPresent(ctx, b.db, inventoryTableV1, idx)).To(Succeed(), "dropping index %s", idx)
	}
	for _, col := range columns {
		Expect(dropColumnIfPresent(ctx, b.db, inventoryTableV1, col)).To(Succeed(), "dropping column %s", col)

		exists, err := columnExists(ctx, b.db, inventoryTableV1, col)
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeFalse(), "column %s should be gone", col)
	}
}

// expectCertIndexSchema asserts the certindex migration has fully applied.
func expectCertIndexSchema(ctx context.Context, b *SQLBackend) {
	GinkgoHelper()

	for _, col := range certIndexColumns {
		exists, err := columnExists(ctx, b.db, inventoryTableV1, col)
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeTrue(), "column %s missing", col)
	}
	for _, idx := range certIndexIndices {
		exists, err := indexExists(ctx, b.db, inventoryTableV1, idx)
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeTrue(), "index %s missing", idx)
	}
}

// expectOneRowPerMigration asserts that every applied migration is recorded
// exactly once. Duplicate rows are the fingerprint of two runners having read
// the migration state at the same time.
func expectOneRowPerMigration(ctx context.Context, b *SQLBackend) {
	GinkgoHelper()

	var names []string
	err := b.db.NewRaw("SELECT name FROM bun_migrations ORDER BY name").Scan(ctx, &names)
	Expect(err).NotTo(HaveOccurred())
	Expect(names).NotTo(BeEmpty())

	seen := make(map[string]int, len(names))
	for _, n := range names {
		seen[n]++
	}
	for name, count := range seen {
		Expect(count).To(Equal(1), "migration %s recorded %d times", name, count)
	}
}
