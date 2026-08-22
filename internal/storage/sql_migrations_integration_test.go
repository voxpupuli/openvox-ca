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

//go:build postgres_integration || mysql_integration

package storage

import (
	"context"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// sqlMigrationsConcurrentRunners drives two independent backends through the
// same pending migration at once, standing in for the signer and frontend
// processes of one replica (or two replicas) starting together. Both must
// succeed, and the migration must end up recorded exactly once: the incident
// this guards against left two rows for one version and a schema stuck
// part-way.
//
// This lives behind the integration tags because only PostgreSQL and MySQL have
// a *distributed* lock to exercise. SQLite reports
// ErrDistributedLockingUnsupported, but since #187 that is no longer the end of
// it: EnsureReady falls through to the same-host flock, so two backends on one
// file do exclude each other, and that case is asserted in the ordinary unit
// suite — see the Describe("the SQLite backend") block in filelock_test.go,
// which races four backends over one DSN and asserts one row per migration.
func sqlMigrationsConcurrentRunners(newBackend func() *SQLBackend) {
	ctx := context.Background()
	runners := []*SQLBackend{newBackend(), newBackend()}

	dropCertIndexSchema(ctx, runners[0], certIndexColumns)
	_, err := runners[0].db.ExecContext(ctx, "DELETE FROM bun_migrations WHERE name = ?", certIndexVersion)
	Expect(err).NotTo(HaveOccurred())

	errs := make([]error, len(runners))
	var wg sync.WaitGroup
	wg.Add(len(runners))
	for i, backend := range runners {
		go func() {
			defer GinkgoRecover()
			defer wg.Done()
			errs[i] = backend.EnsureReady(ctx)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		Expect(err).NotTo(HaveOccurred(), "runner %d", i)
	}
	expectCertIndexSchema(ctx, runners[0])
	expectOneRowPerMigration(ctx, runners[0])
}
