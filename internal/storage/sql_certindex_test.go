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
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/uptrace/bun/migrate"
)

// newCertIndexService returns a StorageService over a fresh SQLite backend
// with the inventory touched and integrity initialised, plus the backend for
// direct blob writes (stored certificates gate Statuses visibility).
func newCertIndexService() (*StorageService, *SQLBackend) {
	ctx := context.Background()
	b := newSQLiteBackend()
	svc := NewWithBackend(b, "")
	Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
	Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")
	return svc, b
}

func putCertBlob(b *SQLBackend, subject string) {
	Expect(b.Put(context.Background(), CertKey(subject), []byte("pem-"+subject), BlobPublic)).
		To(Succeed(), "Put cert blob for "+subject)
}

// certIndexRoundTrip exercises the CertIndex surface end to end against b:
// projected append, latest-per-subject and blob-gated Statuses, the state
// filter, the revocation round-trip, and projection backfill. It is shared
// between the SQLite unit suite and the PostgreSQL/MySQL integration suites
// so every supported dialect runs identical assertions over its real DDL.
func certIndexRoundTrip(b *SQLBackend) {
	ctx := context.Background()
	svc := NewWithBackend(b, "")
	Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
	Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")

	proj := CertProjection{
		Fingerprint:    "aa:bb:cc",
		DNSAltNames:    []string{"node1", "node1.example.com"},
		IPAltNames:     []string{"192.0.2.10", "2001:db8::1"},
		AuthExtensions: map[string]string{"pp_auth_role": "webserver"},
		Fingerprints:   map[string]string{"SHA1": "01:02", "SHA512": "03:04"},
	}
	Expect(svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
	Expect(svc.AppendInventoryRecord(ctx, "0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1", &proj)).To(Succeed())
	Expect(svc.AppendInventory(ctx, "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2")).To(Succeed())
	// node3 keeps its inventory row but has no stored certificate — the
	// cleaned-certificate shape. Statuses' blob gate (the List-derived
	// exclusion set over the MAX(id) GROUP BY rows) must drop it, and having
	// it here runs that per-dialect SQL against real PostgreSQL and MySQL,
	// not just SQLite.
	Expect(svc.AppendInventory(ctx, "0004 2024-01-04T00:00:00UTC 2029-01-04T00:00:00UTC /node3")).To(Succeed())
	for _, subject := range []string{"node1", "node2"} {
		Expect(b.Put(ctx, CertKey(subject), []byte("pem-"+subject), BlobPublic)).To(Succeed())
	}

	recs, ok, err := svc.CertStatuses(ctx, "")
	Expect(err).NotTo(HaveOccurred(), "CertStatuses")
	Expect(ok).To(BeTrue())
	Expect(recs).To(HaveLen(2), "one record per subject with a stored certificate, latest issuance only")
	Expect(recs[0].Subject).To(Equal("node1"))
	Expect(recs[0].Serial).To(Equal("0003"), "node1's latest issuance wins")
	Expect(recs[0].Fingerprint).To(Equal(proj.Fingerprint))
	Expect(recs[0].DNSAltNames).To(Equal(proj.DNSAltNames))
	Expect(recs[0].IPAltNames).To(Equal(proj.IPAltNames))
	Expect(recs[0].AuthExtensions).To(Equal(proj.AuthExtensions))
	Expect(recs[0].Fingerprints).To(Equal(proj.Fingerprints))
	Expect(recs[1].Subject).To(Equal("node2"))
	Expect(recs[1].Fingerprint).To(BeEmpty(), "appended without a projection")

	// Revocation round-trip, including the state filter.
	revokedAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	Expect(svc.MarkCertRevoked(ctx, "0003", revokedAt)).To(Succeed())
	revoked, _, err := svc.CertStatuses(ctx, CertStateRevoked)
	Expect(err).NotTo(HaveOccurred())
	Expect(revoked).To(HaveLen(1))
	Expect(revoked[0].Subject).To(Equal("node1"))
	Expect(revoked[0].RevokedAt).NotTo(BeNil())
	Expect(*revoked[0].RevokedAt).To(BeTemporally("~", revokedAt, time.Second))
	Expect(svc.ClearCertRevoked(ctx, "0003")).To(Succeed())

	// Projection backfill for the projection-less row.
	Expect(svc.SetCertProjection(ctx, "0002", CertProjection{Fingerprint: "dd:ee:ff"})).To(Succeed())
	recs, _, err = svc.CertStatuses(ctx, "")
	Expect(err).NotTo(HaveOccurred())
	Expect(recs).To(HaveLen(2))
	Expect(recs[0].State).To(Equal(CertStateSigned), "ClearCertRevoked restored node1")
	Expect(recs[0].RevokedAt).To(BeNil())
	// A projection with no IP SANs must still read back as one: SetProjection
	// writes "[]" to ip_alt_names, and NULL there would mark it as predating
	// the column.
	Expect(recs[1].Fingerprint).To(Equal("dd:ee:ff"))
	Expect(recs[1].IPAltNames).To(BeNil())

	// A backfill carrying IP SANs, through the dialect's own UPDATE.
	Expect(svc.SetCertProjection(ctx, "0002", CertProjection{
		Fingerprint: "dd:ee:ff", IPAltNames: []string{"198.51.100.7"},
	})).To(Succeed())
	recs, _, err = svc.CertStatuses(ctx, "")
	Expect(err).NotTo(HaveOccurred())
	Expect(recs[1].IPAltNames).To(Equal([]string{"198.51.100.7"}))
	Expect(recs[1].Fingerprints).To(BeNil())

	// A backfill adding other digests, through the dialect's own UPDATE.
	Expect(svc.SetCertProjection(ctx, "0002", CertProjection{
		Fingerprint: "dd:ee:ff", Fingerprints: map[string]string{"SHA512": "05:06"},
	})).To(Succeed())
	recs, _, err = svc.CertStatuses(ctx, "")
	Expect(err).NotTo(HaveOccurred())
	Expect(recs[1].Fingerprints).To(Equal(map[string]string{"SHA512": "05:06"}))
}

// certIndexMigrationRollback rolls every applied migration group back and
// re-applies them, then re-runs the index round-trip. Nothing in the product
// invokes the down migrations, so this is the only check that their DDL —
// notably the certindex column and index drops — is valid for the backend's
// dialect.
func certIndexMigrationRollback(b *SQLBackend) {
	ctx := context.Background()
	migrator := migrate.NewMigrator(b.db, sqlMigrations)
	for {
		group, err := migrator.Rollback(ctx)
		Expect(err).NotTo(HaveOccurred(), "Rollback")
		if group.IsZero() {
			break
		}
	}

	// Assert the rollback actually removed something before re-applying. Every
	// down step is guarded by dropColumnIfPresent/dropIndexIfPresent, so a
	// catalogue query mis-scoped for this dialect would make the rollback a
	// silent no-op, the re-apply a no-op too, and the round-trip below would
	// still pass against a schema nothing ever touched.
	for _, col := range certIndexColumns {
		exists, err := columnExists(ctx, b.db, inventoryTableV1, col)
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeFalse(), "column %s should have been dropped by the rollback", col)
	}
	for _, idx := range certIndexIndices {
		exists, err := indexExists(ctx, b.db, inventoryTableV1, idx)
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeFalse(), "index %s should have been dropped by the rollback", idx)
	}

	_, err := migrator.Migrate(ctx)
	Expect(err).NotTo(HaveOccurred(), "Migrate (re-apply)")
	expectCertIndexSchema(ctx, b)
	exists, err := columnExists(ctx, b.db, inventoryTableV1, ipAltNamesColumnName)
	Expect(err).NotTo(HaveOccurred())
	Expect(exists).To(BeTrue(), "the re-apply must restore %s", ipAltNamesColumnName)
	exists, err = columnExists(ctx, b.db, inventoryTableV1, fingerprintsColumnName)
	Expect(err).NotTo(HaveOccurred())
	Expect(exists).To(BeTrue(), "the re-apply must restore %s", fingerprintsColumnName)
	certIndexRoundTrip(b)
}

// ipAltNamesMigrationDownUp runs the ip_alt_names migration's down and up
// steps on their own, against a table holding a row. The full rollback above
// cannot check them: it unwinds the migration that creates the table too, so
// every column is gone afterwards whatever the down step did. Shared with the
// PostgreSQL/MySQL integration suites, like the helpers above.
func ipAltNamesMigrationDownUp(b *SQLBackend) {
	ctx := context.Background()
	svc := NewWithBackend(b, "")
	Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
	Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")
	proj := CertProjection{Fingerprint: "aa:bb:cc", IPAltNames: []string{"192.0.2.10"}}
	Expect(svc.AppendInventoryRecord(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1", &proj)).
		To(Succeed())

	migrator := migrate.NewMigrator(b.db, sqlMigrations)
	var m *migrate.Migration
	for _, candidate := range sqlMigrations.Sorted() {
		if candidate.Name == "20261011000000" {
			m = &candidate
		}
	}
	Expect(m).NotTo(BeNil(), "the ip_alt_names migration must be registered under its file's timestamp")

	Expect(m.Down(ctx, migrator, m)).To(Succeed(), "down")
	// Put the column back even if an assertion below fails, so a shared
	// integration database is left as the next spec expects it. bun_migrations
	// still records the migration as applied, so nothing else would re-add it.
	DeferCleanup(func(ctx SpecContext) {
		Expect(m.Up(ctx, migrator, m)).To(Succeed(), "restoring %s for the next spec", ipAltNamesColumnName)
	})
	exists, err := columnExists(ctx, b.db, inventoryTableV1, ipAltNamesColumnName)
	Expect(err).NotTo(HaveOccurred())
	Expect(exists).To(BeFalse(), "down must drop %s", ipAltNamesColumnName)
	entries, err := b.Entries(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(entries).To(HaveLen(1), "down must leave the inventory itself alone")

	Expect(m.Up(ctx, migrator, m)).To(Succeed(), "up")
	exists, err = columnExists(ctx, b.db, inventoryTableV1, ipAltNamesColumnName)
	Expect(err).NotTo(HaveOccurred())
	Expect(exists).To(BeTrue(), "up must add %s", ipAltNamesColumnName)

	// The row now holds a fingerprint and NULL ip_alt_names, the shape every
	// row has when the column is first added. It must read as no projection,
	// so that readers fall back to the PEM and repair rewrites it.
	putCertBlob(b, "node1")
	recs, err := b.Statuses(ctx, "")
	Expect(err).NotTo(HaveOccurred())
	Expect(recs).To(HaveLen(1))
	Expect(recs[0].CertProjection).To(Equal(CertProjection{}),
		"a row projected before %s existed must read as unprojected", ipAltNamesColumnName)
}

// fingerprintsMigrationDownUp runs the fingerprints migration's down and up
// steps on their own, against a table holding a row, for the reason
// ipAltNamesMigrationDownUp gives. Shared with the PostgreSQL/MySQL
// integration suites.
func fingerprintsMigrationDownUp(b *SQLBackend) {
	ctx := context.Background()
	svc := NewWithBackend(b, "")
	Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
	Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")
	proj := CertProjection{
		Fingerprint:  "aa:bb:cc",
		IPAltNames:   []string{"192.0.2.10"},
		Fingerprints: map[string]string{"SHA1": "01:02"},
	}
	Expect(svc.AppendInventoryRecord(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1", &proj)).
		To(Succeed())

	migrator := migrate.NewMigrator(b.db, sqlMigrations)
	var m *migrate.Migration
	for _, candidate := range sqlMigrations.Sorted() {
		if candidate.Name == "20261118000000" {
			m = &candidate
		}
	}
	Expect(m).NotTo(BeNil(), "the fingerprints migration must be registered under its file's timestamp")

	Expect(m.Down(ctx, migrator, m)).To(Succeed(), "down")
	DeferCleanup(func(ctx SpecContext) {
		Expect(m.Up(ctx, migrator, m)).To(Succeed(), "restoring %s for the next spec", fingerprintsColumnName)
	})
	exists, err := columnExists(ctx, b.db, inventoryTableV1, fingerprintsColumnName)
	Expect(err).NotTo(HaveOccurred())
	Expect(exists).To(BeFalse(), "down must drop %s", fingerprintsColumnName)
	entries, err := b.Entries(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(entries).To(HaveLen(1), "down must leave the inventory itself alone")

	Expect(m.Up(ctx, migrator, m)).To(Succeed(), "up")
	exists, err = columnExists(ctx, b.db, inventoryTableV1, fingerprintsColumnName)
	Expect(err).NotTo(HaveOccurred())
	Expect(exists).To(BeTrue(), "up must add %s", fingerprintsColumnName)

	// The row now holds NULL fingerprints, the shape every row has when the
	// column is first added. Unlike a NULL ip_alt_names, it is still a
	// projection, one holding no other digests.
	putCertBlob(b, "node1")
	recs, err := b.Statuses(ctx, "")
	Expect(err).NotTo(HaveOccurred())
	Expect(recs).To(HaveLen(1))
	Expect(recs[0].CertProjection).To(Equal(CertProjection{Fingerprint: "aa:bb:cc", IPAltNames: []string{"192.0.2.10"}}),
		"a row projected before %s existed must keep its projection", fingerprintsColumnName)
}

var _ = Describe("SQLiteCertIndex", func() {
	It("round-trips the certificate index end to end", func() {
		certIndexRoundTrip(newSQLiteBackend())
	})

	It("survives a migration rollback and re-apply", func() {
		certIndexMigrationRollback(newSQLiteBackend())
	})

	It("drops and restores ip_alt_names through that migration's own steps", func() {
		ipAltNamesMigrationDownUp(newSQLiteBackend())
	})

	It("drops and restores fingerprints through that migration's own steps", func() {
		fingerprintsMigrationDownUp(newSQLiteBackend())
	})

	It("persists the projection at append time and serves it back from Statuses", func() {
		ctx := context.Background()
		svc, b := newCertIndexService()

		proj := CertProjection{
			Fingerprint:    "aa:bb:cc",
			DNSAltNames:    []string{"node1", "node1.example.com"},
			AuthExtensions: map[string]string{"pp_auth_role": "webserver"},
		}
		line := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1"
		Expect(svc.AppendInventoryRecord(ctx, line, &proj)).To(Succeed(), "AppendInventoryRecord")
		putCertBlob(b, "node1")

		recs, ok, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred(), "CertStatuses")
		Expect(ok).To(BeTrue(), "SQL backend must advertise the CertIndex capability")
		Expect(recs).To(HaveLen(1))
		Expect(recs[0].Serial).To(Equal("0001"))
		Expect(recs[0].Subject).To(Equal("node1"))
		Expect(recs[0].NotBefore).To(Equal("2024-01-01T00:00:00UTC"))
		Expect(recs[0].NotAfter).To(Equal("2029-01-01T00:00:00UTC"))
		Expect(recs[0].State).To(Equal(CertStateSigned))
		Expect(recs[0].RevokedAt).To(BeNil())
		Expect(recs[0].Fingerprint).To(Equal(proj.Fingerprint))
		Expect(recs[0].DNSAltNames).To(Equal(proj.DNSAltNames))
		Expect(recs[0].AuthExtensions).To(Equal(proj.AuthExtensions))
	})

	It("returns only the latest issuance per subject, and only subjects with a stored certificate", func() {
		ctx := context.Background()
		svc, b := newCertIndexService()

		for _, line := range []string{
			"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1",
			"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2",
			"0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1",
		} {
			Expect(svc.AppendInventory(ctx, line)).To(Succeed(), "AppendInventory")
		}
		// node1 has a stored cert; node2 was cleaned (rows remain, blob gone).
		putCertBlob(b, "node1")

		recs, ok, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(recs).To(HaveLen(1), "superseded and cleaned rows must not be listed")
		Expect(recs[0].Serial).To(Equal("0003"), "the latest issuance for node1 wins")
	})

	It("projects revocation state, keeping the first revocation time, and clears it again", func() {
		ctx := context.Background()
		svc, b := newCertIndexService()

		line := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1"
		Expect(svc.AppendInventory(ctx, line)).To(Succeed())
		putCertBlob(b, "node1")

		first := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
		Expect(svc.MarkCertRevoked(ctx, "0001", first)).To(Succeed(), "MarkCertRevoked")
		// A retried revocation must not overwrite the original time.
		Expect(svc.MarkCertRevoked(ctx, "0001", first.Add(24*time.Hour))).To(Succeed(), "MarkCertRevoked (retry)")

		recs, _, err := svc.CertStatuses(ctx, CertStateRevoked)
		Expect(err).NotTo(HaveOccurred())
		Expect(recs).To(HaveLen(1))
		Expect(recs[0].State).To(Equal(CertStateRevoked))
		Expect(recs[0].RevokedAt).NotTo(BeNil())
		Expect(*recs[0].RevokedAt).To(BeTemporally("~", first, time.Second))

		// The state filter must partition the records.
		signed, _, err := svc.CertStatuses(ctx, CertStateSigned)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeEmpty())

		Expect(svc.ClearCertRevoked(ctx, "0001")).To(Succeed(), "ClearCertRevoked")
		recs, _, err = svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs).To(HaveLen(1))
		Expect(recs[0].State).To(Equal(CertStateSigned))
		Expect(recs[0].RevokedAt).To(BeNil())
	})

	It("marks rows imported from a legacy inventory blob as projection-less and backfills them", func() {
		ctx := context.Background()
		svc, b := newCertIndexService()

		// Importing an inventory.txt blob (the Migrate path) replaces the rows
		// with projection-less ones.
		blob := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n"
		Expect(b.Put(ctx, KeyInventory, []byte(blob), BlobPrivate)).To(Succeed(), "Put inventory blob")
		putCertBlob(b, "node1")

		recs, _, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs).To(HaveLen(1))
		Expect(recs[0].Fingerprint).To(BeEmpty(), "imported rows carry no projection")
		Expect(recs[0].State).To(Equal(CertStateSigned), "imported rows default to signed")

		proj := CertProjection{Fingerprint: "dd:ee:ff", DNSAltNames: []string{"node1"}}
		Expect(svc.SetCertProjection(ctx, "0001", proj)).To(Succeed(), "SetCertProjection")

		recs, _, err = svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs[0].Fingerprint).To(Equal("dd:ee:ff"))
		Expect(recs[0].DNSAltNames).To(Equal([]string{"node1"}))
		Expect(recs[0].AuthExtensions).To(BeNil(), "no auth extensions were projected")
	})

	It("degrades a corrupt projection to a missing one instead of failing the record", func() {
		// record() promises undecodable projection JSON reads as "projection
		// missing" (empty Fingerprint) so listings keep working and readers
		// fall back to the authoritative PEM.
		row := sqlInventoryRow{
			Serial: "0001", Subject: "node1",
			NotBefore: "2024-01-01T00:00:00UTC", NotAfter: "2029-01-01T00:00:00UTC",
			State:       CertStateSigned,
			Fingerprint: "aa:bb:cc",
			DNSAltNames: "{not-json",
		}
		rec := row.record()
		Expect(rec.CertProjection).To(Equal(CertProjection{}), "bad dns_alt_names discards the projection")
		Expect(rec.State).To(Equal(CertStateSigned), "state is not part of the projection and survives")

		// Bad auth_extensions JSON discards the whole projection, including
		// the DNS names that decoded successfully — the record is either
		// fully projected or not projected at all.
		row.DNSAltNames = `["node1"]`
		row.AuthExts = "{not-json"
		rec = row.record()
		Expect(rec.CertProjection).To(Equal(CertProjection{}))
	})

	It("degrades a projection with corrupt ip_alt_names to a missing one", func() {
		row := sqlInventoryRow{
			Serial: "0001", Subject: "node1",
			NotBefore: "2024-01-01T00:00:00UTC", NotAfter: "2029-01-01T00:00:00UTC",
			State:       CertStateSigned,
			Fingerprint: "aa:bb:cc",
			DNSAltNames: `["node1"]`,
			IPAltNames:  "{not-json",
		}
		Expect(row.record().CertProjection).To(Equal(CertProjection{}))
	})

	It("degrades a projection with corrupt fingerprints to a missing one", func() {
		row := sqlInventoryRow{
			Serial: "0001", Subject: "node1",
			NotBefore: "2024-01-01T00:00:00UTC", NotAfter: "2029-01-01T00:00:00UTC",
			State:        CertStateSigned,
			Fingerprint:  "aa:bb:cc",
			IPAltNames:   "[]",
			Fingerprints: "{not-json",
		}
		Expect(row.record().CertProjection).To(Equal(CertProjection{}))
	})

	It("reads a projection written before ip_alt_names existed as a missing one", func() {
		// NULL in ip_alt_names beside a fingerprint: a row projected by code
		// that predates the column, or by a replica still running it. It
		// cannot say whether the certificate has IP SANs, so readers must go
		// to the PEM, and the repair pass rewrites it.
		row := sqlInventoryRow{
			Serial: "0001", Subject: "node1",
			NotBefore: "2024-01-01T00:00:00UTC", NotAfter: "2029-01-01T00:00:00UTC",
			State:       CertStateRevoked,
			Fingerprint: "aa:bb:cc",
			DNSAltNames: `["node1"]`,
		}
		rec := row.record()
		Expect(rec.CertProjection).To(Equal(CertProjection{}))
		Expect(rec.State).To(Equal(CertStateRevoked), "state is not part of the projection and survives")
	})

	It("stores a projection with no IP SANs at append time so that it reads back as one", func() {
		ctx := context.Background()
		svc, b := newCertIndexService()

		proj := CertProjection{Fingerprint: "aa:bb:cc", DNSAltNames: []string{"node1"}}
		line := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1"
		Expect(svc.AppendInventoryRecord(ctx, line, &proj)).To(Succeed())
		putCertBlob(b, "node1")

		var stored *string
		Expect(b.db.NewRaw("SELECT ip_alt_names FROM puppet_ca_inventory WHERE serial = ?", "0001").
			Scan(ctx, &stored)).To(Succeed())
		Expect(stored).To(HaveValue(Equal("[]")), "an empty list, never NULL, beside a fingerprint")

		recs, _, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs).To(HaveLen(1))
		Expect(recs[0].CertProjection).To(Equal(proj))
	})

	It("degrades gracefully on backends without the capability", func() {
		ctx := context.Background()
		svc := New(GinkgoT().TempDir())

		_, ok, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse(), "filesystem backend has no certificate index")

		// Index writes are silent no-ops so shared CA paths need no probing.
		Expect(svc.MarkCertRevoked(ctx, "0001", time.Now())).To(Succeed())
		Expect(svc.ClearCertRevoked(ctx, "0001")).To(Succeed())
		Expect(svc.SetCertProjection(ctx, "0001", CertProjection{Fingerprint: "aa"})).To(Succeed())
	})
})

// The CertIndex capability is reached through a type assertion, so a wrapper
// backend that does not implement it must be unwrapped or the capability
// disappears. Its InventoryStore sibling has this exact regression test because
// the exact bug existed once on main: ca_key_file wraps the backend in an
// OverlayBackend, the assertion failed on the wrapper, and StorageService
// silently fell back -- there to a whole-blob HMAC that did not match, here to
// the O(N) scan the index exists to replace, which is slower but correct and
// so would not be noticed.
var _ = Describe("CertIndex through an OverlayBackend", func() {
	It("still answers from the index when the backend is wrapped", func() {
		ctx := context.Background()
		dir := GinkgoT().TempDir()

		b, err := NewSQLBackend(SQLConfig{
			Dialect: SQLitePure,
			DSN:     "file:" + filepath.Join(dir, "ca.db"),
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(ctx)).To(Succeed())

		// The shape an operator gets from ca_key_file: the CA key on local disk,
		// everything else in the database.
		overlay, err := NewOverlayBackend(b, map[string]string{
			KeyCAKey: filepath.Join(dir, "ca_key.pem"),
		})
		Expect(err).NotTo(HaveOccurred())

		svc := NewWithBackend(overlay, dir)
		Expect(svc.EnsureDirs(ctx)).To(Succeed())
		Expect(svc.TouchInventory(ctx)).To(Succeed())

		Expect(svc.AppendInventoryRecord(ctx, "0a 2026-01-01T00:00:00UTC 2036-01-01T00:00:00UTC /node1",
			&CertProjection{Fingerprint: "SHA256:AA:BB"})).To(Succeed())
		Expect(svc.SaveCert(ctx, "node1", []byte("cert-pem"))).To(Succeed())

		recs, ok, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue(), "the capability must survive the wrapper")
		Expect(recs).To(HaveLen(1))
		Expect(recs[0].Subject).To(Equal("node1"))
		Expect(recs[0].Fingerprint).To(Equal("SHA256:AA:BB"),
			"the projection must come back through the wrapper, not from a re-parse")

		// And the mutating half of the capability.
		Expect(svc.MarkCertRevoked(ctx, "0a", time.Now())).To(Succeed())
		recs, _, err = svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs).To(HaveLen(1))
		Expect(recs[0].State).To(Equal(CertStateRevoked))
		Expect(recs[0].RevokedAt).NotTo(BeNil())

		Expect(svc.ClearCertRevoked(ctx, "0a")).To(Succeed())
		recs, _, err = svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs[0].State).To(Equal(CertStateSigned))
	})
})
