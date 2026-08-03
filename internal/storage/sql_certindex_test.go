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
		AuthExtensions: map[string]string{"pp_auth_role": "webserver"},
	}
	Expect(svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
	Expect(svc.AppendInventoryRecord(ctx, "0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1", &proj)).To(Succeed())
	Expect(svc.AppendInventory(ctx, "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2")).To(Succeed())
	for _, subject := range []string{"node1", "node2"} {
		Expect(b.Put(ctx, CertKey(subject), []byte("pem-"+subject), BlobPublic)).To(Succeed())
	}

	recs, ok, err := svc.CertStatuses(ctx, "")
	Expect(err).NotTo(HaveOccurred(), "CertStatuses")
	Expect(ok).To(BeTrue())
	Expect(recs).To(HaveLen(2), "one record per subject, latest issuance only")
	Expect(recs[0].Subject).To(Equal("node1"))
	Expect(recs[0].Serial).To(Equal("0003"), "node1's latest issuance wins")
	Expect(recs[0].Fingerprint).To(Equal(proj.Fingerprint))
	Expect(recs[0].DNSAltNames).To(Equal(proj.DNSAltNames))
	Expect(recs[0].AuthExtensions).To(Equal(proj.AuthExtensions))
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
	Expect(recs[1].Fingerprint).To(Equal("dd:ee:ff"))
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
	certIndexRoundTrip(b)
}

var _ = Describe("SQLiteCertIndex", func() {
	It("round-trips the certificate index end to end", func() {
		certIndexRoundTrip(newSQLiteBackend())
	})

	It("survives a migration rollback and re-apply", func() {
		certIndexMigrationRollback(newSQLiteBackend())
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
