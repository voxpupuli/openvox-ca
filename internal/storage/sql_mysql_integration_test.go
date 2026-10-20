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

//go:build mysql_integration

package storage

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// mysqlDSNFromEnv returns the MySQL/MariaDB DSN to use for integration tests,
// or skips the test if none is configured. The DSN is the go-sql-driver form,
// e.g. "user:pass@tcp(127.0.0.1:3306)/puppetca".
func mysqlDSNFromEnv() string {
	dsn := os.Getenv("OPENVOX_CA_TEST_MYSQL_DSN")
	if dsn == "" {
		Skip("set OPENVOX_CA_TEST_MYSQL_DSN=user:pass@tcp(127.0.0.1:3306)/puppetca to run mysql integration tests")
	}
	return dsn
}

// newMySQLBackend connects to a real MySQL/MariaDB, migrates the schema, and
// truncates the blobs and inventory tables so each test starts clean. Tests in
// a package run sequentially, so shared tables with a per-test truncate are
// sufficient isolation.
func newMySQLBackend() *SQLBackend {
	b, err := NewSQLBackend(SQLConfig{Dialect: SQLMySQL, DSN: mysqlDSNFromEnv()})
	Expect(err).NotTo(HaveOccurred())
	Expect(b.EnsureReady(context.Background())).To(Succeed())
	for _, table := range []string{"puppet_ca_blobs", "puppet_ca_inventory"} {
		_, err := b.db.ExecContext(context.Background(), "DELETE FROM "+table)
		Expect(err).NotTo(HaveOccurred(), "truncate %s", table)
	}
	DeferCleanup(func() { _ = b.Close() })
	return b
}

var _ = Describe("MySQL PutGetDelete", func() {
	It("puts, gets, overwrites, and deletes a blob", func() {
		b := newMySQLBackend()
		ctx := context.Background()

		_, err := b.Get(ctx, KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Get on missing key")
		payload := []byte("pem-data")
		Expect(b.Put(ctx, KeyCACert, payload, BlobPublic)).To(Succeed())
		got, err := b.Get(ctx, KeyCACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(payload))
		Expect(b.Put(ctx, KeyCACert, []byte("replaced"), BlobPublic)).To(Succeed())
		got, _ = b.Get(ctx, KeyCACert)
		Expect(string(got)).To(Equal("replaced"))
		Expect(b.Delete(ctx, KeyCACert)).To(Succeed())
		err = b.Delete(ctx, KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Delete on missing")
	})
})

var _ = Describe("MySQL LargeBlob", func() {
	It("round-trips a blob larger than the 64 KiB BLOB cap", func() {
		// Exceed MySQL's 64 KiB BLOB cap to prove the puppet_ca_blobs.data column was
		// widened to LONGBLOB by the migration. Use KeyCRL: it is a realistic large
		// blob, whereas KeyInventory is now backed by the structured inventory table
		// (which parses writes as inventory.txt lines, not opaque bytes).
		b := newMySQLBackend()
		ctx := context.Background()
		big := bytes.Repeat([]byte("x"), 200*1024)
		Expect(b.Put(ctx, KeyCRL, big, BlobPrivate)).To(Succeed())
		got, err := b.Get(ctx, KeyCRL)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(big), "large blob round-trip mismatch: got %d bytes, want %d", len(got), len(big))
	})
})

var _ = Describe("MySQL List", func() {
	It("lists keys under a prefix in isolation", func() {
		b := newMySQLBackend()
		ctx := context.Background()
		for _, s := range []string{"a.example", "b.example", "c.example"} {
			Expect(b.Put(ctx, CSRKey(s), []byte("csr"), BlobPublic)).To(Succeed())
		}
		Expect(b.Put(ctx, CertKey("a.example"), []byte("cert"), BlobPublic)).To(Succeed())
		csrs, err := b.List(ctx, csrPrefix)
		Expect(err).NotTo(HaveOccurred())
		sort.Strings(csrs)
		want := []string{CSRKey("a.example"), CSRKey("b.example"), CSRKey("c.example")}
		Expect(fmt.Sprint(csrs)).To(Equal(fmt.Sprint(want)))
	})
})

var _ = Describe("MySQL ModTime", func() {
	It("reports a modification time at or after the write", func() {
		b := newMySQLBackend()
		ctx := context.Background()
		_, err := b.ModTime(ctx, KeyCRL)
		Expect(err).To(MatchError(fs.ErrNotExist), "ModTime on missing")
		before := time.Now().Add(-2 * time.Second)
		Expect(b.Put(ctx, KeyCRL, []byte("crl"), BlobPublic)).To(Succeed())
		mt, err := b.ModTime(ctx, KeyCRL)
		Expect(err).NotTo(HaveOccurred())
		Expect(mt.Before(before)).To(BeFalse(), "ModTime = %v, want >= %v", mt, before)
	})
})

var _ = Describe("MySQL AppendLineConcurrent", func() {
	It("does not drop lines under concurrent appends from two backends", func() {
		// Two backends over the same database simulate two replicas appending
		// inventory entries; each AppendLine inserts a row and none may be dropped.
		// Inventory is structured, so lines must be valid entries.
		dsn := mysqlDSNFromEnv()
		a := newMySQLBackend()
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLMySQL, DSN: dsn})
		Expect(err).NotTo(HaveOccurred())
		defer b.Close()

		const writers = 4
		const perWriter = 25
		var wg sync.WaitGroup
		wg.Add(writers)
		for w := 0; w < writers; w++ {
			backend := a
			if w%2 == 1 {
				backend = b
			}
			w := w
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := 0; i < perWriter; i++ {
					line := fmt.Sprintf("%04d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /w%d-i%d\n", w*perWriter+i, w, i)
					err := backend.AppendLine(context.Background(), KeyInventory, []byte(line), BlobPrivate)
					Expect(err).NotTo(HaveOccurred(), "AppendLine")
				}
			}()
		}
		wg.Wait()

		data, err := a.Get(context.Background(), KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
		Expect(lines).To(HaveLen(writers * perWriter))
	})
})

// "MySQL AcquireLockMutualExclusion" asserts that two replicas holding the
// same GET_LOCK name cannot both enter the critical section at once.
var _ = Describe("MySQL AcquireLockMutualExclusion", func() {
	It("makes a second replica wait while the first holds the lock", func() {
		dsn := mysqlDSNFromEnv()
		a := newMySQLBackend()
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLMySQL, DSN: dsn})
		Expect(err).NotTo(HaveOccurred())
		defer b.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ulA, err := a.AcquireLock(ctx, "crl")
		Expect(err).NotTo(HaveOccurred(), "A AcquireLock")

		type result struct {
			got time.Time
			err error
		}
		ch := make(chan result, 1)
		startB := time.Now()
		go func() {
			ul, err := b.AcquireLock(ctx, "crl")
			res := result{got: time.Now(), err: err}
			if err == nil {
				_ = ul.Unlock()
			}
			ch <- res
		}()

		time.Sleep(400 * time.Millisecond)
		Expect(ulA.Unlock()).To(Succeed(), "A Unlock")

		select {
		case res := <-ch:
			Expect(res.err).NotTo(HaveOccurred(), "B AcquireLock")
			// GET_LOCK is polled with a 1-second granularity, so B may observe the
			// release up to ~1s after A unlocks; assert it waited but don't pin the
			// upper bound tightly.
			waited := res.got.Sub(startB)
			Expect(waited).To(BeNumerically(">=", 300*time.Millisecond), "B acquired after %v; expected to wait while A held the lock", waited)
		case <-time.After(5 * time.Second):
			Fail("B never acquired the lock")
		}
	})
})

var _ = Describe("MySQL AcquireLockDistinctNames", func() {
	It("does not block on distinct lock names", func() {
		b := newMySQLBackend()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ul1, err := b.AcquireLock(ctx, "lock-one")
		Expect(err).NotTo(HaveOccurred(), "AcquireLock one")
		ul2, err := b.AcquireLock(ctx, "lock-two")
		Expect(err).NotTo(HaveOccurred(), "AcquireLock two (distinct name should not block)")
		Expect(ul2.Unlock()).To(Succeed(), "Unlock two")
		Expect(ul1.Unlock()).To(Succeed(), "Unlock one")
	})
})

var _ = Describe("MySQL EndToEndViaStorageService", func() {
	It("round-trips through the storage service", func() {
		b := newMySQLBackend()
		svc := NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
		ctx := context.Background()

		Expect(svc.EnsureDirs(ctx)).To(Succeed())
		Expect(svc.SaveCACert(ctx, []byte("ca-cert-pem"))).To(Succeed())
		ok, _ := svc.HasCACert(ctx)
		Expect(ok).To(BeTrue(), "HasCACert = false after SaveCACert")
		Expect(svc.WriteSerial(ctx, "0001")).To(Succeed())
		got, _ := svc.GetSerial(ctx)
		Expect(string(got)).To(Equal("0001"))
		Expect(svc.InitHMAC(ctx)).To(Succeed())
		line1 := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1"
		line2 := "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2"
		Expect(svc.AppendInventory(ctx, line1)).To(Succeed())
		Expect(svc.AppendInventory(ctx, line2)).To(Succeed())
		inv, _ := svc.ReadInventory(ctx)
		Expect(string(inv)).To(Equal(line1 + "\n" + line2 + "\n"))
		serial, err := svc.LatestSerialForSubject(ctx, "node2")
		Expect(err).NotTo(HaveOccurred(), "LatestSerialForSubject(node2)")
		Expect(serial).To(Equal("0002"))
		Expect(svc.SaveCSR(ctx, "node1", []byte("csr-pem"))).To(Succeed())
		csrs, _ := svc.ListCSRs(ctx)
		Expect(len(csrs)).To(Equal(1), "ListCSRs = %v, want [node1]", csrs)
		Expect(csrs[0]).To(Equal("node1"), "ListCSRs = %v, want [node1]", csrs)
	})
})

var _ = Describe("MySQL CertIndex", func() {
	It("round-trips the certificate index end to end", func() {
		certIndexRoundTrip(newMySQLBackend())
	})

	It("survives a migration rollback and re-apply", func() {
		certIndexMigrationRollback(newMySQLBackend())
	})

	It("drops and restores ip_alt_names through that migration's own steps", func() {
		ipAltNamesMigrationDownUp(newMySQLBackend())
	})
})

var _ = Describe("MySQL schema migrations", func() {
	It("survives two backends migrating the same database at once", func() {
		sqlMigrationsConcurrentRunners(newMySQLBackend)
	})

	It("rolls back or resumes a migration failing mid-sequence, per the dialect's contract", func() {
		migrationDDLFaultInjection(newMySQLBackend())
	})
})

var _ = Describe("MySQL AcquireLockAliasingSubjects", func() {
	It("does not let two subject locks that shared one FNV-1a key exclude each other", func() {
		dsn := mysqlDSNFromEnv()
		a := newMySQLBackend()
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLMySQL, DSN: dsn})
		Expect(err).NotTo(HaveOccurred())
		defer b.Close()

		// Short deadline on purpose: before #203 the second acquisition
		// blocked on the first until the context expired, so a regression
		// fails here in seconds rather than hanging the suite.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Two backends deliberately: a single backend's process-local mutex
		// serialises same-name callers before the server is consulted, and
		// these are different names anyway, so only two connections can show
		// whether the *server* thinks they are the same lock.
		ulA, err := a.AcquireLock(ctx, aliasingSubjectA)
		Expect(err).NotTo(HaveOccurred(), "A AcquireLock")
		defer func() { Expect(ulA.Unlock()).To(Succeed(), "A Unlock") }()

		// A cancel of its own, so the regression path can join the goroutine
		// rather than leave it running. Fail unwinds this spec immediately, and
		// a goroutine still inside AcquireLock would then race b's connection
		// pool and lock map against this node's cleanup and the next spec's
		// setup — noise on precisely the branch that exists to fail cleanly.
		attemptCtx, cancelAttempt := context.WithCancel(ctx)
		defer cancelAttempt()

		done := make(chan error, 1)
		go func() {
			ul, err := b.AcquireLock(attemptCtx, aliasingSubjectB)
			if err == nil {
				err = ul.Unlock()
			}
			done <- err
		}()

		select {
		case err := <-done:
			Expect(err).NotTo(HaveOccurred(), "B AcquireLock on the aliasing subject")
		case <-time.After(5 * time.Second):
			// Cancel unblocks the acquisition; the bounded wait confirms it
			// actually left before Fail unwinds the spec.
			cancelAttempt()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
			Fail("B blocked on A: the two subject locks still share one GET_LOCK name")
		}
	})
})

var _ = Describe("MySQL subject CSR and certificate lifecycle", func() {
	It("tracks a subject's CSR and certificate through save, replace and delete", func() {
		subjectBlobLifecycle(newMySQLBackend())
	})
})
