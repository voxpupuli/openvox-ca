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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Two backend values over one store stand in for two processes throughout this
// file, and the substitution is exact rather than convenient: flock(2) is held
// by an *open file description*, not by a process, so two independent
// os.OpenFile calls exclude each other whether or not a fork separates them.
// What a second value does not model is the process-local mutex each backend
// takes first — which is the point, since that mutex is what would otherwise
// hide the flock from a single-process test. The genuine two-process case is
// covered by "excludes a real second process" below, which re-executes this
// test binary.

var _ = Describe("Same-host locking", func() {
	var ctx context.Context

	BeforeEach(func() { ctx = context.Background() })

	// A short deadline for the contended attempts. Long enough that a slow
	// machine does not report contention where there is none, short enough that
	// a regression fails the suite rather than hanging it.
	const contendedTimeout = 750 * time.Millisecond

	svc := func(b Backend) *StorageService {
		return NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
	}

	Describe("the capability it advertises", func() {
		// The filesystem backend must stay a non-Locker. Anything asking whether
		// the store coordinates across replicas -- an operator pre-flight, an HA
		// readiness check -- probes Locker, and answering "yes" because a second
		// *process* is now handled would recommend a multi-node deployment this
		// backend cannot serve. Same-host locking is a separate capability
		// precisely so this answer does not move.
		It("does not make the filesystem backend a distributed Locker", func() {
			var b any = NewFilesystemBackend(GinkgoT().TempDir())

			_, isLocker := b.(Locker)
			Expect(isLocker).To(BeFalse(),
				"FilesystemBackend must not implement Locker: it cannot coordinate across hosts")

			_, isSameHost := b.(SameHostLocker)
			Expect(isSameHost).To(BeTrue(), "FilesystemBackend must implement SameHostLocker")
		})

		// SQLite keeps answering ErrDistributedLockingUnsupported. The same
		// reasoning as above, plus: WithLock's tier order depends on it, since
		// the same-host tier is only reached through that sentinel.
		It("leaves SQLite reporting distributed locking as unsupported", func() {
			b := newSQLiteBackend()

			_, err := b.AcquireLock(ctx, "crl")
			Expect(err).To(MatchError(ErrDistributedLockingUnsupported))

			ul, err := b.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred(), "but the same-host lock is available")
			Expect(ul.Unlock()).To(Succeed())
		})
	})

	Describe("the filesystem backend", func() {
		It("excludes a second holder of the same lock name", func() {
			dir := GinkgoT().TempDir()
			first, second := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := first.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = second.AcquireSameHostLock(deadline, "crl")
			Expect(err).To(HaveOccurred(), "the second holder must not be granted a held lock")
			Expect(err).To(MatchError(context.DeadlineExceeded))
			// The message has to name the situation, not just the timeout: this
			// is what an operator sees when they run a ctl command against a
			// live server, and "context deadline exceeded" alone would send them
			// looking for a network problem.
			Expect(err.Error()).To(ContainSubstring("another process on this host holds the CA lock"))
			Expect(err.Error()).To(ContainSubstring(`"crl"`))

			Expect(held.Unlock()).To(Succeed())
		})

		It("grants the lock once the first holder releases it", func() {
			dir := GinkgoT().TempDir()
			first, second := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := first.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(held.Unlock()).To(Succeed())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			again, err := second.AcquireSameHostLock(deadline, "crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(again.Unlock()).To(Succeed())
		})

		It("does not make distinct lock names contend", func() {
			dir := GinkgoT().TempDir()
			first, second := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := first.AcquireSameHostLock(ctx, "subject:node1.test")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			other, err := second.AcquireSameHostLock(deadline, "subject:node2.test")
			Expect(err).NotTo(HaveOccurred(), "distinct names must not contend")

			Expect(other.Unlock()).To(Succeed())
			Expect(held.Unlock()).To(Succeed())
		})

		It("keeps lock files inside the lock directory, whatever the name", func() {
			// ValidateSubject runs before a subject reaches a lock name, so this
			// is defence in depth rather than the only barrier -- but the whole
			// reason the mapping hashes is that no name should be able to
			// address a path, and a test is cheaper than trusting that twice.
			dir := GinkgoT().TempDir()
			b := NewFilesystemBackend(dir)

			for _, name := range []string{"crl", "subject:../../etc/shadow", "subject:a/b", strings.Repeat("x", 512)} {
				ul, err := b.AcquireSameHostLock(ctx, name)
				Expect(err).NotTo(HaveOccurred(), "acquiring %q", name)
				Expect(ul.Unlock()).To(Succeed())
			}

			entries, err := os.ReadDir(filepath.Join(dir, fsLockDir))
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(4), "one file per distinct lock name, all inside the lock directory")
			for _, e := range entries {
				Expect(e.Name()).To(HaveSuffix(".lock"))
				Expect(e.Name()).To(HaveLen(64+len(".lock")), "a sha256 hex digest, not the name itself")

				info, err := e.Info()
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Mode().Perm()).To(Equal(os.FileMode(FilePermPrivate)),
					"docs/storage-backends.md documents these as 0600")
			}
		})

		DescribeTable("maps a lock name to a fixed file name",
			// The mapping is cross-release protocol: a server and a `ctl`
			// command exclude each other only by deriving the same file from the
			// same name, so an upgrade that changed it would silently stop the
			// two coordinating — the exact double-write this change prevents,
			// with a green suite. Asserting the shape (64 hex characters) does
			// not pin that; a different digest, a salt, or hashing name+"\n"
			// all keep the shape. These literals are the pin. Regenerate them
			// only alongside a deliberate compatibility story.
			func(name, want string) {
				Expect(fileLockFileName(name)).To(Equal(want))
			},
			Entry("crl", "crl",
				"861aaa0731bdaea1fa598d1750466ef6210c4a1cc1e39d3ea4f3ee4f1bc9e5a2.lock"),
			Entry("bootstrap", "bootstrap",
				"333c04dd151a2a6831c039cb9a651df29198be8a04e16ce861d4b6a34a11c954.lock"),
			Entry("a subject lock", "subject:node1.test",
				"3d5323adb88053356f4fe3797846b0268d1b0fef11f5205e248e6435475201ab.lock"),
		)

		It("resolves the same lock directory from equivalent spellings of the root", func() {
			// Two processes are given the same store as differently written
			// configuration. They exclude each other only if both land on the
			// same file.
			dir := GinkgoT().TempDir()
			plain := NewFilesystemBackend(dir)
			awkward := NewFilesystemBackend(filepath.Join(dir, "signed", ".."))

			held, err := plain.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = awkward.AcquireSameHostLock(deadline, "bootstrap")
			Expect(err).To(MatchError(context.DeadlineExceeded))

			Expect(held.Unlock()).To(Succeed())
		})

		It("stores the lock directory as an absolute path", func() {
			// The spec above is satisfied by filepath.Join's own cleaning and
			// would pass without any normalisation at all. This is the half that
			// needs asserting directly: a relative root is resolved once, at
			// construction, so it cannot mean two different directories to two
			// processes started from different working directories. Asserted on
			// the field rather than behaviourally because reproducing the
			// failure would mean chdir'ing the test process.
			Expect(filepath.IsAbs(newFileLocks(filepath.Join("relative", "cadir", "locks")).dir)).
				To(BeTrue(), "a relative lock directory must be resolved at construction")
		})

		// Each failing acquisition below re-attempts on the *same* backend value
		// afterwards. That second call is not redundant: `acquire` takes the
		// per-name mutex before it touches the filesystem and has to hand it
		// back on every error path by hand, and a missed `local.Unlock()` is
		// invisible to a spec that acquires once and discards the backend. The
		// consequence in production is not a slow lock but a permanent one —
		// sync.Mutex honours no context, so the process wedges on that lock name
		// for its lifetime after a single transient failure.
		expectRetryable := func(b *FilesystemBackend, name string) {
			GinkgoHelper()
			done := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(done)
				if ul, err := b.AcquireSameHostLock(ctx, name); err == nil {
					_ = ul.Unlock()
				}
			}()
			Eventually(done, 5*time.Second).Should(BeClosed(),
				"the failed acquisition leaked its per-name mutex: this lock name is now wedged for the process's lifetime")
		}

		It("reports the lock unsupported rather than failing on a read-only store", func() {
			// `openvox-ca-ctl migrate` takes the bootstrap lock on a source it
			// only reads, and that source may be a read-only snapshot. A store
			// nothing can write to has no writer to exclude, so the capability
			// is absent rather than broken.
			if os.Geteuid() == 0 {
				Skip("root ignores the directory mode this case depends on")
			}
			dir := GinkgoT().TempDir()
			Expect(os.Chmod(dir, 0500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(dir, 0700) })

			b := NewFilesystemBackend(dir)
			_, err := b.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).To(MatchError(ErrSameHostLockingUnsupported))
			expectRetryable(b, "bootstrap")
		})

		It("reports a genuine filesystem failure rather than hiding it", func() {
			// The complement of the case above: if the lock cannot be taken for
			// any reason other than "nothing here is writable", whether another
			// process is mutating the store is unknown, and silently proceeding
			// would be the corruption this change exists to prevent. A plain
			// file where the lock directory belongs stands in for that class.
			dir := GinkgoT().TempDir()
			Expect(os.WriteFile(filepath.Join(dir, fsLockDir), []byte("not a directory"), 0600)).To(Succeed())

			b := NewFilesystemBackend(dir)
			_, err := b.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).To(HaveOccurred())
			Expect(err).NotTo(MatchError(ErrSameHostLockingUnsupported))
			Expect(err.Error()).To(ContainSubstring("same-host lock"))
			expectRetryable(b, "bootstrap")
		})

		It("fails loudly when the lock directory belongs to another user", func() {
			// The distinction the two specs above turn on. os.MkdirAll returns
			// nil for a directory that already exists without checking whether
			// it can be written, so a permission error at the *file* is not
			// evidence the store is read-only — it is evidence the lock
			// directory belongs to someone else, which is what an
			// `openvox-ca-ctl` run under sudo leaves behind for a server running
			// as puppet-ca. Downgrading there would return that server to its
			// pre-#187 behaviour permanently and silently, while the root
			// process went on taking flocks it believed were exclusive.
			if os.Geteuid() == 0 {
				Skip("root ignores the directory mode this case depends on")
			}
			dir := GinkgoT().TempDir()
			locks := filepath.Join(dir, fsLockDir)
			Expect(os.MkdirAll(locks, DirPerm)).To(Succeed())
			Expect(os.Chmod(locks, 0500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(locks, 0700) })

			b := NewFilesystemBackend(dir)
			_, err := b.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).To(HaveOccurred())
			Expect(err).NotTo(MatchError(ErrSameHostLockingUnsupported),
				"an unwritable lock directory that already exists is not a read-only store")
			Expect(err.Error()).To(ContainSubstring("chown"),
				"the error must tell the operator how to fix it")
			expectRetryable(b, "bootstrap")
		})

		It("grants an uncontended lock even to a caller whose deadline has gone", func() {
			// ctx bounds the wait for another process, not the acquisition, so
			// this matches the process-local mutex the tier replaces: that
			// mutex honours no deadline either, and a caller arriving with a
			// spent one still enters its critical section and fails on its own
			// first storage read.
			//
			// The distinction is not cosmetic. Revoke counts a failure that
			// reached the CRL work and does not count one refused at lock
			// acquisition (docs/metrics.md, and the alert built on it), so
			// rejecting here would move the filesystem and SQLite backends from
			// one side of that split to the other without anyone asking.
			spent, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
			defer cancel()

			ul, err := NewFilesystemBackend(GinkgoT().TempDir()).AcquireSameHostLock(spent, "crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(ul.Unlock()).To(Succeed())
		})

		It("gives up at once when the lock is held and the deadline has gone", func() {
			// The other half: waiting is what ctx bounds, and a spent deadline
			// buys no wait at all.
			dir := GinkgoT().TempDir()
			held, err := NewFilesystemBackend(dir).AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())
			// Released explicitly below rather than in a cleanup: Unlocker's
			// contract is exactly-once, and a second call unlocks an unlocked
			// mutex, which is fatal rather than merely wrong.

			cancelled, cancel := context.WithCancel(ctx)
			cancel()

			waiter := NewFilesystemBackend(dir)
			start := time.Now()
			_, err = waiter.AcquireSameHostLock(cancelled, "crl")
			Expect(err).To(MatchError(context.Canceled))
			Expect(time.Since(start)).To(BeNumerically("<", contendedTimeout))

			Expect(held.Unlock()).To(Succeed())
			expectRetryable(waiter, "crl")
		})

		It("picks up a release promptly however long it has been waiting", func() {
			// The backoff doubles, and without its ceiling a waiter under the
			// production 60s lockTimeout reaches a ~40s sleep: a lock released
			// at 25s would not be noticed until past 40s, so a revocation that
			// should have succeeded fails at its deadline instead. Every other
			// contended spec here gives up well before the doubling saturates,
			// so none of them would notice the ceiling going missing.
			//
			// Held for comfortably longer than the point at which the backoff
			// reaches fileLockRetryMax (5ms doubling: ~635ms to saturate), then
			// the hand-off is required to be quick rather than another doubling.
			dir := GinkgoT().TempDir()
			holder, waiter := NewFilesystemBackend(dir), NewFilesystemBackend(dir)

			held, err := holder.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())

			acquired := make(chan time.Duration, 1)
			go func() {
				defer GinkgoRecover()
				attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				start := time.Now()
				ul, err := waiter.AcquireSameHostLock(attempt, "crl")
				Expect(err).NotTo(HaveOccurred())
				acquired <- time.Since(start)
				Expect(ul.Unlock()).To(Succeed())
			}()

			// Long enough that the backoff has saturated at its ceiling.
			time.Sleep(1500 * time.Millisecond)
			releasedAt := time.Now()
			Expect(held.Unlock()).To(Succeed())

			var waited time.Duration
			Eventually(acquired, 10*time.Second).Should(Receive(&waited))
			Expect(time.Since(releasedAt)).To(BeNumerically("<", 2*fileLockRetryMax),
				"the waiter must notice the release within a capped poll interval, not after an unbounded doubling")
			Expect(waited).To(BeNumerically(">", time.Second), "sanity: it really did wait")
		})
	})

	Describe("the SQLite backend", func() {
		It("excludes a second connection to the same database file", func() {
			dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")
			first, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = first.Close() })
			second, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = second.Close() })

			held, err := first.AcquireSameHostLock(ctx, "bootstrap")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = second.AcquireSameHostLock(deadline, "bootstrap")
			Expect(err).To(MatchError(context.DeadlineExceeded))

			Expect(held.Unlock()).To(Succeed())
		})

		It("puts its lock files beside the database, not inside it", func() {
			dir := GinkgoT().TempDir()
			dbPath := filepath.Join(dir, "ca.db")
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })
			Expect(b.EnsureReady(ctx)).To(Succeed(), "so there is a database file to sit beside")

			ul, err := b.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(ul.Unlock()).To(Succeed())

			names := []string{}
			entries, err := os.ReadDir(filepath.Join(dir, ".ca.db.locks"))
			Expect(err).NotTo(HaveOccurred(), "lock directory beside the database file")
			for _, e := range entries {
				names = append(names, e.Name())
			}
			// EnsureReady took the schema-migration lock through the same tier,
			// so its file is here too — which is the point of that path.
			Expect(names).To(ContainElements(
				fileLockFileName("crl"), fileLockFileName(lockNameSQLMigrate)))

			// The database file itself is never the lock: SQLite locks it, and a
			// second scheme over the same file would leave two answers to
			// "is this database busy".
			info, err := os.Stat(dbPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeFalse())
		})

		It("holds the migration lock across the whole schema migration", func() {
			// The SQLite half of the change: EnsureReady walks the tiers by hand
			// so two starters cannot both record a version and run the DDL. The
			// lock file merely existing proves only that AcquireSameHostLock was
			// called — move the Unlock out of its defer and that assertion stays
			// green while the race returns in full. This holds the lock from
			// outside and requires EnsureReady to be refused.
			dsn := "file:" + filepath.Join(GinkgoT().TempDir(), "ca.db")
			holder, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = holder.Close() })

			held, err := holder.AcquireSameHostLock(ctx, lockNameSQLMigrate)
			Expect(err).NotTo(HaveOccurred())

			// A short migration budget so the refusal arrives inside the spec
			// rather than after the default ten minutes.
			second, err := NewSQLBackend(SQLConfig{
				Dialect: SQLitePure, DSN: dsn, MigrationTimeout: contendedTimeout,
			})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = second.Close() })

			err = second.EnsureReady(ctx)
			Expect(err).To(HaveOccurred(), "a second starter must not migrate under a held lock")
			Expect(err.Error()).To(ContainSubstring("another process on this host may be migrating"),
				"and the error must say why, since this is a startup failure an operator sees")

			// Released, it proceeds — so the refusal was the lock, not the DSN.
			Expect(held.Unlock()).To(Succeed())
			Expect(second.EnsureReady(ctx)).To(Succeed())
		})

		It("reports the lock unsupported for an in-memory database", func() {
			// Nothing outside this process can open it, so there is nothing to
			// exclude and no file to sit beside. WithLock then uses the
			// process-local mutex, which is the whole of the guarantee available.
			for _, dsn := range []string{":memory:", "file::memory:", "file:x?mode=memory&cache=shared"} {
				b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
				Expect(err).NotTo(HaveOccurred(), "opening %q", dsn)

				_, err = b.AcquireSameHostLock(ctx, "crl")
				Expect(err).To(MatchError(ErrSameHostLockingUnsupported), "dsn %q", dsn)
				Expect(b.Close()).To(Succeed())
			}
		})

		DescribeTable("derives the database path from a DSN",
			func(dsn, wantPath string, wantOK bool) {
				got, ok := sqliteFilePath(dsn)
				Expect(ok).To(Equal(wantOK), "dsn %q", dsn)
				if wantOK {
					Expect(got).To(Equal(wantPath), "dsn %q", dsn)
				}
			},
			Entry("bare absolute path", "/var/lib/puppet-ca/ca.db", "/var/lib/puppet-ca/ca.db", true),
			Entry("bare relative path", "ca.db", "ca.db", true),
			Entry("bare path with parameters", "/var/lib/ca.db?_txlock=immediate", "/var/lib/ca.db", true),
			Entry("file URI, absolute", "file:/var/lib/ca.db", "/var/lib/ca.db", true),
			Entry("file URI, absolute with empty authority", "file:///var/lib/ca.db", "/var/lib/ca.db", true),
			Entry("file URI, relative", "file:ca.db", "ca.db", true),
			Entry("file URI with parameters", "file:/var/lib/ca.db?_pragma=busy_timeout(5000)", "/var/lib/ca.db", true),
			Entry("in-memory, bare", ":memory:", "", false),
			Entry("in-memory, URI", "file::memory:", "", false),
			Entry("in-memory, mode parameter", "file:anything?mode=memory", "", false),
			Entry("empty", "", "", false),
		)
	})

	Describe("the overlay backend", func() {
		It("delegates the same-host lock to its base", func() {
			// The overlay serves local CA material but the store it protects is
			// the base's, so two servers sharing a cadir must still exclude each
			// other through it.
			dir := GinkgoT().TempDir()
			certFile := filepath.Join(GinkgoT().TempDir(), "ca_crt.pem")
			Expect(os.WriteFile(certFile, []byte("cert"), 0600)).To(Succeed())

			overlayOver := func() *OverlayBackend {
				o, err := NewOverlayBackend(NewFilesystemBackend(dir), map[string]string{KeyCACert: certFile})
				Expect(err).NotTo(HaveOccurred())
				return o
			}
			first, second := overlayOver(), overlayOver()

			held, err := first.AcquireSameHostLock(ctx, "crl")
			Expect(err).NotTo(HaveOccurred())

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			_, err = second.AcquireSameHostLock(deadline, "crl")
			Expect(err).To(MatchError(context.DeadlineExceeded))

			Expect(held.Unlock()).To(Succeed())
		})

		It("reports the lock unsupported when the base offers neither tier", func() {
			o, err := NewOverlayBackend(&noLockBackend{}, map[string]string{KeyCACert: "/dev/null"})
			Expect(err).NotTo(HaveOccurred())

			_, err = o.AcquireSameHostLock(ctx, "crl")
			Expect(err).To(MatchError(ErrSameHostLockingUnsupported))
		})
	})

	Describe("WithLock", func() {
		It("takes the same-host lock on the filesystem backend", func() {
			// The tier is reached, not merely implemented: a second service over
			// the same cadir cannot enter the critical section while the first
			// is inside it. Before this change both proceeded at once.
			dir := GinkgoT().TempDir()
			first, second := svc(NewFilesystemBackend(dir)), svc(NewFilesystemBackend(dir))

			inside := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- first.WithLock(ctx, "crl", func() error {
					close(inside)
					<-release
					return nil
				})
			}()
			<-inside

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			err := second.WithLock(deadline, "crl", func() error {
				Fail("the second service entered a critical section the first was holding")
				return nil
			})
			Expect(err).To(MatchError(context.DeadlineExceeded))
			Expect(err.Error()).To(ContainSubstring("acquiring same-host lock"))

			close(release)
			Expect(<-done).To(Succeed())
		})

		It("falls back to the process-local mutex when no tier is available", func() {
			// A backend with neither capability must behave exactly as it did
			// before same-host locking existed: fn runs, serialised in-process.
			s := svc(&noLockBackend{})
			Expect(s.WithLock(ctx, "crl", func() error { return nil })).To(Succeed())
		})

		It("prefers the distributed lock when the backend offers both", func() {
			// The tier order is the whole of the "two distinct capabilities"
			// argument: a backend that can coordinate across hosts must be
			// locked that way, not settled for the weaker one.
			//
			// bothLocker embeds the *concrete* filesystem backend rather than
			// the Backend interface, and that is load-bearing. Embedding the
			// interface promotes only the interface's own methods, and
			// AcquireSameHostLock is not among them — so a stub built that way
			// does not satisfy SameHostLocker at all, and this spec would pass
			// with the tiers reversed, or with tier 2 deleted outright.
			dir := GinkgoT().TempDir()
			both := &bothLocker{FilesystemBackend: NewFilesystemBackend(dir)}

			var asSameHost any = both
			_, ok := asSameHost.(SameHostLocker)
			Expect(ok).To(BeTrue(), "precondition: this backend really does offer both tiers")

			Expect(svc(both).WithLock(ctx, "crl", func() error { return nil })).To(Succeed())
			Expect(both.distributedCalls).To(Equal(1), "the distributed lock must be the one taken")

			// And the same-host tier was not reached: it would have left its
			// directory behind.
			_, err := os.Stat(filepath.Join(dir, fsLockDir))
			Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue(),
				"the same-host tier must not run when a distributed lock succeeded")
		})
	})

	Describe("across real processes", func() {
		It("excludes a real second process", func() {
			// Everything above proves flock's open-file-description semantics.
			// This proves the claim the issue actually makes -- that a `ctl`
			// command cannot write behind a running server's back -- by
			// re-executing this test binary as a second process and asking it to
			// hold the lock.
			if !fileLockingSupported {
				Skip("no flock(2) on " + runtime.GOOS)
			}
			dir := GinkgoT().TempDir()

			// startLockHelper registers its own cleanup.
			helper := startLockHelper(dir, "crl")

			deadline, cancel := context.WithTimeout(ctx, contendedTimeout)
			defer cancel()
			err := svc(NewFilesystemBackend(dir)).WithLock(deadline, "crl", func() error {
				Fail("this process took a lock another process was holding")
				return nil
			})
			Expect(err).To(MatchError(context.DeadlineExceeded))
			Expect(err.Error()).To(ContainSubstring("another process on this host holds the CA lock"))

			// And the lock is genuinely released when that process exits, with
			// no cleanup of our own: the kernel drops it with the descriptor.
			helper.stop()
			Eventually(func() error {
				attempt, cancel := context.WithTimeout(ctx, contendedTimeout)
				defer cancel()
				return svc(NewFilesystemBackend(dir)).WithLock(attempt, "crl", func() error { return nil })
			}, 5*time.Second, 50*time.Millisecond).Should(Succeed())
		})
	})
})

// noLockBackend implements neither Locker nor SameHostLocker, standing in for a
// backend that can only be serialised in-process. The embedded nil Backend is
// never called: every spec using it stops at the capability probe.
type noLockBackend struct{ Backend }

// bothLocker offers both locking capabilities: a working same-host lock from the
// embedded concrete filesystem backend, and a distributed one of its own. It
// exists to pin WithLock's tier order, which no real backend can currently
// exercise — the two that implement SameHostLocker are precisely the two that
// have no distributed lock.
//
// The concrete type is embedded deliberately. An embedded *interface* promotes
// only that interface's method set, so a stub built over Backend would silently
// fail to satisfy SameHostLocker and make the ordering assertion vacuous.
type bothLocker struct {
	*FilesystemBackend
	distributedCalls int
}

func (b *bothLocker) AcquireLock(context.Context, string) (Unlocker, error) {
	b.distributedCalls++
	return noopUnlocker{}, nil
}

type noopUnlocker struct{}

func (noopUnlocker) Unlock() error { return nil }
