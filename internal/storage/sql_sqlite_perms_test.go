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

// Not built on Windows: these specs set syscall.Umask, which does not exist
// there, and file modes do not carry the meaning they are about. The build
// system tolerates a Windows target but nothing ships one.
//go:build !windows

package storage

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The SQLite database holds the CA private key as a blob (KeyCAKey), unencrypted
// unless the operator opts into encrypt_ca_key, so the file carries the material
// the filesystem backend keeps under private/.
//
// The invariant these specs pin is narrow and deliberate: **no world bits, ever,
// on a file openvox-ca creates**. It is not "0600". Group access is permitted
// because a Kubernetes fsGroup ORs it back into the volume at every mount and an
// arbitrary-uid platform needs it to reach a store it did not create; forcing
// 0600 would fight both and protect nothing, since the pod's own group is not a
// third party. What group access cannot be is world access, and that is what is
// asserted here.
//
// The modes are written as literals rather than as sqliteFilePermCreate. Asserting
// the constant would compare the code against itself; these assert the guarantee
// an operator is given.
//
// The sidecars matter as much as the database: a committed page lives in the WAL
// until a checkpoint moves it, so which file holds the key bytes at a given
// instant is a function of checkpoint state, not of anything the operator
// controls. -journal joins them because journal_mode=WAL is only a default and
// the DSN can override it.
const (
	umaskLoose  = 0o022 // the usual default: turns a 0666 create into 0644
	umaskLooser = 0o000 // nothing masked at all: a 0666 create stays 0666
	umaskTight  = 0o077 // group stripped as well as world
)

// permOf stats path and returns its permission bits, failing the spec if the
// file is absent. Absence is a failure rather than a skip: every caller below
// has just done the work that creates the file, so a missing file means the
// spec stopped exercising what it claims to.
func permOf(path string) os.FileMode {
	GinkgoHelper()
	info, err := os.Stat(path)
	Expect(err).NotTo(HaveOccurred(), "stat %s", path)
	return info.Mode().Perm()
}

// worldBits returns the permission bits granted to users outside the owner and
// the group, which is the only thing these specs care about.
func worldBits(path string) os.FileMode {
	GinkgoHelper()
	return permOf(path) & 0o007
}

// sqliteSidecars names the two files SQLite maintains beside the database in WAL
// mode.
func sqliteSidecars(db string) (wal, shm string) {
	return db + "-wal", db + "-shm"
}

var _ = Describe("SQLiteFilePermissions", func() {
	var dbPath string

	// A permissive umask is set for every spec in this block. Without it the
	// result would depend on the umask of whoever ran the suite, and a developer
	// or CI runner sitting at 0077 would see these pass against code that offers
	// no guarantee at all.
	BeforeEach(func() {
		old := syscall.Umask(umaskLoose)
		DeferCleanup(func() { syscall.Umask(old) })
		dbPath = filepath.Join(GinkgoT().TempDir(), "ca.db")
	})

	// openAt opens a backend on dbPath, migrates it, and writes a blob so the WAL
	// has content. Returns the backend for the caller to keep using.
	openAt := func() *SQLBackend {
		GinkgoHelper()
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")
		Expect(b.Put(context.Background(), KeyCAKey, []byte("-----BEGIN RSA PRIVATE KEY-----"), BlobPrivate)).
			To(Succeed(), "Put CA key")
		return b
	}

	It("creates the database with no world access", func() {
		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		Expect(worldBits(dbPath)).To(BeZero(), "world bits on the database")
	})

	It("creates the -wal and -shm sidecars with no world access", func() {
		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		wal, shm := sqliteSidecars(dbPath)
		Expect(worldBits(wal)).To(BeZero(), "world bits on -wal")
		Expect(worldBits(shm)).To(BeZero(), "world bits on -shm")
	})

	// The spec that would have caught issue #351. An umask of 0000 masks nothing,
	// so a driver-created database lands at 0666 and every local account can read
	// the key. The mode is chosen at creation rather than inherited, so the umask
	// cannot widen it.
	It("grants no world access even when the umask masks nothing", func() {
		old := syscall.Umask(umaskLooser)
		DeferCleanup(func() { syscall.Umask(old) })

		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		wal, shm := sqliteSidecars(dbPath)
		Expect(worldBits(dbPath)).To(BeZero(), "world bits on the database under umask 0000")
		Expect(worldBits(wal)).To(BeZero(), "world bits on -wal under umask 0000")
		Expect(worldBits(shm)).To(BeZero(), "world bits on -shm under umask 0000")
	})

	// The other half of the policy, and the reason this is not simply 0600: group
	// access survives. A Kubernetes fsGroup reapplies it at every mount, and on an
	// arbitrary-uid platform it is how the CA reaches a database created by a
	// previous pod under a different uid. Taking it away would break those
	// deployments to protect against the pod's own group.
	It("leaves group access in place when the umask permits it", func() {
		old := syscall.Umask(umaskLooser)
		DeferCleanup(func() { syscall.Umask(old) })

		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		Expect(permOf(dbPath)).To(Equal(os.FileMode(0o660)), "database mode under umask 0000")
	})

	// The umask still narrows, it just cannot widen. An operator who wants the
	// group bits gone sets a umask and gets them gone.
	It("lets a stricter umask narrow the mode further", func() {
		old := syscall.Umask(umaskTight)
		DeferCleanup(func() { syscall.Umask(old) })

		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		Expect(permOf(dbPath)).To(Equal(os.FileMode(0o600)), "database mode under umask 0077")
	})

	// Nothing here modifies a file that already exists. A database whose mode is
	// wrong is the operator's to fix, and the server refuses to serve it rather
	// than silently correcting it -- see StorageService.CheckKeyPermissions and
	// the startup check that acts on it.
	It("leaves an existing database's mode alone", func() {
		Expect(os.WriteFile(dbPath, nil, 0o644)).To(Succeed(), "seed a world-readable database")

		b := openAt()
		DeferCleanup(func() { _ = b.Close() })

		Expect(permOf(dbPath)).To(Equal(os.FileMode(0o644)), "the mode the operator left")
	})

	// "Only if it does not already exist in any form" is O_EXCL's contract, and
	// these three are the forms that would otherwise be dangerous: a directory
	// whose mode we would have replaced, a symlink we would have written through,
	// and a FIFO that would have blocked a reader for ever.
	It("does not create through, or modify, a directory at the database path", func() {
		dir := filepath.Join(GinkgoT().TempDir(), "adirectory")
		Expect(os.Mkdir(dir, 0o755)).To(Succeed(), "seed a directory where a database is named")

		b, _ := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dir})
		if b != nil {
			DeferCleanup(func() { _ = b.Close() })
		}

		Expect(permOf(dir)).To(Equal(os.FileMode(0o755)), "directory mode left alone")
	})

	// A symlink whose target does not exist yet is the operator's own
	// configuration -- "point the CA at the data volume, then bootstrap" -- so it
	// is resolved and the real file is created, with the same mode rule. O_EXCL
	// still applies at the resolved path, so an existing file there is never
	// written through or clobbered.
	It("creates the target of a dangling symlink, with no world access", func() {
		target := filepath.Join(GinkgoT().TempDir(), "elsewhere.db")
		Expect(os.Symlink(target, dbPath)).To(Succeed(), "plant a dangling symlink")

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })

		Expect(target).To(BeAnExistingFile(), "the database was created at the link target")
		Expect(worldBits(target)).To(BeZero(), "world bits on the created target")
	})

	It("does not block on a FIFO at the database path", func() {
		Expect(syscall.Mkfifo(dbPath, 0o644)).To(Succeed(), "plant a FIFO")

		// Reaching this assertion at all is the point: opening a FIFO for reading
		// blocks until a writer appears, so a create that did not use O_EXCL, or
		// any inspection that opened the path, would hang here for ever and take
		// the suite with it rather than failing.
		b, _ := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
		if b != nil {
			// sql.Open is lazy, so construction succeeds here and leaves a handle
			// to close even though nothing usable is behind it.
			DeferCleanup(func() { _ = b.Close() })
		}

		Expect(permOf(dbPath)).To(Equal(os.FileMode(0o644)), "FIFO mode left alone")
	})

	// A symlinked database is the operator's own choice, and it worked before any
	// of this existed. The DSN is resolved so the sidecars and the lock directory
	// are derived from the same real path -- which is also where SQLite puts them,
	// since it canonicalises the filename first.
	It("accepts a DSN that is a symlink to an existing database", func() {
		realDir := GinkgoT().TempDir()
		realDB := filepath.Join(realDir, "real.db")
		link := filepath.Join(GinkgoT().TempDir(), "link.db")
		Expect(os.WriteFile(realDB, nil, 0o600)).To(Succeed(), "seed the relocated database")
		Expect(os.Symlink(realDB, link)).To(Succeed(), "point the DSN at a symlink")

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + link})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")
		Expect(b.Put(context.Background(), KeyCAKey, []byte("key"), BlobPrivate)).To(Succeed(), "Put CA key")

		wal, shm := sqliteSidecars(realDB)
		Expect(worldBits(realDB)).To(BeZero(), "world bits on the resolved database")
		Expect(worldBits(wal)).To(BeZero(), "world bits on -wal beside the resolved path")
		Expect(worldBits(shm)).To(BeZero(), "world bits on -shm beside the resolved path")
	})

	// A chain of dangling links, which is what a relocation through a stable
	// alias looks like before the first bootstrap. Stopping after one hop would
	// leave everything derived from the path -- the sidecars, the lock directory,
	// the files the permission check judges -- pointing at an intermediate link
	// while the driver created the real database somewhere else, under the umask.
	It("resolves a chain of dangling symlinks to its final target", func() {
		dir := GinkgoT().TempDir()
		realDB := filepath.Join(dir, "real.db")
		middle := filepath.Join(dir, "middle.db")
		link := filepath.Join(dir, "link.db")
		Expect(os.Symlink(realDB, middle)).To(Succeed(), "middle -> real")
		Expect(os.Symlink(middle, link)).To(Succeed(), "link -> middle")

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + link})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(realDB).To(BeAnExistingFile(), "the database was created at the end of the chain")
		Expect(worldBits(realDB)).To(BeZero(), "world bits on the created target")
		// Lstat, not Stat: the intermediate link now resolves to the real
		// database, so following it would report a regular file and the
		// assertion would be about the target rather than the link.
		info, err := os.Lstat(middle)
		Expect(err).NotTo(HaveOccurred(), "lstat the intermediate link")
		Expect(info.Mode()&os.ModeSymlink).NotTo(BeZero(), "the intermediate link was not replaced by a file")
	})

	// -journal is declared as key material because journal_mode=WAL is only a
	// default the operator can override back to a rollback journal -- and a
	// rollback journal holds page images of the key row. Every other spec here
	// runs in WAL mode, where no -journal is ever created, so the one sidecar
	// whose presence depends on a decision the operator makes had no mode
	// assertion at all.
	It("creates the -journal sidecar without world access when the DSN asks for one", func() {
		dir, err := filepath.EvalSymlinks(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred(), "resolve the fixture directory")
		dbPath := filepath.Join(dir, "ca.db")

		// journal_mode is only added when the DSN has not set it, so this wins.
		dsn := "file:" + dbPath + "?_pragma=journal_mode(DELETE)"
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dsn})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(worldBits(dbPath)).To(BeZero(), "the database itself")
		Expect(b.KeyFilePaths()).To(ContainElement(dbPath+"-journal"), "declared as key material")

		// The journal exists only while a transaction is open, so assert the
		// mode on whichever of the two spellings is on disk after the write
		// above rather than requiring one to be.
		journal := dbPath + "-journal"
		if _, statErr := os.Lstat(journal); statErr == nil {
			Expect(worldBits(journal)).To(BeZero(), "the rollback journal holds page images of the key")
		}
		Expect(worldBits(dir)).To(BeZero(), "and nothing widened the directory")
	})

	// mode=memory is URI syntax, and SQLite honours it only for a "file:" DSN.
	// On a bare path the driver opens the file anyway, so reading the parameter
	// there meant the create, the key-file list and the lock were all skipped
	// while a real database was written at the umask -- issue #351 again,
	// through a DSN that merely looks like it names no file.
	It("protects a bare DSN carrying mode=memory, which still creates a file", func() {
		// 0022 deliberately, against this block's 0077. At 0077 a database the
		// driver created for itself also lands at 0600, so a "no world bits"
		// assertion would pass with the protection removed and prove nothing.
		// At 0022 the two outcomes are 0640 and 0644, and they differ.
		old := syscall.Umask(0o022)
		DeferCleanup(func() { syscall.Umask(old) })

		dir, err := filepath.EvalSymlinks(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred(), "resolve the fixture directory")
		dbPath := filepath.Join(dir, "ca.db")

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: dbPath + "?mode=memory"})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(dbPath).To(BeAnExistingFile(), "the driver creates a file regardless")
		Expect(worldBits(dbPath)).To(BeZero(), "and it must not be world-accessible")
		Expect(b.KeyFilePaths()).To(ContainElement(dbPath), "it is judged as key material")
		_, ok := sqliteLockDir(dbPath + "?mode=memory")
		Expect(ok).To(BeTrue(), "and it takes a same-host lock")
	})

	// The "file:" form is where the parameter means what it says, and there the
	// database really is in memory with nothing on disk to protect.
	It("still treats a file: DSN with mode=memory as in-memory", func() {
		dir := GinkgoT().TempDir()
		dbPath := filepath.Join(dir, "ca.db")

		_, ok := sqliteFilePath("file:" + dbPath + "?mode=memory")

		Expect(ok).To(BeFalse(), "no file to protect")
	})

	// A relative target, which is the ordinary spelling of the configuration the
	// dangling-link loop exists for ("ln -s ../data/ca.db"). Every other link in
	// these specs is built from a filepath.Join and so is absolute, which means
	// os.Readlink returns an absolute path and the join against the link's own
	// directory is never executed. If that join were wrong, the sidecar names,
	// the lock directory and the paths the permission check judges would all
	// point somewhere the driver never opens, while the driver created the real
	// database elsewhere at the umask -- issue #351 by another route, with
	// nothing failing.
	It("resolves a dangling symlink whose target is relative", func() {
		// Resolved up front, because macOS reaches TempDir through /var -> private/var
		// and the backend resolves the parent too: comparing against the
		// unresolved spelling would fail for a reason that is not the subject.
		dir, err := filepath.EvalSymlinks(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred(), "resolve the fixture directory")
		Expect(os.Mkdir(filepath.Join(dir, "data"), 0o750)).To(Succeed(), "the target's directory")
		link := filepath.Join(dir, "link.db")
		Expect(os.Symlink(filepath.Join("data", "real.db"), link)).To(Succeed(), "link -> data/real.db")

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + link})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		realDB := filepath.Join(dir, "data", "real.db")
		Expect(realDB).To(BeAnExistingFile(), "the database was created at the relative target")
		Expect(worldBits(realDB)).To(BeZero(), "world bits on the created target")

		// And everything derived from the DSN followed it there, rather than
		// staying beside the link.
		Expect(b.KeyFilePaths()).To(ContainElement(realDB+"-wal"), "the sidecar names follow the target")
		lockDir, ok := sqliteLockDir("file:" + link)
		Expect(ok).To(BeTrue(), "lock directory for the link spelling")
		Expect(filepath.Dir(lockDir)).To(Equal(filepath.Join(dir, "data")), "beside the target")
	})

	// A cycle is what the hop bound exists for. Without it the resolution loop
	// spins for ever and startup hangs with no diagnostic, which is worse than
	// the open's own rejection. Reaching the assertion at all is the result.
	It("gives up on a symlink cycle rather than spinning", func() {
		dir := GinkgoT().TempDir()
		a := filepath.Join(dir, "a.db")
		bLink := filepath.Join(dir, "b.db")
		Expect(os.Symlink(bLink, a)).To(Succeed(), "a -> b")
		Expect(os.Symlink(a, bLink)).To(Succeed(), "b -> a")

		back, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + a})
		if back != nil {
			DeferCleanup(func() { _ = back.Close() })
		}

		// Returning at all is the result. But asserting nothing about what it
		// returned would let "give up and leave the path as given" become
		// anything else without a spec noticing, so pin the current outcome:
		// construction succeeds, because sql.Open is lazy and the resolution
		// simply stops after the hop bound.
		Expect(err).NotTo(HaveOccurred(), "giving up on the cycle is not a construction failure")
		Expect(back.KeyFilePaths()).NotTo(BeEmpty(), "it still derived paths from the DSN")
	})

	// The upgrade boundary the resolution created. A process on a version that
	// locked beside the DSN spelling and one on this version do not exclude each
	// other, and nothing here can prevent that -- the other process is the one
	// holding the wrong lock. What it can do is say so where an operator will
	// read it.
	Describe("a lock directory stranded beside the DSN's own spelling", func() {
		captureWarnings := func() *bytes.Buffer {
			GinkgoHelper()
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })
			return &buf
		}

		It("warns when one exists and this version locks elsewhere", func() {
			realDB := filepath.Join(GinkgoT().TempDir(), "real.db")
			linkDir := GinkgoT().TempDir()
			link := filepath.Join(linkDir, "link.db")
			Expect(os.WriteFile(realDB, nil, 0o600)).To(Succeed(), "seed the database")
			Expect(os.Symlink(realDB, link)).To(Succeed(), "reach it through a link")
			legacy := filepath.Join(linkDir, ".link.db.locks")
			Expect(os.Mkdir(legacy, 0o700)).To(Succeed(), "what an earlier version left behind")

			buf := captureWarnings()
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + link})
			Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
			DeferCleanup(func() { _ = b.Close() })

			Expect(buf.String()).To(ContainSubstring("stranded"), "the warning")
			Expect(buf.String()).To(ContainSubstring(legacy), "where the old lock directory is")
			Expect(buf.String()).To(ContainSubstring("upgrade openvox-ca and openvox-ca-ctl together"),
				"what the operator has to do about it")
		})

		// A symlinked *parent* is the case the identity check exists for: the two
		// paths differ as strings while naming one directory. Built explicitly
		// rather than relying on the platform, because on macOS TempDir already
		// sits behind /var -> private/var and on Linux it does not, so the
		// branch would run on one CI platform and never on the other.
		It("says nothing when a symlinked parent names the same directory", func() {
			base, err := filepath.EvalSymlinks(GinkgoT().TempDir())
			Expect(err).NotTo(HaveOccurred(), "resolve the fixture directory")
			data := filepath.Join(base, "data")
			Expect(os.Mkdir(data, 0o750)).To(Succeed(), "the real directory")
			alias := filepath.Join(base, "alias")
			Expect(os.Symlink("data", alias)).To(Succeed(), "another name for it")

			dbPath := filepath.Join(data, "ca.db")
			Expect(os.WriteFile(dbPath, nil, 0o600)).To(Succeed(), "seed the database")
			inUse, ok := sqliteLockDir("file:" + dbPath)
			Expect(ok).To(BeTrue(), "lock directory")
			Expect(os.Mkdir(inUse, 0o700)).To(Succeed(), "the one this version uses")

			viaAlias := filepath.Join(alias, "ca.db")
			Expect(filepath.Join(alias, ".ca.db.locks")).NotTo(Equal(inUse),
				"the two spellings must differ, or the spec proves nothing")

			buf := captureWarnings()
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + viaAlias})
			Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
			DeferCleanup(func() { _ = b.Close() })

			Expect(buf.String()).NotTo(ContainSubstring("stranded"),
				"one directory reached by two names is not a stranded directory")
		})

		// The ordinary case must stay silent, or the warning is one nobody reads:
		// for a DSN that resolves to itself the two directories are the same
		// place, and there is nothing stranded.
		It("says nothing for a DSN that does not traverse a symlink", func() {
			dbPath := filepath.Join(GinkgoT().TempDir(), "ca.db")
			Expect(os.WriteFile(dbPath, nil, 0o600)).To(Succeed(), "seed the database")
			dir, ok := sqliteLockDir("file:" + dbPath)
			Expect(ok).To(BeTrue(), "lock directory")
			Expect(os.Mkdir(dir, 0o700)).To(Succeed(), "the one this version uses")

			buf := captureWarnings()
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
			Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
			DeferCleanup(func() { _ = b.Close() })

			Expect(buf.String()).NotTo(ContainSubstring("stranded"), "nothing was stranded")
		})
	})

	// Everything derived from the DSN has to come from the same resolved path. The
	// lock directory is what stops a second process opening the store, so if it
	// were derived from the spelling instead, two processes reaching one database
	// by two names would take two different locks and exclude nobody.
	It("puts the lock directory beside the resolved database, not beside the link", func() {
		realDB := filepath.Join(GinkgoT().TempDir(), "real.db")
		link := filepath.Join(GinkgoT().TempDir(), "link.db")
		Expect(os.WriteFile(realDB, nil, 0o600)).To(Succeed(), "seed the database")
		Expect(os.Symlink(realDB, link)).To(Succeed(), "reach it through a link as well")

		viaLink, ok := sqliteLockDir("file:" + link)
		Expect(ok).To(BeTrue(), "lock directory for the link spelling")
		viaTarget, ok := sqliteLockDir("file:" + realDB)
		Expect(ok).To(BeTrue(), "lock directory for the target spelling")

		Expect(viaLink).To(Equal(viaTarget), "both spellings must lock in the same place")
	})

	// The driver decodes %HH in a file: URI, so this has to read the DSN the same
	// way or it protects a filename nobody opens. Before the decode was added this
	// created an empty "ca%20b.db" at the encoded spelling while the database that
	// actually held the key was created beside it, by the driver, at the umask.
	It("creates the file the driver opens when the DSN is percent-encoded", func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Chdir(dir)

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:ca%20b.db"})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(filepath.Join(dir, "ca b.db")).To(BeAnExistingFile(), "the decoded name is the real database")
		Expect(worldBits(filepath.Join(dir, "ca b.db"))).To(BeZero(), "world bits on the decoded database")
		Expect(filepath.Join(dir, "ca%20b.db")).NotTo(BeAnExistingFile(), "no decoy at the encoded name")
	})

	// A DSN with a malformed escape is one this cannot read, and the parser reports
	// that the same way it reports an in-memory database: no file. Taken at face
	// value it would skip creation entirely and let the driver make the database at
	// the umask, which is issue #351 again by way of giving up.
	It("refuses an absolute DSN whose escapes it cannot read", func() {
		_, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:/var/lib/ca%zz.db"})
		Expect(err).To(MatchError(ContainSubstring("reading sqlite dsn")), "url.Parse branch")
	})

	// The other refusal branch, and the one the doc comment singles out: a
	// relative file: URI keeps its escapes in url.Opaque, which net/url does not
	// validate, so only the manual unescape rejects it. Asserted on the
	// branch-specific text, because both branches mention "sqlite dsn" and an
	// assertion on the shared part could not tell which one fired.
	It("refuses a relative DSN whose escapes it cannot read", func() {
		_, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:ca%20b%zz.db"})
		Expect(err).To(MatchError(ContainSubstring("reading the database path out of sqlite dsn")),
			"PathUnescape branch")
	})

	// An in-memory database has no file, and the open path must not invent one
	// named after the DSN. The spec runs from its own temp directory so that the
	// regression it guards against would create that file inside the sandbox
	// rather than in the checked-out source tree.
	It("creates no file for an in-memory database", func() {
		GinkgoT().Chdir(GinkgoT().TempDir())

		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: ":memory:"})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(":memory:").NotTo(BeAnExistingFile(), "a file named for the DSN")
	})
})
