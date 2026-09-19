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

//go:build !windows

package storage

import (
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// CheckKeyPermissions is the whole of the control now: nothing corrects a mode,
// so what this reports is what the server acts on. The distinction it has to draw
// is world versus group -- world means every local account can read the CA private
// key and is refused at startup, group is what a Kubernetes fsGroup reapplies at
// every mount and is only warned about.
var _ = Describe("CheckKeyPermissions", func() {
	// findFor returns the warning for path, or nil. Specs assert on the classified
	// finding rather than on list positions, which reorder as sources are added.
	findFor := func(warnings []KeyPermWarning, path string) *KeyPermWarning {
		for i := range warnings {
			if warnings[i].Path == path {
				return &warnings[i]
			}
		}
		return nil
	}

	Describe("the local private-key directory", func() {
		var dir, keyPath string

		BeforeEach(func() {
			dir = GinkgoT().TempDir()
			Expect(os.MkdirAll(filepath.Join(dir, "private"), DirPerm)).To(Succeed())
			keyPath = filepath.Join(dir, "private", "ca_key.pem")
		})

		serviceOn := func() *StorageService {
			GinkgoHelper()
			return NewWithBackend(NewFilesystemBackend(dir), filepath.Join(dir, "private"))
		}

		It("says nothing about a key at 0600", func() {
			Expect(os.WriteFile(keyPath, nil, 0o600)).To(Succeed())
			Expect(serviceOn().CheckKeyPermissions()).To(BeEmpty(), "warnings for a correct key")
		})

		// Seeded at 0600 and chmodded, not written at the mode under test:
		// os.WriteFile's mode is masked by the umask, so a developer or runner
		// sitting at 0077 would get 0600 here, findFor would return nil, and
		// the spec would fail for a reason that is not its subject.
		It("reports a group-readable key as not world-accessible", func() {
			Expect(os.WriteFile(keyPath, nil, 0o600)).To(Succeed())
			Expect(os.Chmod(keyPath, 0o640)).To(Succeed(), "group-readable, whatever the umask")

			w := findFor(serviceOn().CheckKeyPermissions(), keyPath)
			Expect(w).NotTo(BeNil(), "warning for a group-readable key")
			Expect(w.WorldAccessible()).To(BeFalse(), "group access is not world access")
		})

		It("reports a world-readable key as world-accessible", func() {
			Expect(os.WriteFile(keyPath, nil, 0o600)).To(Succeed())
			Expect(os.Chmod(keyPath, 0o644)).To(Succeed(), "world-readable, whatever the umask")

			w := findFor(serviceOn().CheckKeyPermissions(), keyPath)
			Expect(w).NotTo(BeNil(), "warning for a world-readable key")
			Expect(w.WorldAccessible()).To(BeTrue(), "world access")
		})

		// World execute grants no read, but on a key file it is still access
		// granted to everyone and there is no legitimate reason for it.
		It("counts world-execute as world access", func() {
			Expect(os.WriteFile(keyPath, nil, 0o600)).To(Succeed())
			Expect(os.Chmod(keyPath, 0o601)).To(Succeed(), "world-executable, whatever the umask")

			w := findFor(serviceOn().CheckKeyPermissions(), keyPath)
			Expect(w).NotTo(BeNil(), "warning for a world-executable key")
			Expect(w.WorldAccessible()).To(BeTrue(), "world execute is world access")
		})
	})

	Describe("a backend that declares its own key files", func() {
		var dbPath string
		var svc *StorageService

		BeforeEach(func() {
			dbPath = filepath.Join(GinkgoT().TempDir(), "ca.db")
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: "file:" + dbPath})
			Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
			DeferCleanup(func() { _ = b.Close() })
			Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")
			Expect(b.Put(context.Background(), KeyCAKey, []byte("key"), BlobPrivate)).To(Succeed(), "Put CA key")

			// The backend reports the resolved path, since everything derived from
			// the DSN comes from one resolution. On a host where the temp directory
			// is reached through a symlink -- /var on a Mac -- that is not the
			// spelling this spec started with, so line the two up rather than
			// comparing a real path against a link.
			resolved, err := filepath.EvalSymlinks(dbPath)
			Expect(err).NotTo(HaveOccurred(), "resolving the database path")
			dbPath = resolved

			// No local private-key directory: the database is the only source, so a
			// finding here can only have come through KeyFileLister.
			svc = NewWithBackend(b, "")
		})

		// A group-accessible database is reported, but as a group finding: the
		// caller warns about those and refuses only on world. Asserted as "nothing
		// world-accessible" rather than "no findings", because the group finding is
		// the expected steady state under a Kubernetes fsGroup.
		It("reports no world access when the database is only group-accessible", func() {
			Expect(os.Chmod(dbPath, 0o660)).To(Succeed())

			warnings := svc.CheckKeyPermissions()

			// Assert the finding exists before classifying it. A bare loop over
			// the result is satisfied by an empty slice, so narrowing the check
			// to world access only would have kept this green while silently
			// removing everything an fsGroup deployment is told.
			w := findFor(warnings, dbPath)
			Expect(w).NotTo(BeNil(), "a finding for the group-accessible database")
			Expect(w.WorldAccessible()).To(BeFalse(), "group access is not world access")

			for _, other := range warnings {
				Expect(other.WorldAccessible()).To(BeFalse(), "world access on %s (mode %s)", other.Path, other.Mode)
			}
		})

		It("reports a world-readable database", func() {
			Expect(os.Chmod(dbPath, 0o644)).To(Succeed())

			w := findFor(svc.CheckKeyPermissions(), dbPath)
			Expect(w).NotTo(BeNil(), "warning for the database")
			Expect(w.WorldAccessible()).To(BeTrue(), "world access")
		})

		// The WAL holds committed pages, which is to say it can hold the key, and
		// which of the files has it at a given instant is a matter of checkpoint
		// timing rather than anything the operator controls.
		It("reports a world-readable -wal sidecar", func() {
			wal := dbPath + "-wal"
			Expect(wal).To(BeAnExistingFile(), "the WAL exists while the backend is open")
			Expect(os.Chmod(wal, 0o644)).To(Succeed())

			w := findFor(svc.CheckKeyPermissions(), wal)
			Expect(w).NotTo(BeNil(), "warning for the -wal sidecar")
			Expect(w.WorldAccessible()).To(BeTrue(), "world access")
		})
	})

	// A path whose mode cannot be read at all is not the same fact as a path whose
	// mode is fine, and the difference decides whether the CA serves. Reported as
	// world-accessible so the caller refuses rather than starting on key material
	// nobody checked.
	It("reports a path it cannot judge as world-accessible", func() {
		if os.Geteuid() == 0 {
			Skip("root can read a directory whatever its mode")
		}
		dir := GinkgoT().TempDir()
		keyDir := filepath.Join(dir, "private")
		Expect(os.Mkdir(keyDir, 0o700)).To(Succeed(), "make the private directory")
		Expect(os.Chmod(keyDir, 0o000)).To(Succeed(), "make it unreadable")
		DeferCleanup(func() { _ = os.Chmod(keyDir, 0o700) })

		svc := NewWithBackend(NewFilesystemBackend(dir), keyDir)

		w := findFor(svc.CheckKeyPermissions(), keyDir)
		Expect(w).NotTo(BeNil(), "a finding for the unreadable directory")
		Expect(w.Unreadable).To(BeTrue(), "recorded as unjudgeable, not as a mode")
		Expect(w.Err).To(HaveOccurred(), "the reason, for the operator to act on")
		Expect(w.WorldAccessible()).To(BeTrue(), "an unjudgeable path fails closed")
	})

	// A Kubernetes Secret volume projects every entry as a symlink into a
	// timestamped directory, and certificate tooling keeps a stable name pointing
	// at a rotating one. Judging the link rather than its target would skip both:
	// a symlink's own mode is 0777 and says nothing about the file behind it.
	It("judges a symlinked key by the mode of its target", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "real_key.pem")
		Expect(os.WriteFile(target, nil, 0o600)).To(Succeed(), "seed the real key")
		Expect(os.Chmod(target, 0o644)).To(Succeed(), "world-readable, whatever the umask")

		link := filepath.Join(GinkgoT().TempDir(), "ca_key.pem")
		Expect(os.Symlink(target, link)).To(Succeed(), "project it as a link, as a Secret mount does")

		ov, err := NewOverlayBackend(NewFilesystemBackend(dir), map[string]string{KeyCAKey: link})
		Expect(err).NotTo(HaveOccurred(), "NewOverlayBackend")

		w := findFor(NewWithBackend(ov, "").CheckKeyPermissions(), link)
		Expect(w).NotTo(BeNil(), "a finding for the symlinked key")
		Expect(w.WorldAccessible()).To(BeTrue(), "the target is world-readable")
	})

	It("says nothing about a symlinked key whose target is not world-accessible", func() {
		dir := GinkgoT().TempDir()
		target := filepath.Join(dir, "real_key.pem")
		Expect(os.WriteFile(target, nil, 0o600)).To(Succeed(), "seed the real key")
		Expect(os.Chmod(target, 0o600)).To(Succeed(), "owner only")

		link := filepath.Join(GinkgoT().TempDir(), "ca_key.pem")
		Expect(os.Symlink(target, link)).To(Succeed(), "project it as a link")

		ov, err := NewOverlayBackend(NewFilesystemBackend(dir), map[string]string{KeyCAKey: link})
		Expect(err).NotTo(HaveOccurred(), "NewOverlayBackend")

		Expect(NewWithBackend(ov, "").CheckKeyPermissions()).To(BeEmpty(), "a correct key behind a link")
	})

	// A dangling link is the third outcome, and the one with teeth: a Kubernetes
	// Secret volume swings its "..data" symlink during a rotation, so a link
	// whose target is momentarily absent is a state a running deployment passes
	// through. Losing this return drops the path into the unjudgeable arm, which
	// refuses to start and is not covered by the opt-out -- a CA that was serving
	// a minute earlier would refuse on a routine rotation, with nothing in the
	// suite failing to say so.
	It("says nothing about a dangling symlink where a key is expected", func() {
		dir := GinkgoT().TempDir()
		link := filepath.Join(GinkgoT().TempDir(), "ca_key.pem")
		Expect(os.Symlink(filepath.Join(dir, "gone_key.pem"), link)).To(Succeed(), "a link to nothing")

		ov, err := NewOverlayBackend(NewFilesystemBackend(dir), map[string]string{KeyCAKey: link})
		Expect(err).NotTo(HaveOccurred(), "NewOverlayBackend")

		Expect(NewWithBackend(ov, "").CheckKeyPermissions()).To(BeEmpty(),
			"nothing to judge, and nothing was written through it either")
	})

	// The three sources overlap by construction: a ca_key_passphrase_file named
	// inside <cadir>/private is both a directory entry and a caller-supplied
	// path. Reported twice, it is chmodded twice in the remedy and counted twice
	// in the group-access record, which is a number an operator reads.
	It("reports a path reachable from two sources only once", func() {
		dir := GinkgoT().TempDir()
		priv := filepath.Join(dir, "private")
		Expect(os.MkdirAll(priv, DirPerm)).To(Succeed())
		shared := filepath.Join(priv, ".ca_key_passphrase")
		Expect(os.WriteFile(shared, nil, 0o600)).To(Succeed(), "seed it")
		Expect(os.Chmod(shared, 0o644)).To(Succeed(), "world-readable, whatever the umask")

		svc := NewWithBackend(NewFilesystemBackend(dir), priv)

		// Named by the caller as well as found by the directory scan.
		warnings := svc.CheckKeyPermissions(shared)

		Expect(warnings).To(HaveLen(1), "one file, one finding")
		Expect(warnings[0].Path).To(Equal(shared))
	})

	// The other fail-closed arm: a backend-declared file whose own Lstat fails,
	// as opposed to the private-key directory whose ReadDir fails. That is the arm
	// covering the database, its sidecars and a pinned ca_key_file -- everything
	// KeyFileLister exists for.
	It("reports a backend key file it cannot reach as unjudgeable", func() {
		if os.Geteuid() == 0 {
			Skip("root can search a directory whatever its mode")
		}
		parent := filepath.Join(GinkgoT().TempDir(), "data")
		Expect(os.Mkdir(parent, 0o700)).To(Succeed(), "make the data directory")
		keyPath := filepath.Join(parent, "ca_key.pem")
		Expect(os.WriteFile(keyPath, nil, 0o600)).To(Succeed(), "seed the key")
		Expect(os.Chmod(parent, 0o000)).To(Succeed(), "make it unsearchable")
		DeferCleanup(func() { _ = os.Chmod(parent, 0o700) })

		ov, err := NewOverlayBackend(NewFilesystemBackend(GinkgoT().TempDir()),
			map[string]string{KeyCAKey: keyPath})
		Expect(err).NotTo(HaveOccurred(), "NewOverlayBackend")

		w := findFor(NewWithBackend(ov, "").CheckKeyPermissions(), keyPath)
		Expect(w).NotTo(BeNil(), "a finding for the unreachable key file")
		Expect(w.Unreadable).To(BeTrue(), "recorded as unjudgeable")
		Expect(w.WorldAccessible()).To(BeTrue(), "fails closed")
	})

	// An in-memory database has no files, and a backend that declares none must
	// not produce phantom findings for paths that do not exist.
	It("reports nothing for a backend with no files", func() {
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLitePure, DSN: ":memory:"})
		Expect(err).NotTo(HaveOccurred(), "NewSQLBackend")
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")

		Expect(NewWithBackend(b, "").CheckKeyPermissions()).To(BeEmpty(), "warnings for an in-memory store")
	})
})
