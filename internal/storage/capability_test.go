// Copyright (C) 2026 Trevor Vaughan
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
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Backend capability reporting", func() {
	var ctx context.Context

	BeforeEach(func() { ctx = context.Background() })

	svc := func(b Backend) *StorageService {
		return NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
	}

	Describe("SupportsDistributedLocking", func() {
		// The whole point of this method is that it answers a different
		// question from `_, ok := backend.(Locker)`. These first three cases
		// are the ones where the type assertion says "yes" and the truth is
		// "no" -- if this method is ever simplified to an assertion, they fail.
		It("is false for the filesystem backend, which implements no Locker", func() {
			ok, err := svc(NewFilesystemBackend(GinkgoT().TempDir())).SupportsDistributedLocking(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("is false for SQLite, which implements Locker but reports it unsupported", func() {
			b := newSQLiteBackend()
			Expect(b).To(BeAssignableToTypeOf(&SQLBackend{}))

			var asLocker any = b
			_, assertsAsLocker := asLocker.(Locker)
			Expect(assertsAsLocker).To(BeTrue(),
				"precondition: SQLBackend implements Locker, so a type assertion would say yes")

			ok, err := svc(b).SupportsDistributedLocking(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse(), "SQLite is single-node; WithLock falls back to a process mutex")
		})

		It("is false for an overlay over a filesystem base", func() {
			ov, _, _, _ := overlayTestSetup()

			var asLocker any = ov
			_, assertsAsLocker := asLocker.(Locker)
			Expect(assertsAsLocker).To(BeTrue(),
				"precondition: OverlayBackend implements Locker, so a type assertion would say yes")

			ok, err := svc(ov).SupportsDistributedLocking(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse(), "the overlay delegates, and a filesystem base cannot lock")
		})

		It("is true when the backend hands out a lock", func() {
			ok, err := svc(&stubLocker{Backend: NewFilesystemBackend(GinkgoT().TempDir())}).
				SupportsDistributedLocking(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("releases the probe lock it acquires", func() {
			// A probe that leaked would hold a Postgres advisory lock on a
			// pooled connection, or a Redis lease with its heartbeat goroutine,
			// for the rest of the process's life.
			released := make(chan struct{})
			ok, err := svc(&stubLocker{
				Backend:    NewFilesystemBackend(GinkgoT().TempDir()),
				unlockedCh: released,
			}).SupportsDistributedLocking(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
			// stubUnlocker signals by closing.
			Expect(released).To(BeClosed(), "the probe must not hold the lock it took")
		})

		It("reports an error, not false, when the lock service is unreachable", func() {
			// "Cannot reach the backend" and "this backend does not do
			// distributed locking" are different answers. Collapsing the first
			// into false would tell an operator to stop their server on the
			// grounds of a capability their backend actually has.
			ok, err := svc(&stubLocker{
				Backend: NewFilesystemBackend(GinkgoT().TempDir()),
				err:     errors.New("connection refused"),
			}).SupportsDistributedLocking(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("probing distributed locking"))
			Expect(ok).To(BeFalse())
		})

		It("agrees with WithLock about which backends coordinate across processes", func() {
			// The probe duplicates WithLock's classification by construction --
			// it cannot be folded into WithLock without adding a lock round
			// trip to every Sign. This is what stops the two drifting apart.
			for _, tc := range []struct {
				name    string
				backend Backend
			}{
				{"filesystem", NewFilesystemBackend(GinkgoT().TempDir())},
				{"sqlite", newSQLiteBackend()},
				{"stub locker", &stubLocker{Backend: NewFilesystemBackend(GinkgoT().TempDir())}},
			} {
				s := svc(tc.backend)

				reported, err := s.SupportsDistributedLocking(ctx)
				Expect(err).NotTo(HaveOccurred(), tc.name)

				// Observe what WithLock did: a distributed lock leaves no entry
				// in the process-local map, a fallback creates one.
				Expect(s.WithLock(ctx, "agreement-probe", func() error { return nil })).To(Succeed(), tc.name)
				_, usedLocalMutex := s.localLocks.Load("agreement-probe")

				Expect(reported).To(Equal(!usedLocalMutex),
					"%s: SupportsDistributedLocking must match what WithLock actually does", tc.name)
			}
		})
	})

	Describe("SupportsAtomicInventory", func() {
		It("is false for the filesystem backend", func() {
			Expect(svc(NewFilesystemBackend(GinkgoT().TempDir())).SupportsAtomicInventory()).To(BeFalse())
		})

		It("is true for a SQL backend", func() {
			// Note this is true for SQLite while SupportsDistributedLocking is
			// false: the two capabilities are independent, which is exactly why
			// callers must check both before deciding it is safe to write from
			// a second process.
			Expect(svc(newSQLiteBackend()).SupportsAtomicInventory()).To(BeTrue())
		})

		It("sees through an overlay to a SQL base", func() {
			base := newSQLiteBackend()
			overlayDir := GinkgoT().TempDir()
			ov, err := NewOverlayBackend(base, map[string]string{
				KeyCACert: filepath.Join(overlayDir, "ca_crt.pem"),
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(svc(ov).SupportsAtomicInventory()).To(BeTrue(),
				"a caller-side type assertion would answer no here")
		})
	})
})
