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
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("WithLock", func() {
	// TestWithLockLocalFallbackSerialises covers in-process serialisation on the
	// filesystem backend. Many goroutines hammering the same lock must enter the
	// critical section strictly one-at-a-time. Since #187 that is the per-name
	// mutex the backend's same-host lock takes before touching the filesystem
	// rather than WithLock's own fallback map, which is the point of taking it
	// first: in-process contention must stay a mutex wait, not N processes'
	// worth of flock retries. The cross-process half is in filelock_test.go.
	Context("local fallback", func() {
		It("serialises concurrent callers", func() {
			dir := GinkgoT().TempDir()
			svc := NewWithBackend(NewFilesystemBackend(dir), filepath.Join(dir, "private"))

			var inside atomic.Int32
			var maxInside atomic.Int32
			var wg sync.WaitGroup
			const n = 10
			wg.Add(n)
			for i := 0; i < n; i++ {
				go func() {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = svc.WithLock(ctx, "crl", func() error {
						cur := inside.Add(1)
						for {
							m := maxInside.Load()
							if cur <= m || maxInside.CompareAndSwap(m, cur) {
								break
							}
						}
						time.Sleep(5 * time.Millisecond)
						inside.Add(-1)
						return nil
					})
				}()
			}
			wg.Wait()
			Expect(maxInside.Load()).To(Equal(int32(1)))
		})
	})

	// TestWithLockDistinctNamesParallel asserts that different lock names do not
	// contend under the local fallback.
	Context("distinct names", func() {
		It("do not contend under the local fallback", func() {
			dir := GinkgoT().TempDir()
			svc := NewWithBackend(NewFilesystemBackend(dir), filepath.Join(dir, "private"))

			// Hold lock A; attempt to acquire B — it should not block.
			aHeld := make(chan struct{})
			aRelease := make(chan struct{})
			go func() {
				_ = svc.WithLock(context.Background(), "a", func() error {
					close(aHeld)
					<-aRelease
					return nil
				})
			}()
			<-aHeld

			done := make(chan error, 1)
			go func() {
				done <- svc.WithLock(context.Background(), "b", func() error { return nil })
			}()
			select {
			case err := <-done:
				Expect(err).NotTo(HaveOccurred())
			case <-time.After(2 * time.Second):
				Fail("B WithLock blocked despite distinct lock names")
			}
			close(aRelease)
		})
	})

	// TestWithLockPropagatesFnError confirms fn's error is returned unchanged.
	It("propagates fn's error unchanged", func() {
		dir := GinkgoT().TempDir()
		svc := NewWithBackend(NewFilesystemBackend(dir), filepath.Join(dir, "private"))

		boom := errors.New("boom")
		got := svc.WithLock(context.Background(), "x", func() error { return boom })
		Expect(got).To(MatchError(boom))
	})

	// TestWithLockFallsBackOnUnsupported drives the case a wrapping backend
	// produces — e.g. OverlayBackend over a base with no Locker: the backend
	// advertises Locker but reports ErrDistributedLockingUnsupported, and
	// WithLock must fall through rather than erroring. A stubLocker stands in
	// for the wrapper here; the real OverlayBackend delegation is covered in
	// overlay_test.go.
	//
	// The stub's embedded Backend is a bare interface value, so it offers no
	// same-host lock either and the fall-through reaches WithLock's own mutex —
	// which is what this spec is about. Where the base does offer one, the
	// same-host tier catches the fall-through instead; filelock_test.go pins
	// that, and both orders are covered.
	It("falls back to the local mutex when distributed locking is unsupported", func() {
		dir := GinkgoT().TempDir()
		sl := &stubLocker{err: ErrDistributedLockingUnsupported}
		svc := NewWithBackend(sl, filepath.Join(dir, "private"))

		// Serialises via local fallback.
		var inside atomic.Int32
		var maxInside atomic.Int32
		var wg sync.WaitGroup
		const n = 6
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				_ = svc.WithLock(context.Background(), "crl", func() error {
					cur := inside.Add(1)
					for {
						m := maxInside.Load()
						if cur <= m || maxInside.CompareAndSwap(m, cur) {
							break
						}
					}
					time.Sleep(2 * time.Millisecond)
					inside.Add(-1)
					return nil
				})
			}()
		}
		wg.Wait()
		Expect(maxInside.Load()).To(Equal(int32(1)))
	})

	// TestWithLockSurfacesAcquireError asserts a non-sentinel acquisition error
	// is returned rather than silently falling back.
	It("surfaces a non-sentinel acquisition error", func() {
		dir := GinkgoT().TempDir()
		sentinel := errors.New("etcd down")
		sl := &stubLocker{Backend: NewFilesystemBackend(dir), err: sentinel}
		svc := NewWithBackend(sl, filepath.Join(dir, "private"))

		err := svc.WithLock(context.Background(), "crl", func() error { return nil })
		Expect(err).To(MatchError(sentinel))
	})

	// TestWithLockSwallowsUnlockError asserts a failed lock release does not
	// mask fn's result: WithLock logs the Unlock error and still returns
	// whatever fn returned. A refactor that surfaced the Unlock error instead
	// would turn a committed mutation into a spurious caller-visible failure.
	It("returns fn's result even when Unlock fails", func() {
		dir := GinkgoT().TempDir()
		sl := &stubLocker{Backend: NewFilesystemBackend(dir), unlockErr: errors.New("release failed")}
		svc := NewWithBackend(sl, filepath.Join(dir, "private"))

		// fn succeeds: the Unlock error must not turn it into a failure.
		Expect(svc.WithLock(context.Background(), "crl", func() error { return nil })).To(Succeed())

		// fn fails: WithLock returns fn's error, not the Unlock error.
		boom := errors.New("fn failed")
		Expect(svc.WithLock(context.Background(), "crl", func() error { return boom })).To(MatchError(boom))
	})

	// TestWithLockReleasesLockOnPanic sanity-checks defer-based unlock. If fn
	// panics, the lock must still be released so the next caller isn't wedged.
	It("releases the lock when fn panics", func() {
		dir := GinkgoT().TempDir()
		unlocked := make(chan struct{})
		sl := &stubLocker{Backend: NewFilesystemBackend(dir), unlockedCh: unlocked}
		svc := NewWithBackend(sl, filepath.Join(dir, "private"))

		defer func() {
			r := recover()
			Expect(r).NotTo(BeNil(), "expected panic to propagate out of WithLock")
		}()

		func() {
			defer func() {
				// Swallow the panic so we can still observe unlock.
				select {
				case <-unlocked:
				case <-time.After(time.Second):
					Fail("Unlocker.Unlock was not called on panic")
				}
				// Re-panic to satisfy outer recover().
				if r := recover(); r != nil {
					panic(r)
				}
			}()
			_ = svc.WithLock(context.Background(), "crl", func() error {
				panic(fmt.Errorf("boom"))
			})
		}()
	})
})

// stubLocker lets us drive WithLock down the distributed path in unit tests
// (no etcd needed).
type stubLocker struct {
	Backend
	err        error
	unlockErr  error
	unlockedCh chan struct{}
}

func (s *stubLocker) AcquireLock(ctx context.Context, name string) (Unlocker, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &stubUnlocker{err: s.unlockErr, done: s.unlockedCh}, nil
}

type stubUnlocker struct {
	err  error
	done chan struct{}
}

func (u *stubUnlocker) Unlock() error {
	if u.done != nil {
		close(u.done)
	}
	return u.err
}
