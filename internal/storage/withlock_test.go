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
	// TestWithLockLocalFallbackSerialises covers the process-local fallback used
	// when the backend does not implement Locker (i.e. the filesystem backend).
	// Many goroutines hammering the same lock must enter the critical section
	// strictly one-at-a-time.
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

	// TestWithLockFallsBackOnUnsupported covers the OverlayBackend-over-filesystem
	// case: the wrapping backend advertises Locker but reports that the base
	// backend can't provide one, and WithLock must fall back to the process-local
	// mutex rather than erroring.
	It("falls back to the local mutex when distributed locking is unsupported", func() {
		dir := GinkgoT().TempDir()
		base := NewFilesystemBackend(dir)
		sl := &stubLocker{Backend: base, err: ErrDistributedLockingUnsupported}
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
