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

// White-box because the ordering these specs pin is decided before anything a
// backend can observe: whether a yielding caller queues at all, and whether it
// lets go of a lock it has just been granted. svc.priority is the only place
// that state is visible.
var _ = Describe("WithLockYielding", func() {
	// recorder collects the order in which fn bodies ran, which is the property
	// the gate exists for. Asserting on it rather than on how often the backend
	// was asked for the lock keeps these specs about the outcome.
	type recorder struct {
		mu    sync.Mutex
		order []string
	}
	record := func(r *recorder, who string) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.order = append(r.order, who)
	}
	recorded := func(r *recorder) []string {
		r.mu.Lock()
		defer r.mu.Unlock()
		return append([]string(nil), r.order...)
	}

	newService := func() *StorageService {
		dir := GinkgoT().TempDir()
		return NewWithBackend(NewFilesystemBackend(dir), filepath.Join(dir, "private"))
	}

	// holdWithLock starts a WithLock caller that holds name until release is
	// called, and returns once it holds it. The release is registered for
	// cleanup too, so a spec that fails before calling it does not leave the
	// holder blocked on the lock.
	holdWithLock := func(svc *StorageService, name, who string, r *recorder) (<-chan error, func()) {
		ch := make(chan struct{})
		var release <-chan struct{} = ch
		releaseOnce := sync.OnceFunc(func() { close(ch) })
		DeferCleanup(releaseOnce)
		held := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- svc.WithLock(context.Background(), name, func() error {
				record(r, who)
				close(held)
				<-release
				return nil
			})
		}()
		Eventually(held).Should(BeClosed())
		return done, releaseOnce
	}

	It("does not run while a WithLock caller holds the name, and runs once it leaves", func() {
		svc := newService()
		r := &recorder{}
		priorityDone, release := holdWithLock(svc, "crl", "revoke", r)

		yieldDone := make(chan error, 1)
		go func() {
			yieldDone <- svc.WithLockYielding(context.Background(), "crl", func() error {
				record(r, "sweep")
				return nil
			})
		}()
		Consistently(yieldDone, 200*time.Millisecond).ShouldNot(Receive())

		release()
		Eventually(priorityDone).Should(Receive(BeNil()))
		Eventually(yieldDone).Should(Receive(BeNil()))
		Expect(recorded(r)).To(Equal([]string{"revoke", "sweep"}))
	})

	// The case a plain mutex gets wrong. The sweep is parked before the second
	// revocation arrives, so a lock that served waiters in arrival order would
	// give it the name first. Priority has to be decided by who is waiting when
	// the name comes free, not by who asked first.
	It("lets a WithLock caller that arrives later go first", func() {
		svc := newService()
		r := &recorder{}
		firstDone, release := holdWithLock(svc, "crl", "first-revoke", r)

		yieldDone := make(chan error, 1)
		go func() {
			yieldDone <- svc.WithLockYielding(context.Background(), "crl", func() error {
				record(r, "sweep")
				return nil
			})
		}()
		// Parked, not merely unfinished: a sweep that had not yet reached the
		// gate would arrive after both revocations, a case any lock orders
		// right.
		Eventually(func() int {
			svc.priority.mu.Lock()
			defer svc.priority.mu.Unlock()
			return len(svc.priority.clear["crl"])
		}).Should(Equal(1))

		secondDone := make(chan error, 1)
		go func() {
			secondDone <- svc.WithLock(context.Background(), "crl", func() error {
				record(r, "second-revoke")
				return nil
			})
		}()
		// Both are registered before the name comes free: the first holding,
		// the second queued behind it.
		Eventually(func() int {
			svc.priority.mu.Lock()
			defer svc.priority.mu.Unlock()
			return svc.priority.count["crl"]
		}).Should(Equal(2))

		release()
		Eventually(firstDone).Should(Receive(BeNil()))
		Eventually(secondDone).Should(Receive(BeNil()))
		Eventually(yieldDone).Should(Receive(BeNil()))
		Expect(recorded(r)).To(Equal([]string{"first-revoke", "second-revoke", "sweep"}))
	})

	// The window the re-check closes: the gate was clear when the sweep looked,
	// and a revocation registered while the sweep was being granted the lock.
	// pausingLocker parks the sweep inside AcquireLock, holding the lock, until
	// the revocation is registered behind it.
	It("hands back a lock it was granted while a WithLock caller registered", func() {
		dir := GinkgoT().TempDir()
		pl := &pausingLocker{Backend: NewFilesystemBackend(dir), granted: make(chan struct{}),
			resume: make(chan struct{})}
		svc := NewWithBackend(pl, filepath.Join(dir, "private"))
		r := &recorder{}
		resume := sync.OnceFunc(func() { close(pl.resume) })
		DeferCleanup(resume)

		pl.pauseNext()
		yieldDone := make(chan error, 1)
		go func() {
			yieldDone <- svc.WithLockYielding(context.Background(), "crl", func() error {
				record(r, "sweep")
				return nil
			})
		}()
		Eventually(pl.granted).Should(BeClosed())

		priorityDone := make(chan error, 1)
		go func() {
			priorityDone <- svc.WithLock(context.Background(), "crl", func() error {
				record(r, "revoke")
				return nil
			})
		}()
		Eventually(func() bool { return svc.priority.waiting("crl") }).Should(BeTrue())

		resume()
		Eventually(priorityDone).Should(Receive(BeNil()))
		Eventually(yieldDone).Should(Receive(BeNil()))
		Expect(recorded(r)).To(Equal([]string{"revoke", "sweep"}),
			"the sweep must release the lock it was granted rather than run ahead of the revocation")
	})

	It("is not held back by a WithLock caller on a different name", func() {
		svc := newService()
		holderDone, release := holdWithLock(svc, "subject:node", "sign", &recorder{})

		done := make(chan error, 1)
		go func() {
			done <- svc.WithLockYielding(context.Background(), "crl", func() error { return nil })
		}()
		Eventually(done).Should(Receive(BeNil()))

		release()
		Eventually(holderDone).Should(Receive(BeNil()))
		Expect(svc.priority.waiting("subject:node")).To(BeFalse())
	})

	// leave wakes every parked caller once the count reaches zero, and a
	// WithLock caller can register again before a woken one runs. The woken
	// one has to look again rather than go on to queue for the lock, because
	// that queue is an in-process mutex its deadline does not end.
	It("parks a woken caller again when a WithLock caller registered before it ran", func() {
		svc := newService()
		svc.priority.enter("crl")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- svc.priority.waitClear(ctx, "crl") }()
		Eventually(func() int {
			svc.priority.mu.Lock()
			defer svc.priority.mu.Unlock()
			return len(svc.priority.clear["crl"])
		}).Should(Equal(1))

		// leave() followed at once by another enter(), as one step: the
		// parked caller is woken while the count is non-zero again.
		svc.priority.mu.Lock()
		for _, ch := range svc.priority.clear["crl"] {
			close(ch)
		}
		delete(svc.priority.clear, "crl")
		svc.priority.mu.Unlock()

		Consistently(done, 200*time.Millisecond).ShouldNot(Receive(),
			"a caller woken while a WithLock caller is registered must park again")
		svc.priority.leave("crl")
		Eventually(done).Should(Receive(BeNil()))
	})

	// forget is handed a wait that gave up, and leave may already have closed
	// and dropped it: a wake and a cancellation race, and the select in
	// waitClear may pick the cancellation. forget must then remove nothing,
	// and above all not index the list with the -1 it gets back.
	It("forgets a wait that is no longer parked without touching the rest", func() {
		svc := newService()
		Expect(func() { svc.priority.forget("crl", make(chan struct{})) }).NotTo(Panic())
		svc.priority.mu.Lock()
		Expect(svc.priority.clear).To(BeEmpty())
		svc.priority.mu.Unlock()

		svc.priority.enter("crl")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- svc.priority.waitClear(ctx, "crl") }()
		parked := func() int {
			svc.priority.mu.Lock()
			defer svc.priority.mu.Unlock()
			return len(svc.priority.clear["crl"])
		}
		Eventually(parked).Should(Equal(1))

		Expect(func() { svc.priority.forget("crl", make(chan struct{})) }).NotTo(Panic())
		Expect(parked()).To(Equal(1), "forgetting a wait that is not parked must leave the others")
		svc.priority.leave("crl")
		Eventually(done).Should(Receive(BeNil()))
	})

	// leave wakes every caller parked on the name, not just the first: a name
	// can have several background callers waiting on it at once.
	It("wakes every yielding caller parked on the name when the last WithLock caller leaves", func() {
		svc := newService()
		r := &recorder{}
		holderDone, release := holdWithLock(svc, "crl", "revoke", r)

		const yielders = 3
		done := make(chan error, yielders)
		for i := range yielders {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				done <- svc.WithLockYielding(ctx, "crl", func() error {
					record(r, fmt.Sprintf("sweep%d", i))
					return nil
				})
			}()
		}
		Eventually(func() int {
			svc.priority.mu.Lock()
			defer svc.priority.mu.Unlock()
			return len(svc.priority.clear["crl"])
		}).Should(Equal(yielders))

		release()
		Eventually(holderDone).Should(Receive(BeNil()))
		for range yielders {
			Eventually(done, 2*time.Second).Should(Receive(BeNil()),
				"a parked caller was not woken and waited out its own deadline")
		}
		Expect(recorded(r)).To(HaveLen(1 + yielders))
		Expect(recorded(r)[0]).To(Equal("revoke"))
	})

	// The deferred leave is what keeps a panic from wedging the gate: net/http
	// recovers a handler's panic, and a name left registered would park every
	// background job on it for the life of the process.
	It("leaves the gate when fn panics", func() {
		svc := newService()
		Expect(func() {
			_ = svc.WithLock(context.Background(), "crl", func() error { panic("boom") })
		}).To(PanicWith("boom"))
		Expect(svc.priority.waiting("crl")).To(BeFalse())

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		Expect(svc.WithLockYielding(ctx, "crl", func() error { return nil })).To(Succeed())
	})

	// Each entry point defers its own release, so each is pinned apart: a
	// panicking fn must not leave the lock held, which on the CRL lock would
	// block every revocation for the life of the process.
	DescribeTable("releases the lock when fn panics",
		func(take func(*StorageService, func() error) error) {
			dir := GinkgoT().TempDir()
			unlocked := make(chan struct{})
			sl := &stubLocker{Backend: NewFilesystemBackend(dir), unlockedCh: unlocked}
			svc := NewWithBackend(sl, filepath.Join(dir, "private"))

			Expect(func() {
				_ = take(svc, func() error { panic("boom") })
			}).To(PanicWith("boom"))
			Eventually(unlocked).Should(BeClosed(), "the lock was not released on panic")
		},
		Entry("WithLockYielding", func(svc *StorageService, fn func() error) error {
			return svc.WithLockYielding(context.Background(), "crl", fn)
		}),
		Entry("WithLockNeutral", func(svc *StorageService, fn func() error) error {
			return svc.WithLockNeutral(context.Background(), "crl", fn)
		}),
	)

	// The other side of the wording contract: a backend that refuses the lock
	// is a storage fault, and its error must not read as standing aside, or
	// the runbooks would tell a responder to dismiss it.
	It("does not word a backend's refusal as standing aside", func() {
		dir := GinkgoT().TempDir()
		sentinel := errors.New("etcd down")
		sl := &stubLocker{Backend: NewFilesystemBackend(dir), err: sentinel}
		svc := NewWithBackend(sl, filepath.Join(dir, "private"))

		err := svc.WithLockYielding(context.Background(), "crl", func() error { return nil })
		Expect(err).To(MatchError(sentinel))
		Expect(err.Error()).NotTo(ContainSubstring("behind a priority caller"))
	})

	// WithLockNeutral takes the same lock with no part in the priority: a
	// yielding caller does not stand aside for it, and it does not stand aside
	// for a WithLock caller either, but queues on the lock like anyone else.
	It("takes the lock without registering or parking", func() {
		svc := newService()
		release := make(chan struct{})
		var releaseOnce sync.Once
		DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
		held := make(chan struct{})
		neutralDone := make(chan error, 1)
		go func() {
			neutralDone <- svc.WithLockNeutral(context.Background(), "crl", func() error {
				close(held)
				<-release
				return nil
			})
		}()
		Eventually(held).Should(BeClosed())
		Expect(svc.priority.waiting("crl")).To(BeFalse(), "a neutral holder registered as a priority caller")

		// A yielding caller queues on the lock behind it rather than parking.
		yieldDone := make(chan error, 1)
		go func() {
			yieldDone <- svc.WithLockYielding(context.Background(), "crl", func() error { return nil })
		}()
		parked := func() int {
			svc.priority.mu.Lock()
			defer svc.priority.mu.Unlock()
			return len(svc.priority.clear["crl"])
		}
		Consistently(parked, 100*time.Millisecond).Should(BeZero())
		releaseOnce.Do(func() { close(release) })
		Eventually(neutralDone).Should(Receive(BeNil()))
		Eventually(yieldDone).Should(Receive(BeNil()))

		// And it does not park behind a WithLock caller, though it waits for it.
		holderDone, releaseHolder := holdWithLock(svc, "crl", "revoke", &recorder{})
		neutralDone2 := make(chan error, 1)
		go func() {
			neutralDone2 <- svc.WithLockNeutral(context.Background(), "crl", func() error { return nil })
		}()
		Consistently(parked, 100*time.Millisecond).Should(BeZero())
		Consistently(neutralDone2, 50*time.Millisecond).ShouldNot(Receive())
		releaseHolder()
		Eventually(holderDone).Should(Receive(BeNil()))
		Eventually(neutralDone2).Should(Receive(BeNil()))
	})

	// A WithLock that never got the lock must still leave the gate, or every
	// yielding caller of that name in this process parks behind a caller that
	// is gone, for every pass, for as long as the process runs.
	It("leaves the gate when it fails to acquire the lock", func() {
		dir := GinkgoT().TempDir()
		sl := &stubLocker{Backend: NewFilesystemBackend(dir), err: errors.New("etcd down")}
		svc := NewWithBackend(sl, filepath.Join(dir, "private"))

		err := svc.WithLock(context.Background(), "crl", func() error { return nil })
		Expect(err).To(MatchError(ContainSubstring("etcd down")))
		Expect(svc.priority.waiting("crl")).To(BeFalse())
		svc.priority.mu.Lock()
		defer svc.priority.mu.Unlock()
		Expect(svc.priority.count).To(BeEmpty())
	})

	It("gives up with ctx's error when the name stays busy, without running fn or leaving state behind", func() {
		svc := newService()
		priorityDone, release := holdWithLock(svc, "crl", "revoke", &recorder{})

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		var ran atomic.Bool
		yieldDone := make(chan error, 1)
		// In a goroutine and bounded, because the regression this guards hangs
		// rather than fails: a caller that skipped the gate would queue on the
		// in-process mutex, which no deadline ends.
		go func() {
			yieldDone <- svc.WithLockYielding(ctx, "crl", func() error {
				ran.Store(true)
				return nil
			})
		}()
		var err error
		Eventually(yieldDone, 5*time.Second).Should(Receive(&err),
			"WithLockYielding did not give up at its deadline; it is queued on the lock rather than at the gate")
		Expect(err).To(MatchError(context.DeadlineExceeded))
		// The wording is a contract: it is what an operator searches the log
		// for to tell a job that stood aside from one that failed.
		Expect(err).To(MatchError(ContainSubstring(`waiting to acquire lock "crl" behind a priority caller`)))
		Expect(ran.Load()).To(BeFalse())
		// Checked while the holder is still registered: once it leaves, leave()
		// clears the name's parked list whether or not the abandoned wait
		// took itself off it, so only now can a wait that failed to do so be seen.
		svc.priority.mu.Lock()
		parked := len(svc.priority.clear["crl"])
		svc.priority.mu.Unlock()
		Expect(parked).To(BeZero(), "an abandoned wait must take itself off the parked list")

		release()
		Eventually(priorityDone).Should(Receive(BeNil()))
		svc.priority.mu.Lock()
		defer svc.priority.mu.Unlock()
		Expect(svc.priority.count).To(BeEmpty(), "a name with no priority callers must not stay in the map")
		Expect(svc.priority.clear).To(BeEmpty(), "an abandoned wait must not stay parked")
	})
})

// pausingLocker is a Locker over one real mutex that can park the next
// acquisition after it has been granted, so a spec can register a competing
// caller while the first holds the lock but has not yet returned from
// AcquireLock.
type pausingLocker struct {
	Backend
	mu sync.Mutex

	ctl     sync.Mutex
	pause   bool
	granted chan struct{}
	resume  chan struct{}
}

func (p *pausingLocker) pauseNext() {
	p.ctl.Lock()
	defer p.ctl.Unlock()
	p.pause = true
}

func (p *pausingLocker) AcquireLock(ctx context.Context, _ string) (Unlocker, error) {
	p.mu.Lock()
	p.ctl.Lock()
	pause := p.pause
	p.pause = false
	p.ctl.Unlock()
	if pause {
		close(p.granted)
		<-p.resume
	}
	return pausingUnlocker{p: p}, nil
}

type pausingUnlocker struct{ p *pausingLocker }

func (u pausingUnlocker) Unlock() error {
	u.p.mu.Unlock()
	return nil
}
