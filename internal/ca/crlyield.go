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

package ca

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// A revocation always wins over a background sweep (#347). This file is how.
//
// The background jobs that write the CRL — CleanupExpiredCerts,
// ReconcileSuperseded, RefreshCRLIfDue, RefreshCRLChainFile and
// MergeFetchedUpstreamCRLs — take the CRL
// lock through StorageService.WithLockYielding, so none of them queues for it
// while a revocation in this process is waiting for or holding it. Every other
// acquisition of the CRL lock but one goes through plain WithLock and so has
// priority without opting in, which is the safe default for an operation added
// later; the exception, recordSuperseded, is below. What decides which side a
// job is on is whether anyone is waiting on it. Work an operator or a
// correctness path is waiting on keeps WithLock: Revoke, RevokeSerial,
// ReissueCRL, and ReconcileManaged's rollback and the retirements it revokes
// inline, though that job runs on a timer. Scheduled work whose timing is
// already approximate yields — expiry pruning, the CRL refresh, the chain
// refresh and the crl_chain.urls merge, and the delayed-supersession sweep,
// whose revocations are owed after
// a window anyway and which #347 names as a sweep. Recording a supersession is
// neither: a client waits on it, but it revokes nothing, so recordSuperseded
// takes the lock through WithLockNeutral.
//
// Yielding before a step is not enough on its own, because a revocation that
// arrives after a step has started waits for that step to end. So the sweeps
// work in steps, each its own acquisition, the two refresh jobs run as a
// single step each, all through sweepStep, and every step's hold is bounded by
// one budget, sweepStepBudget, counted from the moment the lock is granted,
// with nothing inside the lock extending it. That is the shape #347 removed:
// both sweeps used to hold the lock for a LockTimeout and then grant
// themselves a further LockTimeout/2 on a detached context, so a slow sweep
// could outlast every revocation waiting on it. The spec in
// crlyield_internal_test.go fails if a CRL-lock closure derives a detached
// context again.
//
// What this does not cover, stated so nobody reads more into it: a revocation
// on another replica. The gate sees callers in this process only. There a
// revocation waits for the step in progress, and also for every step other
// replicas already have queued ahead of it, since a backend that queues lock
// waiters (etcd) grants them in order. The pause between steps only stops a
// replica's own next step jumping that queue, and gives a backend whose lock
// is polled rather than queued (Redis) the chance to grant the revocation at
// all; nothing gives it priority. So the worst case grows with the number of
// replicas sweeping at once.
const (
	// sweepStepBudget bounds one step of a background sweep twice over: the
	// wait for the lock, and separately the hold, counted from the moment the
	// lock is granted, with every write made under it. A revocation that
	// arrives just after a step starts waits for at most the hold, so it must
	// leave the smallest revocation budget enough to finish in. That is the
	// managed certificate rollback's LockTimeout/2; a quarter of LockTimeout
	// leaves it half its budget. The spec pins the relation against the
	// rollback's own budget expressions, not the number. One thing in a hold
	// does not honour this budget: the CA signature, which takes no context,
	// so a hold is this budget plus at most one signature in flight
	// (locking.md, known gaps).
	sweepStepBudget = LockTimeout / 4

	// sweepStepPause separates one step's release from the next step's
	// acquisition. It is for revocations on other replicas: Redis polls for a
	// lock with a backoff that tops out at 500ms, so a sweep that re-queued at
	// once would usually win the lock back before the waiter next looked.
	sweepStepPause = time.Second

	// sweepStepEntries caps the entries one step prunes or revokes. The CRL
	// re-sign is one per step whatever the count; what the cap bounds is the
	// per-entry work around it, which is what grows with a backlog. It does not
	// bound the scan: the cleanup's prune reads and verifies the whole
	// inventory on every step, so a backlog of N costs N/sweepStepEntries
	// scans where one pass used to cost one, and on the filesystem backend as
	// many whole-inventory rewrites. The etcd and Redis prune caps (900 and
	// 5000 a call) are only a backstop while this stays below both; their
	// comments in internal/storage rely on it.
	sweepStepEntries = 100
)

// sweepTuning overrides the step constants above. Its zero value means the
// constants, and nothing in production sets it: it is a seam for specs, which
// cannot wait out a fifteen-second step.
type sweepTuning struct {
	stepBudget  time.Duration
	stepPause   time.Duration
	stepEntries int
}

func (c *CA) sweepStepBudget() time.Duration {
	if c.sweep.stepBudget > 0 {
		return c.sweep.stepBudget
	}
	return sweepStepBudget
}

func (c *CA) sweepStepEntries() int {
	if c.sweep.stepEntries > 0 {
		return c.sweep.stepEntries
	}
	return sweepStepEntries
}

// sweepStep runs one step of a background sweep: it takes the CRL lock with
// lock, which must be one of the yielding acquisitions, and runs fn under it.
//
// Two budgets, one per half, each sweepStepBudget. The wait for the lock runs
// on parent, so a shutdown ends it, as it ends any wait that is not protecting
// a write. The hold runs on a context detached from parent, so a shutdown
// cannot cut a step off between a durable write and the bookkeeping that has
// to follow it, and its budget starts when the lock is granted, so a step that
// waited long still has its whole budget for that bookkeeping.
//
// The detachment happens here, before the lock is taken, never inside it, and
// the hold's budget is fixed at acquisition and not extended after. That is
// the whole difference from the shape #347 removed: a revocation that arrives
// while fn runs waits for at most sweepStepBudget, plus any CA signature fn
// has in flight, which takes no context. fn's context is the only one it may
// use for storage.
func (c *CA) sweepStep(parent context.Context, lock func(context.Context, func() error) error,
	fn func(ctx context.Context) error) error {
	waitCtx, cancelWait := context.WithTimeout(parent, c.sweepStepBudget())
	defer cancelWait()
	detached := context.WithoutCancel(parent)
	return lock(waitCtx, func() error {
		holdCtx, cancelHold := context.WithTimeout(detached, c.sweepStepBudget())
		defer cancelHold()
		return fn(holdCtx)
	})
}

// shareOfStep returns a context for the first of two phases of a step, ending
// halfway through what remains of the step's budget, so that the phase after
// it keeps at least that half. It subdivides the step's budget rather than
// adding to it: the step's own deadline still bounds both.
func shareOfStep(step context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := step.Deadline()
	if !ok {
		return context.WithCancel(step)
	}
	return context.WithTimeout(step, time.Until(deadline)/2)
}

// pauseBetweenSweepSteps waits sweepStepPause, or returns ctx's error if ctx
// ends first.
func (c *CA) pauseBetweenSweepSteps(ctx context.Context) error {
	pause := sweepStepPause
	if c.sweep.stepPause > 0 {
		pause = c.sweep.stepPause
	}
	t := time.NewTimer(pause)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// sweepProgressEvery is how often a pass that is still stepping reports its
// running total at info level. A large first pass now takes a step and a
// pause per sweepStepEntries entries, so it can run for many minutes, and a
// pass that reported only when it ended would look the same as one that had
// wedged.
const sweepProgressEvery = time.Minute

// sweepProgress reports a multi-step pass's running total: every step at debug
// level, and at most once a sweepProgressEvery at info.
type sweepProgress struct {
	what, unit string
	last       time.Time
}

func newSweepProgress(what, unit string) *sweepProgress {
	return &sweepProgress{what: what, unit: unit, last: time.Now()}
}

// step records that another step finished with total so far.
func (p *sweepProgress) step(total int) {
	slog.Debug(p.what+": step done, more remain", p.unit, total)
	if time.Since(p.last) >= sweepProgressEvery {
		p.last = time.Now()
		slog.Info(p.what+" in progress", p.unit, total)
	}
}

// StoppedByShutdown reports whether err is ctx being cancelled: a background
// pass that a shutdown ended, which is not a failed pass and is not counted. A
// deadline of ctx's own that ran out is a pass that did not finish, and is. The
// jobs that count failures and the drivers that log them all decide by this one
// predicate, so a counter and its log line cannot disagree about a pass.
func StoppedByShutdown(ctx context.Context, err error) bool {
	return errors.Is(ctx.Err(), context.Canceled) && errors.Is(err, context.Canceled)
}

// withCRLLockYielding is withCRLLockCounted for background work: it takes the
// CRL lock through WithLockYielding, and counts a failure to take it at all
// into crlUpdateFailures as withCRLLockCounted does, for the reason that
// function gives, with the one exception below.
//
// A job that yielded for its whole budget is counted by that too, since it is
// a re-sign that did not happen. It takes a revocation storm lasting the whole
// step budget to do it. A wait that a shutdown ended is not: the pass did not
// fail, the process is stopping (locking.md, "A pass that a shutdown ends is
// not a failed pass").
func (c *CA) withCRLLockYielding(ctx context.Context, fn func() error) error {
	ran := false
	err := c.Storage.WithLockYielding(ctx, lockNameCRL, func() error {
		ran = true
		return fn()
	})
	stopped := StoppedByShutdown(ctx, err)
	if err != nil && !ran && !stopped {
		c.crlUpdateFailures.Add(1)
	}
	return err
}
