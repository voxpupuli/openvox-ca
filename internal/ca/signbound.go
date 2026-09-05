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
	"time"
)

// ErrSigningBusy is returned when a signature was refused because the CA-key
// signing bound was already full and the caller's wait for a slot expired.
//
// Only the OCSP responder can see this: it is the one signing path that sheds
// rather than queues, and acquireSigningSlotOrShed is where that happens. The
// HTTP layer turns it into an RFC 6960 `tryLater`.
var ErrSigningBusy = errors.New("CA signing concurrency limit reached")

// ocspSigningWait is how long the OCSP responder waits for a signing slot
// before shedding the request.
//
// It is a compromise between two failure modes rather than a tuned value. Zero
// wait would shed on any momentary overlap with an issuance, turning normal
// traffic into `tryLater`s. A long wait would let the queue this bound exists
// to prevent re-form in front of it — goroutines, connections and memory
// accumulating while nothing is refused. One second is comfortably longer than
// a signature on any supported backend (an in-process RSA-4096 sign is
// single-digit milliseconds; OpenBao Transit bounds each call at roughly twice
// its login timeout) and short enough that a flood is refused rather than
// absorbed.
const ocspSigningWait = time.Second

// initSigningBound sizes the CA-key signing bound from SigningConcurrency.
// Called by Init with c.mu held.
//
// A non-positive value leaves signSlots nil, which every operation below reads
// as "unbounded" — the pre-bound behaviour, and what a library caller that
// never sets the field gets. That is deliberate rather than a default: this
// mirrors CSRRateLimit, where the zero value disables the limiter and the
// command layer is what turns an unset config key into the shipped default.
func (c *CA) initSigningBound() {
	c.signWait = ocspSigningWait
	if c.SigningConcurrency > 0 {
		c.signSlots = make(chan struct{}, c.SigningConcurrency)
		return
	}
	c.signSlots = nil
}

// acquireSigningSlot takes a CA-key signing slot, waiting until one is free or
// ctx is done. The caller must call releaseSigningSlot when the signature is
// complete, whether or not it succeeded.
//
// This is the queueing half of the bound, and it is what the issuance and CRL
// paths use. They are authenticated, they are already serialised against each
// other by c.mu, and a certificate a client asked for must not be silently
// refused because an unauthenticated responder was busy — so they wait.
//
// SAFETY: both callers hold c.mu across this wait, which would be an
// unbounded stall if the wait itself were unbounded. Two things bound it. The
// OCSP path sheds instead of queueing, so it can never build a queue that an
// issuance has to get to the back of; and this wait honours ctx, so an
// issuance whose client has gone away stops waiting rather than holding c.mu
// on behalf of nobody. Removing either — letting OCSP queue here, or dropping
// the ctx — reintroduces the process-wide stall that
// [#197](https://github.com/voxpupuli/openvox-ca/issues/197) removed, by a
// different queue. See docs/development/locking.md.
func (c *CA) acquireSigningSlot(ctx context.Context) error {
	if c.signSlots == nil {
		return nil
	}
	select {
	case c.signSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// acquireSigningSlotOrShed takes a CA-key signing slot, giving up after
// ocspSigningWait and returning ErrSigningBusy. The caller must call
// releaseSigningSlot on success — and must not on failure.
//
// This is the shedding half, used only by the OCSP responder. `/ocsp` is
// unauthenticated (tierPublic in internal/api/auth.go) and a cache miss signs,
// so it is the one path an anonymous caller can drive at will; letting it
// queue would convert unbounded signing into unbounded queueing rather than
// bounding anything. Refusing is cheap in a way that is specific to this
// protocol: an RFC 6960 non-success response carries no signature at all, so a
// shed request costs no CA-key work whatsoever.
//
// A ctx that is already done is reported as such rather than as ErrSigningBusy.
// The two are different events — a client that went away versus a responder at
// capacity — and only the second is worth counting, so only the second
// increments signingShed.
func (c *CA) acquireSigningSlotOrShed(ctx context.Context) error {
	if c.signSlots == nil {
		return nil
	}

	// Fast path first, so the common uncontended case allocates no timer.
	select {
	case c.signSlots <- struct{}{}:
		return nil
	default:
	}

	timer := time.NewTimer(c.signWait)
	defer timer.Stop()

	select {
	case c.signSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		c.signingShed.Add(1)
		return ErrSigningBusy
	}
}

// releaseSigningSlot returns a slot taken by acquireSigningSlot or
// acquireSigningSlotOrShed. Safe to call on an unbounded CA, where it is a
// no-op, so call sites can defer it unconditionally.
//
// MUST be deferred, not called sequentially after the signature. A panic
// crossing the signing call would otherwise leak the slot, and that is not
// self-correcting the way a panic usually is here: two of the three call sites
// are reachable from an HTTP handler, and net/http's conn.serve recovers a
// handler panic, logs it and drops that one connection — the process survives.
// Nothing in this repository calls recover() itself, so it is that recovery,
// not ours, that turns a crash into permanent capacity loss.
//
// The consequence is worse than it first looks, because the pool is meant to be
// small. `ca_signing_concurrency` defaults to max(4, GOMAXPROCS), but operators
// running a remote signer are explicitly told to lower it to that signer's
// capacity, so 1 or 2 is an ordinary setting rather than a pathological one.
// There, a single leaked slot wedges issuance and CRL re-signing — both queue,
// and under c.mu — and sheds every OCSP request with `tryLater` until restart:
// a permanent denial of service inside the control added to bound one.
//
// Use the closure-with-defer shape at the call sites so the slot is held for
// the signature alone: a function-scoped defer would keep it across storage
// writes that follow. This is rule 4 of docs/development/locking.md applied to
// the bound, and signing.go's "a panic mid-sign still frees the lock rather
// than wedging the CA" is the same argument for c.mu.
func (c *CA) releaseSigningSlot() {
	if c.signSlots == nil {
		return
	}
	<-c.signSlots
}

// SigningInFlight returns how many CA-key signatures are in flight right now,
// and the configured bound. A zero limit means signing is unbounded.
//
// The pair is what makes the gauge readable: in-flight alone cannot tell an
// operator whether 8 concurrent signatures is comfortable or is the ceiling.
// The metrics exporter surfaces them as puppetca_ca_signing_in_flight and
// puppetca_ca_signing_limit.
func (c *CA) SigningInFlight() (inFlight int, limit int) {
	if c.signSlots == nil {
		return 0, 0
	}
	return len(c.signSlots), cap(c.signSlots)
}

// SigningShedTotal returns the number of OCSP responses refused because the
// CA-key signing bound was full.
//
// A rising value means an unauthenticated caller — or simply more verifier
// traffic than the configured bound allows — is being turned away with
// `tryLater` rather than being allowed to grow the signer's queue without
// limit. It is not by itself a fault: it is the bound doing its job, and the
// question it poses is whether the limit matches the deployment's signer. The
// metrics exporter surfaces it as puppetca_ca_signing_shed_total.
func (c *CA) SigningShedTotal() uint64 {
	return c.signingShed.Load()
}
