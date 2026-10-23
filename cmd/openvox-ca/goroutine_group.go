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

package main

import (
	"context"
	"sync"
)

// goroutineGroup runs goroutines under one context and can stop them all and
// wait for them to finish.
//
// The serve command starts every goroutine it owns through one of these, and
// stops it on every return path before its own teardown runs. Before this, each
// goroutine was bound to the command's context and nothing joined it. Cancelling
// that context told them to stop, but the command returned without waiting, so a
// reconcile pass could still be writing to the store after the instance lock was
// released and the runtime closed (#546). Nothing that ends with the process
// shows that. Running the command in-process does: a spec's temporary directory
// was being removed while the pass created a lock file in it.
type goroutineGroup struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// newGoroutineGroup returns a group whose goroutines see a context derived from
// parent: cancelled when parent is, or when Stop is called.
func newGoroutineGroup(parent context.Context) *goroutineGroup {
	ctx, cancel := context.WithCancel(parent)
	return &goroutineGroup{ctx: ctx, cancel: cancel}
}

// Go runs f in a new goroutine with the group's context. f must return once
// that context is cancelled, or Stop waits for it indefinitely.
func (g *goroutineGroup) Go(f func(ctx context.Context)) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		f(g.ctx)
	}()
}

// Stop cancels the group's context and waits for every goroutine started with
// Go to return. Safe to call more than once.
//
// The wait is unbounded on purpose. Everything the serve command runs here
// returns on cancellation. The slowest is a call to the isolated signer, which
// gives up after signer.defaultRemoteSignTimeout. Beyond that the process is
// bounded from outside: the launcher kills the frontend after its drain budget
// plus headroom, and a service manager stops a single-process server after its
// own timeout. A timeout here would only bring back the overlap this type
// exists to prevent.
func (g *goroutineGroup) Stop() {
	g.cancel()
	g.wg.Wait()
}
