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
	"slices"
	"sync"
)

// priorityGates counts, per lock name, the WithLock callers in this process
// that are waiting for or holding that name, and wakes WithLockYielding callers
// when the count for their name falls to zero.
//
// Priority is the default and yielding the exception, deliberately. Every
// WithLock caller registers here without opting in, so an operation added
// later is protected by default, and only a caller that chose WithLockYielding
// can be made to wait. The reverse arrangement would leave each new
// foreground caller unprotected until someone remembered to mark it.
//
// A name is present in the maps only while it has priority callers, so their
// size is bounded by the locks in use at once rather than by every subject
// ever signed.
type priorityGates struct {
	mu sync.Mutex
	// count is the number of WithLock callers registered for each name.
	count map[string]int
	// clear holds one channel per WithLockYielding caller parked on a name,
	// each closed when that name's count reaches zero.
	clear map[string][]chan struct{}
}

// enter registers a priority caller for name.
func (g *priorityGates) enter(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.count == nil {
		g.count = make(map[string]int)
	}
	g.count[name]++
}

// leave deregisters a priority caller for name, waking every caller parked in
// waitClear when it was the last.
func (g *priorityGates) leave(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.count[name]--
	if g.count[name] > 0 {
		return
	}
	delete(g.count, name)
	for _, ch := range g.clear[name] {
		close(ch)
	}
	delete(g.clear, name)
}

// waiting reports whether any priority caller is registered for name.
func (g *priorityGates) waiting(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.count[name] > 0
}

// waitClear returns once no priority caller is registered for name, or with
// ctx's error if ctx ends first.
func (g *priorityGates) waitClear(ctx context.Context, name string) error {
	for {
		g.mu.Lock()
		if g.count[name] == 0 {
			g.mu.Unlock()
			return nil
		}
		if g.clear == nil {
			g.clear = make(map[string][]chan struct{})
		}
		ch := make(chan struct{})
		g.clear[name] = append(g.clear[name], ch)
		g.mu.Unlock()

		select {
		case <-ch:
			// Re-checked from the top: another priority caller may have
			// registered between the wake and this goroutine running.
		case <-ctx.Done():
			g.forget(name, ch)
			return ctx.Err()
		}
	}
}

// forget removes a parked channel whose caller gave up, so a name that stays
// busy does not accumulate one per abandoned wait. leave may already have
// closed and dropped it, in which case there is nothing to remove.
func (g *priorityGates) forget(name string, ch chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	parked := g.clear[name]
	if i := slices.Index(parked, ch); i >= 0 {
		g.clear[name] = slices.Delete(parked, i, i+1)
	}
}
