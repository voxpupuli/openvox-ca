// Copyright (C) 2026 Chris Boot
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
	"bytes"
	"context"
	"testing"
)

// newFilesystemInventoryService returns a StorageService over a fresh
// filesystem backend with the inventory touched, integrity initialised, and
// sampleInventoryLines appended. It mirrors newInventoryService (SQLite) so the
// prune tests can exercise both the structured and blob inventory paths.
func newFilesystemInventoryService(t *testing.T) *StorageService {
	t.Helper()
	ctx := context.Background()
	svc := New(t.TempDir())
	if err := svc.EnsureDirs(ctx); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := svc.TouchInventory(ctx); err != nil {
		t.Fatalf("TouchInventory: %v", err)
	}
	if err := svc.InitHMAC(ctx); err != nil {
		t.Fatalf("InitHMAC: %v", err)
	}
	for _, line := range sampleInventoryLines {
		if err := svc.AppendInventory(ctx, line); err != nil {
			t.Fatalf("AppendInventory(%q): %v", line, err)
		}
	}
	return svc
}

// keepNotSerial returns a predicate that keeps every entry except the one with
// the given serial.
func keepNotSerial(serial string) func(InventoryEntry) bool {
	return func(e InventoryEntry) bool { return e.Serial != serial }
}

// TestPruneInventory exercises StorageService.PruneInventory against both the
// structured (SQLite) and blob (filesystem) backends. The critical property is
// that after a prune the integrity head is rewritten so ReadInventory — which
// verifies the HMAC/hash chain — still succeeds; a stale head would surface as
// ErrInventoryTampered.
func TestPruneInventory(t *testing.T) {
	backends := map[string]func(t *testing.T) *StorageService{
		"sqlite": func(t *testing.T) *StorageService {
			svc, _ := newInventoryService(t)
			return svc
		},
		"filesystem": newFilesystemInventoryService,
	}

	for name, mk := range backends {
		t.Run(name, func(t *testing.T) {
			t.Run("removes matching entries and rewrites the integrity head", func(t *testing.T) {
				ctx := context.Background()
				svc := mk(t)

				// Drop serial 0002 (node2); node1's 0001 and 0003 must survive in order.
				removed, err := svc.PruneInventory(ctx, keepNotSerial("0002"))
				if err != nil {
					t.Fatalf("PruneInventory: %v", err)
				}
				if len(removed) != 1 || removed[0].Serial != "0002" || removed[0].Subject != "node2" {
					t.Fatalf("removed = %+v; want one entry serial 0002 subject node2", removed)
				}

				// ReadInventory verifies the integrity head before returning, so a
				// successful read proves the chain/HMAC was rewritten for the survivors.
				got, err := svc.ReadInventory(ctx)
				if err != nil {
					t.Fatalf("ReadInventory after prune: %v (head not rewritten?)", err)
				}
				want := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n" +
					"0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1\n"
				if !bytes.Equal(got, []byte(want)) {
					t.Errorf("inventory after prune = %q, want %q", got, want)
				}

				// A subsequent append must extend the rewritten chain cleanly.
				if err := svc.AppendInventory(ctx, "0004 2024-01-04T00:00:00UTC 2029-01-04T00:00:00UTC /node3"); err != nil {
					t.Fatalf("AppendInventory after prune: %v", err)
				}
				if _, err := svc.ReadInventory(ctx); err != nil {
					t.Fatalf("ReadInventory after post-prune append: %v", err)
				}
			})

			t.Run("no match leaves inventory and head untouched", func(t *testing.T) {
				ctx := context.Background()
				svc := mk(t)

				before, err := svc.ReadInventory(ctx)
				if err != nil {
					t.Fatalf("ReadInventory: %v", err)
				}
				removed, err := svc.PruneInventory(ctx, func(InventoryEntry) bool { return true })
				if err != nil {
					t.Fatalf("PruneInventory: %v", err)
				}
				if len(removed) != 0 {
					t.Fatalf("removed = %+v; want none", removed)
				}
				after, err := svc.ReadInventory(ctx)
				if err != nil {
					t.Fatalf("ReadInventory after no-op prune: %v", err)
				}
				if !bytes.Equal(before, after) {
					t.Errorf("inventory changed by no-op prune: before %q after %q", before, after)
				}
			})
		})
	}
}
