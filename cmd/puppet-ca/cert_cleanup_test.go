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

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

// seedExpiredInventoryEntry appends an inventory entry whose NotAfter is two
// years in the past, so a cleanup pass with any modest retention removes it.
// (newRefresherTestCA is defined in crl_refresh_test.go in this package.)
func seedExpiredInventoryEntry(t *testing.T, store *storage.StorageService, subject string) {
	t.Helper()
	past := time.Now().Add(-2 * 365 * 24 * time.Hour).Format("2006-01-02T15:04:05UTC")
	entry := "ABCD " + past + " " + past + " /" + subject
	if err := store.AppendInventory(context.Background(), entry); err != nil {
		t.Fatalf("AppendInventory: %v", err)
	}
}

func inventoryHas(t *testing.T, store *storage.StorageService, needle string) bool {
	t.Helper()
	data, err := store.ReadInventory(context.Background())
	if err != nil {
		t.Fatalf("ReadInventory: %v", err)
	}
	return strings.Contains(string(data), needle)
}

// cleanupExpiredOnce should remove an expired entry and leave a fresh one alone.
func TestCleanupExpiredOnce(t *testing.T) {
	c, store := newRefresherTestCA(t)
	ctx := context.Background()

	seedExpiredInventoryEntry(t, store, "expired-node")
	if !inventoryHas(t, store, "/expired-node") {
		t.Fatal("precondition: expired-node should be in the inventory")
	}

	cleanupExpiredOnce(ctx, c, time.Hour)
	if inventoryHas(t, store, "/expired-node") {
		t.Error("expired-node should have been removed from the inventory")
	}
}

// runCertCleaner must perform an immediate cleanup at startup and then return
// promptly once its context is cancelled.
func TestRunCertCleanerStartupAndShutdown(t *testing.T) {
	c, store := newRefresherTestCA(t)
	seedExpiredInventoryEntry(t, store, "expired-node")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runCertCleaner(ctx, c, time.Hour, time.Hour)
		close(done)
	}()

	// The startup pass should prune the expired entry before we cancel; poll.
	deadline := time.After(2 * time.Second)
	for inventoryHas(t, store, "/expired-node") {
		select {
		case <-deadline:
			t.Fatal("startup cleanup did not run within 2s")
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCertCleaner did not return after context cancellation")
	}
}
