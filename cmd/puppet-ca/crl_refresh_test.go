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
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/storage"
	"github.com/tvaughan/puppet-ca/internal/testutil"
)

// newRefresherTestCA builds an initialised CA backed by a temp filesystem store,
// seeded with a freshly generated test CA and CRL.
func newRefresherTestCA(t *testing.T) (*ca.CA, *storage.StorageService) {
	t.Helper()
	keyPEM, crtPEM, crlPEM, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("GenerateTestCA: %v", err)
	}

	store := storage.New(t.TempDir())
	c := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
	ctx := context.Background()
	if err := store.EnsureDirs(ctx); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := store.SaveCAKey(ctx, keyPEM); err != nil {
		t.Fatalf("SaveCAKey: %v", err)
	}
	if err := store.SaveCACert(ctx, crtPEM); err != nil {
		t.Fatalf("SaveCACert: %v", err)
	}
	if err := store.UpdateCRL(ctx, crlPEM); err != nil {
		t.Fatalf("UpdateCRL: %v", err)
	}
	if err := store.WriteSerial(ctx, "0001"); err != nil {
		t.Fatalf("WriteSerial: %v", err)
	}
	if err := store.TouchInventory(ctx); err != nil {
		t.Fatalf("TouchInventory: %v", err)
	}
	if err := c.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return c, store
}

func storedCRLNumber(t *testing.T, store *storage.StorageService) int64 {
	t.Helper()
	crlPEM, err := store.GetCRL(context.Background())
	if err != nil {
		t.Fatalf("GetCRL: %v", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatalf("CRL is not PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	return crl.Number.Int64()
}

// refreshCRLOnce should re-sign when the refresh window exceeds the CRL's
// remaining validity, and leave it alone otherwise.
func TestRefreshCRLOnce(t *testing.T) {
	c, store := newRefresherTestCA(t)
	ctx := context.Background()

	start := storedCRLNumber(t, store)

	// Window far larger than remaining validity: must re-sign.
	refreshCRLOnce(ctx, c, 3650*24*time.Hour)
	afterDue := storedCRLNumber(t, store)
	if afterDue != start+1 {
		t.Fatalf("expected CRL number to increment from %d, got %d", start, afterDue)
	}

	// Tiny window against a freshly reissued CRL: must not re-sign.
	refreshCRLOnce(ctx, c, time.Hour)
	afterFresh := storedCRLNumber(t, store)
	if afterFresh != afterDue {
		t.Fatalf("expected CRL number to stay at %d, got %d", afterDue, afterFresh)
	}
}

// runCRLRefresher must perform an immediate check at startup and then return
// promptly once its context is cancelled.
func TestRunCRLRefresherStartupAndShutdown(t *testing.T) {
	c, store := newRefresherTestCA(t)
	start := storedCRLNumber(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		// A large refresh window guarantees the startup check re-signs.
		runCRLRefresher(ctx, c, time.Hour, 3650*24*time.Hour)
		close(done)
	}()

	// The startup check should re-sign before we cancel; poll briefly.
	deadline := time.After(2 * time.Second)
	for storedCRLNumber(t, store) == start {
		select {
		case <-deadline:
			t.Fatal("startup refresh did not run within 2s")
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCRLRefresher did not return after context cancellation")
	}
}
