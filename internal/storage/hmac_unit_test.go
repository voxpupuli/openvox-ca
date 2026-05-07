// Copyright (C) 2026 Trevor Vaughan
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
	"io/fs"
	"testing"
	"time"
)

// hmacStubBackend lets tests script the response of Get(KeyHMACKey) and
// observe whether Put(KeyHMACKey, ...) is called.
type hmacStubBackend struct {
	getErr   error
	getValue []byte
	putCalls int
}

func (b *hmacStubBackend) EnsureReady(context.Context) error { return nil }
func (b *hmacStubBackend) Get(_ context.Context, key string) ([]byte, error) {
	if key == KeyHMACKey {
		return b.getValue, b.getErr
	}
	return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
}
func (b *hmacStubBackend) Put(_ context.Context, key string, _ []byte, _ BlobKind) error {
	if key == KeyHMACKey {
		b.putCalls++
	}
	return nil
}
func (b *hmacStubBackend) Delete(context.Context, string) error                   { return nil }
func (b *hmacStubBackend) Exists(context.Context, string) (bool, error)           { return false, nil }
func (b *hmacStubBackend) List(context.Context, string) ([]string, error)         { return nil, nil }
func (b *hmacStubBackend) AppendLine(context.Context, string, []byte, BlobKind) error {
	return nil
}
func (b *hmacStubBackend) ModTime(context.Context, string) (time.Time, error) { return time.Time{}, nil }
func (b *hmacStubBackend) Close() error                                       { return nil }

// TestEnsureHMACKeyDoesNotOverwriteOnTransientError guards against the most
// dangerous failure mode: a transient backend error (network blip, deadline,
// etc.) being treated as "key absent" and silently regenerating the HMAC key,
// which would invalidate every existing inventory MAC.
func TestEnsureHMACKeyDoesNotOverwriteOnTransientError(t *testing.T) {
	transient := errors.New("etcd: deadline exceeded")
	be := &hmacStubBackend{getErr: transient}
	svc := NewWithBackend(be, "")

	_, err := svc.EnsureHMACKey(context.Background())
	if err == nil {
		t.Fatal("EnsureHMACKey returned nil error; want propagated transient error")
	}
	if !errors.Is(err, transient) {
		t.Fatalf("EnsureHMACKey error = %v; want it to wrap %v", err, transient)
	}
	if be.putCalls != 0 {
		t.Fatalf("EnsureHMACKey called Put %d times on transient error; want 0", be.putCalls)
	}
}

// TestEnsureHMACKeyGeneratesOnNotExist confirms that a real "not present"
// signal still triggers fresh-key generation (the happy path of first boot).
func TestEnsureHMACKeyGeneratesOnNotExist(t *testing.T) {
	notExist := &fs.PathError{Op: "get", Path: KeyHMACKey, Err: fs.ErrNotExist}
	be := &hmacStubBackend{getErr: notExist}
	svc := NewWithBackend(be, "")

	key, err := svc.EnsureHMACKey(context.Background())
	if err != nil {
		t.Fatalf("EnsureHMACKey: %v", err)
	}
	if len(key) != hmacKeyLen {
		t.Fatalf("key length = %d; want %d", len(key), hmacKeyLen)
	}
	if be.putCalls != 1 {
		t.Fatalf("Put called %d times; want 1", be.putCalls)
	}
}

// TestEnsureHMACKeyRegeneratesOnTruncated covers the case where the stored
// blob exists but is the wrong length (corruption / partial write). The
// existing behaviour treats this as "regenerate", which is preserved.
func TestEnsureHMACKeyRegeneratesOnTruncated(t *testing.T) {
	be := &hmacStubBackend{getValue: []byte("too-short")}
	svc := NewWithBackend(be, "")

	key, err := svc.EnsureHMACKey(context.Background())
	if err != nil {
		t.Fatalf("EnsureHMACKey: %v", err)
	}
	if len(key) != hmacKeyLen {
		t.Fatalf("key length = %d; want %d", len(key), hmacKeyLen)
	}
	if be.putCalls != 1 {
		t.Fatalf("Put called %d times; want 1", be.putCalls)
	}
}

// TestEnsureHMACKeyReturnsExistingWithoutWrite is the happy path: a valid
// key already lives in the backend, so EnsureHMACKey must return it
// verbatim without issuing a Put. Without this property, every restart
// would replace the persisted key (silently invalidating the inventory
// HMAC baseline on every boot).
func TestEnsureHMACKeyReturnsExistingWithoutWrite(t *testing.T) {
	stored := make([]byte, hmacKeyLen)
	for i := range stored {
		stored[i] = byte(i)
	}
	be := &hmacStubBackend{getValue: stored}
	svc := NewWithBackend(be, "")

	key, err := svc.EnsureHMACKey(context.Background())
	if err != nil {
		t.Fatalf("EnsureHMACKey: %v", err)
	}
	if len(key) != hmacKeyLen {
		t.Fatalf("key length = %d; want %d", len(key), hmacKeyLen)
	}
	for i, b := range key {
		if b != stored[i] {
			t.Fatalf("key[%d] = 0x%02x; want 0x%02x (existing key not returned verbatim)", i, b, stored[i])
		}
	}
	if be.putCalls != 0 {
		t.Fatalf("Put called %d times; want 0 (existing valid key must not be overwritten)", be.putCalls)
	}
}

// Compile-time check that the stub satisfies the interface as exercised by
// StorageService. Locker is intentionally not implemented so WithLock falls
// back to the local mutex path (irrelevant for these tests).
var _ Backend = (*hmacStubBackend)(nil)

// ctxObservingBackend records the ctx it was last called with, so a test
// can verify StorageService threads its caller's ctx all the way down
// rather than substituting context.Background() somewhere in between.
type ctxObservingBackend struct {
	hmacStubBackend
	lastCtx context.Context
}

func (b *ctxObservingBackend) Get(ctx context.Context, key string) ([]byte, error) {
	b.lastCtx = ctx
	return b.hmacStubBackend.Get(ctx, key)
}

func (b *ctxObservingBackend) Put(ctx context.Context, key string, data []byte, kind BlobKind) error {
	b.lastCtx = ctx
	return b.hmacStubBackend.Put(ctx, key, data, kind)
}

// TestStorageServicePropagatesContext is the end-to-end positive case for
// the ctx propagation: the ctx the caller passes to a StorageService
// method must be observed by the backend, not silently replaced with
// context.Background() at the boundary.
func TestStorageServicePropagatesContext(t *testing.T) {
	be := &ctxObservingBackend{
		hmacStubBackend: hmacStubBackend{getValue: make([]byte, hmacKeyLen)},
	}
	svc := NewWithBackend(be, "")

	type ctxKey struct{}
	caller := context.WithValue(context.Background(), ctxKey{}, "caller-marker")

	if _, err := svc.EnsureHMACKey(caller); err != nil {
		t.Fatalf("EnsureHMACKey: %v", err)
	}
	if got := be.lastCtx.Value(ctxKey{}); got != "caller-marker" {
		t.Fatalf("backend received ctx without caller marker (got %v); StorageService is not propagating ctx", got)
	}
}

// TestStorageServiceHonoursCancelledContext is the negative case: a
// cancelled caller ctx must surface from the backend as context.Canceled
// rather than being swallowed by an internal context.Background() wrap.
func TestStorageServiceHonoursCancelledContext(t *testing.T) {
	be := &ctxObservingBackend{
		hmacStubBackend: hmacStubBackend{getErr: context.Canceled},
	}
	svc := NewWithBackend(be, "")

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := svc.EnsureHMACKey(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureHMACKey err = %v; want it to wrap context.Canceled", err)
	}
}
