// Copyright (C) 2026 Trevor Vaughan
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
	"io/fs"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
func (b *hmacStubBackend) Delete(context.Context, string) error           { return nil }
func (b *hmacStubBackend) Exists(context.Context, string) (bool, error)   { return false, nil }
func (b *hmacStubBackend) List(context.Context, string) ([]string, error) { return nil, nil }
func (b *hmacStubBackend) AppendLine(context.Context, string, []byte, BlobKind) error {
	return nil
}
func (b *hmacStubBackend) ModTime(context.Context, string) (time.Time, error) {
	return time.Time{}, nil
}
func (b *hmacStubBackend) Close() error { return nil }

var _ = Describe("EnsureHMACKey", func() {
	// Guards against the most dangerous failure mode: a transient backend
	// error (network blip, deadline, etc.) being treated as "key absent" and
	// silently regenerating the HMAC key, which would invalidate every
	// existing inventory MAC.
	Context("when the backend returns a transient error", func() {
		It("does not overwrite the key", func() {
			transient := errors.New("etcd: deadline exceeded")
			be := &hmacStubBackend{getErr: transient}
			svc := NewWithBackend(be, "")

			_, err := svc.EnsureHMACKey(context.Background())
			Expect(err).To(HaveOccurred(), "EnsureHMACKey returned nil error; want propagated transient error")
			Expect(err).To(MatchError(transient), "EnsureHMACKey error = %v; want it to wrap %v", err, transient)
			Expect(be.putCalls).To(Equal(0), "EnsureHMACKey called Put %d times on transient error; want 0", be.putCalls)
		})
	})

	// Confirms that a real "not present" signal still triggers fresh-key
	// generation (the happy path of first boot).
	Context("when the key does not exist", func() {
		It("generates a new key", func() {
			notExist := &fs.PathError{Op: "get", Path: KeyHMACKey, Err: fs.ErrNotExist}
			be := &hmacStubBackend{getErr: notExist}
			svc := NewWithBackend(be, "")

			key, err := svc.EnsureHMACKey(context.Background())
			Expect(err).NotTo(HaveOccurred(), "EnsureHMACKey: %v", err)
			Expect(key).To(HaveLen(hmacKeyLen), "key length = %d; want %d", len(key), hmacKeyLen)
			Expect(be.putCalls).To(Equal(1), "Put called %d times; want 1", be.putCalls)
		})
	})

	// Covers the case where the stored blob exists but is the wrong length
	// (corruption / partial write). The existing behaviour treats this as
	// "regenerate", which is preserved.
	Context("when the stored key is truncated", func() {
		It("regenerates the key", func() {
			be := &hmacStubBackend{getValue: []byte("too-short")}
			svc := NewWithBackend(be, "")

			key, err := svc.EnsureHMACKey(context.Background())
			Expect(err).NotTo(HaveOccurred(), "EnsureHMACKey: %v", err)
			Expect(key).To(HaveLen(hmacKeyLen), "key length = %d; want %d", len(key), hmacKeyLen)
			Expect(be.putCalls).To(Equal(1), "Put called %d times; want 1", be.putCalls)
		})
	})

	// The happy path: a valid key already lives in the backend, so
	// EnsureHMACKey must return it verbatim without issuing a Put. Without
	// this property, every restart would replace the persisted key (silently
	// invalidating the inventory HMAC baseline on every boot).
	Context("when a valid key already exists", func() {
		It("returns it verbatim without writing", func() {
			stored := make([]byte, hmacKeyLen)
			for i := range stored {
				stored[i] = byte(i)
			}
			be := &hmacStubBackend{getValue: stored}
			svc := NewWithBackend(be, "")

			key, err := svc.EnsureHMACKey(context.Background())
			Expect(err).NotTo(HaveOccurred(), "EnsureHMACKey: %v", err)
			Expect(key).To(HaveLen(hmacKeyLen), "key length = %d; want %d", len(key), hmacKeyLen)
			for i := range stored {
				Expect(key[i]).To(Equal(stored[i]), "key[%d] = 0x%02x; want 0x%02x (existing key not returned verbatim)", i, key[i], stored[i])
			}
			Expect(be.putCalls).To(Equal(0), "Put called %d times; want 0 (existing valid key must not be overwritten)", be.putCalls)
		})
	})
})

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

var _ = Describe("StorageService context propagation", func() {
	// The end-to-end positive case for the ctx propagation: the ctx the
	// caller passes to a StorageService method must be observed by the
	// backend, not silently replaced with context.Background() at the
	// boundary.
	Context("when the caller passes a context with a value", func() {
		It("propagates the context to the backend", func() {
			be := &ctxObservingBackend{
				hmacStubBackend: hmacStubBackend{getValue: make([]byte, hmacKeyLen)},
			}
			svc := NewWithBackend(be, "")

			type ctxKey struct{}
			caller := context.WithValue(context.Background(), ctxKey{}, "caller-marker")

			_, err := svc.EnsureHMACKey(caller)
			Expect(err).NotTo(HaveOccurred(), "EnsureHMACKey: %v", err)
			Expect(be.lastCtx.Value(ctxKey{})).To(Equal("caller-marker"), "backend received ctx without caller marker; StorageService is not propagating ctx")
		})
	})

	// The negative case: a cancelled caller ctx must surface from the
	// backend as context.Canceled rather than being swallowed by an
	// internal context.Background() wrap.
	Context("when the caller passes a cancelled context", func() {
		It("surfaces context.Canceled", func() {
			be := &ctxObservingBackend{
				hmacStubBackend: hmacStubBackend{getErr: context.Canceled},
			}
			svc := NewWithBackend(be, "")

			cancelled, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := svc.EnsureHMACKey(cancelled)
			Expect(err).To(MatchError(context.Canceled), "EnsureHMACKey err = %v; want it to wrap context.Canceled", err)
		})
	})
})
