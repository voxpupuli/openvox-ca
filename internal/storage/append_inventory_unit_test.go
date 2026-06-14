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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// hmacPutFailBackend wraps a real FilesystemBackend but can be armed to fail
// Put(KeyInventoryHMAC, ...) specifically, while letting the inventory line
// append and every other operation succeed. This reproduces the dangerous
// state where the inventory has grown but its HMAC could not be updated.
type hmacPutFailBackend struct {
	*FilesystemBackend
	failHMACPut bool
}

func (b *hmacPutFailBackend) Put(ctx context.Context, key string, data []byte, kind BlobKind) error {
	if b.failHMACPut && key == KeyInventoryHMAC {
		return errors.New("simulated backend failure writing inventory HMAC")
	}
	return b.FilesystemBackend.Put(ctx, key, data, kind)
}

var _ = Describe("AppendInventory HMAC update failure", func() {
	// Proves that when the inventory line is durably appended but the
	// subsequent HMAC update fails, AppendInventory returns a non-nil error
	// instead of silently downgrading it to a warning. Swallowing the error
	// leaves the inventory and its stored HMAC inconsistent, so the next
	// ReadInventory would falsely report tampering.
	It("surfaces the HMAC update failure", func() {
		dir := GinkgoT().TempDir()

		be := &hmacPutFailBackend{FilesystemBackend: NewFilesystemBackend(dir)}
		svc := NewWithBackend(be, "")

		ctx := context.Background()
		err := svc.EnsureDirs(ctx)
		Expect(err).NotTo(HaveOccurred(), "EnsureDirs: %v", err)
		err = svc.TouchInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "TouchInventory: %v", err)
		err = svc.InitHMAC(ctx)
		Expect(err).NotTo(HaveOccurred(), "InitHMAC: %v", err)

		// Arm the failure only now, so init succeeded and hmacKey is set.
		be.failHMACPut = true

		err = svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")
		Expect(err).To(HaveOccurred(), "AppendInventory returned nil; want a non-nil error when the HMAC update fails")
	})
})
