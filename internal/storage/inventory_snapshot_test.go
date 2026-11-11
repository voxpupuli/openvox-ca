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
	"bytes"
	"context"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// peerHeadBackend answers a direct read of the stored integrity head with a
// head another replica's later append would have left, while the rows and the
// head inside the store itself stay as they are. That is exactly what a reader
// sees when a peer's append commits between reading the rows and reading the
// head separately: one state's rows, the next state's head.
//
// Unwrap lets asInventoryStore reach the real backend underneath, so
// EntriesWithHead reads rows and head from that backend's own snapshot and
// never sees the substituted head. Only a reader that fetches the head through
// Get, apart from the rows, does.
type peerHeadBackend struct {
	Backend
	head []byte
}

func (b peerHeadBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == KeyInventoryHMAC {
		return b.head, nil
	}
	return b.Backend.Get(ctx, key)
}

func (b peerHeadBackend) Unwrap() Backend { return b.Backend }

// Verification on a structured backend compares the fold over the rows with the
// head from the same snapshot. Read apart, a peer's append landing between the
// two reads is indistinguishable from tampering, and the periodic verification
// pages it as such on every multi-replica deployment.
var _ = Describe("Inventory verification on a structured backend", func() {
	var (
		ctx context.Context
		svc *StorageService
		raw Backend
	)

	BeforeEach(func() {
		ctx = context.Background()
		svc = NewWithBackend(newSQLiteBackend(), "")
		Expect(svc.TouchInventory(ctx)).To(Succeed())
		Expect(svc.InitHMAC(ctx)).To(Succeed())
		Expect(svc.AppendInventoryRecord(ctx,
			"0A 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /a.example.com", nil)).To(Succeed())
		Expect(svc.AppendInventoryRecord(ctx,
			"0B 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /b.example.com", nil)).To(Succeed())
		raw = svc.backend
		svc.backend = peerHeadBackend{Backend: raw, head: bytes.Repeat([]byte{0x5a}, 32)}
	})

	It("does not read a peer's append between the rows and the head as tampering", func() {
		_, err := svc.InventoryEntries(ctx)
		Expect(err).NotTo(HaveOccurred())
	})

	It("does not refuse startup verification for a peer's append either", func() {
		Expect(svc.VerifyInventoryHMAC(ctx, svc.hmacKey)).To(Succeed())
	})

	// The report rebuild-inventory-hmac prints, and the check a migration
	// makes of its source, both of which may run against a live CA.
	It("does not report a peer's append as an inventory that fails to verify", func() {
		rep, err := svc.InventoryIntegrityReport(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rep.Verifies).To(BeTrue())
	})

	// The control: the same fixture still fails on a head that is wrong
	// inside the snapshot, so the two specs above are not passing because
	// nothing is compared at all.
	It("still refuses a head that does not match the rows it was read with", func() {
		Expect(raw.Put(ctx, KeyInventoryHMAC, bytes.Repeat([]byte{0xa5}, 32), BlobPrivate)).To(Succeed())

		_, err := svc.InventoryEntries(ctx)
		Expect(err).To(MatchError(ErrInventoryTampered))
		Expect(svc.VerifyInventoryHMAC(ctx, svc.hmacKey)).To(MatchError(ErrInventoryTampered))
		rep, err := svc.InventoryIntegrityReport(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rep.Verifies).To(BeFalse())
	})
})

// expectVerificationBesidePeerAppends has writer append while reader verifies
// its inventory over and over, as two replicas of one store do, and fails if
// any verification reads the race as tampering. Before rows and head were read
// in one snapshot, a write committing between the two reads did exactly that.
//
// Both services must be over one store and already initialised with the same
// HMAC key. Shared by the backends that support more than one replica; each
// calls it from its own suite, since each needs its own store to stand up.
func expectVerificationBesidePeerAppends(reader, writer *StorageService) {
	GinkgoHelper()
	ctx := context.Background()
	const appends = 150

	before, err := reader.InventoryEntries(ctx)
	Expect(err).NotTo(HaveOccurred())
	start := len(before)

	done := make(chan error, 1)
	go func() {
		defer GinkgoRecover()
		for i := range appends {
			line := fmt.Sprintf("%X 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /peer-%d.example.com", 0x10000+i, i)
			if err := writer.AppendInventoryRecord(ctx, line, nil); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	var reads, tampered, midway int
	for running := true; running; {
		select {
		case err := <-done:
			Expect(err).NotTo(HaveOccurred(), "the peer's appends must succeed for the race to be exercised")
			running = false
		default:
		}
		entries, err := reader.InventoryEntries(ctx)
		reads++
		switch {
		case errors.Is(err, ErrInventoryTampered):
			tampered++
		default:
			Expect(err).NotTo(HaveOccurred())
			if n := len(entries); n > start && n < start+appends {
				midway++
			}
		}
	}
	Expect(tampered).To(BeZero(),
		"%d of %d verifications read a peer's append as tampering", tampered, reads)
	// The floor: without a read that landed while the peer was appending,
	// nothing above was exercised, and a backend that read rows and head
	// apart would pass as readily as one that does not.
	Expect(midway).To(BeNumerically(">", 0),
		"no verification overlapped the peer's appends (%d reads), so the race was not exercised", reads)
	Expect(reader.VerifyInventoryHMAC(ctx, reader.hmacKey)).To(Succeed(),
		"the store must verify once the peer has finished")
}

var _ = Describe("SQLBackend.EntriesWithHead", func() {
	It("returns the rows and the head the store holds", func() {
		ctx := context.Background()
		b := newSQLiteBackend()
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).To(Succeed())
		Expect(svc.InitHMAC(ctx)).To(Succeed())
		Expect(svc.AppendInventoryRecord(ctx,
			"0A 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /a.example.com", nil)).To(Succeed())

		entries, head, present, err := b.EntriesWithHead(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(present).To(BeTrue())
		Expect(entries).To(HaveLen(1))
		stored, err := b.Get(ctx, KeyInventoryHMAC)
		Expect(err).NotTo(HaveOccurred())
		Expect(head).To(Equal(stored))
	})

	It("reports a store with no head as having none", func() {
		ctx := context.Background()
		b := newSQLiteBackend()
		Expect(NewWithBackend(b, "").TouchInventory(ctx)).To(Succeed())

		_, head, present, err := b.EntriesWithHead(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(present).To(BeFalse())
		Expect(head).To(BeNil())
	})

	// A baseline over an empty chain stores the nil fold, which reads back
	// as an empty value. Present but empty is a baseline, not its absence,
	// as Get reports it.
	It("reports an empty stored head as present and empty, not absent", func() {
		ctx := context.Background()
		b := newSQLiteBackend()
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).To(Succeed())
		Expect(svc.InitHMAC(ctx)).To(Succeed())

		_, head, present, err := b.EntriesWithHead(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(present).To(BeTrue())
		Expect(head).NotTo(BeNil())
		Expect(head).To(BeEmpty())
	})
})
