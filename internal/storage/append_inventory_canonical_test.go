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
	"crypto/hmac"
	"crypto/sha256"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Issue #444: the structured append path chained the entry string as passed
// in, while every verification chains canonicalInventoryLine of the parsed
// record. parseInventoryEntry is lenient, so an entry that parsed but was not
// canonical was accepted on append and then reported as tampering on the next
// read. AppendInventory now refuses such entries on every backend.
var _ = Describe("AppendInventory canonical form", func() {
	type backend struct {
		name       string
		structured bool
		mk         func() *StorageService
	}
	// A slice rather than a map so the spec tree is built in the same order
	// every run.
	backends := []backend{
		{"sqlite", true, func() *StorageService {
			svc, _ := newInventoryService()
			return svc
		}},
		{"redis", true, func() *StorageService {
			svc, _, _, stop := newRedisInventoryService()
			DeferCleanup(stop)
			return svc
		}},
		{"filesystem", false, newFilesystemInventoryService},
	}

	const canonical = "0009 2024-01-09T00:00:00UTC 2029-01-09T00:00:00UTC /node9"

	for _, b := range backends {
		Context(b.name, func() {
			var (
				ctx     context.Context
				svc     *StorageService
				invPre  []byte
				headPre []byte
			)

			BeforeEach(func() {
				ctx = context.Background()
				svc = b.mk()
				var err error
				invPre, err = svc.ReadInventory(ctx)
				Expect(err).NotTo(HaveOccurred(), "ReadInventory before the append")
				headPre, err = svc.backend.Get(ctx, KeyInventoryHMAC)
				Expect(err).NotTo(HaveOccurred(), "reading the integrity head before the append")
			})

			DescribeTable("refuses an entry that parses but is not canonical, and leaves the inventory verifiable",
				func(entry string) {
					// Every case must parse, and must not already be canonical
					// under the grammar in force: an unparseable entry is
					// refused by the older malformed-entry check, and a
					// canonical one is not a case at all. Either would let
					// this spec pass, or fail, for the wrong reason.
					parsed, ok := parseInventoryEntry(entry)
					Expect(ok).To(BeTrue(), "fixture must parse, or it does not exercise the canonical check")
					Expect(canonicalInventoryLine(parsed)).NotTo(Equal(entry), "fixture must not be canonical")

					err := svc.AppendInventory(ctx, entry)
					Expect(err).To(MatchError(ContainSubstring("non-canonical inventory entry")))

					// Nothing was written: the integrity head is untouched and
					// the inventory still verifies to exactly what it held.
					head, err := svc.backend.Get(ctx, KeyInventoryHMAC)
					Expect(err).NotTo(HaveOccurred())
					Expect(head).To(Equal(headPre), "the integrity head must not move for a refused entry")
					inv, err := svc.ReadInventory(ctx)
					Expect(err).NotTo(HaveOccurred(), "the inventory must still verify after a refused append")
					Expect(inv).To(Equal(invPre))
				},
				Entry("a doubled space between fields",
					"0009  2024-01-09T00:00:00UTC 2029-01-09T00:00:00UTC /node9"),
				Entry("a tab between fields",
					"0009\t2024-01-09T00:00:00UTC 2029-01-09T00:00:00UTC /node9"),
				Entry("leading whitespace",
					" "+canonical),
				Entry("trailing whitespace",
					canonical+" "),
				// Tab-separated, so that no subject grammar can read it as
				// part of the subject and make the line canonical.
				Entry("a trailing field",
					canonical+"\textra"),
				Entry("a trailing newline",
					canonical+"\n"),
				Entry("an embedded newline carrying a second entry",
					canonical+"\n0010 2024-01-10T00:00:00UTC 2029-01-10T00:00:00UTC /node10"),
				Entry("a subject without its leading slash",
					"0009 2024-01-09T00:00:00UTC 2029-01-09T00:00:00UTC node9"),
			)

			It("accepts a canonical entry and still verifies", func() {
				before, err := svc.InventoryEntries(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(svc.AppendInventory(ctx, canonical)).To(Succeed())
				// InventoryEntries verifies before returning. Counted rather
				// than compared, because the rendered bytes and the serial's
				// form are the blob backend's own to choose.
				after, err := svc.InventoryEntries(ctx)
				Expect(err).NotTo(HaveOccurred(), "the inventory must verify after a canonical append")
				Expect(after).To(HaveLen(len(before) + 1))
			})

			// A guard on what the fix must preserve rather than a spec for
			// the fix, so it passes with and without it: for a canonical entry
			// the head is HMAC-SHA256 over exactly the bytes passed in, chained
			// from the previous head, as it was before #444. Computed here with
			// crypto/hmac directly, not chainInventoryMAC, so the bytes are
			// pinned rather than the helper. Any chain that verified before
			// the change has the same head after it.
			It("chains a canonical entry over exactly the bytes passed in", func() {
				if !b.structured {
					Skip("the blob backend has a whole-blob HMAC, not a chain")
				}
				Expect(svc.hmacKey).NotTo(BeEmpty(), "integrity must be enabled for there to be a chain")

				entry := FormatInventoryLine("0009",
					time.Date(2024, 1, 9, 0, 0, 0, 0, time.UTC),
					time.Date(2029, 1, 9, 0, 0, 0, 0, time.UTC),
					"node9")
				Expect(entry).To(Equal(canonical), "FormatInventoryLine output is the canonical form")
				Expect(svc.AppendInventory(ctx, entry)).To(Succeed())

				var want []byte
				for _, line := range append(append([]string{}, sampleInventoryLines...), entry) {
					mac := hmac.New(sha256.New, svc.hmacKey)
					mac.Write(want)
					mac.Write([]byte(line))
					want = mac.Sum(nil)
				}
				head, err := svc.backend.Get(ctx, KeyInventoryHMAC)
				Expect(err).NotTo(HaveOccurred())
				Expect(head).To(Equal(want))
			})
		})
	}
})
