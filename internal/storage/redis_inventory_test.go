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
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The decomposed Redis inventory (issue #139). miniredis implements Lua,
// hashes and MULTI/EXEC faithfully enough to exercise every script here in
// process, so unlike the etcd suite these are plain unit tests; the
// redis_integration suite re-runs the concurrency-critical ones against a real
// server.

const redisTestPrefix = "inv-test"

// newRawRedisBackend wires a backend to cli WITHOUT running EnsureReady, so a
// test can plant pre-decomposition state first.
func newRawRedisBackend(cli redis.UniversalClient, prefix string) *RedisBackend {
	return NewRedisBackendFromClient(cli, prefix, 5*time.Second, 5*time.Second)
}

// newRedisInventoryService returns a ready StorageService over a fresh
// miniredis, with the inventory touched, integrity initialised, and
// sampleInventoryLines appended. The backend and a stop func come back so
// tests can inspect the raw keys and add a second "replica".
func newRedisInventoryService() (*StorageService, *RedisBackend, redis.UniversalClient, func()) {
	ctx := context.Background()
	_, cli, stop := newMiniredis()
	b := newRedisBackend(cli, redisTestPrefix)
	svc := NewWithBackend(b, "")
	Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
	Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")
	for _, line := range sampleInventoryLines {
		Expect(svc.AppendInventory(ctx, line)).To(Succeed(), fmt.Sprintf("AppendInventory(%q)", line))
	}
	return svc, b, cli, stop
}

// invKey names one of the decomposed inventory keys under the test prefix.
func invKey(sub string) string { return redisTestPrefix + ":" + sub }

// hashFields returns the raw hash at key.
func hashFields(cli redis.UniversalClient, key string) map[string]string {
	out, err := cli.HGetAll(context.Background(), key).Result()
	Expect(err).NotTo(HaveOccurred(), "HGETALL "+key)
	return out
}

var _ = Describe("RedisInventoryStore", func() {
	It("is discovered through the InventoryStore and CertIndex probes", func() {
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, redisTestPrefix)

		store, ok := asInventoryStore(b)
		Expect(ok).To(BeTrue(), "RedisBackend must satisfy InventoryStore")
		Expect(store).To(BeIdenticalTo(b))
		idx, ok := asCertIndex(b)
		Expect(ok).To(BeTrue(), "RedisBackend must satisfy CertIndex")
		Expect(idx).To(BeIdenticalTo(b))
	})

	It("stores appends as hash fields and renders byte-identical inventory text", func() {
		ctx := context.Background()
		svc, _, cli, stop := newRedisInventoryService()
		defer stop()

		// The blob key is now only a presence marker: an mtime header and
		// nothing else. This is the whole point of the issue — a signing no
		// longer rewrites an ever-growing value.
		marker, err := cli.Get(ctx, invKey(redisInvDataSub)).Bytes()
		Expect(err).NotTo(HaveOccurred(), "the presence marker must exist")
		_, payload, err := decodeBlob(marker)
		Expect(err).NotTo(HaveOccurred())
		Expect(payload).To(BeEmpty(), "the marker must carry no inventory text")

		entries := hashFields(cli, invKey(redisInvEntriesSub))
		Expect(entries).To(HaveLen(len(sampleInventoryLines)), "one hash field per issuance")
		Expect(entries).To(HaveKey("1"))
		Expect(entries).To(HaveKey("3"))

		Expect(hashFields(cli, invKey(redisInvSerialSub))).To(Equal(map[string]string{
			"0001": "1", "0002": "2", "0003": "3",
		}), "by-serial maps each serial to its issuance sequence")
		Expect(hashFields(cli, invKey(redisInvSubjectSub))).To(Equal(map[string]string{
			"node1": "0003", "node2": "0002",
		}), "by-subject holds each subject's newest serial")
		Expect(cli.Get(ctx, invKey(redisInvSeqSub)).Val()).To(Equal("3"))

		// Rendering back through the blob shim must be byte-identical to what
		// the append-only blob held, or Migrate and the OCSP index build break.
		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory")
		Expect(string(got)).To(Equal(strings.Join(sampleInventoryLines, "\n") + "\n"))
	})

	It("returns the latest serial per subject and fs.ErrNotExist for unknown ones", func() {
		ctx := context.Background()
		svc, _, _, stop := newRedisInventoryService()
		defer stop()

		got, err := svc.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("0003"), "node1 was issued twice; the newest wins")

		got, err = svc.LatestSerialForSubject(ctx, "node2")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("0002"))

		_, err = svc.LatestSerialForSubject(ctx, "nobody")
		Expect(err).To(MatchError(fs.ErrNotExist))
	})

	It("reads a touched-but-empty inventory as present and empty, not absent", func() {
		ctx := context.Background()
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, redisTestPrefix)
		svc := NewWithBackend(b, "")

		_, err := b.Get(ctx, KeyInventory)
		Expect(err).To(MatchError(fs.ErrNotExist), "before TouchInventory the key is absent")

		Expect(svc.TouchInventory(ctx)).To(Succeed())
		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).NotTo(BeNil(), "a touched inventory reads as present…")
		Expect(got).To(BeEmpty(), "…and empty")

		ok, err := b.Exists(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
	})

	It("replaces and deletes the inventory through the Put/Delete shim", func() {
		ctx := context.Background()
		svc, b, cli, stop := newRedisInventoryService()
		defer stop()

		replacement := "0009 2025-01-01T00:00:00UTC 2030-01-01T00:00:00UTC /node9\n"
		Expect(b.Put(ctx, KeyInventory, []byte(replacement), BlobPrivate)).To(Succeed())

		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(replacement))
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(1), "the old entries are gone")
		Expect(hashFields(cli, invKey(redisInvSerialSub))).To(Equal(map[string]string{"0009": "1"}))
		Expect(hashFields(cli, invKey(redisInvSubjectSub))).To(Equal(map[string]string{"node9": "0009"}))

		// A replacement leaves the head for the caller to recompute; doing so
		// must produce a chain the verifier accepts.
		Expect(svc.RebuildInventoryHMAC(ctx)).To(Succeed())
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory verifies the head")

		Expect(b.Delete(ctx, KeyInventory)).To(Succeed())
		Expect(cli.Exists(ctx, invKey(redisInvEntriesSub)).Val()).To(BeZero())
		Expect(cli.Exists(ctx, invKey(redisInvSeqSub)).Val()).To(BeZero())
		Expect(b.Delete(ctx, KeyInventory)).To(MatchError(fs.ErrNotExist))
	})

	It("rejects a duplicate serial reissued by another replica", func() {
		ctx := context.Background()
		svc, _, cli, stop := newRedisInventoryService()
		defer stop()

		// A second backend on the same Redis is a second replica: the
		// duplicate-serial guard is server-side (HEXISTS in the append
		// script), so it holds across processes — the guarantee the blob path
		// only ever had within one process (#204).
		other := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")
		err := other.AppendInventory(ctx, "0001 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /impostor")
		Expect(err).To(MatchError(ErrDuplicateSerial))

		// And nothing was written: no entry, no sequence number consumed.
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(len(sampleInventoryLines)))
		Expect(cli.Get(ctx, invKey(redisInvSeqSub)).Val()).To(Equal("3"))
		Expect(hashFields(cli, invKey(redisInvSubjectSub))).NotTo(HaveKey("impostor"))
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the rejected append must not disturb the chain")
	})

	It("appends parsed rows for direct AppendLine calls and rejects bad input", func() {
		ctx := context.Background()
		_, b, cli, stop := newRedisInventoryService()
		defer stop()

		Expect(b.AppendLine(ctx, KeyInventory, []byte(
			"0011 2024-02-01T00:00:00UTC 2029-02-01T00:00:00UTC /node11\n"+
				"0012 2024-02-02T00:00:00UTC 2029-02-02T00:00:00UTC /node12\n"), BlobPrivate)).To(Succeed())
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(5))
		Expect(cli.Get(ctx, invKey(redisInvSeqSub)).Val()).To(Equal("5"))

		err := b.AppendLine(ctx, KeyInventory, []byte("too few fields\n"), BlobPrivate)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("malformed inventory line"))
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(5),
			"a malformed line must not be written")

		err = b.AppendLine(ctx, KeyInventory, []byte(
			"0013 2024-02-03T00:00:00UTC 2029-02-03T00:00:00UTC /node13\n"+
				"0011 2024-02-04T00:00:00UTC 2029-02-04T00:00:00UTC /node14\n"), BlobPrivate)
		Expect(err).To(MatchError(ErrDuplicateSerial))
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(5),
			"a batch containing a duplicate must insert none of its lines")
	})

	It("serves a not-yet-decomposed legacy blob verbatim before EnsureReady has run", func() {
		ctx := context.Background()
		_, cli, stop := newMiniredis()
		defer stop()

		legacy := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n"
		Expect(cli.Set(ctx, invKey(redisInvDataSub), encodeBlob(time.Now(), []byte(legacy)), 0).Err()).To(Succeed())

		b := newRawRedisBackend(cli, redisTestPrefix)
		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(legacy), "reads must stay correct before conversion runs")
	})
})

var _ = Describe("RedisInventoryConcurrentAppends", func() {
	// The regression test for the Redis half of #204. On the blob path,
	// AppendInventoryRecord read the whole inventory, appended a line, then
	// wrote a whole-blob HMAC computed from the bytes it read BEFORE its own
	// append; two replicas interleaving there left the stored HMAC covering a
	// blob that no longer existed, and the next verifying read — revocation,
	// OCSP, the renewal serial lookup — failed with ErrInventoryTampered. The
	// decomposed path advances the head atomically with the entry, so there is
	// no read-compute-write window to lose.
	It("loses no entries and keeps the chain verifiable across two replicas", func() {
		ctx := context.Background()
		_, cli, stop := newMiniredis()
		defer stop()

		a := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")
		Expect(a.TouchInventory(ctx)).To(Succeed())
		Expect(a.InitHMAC(ctx)).To(Succeed())
		b := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")
		Expect(b.InitHMAC(ctx)).To(Succeed())

		const writers = 4
		const perWriter = 16
		var wg sync.WaitGroup
		wg.Add(writers)
		for w := range writers {
			svc := a
			if w%2 == 1 {
				svc = b
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := range perWriter {
					n := w*perWriter + i
					line := fmt.Sprintf("%04d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node%d", n, n)
					Expect(svc.AppendInventory(ctx, line)).To(Succeed())
				}
			}()
		}
		wg.Wait()

		// ReadInventory verifies the head before returning, so a successful
		// read is the assertion: every append advanced the chain from the head
		// its own entry was chained onto.
		got, err := a.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the chain must verify after a concurrent append storm")
		Expect(strings.Count(string(got), "\n")).To(Equal(writers*perWriter), "no appends lost")

		// And from the other replica's view too, which is the read that failed
		// in CI: it recomputes the chain from storage rather than trusting its
		// own last write.
		_, err = b.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the second replica must see the same verifiable chain")
	})
})

var _ = Describe("RedisInventoryChainTamperDetection", func() {
	var (
		svc  *StorageService
		cli  redis.UniversalClient
		stop func()
		key  []byte
	)
	BeforeEach(func() {
		var err error
		svc, _, cli, stop = newRedisInventoryService()
		key, err = svc.EnsureHMACKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
	})
	AfterEach(func() { stop() })

	It("detects a modified entry", func() {
		ctx := context.Background()
		rec, err := encodeInventoryRecord(CertRecord{InventoryEntry: InventoryEntry{
			Serial: "0002", NotBefore: "2024-01-02T00:00:00UTC", NotAfter: "2029-01-02T00:00:00UTC",
			Subject: "attacker",
		}})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.HSet(ctx, invKey(redisInvEntriesSub), "2", string(rec)).Err()).To(Succeed())
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(MatchError(ErrInventoryTampered))
	})

	It("detects an inserted entry", func() {
		ctx := context.Background()
		rec, err := encodeInventoryRecord(CertRecord{InventoryEntry: InventoryEntry{
			Serial: "0099", NotBefore: "2024-01-09T00:00:00UTC", NotAfter: "2029-01-09T00:00:00UTC",
			Subject: "smuggled",
		}})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.HSet(ctx, invKey(redisInvEntriesSub), "4", string(rec)).Err()).To(Succeed())
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(MatchError(ErrInventoryTampered))
	})

	It("detects a deleted entry", func() {
		ctx := context.Background()
		Expect(cli.HDel(ctx, invKey(redisInvEntriesSub), "2").Err()).To(Succeed())
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(MatchError(ErrInventoryTampered))
	})
})

var _ = Describe("RedisInventoryPrune", func() {
	It("removes matching entries, rewrites the head, and repoints the subject index", func() {
		ctx := context.Background()
		svc, _, cli, stop := newRedisInventoryService()
		defer stop()

		// Drop node1's newest issuance: by-subject must fall back to its older
		// one rather than dangle at a serial that no longer exists.
		removed, err := svc.PruneInventory(ctx, keepNotSerial("0003"))
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(HaveLen(1))
		Expect(removed[0].Serial).To(Equal("0003"))

		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(2))
		Expect(hashFields(cli, invKey(redisInvSerialSub))).To(Equal(map[string]string{"0001": "1", "0002": "2"}))
		Expect(hashFields(cli, invKey(redisInvSubjectSub))).To(Equal(map[string]string{
			"node1": "0001", "node2": "0002",
		}), "node1 must fall back to its surviving issuance")
		Expect(cli.Get(ctx, invKey(redisInvSeqSub)).Val()).To(Equal("3"),
			"a prune allocates nothing, so the counter is a fence and stays put")

		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory verifies the rewritten head")
		Expect(string(got)).To(Equal(
			"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n" +
				"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2\n"))

		// A subsequent append must extend the rewritten chain cleanly.
		Expect(svc.AppendInventory(ctx, "0004 2024-01-04T00:00:00UTC 2029-01-04T00:00:00UTC /node3")).To(Succeed())
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
	})

	It("drops the by-subject field when a subject's every entry is pruned", func() {
		ctx := context.Background()
		svc, _, cli, stop := newRedisInventoryService()
		defer stop()

		removed, err := svc.PruneInventory(ctx, func(e InventoryEntry) bool { return e.Subject != "node2" })
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(HaveLen(1))
		Expect(hashFields(cli, invKey(redisInvSubjectSub))).To(Equal(map[string]string{"node1": "0003"}))
		Expect(hashFields(cli, invKey(redisInvSerialSub))).NotTo(HaveKey("0002"))

		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
	})

	It("leaves the head untouched when integrity is disabled", func() {
		ctx := context.Background()
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, redisTestPrefix)
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).To(Succeed())
		for _, line := range sampleInventoryLines {
			Expect(svc.AppendInventory(ctx, line)).To(Succeed())
		}
		Expect(cli.Exists(ctx, invKey(redisInvHMACSub)).Val()).To(BeZero(),
			"no HMAC key means no head is ever written")

		removed, err := svc.PruneInventory(ctx, keepNotSerial("0002"))
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(HaveLen(1))
		Expect(cli.Exists(ctx, invKey(redisInvHMACSub)).Val()).To(BeZero(),
			"a nil advanceHead must leave the stored head alone")
	})

	It("detects an interleaved append with integrity disabled, where no head guards it", func() {
		ctx := context.Background()
		_, cli, stop := newMiniredis()
		defer stop()
		b := newRedisBackend(cli, redisTestPrefix)
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).To(Succeed())
		for _, line := range sampleInventoryLines {
			Expect(svc.AppendInventory(ctx, line)).To(Succeed())
		}

		// With no HMAC key there is no head to guard on, so the
		// sequence-counter fence is the only thing standing between a prune's
		// stale snapshot and an append that landed after it. Without it the
		// prune would repoint node1's by-subject field at the older surviving
		// serial from its snapshot, silently undoing the newer issuance.
		other := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")
		var once sync.Once
		b.pruneSnapshotHook = func() {
			once.Do(func() {
				Expect(other.AppendInventory(ctx,
					"0008 2024-01-08T00:00:00UTC 2029-01-08T00:00:00UTC /node1")).To(Succeed())
			})
		}

		removed, err := svc.PruneInventory(ctx, keepNotSerial("0003"))
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(HaveLen(1))
		Expect(hashFields(cli, invKey(redisInvSubjectSub))["node1"]).To(Equal("0008"),
			"node1 must point at the interleaved issuance, not the snapshot's older one")
	})

	It("returns nothing and touches nothing when no entry matches", func() {
		ctx := context.Background()
		svc, _, cli, stop := newRedisInventoryService()
		defer stop()
		before := cli.Get(ctx, invKey(redisInvHMACSub)).Val()

		removed, err := svc.PruneInventory(ctx, func(InventoryEntry) bool { return true })
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(BeEmpty())
		Expect(cli.Get(ctx, invKey(redisInvHMACSub)).Val()).To(Equal(before))
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(3))
	})

	It("retries past an append that lands between the snapshot and the commit", func() {
		ctx := context.Background()
		svc, b, cli, stop := newRedisInventoryService()
		defer stop()

		// Interleave one append from a "second replica" after the prune has
		// read its snapshot. The sequence-counter fence (and the head guard)
		// must catch it, so the prune re-reads and produces a chain that
		// covers the newcomer too rather than one that silently omits it.
		other := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")
		Expect(other.InitHMAC(ctx)).To(Succeed())
		var once sync.Once
		b.importBatchHook = nil
		b.pruneSnapshotHook = func() {
			once.Do(func() {
				Expect(other.AppendInventory(ctx,
					"0007 2024-01-07T00:00:00UTC 2029-01-07T00:00:00UTC /node7")).To(Succeed())
			})
		}

		removed, err := svc.PruneInventory(ctx, keepNotSerial("0002"))
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(HaveLen(1))
		Expect(removed[0].Serial).To(Equal("0002"))

		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the rewritten chain must cover the interleaved append")
		Expect(string(got)).To(ContainSubstring("/node7"))
	})
})

var _ = Describe("RedisPrunePlan", func() {
	// planRedisPrune owns the per-call bound and the index repairs, and is
	// pure — testing it directly is the only practical way to cover a bound
	// that only bites above redisPruneMaxPerCall entries.
	mkRecords := func(n int) []indexedRecord {
		recs := make([]indexedRecord, n)
		for i := range n {
			recs[i] = indexedRecord{seq: uint64(i) + 1, rec: CertRecord{InventoryEntry: InventoryEntry{
				Serial:  fmt.Sprintf("%06d", i+1),
				Subject: fmt.Sprintf("node%d", i%3),
			}}}
		}
		return recs
	}

	It("bounds one call to redisPruneMaxPerCall, deferring the newest matches", func() {
		recs := mkRecords(redisPruneMaxPerCall + 25)
		plan := planRedisPrune(recs, func(InventoryEntry) bool { return false })

		Expect(plan.removed).To(HaveLen(redisPruneMaxPerCall))
		Expect(plan.removed[0].seq).To(Equal(uint64(1)), "the oldest matches go first")
		Expect(plan.survivors).To(HaveLen(25), "deferred matches are survivors for this round")
		Expect(plan.survivors[0].seq).To(Equal(uint64(redisPruneMaxPerCall + 1)))
		Expect(plan.entryFields).To(HaveLen(redisPruneMaxPerCall))
	})

	It("keeps a serial reserved while any record still bears it", func() {
		// Two records sharing a serial, as a converted legacy blob can hold.
		recs := []indexedRecord{
			{seq: 1, rec: CertRecord{InventoryEntry: InventoryEntry{Serial: "dup", Subject: "a"}}},
			{seq: 2, rec: CertRecord{InventoryEntry: InventoryEntry{Serial: "dup", Subject: "b"}}},
		}
		plan := planRedisPrune(recs, func(e InventoryEntry) bool { return e.Subject != "a" })
		Expect(plan.serialDrops).To(BeEmpty(),
			"one bearer survives, so the ambiguity sentinel must stay reserved")

		plan = planRedisPrune(recs, func(InventoryEntry) bool { return false })
		Expect(plan.serialDrops).To(Equal([]string{"dup"}),
			"the last bearer's removal releases the serial, once")
	})

	It("names each affected subject once, pointing at its newest survivor", func() {
		recs := mkRecords(9) // subjects node0/node1/node2, three issuances each
		plan := planRedisPrune(recs, func(e InventoryEntry) bool { return e.Serial > "000003" })
		Expect(plan.removed).To(HaveLen(3))
		Expect(plan.subjectSets).To(HaveLen(6), "three field/value pairs")
		Expect(plan.subjectDrops).To(BeEmpty())
		// node0's entries are seq 1,4,7; dropping seq 1 leaves seq 7 newest.
		pairs := map[string]string{}
		for i := 0; i < len(plan.subjectSets); i += 2 {
			pairs[plan.subjectSets[i]] = plan.subjectSets[i+1]
		}
		Expect(pairs["node0"]).To(Equal("000007"))
	})
})

var _ = Describe("RedisLegacyInventoryDecompose", func() {
	// legacySetup plants a pre-decomposition CA: a blob at inventory:data, an
	// HMAC key, and the whole-blob HMAC over that blob — exactly the state an
	// upgrade finds.
	legacySetup := func(lines []string) (redis.UniversalClient, func(), []byte, string) {
		ctx := context.Background()
		_, cli, stop := newMiniredis()
		blob := ""
		for _, l := range lines {
			blob += l + "\n"
		}
		key := make([]byte, hmacKeyLen)
		for i := range key {
			key[i] = byte(i)
		}
		Expect(cli.Set(ctx, redisTestPrefix+":private:hmac_key", encodeBlob(time.Now(), key), 0).Err()).To(Succeed())
		Expect(cli.Set(ctx, invKey(redisInvDataSub), encodeBlob(time.Now(), []byte(blob)), 0).Err()).To(Succeed())
		Expect(cli.Set(ctx, invKey(redisInvHMACSub),
			encodeBlob(time.Now(), wholeBlobInventoryMAC(key, []byte(blob))), 0).Err()).To(Succeed())
		return cli, stop, key, blob
	}

	It("imports a pre-decomposition blob on EnsureReady and re-baselines integrity", func() {
		ctx := context.Background()
		cli, stop, key, blob := legacySetup(sampleInventoryLines)
		defer stop()

		b := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b.EnsureReady(ctx)).To(Succeed())

		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(3))
		Expect(hashFields(cli, invKey(redisInvSerialSub))).To(Equal(map[string]string{
			"0001": "1", "0002": "2", "0003": "3",
		}))
		Expect(hashFields(cli, invKey(redisInvSubjectSub))).To(Equal(map[string]string{
			"node1": "0003", "node2": "0002",
		}))
		marker, err := cli.Get(ctx, invKey(redisInvDataSub)).Bytes()
		Expect(err).NotTo(HaveOccurred())
		_, payload, err := decodeBlob(marker)
		Expect(err).NotTo(HaveOccurred())
		Expect(payload).To(BeEmpty(), "the blob is retired to a bare marker")
		Expect(cli.Exists(ctx, invKey(redisInvHMACSub)).Val()).To(BeZero(),
			"the whole-blob head cannot carry over into the chained scheme")

		svc := NewWithBackend(b, "")
		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(blob), "the rendered text must be byte-identical to the blob")
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(Succeed(), "the baseline re-establishes")
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
	})

	It("is a cheap no-op on every start after the conversion", func() {
		ctx := context.Background()
		cli, stop, _, _ := legacySetup(sampleInventoryLines)
		defer stop()

		b := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b.EnsureReady(ctx)).To(Succeed())
		before := hashFields(cli, invKey(redisInvEntriesSub))

		var imports atomic.Int32
		b.importBatchHook = func() { imports.Add(1) }
		Expect(b.EnsureReady(ctx)).To(Succeed())
		Expect(imports.Load()).To(BeZero(), "a converted inventory must not be re-imported")
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(Equal(before))
	})

	It("resumes an interrupted import from the intact blob", func() {
		ctx := context.Background()
		lines := make([]string, 0, redisImportBatch+5)
		for i := range redisImportBatch + 5 {
			lines = append(lines, fmt.Sprintf(
				"%06d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node%d", i+1, i))
		}
		cli, stop, key, blob := legacySetup(lines)
		defer stop()

		// Abort after the wipe and the first batch have committed. The blob is
		// still authoritative — the marker is only emptied by the final step —
		// so the next start must redo the import from it.
		b := newRawRedisBackend(cli, redisTestPrefix)
		var n atomic.Int32
		abort := errors.New("simulated interruption")
		func() {
			defer func() {
				r := recover()
				Expect(r).To(Equal(abort))
			}()
			b.importBatchHook = func() {
				if n.Add(1) == 2 {
					panic(abort)
				}
			}
			_ = b.EnsureReady(ctx)
		}()

		partial := hashFields(cli, invKey(redisInvEntriesSub))
		Expect(len(partial)).To(BeNumerically("<", len(lines)), "the import really was interrupted")
		marker, err := cli.Get(ctx, invKey(redisInvDataSub)).Bytes()
		Expect(err).NotTo(HaveOccurred())
		_, payload, err := decodeBlob(marker)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(payload)).To(Equal(blob), "the blob stays authoritative until the final step")

		b2 := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b2.EnsureReady(ctx)).To(Succeed())
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(len(lines)))
		svc := NewWithBackend(b2, "")
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(Succeed())
	})

	It("refuses to decompose when the blob and existing entries contradict each other", func() {
		ctx := context.Background()
		cli, stop, _, _ := legacySetup(sampleInventoryLines)
		defer stop()

		// Entries that are not the import-written prefix of the blob: a
		// mixed-version deployment wrote both forms.
		rec, err := encodeInventoryRecord(CertRecord{InventoryEntry: InventoryEntry{
			Serial: "9999", NotBefore: "2024-01-01T00:00:00UTC", NotAfter: "2029-01-01T00:00:00UTC",
			Subject: "elsewhere",
		}})
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.HSet(ctx, invKey(redisInvEntriesSub), "1", string(rec)).Err()).To(Succeed())

		b := newRawRedisBackend(cli, redisTestPrefix)
		err = b.EnsureReady(ctx)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Refusing to guess"))
	})

	It("fails startup when the legacy blob does not match its stored HMAC", func() {
		ctx := context.Background()
		cli, stop, _, _ := legacySetup(sampleInventoryLines)
		defer stop()

		tampered := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /attacker\n"
		Expect(cli.Set(ctx, invKey(redisInvDataSub), encodeBlob(time.Now(), []byte(tampered)), 0).Err()).To(Succeed())

		b := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b.EnsureReady(ctx)).To(MatchError(ErrInventoryTampered))
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(BeEmpty(), "nothing may be imported")
	})

	It("fails startup when the HMAC key is missing or malformed rather than importing unverified", func() {
		ctx := context.Background()
		cli, stop, _, _ := legacySetup(sampleInventoryLines)
		defer stop()

		Expect(cli.Del(ctx, redisTestPrefix+":private:hmac_key").Err()).To(Succeed())
		b := newRawRedisBackend(cli, redisTestPrefix)
		err := b.EnsureReady(ctx)
		Expect(err).To(MatchError(ErrInventoryTampered))
		Expect(err.Error()).To(ContainSubstring("no HMAC key to verify it with"))

		Expect(cli.Set(ctx, redisTestPrefix+":private:hmac_key", encodeBlob(time.Now(), []byte("short")), 0).Err()).To(Succeed())
		err = b.EnsureReady(ctx)
		Expect(err).To(MatchError(ErrInventoryTampered))
		Expect(err.Error()).To(ContainSubstring("unreadable or malformed"))
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(BeEmpty())
	})

	It("fails startup on a malformed legacy line, leaving the blob intact", func() {
		ctx := context.Background()
		_, cli, stop := newMiniredis()
		defer stop()
		blob := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\nrubbish\n"
		Expect(cli.Set(ctx, invKey(redisInvDataSub), encodeBlob(time.Now(), []byte(blob)), 0).Err()).To(Succeed())

		b := newRawRedisBackend(cli, redisTestPrefix)
		err := b.EnsureReady(ctx)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("malformed inventory line"))
		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(blob), "the blob must survive a refused conversion")
	})

	It("tolerates duplicate serials in the legacy blob, refusing index writes for them", func() {
		ctx := context.Background()
		lines := []string{
			"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1",
			"0001 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2",
			"0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node3",
		}
		cli, stop, key, blob := legacySetup(lines)
		defer stop()

		b := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b.EnsureReady(ctx)).To(Succeed(), "a duplicated serial must not brick startup")

		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(3), "every line is imported verbatim")
		Expect(hashFields(cli, invKey(redisInvSerialSub))).To(Equal(map[string]string{
			"0001": serialAmbiguous, "0003": "3",
		}))
		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(blob))

		svc := NewWithBackend(b, "")
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(Succeed())
		for _, subject := range []string{"node1", "node2", "node3"} {
			Expect(b.Put(ctx, CertKey(subject), []byte("pem-"+subject), BlobPublic)).To(Succeed())
		}

		// The serial stays reserved against reissue…
		Expect(svc.AppendInventory(ctx, "0001 2025-01-01T00:00:00UTC 2030-01-01T00:00:00UTC /node9")).
			To(MatchError(ErrDuplicateSerial))

		// …but index writes for it are explicit no-ops rather than landing on
		// an arbitrary bearer, and Statuses reports the bearers as unknown so
		// readers consult the CRL instead.
		Expect(svc.MarkCertRevoked(ctx, "0001", time.Now())).To(Succeed())
		Expect(svc.SetCertProjection(ctx, "0001", CertProjection{Fingerprint: "aa:bb"})).To(Succeed())
		recs, ok, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(recs).To(HaveLen(3))
		bySubject := map[string]CertRecord{}
		for _, r := range recs {
			bySubject[r.Subject] = r
		}
		Expect(bySubject["node1"].State).To(Equal(CertStateUnknown))
		Expect(bySubject["node1"].Fingerprint).To(BeEmpty(), "the projection write was refused")
		Expect(bySubject["node2"].State).To(Equal(CertStateUnknown))
		Expect(bySubject["node3"].State).To(Equal(CertStateSigned), "the unique serial is unaffected")
	})

	It("removes the stale whole-blob head when upgrading a CA whose inventory is empty", func() {
		ctx := context.Background()
		cli, stop, key, _ := legacySetup(nil)
		defer stop()
		// legacySetup with no lines leaves an empty blob plus the whole-blob
		// MAC over it — what CA bootstrap writes before the first issuance.
		Expect(cli.Exists(ctx, invKey(redisInvHMACSub)).Val()).To(Equal(int64(1)))

		b := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b.EnsureReady(ctx)).To(Succeed())
		Expect(cli.Exists(ctx, invKey(redisInvHMACSub)).Val()).To(BeZero(),
			"no import would ever have dropped it, so EnsureReady must")

		svc := NewWithBackend(b, "")
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(Succeed(), "the chained baseline re-establishes cleanly")
	})

	It("leaves an unverifiable head over an empty inventory for verification to fail closed", func() {
		ctx := context.Background()
		cli, stop, key, _ := legacySetup(nil)
		defer stop()
		// A head that is NOT the whole-blob MAC of an empty inventory is
		// indistinguishable from the residue of a decomposed inventory whose
		// entries were tampered away; deleting it would silently accept that.
		Expect(cli.Set(ctx, invKey(redisInvHMACSub), encodeBlob(time.Now(), []byte("not-the-empty-mac")), 0).Err()).To(Succeed())

		b := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b.EnsureReady(ctx)).To(Succeed())
		Expect(cli.Exists(ctx, invKey(redisInvHMACSub)).Val()).To(Equal(int64(1)))

		svc := NewWithBackend(b, "")
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(MatchError(ErrInventoryTampered))
	})

	It("lets two replicas decompose concurrently without double-importing", func() {
		ctx := context.Background()
		cli, stop, key, blob := legacySetup(sampleInventoryLines)
		defer stop()

		a := newRawRedisBackend(cli, redisTestPrefix)
		b := newRawRedisBackend(cli, redisTestPrefix)
		var wg sync.WaitGroup
		wg.Add(2)
		for _, backend := range []*RedisBackend{a, b} {
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				Expect(backend.EnsureReady(ctx)).To(Succeed())
			}()
		}
		wg.Wait()

		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(3), "imported exactly once")
		got, err := a.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(blob))
		Expect(NewWithBackend(a, "").VerifyInventoryHMAC(ctx, key)).To(Succeed())
	})

	It("restarts the import when a legacy writer touches the blob mid-import", func() {
		ctx := context.Background()
		lines := make([]string, 0, redisImportBatch+5)
		for i := range redisImportBatch + 5 {
			lines = append(lines, fmt.Sprintf(
				"%06d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node%d", i+1, i))
		}
		cli, stop, key, blob := legacySetup(lines)
		defer stop()

		// A not-yet-upgraded replica appends to the blob after the import has
		// read it. The marker guard must catch that and restart from the new
		// blob rather than import a snapshot that is already stale.
		// The blob is two batches' worth, so an import commits three steps:
		// the wipe, then batch 1, then batch 2. Interfering after step 2 lets
		// the assertion below distinguish the batch guard from the final one:
		// the batch guard aborts at step 3, so the first attempt commits two
		// steps and the (clean) retry commits three. Were only the final guard
		// live, the first attempt would import every stale record first and
		// six steps would be committed in total.
		extra := "999999 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /latecomer\n"
		b := newRawRedisBackend(cli, redisTestPrefix)
		var steps atomic.Int32
		b.importBatchHook = func() {
			if steps.Add(1) != 2 {
				return
			}
			updated := blob + extra
			Expect(cli.Set(ctx, invKey(redisInvDataSub), encodeBlob(time.Now(), []byte(updated)), 0).Err()).To(Succeed())
			Expect(cli.Set(ctx, invKey(redisInvHMACSub),
				encodeBlob(time.Now(), wholeBlobInventoryMAC(key, []byte(updated))), 0).Err()).To(Succeed())
		}
		Expect(b.EnsureReady(ctx)).To(Succeed())
		Expect(steps.Load()).To(Equal(int32(5)),
			"the import must abort at the batch after the interfering write, not run to completion first")

		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(len(lines)+1),
			"the restarted import must include the latecomer")
		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(blob + extra))
	})
})

var _ = Describe("RedisCertIndex", func() {
	// newCertIndexRedis returns a service with three issuances (node1 twice)
	// and stored cert blobs, the state Statuses joins against.
	newCertIndexRedis := func() (*StorageService, *RedisBackend, redis.UniversalClient, func()) {
		ctx := context.Background()
		svc, b, cli, stop := newRedisInventoryService()
		for _, subject := range []string{"node1", "node2"} {
			Expect(b.Put(ctx, CertKey(subject), []byte("pem-"+subject), BlobPublic)).To(Succeed())
		}
		return svc, b, cli, stop
	}

	It("serves the latest issuance per subject, gated on stored certs", func() {
		ctx := context.Background()
		svc, b, _, stop := newCertIndexRedis()
		defer stop()

		recs, ok, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue(), "the Redis backend must serve the index")
		Expect(recs).To(HaveLen(2))
		Expect(recs[0].Subject).To(Equal("node1"))
		Expect(recs[0].Serial).To(Equal("0003"), "node1's newest issuance wins")
		Expect(recs[1].Subject).To(Equal("node2"))

		// Removing the stored PEM removes the subject from the report even
		// though its historical inventory entries remain.
		Expect(b.Delete(ctx, CertKey("node2"))).To(Succeed())
		recs, _, err = svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs).To(HaveLen(1))
		Expect(recs[0].Subject).To(Equal("node1"))
	})

	It("projects revocation idempotently, partitions by state, and clears again", func() {
		ctx := context.Background()
		svc, _, _, stop := newCertIndexRedis()
		defer stop()

		at := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
		Expect(svc.MarkCertRevoked(ctx, "0003", at)).To(Succeed())
		Expect(svc.MarkCertRevoked(ctx, "0003", at.Add(48*time.Hour))).To(Succeed())

		revoked, _, err := svc.CertStatuses(ctx, CertStateRevoked)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(HaveLen(1))
		Expect(revoked[0].Subject).To(Equal("node1"))
		Expect(revoked[0].RevokedAt).NotTo(BeNil())
		Expect(*revoked[0].RevokedAt).To(BeTemporally("~", at, time.Second),
			"re-marking keeps the original revocation time")

		signed, _, err := svc.CertStatuses(ctx, CertStateSigned)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(HaveLen(1))
		Expect(signed[0].Subject).To(Equal("node2"))

		Expect(svc.ClearCertRevoked(ctx, "0003")).To(Succeed())
		signed, _, err = svc.CertStatuses(ctx, CertStateSigned)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(HaveLen(2))
	})

	It("backfills the projection for a projection-less record", func() {
		ctx := context.Background()
		svc, _, _, stop := newCertIndexRedis()
		defer stop()

		proj := CertProjection{
			Fingerprint:    "aa:bb:cc",
			DNSAltNames:    []string{"node1", "node1.example.com"},
			AuthExtensions: map[string]string{"pp_auth_role": "webserver"},
		}
		Expect(svc.SetCertProjection(ctx, "0003", proj)).To(Succeed())

		recs, _, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs[0].Fingerprint).To(Equal(proj.Fingerprint))
		Expect(recs[0].DNSAltNames).To(Equal(proj.DNSAltNames))
		Expect(recs[0].AuthExtensions).To(Equal(proj.AuthExtensions))
	})

	It("keeps the integrity chain untouched by index writes", func() {
		ctx := context.Background()
		svc, _, cli, stop := newCertIndexRedis()
		defer stop()
		before := cli.Get(ctx, invKey(redisInvHMACSub)).Val()

		Expect(svc.MarkCertRevoked(ctx, "0003", time.Now())).To(Succeed())
		Expect(svc.SetCertProjection(ctx, "0001", CertProjection{Fingerprint: "dd:ee"})).To(Succeed())

		Expect(cli.Get(ctx, invKey(redisInvHMACSub)).Val()).To(Equal(before),
			"only the canonical fields are chained, and index writes never touch them")
		_, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
	})

	It("treats unknown serials and dangling pointers as no-ops", func() {
		ctx := context.Background()
		svc, _, cli, stop := newCertIndexRedis()
		defer stop()

		Expect(svc.MarkCertRevoked(ctx, "does-not-exist", time.Now())).To(Succeed())
		Expect(svc.SetCertProjection(ctx, "does-not-exist", CertProjection{Fingerprint: "x"})).To(Succeed())
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(3))

		// A by-serial field pointing at an entry that no longer exists must
		// not resurrect it, matching the SQL backend's zero-rows-updated.
		Expect(cli.HSet(ctx, invKey(redisInvSerialSub), "0404", "404").Err()).To(Succeed())
		Expect(svc.MarkCertRevoked(ctx, "0404", time.Now())).To(Succeed())
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(3))
	})

	It("retries an index write once past a conflict, and errors when conflicts never stop", func() {
		ctx := context.Background()
		svc, b, cli, stop := newCertIndexRedis()
		defer stop()

		// One injected conflict: rewrite the entry between the read and the
		// guarded commit, so the first attempt's compare-and-set fails.
		var once sync.Once
		b.mutateRecordHook = func() {
			once.Do(func() {
				rec, err := decodeInventoryRecord([]byte(cli.HGet(ctx, invKey(redisInvEntriesSub), "3").Val()))
				Expect(err).NotTo(HaveOccurred())
				rec.Fingerprint = "interloper"
				val, err := encodeInventoryRecord(rec)
				Expect(err).NotTo(HaveOccurred())
				Expect(cli.HSet(ctx, invKey(redisInvEntriesSub), "3", string(val)).Err()).To(Succeed())
			})
		}
		at := time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
		Expect(svc.MarkCertRevoked(ctx, "0003", at)).To(Succeed())

		recs, _, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs[0].State).To(Equal(CertStateRevoked), "the retried write must land")
		Expect(recs[0].Fingerprint).To(Equal("interloper"), "on top of the conflicting write, not over it")

		// Conflicts that never stop must be reported, not spun on forever.
		var n atomic.Int32
		b.mutateRecordHook = func() {
			i := n.Add(1)
			Expect(cli.HSet(ctx, invKey(redisInvEntriesSub), "2",
				fmt.Sprintf(`{"serial":"0002","not_before":"2024-01-02T00:00:00UTC","not_after":"2029-01-02T00:00:00UTC","subject":"node2","fingerprint":"%d"}`, i)).
				Err()).To(Succeed())
		}
		err = svc.SetCertProjection(ctx, "0002", CertProjection{Fingerprint: "never-lands"})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("too many concurrent writers"))
		Expect(int(n.Load())).To(Equal(redisMaxRetries), "the retry loop is bounded")
	})

	It("serialises concurrent index writers on one serial", func() {
		ctx := context.Background()
		svc, _, cli, stop := newCertIndexRedis()
		defer stop()
		other := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")

		var wg sync.WaitGroup
		wg.Add(4)
		for w := range 4 {
			s, i := svc, w
			if w%2 == 1 {
				s = other
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for range 10 {
					Expect(s.SetCertProjection(ctx, "0003",
						CertProjection{Fingerprint: "w" + strconv.Itoa(i)})).To(Succeed())
				}
			}()
		}
		wg.Wait()

		// Whichever writer landed last, the record must still decode and the
		// chain must still verify: no write may have been torn or lost.
		recs, _, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs[0].Fingerprint).To(HavePrefix("w"))
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
	})
})
