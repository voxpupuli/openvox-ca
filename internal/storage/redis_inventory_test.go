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
	"path/filepath"
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

var _ = Describe("RedisInventoryAppendHeadGuard", func() {
	// The storm test above proves the end state is right, but it cannot prove
	// the head guard ever fired: if the two replicas' read→commit windows
	// happen not to overlap (a loaded or single-CPU runner), it passes having
	// exercised zero conflicts. These two drive the guard deterministically.
	It("retries past an append that advanced the head, chaining onto it", func() {
		ctx := context.Background()
		svc, b, cli, stop := newRedisInventoryService()
		defer stop()

		other := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")
		Expect(other.InitHMAC(ctx)).To(Succeed())

		// One interleaved append from a second replica, landing after our head
		// read and before our commit. The stored head is then no longer the
		// one our chain value was computed from, so the script must refuse it.
		var once sync.Once
		var attempts atomic.Int32
		b.appendHeadHook = func() {
			attempts.Add(1)
			once.Do(func() {
				Expect(other.AppendInventory(ctx,
					"0006 2024-01-06T00:00:00UTC 2029-01-06T00:00:00UTC /node6")).To(Succeed())
			})
		}

		Expect(svc.AppendInventory(ctx, "0007 2024-01-07T00:00:00UTC 2029-01-07T00:00:00UTC /node7")).To(Succeed())
		Expect(attempts.Load()).To(Equal(int32(2)), "the first attempt must have been refused and retried")

		// Both appends are present and the chain covers them in issuance
		// order — the retry re-read and chained onto the interloper rather
		// than overwriting its head.
		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the chain must verify after the retry")
		Expect(string(got)).To(HaveSuffix(
			"0006 2024-01-06T00:00:00UTC 2029-01-06T00:00:00UTC /node6\n" +
				"0007 2024-01-07T00:00:00UTC 2029-01-07T00:00:00UTC /node7\n"))
	})

	It("gives up with a named error when the head never stops moving", func() {
		ctx := context.Background()
		svc, b, cli, stop := newRedisInventoryService()
		defer stop()

		other := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")
		Expect(other.InitHMAC(ctx)).To(Succeed())

		var n atomic.Int32
		b.appendHeadHook = func() {
			i := n.Add(1)
			Expect(other.AppendInventory(ctx, fmt.Sprintf(
				"%04d 2024-02-01T00:00:00UTC 2029-02-01T00:00:00UTC /interloper%d", 1000+i, i))).To(Succeed())
		}

		err := svc.AppendInventory(ctx, "0008 2024-01-08T00:00:00UTC 2029-01-08T00:00:00UTC /node8")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("too many concurrent writers"))
		Expect(int(n.Load())).To(Equal(redisMaxRetries), "the retry loop is bounded")

		// Nothing of ours was written, and the chain the interlopers built is
		// intact — a refused append must leave no trace.
		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the chain must still verify")
		Expect(string(got)).NotTo(ContainSubstring("/node8"))
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

	It("prunes every entry, leaving a present-but-empty inventory", func() {
		ctx := context.Background()
		svc, _, cli, stop := newRedisInventoryService()
		defer stop()

		removed, err := svc.PruneInventory(ctx, func(InventoryEntry) bool { return false })
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(HaveLen(3))

		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(BeEmpty())
		Expect(hashFields(cli, invKey(redisInvSerialSub))).To(BeEmpty())
		Expect(hashFields(cli, invKey(redisInvSubjectSub))).To(BeEmpty())

		// The chain over zero entries is the empty head, which must still
		// verify — a stored empty payload and a computed nil compare equal —
		// and the inventory must read as present-but-empty, not absent.
		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory after a total prune")
		Expect(got).NotTo(BeNil())
		Expect(got).To(BeEmpty())

		Expect(svc.AppendInventory(ctx, "0005 2024-01-05T00:00:00UTC 2029-01-05T00:00:00UTC /node5")).To(Succeed())
		got, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the chain restarts cleanly from empty")
		Expect(string(got)).To(Equal("0005 2024-01-05T00:00:00UTC 2029-01-05T00:00:00UTC /node5\n"))
	})

	It("gives up without removing anything when the fence never stops moving", func() {
		ctx := context.Background()
		svc, b, cli, stop := newRedisInventoryService()
		defer stop()

		other := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")
		Expect(other.InitHMAC(ctx)).To(Succeed())

		// An append on every attempt, so the fence and the head have both
		// moved by the time each commit is tried.
		var n atomic.Int32
		b.pruneSnapshotHook = func() {
			i := n.Add(1)
			Expect(other.AppendInventory(ctx, fmt.Sprintf(
				"%04d 2024-03-01T00:00:00UTC 2029-03-01T00:00:00UTC /latecomer%d", 2000+i, i))).To(Succeed())
		}

		removed, err := svc.PruneInventory(ctx, keepNotSerial("0002"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("too many concurrent writers"))
		Expect(int(n.Load())).To(Equal(redisMaxRetries), "the retry loop is bounded")

		// The Redis half of the PruneEntries contract: the whole removal is
		// one atomic script, so a failed prune removes NOTHING and returns an
		// empty slice — unlike etcd, which may partially complete and must
		// report what it durably removed.
		Expect(removed).To(BeEmpty(), "a failed redis prune must not have removed anything")
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveKey("2"), "0002 must still be present")
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the chain must still verify")
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

	// The two //nolint:nilerr branches of convertLegacyEmptyHead: an empty
	// pre-decomposition inventory whose stored whole-blob head cannot be
	// verified, because the HMAC key is missing or malformed. Both deliberately
	// leave the head in place rather than dropping it — dropping an
	// unverifiable head would launder a tampered-away entry set into a clean
	// baseline — so the fail-closed claim is that startup succeeds and the
	// NEXT verification rejects the state. The sibling spec above proves that
	// for the mismatching-head branch; these prove it for the unverifiable
	// ones, which the comments only asserted in prose.
	It("leaves the head alone when the HMAC key is missing, failing closed later", func() {
		ctx := context.Background()
		cli, stop, key, _ := legacySetup(nil)
		defer stop()
		Expect(cli.Del(ctx, redisTestPrefix+":private:hmac_key").Err()).To(Succeed())

		b := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b.EnsureReady(ctx)).To(Succeed(), "an unverifiable head must not block startup")
		Expect(cli.Exists(ctx, invKey(redisInvHMACSub)).Val()).To(Equal(int64(1)),
			"the head must be left in place, not dropped unverified")

		Expect(NewWithBackend(b, "").VerifyInventoryHMAC(ctx, key)).To(MatchError(ErrInventoryTampered),
			"verification must reject the state the conversion declined to resolve")
	})

	It("leaves the head alone when the HMAC key is malformed, failing closed later", func() {
		ctx := context.Background()
		cli, stop, key, _ := legacySetup(nil)
		defer stop()
		Expect(cli.Set(ctx, redisTestPrefix+":private:hmac_key",
			encodeBlob(time.Now(), []byte("too-short")), 0).Err()).To(Succeed())

		b := newRawRedisBackend(cli, redisTestPrefix)
		Expect(b.EnsureReady(ctx)).To(Succeed(), "an unverifiable head must not block startup")
		Expect(cli.Exists(ctx, invKey(redisInvHMACSub)).Val()).To(Equal(int64(1)),
			"the head must be left in place, not dropped unverified")

		Expect(NewWithBackend(b, "").VerifyInventoryHMAC(ctx, key)).To(MatchError(ErrInventoryTampered),
			"verification must reject the state the conversion declined to resolve")
	})

	// redisDropHeadLua is the last compare-and-set in this file without a
	// conflict spec. Its guard matters in one narrow window: another replica
	// signing the first certificate — and so writing a chained head — between
	// this replica's read of the legacy head and its delete. Were the guard an
	// unconditional DEL, that live chained head would be dropped, and the next
	// verification would find nothing, log "No inventory HMAC found" and
	// silently adopt whatever it saw. That is the same laundering the two
	// specs above exist to prevent, in the concurrent case.
	It("refuses to drop a head that changed since it was read", func() {
		ctx := context.Background()
		cli, stop, _, _ := legacySetup(nil)
		defer stop()
		b := newRawRedisBackend(cli, redisTestPrefix)

		before, err := cli.Get(ctx, invKey(redisInvHMACSub)).Bytes()
		Expect(err).NotTo(HaveOccurred())

		// Present the script a payload that is not the stored one, which is
		// exactly what a caller holding a stale read would present.
		status, _, err := b.runInvScript(ctx, b.invDropHeadScript, "not-the-stored-payload")
		Expect(err).NotTo(HaveOccurred())
		Expect(status).To(Equal(redisResultConflict))

		after, err := cli.Get(ctx, invKey(redisInvHMACSub)).Bytes()
		Expect(err).NotTo(HaveOccurred(), "the head must survive a refused drop")
		Expect(after).To(Equal(before))
	})

	It("lets two replicas decompose concurrently without double-importing", func() {
		ctx := context.Background()
		cli, stop, key, blob := legacySetup(sampleInventoryLines)
		defer stop()

		// Counting committed import steps is the assertion, not the end state:
		// a second replica that re-wiped and re-imported the same blob would
		// leave exactly the same three entries, so an entry count alone would
		// stay green with the decompose lock removed. One import of a
		// three-line blob commits two steps — the wipe and a single batch.
		var steps atomic.Int32
		a := newRawRedisBackend(cli, redisTestPrefix)
		b := newRawRedisBackend(cli, redisTestPrefix)
		a.importBatchHook = func() { steps.Add(1) }
		b.importBatchHook = func() { steps.Add(1) }
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

		Expect(steps.Load()).To(Equal(int32(2)), "the lock must keep the second replica from re-importing")
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

	It("treats an entry pruned between the read and the write as a no-op", func() {
		ctx := context.Background()
		svc, b, cli, stop := newCertIndexRedis()
		defer stop()

		// The prune-during-revocation race: the entry exists when
		// mutateRecordBySerial reads it and is gone by the time the script
		// runs. Nothing serialises those across replicas, so the script's
		// "missing" status must be a silent no-op — matching the SQL
		// backend's zero-rows-updated — rather than an error surfaced to the
		// operator during a routine CRL cleanup.
		var once sync.Once
		b.mutateRecordHook = func() {
			once.Do(func() {
				Expect(cli.HDel(ctx, invKey(redisInvEntriesSub), "3").Err()).To(Succeed())
			})
		}

		Expect(svc.MarkCertRevoked(ctx, "0003", time.Now())).To(Succeed(),
			"a vanished entry must not surface as an error")
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).NotTo(HaveKey("3"),
			"the write must not resurrect the pruned entry")
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

	It("keeps a record coherent under concurrent index writers on one serial", func() {
		ctx := context.Background()
		svc, _, cli, stop := newCertIndexRedis()
		defer stop()
		other := NewWithBackend(newRedisBackend(cli, redisTestPrefix), "")

		// This is a coherence and race-detector exercise, not a test of the
		// compare-and-set: SetProjection overwrites the projection wholesale,
		// and Redis never tears a whole-value HSET, so removing the CAS from
		// redisSetRecordLua would leave this spec green. The CAS is covered
		// deterministically by the conflict spec above, which needs it to
		// preserve a concurrent writer's change. What this one asserts is that
		// concurrent writers across two replicas leave a record that still
		// decodes, carries a value some writer actually sent, and has its
		// canonical (chained) fields untouched.
		want := make(map[string]bool)
		var mu sync.Mutex
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
				for n := range 10 {
					fp := fmt.Sprintf("w%d-%d", i, n)
					mu.Lock()
					want[fp] = true
					mu.Unlock()
					Expect(s.SetCertProjection(ctx, "0003", CertProjection{Fingerprint: fp})).To(Succeed())
				}
			}()
		}
		wg.Wait()

		recs, _, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(want).To(HaveKey(recs[0].Fingerprint),
			"the surviving projection must be a value some writer actually sent")

		// The canonical fields are not the index's to touch, and the chain
		// covers only them — both must have come through untouched.
		Expect(recs[0].Serial).To(Equal("0003"))
		Expect(recs[0].Subject).To(Equal("node1"))
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
	})
})

// Mirrors EtcdInventoryDecodeCorruptKeyspace: decodeEntryFields gates every
// Redis inventory read (readInventorySnapshot, Entries, getInventory,
// Statuses), and Statuses does not verify the integrity chain — so a
// regression that skipped an undecodable field instead of erroring would
// silently under-report certificates rather than fail closed.
var _ = Describe("RedisInventoryDecodeCorruptKeyspace", func() {
	It("rejects a hash field whose name is not a sequence number, naming the field", func() {
		_, err := decodeEntryFields(map[string]string{"stray": "{}"})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("stray"))
	})

	It("rejects an entry with an undecodable value, naming the field", func() {
		_, err := decodeEntryFields(map[string]string{"1": "{not-json"})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`"1"`))
	})

	It("surfaces a corrupt field through both the verified and unverified reads", func() {
		ctx := context.Background()
		svc, b, cli, stop := newRedisInventoryService()
		defer stop()
		Expect(b.Put(ctx, CertKey("node1"), []byte("pem-node1"), BlobPublic)).To(Succeed())

		Expect(cli.HSet(ctx, invKey(redisInvEntriesSub), "4", "{not-json").Err()).To(Succeed())

		// ReadInventory verifies before it renders, so its error comes from
		// the chain fold. Asserting the field name (not merely that some error
		// occurred) is what distinguishes fail-loud from a regression that
		// substitutes a placeholder record: that would still fail the read,
		// but with ErrInventoryTampered rather than by naming the entry.
		_, err := svc.ReadInventory(ctx)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`entry "4"`))

		// CertStatuses does NOT verify the chain, so it is the path where a
		// dropped error check would silently under-report certificates to the
		// CRL and OCSP consumers. It must fail closed on its own account.
		_, _, err = svc.CertStatuses(ctx, "")
		Expect(err).To(HaveOccurred(), "Statuses must fail closed, not skip the corrupt entry")
		Expect(err.Error()).To(ContainSubstring(`entry "4"`))
	})
})

var _ = Describe("RedisInventoryAppendLineBudget", func() {
	It("refuses a direct AppendLine larger than one script's budget", func() {
		ctx := context.Background()
		_, b, cli, stop := newRedisInventoryService()
		defer stop()

		var buf strings.Builder
		for i := range redisImportBatch + 1 {
			fmt.Fprintf(&buf, "%06d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /bulk%d\n", 10000+i, i)
		}
		err := b.AppendLine(ctx, KeyInventory, []byte(buf.String()), BlobPrivate)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("exceeds the redis single-script budget"))
		Expect(hashFields(cli, invKey(redisInvEntriesSub))).To(HaveLen(len(sampleInventoryLines)),
			"a refused batch must write nothing")
	})
})

var _ = Describe("RedisMigrateFromFilesystem", func() {
	It("imports a filesystem CA and rebuilds the chain head for the decomposed inventory", func() {
		ctx := context.Background()
		_, cli, stop := newMiniredis()
		defer stop()

		src := New(GinkgoT().TempDir())
		Expect(src.EnsureDirs(ctx)).To(Succeed())
		Expect(src.SaveCACert(ctx, []byte("ca-cert-pem"))).To(Succeed())
		Expect(src.TouchInventory(ctx)).To(Succeed())
		Expect(src.InitHMAC(ctx)).To(Succeed())
		for _, line := range sampleInventoryLines {
			Expect(src.AppendInventory(ctx, line)).To(Succeed())
		}
		Expect(src.SaveCert(ctx, "node1", []byte("cert-pem"))).To(Succeed())

		// Migrate copies KeyInventory as text through the blob shim, so the
		// destination parses it back into hash fields and rebuilds the head
		// in its own scheme — the source's whole-blob HMAC cannot carry over.
		dstBackend := newRedisBackend(cli, redisTestPrefix)
		dst := NewWithBackend(dstBackend, filepath.Join(GinkgoT().TempDir(), "private"))
		_, err := MigrateService(ctx, src, dst, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "MigrateService")

		// InitHMAC verifies against the head MigrateService rebuilt over the
		// decomposed entries; a whole-blob HMAC left behind would fail here.
		Expect(dst.InitHMAC(ctx)).To(Succeed(), "InitHMAC on destination")

		srcInv, err := src.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		dstInv, err := dst.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(dstInv).To(Equal(srcInv), "migrated inventory must render identically")

		serial, err := dst.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal("0003"), "the subject index must be built during import")
	})
})
