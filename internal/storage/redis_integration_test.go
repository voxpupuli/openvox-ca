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

//go:build redis_integration

package storage

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/redis/go-redis/v9"
)

// redisAddrFromEnv returns the Redis/Valkey address to use for integration
// tests, or skips the test if none is configured.
func redisAddrFromEnv() string {
	addr := os.Getenv("PUPPET_CA_TEST_REDIS_ADDR")
	if addr == "" {
		Skip("set PUPPET_CA_TEST_REDIS_ADDR=host:port to run redis integration tests")
	}
	return addr
}

// newIntegrationBackend connects to a real Redis/Valkey and returns a
// backend whose key prefix is unique to this test so parallel runs don't
// stomp on each other. Registers a cleanup that FLUSHDBs the prefix.
func newIntegrationBackend(prefixSuffix string) *RedisBackend {
	addr := redisAddrFromEnv()
	prefix := fmt.Sprintf("openvox-ca-test:%s:%d", prefixSuffix, time.Now().UnixNano())
	cfg := RedisConfig{
		Addrs:     []string{addr},
		KeyPrefix: prefix,
		LockTTL:   10 * time.Second,
	}
	b, err := NewRedisBackend(cfg)
	Expect(err).NotTo(HaveOccurred(), "NewRedisBackend")
	Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")
	DeferCleanup(func() {
		// Best-effort: drop every key under our prefix.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cli := redis.NewClient(&redis.Options{Addr: addr})
		defer cli.Close()
		iter := cli.Scan(ctx, 0, prefix+":*", 1000).Iterator()
		var keys []string
		for iter.Next(ctx) {
			keys = append(keys, iter.Val())
		}
		if len(keys) > 0 {
			_ = cli.Del(ctx, keys...).Err()
		}
		_ = b.Close()
	})
	return b
}

var _ = Describe("RedisIntegrationPutGetDelete", func() {
	It("puts, gets, and deletes blobs", func() {
		b := newIntegrationBackend("putgetdelete")
		ctx := context.Background()

		_, err := b.Get(ctx, KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Get on missing key: err = %v, want fs.ErrNotExist", err)
		payload := []byte("pem-data")
		Expect(b.Put(ctx, KeyCACert, payload, BlobPublic)).To(Succeed(), "Put")
		got, err := b.Get(ctx, KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "Get")
		Expect(got).To(Equal(payload), "Get returned %q, want %q", got, payload)
		Expect(b.Delete(ctx, KeyCACert)).To(Succeed(), "Delete")
		err = b.Delete(ctx, KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Delete on missing: err = %v, want fs.ErrNotExist", err)
	})
})

var _ = Describe("RedisIntegrationListCSR", func() {
	It("lists CSR keys by prefix", func() {
		b := newIntegrationBackend("list")
		ctx := context.Background()
		subjects := []string{"a.example", "b.example", "c.example"}
		for _, s := range subjects {
			Expect(b.Put(ctx, CSRKey(s), []byte("csr"), BlobPublic)).To(Succeed(), "Put")
		}
		csrs, err := b.List(ctx, csrPrefix)
		Expect(err).NotTo(HaveOccurred(), "List")
		sort.Strings(csrs)
		want := []string{CSRKey("a.example"), CSRKey("b.example"), CSRKey("c.example")}
		Expect(fmt.Sprint(csrs)).To(Equal(fmt.Sprint(want)), "List = %v, want %v", csrs, want)
	})
})

var _ = Describe("RedisIntegrationAppendLineConcurrent", func() {
	// Since the inventory decomposition (issue #139) this exercises
	// appendInventoryLines against a real server's Lua, not the blob append
	// script, so the lines must be well-formed inventory entries with distinct
	// serials — a duplicate would now be rejected rather than appended.
	It("does not lose lines under concurrent appends from two replicas", func() {
		// Two backends sharing a Redis → simulates two replicas.
		a := newIntegrationBackend("append-a")
		b := newIntegrationBackend("append-b")
		// Rebase both on the same prefix so they hit the same physical key.
		b.prefix = a.prefix

		const writers = 4
		const perWriter = 25
		var wg sync.WaitGroup
		wg.Add(writers)
		for w := 0; w < writers; w++ {
			backend := a
			if w%2 == 1 {
				backend = b
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := 0; i < perWriter; i++ {
					line := fmt.Sprintf("%04d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /w%d-i%d\n",
						w*perWriter+i, w, i)
					Expect(backend.AppendLine(context.Background(), KeyInventory, []byte(line), BlobPrivate)).To(Succeed(), "AppendLine")
				}
			}()
		}
		wg.Wait()

		data, err := a.Get(context.Background(), KeyInventory)
		Expect(err).NotTo(HaveOccurred(), "Get")
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
		Expect(lines).To(HaveLen(writers*perWriter), "got %d lines, want %d", len(lines), writers*perWriter)

		// Set-equality: a lost line masked by a duplicated one nets to the
		// same count, so assert every expected token appears exactly once.
		seen := make(map[string]int, writers*perWriter)
		for _, l := range lines {
			seen[string(l)]++
		}
		for w := 0; w < writers; w++ {
			for i := 0; i < perWriter; i++ {
				tok := fmt.Sprintf("%04d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /w%d-i%d",
					w*perWriter+i, w, i)
				Expect(seen[tok]).To(Equal(1), "token %q appeared %d times, want exactly 1", tok, seen[tok])
			}
		}
	})
})

var _ = Describe("RedisIntegrationAcquireLockSerialises", func() {
	It("serialises concurrent callers through the same lock", func() {
		a := newIntegrationBackend("lock-a")
		b := newIntegrationBackend("lock-b")
		b.prefix = a.prefix

		const workers = 6
		var inCritical atomic.Int32
		var maxConcurrent atomic.Int32
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			backend := a
			if i%2 == 1 {
				backend = b
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				ul, err := backend.AcquireLock(ctx, "crl")
				Expect(err).NotTo(HaveOccurred(), "AcquireLock")
				cur := inCritical.Add(1)
				for {
					m := maxConcurrent.Load()
					if cur <= m || maxConcurrent.CompareAndSwap(m, cur) {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
				inCritical.Add(-1)
				Expect(ul.Unlock()).To(Succeed(), "Unlock")
			}()
		}
		wg.Wait()
		Expect(maxConcurrent.Load()).To(Equal(int32(1)), "maxConcurrent = %d, want 1", maxConcurrent.Load())
	})
})

// The decomposed-inventory suite (issue #139) against a real server. The unit
// suite covers the same ground against miniredis; these re-run the parts whose
// correctness depends on the server rather than the Go side — real Redis Lua,
// real MULTI/EXEC, and genuine cross-process concurrency — where miniredis's
// gopher-lua interpreter and single-process fake could hide a divergence.

// newSharedIntegrationBackends returns n backends over one Redis prefix: n
// replicas of the same CA.
func newSharedIntegrationBackends(name string, n int) []*RedisBackend {
	out := make([]*RedisBackend, 0, n)
	for i := 0; i < n; i++ {
		b := newIntegrationBackend(fmt.Sprintf("%s-%d", name, i))
		if i > 0 {
			b.prefix = out[0].prefix
		}
		out = append(out, b)
	}
	return out
}

var _ = Describe("RedisIntegrationInventoryStore", func() {
	It("stores appends as hash fields and renders byte-identical inventory text", func() {
		ctx := context.Background()
		b := newIntegrationBackend("inv-store")
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
		Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")

		lines := []string{
			"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1",
			"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2",
			"0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1",
		}
		for _, l := range lines {
			Expect(svc.AppendInventory(ctx, l)).To(Succeed(), "AppendInventory")
		}

		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory")
		Expect(string(got)).To(Equal(strings.Join(lines, "\n")+"\n"), "rendered inventory")

		serial, err := svc.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred(), "LatestSerialForSubject")
		Expect(serial).To(Equal("0003"), "node1's newest issuance wins")

		// The blob key must be a bare presence marker now: this is the O(1)
		// append the issue is about.
		raw, err := b.client.Get(ctx, b.invPhys(redisInvDataSub)).Bytes()
		Expect(err).NotTo(HaveOccurred(), "GET marker")
		_, payload, err := decodeBlob(raw)
		Expect(err).NotTo(HaveOccurred(), "decodeBlob")
		Expect(payload).To(BeEmpty(), "the marker must carry no inventory text")
	})

	It("rejects a duplicate serial across two replicas", func() {
		ctx := context.Background()
		backends := newSharedIntegrationBackends("inv-dup", 2)
		a := NewWithBackend(backends[0], "")
		Expect(a.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
		Expect(a.InitHMAC(ctx)).To(Succeed(), "InitHMAC")
		other := NewWithBackend(backends[1], "")
		Expect(other.InitHMAC(ctx)).To(Succeed(), "InitHMAC")

		Expect(a.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
		// The guard lives in the server-side script, so it holds across
		// processes — the cross-replica guarantee the blob path never had.
		err := other.AppendInventory(ctx, "0001 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /impostor")
		Expect(err).To(MatchError(ErrDuplicateSerial), "cross-replica duplicate serial")

		got, err := a.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory after a rejected append")
		Expect(string(got)).NotTo(ContainSubstring("impostor"))
	})

	It("keeps the chain verifiable under a concurrent append storm across replicas", func() {
		// The regression test for the Redis half of issue #204: on the blob
		// path two replicas interleaving here left the stored whole-blob HMAC
		// covering a blob that no longer existed, and the next verifying read
		// failed with ErrInventoryTampered (it reproduced in ~15% of runs).
		ctx := context.Background()
		backends := newSharedIntegrationBackends("inv-storm", 2)
		a := NewWithBackend(backends[0], "")
		Expect(a.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
		Expect(a.InitHMAC(ctx)).To(Succeed(), "InitHMAC")
		b := NewWithBackend(backends[1], "")
		Expect(b.InitHMAC(ctx)).To(Succeed(), "InitHMAC")

		const writers = 8
		const perWriter = 8
		var wg sync.WaitGroup
		wg.Add(writers)
		for w := 0; w < writers; w++ {
			svc := a
			if w%2 == 1 {
				svc = b
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := 0; i < perWriter; i++ {
					n := w*perWriter + i
					Expect(svc.AppendInventory(ctx, fmt.Sprintf(
						"%04d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node%d", n, n))).To(Succeed())
				}
			}()
		}
		wg.Wait()

		// ReadInventory verifies the head before returning, from both replicas'
		// points of view: each recomputes the chain from storage rather than
		// trusting its own last write.
		for i, svc := range []*StorageService{a, b} {
			got, err := svc.ReadInventory(ctx)
			Expect(err).NotTo(HaveOccurred(), "ReadInventory from replica %d", i)
			Expect(strings.Count(string(got), "\n")).To(Equal(writers*perWriter), "no appends lost")
		}
	})

	It("prunes matching entries and rewrites the head in one atomic step", func() {
		ctx := context.Background()
		b := newIntegrationBackend("inv-prune")
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
		Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")
		for _, l := range []string{
			"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1",
			"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2",
			"0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1",
		} {
			Expect(svc.AppendInventory(ctx, l)).To(Succeed(), "AppendInventory")
		}

		removed, err := svc.PruneInventory(ctx, func(e InventoryEntry) bool { return e.Serial != "0003" })
		Expect(err).NotTo(HaveOccurred(), "PruneInventory")
		Expect(removed).To(HaveLen(1))
		Expect(removed[0].Serial).To(Equal("0003"))

		got, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory verifies the rewritten head")
		Expect(string(got)).To(Equal(
			"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n" +
				"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2\n"))

		serial, err := svc.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred(), "LatestSerialForSubject after prune")
		Expect(serial).To(Equal("0001"), "node1 falls back to its surviving issuance")

		Expect(svc.AppendInventory(ctx, "0004 2024-01-04T00:00:00UTC 2029-01-04T00:00:00UTC /node3")).To(Succeed())
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "the post-prune chain extends cleanly")
	})

	It("converts a pre-decomposition blob on EnsureReady and re-baselines integrity", func() {
		ctx := context.Background()
		b := newIntegrationBackend("inv-legacy")

		// Plant the state an upgrade finds: a text blob at the inventory key,
		// an HMAC key, and the whole-blob HMAC over that blob.
		blob := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n" +
			"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2\n"
		key := make([]byte, hmacKeyLen)
		for i := range key {
			key[i] = byte(i)
		}
		Expect(b.client.Set(ctx, b.prefix+":private:hmac_key", encodeBlob(time.Now(), key), 0).Err()).To(Succeed())
		Expect(b.client.Set(ctx, b.invPhys(redisInvDataSub), encodeBlob(time.Now(), []byte(blob)), 0).Err()).To(Succeed())
		Expect(b.client.Set(ctx, b.invPhys(redisInvHMACSub),
			encodeBlob(time.Now(), wholeBlobInventoryMAC(key, []byte(blob))), 0).Err()).To(Succeed())

		Expect(b.EnsureReady(ctx)).To(Succeed(), "EnsureReady must convert the blob")

		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred(), "Get(KeyInventory)")
		Expect(string(got)).To(Equal(blob), "the rendered text must be byte-identical to the blob")

		n, err := b.client.HLen(ctx, b.invPhys(redisInvEntriesSub)).Result()
		Expect(err).NotTo(HaveOccurred(), "HLEN entries")
		Expect(n).To(Equal(int64(2)), "one hash field per line")

		svc := NewWithBackend(b, "")
		Expect(svc.VerifyInventoryHMAC(ctx, key)).To(Succeed(), "the chained baseline re-establishes")
	})

	It("serves the certificate index from the decomposed entries", func() {
		ctx := context.Background()
		b := newIntegrationBackend("inv-index")
		svc := NewWithBackend(b, "")
		Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
		Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")

		proj := CertProjection{Fingerprint: "aa:bb:cc", DNSAltNames: []string{"node1.example"}}
		Expect(svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
		Expect(svc.AppendInventoryRecord(ctx, "0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1", &proj)).To(Succeed())
		Expect(svc.AppendInventory(ctx, "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2")).To(Succeed())
		for _, subject := range []string{"node1", "node2"} {
			Expect(b.Put(ctx, CertKey(subject), []byte("pem-"+subject), BlobPublic)).To(Succeed())
		}

		recs, ok, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred(), "CertStatuses")
		Expect(ok).To(BeTrue(), "the Redis backend must serve the index")
		Expect(recs).To(HaveLen(2), "one record per subject, latest issuance only")
		Expect(recs[0].Subject).To(Equal("node1"))
		Expect(recs[0].Serial).To(Equal("0003"))
		Expect(recs[0].Fingerprint).To(Equal(proj.Fingerprint))

		at := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
		Expect(svc.MarkCertRevoked(ctx, "0003", at)).To(Succeed(), "MarkCertRevoked")
		revoked, _, err := svc.CertStatuses(ctx, CertStateRevoked)
		Expect(err).NotTo(HaveOccurred(), "CertStatuses(revoked)")
		Expect(revoked).To(HaveLen(1))
		Expect(revoked[0].Subject).To(Equal("node1"))

		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "index writes must leave the chain untouched")
	})
})
