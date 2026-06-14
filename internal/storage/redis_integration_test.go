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
			w := w
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := 0; i < perWriter; i++ {
					line := fmt.Sprintf("w%d-i%d\n", w, i)
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
				tok := fmt.Sprintf("w%d-i%d", w, i)
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
