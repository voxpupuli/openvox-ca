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

//go:build redis_integration

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisAddrFromEnv returns the Redis/Valkey address to use for integration
// tests, or skips the test if none is configured.
func redisAddrFromEnv(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("PUPPET_CA_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set PUPPET_CA_TEST_REDIS_ADDR=host:port to run redis integration tests")
	}
	return addr
}

// newIntegrationBackend connects to a real Redis/Valkey and returns a
// backend whose key prefix is unique to this test so parallel runs don't
// stomp on each other. Registers a cleanup that FLUSHDBs the prefix.
func newIntegrationBackend(t *testing.T, prefixSuffix string) *RedisBackend {
	t.Helper()
	addr := redisAddrFromEnv(t)
	prefix := fmt.Sprintf("puppet-ca-test:%s:%d", prefixSuffix, time.Now().UnixNano())
	cfg := RedisConfig{
		Addrs:     []string{addr},
		KeyPrefix: prefix,
		LockTTL:   10 * time.Second,
	}
	b, err := NewRedisBackend(cfg)
	if err != nil {
		t.Fatalf("NewRedisBackend: %v", err)
	}
	if err := b.EnsureReady(context.Background()); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	t.Cleanup(func() {
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

func TestRedisIntegrationPutGetDelete(t *testing.T) {
	b := newIntegrationBackend(t, "putgetdelete")
	ctx := context.Background()

	if _, err := b.Get(ctx, KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Get on missing key: err = %v, want fs.ErrNotExist", err)
	}
	payload := []byte("pem-data")
	if err := b.Put(ctx, KeyCACert, payload, BlobPublic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(ctx, KeyCACert)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get returned %q, want %q", got, payload)
	}
	if err := b.Delete(ctx, KeyCACert); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := b.Delete(ctx, KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete on missing: err = %v, want fs.ErrNotExist", err)
	}
}

func TestRedisIntegrationListCSR(t *testing.T) {
	b := newIntegrationBackend(t, "list")
	ctx := context.Background()
	subjects := []string{"a.example", "b.example", "c.example"}
	for _, s := range subjects {
		if err := b.Put(ctx, CSRKey(s), []byte("csr"), BlobPublic); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	csrs, err := b.List(ctx, csrPrefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(csrs)
	want := []string{CSRKey("a.example"), CSRKey("b.example"), CSRKey("c.example")}
	if fmt.Sprint(csrs) != fmt.Sprint(want) {
		t.Errorf("List = %v, want %v", csrs, want)
	}
}

func TestRedisIntegrationAppendLineConcurrent(t *testing.T) {
	// Two backends sharing a Redis → simulates two replicas.
	a := newIntegrationBackend(t, "append-a")
	b := newIntegrationBackend(t, "append-b")
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
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				line := fmt.Sprintf("w%d-i%d\n", w, i)
				if err := backend.AppendLine(context.Background(), KeyInventory, []byte(line), BlobPrivate); err != nil {
					t.Errorf("AppendLine: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	data, err := a.Get(context.Background(), KeyInventory)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
	if len(lines) != writers*perWriter {
		t.Errorf("got %d lines, want %d", len(lines), writers*perWriter)
	}
}

func TestRedisIntegrationAcquireLockSerialises(t *testing.T) {
	a := newIntegrationBackend(t, "lock-a")
	b := newIntegrationBackend(t, "lock-b")
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
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			ul, err := backend.AcquireLock(ctx, "crl")
			if err != nil {
				t.Errorf("AcquireLock: %v", err)
				return
			}
			cur := inCritical.Add(1)
			for {
				m := maxConcurrent.Load()
				if cur <= m || maxConcurrent.CompareAndSwap(m, cur) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond)
			inCritical.Add(-1)
			if err := ul.Unlock(); err != nil {
				t.Errorf("Unlock: %v", err)
			}
		}()
	}
	wg.Wait()
	if maxConcurrent.Load() != 1 {
		t.Errorf("maxConcurrent = %d, want 1", maxConcurrent.Load())
	}
}
