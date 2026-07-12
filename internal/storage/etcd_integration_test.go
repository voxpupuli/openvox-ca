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

//go:build etcd_integration

package storage

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
)

// startEmbeddedEtcd boots an in-process etcd server on an ephemeral port and
// returns a client connected to it plus a teardown function.
func startEmbeddedEtcd() (*clientv3.Client, func()) {
	dir := GinkgoT().TempDir()

	peerURL, err := url.Parse("http://127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	clientURL, err := url.Parse("http://127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())

	cfg := embed.NewConfig()
	cfg.Dir = filepath.Join(dir, "etcd")
	cfg.Name = "default"
	cfg.ListenPeerUrls = []url.URL{*peerURL}
	cfg.ListenClientUrls = []url.URL{*clientURL}
	cfg.AdvertisePeerUrls = []url.URL{*peerURL}
	cfg.AdvertiseClientUrls = []url.URL{*clientURL}
	cfg.InitialCluster = fmt.Sprintf("%s=%s", cfg.Name, peerURL.String())
	cfg.LogLevel = "error"

	e, err := embed.StartEtcd(cfg)
	Expect(err).NotTo(HaveOccurred(), "start embedded etcd: %v", err)

	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		e.Server.Stop()
		Fail("embedded etcd failed to become ready")
	}

	// Use whichever client URL the server actually bound to.
	endpoints := make([]string, 0, len(e.Clients))
	for _, l := range e.Clients {
		endpoints = append(endpoints, "http://"+l.Addr().String())
	}

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		e.Close()
		Expect(err).NotTo(HaveOccurred(), "etcd client: %v", err)
	}

	cleanup := func() {
		cli.Close()
		e.Close()
		os.RemoveAll(dir)
	}
	return cli, cleanup
}

func newBackend(cli *clientv3.Client, prefix string) *EtcdBackend {
	b := NewEtcdBackendFromClient(cli, prefix, 5*time.Second)
	Expect(b.EnsureReady(context.Background())).To(Succeed(), "EnsureReady")
	return b
}

var _ = Describe("EtcdBackendPutGetDelete", func() {
	It("puts, gets, and deletes blobs", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		b := newBackend(cli, "/test1")

		// Missing key → wrapped fs.ErrNotExist.
		_, err := b.Get(context.Background(), KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Get on missing key: err = %v, want fs.ErrNotExist", err)
		ok, err := b.Exists(context.Background(), KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "Exists on missing key: ok=%v err=%v", ok, err)
		Expect(ok).To(BeFalse(), "Exists on missing key: ok=%v err=%v", ok, err)

		// Put then Get.
		payload := []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n")
		Expect(b.Put(context.Background(), KeyCACert, payload, BlobPublic)).To(Succeed(), "Put")
		got, err := b.Get(context.Background(), KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "Get")
		Expect(got).To(Equal(payload), "Get returned %q, want %q", got, payload)
		ok, err = b.Exists(context.Background(), KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "Exists after Put: ok=%v err=%v", ok, err)
		Expect(ok).To(BeTrue(), "Exists after Put: ok=%v err=%v", ok, err)

		// Delete and re-check.
		Expect(b.Delete(context.Background(), KeyCACert)).To(Succeed(), "Delete")
		err = b.Delete(context.Background(), KeyCACert)
		Expect(err).To(MatchError(fs.ErrNotExist), "Delete on missing: err = %v, want fs.ErrNotExist", err)
	})
})

var _ = Describe("EtcdBackendModTime", func() {
	It("reports a recent modification time after Put", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		b := newBackend(cli, "/test-modtime")

		_, err := b.ModTime(context.Background(), KeyCRL)
		Expect(err).To(MatchError(fs.ErrNotExist), "ModTime on missing: err = %v, want fs.ErrNotExist", err)

		before := time.Now().Add(-time.Second)
		Expect(b.Put(context.Background(), KeyCRL, []byte("crl-data"), BlobPublic)).To(Succeed(), "Put")
		mt, err := b.ModTime(context.Background(), KeyCRL)
		Expect(err).NotTo(HaveOccurred(), "ModTime")
		Expect(mt.Before(before)).To(BeFalse(), "ModTime = %v, expected near now", mt)
		Expect(mt.After(time.Now().Add(time.Second))).To(BeFalse(), "ModTime = %v, expected near now", mt)
	})
})

var _ = Describe("EtcdBackendList", func() {
	It("lists keys by prefix without cross-contamination", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		b := newBackend(cli, "/test-list")

		subjects := []string{"alpha.example.com", "beta.example.com", "gamma.example.com"}
		for _, s := range subjects {
			Expect(b.Put(context.Background(), CSRKey(s), []byte("csr:"+s), BlobPublic)).To(Succeed(), "Put csr %s", s)
		}
		// Drop one and add a cert to ensure prefixes don't cross-contaminate.
		Expect(b.Put(context.Background(), CertKey("alpha.example.com"), []byte("cert"), BlobPublic)).To(Succeed(), "Put cert")

		csrs, err := b.List(context.Background(), csrPrefix)
		Expect(err).NotTo(HaveOccurred(), "List csr")
		sort.Strings(csrs)
		want := []string{
			CSRKey("alpha.example.com"),
			CSRKey("beta.example.com"),
			CSRKey("gamma.example.com"),
		}
		Expect(fmt.Sprint(csrs)).To(Equal(fmt.Sprint(want)), "List csr = %v, want %v", csrs, want)

		certs, err := b.List(context.Background(), certPrefix)
		Expect(err).NotTo(HaveOccurred(), "List cert")
		Expect(len(certs) == 1 && certs[0] == CertKey("alpha.example.com")).To(BeTrue(), "List cert = %v, want [%s]", certs, CertKey("alpha.example.com"))

		_, err = b.List(context.Background(), "bogus/")
		Expect(err).To(HaveOccurred(), "List with unknown prefix should error")
	})
})

var _ = Describe("EtcdBackendAppendLineConcurrent", func() {
	It("does not lose lines under concurrent appends from two backends", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		// Two backends sharing the cluster → simulates two processes.
		a := newBackend(cli, "/test-append")
		b := newBackend(cli, "/test-append")

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
		Expect(err).NotTo(HaveOccurred(), "Get after appends")
		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
		Expect(lines).To(HaveLen(writers*perWriter), "got %d lines, want %d (no lines were lost?)", len(lines), writers*perWriter)

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

var _ = Describe("EtcdBackendEndToEndViaStorageService", func() {
	It("round-trips the content API through the etcd backend", func() {
		// Round-trip through StorageService to validate the content-oriented API
		// works over the etcd backend as it does over the filesystem backend.
		cli, stop := startEmbeddedEtcd()
		defer stop()
		backend := newBackend(cli, "/test-service")
		tmp := GinkgoT().TempDir()
		svc := NewWithBackend(backend, filepath.Join(tmp, "private"))

		Expect(svc.EnsureDirs(context.Background())).To(Succeed(), "EnsureDirs")

		Expect(svc.SaveCACert(context.Background(), []byte("ca-cert-pem"))).To(Succeed(), "SaveCACert")
		ok, _ := svc.HasCACert(context.Background())
		Expect(ok).To(BeTrue(), "HasCACert = false after SaveCACert")

		Expect(svc.WriteSerial(context.Background(), "0001")).To(Succeed(), "WriteSerial")
		got, err := svc.GetSerial(context.Background())
		Expect(err).NotTo(HaveOccurred(), "GetSerial")
		Expect(string(got)).To(Equal("0001"), "GetSerial = %q, want 0001", got)

		Expect(svc.InitHMAC(context.Background())).To(Succeed(), "InitHMAC")
		const line1 = "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1"
		const line2 = "0002 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node2"
		Expect(svc.AppendInventory(context.Background(), line1)).To(Succeed(), "AppendInventory")
		Expect(svc.AppendInventory(context.Background(), line2)).To(Succeed(), "AppendInventory")

		inv, err := svc.ReadInventory(context.Background())
		Expect(err).NotTo(HaveOccurred(), "ReadInventory")
		Expect(string(inv)).To(Equal(line1+"\n"+line2+"\n"), "ReadInventory = %q, want %q", inv, line1+"\n"+line2+"\n")

		Expect(svc.SaveCSR(context.Background(), "node1", []byte("csr-pem"))).To(Succeed(), "SaveCSR")
		Expect(svc.SaveCert(context.Background(), "node1", []byte("cert-pem"))).To(Succeed(), "SaveCert")
		csrs, err := svc.ListCSRs(context.Background())
		Expect(err).NotTo(HaveOccurred(), "ListCSRs")
		Expect(len(csrs) == 1 && csrs[0] == "node1").To(BeTrue(), "ListCSRs = %v, want [node1]", csrs)
		certs, err := svc.ListCerts(context.Background())
		Expect(err).NotTo(HaveOccurred(), "ListCerts")
		Expect(len(certs) == 1 && certs[0] == "node1").To(BeTrue(), "ListCerts = %v, want [node1]", certs)
	})
})

// EtcdBackendAcquireLockMutualExclusion asserts that two replicas holding
// the same lock name cannot both enter the critical section at once. Replica
// A holds the lock for ~200ms; replica B must wait.
var _ = Describe("EtcdBackendAcquireLockMutualExclusion", func() {
	It("blocks a second replica until the first releases the lock", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		a := newBackend(cli, "/test-lock-mutex")
		b := newBackend(cli, "/test-lock-mutex")
		defer a.Close()
		defer b.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ulA, err := a.AcquireLock(ctx, "crl")
		Expect(err).NotTo(HaveOccurred(), "A AcquireLock")

		type result struct {
			got time.Time
			err error
		}
		ch := make(chan result, 1)
		startB := time.Now()
		go func() {
			ul, err := b.AcquireLock(ctx, "crl")
			res := result{got: time.Now(), err: err}
			if err == nil {
				_ = ul.Unlock()
			}
			ch <- res
		}()

		// Give B time to attempt acquisition and block.
		time.Sleep(200 * time.Millisecond)
		Expect(ulA.Unlock()).To(Succeed(), "A Unlock")

		select {
		case res := <-ch:
			Expect(res.err).NotTo(HaveOccurred(), "B AcquireLock")
			waited := res.got.Sub(startB)
			Expect(waited).To(BeNumerically(">=", 150*time.Millisecond), "B acquired after %v; expected to wait ~200ms while A held the lock", waited)
		case <-time.After(5 * time.Second):
			Fail("B never acquired the lock")
		}
	})
})

// EtcdBackendAcquireLockDistinctNames asserts that different lock names
// do NOT contend: locks are per-name, not global.
var _ = Describe("EtcdBackendAcquireLockDistinctNames", func() {
	It("does not contend across distinct lock names", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		b := newBackend(cli, "/test-lock-distinct")
		defer b.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ul1, err := b.AcquireLock(ctx, "subject:alpha")
		Expect(err).NotTo(HaveOccurred(), "AcquireLock alpha")
		ul2, err := b.AcquireLock(ctx, "subject:beta")
		Expect(err).NotTo(HaveOccurred(), "AcquireLock beta")
		Expect(ul1.Unlock()).To(Succeed(), "Unlock alpha")
		Expect(ul2.Unlock()).To(Succeed(), "Unlock beta")
	})
})

// EtcdBackendAcquireLockSerialisesConcurrentCallers fires many goroutines
// through the same lock and asserts that they entered the critical section
// strictly one-at-a-time.
var _ = Describe("EtcdBackendAcquireLockSerialisesConcurrentCallers", func() {
	It("serialises concurrent callers through the same lock", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		// Two backends to force cross-session (cross-replica) contention.
		a := newBackend(cli, "/test-lock-serial")
		b := newBackend(cli, "/test-lock-serial")
		defer a.Close()
		defer b.Close()

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
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		Expect(maxConcurrent.Load()).To(Equal(int32(1)), "maxConcurrent = %d, want 1 (lock did not serialise writers)", maxConcurrent.Load())
	})
})

// EtcdBackendWithLockCrossBackend asserts StorageService.WithLock
// coordinates across two StorageService instances sharing an etcd cluster.
var _ = Describe("EtcdBackendWithLockCrossBackend", func() {
	It("coordinates WithLock across two StorageService instances", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		a := newBackend(cli, "/test-withlock")
		b := newBackend(cli, "/test-withlock")
		svcA := NewWithBackend(a, filepath.Join(GinkgoT().TempDir(), "a"))
		svcB := NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "b"))

		var counter atomic.Int32
		var maxSeen atomic.Int32
		var wg sync.WaitGroup
		wg.Add(4)
		for i := 0; i < 4; i++ {
			svc := svcA
			if i%2 == 1 {
				svc = svcB
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				err := svc.WithLock(ctx, "crl", func() error {
					cur := counter.Add(1)
					for {
						m := maxSeen.Load()
						if cur <= m || maxSeen.CompareAndSwap(m, cur) {
							break
						}
					}
					time.Sleep(50 * time.Millisecond)
					counter.Add(-1)
					return nil
				})
				Expect(err).NotTo(HaveOccurred(), "WithLock")
			}()
		}
		wg.Wait()
		Expect(maxSeen.Load()).To(Equal(int32(1)), "maxSeen = %d, want 1", maxSeen.Load())
	})
})
