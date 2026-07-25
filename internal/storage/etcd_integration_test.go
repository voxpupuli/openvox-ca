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

// newEtcdInventoryService wraps a fresh backend on prefix in a StorageService
// with the inventory touched and integrity initialised. Multiple services may
// share a prefix; the first to initialise creates the HMAC key, the rest read
// it back.
func newEtcdInventoryService(cli *clientv3.Client, prefix string) (*StorageService, *EtcdBackend) {
	b := newBackend(cli, prefix)
	svc := NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
	ctx := context.Background()
	Expect(svc.EnsureDirs(ctx)).To(Succeed(), "EnsureDirs")
	Expect(svc.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
	Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC")
	return svc, b
}

// EtcdInventoryConcurrentAppends drives concurrent AppendInventory calls
// through two StorageServices sharing one etcd prefix (simulating two
// replicas) with integrity enabled. Afterwards ReadInventory — which verifies
// the hash chain — must succeed on both replicas, proving the chained head
// never forked, and every appended line must appear exactly once.
var _ = Describe("EtcdInventoryConcurrentAppends", func() {
	It("loses no entries and keeps the hash chain intact across two replicas", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		svcA, _ := newEtcdInventoryService(cli, "/test-append")
		svcB, _ := newEtcdInventoryService(cli, "/test-append")

		const writers = 4
		const perWriter = 25
		var wg sync.WaitGroup
		wg.Add(writers)
		for w := 0; w < writers; w++ {
			svc := svcA
			if w%2 == 1 {
				svc = svcB
			}
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				for i := 0; i < perWriter; i++ {
					line := fmt.Sprintf("%02d%02d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /w%d", w, i, w)
					Expect(svc.AppendInventory(context.Background(), line)).To(Succeed(), "AppendInventory")
				}
			}()
		}
		wg.Wait()

		// ReadInventory verifies the chained head before returning; success
		// on both replicas proves entries and head stayed in sync throughout.
		data, err := svcA.ReadInventory(context.Background())
		Expect(err).NotTo(HaveOccurred(), "ReadInventory on A (chain forked?)")
		_, err = svcB.ReadInventory(context.Background())
		Expect(err).NotTo(HaveOccurred(), "ReadInventory on B (chain forked?)")

		lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
		Expect(lines).To(HaveLen(writers*perWriter), "got %d lines, want %d (no lines were lost?)", len(lines), writers*perWriter)

		// Set-equality: a lost line masked by a duplicated one nets to the
		// same count, so assert every expected serial appears exactly once.
		seen := make(map[string]int, writers*perWriter)
		for _, l := range lines {
			seen[string(bytes.Fields(l)[0])]++
		}
		for w := 0; w < writers; w++ {
			for i := 0; i < perWriter; i++ {
				serial := fmt.Sprintf("%02d%02d", w, i)
				Expect(seen[serial]).To(Equal(1), "serial %q appeared %d times, want exactly 1", serial, seen[serial])
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

		// Re-appending line1's serial (0001) under a different subject must be
		// rejected by the by-serial guard in the append transaction, and must
		// not mutate the inventory.
		dup := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node3"
		Expect(svc.AppendInventory(context.Background(), dup)).To(MatchError(ErrDuplicateSerial), "duplicate serial must be rejected")
		inv, err = svc.ReadInventory(context.Background())
		Expect(err).NotTo(HaveOccurred(), "ReadInventory after duplicate")
		Expect(string(inv)).To(Equal(line1+"\n"+line2+"\n"), "inventory must be unchanged after a rejected duplicate")

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

// --- InventoryStore ---

var _ = Describe("EtcdInventoryStore", func() {
	It("stores appends as per-entry keys and renders byte-identical inventory text", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		svc, b := newEtcdInventoryService(cli, "/test-inv-store")
		ctx := context.Background()

		for _, line := range sampleInventoryLines {
			Expect(svc.AppendInventory(ctx, line)).To(Succeed(), "AppendInventory(%q)", line)
		}

		inv, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory")
		want := ""
		for _, line := range sampleInventoryLines {
			want += line + "\n"
		}
		Expect(string(inv)).To(Equal(want), "rendered inventory must be byte-identical to the appended lines")

		// The entries really are decomposed: one key per issuance.
		resp, err := cli.Get(ctx, "/test-inv-store/inventory/entries/", clientv3.WithPrefix(), clientv3.WithCountOnly())
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Count).To(Equal(int64(len(sampleInventoryLines))), "one entry key per appended line")

		entries, err := b.Entries(ctx)
		Expect(err).NotTo(HaveOccurred(), "Entries")
		Expect(entries).To(HaveLen(3))
		Expect(entries[2].Serial).To(Equal("0003"), "issuance order preserved")

		// Subject lookups come from the by-subject index.
		serial, err := svc.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred(), "LatestSerialForSubject")
		Expect(serial).To(Equal("0003"), "node1's later issuance wins")
		_, err = svc.LatestSerialForSubject(ctx, "unknown")
		Expect(err).To(MatchError(fs.ErrNotExist), "unknown subject must wrap fs.ErrNotExist")
	})

	It("rejects a duplicate serial across two replicas", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		svcA, _ := newEtcdInventoryService(cli, "/test-inv-dup")
		svcB, _ := newEtcdInventoryService(cli, "/test-inv-dup")
		ctx := context.Background()

		Expect(svcA.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
		err := svcB.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node2")
		Expect(err).To(MatchError(ErrDuplicateSerial), "replica B must see replica A's serial")
		Expect(svcB.AppendInventory(ctx, "0002 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node2")).To(Succeed())

		inv, err := svcA.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(inv)).To(Equal(
			"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n"+
				"0002 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node2\n"),
			"the rejected duplicate must not have left any trace")
	})

	It("appends parsed rows for direct AppendLine calls and rejects bad input", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		_, b := newEtcdInventoryService(cli, "/test-inv-appendline")
		ctx := context.Background()

		lines := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n" +
			"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2\n"
		Expect(b.AppendLine(ctx, KeyInventory, []byte(lines), BlobPrivate)).To(Succeed(), "AppendLine")

		entries, err := b.Entries(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(2))

		Expect(b.AppendLine(ctx, KeyInventory, []byte("too few fields\n"), BlobPrivate)).
			To(HaveOccurred(), "malformed lines must be rejected, not dropped")
		Expect(b.AppendLine(ctx, KeyInventory, []byte("0001 nb na /node3\n"), BlobPrivate)).
			To(MatchError(ErrDuplicateSerial), "stored serials must be rejected")

		entries, err = b.Entries(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(2), "rejected appends must not add entries")
	})

	It("replaces and serves the inventory through the Put/Get shim", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		b := newBackend(cli, "/test-inv-shim")
		ctx := context.Background()

		// Never initialised → absent.
		_, err := b.Get(ctx, KeyInventory)
		Expect(err).To(MatchError(fs.ErrNotExist), "Get before init")

		blob := "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n" +
			"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2\n"
		Expect(b.Put(ctx, KeyInventory, []byte(blob), BlobPrivate)).To(Succeed(), "Put")

		got, err := b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred(), "Get")
		Expect(string(got)).To(Equal(blob), "render must be byte-identical to the imported blob")
		ok, err := b.Exists(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue(), "Exists after Put")

		// Replacement drops the previous contents entirely.
		replacement := "0009 2025-01-01T00:00:00UTC 2030-01-01T00:00:00UTC /node9\n"
		Expect(b.Put(ctx, KeyInventory, []byte(replacement), BlobPrivate)).To(Succeed(), "Put (replace)")
		got, err = b.Get(ctx, KeyInventory)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal(replacement))
		serial, err := b.LatestSerialForSubject(ctx, "node9")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal("0009"), "indices must be rebuilt on replace")
		_, err = b.LatestSerialForSubject(ctx, "node1")
		Expect(err).To(MatchError(fs.ErrNotExist), "replaced subjects must vanish from the index")

		// A blob with duplicate serials must be rejected, like SQL's unique index.
		Expect(b.Put(ctx, KeyInventory, []byte("0009 nb na /a\n0009 nb na /b\n"), BlobPrivate)).
			To(MatchError(ErrDuplicateSerial))

		Expect(b.Delete(ctx, KeyInventory)).To(Succeed(), "Delete")
		_, err = b.Get(ctx, KeyInventory)
		Expect(err).To(MatchError(fs.ErrNotExist), "Get after Delete")
		Expect(b.Delete(ctx, KeyInventory)).To(MatchError(fs.ErrNotExist), "Delete on missing")
	})
})

var _ = Describe("EtcdInventoryPrune", func() {
	It("removes matching entries, rewrites the head, and repoints the subject index", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		svc, _ := newEtcdInventoryService(cli, "/test-inv-prune")
		ctx := context.Background()

		for _, line := range sampleInventoryLines {
			Expect(svc.AppendInventory(ctx, line)).To(Succeed())
		}

		// Drop node1's *latest* issuance so the subject index must repoint.
		removed, err := svc.PruneInventory(ctx, keepNotSerial("0003"))
		Expect(err).NotTo(HaveOccurred(), "PruneInventory")
		Expect(removed).To(HaveLen(1))
		Expect(removed[0].Serial).To(Equal("0003"))

		// ReadInventory verifies the chain, so success proves the head was
		// rewritten for the survivors.
		inv, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory after prune (head not rewritten?)")
		Expect(string(inv)).To(Equal(
			"0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1\n" +
				"0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2\n"))

		serial, err := svc.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal("0001"), "subject index must fall back to the surviving issuance")

		// A pruned serial is free for reuse, and the chain extends cleanly.
		Expect(svc.AppendInventory(ctx, "0003 2024-01-04T00:00:00UTC 2029-01-04T00:00:00UTC /node3")).To(Succeed())
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory after post-prune append")

		// No-match prunes are a no-op.
		removed, err = svc.PruneInventory(ctx, func(InventoryEntry) bool { return true })
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(BeEmpty())
	})

	It("prunes more entries than one transaction batch holds, staying consistent throughout", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		svc, _ := newEtcdInventoryService(cli, "/test-inv-prune-big")
		ctx := context.Background()

		const total = 80
		for i := 1; i <= total; i++ {
			line := fmt.Sprintf("%04d 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node%d", i, i%8)
			Expect(svc.AppendInventory(ctx, line)).To(Succeed())
		}

		// Remove the first 65 serials: spans three etcdPruneBatch (30)
		// transactions, so the batched path with intermediate heads runs.
		keep := func(e InventoryEntry) bool { return e.Serial > "0065" }
		removed, err := svc.PruneInventory(ctx, keep)
		Expect(err).NotTo(HaveOccurred(), "PruneInventory")
		Expect(removed).To(HaveLen(65))

		inv, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory after batched prune (head inconsistent?)")
		lines := bytes.Split(bytes.TrimRight(inv, "\n"), []byte{'\n'})
		Expect(lines).To(HaveLen(total - 65))
		Expect(string(bytes.Fields(lines[0])[0])).To(Equal("0066"), "survivors keep issuance order")

		// node7's newest surviving serial is 0079 (79 mod 8 == 7).
		serial, err := svc.LatestSerialForSubject(ctx, "node7")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal("0079"))

		Expect(svc.AppendInventory(ctx, "9999 2024-06-01T00:00:00UTC 2029-06-01T00:00:00UTC /fresh")).To(Succeed(), "append after batched prune")
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
	})
})

// --- Legacy blob decomposition ---

var _ = Describe("EtcdLegacyInventoryDecompose", func() {
	It("imports a pre-decomposition blob on EnsureReady and re-baselines integrity", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		ctx := context.Background()
		const prefix = "/test-inv-legacy"

		// Seed the exact state a pre-decomposition version leaves behind: the
		// inventory text at inventory/data, a whole-blob HMAC under
		// inventory/hmac, and the HMAC key.
		key := bytes.Repeat([]byte{0x42}, 32)
		blob := ""
		for _, line := range sampleInventoryLines {
			blob += line + "\n"
		}
		now := time.Now()
		_, err := cli.Put(ctx, prefix+"/private/hmac_key", string(encodeBlob(now, key)))
		Expect(err).NotTo(HaveOccurred())
		_, err = cli.Put(ctx, prefix+"/inventory/data", string(encodeBlob(now, []byte(blob))))
		Expect(err).NotTo(HaveOccurred())
		_, err = cli.Put(ctx, prefix+"/inventory/hmac", string(encodeBlob(now, wholeBlobInventoryMAC(key, []byte(blob)))))
		Expect(err).NotTo(HaveOccurred())

		// newBackend runs EnsureReady, which performs the decomposition.
		b := newBackend(cli, prefix)
		defer b.Close()

		resp, err := cli.Get(ctx, prefix+"/inventory/entries/", clientv3.WithPrefix(), clientv3.WithCountOnly())
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Count).To(Equal(int64(len(sampleInventoryLines))), "blob lines must become entry keys")
		headResp, err := cli.Get(ctx, prefix+"/inventory/hmac")
		Expect(err).NotTo(HaveOccurred())
		Expect(headResp.Kvs).To(BeEmpty(), "the whole-blob HMAC must be dropped: it is not a chain head")

		// InitHMAC re-baselines from the imported entries and verifies clean.
		svc := NewWithBackend(b, filepath.Join(GinkgoT().TempDir(), "private"))
		Expect(svc.InitHMAC(ctx)).To(Succeed(), "InitHMAC after decomposition")
		inv, err := svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "ReadInventory")
		Expect(string(inv)).To(Equal(blob), "decomposed inventory must render the original text")
		serial, err := svc.LatestSerialForSubject(ctx, "node1")
		Expect(err).NotTo(HaveOccurred())
		Expect(serial).To(Equal("0003"), "the subject index must be built from the blob")

		// Running EnsureReady again must be a no-op.
		Expect(b.EnsureReady(ctx)).To(Succeed(), "EnsureReady (again)")
		resp, err = cli.Get(ctx, prefix+"/inventory/entries/", clientv3.WithPrefix(), clientv3.WithCountOnly())
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Count).To(Equal(int64(len(sampleInventoryLines))), "a second EnsureReady must not re-import")

		// Appends extend the decomposed inventory and the fresh chain.
		Expect(svc.AppendInventory(ctx, "0004 2024-01-04T00:00:00UTC 2029-01-04T00:00:00UTC /node3")).To(Succeed())
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
	})
})

// --- CertIndex ---

var _ = Describe("EtcdCertIndex", func() {
	It("round-trips the certificate index end to end", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		svc, b := newEtcdInventoryService(cli, "/test-certindex")
		ctx := context.Background()

		proj := CertProjection{
			Fingerprint:    "aa:bb:cc",
			DNSAltNames:    []string{"node1", "node1.example.com"},
			AuthExtensions: map[string]string{"pp_auth_role": "webserver"},
		}
		Expect(svc.AppendInventory(ctx, "0001 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /node1")).To(Succeed())
		Expect(svc.AppendInventoryRecord(ctx, "0003 2024-01-03T00:00:00UTC 2029-01-03T00:00:00UTC /node1", &proj)).To(Succeed())
		Expect(svc.AppendInventory(ctx, "0002 2024-01-02T00:00:00UTC 2029-01-02T00:00:00UTC /node2")).To(Succeed())
		// node1 and node2 hold stored certs; node3 has an inventory entry but
		// no blob and must stay invisible.
		Expect(svc.AppendInventory(ctx, "0004 2024-01-04T00:00:00UTC 2029-01-04T00:00:00UTC /node3")).To(Succeed())
		for _, subject := range []string{"node1", "node2"} {
			Expect(b.Put(ctx, CertKey(subject), []byte("pem-"+subject), BlobPublic)).To(Succeed())
		}

		recs, ok, err := svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred(), "CertStatuses")
		Expect(ok).To(BeTrue(), "etcd backend must advertise the CertIndex capability")
		Expect(recs).To(HaveLen(2), "one record per subject with a stored cert, latest issuance only")
		Expect(recs[0].Subject).To(Equal("node1"))
		Expect(recs[0].Serial).To(Equal("0003"), "node1's latest issuance wins")
		Expect(recs[0].Fingerprint).To(Equal(proj.Fingerprint))
		Expect(recs[0].DNSAltNames).To(Equal(proj.DNSAltNames))
		Expect(recs[0].AuthExtensions).To(Equal(proj.AuthExtensions))
		Expect(recs[1].Subject).To(Equal("node2"))
		Expect(recs[1].Fingerprint).To(BeEmpty(), "appended without a projection")

		// Revocation round-trip: idempotent marking keeps the first time, the
		// state filter partitions, and clearing restores the signed state.
		revokedAt := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
		Expect(svc.MarkCertRevoked(ctx, "0003", revokedAt)).To(Succeed())
		Expect(svc.MarkCertRevoked(ctx, "0003", revokedAt.Add(24*time.Hour))).To(Succeed(), "re-marking must not error")
		revoked, _, err := svc.CertStatuses(ctx, CertStateRevoked)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(HaveLen(1))
		Expect(revoked[0].Subject).To(Equal("node1"))
		Expect(revoked[0].RevokedAt).NotTo(BeNil())
		Expect(*revoked[0].RevokedAt).To(BeTemporally("~", revokedAt, time.Second), "the first revocation time must be kept")
		signed, _, err := svc.CertStatuses(ctx, CertStateSigned)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(HaveLen(1))
		Expect(signed[0].Subject).To(Equal("node2"))

		Expect(svc.ClearCertRevoked(ctx, "0003")).To(Succeed())

		// Projection backfill for the projection-less record.
		Expect(svc.SetCertProjection(ctx, "0002", CertProjection{Fingerprint: "dd:ee:ff"})).To(Succeed())
		recs, _, err = svc.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs).To(HaveLen(2))
		Expect(recs[0].State).To(Equal(CertStateSigned), "ClearCertRevoked restored node1")
		Expect(recs[0].RevokedAt).To(BeNil())
		Expect(recs[1].Fingerprint).To(Equal("dd:ee:ff"))

		// The chain covers only canonical fields, so none of the index writes
		// above may have disturbed it.
		_, err = svc.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred(), "index writes must not touch the integrity chain")
	})

	It("treats unknown serials as no-ops for revocation and projection writes", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		svc, _ := newEtcdInventoryService(cli, "/test-certindex-noop")
		ctx := context.Background()

		Expect(svc.MarkCertRevoked(ctx, "FFFF", time.Now())).To(Succeed())
		Expect(svc.ClearCertRevoked(ctx, "FFFF")).To(Succeed())
		Expect(svc.SetCertProjection(ctx, "FFFF", CertProjection{Fingerprint: "aa"})).To(Succeed())
	})
})

// --- Migration ---

var _ = Describe("EtcdMigrateFromFilesystem", func() {
	It("imports a filesystem CA and rebuilds the chain head for the decomposed inventory", func() {
		cli, stop := startEmbeddedEtcd()
		defer stop()
		ctx := context.Background()

		src := New(GinkgoT().TempDir())
		Expect(src.EnsureDirs(ctx)).To(Succeed())
		Expect(src.SaveCACert(ctx, []byte("ca-cert-pem"))).To(Succeed())
		Expect(src.TouchInventory(ctx)).To(Succeed())
		Expect(src.InitHMAC(ctx)).To(Succeed())
		for _, line := range sampleInventoryLines {
			Expect(src.AppendInventory(ctx, line)).To(Succeed())
		}
		Expect(src.SaveCert(ctx, "node1", []byte("cert-pem"))).To(Succeed())

		dstBackend := newBackend(cli, "/test-migrate")
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
