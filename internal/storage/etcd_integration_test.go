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

//go:build etcd_integration

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
)

// startEmbeddedEtcd boots an in-process etcd server on an ephemeral port and
// returns a client connected to it plus a teardown function.
func startEmbeddedEtcd(t *testing.T) (*clientv3.Client, func()) {
	t.Helper()
	dir := t.TempDir()

	peerURL, err := url.Parse("http://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	clientURL, err := url.Parse("http://127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatalf("start embedded etcd: %v", err)
	}

	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		e.Server.Stop()
		t.Fatal("embedded etcd failed to become ready")
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
		t.Fatalf("etcd client: %v", err)
	}

	cleanup := func() {
		cli.Close()
		e.Close()
		os.RemoveAll(dir)
	}
	return cli, cleanup
}

func newBackend(t *testing.T, cli *clientv3.Client, prefix string) *EtcdBackend {
	t.Helper()
	b := NewEtcdBackendFromClient(cli, prefix, 5*time.Second)
	if err := b.EnsureReady(); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	return b
}

func TestEtcdBackendPutGetDelete(t *testing.T) {
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	b := newBackend(t, cli, "/test1")

	// Missing key → wrapped fs.ErrNotExist.
	if _, err := b.Get(KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Get on missing key: err = %v, want fs.ErrNotExist", err)
	}
	ok, err := b.Exists(KeyCACert)
	if err != nil || ok {
		t.Fatalf("Exists on missing key: ok=%v err=%v", ok, err)
	}

	// Put then Get.
	payload := []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n")
	if err := b.Put(KeyCACert, payload, BlobPublic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(KeyCACert)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get returned %q, want %q", got, payload)
	}
	ok, err = b.Exists(KeyCACert)
	if err != nil || !ok {
		t.Fatalf("Exists after Put: ok=%v err=%v", ok, err)
	}

	// Delete and re-check.
	if err := b.Delete(KeyCACert); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := b.Delete(KeyCACert); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete on missing: err = %v, want fs.ErrNotExist", err)
	}
}

func TestEtcdBackendModTime(t *testing.T) {
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	b := newBackend(t, cli, "/test-modtime")

	if _, err := b.ModTime(KeyCRL); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ModTime on missing: err = %v, want fs.ErrNotExist", err)
	}

	before := time.Now().Add(-time.Second)
	if err := b.Put(KeyCRL, []byte("crl-data"), BlobPublic); err != nil {
		t.Fatalf("Put: %v", err)
	}
	mt, err := b.ModTime(KeyCRL)
	if err != nil {
		t.Fatalf("ModTime: %v", err)
	}
	if mt.Before(before) || mt.After(time.Now().Add(time.Second)) {
		t.Errorf("ModTime = %v, expected near now", mt)
	}
}

func TestEtcdBackendList(t *testing.T) {
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	b := newBackend(t, cli, "/test-list")

	subjects := []string{"alpha.example.com", "beta.example.com", "gamma.example.com"}
	for _, s := range subjects {
		if err := b.Put(CSRKey(s), []byte("csr:"+s), BlobPublic); err != nil {
			t.Fatalf("Put csr %s: %v", s, err)
		}
	}
	// Drop one and add a cert to ensure prefixes don't cross-contaminate.
	if err := b.Put(CertKey("alpha.example.com"), []byte("cert"), BlobPublic); err != nil {
		t.Fatalf("Put cert: %v", err)
	}

	csrs, err := b.List(csrPrefix)
	if err != nil {
		t.Fatalf("List csr: %v", err)
	}
	sort.Strings(csrs)
	want := []string{
		CSRKey("alpha.example.com"),
		CSRKey("beta.example.com"),
		CSRKey("gamma.example.com"),
	}
	if fmt.Sprint(csrs) != fmt.Sprint(want) {
		t.Errorf("List csr = %v, want %v", csrs, want)
	}

	certs, err := b.List(certPrefix)
	if err != nil {
		t.Fatalf("List cert: %v", err)
	}
	if len(certs) != 1 || certs[0] != CertKey("alpha.example.com") {
		t.Errorf("List cert = %v, want [%s]", certs, CertKey("alpha.example.com"))
	}

	if _, err := b.List("bogus/"); err == nil {
		t.Errorf("List with unknown prefix should error")
	}
}

func TestEtcdBackendAppendLineConcurrent(t *testing.T) {
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	// Two backends sharing the cluster → simulates two processes.
	a := newBackend(t, cli, "/test-append")
	b := newBackend(t, cli, "/test-append")

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
				if err := backend.AppendLine(KeyInventory, []byte(line), BlobPrivate); err != nil {
					t.Errorf("AppendLine: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	data, err := a.Get(KeyInventory)
	if err != nil {
		t.Fatalf("Get after appends: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte{'\n'})
	if len(lines) != writers*perWriter {
		t.Errorf("got %d lines, want %d (no lines were lost?)", len(lines), writers*perWriter)
	}
}

func TestEtcdBackendEndToEndViaStorageService(t *testing.T) {
	// Round-trip through StorageService to validate the content-oriented API
	// works over the etcd backend as it does over the filesystem backend.
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	backend := newBackend(t, cli, "/test-service")
	tmp := t.TempDir()
	svc := NewWithBackend(backend, filepath.Join(tmp, "private"))

	if err := svc.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}

	if err := svc.SaveCACert([]byte("ca-cert-pem")); err != nil {
		t.Fatalf("SaveCACert: %v", err)
	}
	if ok, _ := svc.HasCACert(); !ok {
		t.Errorf("HasCACert = false after SaveCACert")
	}

	if err := svc.WriteSerial("0001"); err != nil {
		t.Fatalf("WriteSerial: %v", err)
	}
	got, err := svc.GetSerial()
	if err != nil {
		t.Fatalf("GetSerial: %v", err)
	}
	if string(got) != "0001" {
		t.Errorf("GetSerial = %q, want 0001", got)
	}

	if err := svc.InitHMAC(); err != nil {
		t.Fatalf("InitHMAC: %v", err)
	}
	if err := svc.AppendInventory("line 1"); err != nil {
		t.Fatalf("AppendInventory: %v", err)
	}
	if err := svc.AppendInventory("line 2"); err != nil {
		t.Fatalf("AppendInventory: %v", err)
	}

	inv, err := svc.ReadInventory()
	if err != nil {
		t.Fatalf("ReadInventory: %v", err)
	}
	if string(inv) != "line 1\nline 2\n" {
		t.Errorf("ReadInventory = %q, want 'line 1\\nline 2\\n'", inv)
	}

	if err := svc.SaveCSR("node1", []byte("csr-pem")); err != nil {
		t.Fatalf("SaveCSR: %v", err)
	}
	if err := svc.SaveCert("node1", []byte("cert-pem")); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}
	csrs, err := svc.ListCSRs()
	if err != nil {
		t.Fatalf("ListCSRs: %v", err)
	}
	if len(csrs) != 1 || csrs[0] != "node1" {
		t.Errorf("ListCSRs = %v, want [node1]", csrs)
	}
	certs, err := svc.ListCerts()
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(certs) != 1 || certs[0] != "node1" {
		t.Errorf("ListCerts = %v, want [node1]", certs)
	}
}

// TestEtcdBackendAcquireLockMutualExclusion asserts that two replicas holding
// the same lock name cannot both enter the critical section at once. Replica
// A holds the lock for ~200ms; replica B must wait.
func TestEtcdBackendAcquireLockMutualExclusion(t *testing.T) {
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	a := newBackend(t, cli, "/test-lock-mutex")
	b := newBackend(t, cli, "/test-lock-mutex")
	defer a.Close()
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ulA, err := a.AcquireLock(ctx, "crl")
	if err != nil {
		t.Fatalf("A AcquireLock: %v", err)
	}

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
	if err := ulA.Unlock(); err != nil {
		t.Fatalf("A Unlock: %v", err)
	}

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("B AcquireLock: %v", res.err)
		}
		waited := res.got.Sub(startB)
		if waited < 150*time.Millisecond {
			t.Errorf("B acquired after %v; expected to wait ~200ms while A held the lock", waited)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("B never acquired the lock")
	}
}

// TestEtcdBackendAcquireLockDistinctNames asserts that different lock names
// do NOT contend: locks are per-name, not global.
func TestEtcdBackendAcquireLockDistinctNames(t *testing.T) {
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	b := newBackend(t, cli, "/test-lock-distinct")
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ul1, err := b.AcquireLock(ctx, "subject:alpha")
	if err != nil {
		t.Fatalf("AcquireLock alpha: %v", err)
	}
	ul2, err := b.AcquireLock(ctx, "subject:beta")
	if err != nil {
		t.Fatalf("AcquireLock beta: %v", err)
	}
	if err := ul1.Unlock(); err != nil {
		t.Errorf("Unlock alpha: %v", err)
	}
	if err := ul2.Unlock(); err != nil {
		t.Errorf("Unlock beta: %v", err)
	}
}

// TestEtcdBackendAcquireLockSerialisesConcurrentCallers fires many goroutines
// through the same lock and asserts that they entered the critical section
// strictly one-at-a-time.
func TestEtcdBackendAcquireLockSerialisesConcurrentCallers(t *testing.T) {
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	// Two backends to force cross-session (cross-replica) contention.
	a := newBackend(t, cli, "/test-lock-serial")
	b := newBackend(t, cli, "/test-lock-serial")
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
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		t.Errorf("maxConcurrent = %d, want 1 (lock did not serialise writers)", maxConcurrent.Load())
	}
}

// TestEtcdBackendWithLockCrossBackend asserts StorageService.WithLock
// coordinates across two StorageService instances sharing an etcd cluster.
func TestEtcdBackendWithLockCrossBackend(t *testing.T) {
	cli, stop := startEmbeddedEtcd(t)
	defer stop()
	a := newBackend(t, cli, "/test-withlock")
	b := newBackend(t, cli, "/test-withlock")
	svcA := NewWithBackend(a, filepath.Join(t.TempDir(), "a"))
	svcB := NewWithBackend(b, filepath.Join(t.TempDir(), "b"))

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
			if err != nil {
				t.Errorf("WithLock: %v", err)
			}
		}()
	}
	wg.Wait()
	if maxSeen.Load() != 1 {
		t.Errorf("maxSeen = %d, want 1", maxSeen.Load())
	}
}
