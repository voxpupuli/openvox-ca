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
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
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
