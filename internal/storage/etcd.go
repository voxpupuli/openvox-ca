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

package storage

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// EtcdConfig configures the etcd-backed storage backend.
type EtcdConfig struct {
	// Endpoints is the list of etcd cluster endpoints (host:port).
	Endpoints []string
	// DialTimeout bounds the initial connection attempt. Zero uses 5s.
	DialTimeout time.Duration
	// RequestTimeout bounds per-request operations. Zero uses 5s.
	RequestTimeout time.Duration
	// Username / Password enable etcd authentication when both are set.
	Username string
	Password string
	// TLS, if non-nil, configures TLS for the etcd connection.
	TLS *tls.Config
	// KeyPrefix namespaces all keys stored by this backend so multiple CAs
	// (or other applications) can share a single etcd cluster. Defaults to
	// "/puppet-ca" when empty.
	KeyPrefix string
}

// etcdBackendDefaults fills in zero-valued fields with sensible defaults.
func (c *EtcdConfig) applyDefaults() {
	if c.DialTimeout == 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 5 * time.Second
	}
	if c.KeyPrefix == "" {
		c.KeyPrefix = "/puppet-ca"
	}
	c.KeyPrefix = strings.TrimRight(c.KeyPrefix, "/")
}

// EtcdBackend is a Backend implementation backed by an etcd v3 cluster.
//
// Blob contents are wrapped with an 8-byte big-endian nanosecond mtime prefix
// so ModTime can be answered without a second key. Appends use an etcd Txn
// with a ModRevision guard to remain atomic across concurrent writers,
// including those in different processes.
type EtcdBackend struct {
	client   *clientv3.Client
	owned    bool // true when Close should close the client
	prefix   string
	timeout  time.Duration
	appendMu sync.Mutex // serialises AppendLine within this process
}

// etcdLayout maps logical keys to their physical etcd sub-paths. CSR and
// signed-cert keys are handled directly in physicalKey.
var etcdLayout = map[string]string{
	KeyCACert:        "ca/cert",
	KeyCAPubKey:      "ca/pubkey",
	KeyCAKey:         "ca/key",
	KeyCRL:           "ca/crl",
	KeySerial:        "serial",
	KeyInventory:     "inventory/data",
	KeyInventoryHMAC: "inventory/hmac",
	KeyHMACKey:       "private/hmac_key",
}

// NewEtcdBackend connects to the configured etcd cluster and returns a ready
// backend. The caller must call Close to release the underlying client.
func NewEtcdBackend(cfg EtcdConfig) (*EtcdBackend, error) {
	cfg.applyDefaults()
	clientCfg := clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: cfg.DialTimeout,
		Username:    cfg.Username,
		Password:    cfg.Password,
		TLS:         cfg.TLS,
	}
	cli, err := clientv3.New(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to etcd: %w", err)
	}
	return &EtcdBackend{
		client:  cli,
		owned:   true,
		prefix:  cfg.KeyPrefix,
		timeout: cfg.RequestTimeout,
	}, nil
}

// NewEtcdBackendFromClient wraps an existing etcd client. The backend does
// not take ownership and Close leaves the client open. Primarily used by
// tests that need to share a single embedded etcd across backends.
func NewEtcdBackendFromClient(cli *clientv3.Client, keyPrefix string, requestTimeout time.Duration) *EtcdBackend {
	cfg := EtcdConfig{KeyPrefix: keyPrefix, RequestTimeout: requestTimeout}
	cfg.applyDefaults()
	return &EtcdBackend{
		client:  cli,
		prefix:  cfg.KeyPrefix,
		timeout: cfg.RequestTimeout,
	}
}

// physicalKey translates a logical key into its etcd key. Returns an error
// for unknown logical keys or obviously unsafe components (e.g. "..").
func (b *EtcdBackend) physicalKey(logical string) (string, error) {
	if strings.Contains(logical, "..") {
		return "", fmt.Errorf("invalid key %q: must not contain ..", logical)
	}
	if sub, ok := etcdLayout[logical]; ok {
		return b.prefix + "/" + sub, nil
	}
	switch {
	case strings.HasPrefix(logical, csrPrefix):
		subj := strings.TrimPrefix(logical, csrPrefix)
		return b.prefix + "/requests/" + subj, nil
	case strings.HasPrefix(logical, certPrefix):
		subj := strings.TrimPrefix(logical, certPrefix)
		return b.prefix + "/signed/" + subj, nil
	}
	return "", fmt.Errorf("unknown key %q", logical)
}

func (b *EtcdBackend) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), b.timeout)
}

// EnsureReady verifies connectivity by listing the cluster status. Etcd has
// no directory concept so there is nothing else to prepare.
func (b *EtcdBackend) EnsureReady() error {
	if len(b.client.Endpoints()) == 0 {
		return fmt.Errorf("etcd backend has no endpoints configured")
	}
	ctx, cancel := b.ctx()
	defer cancel()
	_, err := b.client.Status(ctx, b.client.Endpoints()[0])
	if err != nil {
		return fmt.Errorf("etcd not reachable: %w", err)
	}
	return nil
}

// Get returns the (unwrapped) blob at key, wrapping fs.ErrNotExist when absent.
func (b *EtcdBackend) Get(key string) ([]byte, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return nil, err
	}
	ctx, cancel := b.ctx()
	defer cancel()
	resp, err := b.client.Get(ctx, phys)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
	}
	_, data, err := decodeBlob(resp.Kvs[0].Value)
	if err != nil {
		return nil, fmt.Errorf("decoding blob %q: %w", key, err)
	}
	return data, nil
}

// Put writes the blob at key. The BlobKind hint is recorded but has no
// effect on the stored form: etcd access control is managed by the cluster.
func (b *EtcdBackend) Put(key string, data []byte, _ BlobKind) error {
	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}
	ctx, cancel := b.ctx()
	defer cancel()
	_, err = b.client.Put(ctx, phys, string(encodeBlob(time.Now(), data)))
	return err
}

// Delete removes key, wrapping fs.ErrNotExist when the key is absent.
func (b *EtcdBackend) Delete(key string) error {
	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}
	ctx, cancel := b.ctx()
	defer cancel()
	resp, err := b.client.Delete(ctx, phys)
	if err != nil {
		return err
	}
	if resp.Deleted == 0 {
		return &fs.PathError{Op: "delete", Path: key, Err: fs.ErrNotExist}
	}
	return nil
}

// Exists reports whether key is present.
func (b *EtcdBackend) Exists(key string) (bool, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return false, err
	}
	ctx, cancel := b.ctx()
	defer cancel()
	resp, err := b.client.Get(ctx, phys, clientv3.WithCountOnly())
	if err != nil {
		return false, err
	}
	return resp.Count > 0, nil
}

// List returns the logical keys sharing prefix. Only csrPrefix and certPrefix
// are supported; other prefixes yield an error.
func (b *EtcdBackend) List(prefix string) ([]string, error) {
	var subDir, outPrefix string
	switch prefix {
	case csrPrefix:
		subDir = "requests/"
		outPrefix = csrPrefix
	case certPrefix:
		subDir = "signed/"
		outPrefix = certPrefix
	default:
		return nil, fmt.Errorf("unsupported list prefix %q", prefix)
	}
	physPrefix := b.prefix + "/" + subDir
	ctx, cancel := b.ctx()
	defer cancel()
	resp, err := b.client.Get(ctx, physPrefix, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		name := strings.TrimPrefix(string(kv.Key), physPrefix)
		// Skip any accidental sub-namespaces.
		if strings.Contains(name, "/") {
			continue
		}
		out = append(out, outPrefix+name)
	}
	return out, nil
}

// AppendLine atomically appends data to key. Concurrent appends from this
// process are serialised on appendMu; concurrent appends from other processes
// are resolved by an etcd Txn guarded on the key's ModRevision with bounded
// retry on conflict.
func (b *EtcdBackend) AppendLine(key string, data []byte, _ BlobKind) error {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}

	const maxRetries = 8
	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := b.ctx()
		resp, err := b.client.Get(ctx, phys)
		cancel()
		if err != nil {
			return err
		}

		var existing []byte
		var modRev int64
		if len(resp.Kvs) > 0 {
			_, existing, err = decodeBlob(resp.Kvs[0].Value)
			if err != nil {
				return fmt.Errorf("decoding existing blob %q: %w", key, err)
			}
			modRev = resp.Kvs[0].ModRevision
		}

		merged := make([]byte, 0, len(existing)+len(data))
		merged = append(merged, existing...)
		merged = append(merged, data...)
		wrapped := string(encodeBlob(time.Now(), merged))

		ctx2, cancel2 := b.ctx()
		txn := b.client.Txn(ctx2).
			If(clientv3.Compare(clientv3.ModRevision(phys), "=", modRev)).
			Then(clientv3.OpPut(phys, wrapped))
		txnResp, err := txn.Commit()
		cancel2()
		if err != nil {
			return err
		}
		if txnResp.Succeeded {
			return nil
		}
		// Another writer won the race; back off briefly and retry.
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return fmt.Errorf("append to %q failed: too many concurrent writers", key)
}

// ModTime returns the wall-clock timestamp recorded when the blob was last
// written. Returns fs.ErrNotExist-wrapped when the key is absent.
func (b *EtcdBackend) ModTime(key string) (time.Time, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancel := b.ctx()
	defer cancel()
	resp, err := b.client.Get(ctx, phys)
	if err != nil {
		return time.Time{}, err
	}
	if len(resp.Kvs) == 0 {
		return time.Time{}, &fs.PathError{Op: "modtime", Path: key, Err: fs.ErrNotExist}
	}
	mtime, _, err := decodeBlob(resp.Kvs[0].Value)
	if err != nil {
		return time.Time{}, fmt.Errorf("decoding blob %q: %w", key, err)
	}
	return mtime, nil
}

// Close releases the underlying etcd client when owned by this backend.
func (b *EtcdBackend) Close() error {
	if !b.owned || b.client == nil {
		return nil
	}
	return b.client.Close()
}

// encodeBlob prepends an 8-byte big-endian unix-nano mtime to data. Using a
// fixed prefix lets Get and ModTime share a single round-trip.
func encodeBlob(mtime time.Time, data []byte) []byte {
	out := make([]byte, 8+len(data))
	binary.BigEndian.PutUint64(out[:8], uint64(mtime.UnixNano()))
	copy(out[8:], data)
	return out
}

// decodeBlob reverses encodeBlob. Values shorter than 8 bytes are rejected.
func decodeBlob(raw []byte) (time.Time, []byte, error) {
	if len(raw) < 8 {
		return time.Time{}, nil, fmt.Errorf("blob too short: %d bytes", len(raw))
	}
	ns := int64(binary.BigEndian.Uint64(raw[:8]))
	return time.Unix(0, ns), raw[8:], nil
}
