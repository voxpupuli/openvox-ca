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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
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
// so ModTime can be answered without a second key. The certificate inventory
// is not stored as a blob: it is decomposed into per-entry keys (see
// etcd_inventory.go), and the backend implements InventoryStore and
// CertIndex. Mutations use etcd Txns with ModRevision guards to remain atomic
// across concurrent writers, including those in different processes.
// Distributed locks are provided via AcquireLock using etcd's
// concurrency.Mutex on a lazily-created lease session.
type EtcdBackend struct {
	client   *clientv3.Client
	owned    bool // true when Close should close the client
	prefix   string
	timeout  time.Duration
	appendMu sync.Mutex // serialises inventory mutations within this process

	// pruneBatchHook, when non-nil, runs after each committed prune
	// transaction; mutateRecordHook runs between an index write's entry read
	// and its guarded commit. Test seams only: they let the suite interleave
	// conflicting writes deterministically to exercise the partial-completion
	// and guard-retry paths.
	pruneBatchHook   func()
	mutateRecordHook func()
	// unlockHook, when non-nil, runs before each attempt to delete a lock
	// key; an error from it stands in for a failed delete. Test seam only:
	// it drives the release-retry path without an etcd outage.
	unlockHook func() error

	// session is the lease-backed concurrency session used for distributed
	// mutexes. It is created lazily on the first AcquireLock call and
	// re-created when its lease has expired. Protected by sessionMu.
	sessionMu sync.Mutex
	session   *concurrency.Session
	// sessionCtx is the context every session's keepalive runs on, and
	// Close cancels it. It belongs to the backend, never to a caller: the
	// session is shared by every lock this backend takes, so it outlives
	// the AcquireLock call that happened to create it (#442).
	sessionCtx    context.Context
	sessionCancel context.CancelFunc
	// lockTTL is the session lease's TTL in seconds: etcdLockTTLSeconds,
	// which the suite lowers so a lapse is observable without a 30s wait.
	lockTTL int

	// localLocks holds a *sync.Mutex per lock name. etcd's concurrency.Mutex
	// is *not* safe for re-entry by multiple goroutines sharing a single
	// session (they all inherit the same lease ID and the server treats them
	// as the same holder). We take this per-name local mutex before the
	// distributed one so intra-process contention is resolved locally first.
	localLocks sync.Map
}

// etcdLockTTLSeconds is the lease TTL (in seconds) for the distributed
// lock session. If the holder's openvox-ca process dies without calling
// Unlock, the lock is released automatically after this TTL expires so
// the cluster does not wedge.
const etcdLockTTLSeconds = 30

// errEtcdBackendClosed refuses a lock asked of a backend after Close.
var errEtcdBackendClosed = errors.New("etcd backend is closed")

// etcdLayout maps logical keys to their physical etcd sub-paths. CSR and
// signed-cert keys are handled directly in physicalKey. KeyInventory's
// physical key holds only a presence marker: the inventory itself is
// decomposed into per-entry keys (see etcd_inventory.go).
var etcdLayout = map[string]string{
	KeyCACert:        "ca/cert",
	KeyCAPubKey:      "ca/pubkey",
	KeyCAKey:         "ca/key",
	KeyCRL:           "ca/crl",
	KeySerial:        "serial",
	KeyInventory:     etcdInvDataSub,
	KeyInventoryHMAC: etcdInvHMACSub,
	KeyHMACKey:       "private/hmac_key",
	KeySuperseded:    "superseded",
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
	b := newEtcdBackend(cli, cfg)
	b.owned = true
	return b, nil
}

// NewEtcdBackendFromClient wraps an existing etcd client. The backend does
// not take ownership and Close leaves the client open. Primarily used by
// tests that need to share a single embedded etcd across backends.
func NewEtcdBackendFromClient(cli *clientv3.Client, keyPrefix string, requestTimeout time.Duration) *EtcdBackend {
	cfg := EtcdConfig{KeyPrefix: keyPrefix, RequestTimeout: requestTimeout}
	cfg.applyDefaults()
	return newEtcdBackend(cli, cfg)
}

// newEtcdBackend builds a backend over cli from a defaulted cfg.
func newEtcdBackend(cli *clientv3.Client, cfg EtcdConfig) *EtcdBackend {
	sessionCtx, sessionCancel := context.WithCancel(context.Background())
	return &EtcdBackend{
		client:        cli,
		prefix:        cfg.KeyPrefix,
		timeout:       cfg.RequestTimeout,
		lockTTL:       etcdLockTTLSeconds,
		sessionCtx:    sessionCtx,
		sessionCancel: sessionCancel,
	}
}

// physicalKey translates a logical key into its etcd key. Returns an error
// for unknown logical keys or obviously unsafe components (e.g. "..").
func (b *EtcdBackend) physicalKey(logical string) (string, error) {
	if err := validateKey(logical); err != nil {
		return "", err
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

// callCtx layers the backend's per-call timeout on top of the caller's
// context. Caller cancellation always wins; if the caller has no deadline
// b.timeout becomes the effective bound.
func (b *EtcdBackend) callCtx(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, b.timeout)
}

// EnsureReady verifies connectivity by listing the cluster status (etcd has
// no directory concept so there is nothing to create), then refuses a store
// whose inventory is still a pre-alpha blob: the structured paths assume the
// blob key is only a presence marker.
func (b *EtcdBackend) EnsureReady(ctx context.Context) error {
	if len(b.client.Endpoints()) == 0 {
		return fmt.Errorf("etcd backend has no endpoints configured")
	}
	statusCtx, cancel := b.callCtx(ctx)
	defer cancel()
	if _, err := b.client.Status(statusCtx, b.client.Endpoints()[0]); err != nil {
		return fmt.Errorf("etcd not reachable: %w", err)
	}
	return b.RefuseUndecomposedInventory(ctx)
}

// Get returns the (unwrapped) blob at key, wrapping fs.ErrNotExist when
// absent. The KeyInventory key is served from the decomposed entry keys
// (rendered to inventory.txt text) rather than a stored blob.
func (b *EtcdBackend) Get(ctx context.Context, key string) ([]byte, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return nil, err
	}
	if key == KeyInventory {
		return b.getInventory(ctx)
	}
	ctx, cancel := b.callCtx(ctx)
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
// Putting KeyInventory parses the text and replaces the decomposed entries.
func (b *EtcdBackend) Put(ctx context.Context, key string, data []byte, _ BlobKind) error {
	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}
	if key == KeyInventory {
		return b.putInventory(ctx, data)
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	_, err = b.client.Put(ctx, phys, string(encodeBlob(time.Now(), data)))
	return err
}

// Delete removes key, wrapping fs.ErrNotExist when the key is absent.
// Deleting KeyInventory removes the marker and the decomposed structure.
func (b *EtcdBackend) Delete(ctx context.Context, key string) error {
	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}
	if key == KeyInventory {
		return b.deleteInventory(ctx)
	}
	ctx, cancel := b.callCtx(ctx)
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
func (b *EtcdBackend) Exists(ctx context.Context, key string) (bool, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return false, err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Get(ctx, phys, clientv3.WithCountOnly())
	if err != nil {
		return false, err
	}
	return resp.Count > 0, nil
}

// List returns the logical keys sharing prefix. Only csrPrefix and certPrefix
// are supported; other prefixes yield an error.
func (b *EtcdBackend) List(ctx context.Context, prefix string) ([]string, error) {
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
	ctx, cancel := b.callCtx(ctx)
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
func (b *EtcdBackend) AppendLine(ctx context.Context, key string, data []byte, _ BlobKind) error {
	phys, err := b.physicalKey(key)
	if err != nil {
		return err
	}
	if key == KeyInventory {
		// Inventory is decomposed: parse the lines and append them as entry
		// keys. StorageService routes inventory appends through AppendEntry,
		// so this only runs if a caller uses AppendLine(KeyInventory, ...)
		// directly.
		return b.appendInventoryLines(ctx, data)
	}

	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	for attempt := range etcdMaxTxnRetries {
		getCtx, cancel := b.callCtx(ctx)
		resp, err := b.client.Get(getCtx, phys)
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

		txnCtx, cancel2 := b.callCtx(ctx)
		txn := b.client.Txn(txnCtx).
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
		// Another writer won the race; back off and retry.
		if err := b.txnBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("append to %q failed: too many concurrent writers", key)
}

// txnBackoff sleeps between optimistic-transaction retries. The sleep is a
// growing window with full jitter: jitter decorrelates two writers that would
// otherwise retry in lock-step on the same schedule and keep colliding (the
// cause of spurious "too many concurrent writers" under load). Honours the
// caller's cancellation rather than spinning past it.
func (b *EtcdBackend) txnBackoff(ctx context.Context, attempt int) error {
	window := time.Duration(attempt+1) * 10 * time.Millisecond
	// math/rand/v2 is deliberate here: this value is retry timing only, never a
	// token or key, and the v2 generator is ChaCha8 seeded per-process from OS
	// entropy, so remote writers cannot predict each other's jitter. All
	// security-relevant randomness in this codebase uses crypto/rand.
	// nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
	backoff := time.Duration(rand.Int64N(int64(window))) //nolint:gosec // jitter, not security-sensitive
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(backoff):
		return nil
	}
}

// ModTime returns the wall-clock timestamp recorded when the blob was last
// written. Returns fs.ErrNotExist-wrapped when the key is absent.
func (b *EtcdBackend) ModTime(ctx context.Context, key string) (time.Time, error) {
	phys, err := b.physicalKey(key)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancel := b.callCtx(ctx)
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

// AcquireLock obtains a distributed mutex under <prefix>/locks/<name> using
// etcd's concurrency.Mutex. Local goroutines racing on the same name are
// serialised by a per-name process-local mutex first (concurrency.Mutex is
// not safe for re-entry on the same session), then the distributed mutex
// is taken so only one process in the cluster holds the lock at a time.
func (b *EtcdBackend) AcquireLock(ctx context.Context, name string) (Unlocker, error) {
	local := b.localLockFor(name)
	local.Lock()

	sess, err := b.ensureSession(ctx)
	if err != nil {
		local.Unlock()
		return nil, err
	}
	mu := concurrency.NewMutex(sess, b.prefix+"/locks/"+name)
	if err := mu.Lock(ctx); err != nil {
		// Lock can fail with this session's key still on the server: a
		// commit whose answer is lost to the caller's deadline leaves the
		// key with no revision Mutex.Unlock will act on, and Lock's own
		// cleanup delete can fail. On a lease this backend keeps renewing,
		// that key would queue every other replica behind it, so delete it
		// directly, under the same retry as a failed release. The key is
		// the one tryAcquire writes: the mutex prefix, then the lease ID.
		key := fmt.Sprintf("%s/locks/%s/%x", b.prefix, name, sess.Lease())
		ul := b.newUnlocker(sess, key, func(ctx context.Context) error {
			_, err := b.client.Delete(ctx, key)
			return err
		}, local)
		return nil, fmt.Errorf("locking %q: %w", name, errors.Join(err, ul.Unlock()))
	}
	// Lock only checks that its key still exists, which it does until the
	// lease expires on the server, so it can succeed on a session whose
	// keepalive has already stopped. Granting that lock would let the
	// caller start a read-modify-write that another replica can enter
	// within the TTL. Give the key back and refuse instead.
	select {
	case <-sess.Done():
		ul := b.newUnlocker(sess, mu.Key(), mu.Unlock, local)
		return nil, fmt.Errorf("locking %q: %w", name, errors.Join(concurrency.ErrSessionExpired, ul.Unlock()))
	default:
	}
	return b.newUnlocker(sess, mu.Key(), mu.Unlock, local), nil
}

// newUnlocker returns an unlocker that releases key by calling del, and then
// the process-local mutex.
func (b *EtcdBackend) newUnlocker(sess *concurrency.Session, key string, del func(context.Context) error, local *sync.Mutex) *etcdUnlocker {
	return &etcdUnlocker{sess: sess, key: key, del: del, local: local, timeout: b.timeout, hook: b.unlockHook}
}

// localLockFor returns the process-local mutex for lock name, creating it
// on first use. Mutexes are never removed; the namespace is small and bounded.
func (b *EtcdBackend) localLockFor(name string) *sync.Mutex {
	if v, ok := b.localLocks.Load(name); ok {
		return v.(*sync.Mutex)
	}
	v, _ := b.localLocks.LoadOrStore(name, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// ensureSession returns the current concurrency session, creating or
// replacing it as needed. Safe for concurrent callers. ctx bounds only the
// lease grant: the session runs on the backend's own context, because every
// later caller shares it.
func (b *EtcdBackend) ensureSession(ctx context.Context) (*concurrency.Session, error) {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessionCtx.Err() != nil {
		return nil, errEtcdBackendClosed
	}
	if b.session != nil {
		select {
		case <-b.session.Done():
			// Lease expired; fall through and create a fresh session.
			b.session = nil
		default:
			return b.session, nil
		}
	}
	grantCtx, cancel := b.callCtx(ctx)
	defer cancel()
	lease, err := b.client.Grant(grantCtx, int64(b.lockTTL))
	if err != nil {
		return nil, fmt.Errorf("granting etcd lock lease: %w", err)
	}
	sess, err := concurrency.NewSession(b.client,
		concurrency.WithLease(lease.ID),
		concurrency.WithTTL(b.lockTTL),
		concurrency.WithContext(b.sessionCtx),
	)
	if err != nil {
		return nil, fmt.Errorf("creating etcd lock session: %w", err)
	}
	b.session = sess
	return sess, nil
}

// etcdUnlockRetryInterval is how long a failed lock release waits before
// trying to delete the key again.
const etcdUnlockRetryInterval = 500 * time.Millisecond

// etcdUnlocker deletes one distributed lock key, through del (the mutex's
// Unlock, or a direct delete when Lock failed), then releases the
// process-local mutex acquired in AcquireLock.
//
// If deleting the lock key fails, the key stays on a lease this backend goes
// on renewing, so every other replica would wait for it until this one next
// takes the same name or exits. Unlock therefore keeps retrying in the
// background until the delete succeeds or the session stops renewing (when
// the lease, and the key with it, lapses within the TTL). The local mutex is
// held until then: a re-acquisition of the name by this backend would reuse
// the very same key, so a retry landing after it would delete a live lock.
// In-process callers of that name wait for the retry, as they wait on the
// local mutex anyway.
type etcdUnlocker struct {
	sess    *concurrency.Session
	key     string
	del     func(context.Context) error
	local   *sync.Mutex
	timeout time.Duration
	hook    func() error
}

func (u *etcdUnlocker) Unlock() error {
	if err := u.release(); err != nil {
		go u.retryRelease()
		return err
	}
	u.local.Unlock()
	return nil
}

// release makes one attempt to delete the lock key.
func (u *etcdUnlocker) release() error {
	if u.hook != nil {
		if err := u.hook(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), u.timeout)
	defer cancel()
	return u.del(ctx)
}

// retryRelease retries release until it succeeds or the session lapses,
// then frees the local mutex.
func (u *etcdUnlocker) retryRelease() {
	defer u.local.Unlock()
	t := time.NewTicker(etcdUnlockRetryInterval)
	defer t.Stop()
	for {
		select {
		case <-u.sess.Done():
			slog.Warn("Stopped retrying a distributed lock release: the session has lapsed, and the key with it", "key", u.key)
			return
		case <-t.C:
		}
		if u.release() == nil {
			slog.Info("Released distributed lock after retrying", "key", u.key)
			return
		}
	}
}

// Close releases the underlying etcd client when owned by this backend,
// and always closes the lock session if one was created. Later lock
// acquisitions fail with errEtcdBackendClosed.
func (b *EtcdBackend) Close() error {
	b.sessionMu.Lock()
	if b.session != nil {
		// Before cancelling sessionCtx: Session.Close revokes the lease
		// under it, and a cancelled one would leave every lock this
		// backend holds to wait out the TTL instead. The revoke waits for
		// etcd for up to the TTL, though, so cut it off at the request
		// timeout. That still runs after the HTTP drain, so during an
		// outage it can outlast the launcher's shutdown headroom; the
		// lease then lapses on its TTL, as it would have anyway.
		stop := time.AfterFunc(b.timeout, b.sessionCancel)
		_ = b.session.Close()
		stop.Stop()
		b.session = nil
	}
	if b.sessionCancel != nil {
		b.sessionCancel()
	}
	b.sessionMu.Unlock()
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
//
// The returned data slice is an independent copy of the payload bytes: it
// must not alias raw because backend Get paths return this slice straight
// through to callers, and callers may freely mutate, append, or hand the
// slice to a buffer pool. Aliasing would let those callers corrupt the
// underlying client response buffer.
func decodeBlob(raw []byte) (time.Time, []byte, error) {
	if len(raw) < 8 {
		return time.Time{}, nil, fmt.Errorf("blob too short: %d bytes", len(raw))
	}
	ns := int64(binary.BigEndian.Uint64(raw[:8])) //nolint:gosec // G115: internal mtime round-trip; the same value was written via int64->uint64 by encodeBlob
	return time.Unix(0, ns), bytes.Clone(raw[8:]), nil
}
