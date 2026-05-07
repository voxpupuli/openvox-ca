// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Trevor Vaughan
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
	"os"
	"time"
)

// ErrDistributedLockingUnsupported signals that a backend advertising the
// Locker interface cannot actually provide a distributed lock in the current
// configuration (typically because it wraps a base backend that has no
// locking support). StorageService.WithLock treats this as a hint to fall
// back to a process-local mutex.
var ErrDistributedLockingUnsupported = errors.New("distributed locking unsupported by this backend")

// BlobKind signals the desired visibility of a stored blob. The filesystem
// backend maps these to file permissions (0600 vs 0644); remote backends
// may ignore it or use the hint to pick a storage namespace.
type BlobKind int

const (
	// BlobPublic marks blobs that may be world-readable (CA cert, CRL, CSRs,
	// signed certs). Filesystem backend writes 0644.
	BlobPublic BlobKind = iota
	// BlobPrivate marks blobs that must stay owner-only (CA key, HMAC key,
	// inventory). Filesystem backend writes 0600.
	BlobPrivate
)

// Logical key names used by StorageService to address backend blobs.
// Backends translate these into physical locations (paths, etcd keys, redis
// keys). Keys of the form "csr/<subject>" and "cert/<subject>" address
// per-subject CSRs and signed certificates.
const (
	KeyCACert        = "ca_cert"
	KeyCAPubKey      = "ca_pubkey"
	KeyCAKey         = "ca_key"
	KeyCRL           = "crl"
	KeySerial        = "serial"
	KeyInventory     = "inventory"
	KeyInventoryHMAC = "inventory_hmac"
	KeyHMACKey       = "hmac_key"

	csrPrefix  = "csr/"
	certPrefix = "cert/"
)

// CSRKey returns the logical key addressing subject's pending CSR.
func CSRKey(subject string) string { return csrPrefix + subject }

// CertKey returns the logical key addressing subject's signed certificate.
func CertKey(subject string) string { return certPrefix + subject }

// KeyPermWarning describes a stored blob whose on-disk permissions are
// looser than expected. Only the filesystem backend produces warnings.
type KeyPermWarning struct {
	Path string
	Mode os.FileMode
}

// Backend is the pluggable storage abstraction that StorageService delegates
// to. Implementations translate the logical key namespace into physical
// storage (filesystem paths, etcd/redis keys, ...).
//
// Get and Delete must return an error that wraps os.ErrNotExist (fs.ErrNotExist)
// when the key does not exist so callers can distinguish absence from failure.
type Backend interface {
	// EnsureReady prepares the backend for use (creates directories,
	// verifies connectivity, etc). Safe to call multiple times.
	EnsureReady() error

	// Get returns the blob at key. Wraps os.ErrNotExist when absent.
	Get(key string) ([]byte, error)

	// Put stores data at key atomically with respect to concurrent readers.
	// kind hints at visibility for backends that care.
	Put(key string, data []byte, kind BlobKind) error

	// Delete removes key. Wraps os.ErrNotExist when absent.
	Delete(key string) error

	// Exists reports whether key is present.
	Exists(key string) (bool, error)

	// List returns all keys with the given prefix. Only the csrPrefix and
	// certPrefix namespaces are listable.
	List(prefix string) ([]string, error)

	// AppendLine appends data to key, creating it if absent. The append is
	// atomic with respect to concurrent AppendLine calls on the same key
	// within a single process. Callers include any trailing newline in data.
	AppendLine(key string, data []byte, kind BlobKind) error

	// ModTime returns the last-modified time of key. Backends that do not
	// track modification time may return the zero time with a nil error.
	// Wraps os.ErrNotExist when absent.
	ModTime(key string) (time.Time, error)

	// Close releases any resources held by the backend.
	Close() error
}

// PathProvider is an optional capability for backends that map keys onto a
// filesystem. Callers use this to obtain a physical path for diagnostic
// messages or legacy APIs that still deal in paths.
type PathProvider interface {
	// Path returns the filesystem path for key, or empty if the key is
	// unknown to this backend.
	Path(key string) string
	// BaseDir returns the root directory under which keys are stored.
	BaseDir() string
}

// Locker is an optional Backend capability that provides a cross-node
// distributed mutex. Backends implement it when they have a natural way
// to coordinate a lock across replicas (etcd's concurrency.Mutex, Redis
// SET NX, etc.). Backends without this capability let StorageService
// fall back to a process-local named mutex, which is sufficient for
// single-node backends like the filesystem one.
//
// The returned Unlocker must be called exactly once, typically via defer.
// Implementations are free to use leases, so a long-delayed Unlock may
// no-op if the lease has already expired.
type Locker interface {
	AcquireLock(ctx context.Context, name string) (Unlocker, error)
}

// Unlocker releases a lock previously acquired via Locker.AcquireLock.
type Unlocker interface {
	Unlock() error
}
