// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Trevor Vaughan
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
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
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

// validateKey is the shared defense-in-depth guard every backend runs on a
// logical key before translating it to a physical key/path. Per-subject keys
// are built from a subject that ca.ValidateSubject has already vetted, so in
// normal operation an unsafe key is impossible; this is the storage layer's
// own boundary check against a caller that constructs a key by another route,
// keeping the four backends from each duplicating the same "..", empty-key
// logic. It rejects an empty key and any key containing ".." (path traversal).
func validateKey(key string) error {
	if key == "" {
		return fmt.Errorf("empty key")
	}
	if strings.Contains(key, "..") {
		return fmt.Errorf("invalid key %q: contains '..'", key)
	}
	return nil
}

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
//
// All operations except Close take a context for caller cancellation and
// deadline propagation. Implementations may further bound a single network
// round-trip with their own per-call timeout (context.WithTimeout on top of
// the caller's ctx); cancellation of the caller's ctx must always propagate.
// The filesystem backend honours ctx only at the start of each call —
// individual syscalls cannot be interrupted mid-flight.
type Backend interface {
	// EnsureReady prepares the backend for use (creates directories,
	// verifies connectivity, etc). Safe to call multiple times.
	EnsureReady(ctx context.Context) error

	// Get returns the blob at key. Wraps os.ErrNotExist when absent.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores data at key atomically with respect to concurrent readers.
	// kind hints at visibility for backends that care.
	Put(ctx context.Context, key string, data []byte, kind BlobKind) error

	// Delete removes key. Wraps os.ErrNotExist when absent.
	Delete(ctx context.Context, key string) error

	// Exists reports whether key is present.
	Exists(ctx context.Context, key string) (bool, error)

	// List returns all keys with the given prefix. Only the csrPrefix and
	// certPrefix namespaces are listable.
	List(ctx context.Context, prefix string) ([]string, error)

	// AppendLine appends data to key, creating it if absent. The append is
	// atomic with respect to concurrent AppendLine calls on the same key
	// within a single process. Callers include any trailing newline in data.
	AppendLine(ctx context.Context, key string, data []byte, kind BlobKind) error

	// ModTime returns the last-modified time of key. Backends that do not
	// track modification time may return the zero time with a nil error.
	// Wraps os.ErrNotExist when absent.
	ModTime(ctx context.Context, key string) (time.Time, error)

	// Close releases any resources held by the backend. Close is intended
	// for shutdown and intentionally does not take a context: cleanup must
	// always run.
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

// InventoryEntry is one issued-certificate record in the inventory. NotBefore
// and NotAfter are stored verbatim as the formatted strings the signing path
// produces, so that rendering entries back to the inventory.txt line is
// byte-identical to the legacy append-only blob.
type InventoryEntry struct {
	Serial    string
	NotBefore string
	NotAfter  string
	Subject   string
}

// Certificate index states recorded in CertRecord.State. Pending CSRs are not
// issued certificates and never appear in the index; the API layer derives the
// "requested" state from the csr/ namespace instead.
//
// CertStateUnknown is reported (never stored as a target state) by a backend
// that cannot maintain per-serial state for a record — today only the etcd
// backend for serials that appeared more than once in a converted legacy
// blob, which its one-to-one by-serial index cannot address. Readers must
// derive such a record's real state from the signed CRL (the authoritative
// artefact) rather than trust the index.
const (
	CertStateSigned  = "signed"
	CertStateRevoked = "revoked"
	CertStateUnknown = "unknown"
)

// CertProjection carries the display fields denormalised from a signed
// certificate into the certificate index. Every field is immutable for the
// life of the certificate (they are fixed at signing), so the projection can
// never drift from the stored PEM — the PEM remains the authoritative
// artefact and the projection is rebuildable from it at any time.
type CertProjection struct {
	// Fingerprint is the SHA-256 digest of the certificate's DER encoding,
	// rendered as colon-separated hex pairs exactly as the status API emits it.
	// An empty Fingerprint marks a record whose projection has not been
	// populated (e.g. rows imported from a legacy inventory blob); readers must
	// fall back to parsing the stored PEM for such records.
	Fingerprint string
	// DNSAltNames holds the certificate's DNS subject alternative names.
	DNSAltNames []string
	// AuthExtensions holds Puppet auth-arc extension values keyed by short
	// name (e.g. "pp_auth_role") or dotted OID when no short name is known.
	AuthExtensions map[string]string
}

// CertRecord is one issued certificate as the certificate index sees it: the
// canonical inventory fields, the denormalised display projection, and the one
// mutable fact — revocation. State/RevokedAt are a projection of the signed
// CRL (the source of truth), written alongside CRL updates and rebuildable
// from it, exactly as the projection fields relate to the PEM. The
// rebuildability guarantee is conditional on the backend being able to
// address the record's serial one-to-one; when it cannot, State is reported
// as CertStateUnknown and the reader consults the CRL directly.
//
// Note the integrity hash chain covers only the canonical InventoryEntry
// fields (via canonicalInventoryLine); the projection columns are not chained.
// That is deliberate: each projection field is independently verifiable
// against a signed artefact (the certificate PEM or the CRL), so chaining
// them would add nothing the artefacts do not already guarantee.
type CertRecord struct {
	InventoryEntry
	CertProjection
	State     string     // CertStateSigned or CertStateRevoked
	RevokedAt *time.Time // nil unless revoked
}

// CertIndex is an optional capability of InventoryStore backends: the backend
// that owns the structured inventory rows can answer certificate-status
// queries from indexed columns instead of forcing the caller into a
// list-certs → read-PEM → parse → CRL-check scan per subject.
//
// The certificate blobs stay authoritative. Statuses reflects the index rows
// joined against blob existence, so a certificate removed by clean/cleanup
// stops being reported even though its historical inventory rows remain.
type CertIndex interface {
	// Statuses returns one record per subject that currently holds a stored
	// signed certificate — the latest issuance for that subject — in subject
	// order. stateFilter narrows the result to CertStateSigned or
	// CertStateRevoked; "" returns all records. Records whose projection has
	// never been populated are returned with an empty Fingerprint so the
	// caller can fall back to the stored PEM for display fields.
	//
	// Note today's in-tree callers always pass "": the statuses handler must
	// see every certified subject to keep its CSR-dedup set complete (it
	// filters per record in Go), and the index repair pass reconciles all
	// records. The filter is nevertheless part of the capability contract —
	// it is the indexed query shape issue #137 fixes the schema for, it is
	// dialect-tested, and direct consumers (CLI/report tooling) can use it
	// without a schema change.
	Statuses(ctx context.Context, stateFilter string) ([]CertRecord, error)

	// SetRevoked marks every index row bearing serial as revoked at the given
	// time. Idempotent: re-marking an already-revoked serial keeps the
	// original revocation time. A serial with no matching row is a no-op, not
	// an error (the CRL may legitimately reference certs the index no longer
	// tracks).
	//
	// SetRevoked, ClearRevoked, and SetProjection may also decline a write —
	// as a logged no-op, not an error — when the implementation cannot
	// unambiguously identify the bearing rows (the etcd backend's one-to-one
	// by-serial index cannot address a serial duplicated in a converted
	// legacy blob). Statuses reports such records with CertStateUnknown so
	// callers know to derive their state from the CRL instead.
	SetRevoked(ctx context.Context, serial string, at time.Time) error

	// ClearRevoked returns every index row bearing serial to the signed
	// state. Used by index repair when a row claims a revocation the signed
	// CRL does not corroborate.
	ClearRevoked(ctx context.Context, serial string) error

	// SetProjection fills the denormalised display fields for every index row
	// bearing serial. Used to backfill rows created from projection-less
	// sources (legacy inventory blobs, direct AppendLine writes).
	SetProjection(ctx context.Context, serial string, proj CertProjection) error
}

// asCertIndex probes b for the CertIndex capability, unwrapping wrapper
// backends the same way asInventoryStore does.
func asCertIndex(b Backend) (CertIndex, bool) {
	for {
		if idx, ok := b.(CertIndex); ok {
			return idx, true
		}
		unwrapper, ok := b.(interface{ Unwrap() Backend })
		if !ok {
			return nil, false
		}
		b = unwrapper.Unwrap()
	}
}

// InventoryStore is an optional Backend capability for storing the certificate
// inventory as structured records (e.g. a SQL table) rather than the single
// append-only KeyInventory blob. Backends that implement it let StorageService
// skip the render → scan → reparse round-trip for appends and subject lookups,
// and verify integrity with a hash chain instead of re-hashing the whole blob.
//
// Backends that do not implement it keep using the KeyInventory blob via
// AppendLine/Get; StorageService selects the path with a type assertion, the
// same way it probes Locker.
//
// A backend that implements InventoryStore must still serve the KeyInventory
// logical key through Get/Put/Exists (rendering rows to inventory.txt text and
// parsing text back to rows) so that Migrate and the OCSP index build remain
// backend-agnostic.
type InventoryStore interface {
	// AppendEntry inserts rec and advances the integrity head atomically.
	// newHead computes the chained head MAC from the previous head (nil when
	// the inventory is empty); the backend MUST invoke it inside the same
	// transaction or lock that serialises appends so the chain cannot fork
	// under concurrent appenders. A nil newHead means integrity is disabled
	// (no HMAC key configured): the backend appends the entry and leaves the
	// stored head untouched. Only rec's canonical InventoryEntry fields feed
	// the chain; the projection/state columns are stored uncovered (see
	// CertRecord).
	AppendEntry(ctx context.Context, rec CertRecord, newHead func(prev []byte) []byte) error

	// Entries returns every entry in issuance order, for the OCSP index build
	// and for chain verification.
	Entries(ctx context.Context) ([]InventoryEntry, error)

	// LatestSerialForSubject returns the most recently issued serial for
	// subject. Wraps os.ErrNotExist when the subject has no entry.
	LatestSerialForSubject(ctx context.Context, subject string) (string, error)

	// PruneEntries removes every entry for which keep returns false and
	// rewrites the integrity head over the survivors. advanceHead advances the
	// hash chain by one entry from the previous head (nil for the first
	// entry); a nil advanceHead means integrity is disabled and the stored
	// head is left untouched.
	//
	// Consistency contract: the stored entries and the stored head must never
	// be observable out of sync by another replica. Implementations need not
	// perform the whole prune in one transaction — the etcd backend commits
	// it in batches, each of which writes a head covering exactly the entries
	// that remain after it — so a prune may partially complete on conflict or
	// error, and an implementation may deliberately bound how much one call
	// removes (etcd caps a call's batches so a huge backlog cannot blow the
	// caller's time budget; deferred matches stay present and consistent for
	// later calls). Whatever happens, the returned slice must contain every
	// entry actually removed (in issuance order), including alongside a
	// non-nil error: callers drive CRL entry removal and blob cleanup from
	// it, and an entry that was durably removed but not returned can never be
	// rediscovered. An empty slice with a nil error means nothing matched.
	PruneEntries(ctx context.Context, keep func(InventoryEntry) bool, advanceHead func(prev []byte, e InventoryEntry) []byte) ([]InventoryEntry, error)
}

// asInventoryStore probes b for the InventoryStore capability, unwrapping
// wrapper backends (e.g. OverlayBackend) that don't implement InventoryStore
// themselves but delegate KeyInventory to a base backend that does. Without
// this, wrapping a SQL backend in OverlayBackend (e.g. via ca_cert_file/
// ca_key_file) would silently downgrade its integrity scheme from the O(1)
// hash chain to a whole-blob HMAC: StorageService picks the scheme via this
// same type assertion in several places, and computing it one way while a
// previously stored value used the other reads back as tampering.
func asInventoryStore(b Backend) (InventoryStore, bool) {
	for {
		if store, ok := b.(InventoryStore); ok {
			return store, true
		}
		unwrapper, ok := b.(interface{ Unwrap() Backend })
		if !ok {
			return nil, false
		}
		b = unwrapper.Unwrap()
	}
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
