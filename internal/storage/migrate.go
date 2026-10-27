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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// migratableSingleton pairs a fixed (non-enumerable) blob key with the
// visibility it is normally written with, so the destination backend can
// reproduce the correct permissions (e.g. 0600 vs 0644 on the filesystem).
type migratableSingleton struct {
	Key  string
	Kind BlobKind
}

// migratableSingletons lists every fixed blob a CA may hold, in a stable copy
// order (CA material first, then operational state). The kinds mirror how
// StorageService writes each blob. Per-subject CSRs and signed certs are
// enumerated separately via List; per-subject generated private keys are
// intentionally excluded — they always live on local disk
// (StorageService.localPrivateKeyDir) and are never stored in a backend.
var migratableSingletons = []migratableSingleton{
	{KeyCACert, BlobPublic},
	{KeyCAPubKey, BlobPublic},
	{KeyCAKey, BlobPrivate},
	{KeyCRL, BlobPublic},
	{KeySerial, BlobPublic},
	{KeyInventory, BlobPrivate},
	{KeyInventoryHMAC, BlobPrivate},
	{KeyHMACKey, BlobPrivate},
	{KeySuperseded, BlobPrivate},
}

// MigrateOptions tunes a Migrate run.
type MigrateOptions struct {
	// Force permits writing into a destination that already holds CA material.
	// When false, Migrate aborts with ErrDestinationNotEmpty if the destination
	// already has a CA certificate, to avoid clobbering a live CA.
	Force bool

	// Logf, when non-nil, receives one human-readable line per copied blob.
	Logf func(format string, args ...any)

	// AllowUnverifiedSource lets MigrateService copy a source whose inventory
	// does not verify against its stored integrity value, rather than refusing
	// with ErrSourceUnverified. Migrate itself never verifies, so it ignores
	// this.
	AllowUnverifiedSource bool
}

// MigrateReport summarises what a Migrate run copied.
type MigrateReport struct {
	Singletons int // fixed CA/operational blobs copied
	CSRs       int // pending certificate requests copied
	Certs      int // signed certificates copied

	// UnverifiedSource is set by MigrateService when it copied a source
	// inventory it could not verify, and says why: either the source never
	// recorded an integrity value, or AllowUnverifiedSource let a failure
	// through. Empty when the source verified. Whichever it is, the
	// destination's integrity value will vouch for the copy: MigrateService
	// rebuilds it when the destination holds an HMAC key (copied from the
	// source, or already there, as under Force), and otherwise the server's
	// first start writes it, at Warn. A caller should show this to the operator: it
	// is the only record that the value vouches for an inventory nothing
	// checked.
	UnverifiedSource string
}

// Total returns the total number of blobs copied.
func (r MigrateReport) Total() int { return r.Singletons + r.CSRs + r.Certs }

// ErrDestinationNotEmpty is returned by Migrate when the destination backend
// already holds a CA certificate and MigrateOptions.Force is false.
var ErrDestinationNotEmpty = errors.New("destination backend already contains a CA certificate (use --force to overwrite)")

// ErrSourceUnverified is returned by MigrateService when the source inventory
// does not verify against its stored integrity value and
// MigrateOptions.AllowUnverifiedSource is false.
var ErrSourceUnverified = errors.New("refusing to migrate a source inventory that does not verify")

// AllowUnverifiedSourceFlag is the openvox-ca-ctl migrate flag that sets
// MigrateOptions.AllowUnverifiedSource. Defined here because the refusal names
// it, and consumed by the command rather than spelled twice, for the same
// reason as RebuildConfirmFlag.
const AllowUnverifiedSourceFlag = "allow-unverified-source"

// migrateLockName is the distributed-lock name MigrateService holds on both
// backends for the duration of a copy. It deliberately matches the CA
// bootstrap lock (internal/ca uses "bootstrap") so a migration and a server
// bootstrapping or re-initialising the same backend are mutually exclusive,
// and so two migrations cannot run against the same backend at once.
//
// Per-subject signing uses different lock names and is therefore not held off;
// operators should still stop the server during a migration. The exclusion it
// does provide is cross-process on every backend: those without a distributed
// lock fall through to the same-host flock, so a migration and a booting server
// on one host now exclude each other rather than racing. What that costs is
// patience — MigrateService applies no timeout, so a contended lock waits
// indefinitely (see docs/development/locking.md).
const migrateLockName = "bootstrap"

// MigrateService copies src to dst exactly like Migrate, but holds each
// backend's strongest lock for the whole copy, guarding against a concurrent
// migration or a CA bootstrap racing on either backend. Locks are acquired
// source-first, then destination, and released in reverse on return.
//
// Note: pointing both src and dst at the same store would have the two lock
// acquisitions deadlock. On a distributed backend they are separate sessions;
// on a single-node one they are two separate backend values, each with its own
// per-name mutex, so the second blocks on the *flock* and spins in its backoff
// loop rather than parking on a mutex — a live poll, not a blocked goroutine,
// which is what a maintainer reading a stack dump needs to know. Since
// MigrateService applies no timeout, that wait never ends; it announces itself
// on the first refusal ("Waiting for the CA lock"), so interrupt it. Migrating
// a store onto itself is not a supported operation, and this is now the same
// failure on every backend rather than only the distributed ones.
//
// A source this process cannot write to is fine: the same-host lock reports
// itself unsupported rather than failing there, since a store nothing can write
// to has no writer to exclude, and a migration only reads its source.
//
// The source inventory is verified first, under the source's lock and before
// the destination is touched, because the destination's integrity value is
// rebuilt over whatever was copied: without the check, a migration would turn
// a tampered inventory into one that verifies. See verifyMigrationSource for
// what refuses and what does not.
func MigrateService(ctx context.Context, src, dst *StorageService, opts MigrateOptions) (MigrateReport, error) {
	var report MigrateReport
	err := src.WithLock(ctx, migrateLockName, func() error {
		unverified, err := verifyMigrationSource(ctx, src, opts.AllowUnverifiedSource)
		if err != nil {
			return err
		}
		return dst.WithLock(ctx, migrateLockName, func() error {
			r, e := Migrate(ctx, src.Backend(), dst.Backend(), opts)
			report = r
			report.UnverifiedSource = unverified
			if e != nil {
				return e
			}
			// The destination's integrity scheme may differ from the source's
			// (a structured backend uses a hash chain, a blob backend hashes the
			// whole inventory), so the copied inventory_hmac is not meaningful
			// for the destination. Recompute it from the copied inventory.
			return dst.RebuildInventoryHMAC(ctx)
		})
	})
	return report, err
}

// verifyMigrationSource judges the source inventory's integrity before a
// migration copies it. It returns an empty reason when the inventory verifies.
// Otherwise it returns ErrSourceUnverified, naming the reason, unless allow is
// set, in which case it returns the reason for the caller to report.
//
// One state is let through without allow: a store with no HMAC key and no
// integrity value, which never initialised integrity at all (a cadir written
// by OpenVox Server, or a store no server has started against). There is
// nothing to verify it against, and the reason is still returned so the
// operator is told. Every other failure refuses, including a key with no value
// and a value with no key: deleting the value is the cheapest bypass of the
// check, so absence alone is not taken as innocence while a key says
// integrity was once recorded.
//
// It reads through InventoryIntegrityReport, which reports on every backend
// and scheme and writes nothing — a migration never writes its source.
func verifyMigrationSource(ctx context.Context, src *StorageService, allow bool) (string, error) {
	rep, err := src.InventoryIntegrityReport(ctx)
	if err != nil {
		return "", fmt.Errorf("checking the source inventory's integrity: %w", err)
	}

	var reason string
	switch {
	case rep.LegacyUndecomposed:
		// Checked first: the report's other fields describe the empty
		// decomposed rows, not the legacy blob that holds the inventory.
		reason = "the source still holds an undecomposed legacy inventory, which is verified only " +
			"when a server starts against it"
	case rep.KeyState == HMACKeyAbsent && rep.StoredHead == nil:
		return "the source never recorded an inventory integrity value (no HMAC key and no value " +
			"are stored), so there was nothing to verify it against", nil
	case rep.KeyState == HMACKeyAbsent:
		reason = "an inventory integrity value is stored but no HMAC key, so nothing can reproduce it"
	case rep.KeyState == HMACKeyWrongLength:
		reason = "the stored inventory HMAC key is the wrong length, so no stored value can be reproduced"
	case rep.StoredHead == nil:
		reason = "no inventory integrity value is stored, although an HMAC key is"
	case !rep.Verifies:
		reason = "the inventory does not match its stored integrity value (scheme " + rep.Scheme +
			"), so it may have been altered"
	default:
		return "", nil
	}

	if allow {
		return reason, nil
	}
	return "", fmt.Errorf("%w: %s. Run 'openvox-ca rebuild-inventory-hmac' against the source's "+
		"configuration to see its state and what to do about it, or pass --%s to migrate it as it "+
		"stands, which makes the destination vouch for it", ErrSourceUnverified, reason,
		AllowUnverifiedSourceFlag)
}

// Migrate copies every blob held by src into dst, preserving each blob's
// visibility (public/private). It is backend-agnostic: any pair of Backend
// implementations may be combined, enabling filesystem→database,
// database→database and database→filesystem migrations.
//
// Per-subject generated private keys are not copied: they always live on the
// local filesystem outside any backend.
//
// Migrate is not transactional. On error it returns the blobs copied so far in
// the report. Re-running is safe: copies overwrite matching keys idempotently.
func Migrate(ctx context.Context, src, dst Backend, opts MigrateOptions) (MigrateReport, error) {
	var report MigrateReport

	if err := dst.EnsureReady(ctx); err != nil {
		return report, fmt.Errorf("preparing destination: %w", err)
	}

	if !opts.Force {
		exists, err := dst.Exists(ctx, KeyCACert)
		if err != nil {
			return report, fmt.Errorf("checking destination for existing CA: %w", err)
		}
		if exists {
			return report, ErrDestinationNotEmpty
		}
	}

	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	// Whether each end keeps the inventory as structured records or as the
	// whole blob; copyKey converts the inventory when they differ.
	_, srcStructured := asInventoryStore(src)
	_, dstStructured := asInventoryStore(dst)

	// copyKey copies one blob; a key absent in the source is skipped (not an
	// error) so partially-populated CAs migrate cleanly. The inventory is the
	// one blob it converts: from the filesystem's OpenVox Server form to the
	// structured backends' canonical form (canonicaliseBlobInventory), or the
	// other way (openVoxBlobInventory).
	copyKey := func(key string, kind BlobKind) (bool, error) {
		data, err := src.Get(ctx, key)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, fmt.Errorf("reading %q from source: %w", key, err)
		}
		if key == KeyInventory && !srcStructured && dstStructured {
			data = canonicaliseBlobInventory(data)
		}
		if key == KeyInventory && srcStructured && !dstStructured {
			data = openVoxBlobInventory(data)
		}
		if err := dst.Put(ctx, key, data, kind); err != nil {
			return false, fmt.Errorf("writing %q to destination: %w", key, err)
		}
		// %q, not %s: Logf is operator-facing and its only implementation
		// (cmd/openvox-ca-ctl/migrate.go) writes the line to stderr with no
		// escaping. Keys are built from source directory entry names
		// (filesystem.go's listing trims ".pem" off e.Name()), and migrating a
		// foreign or legacy CA directory is exactly the case where a filename
		// could carry a newline and forge a second progress line. Both Get and
		// Put above run validateKey, which refuses a control character and a
		// name that is not valid UTF-8, so on every shipped backend no such key
		// reaches this line; %q is the second layer, and one of the two
		// sanitisers CodeQL's go/log-injection query itself recognises. A spec
		// reaches it through a test double, so it stays pinned.
		logf("copied %q (%d bytes)", key, len(data))
		return true, nil
	}

	for _, s := range migratableSingletons {
		copied, err := copyKey(s.Key, s.Kind)
		if err != nil {
			return report, err
		}
		if copied {
			report.Singletons++
		}
	}

	csrKeys, err := src.List(ctx, csrPrefix)
	if err != nil {
		return report, fmt.Errorf("listing CSRs in source: %w", err)
	}
	for _, key := range csrKeys {
		copied, err := copyKey(key, BlobPublic)
		if err != nil {
			return report, err
		}
		if copied {
			report.CSRs++
		}
	}

	certKeys, err := src.List(ctx, certPrefix)
	if err != nil {
		return report, fmt.Errorf("listing signed certificates in source: %w", err)
	}
	for _, key := range certKeys {
		copied, err := copyKey(key, BlobPublic)
		if err != nil {
			return report, err
		}
		if copied {
			report.Certs++
		}
	}

	return report, nil
}

// canonicaliseBlobInventory rewrites a whole-blob inventory into the canonical
// lines a structured backend stores, for a migration out of the filesystem
// backend. That inventory may hold OpenVox Server's lines ("0x0002 ...
// /CN=agent") beside this CA's ("2 ... /agent"), and the structured backends
// key their rows, their indexes and their hash chain on this CA's form, so each
// line is read the way the filesystem backend reads it (parseBlobInventoryEntry)
// and rendered canonically. A line that does not parse is passed through
// unchanged, for the destination to refuse as loudly as it always has.
//
// This is the conversion step, and it is the only one: the filesystem backend
// itself never rewrites a line, and a migration between two structured backends
// copies their already-canonical rendering as it is. openVoxBlobInventory is the
// same step in the other direction.
func canonicaliseBlobInventory(data []byte) []byte {
	var buf strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if e, ok := parseBlobInventoryEntry(line); ok {
			line = canonicalInventoryLine(e)
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	return []byte(buf.String())
}

// openVoxBlobInventory renders a structured backend's canonical inventory as
// OpenVox Server writes its own, for a migration onto the filesystem backend,
// so that the cadir it produces can be handed to OpenVox Server like any other.
// Lines go through openVoxInventoryLine, the one place that format is produced.
func openVoxBlobInventory(data []byte) []byte {
	var buf strings.Builder
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if e, ok := parseInventoryEntry(line); ok {
			line = openVoxInventoryLine(e, line)
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	return []byte(buf.String())
}
