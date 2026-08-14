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
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBackend implements CertIndex: certificate-status queries are answered
// from the decomposed inventory entries (one hash read) instead of reading and
// parsing every stored certificate PEM. See CertIndex for the contract.
var _ CertIndex = (*RedisBackend)(nil)

// Statuses returns one record per subject that currently holds a stored signed
// certificate (the subject's latest issuance), in subject order, optionally
// narrowed to stateFilter. Like etcd — and unlike SQL — there is no indexed
// query to push the latest-per-subject fold into, so the whole entry hash is
// read and folded in Go; that is still a single round-trip, compared with the
// per-subject PEM read-and-parse the fallback path costs.
func (b *RedisBackend) Statuses(ctx context.Context, stateFilter string) ([]CertRecord, error) {
	certKeys, err := b.List(ctx, certPrefix)
	if err != nil {
		return nil, err
	}
	if len(certKeys) == 0 {
		return nil, nil
	}
	stored := make(map[string]bool, len(certKeys))
	for _, key := range certKeys {
		stored[strings.TrimPrefix(key, certPrefix)] = true
	}

	// Entries and the by-serial index are read in ONE MULTI/EXEC: read
	// separately, a prune deleting a duplicated serial's last bearer between
	// the two reads would yield a snapshot containing the bearer without its
	// sentinel, briefly presenting the record's stale stored state as
	// authoritative.
	callCtx, cancel := b.callCtx(ctx)
	defer cancel()

	var entriesCmd, serialsCmd *redis.MapStringStringCmd
	if _, err := b.client.TxPipelined(callCtx, func(p redis.Pipeliner) error {
		entriesCmd = p.HGetAll(callCtx, b.invPhys(redisInvEntriesSub))
		serialsCmd = p.HGetAll(callCtx, b.invPhys(redisInvSerialSub))
		return nil
	}); err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	entryFields, err := entriesCmd.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}
	recs, err := decodeEntryFields(entryFields)
	if err != nil {
		return nil, err
	}
	serialFields, err := serialsCmd.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	// Ascending issuance order: a later record for the same subject wins.
	// Serials whose by-serial field carries the ambiguity sentinel (imported
	// legacy duplicates) cannot have index-maintained state —
	// mutateRecordBySerial refuses writes for them — so report those records
	// as CertStateUnknown, which tells the reader to derive state from the
	// signed CRL instead of trusting a value that revocation writes were never
	// able to update. The sentinel, not a live duplicate count, is the source
	// of truth: it survives a partial prune, so a lone remaining bearer whose
	// writes were refused while it was ambiguous stays unknown until the
	// serial is fully released.
	latest := make(map[string]CertRecord, len(recs))
	for _, r := range recs {
		rec := r.rec
		if serialFields[rec.Serial] == serialAmbiguous {
			rec.State = CertStateUnknown
			rec.RevokedAt = nil
		}
		latest[rec.Subject] = rec
	}

	subjects := make([]string, 0, len(latest))
	for subject := range latest {
		if stored[subject] {
			subjects = append(subjects, subject)
		}
	}
	sort.Strings(subjects)

	records := make([]CertRecord, 0, len(subjects))
	for _, subject := range subjects {
		rec := latest[subject]
		if stateFilter != "" && rec.State != stateFilter {
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}

// SetRevoked marks the entry bearing serial as revoked at the given time.
// Idempotent: an already-revoked entry keeps its original revocation time. A
// serial with no entry is a no-op, not an error.
func (b *RedisBackend) SetRevoked(ctx context.Context, serial string, at time.Time) error {
	return b.mutateRecordBySerial(ctx, serial, func(rec *CertRecord) bool {
		if rec.State == CertStateRevoked {
			return false
		}
		rec.State = CertStateRevoked
		utc := at.UTC()
		rec.RevokedAt = &utc
		return true
	})
}

// ClearRevoked returns the entry bearing serial to the signed state.
func (b *RedisBackend) ClearRevoked(ctx context.Context, serial string) error {
	return b.mutateRecordBySerial(ctx, serial, func(rec *CertRecord) bool {
		if rec.State == CertStateSigned && rec.RevokedAt == nil {
			return false
		}
		rec.State = CertStateSigned
		rec.RevokedAt = nil
		return true
	})
}

// SetProjection fills the denormalised display fields for the entry bearing
// serial. Used to backfill records created from projection-less sources
// (legacy blob imports, direct AppendLine writes).
func (b *RedisBackend) SetProjection(ctx context.Context, serial string, proj CertProjection) error {
	return b.mutateRecordBySerial(ctx, serial, func(rec *CertRecord) bool {
		rec.CertProjection = proj
		return true
	})
}

// mutateRecordBySerial applies mutate to the entry the by-serial index points
// at, writing it back only if the stored value is still the one that was
// decoded, so a concurrent mutation (e.g. SetRevoked racing SetProjection
// during index repair) is re-read rather than clobbered. mutate returns false
// to signal a no-op. An unknown serial — or a dangling by-serial field — is a
// no-op, matching the SQL backend's zero-rows-updated behaviour.
//
// The entry values are not part of the integrity chain input (only the
// canonical fields are, and mutate must not touch them), so no fence or head
// update is involved.
func (b *RedisBackend) mutateRecordBySerial(ctx context.Context, serial string, mutate func(rec *CertRecord) bool) error {
	for attempt := range redisMaxRetries {
		seq, err := b.serialSeq(ctx, serial)
		if err != nil || seq == "" {
			return err
		}

		readCtx, cancel := b.callCtx(ctx)
		current, err := b.client.HGet(readCtx, b.invPhys(redisInvEntriesSub), seq).Result()
		cancel()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil
			}
			return err
		}
		rec, err := decodeInventoryRecord([]byte(current))
		if err != nil {
			return err
		}
		if !mutate(&rec) {
			return nil
		}
		if b.mutateRecordHook != nil {
			b.mutateRecordHook()
		}
		val, err := encodeInventoryRecord(rec)
		if err != nil {
			return err
		}

		status, _, err := b.runInvScript(ctx, b.invSetRecordScript, seq, current, string(val))
		if err != nil {
			return err
		}
		switch status {
		case redisResultOK, redisResultMissing:
			// Missing: the entry was pruned between the read and the write.
			// The SQL backend's UPDATE would have matched zero rows for the
			// same reason, and treats it the same way.
			return nil
		case redisResultConflict:
			if err := b.scriptBackoff(ctx, attempt); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected inventory record write result %q", status)
		}
	}
	return fmt.Errorf("updating inventory record for serial %q: too many concurrent writers", serial)
}

// serialSeq resolves a serial to the sequence number of the entry bearing it.
// It returns "" for an unknown serial and for one carrying the ambiguity
// sentinel, both of which make the caller a no-op.
func (b *RedisBackend) serialSeq(ctx context.Context, serial string) (string, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	seq, err := b.client.HGet(ctx, b.invPhys(redisInvSerialSub), serial).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", nil
		}
		return "", err
	}
	if seq == serialAmbiguous {
		// The serial appears on several imported legacy records; applying the
		// write through the one-to-one index would land it on an arbitrary
		// bearer (e.g. another subject's record receiving this certificate's
		// fingerprint). Refuse rather than alias.
		slog.Warn("Certificate-index write skipped: serial is duplicated in the imported legacy inventory",
			"serial", serial)
		return "", nil
	}
	return seq, nil
}
