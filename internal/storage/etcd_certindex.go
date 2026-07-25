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
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// EtcdBackend implements CertIndex: certificate-status queries are answered
// from the decomposed inventory entries (one range read) instead of reading
// and parsing every stored certificate PEM. See CertIndex for the contract.
var _ CertIndex = (*EtcdBackend)(nil)

// Statuses returns one record per subject that currently holds a stored
// signed certificate (the subject's latest issuance), in subject order,
// optionally narrowed to stateFilter. Unlike SQL there is no indexed query to
// push the latest-per-subject fold into, so the whole entry range is read and
// folded in Go — still a single round-trip against the entries, compared with
// the per-subject PEM read-and-parse the fallback path costs.
func (b *EtcdBackend) Statuses(ctx context.Context, stateFilter string) ([]CertRecord, error) {
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

	recs, _, err := b.readIndexedRecords(ctx)
	if err != nil {
		return nil, err
	}
	// Ascending issuance order: a later record for the same subject wins.
	latest := make(map[string]CertRecord, len(recs))
	for _, r := range recs {
		latest[r.rec.Subject] = r.rec
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
func (b *EtcdBackend) SetRevoked(ctx context.Context, serial string, at time.Time) error {
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
func (b *EtcdBackend) ClearRevoked(ctx context.Context, serial string) error {
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
func (b *EtcdBackend) SetProjection(ctx context.Context, serial string, proj CertProjection) error {
	return b.mutateRecordBySerial(ctx, serial, func(rec *CertRecord) bool {
		rec.CertProjection = proj
		return true
	})
}

// mutateRecordBySerial applies mutate to the entry the by-serial index points
// at, writing it back guarded on the entry's ModRevision so a concurrent
// mutation (e.g. SetRevoked racing SetProjection during index repair) is
// re-read rather than clobbered. mutate returns false to signal a no-op. An
// unknown serial — or a dangling by-serial key — is a no-op, matching the SQL
// backend's zero-rows-updated behaviour.
//
// The entry keys are not part of the integrity chain input (only the
// canonical fields are, and mutate must not touch them), so no fence or head
// update is involved.
func (b *EtcdBackend) mutateRecordBySerial(ctx context.Context, serial string, mutate func(rec *CertRecord) bool) error {
	serialPhys := b.invPhys(etcdInvSerialSub + serial)
	for attempt := range etcdMaxTxnRetries {
		readCtx, cancel := b.callCtx(ctx)
		resp, err := b.client.Get(readCtx, serialPhys)
		cancel()
		if err != nil {
			return err
		}
		if len(resp.Kvs) == 0 {
			return nil
		}
		seq, err := strconv.ParseUint(string(resp.Kvs[0].Value), 10, 64)
		if err != nil {
			return fmt.Errorf("parsing by-serial index for %q: %w", serial, err)
		}

		entryPhys := b.entryPhys(seq)
		entryCtx, cancel2 := b.callCtx(ctx)
		entryResp, err := b.client.Get(entryCtx, entryPhys)
		cancel2()
		if err != nil {
			return err
		}
		if len(entryResp.Kvs) == 0 {
			return nil
		}
		rec, err := decodeInventoryRecord(entryResp.Kvs[0].Value)
		if err != nil {
			return err
		}
		if !mutate(&rec) {
			return nil
		}
		val, err := encodeInventoryRecord(rec)
		if err != nil {
			return err
		}

		txnCtx, cancel3 := b.callCtx(ctx)
		txnResp, err := b.client.Txn(txnCtx).
			If(clientv3.Compare(clientv3.ModRevision(entryPhys), "=", entryResp.Kvs[0].ModRevision)).
			Then(clientv3.OpPut(entryPhys, string(val))).
			Commit()
		cancel3()
		if err != nil {
			return err
		}
		if txnResp.Succeeded {
			return nil
		}
		if err := b.txnBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("updating inventory record for serial %q: too many concurrent writers", serial)
}
