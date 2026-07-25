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
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// The etcd backend stores the certificate inventory decomposed into per-entry
// keys rather than the single append-only inventory/data blob (issue #138):
//
//	inventory/entries/<seq>      one JSON-encoded CertRecord per issuance;
//	                             <seq> is zero-padded so a range scan returns
//	                             issuance order
//	inventory/seq                last allocated sequence number; its
//	                             ModRevision doubles as the fence every
//	                             structured mutation is guarded on
//	inventory/by-serial/<serial> serial → seq; its existence is the atomic,
//	                             cluster-wide duplicate-serial guard
//	inventory/by-subject/<subj>  subject → most recently issued serial
//	inventory/data               presence marker (empty payload); also where
//	                             pre-decomposition versions kept the blob
//	inventory/hmac               chained integrity head (blob-encoded, still
//	                             addressed by the KeyInventoryHMAC logical key)
//
// etcd transactions are compare-then-op, not read-compute-write, so every
// mutation is an optimistic loop: read the fence (and whatever else the
// mutation needs), compute the new state in Go, then commit a Txn guarded on
// the fence's ModRevision being unchanged, retrying on conflict. Appending is
// O(1) in the inventory size; the by-serial guard gives etcd the cross-replica
// duplicate-serial guarantee that previously only the SQL backends had.
//
// Index keys (seq, by-serial, by-subject) hold raw values; only blobs
// addressed by logical keys carry the encodeBlob mtime header.
const (
	etcdInvDataSub    = "inventory/data"
	etcdInvHMACSub    = "inventory/hmac"
	etcdInvSeqSub     = "inventory/seq"
	etcdInvEntriesSub = "inventory/entries/"
	etcdInvSerialSub  = "inventory/by-serial/"
	etcdInvSubjectSub = "inventory/by-subject/"
)

// etcdMaxTxnRetries bounds every optimistic-transaction retry loop in this
// backend. Conflicts are transient (another writer won the race), so a bounded
// loop with jittered backoff resolves them; hitting the bound means pathological
// contention and is reported as an error.
const etcdMaxTxnRetries = 16

// Batch sizes for multi-transaction imports and prunes, chosen to keep each
// transaction comfortably under etcd's default --max-txn-ops (128): an import
// costs up to 3 ops per entry (entry, by-serial, by-subject) and a prune up to
// 3 per removed entry, plus a handful of fixed ops (fence, head, marker).
const (
	etcdImportBatch = 32
	etcdPruneBatch  = 30
)

// etcdInventoryRecord is the stored JSON form of a CertRecord. The field set
// is spelled out (rather than marshalling CertRecord directly) so the wire
// format is explicit and stable against refactors of the in-memory structs.
type etcdInventoryRecord struct {
	Serial         string            `json:"serial"`
	NotBefore      string            `json:"not_before"`
	NotAfter       string            `json:"not_after"`
	Subject        string            `json:"subject"`
	Fingerprint    string            `json:"fingerprint,omitempty"`
	DNSAltNames    []string          `json:"dns_alt_names,omitempty"`
	AuthExtensions map[string]string `json:"auth_extensions,omitempty"`
	State          string            `json:"state,omitempty"`
	RevokedAt      *time.Time        `json:"revoked_at,omitempty"`
}

func encodeInventoryRecord(rec CertRecord) ([]byte, error) {
	if rec.State == "" {
		rec.State = CertStateSigned
	}
	return json.Marshal(etcdInventoryRecord{
		Serial:         rec.Serial,
		NotBefore:      rec.NotBefore,
		NotAfter:       rec.NotAfter,
		Subject:        rec.Subject,
		Fingerprint:    rec.Fingerprint,
		DNSAltNames:    rec.DNSAltNames,
		AuthExtensions: rec.AuthExtensions,
		State:          rec.State,
		RevokedAt:      rec.RevokedAt,
	})
}

// decodeInventoryRecord is the inverse of encodeInventoryRecord. Unlike the
// SQL row decoder — which can salvage the canonical columns when only the
// projection JSON is corrupt — the whole record shares one JSON value here, so
// an undecodable value is a hard error: there is nothing left to fall back on.
func decodeInventoryRecord(data []byte) (CertRecord, error) {
	var r etcdInventoryRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return CertRecord{}, fmt.Errorf("decoding inventory record: %w", err)
	}
	rec := CertRecord{
		InventoryEntry: InventoryEntry{
			Serial:    r.Serial,
			NotBefore: r.NotBefore,
			NotAfter:  r.NotAfter,
			Subject:   r.Subject,
		},
		CertProjection: CertProjection{
			Fingerprint:    r.Fingerprint,
			DNSAltNames:    r.DNSAltNames,
			AuthExtensions: r.AuthExtensions,
		},
		State:     r.State,
		RevokedAt: r.RevokedAt,
	}
	if rec.State == "" {
		rec.State = CertStateSigned
	}
	return rec, nil
}

// invPhys returns the physical etcd key for an inventory sub-path.
func (b *EtcdBackend) invPhys(sub string) string { return b.prefix + "/" + sub }

// entryPhys returns the physical key of the entry with sequence number seq.
// Zero-padding to 20 digits (the width of MaxUint64) keeps lexical key order
// identical to numeric issuance order for any realistic sequence value.
func (b *EtcdBackend) entryPhys(seq uint64) string {
	return fmt.Sprintf("%s%020d", b.invPhys(etcdInvEntriesSub), seq)
}

// etcdSeqState is a snapshot of the inventory/seq fence key.
type etcdSeqState struct {
	present bool
	rev     int64  // ModRevision; 0 when absent
	last    uint64 // last allocated sequence number; 0 when absent
}

func decodeSeqState(kvs []*mvccpb.KeyValue) (etcdSeqState, error) {
	if len(kvs) == 0 {
		return etcdSeqState{}, nil
	}
	last, err := strconv.ParseUint(string(kvs[0].Value), 10, 64)
	if err != nil {
		return etcdSeqState{}, fmt.Errorf("parsing inventory sequence counter %q: %w", kvs[0].Value, err)
	}
	return etcdSeqState{present: true, rev: kvs[0].ModRevision, last: last}, nil
}

// seqGuard is the fence comparison every structured mutation includes: the
// inventory/seq key must not have been touched since it was read. Every
// mutating transaction also re-puts the key, so any interleaved append, prune,
// or import invalidates the guard and forces a re-read.
func (b *EtcdBackend) seqGuard(seq etcdSeqState) clientv3.Cmp {
	return clientv3.Compare(clientv3.ModRevision(b.invPhys(etcdInvSeqSub)), "=", seq.rev)
}

// etcdIndexedRecord pairs a decoded record with its sequence number and the
// entry key's ModRevision (for guarded in-place updates).
type etcdIndexedRecord struct {
	seq    uint64
	modRev int64
	rec    CertRecord
}

func decodeIndexedRecords(prefix string, kvs []*mvccpb.KeyValue) ([]etcdIndexedRecord, error) {
	out := make([]etcdIndexedRecord, 0, len(kvs))
	for _, kv := range kvs {
		seq, err := strconv.ParseUint(strings.TrimPrefix(string(kv.Key), prefix), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing inventory entry key %q: %w", kv.Key, err)
		}
		rec, err := decodeInventoryRecord(kv.Value)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", kv.Key, err)
		}
		out = append(out, etcdIndexedRecord{seq: seq, modRev: kv.ModRevision, rec: rec})
	}
	return out, nil
}

func entriesOf(recs []etcdIndexedRecord) []InventoryEntry {
	entries := make([]InventoryEntry, len(recs))
	for i, r := range recs {
		entries[i] = r.rec.InventoryEntry
	}
	return entries
}

// readIndexedRecords returns every inventory entry in issuance order together
// with the fence snapshot, read atomically in a single transaction.
func (b *EtcdBackend) readIndexedRecords(ctx context.Context) ([]etcdIndexedRecord, etcdSeqState, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Txn(ctx).Then(
		clientv3.OpGet(b.invPhys(etcdInvSeqSub)),
		clientv3.OpGet(b.invPhys(etcdInvEntriesSub), clientv3.WithPrefix()),
	).Commit()
	if err != nil {
		return nil, etcdSeqState{}, err
	}
	seq, err := decodeSeqState(resp.Responses[0].GetResponseRange().Kvs)
	if err != nil {
		return nil, etcdSeqState{}, err
	}
	recs, err := decodeIndexedRecords(b.invPhys(etcdInvEntriesSub), resp.Responses[1].GetResponseRange().Kvs)
	if err != nil {
		return nil, etcdSeqState{}, err
	}
	return recs, seq, nil
}

// markerTouchOp returns the Put that (re)writes the inventory presence marker
// with a fresh mtime, mirroring how the SQL backend bumps its marker row.
func (b *EtcdBackend) markerTouchOp() clientv3.Op {
	return clientv3.OpPut(b.invPhys(etcdInvDataSub), string(encodeBlob(time.Now(), []byte{})))
}

// EtcdBackend implements InventoryStore: the inventory lives as one key per
// entry (plus by-serial/by-subject index keys) instead of a single append-only
// blob, making appends O(1) and giving duplicate-serial rejection cluster-wide
// semantics. The inventory/data key remains as a presence marker so the
// KeyInventory logical key keeps its Get/Put/Exists/ModTime behaviour.
var _ InventoryStore = (*EtcdBackend)(nil)

// AppendEntry inserts rec and advances the integrity head atomically. The
// commit transaction is guarded on the fence being unchanged since the read
// (so the head cannot fork under concurrent appenders, including other
// replicas) and on rec's by-serial key not existing (the cluster-wide
// duplicate-serial guarantee). newHead runs in Go between the read and the
// commit; a conflicting writer invalidates the guard and the loop re-reads.
func (b *EtcdBackend) AppendEntry(ctx context.Context, rec CertRecord, newHead func(prev []byte) []byte) error {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	val, err := encodeInventoryRecord(rec)
	if err != nil {
		return err
	}
	serialPhys := b.invPhys(etcdInvSerialSub + rec.Serial)
	subjectPhys := b.invPhys(etcdInvSubjectSub + rec.Subject)

	for attempt := range etcdMaxTxnRetries {
		readCtx, cancel := b.callCtx(ctx)
		resp, err := b.client.Txn(readCtx).Then(
			clientv3.OpGet(b.invPhys(etcdInvSeqSub)),
			clientv3.OpGet(b.invPhys(etcdInvHMACSub)),
			clientv3.OpGet(serialPhys, clientv3.WithCountOnly()),
		).Commit()
		cancel()
		if err != nil {
			return err
		}
		if resp.Responses[2].GetResponseRange().Count > 0 {
			return fmt.Errorf("%w: %s", ErrDuplicateSerial, rec.Serial)
		}
		seq, err := decodeSeqState(resp.Responses[0].GetResponseRange().Kvs)
		if err != nil {
			return err
		}
		next := seq.last + 1

		ops := []clientv3.Op{
			clientv3.OpPut(b.entryPhys(next), string(val)),
			clientv3.OpPut(b.invPhys(etcdInvSeqSub), strconv.FormatUint(next, 10)),
			clientv3.OpPut(serialPhys, strconv.FormatUint(next, 10)),
			clientv3.OpPut(subjectPhys, rec.Serial),
			b.markerTouchOp(),
		}
		if newHead != nil {
			var prev []byte
			if kvs := resp.Responses[1].GetResponseRange().Kvs; len(kvs) > 0 {
				if _, prev, err = decodeBlob(kvs[0].Value); err != nil {
					return fmt.Errorf("decoding inventory head: %w", err)
				}
			}
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvHMACSub), string(encodeBlob(time.Now(), newHead(prev)))))
		}

		txnCtx, cancel2 := b.callCtx(ctx)
		txnResp, err := b.client.Txn(txnCtx).If(
			b.seqGuard(seq),
			clientv3.Compare(clientv3.CreateRevision(serialPhys), "=", 0),
		).Then(ops...).Commit()
		cancel2()
		if err != nil {
			return err
		}
		if txnResp.Succeeded {
			return nil
		}
		// Another writer won the race (or inserted this serial — the re-read
		// at the top of the loop distinguishes the two).
		if err := b.txnBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("inventory append failed: too many concurrent writers")
}

// Entries returns every inventory entry in issuance order.
func (b *EtcdBackend) Entries(ctx context.Context) ([]InventoryEntry, error) {
	recs, _, err := b.readIndexedRecords(ctx)
	if err != nil {
		return nil, err
	}
	return entriesOf(recs), nil
}

// LatestSerialForSubject returns the most recently issued serial for subject,
// wrapping fs.ErrNotExist when the subject has no entry. This is a single
// point read of the by-subject index key.
func (b *EtcdBackend) LatestSerialForSubject(ctx context.Context, subject string) (string, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Get(ctx, b.invPhys(etcdInvSubjectSub+subject))
	if err != nil {
		return "", err
	}
	if len(resp.Kvs) == 0 {
		return "", &fs.PathError{Op: "latest-serial", Path: subject, Err: fs.ErrNotExist}
	}
	return string(resp.Kvs[0].Value), nil
}

// PruneEntries removes the entries for which keep returns false and rewrites
// the integrity head over the survivors. A prune larger than one transaction's
// op budget is split into batches; every intermediate transaction writes a
// head that exactly covers the entries remaining after it, so each committed
// revision is internally consistent (entries and head always match — a
// concurrent verifier on another replica never observes a spurious mismatch,
// and a crash mid-prune leaves a valid, partially-pruned inventory that the
// caller's next prune completes). Interleaved appends invalidate the fence
// and restart the prune from a fresh read.
func (b *EtcdBackend) PruneEntries(ctx context.Context, keep func(InventoryEntry) bool, recomputeHead func(survivors []InventoryEntry) []byte) ([]InventoryEntry, error) {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	for attempt := range etcdMaxTxnRetries {
		removed, conflict, err := b.pruneEntriesOnce(ctx, keep, recomputeHead)
		if err != nil {
			return nil, err
		}
		if !conflict {
			return removed, nil
		}
		if err := b.txnBackoff(ctx, attempt); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("inventory prune failed: too many concurrent writers")
}

func (b *EtcdBackend) pruneEntriesOnce(ctx context.Context, keep func(InventoryEntry) bool, recomputeHead func(survivors []InventoryEntry) []byte) ([]InventoryEntry, bool, error) {
	recs, seq, err := b.readIndexedRecords(ctx)
	if err != nil {
		return nil, false, err
	}

	var removed []etcdIndexedRecord
	for _, r := range recs {
		if !keep(r.rec.InventoryEntry) {
			removed = append(removed, r)
		}
	}
	if len(removed) == 0 {
		return nil, false, nil
	}

	// Fence value: unchanged when present; derived from the highest allocated
	// seq otherwise (possible only for indices built before appends ran).
	seqVal := strconv.FormatUint(seq.last, 10)
	if !seq.present && len(recs) > 0 {
		seqVal = strconv.FormatUint(recs[len(recs)-1].seq, 10)
	}

	seqRev := seq.rev
	for start := 0; start < len(removed); start += etcdPruneBatch {
		batch := removed[start:min(start+etcdPruneBatch, len(removed))]
		// The state this transaction commits is the full record set minus
		// every entry removed up to and including this batch. Later batches'
		// removals are still present, so each committed revision is
		// internally consistent (its head covers exactly its entries).
		afterSet := make([]etcdIndexedRecord, 0, len(recs))
		removedSoFar := make(map[uint64]bool, start+len(batch))
		for _, r := range removed[:start+len(batch)] {
			removedSoFar[r.seq] = true
		}
		for _, r := range recs {
			if !removedSoFar[r.seq] {
				afterSet = append(afterSet, r)
			}
		}

		ops := make([]clientv3.Op, 0, 3*len(batch)+3)
		subjects := make(map[string]bool, len(batch))
		for _, r := range batch {
			ops = append(ops,
				clientv3.OpDelete(b.entryPhys(r.seq)),
				clientv3.OpDelete(b.invPhys(etcdInvSerialSub+r.rec.Serial)),
			)
			subjects[r.rec.Subject] = true
		}
		// Repoint each affected subject's by-subject key at its newest
		// surviving serial, or drop the key when none survives.
		for subject := range subjects {
			latest := ""
			for _, r := range afterSet {
				if r.rec.Subject == subject {
					latest = r.rec.Serial
				}
			}
			key := b.invPhys(etcdInvSubjectSub + subject)
			if latest == "" {
				ops = append(ops, clientv3.OpDelete(key))
			} else {
				ops = append(ops, clientv3.OpPut(key, latest))
			}
		}
		if recomputeHead != nil {
			head := recomputeHead(entriesOf(afterSet))
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvHMACSub), string(encodeBlob(time.Now(), head))))
		}
		ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSeqSub), seqVal))

		txnCtx, cancel := b.callCtx(ctx)
		resp, err := b.client.Txn(txnCtx).If(
			clientv3.Compare(clientv3.ModRevision(b.invPhys(etcdInvSeqSub)), "=", seqRev),
		).Then(ops...).Commit()
		cancel()
		if err != nil {
			return nil, false, err
		}
		if !resp.Succeeded {
			return nil, true, nil
		}
		// Our own put moved the fence; subsequent batches guard on the new
		// revision, which every op in this transaction committed at.
		seqRev = resp.Header.Revision
	}

	out := make([]InventoryEntry, len(removed))
	for i, r := range removed {
		out[i] = r.rec.InventoryEntry
	}
	return out, false, nil
}

// --- KeyInventory blob shim ---
//
// A backend implementing InventoryStore must still serve the KeyInventory
// logical key through Get/Put/Exists (rendering entries to inventory.txt text
// and parsing text back) so Migrate and the OCSP index build stay
// backend-agnostic. Exists and ModTime need no dispatch: the presence marker
// lives at KeyInventory's own physical key.

// getInventory renders the decomposed entries to byte-identical inventory.txt
// text. An inventory that was never initialised (no marker, no entries) wraps
// fs.ErrNotExist. A non-empty legacy blob that decomposeLegacyInventory has
// not yet processed is returned verbatim so reads stay correct even before
// EnsureReady has run.
func (b *EtcdBackend) getInventory(ctx context.Context) ([]byte, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Txn(ctx).Then(
		clientv3.OpGet(b.invPhys(etcdInvDataSub)),
		clientv3.OpGet(b.invPhys(etcdInvEntriesSub), clientv3.WithPrefix()),
	).Commit()
	if err != nil {
		return nil, err
	}
	markerKVs := resp.Responses[0].GetResponseRange().Kvs
	entryKVs := resp.Responses[1].GetResponseRange().Kvs
	if len(markerKVs) == 0 && len(entryKVs) == 0 {
		return nil, &fs.PathError{Op: "get", Path: KeyInventory, Err: fs.ErrNotExist}
	}
	if len(entryKVs) == 0 && len(markerKVs) > 0 {
		_, legacy, err := decodeBlob(markerKVs[0].Value)
		if err != nil {
			return nil, fmt.Errorf("decoding blob %q: %w", KeyInventory, err)
		}
		if len(legacy) > 0 {
			return legacy, nil
		}
	}
	recs, err := decodeIndexedRecords(b.invPhys(etcdInvEntriesSub), entryKVs)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, r := range recs {
		buf.WriteString(canonicalInventoryLine(r.rec.InventoryEntry))
		buf.WriteByte('\n')
	}
	// Normalise to a non-nil empty slice so a touched-but-empty inventory
	// reads as present-but-empty, not absent (matching the other backends).
	if buf.Len() == 0 {
		return []byte{}, nil
	}
	return buf.Bytes(), nil
}

// parseInventoryRecords parses an inventory.txt blob into projection-less
// records. Malformed lines are rejected so a corrupt import fails loudly
// rather than silently dropping entries.
func parseInventoryRecords(data []byte) ([]CertRecord, error) {
	var recs []CertRecord
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, ok := parseInventoryEntry(line)
		if !ok {
			return nil, fmt.Errorf("malformed inventory line %q", line)
		}
		recs = append(recs, CertRecord{InventoryEntry: e, State: CertStateSigned})
	}
	return recs, nil
}

// rejectDuplicateSerials returns ErrDuplicateSerial (wrapped) when two records
// share a serial, mirroring the unique index a SQL import would trip over.
func rejectDuplicateSerials(recs []CertRecord) error {
	seen := make(map[string]bool, len(recs))
	for _, r := range recs {
		if seen[r.Serial] {
			return fmt.Errorf("%w: %s", ErrDuplicateSerial, r.Serial)
		}
		seen[r.Serial] = true
	}
	return nil
}

// putInventory replaces the entire decomposed inventory with the entries
// parsed from data (an inventory.txt blob) and sets the presence marker. Used
// by TouchInventory (empty data) and by Migrate when importing into etcd. The
// integrity head is not touched: Migrate recomputes it afterwards, and a
// touched-but-empty inventory gets its baseline on first verification.
func (b *EtcdBackend) putInventory(ctx context.Context, data []byte) error {
	recs, err := parseInventoryRecords(data)
	if err != nil {
		return err
	}
	if err := rejectDuplicateSerials(recs); err != nil {
		return err
	}

	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	for attempt := range etcdMaxTxnRetries {
		conflict, err := b.replaceInventoryOnce(ctx, recs, -1, false)
		if err != nil {
			return err
		}
		if !conflict {
			return nil
		}
		if err := b.txnBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("inventory replace failed: too many concurrent writers")
}

// replaceInventoryOnce performs one attempt at atomically-observed replacement
// of the decomposed structure with recs: clear everything, import in batches,
// then write the fresh presence marker. Each transaction is guarded on the
// fence; markerRev >= 0 additionally guards every transaction on the marker
// being unchanged (used by decomposeLegacyInventory to detect a
// pre-decomposition replica appending to the blob mid-import). dropHead also
// deletes the stored integrity head in the final transaction, for callers
// whose head is known to be in the wrong scheme. Returns conflict=true when a
// guard failed and the caller should re-read and retry.
func (b *EtcdBackend) replaceInventoryOnce(ctx context.Context, recs []CertRecord, markerRev int64, dropHead bool) (bool, error) {
	readCtx, cancel := b.callCtx(ctx)
	resp, err := b.client.Get(readCtx, b.invPhys(etcdInvSeqSub))
	cancel()
	if err != nil {
		return false, err
	}
	seq, err := decodeSeqState(resp.Kvs)
	if err != nil {
		return false, err
	}

	guards := func(seqRev int64) []clientv3.Cmp {
		cmps := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(b.invPhys(etcdInvSeqSub)), "=", seqRev)}
		if markerRev >= 0 {
			cmps = append(cmps, clientv3.Compare(clientv3.ModRevision(b.invPhys(etcdInvDataSub)), "=", markerRev))
		}
		return cmps
	}

	commit := func(seqRev int64, ops []clientv3.Op) (int64, bool, error) {
		txnCtx, cancel := b.callCtx(ctx)
		defer cancel()
		resp, err := b.client.Txn(txnCtx).If(guards(seqRev)...).Then(ops...).Commit()
		if err != nil {
			return 0, false, err
		}
		if !resp.Succeeded {
			return 0, true, nil
		}
		return resp.Header.Revision, false, nil
	}

	// Clear the existing structure and reset the fence.
	seqRev, conflict, err := commit(seq.rev, []clientv3.Op{
		clientv3.OpDelete(b.invPhys(etcdInvEntriesSub), clientv3.WithPrefix()),
		clientv3.OpDelete(b.invPhys(etcdInvSerialSub), clientv3.WithPrefix()),
		clientv3.OpDelete(b.invPhys(etcdInvSubjectSub), clientv3.WithPrefix()),
		clientv3.OpPut(b.invPhys(etcdInvSeqSub), "0"),
	})
	if err != nil || conflict {
		return conflict, err
	}

	for start := 0; start < len(recs); start += etcdImportBatch {
		batch := recs[start:min(start+etcdImportBatch, len(recs))]
		ops := make([]clientv3.Op, 0, 3*len(batch)+1)
		// One by-subject put per subject per transaction (etcd rejects
		// duplicate keys within a txn); later batches overwrite earlier ones,
		// leaving each subject pointing at its newest serial.
		subjectLatest := make(map[string]string, len(batch))
		for i, rec := range batch {
			val, err := encodeInventoryRecord(rec)
			if err != nil {
				return false, err
			}
			n := uint64(start+i) + 1
			ops = append(ops,
				clientv3.OpPut(b.entryPhys(n), string(val)),
				clientv3.OpPut(b.invPhys(etcdInvSerialSub+rec.Serial), strconv.FormatUint(n, 10)),
			)
			subjectLatest[rec.Subject] = rec.Serial
		}
		for subject, serial := range subjectLatest {
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSubjectSub+subject), serial))
		}
		ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSeqSub), strconv.Itoa(start+len(batch))))
		if seqRev, conflict, err = commit(seqRev, ops); err != nil || conflict {
			return conflict, err
		}
	}

	final := []clientv3.Op{b.markerTouchOp()}
	if dropHead {
		final = append(final, clientv3.OpDelete(b.invPhys(etcdInvHMACSub)))
	}
	final = append(final, clientv3.OpPut(b.invPhys(etcdInvSeqSub), strconv.Itoa(len(recs))))
	_, conflict, err = commit(seqRev, final)
	return conflict, err
}

// appendInventoryLines appends the entries parsed from data as new records,
// without touching the integrity head. StorageService routes inventory appends
// through AppendEntry; this runs only when a caller invokes
// Backend.AppendLine(KeyInventory, ...) directly. Duplicate serials — within
// data or against the stored inventory — are rejected, mirroring the unique
// index the SQL backend's direct-append path trips over.
func (b *EtcdBackend) appendInventoryLines(ctx context.Context, data []byte) error {
	recs, err := parseInventoryRecords(data)
	if err != nil {
		return err
	}
	if err := rejectDuplicateSerials(recs); err != nil {
		return err
	}

	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	for attempt := range etcdMaxTxnRetries {
		readOps := []clientv3.Op{clientv3.OpGet(b.invPhys(etcdInvSeqSub))}
		for _, rec := range recs {
			readOps = append(readOps, clientv3.OpGet(b.invPhys(etcdInvSerialSub+rec.Serial), clientv3.WithCountOnly()))
		}
		readCtx, cancel := b.callCtx(ctx)
		resp, err := b.client.Txn(readCtx).Then(readOps...).Commit()
		cancel()
		if err != nil {
			return err
		}
		for i, rec := range recs {
			if resp.Responses[i+1].GetResponseRange().Count > 0 {
				return fmt.Errorf("%w: %s", ErrDuplicateSerial, rec.Serial)
			}
		}
		seq, err := decodeSeqState(resp.Responses[0].GetResponseRange().Kvs)
		if err != nil {
			return err
		}

		cmps := []clientv3.Cmp{b.seqGuard(seq)}
		ops := make([]clientv3.Op, 0, 3*len(recs)+2)
		subjectLatest := make(map[string]string, len(recs))
		next := seq.last
		for _, rec := range recs {
			next++
			val, err := encodeInventoryRecord(rec)
			if err != nil {
				return err
			}
			serialPhys := b.invPhys(etcdInvSerialSub + rec.Serial)
			cmps = append(cmps, clientv3.Compare(clientv3.CreateRevision(serialPhys), "=", 0))
			ops = append(ops,
				clientv3.OpPut(b.entryPhys(next), string(val)),
				clientv3.OpPut(serialPhys, strconv.FormatUint(next, 10)),
			)
			subjectLatest[rec.Subject] = rec.Serial
		}
		for subject, serial := range subjectLatest {
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSubjectSub+subject), serial))
		}
		if len(recs) > 0 {
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSeqSub), strconv.FormatUint(next, 10)))
		}
		ops = append(ops, b.markerTouchOp())

		txnCtx, cancel2 := b.callCtx(ctx)
		txnResp, err := b.client.Txn(txnCtx).If(cmps...).Then(ops...).Commit()
		cancel2()
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
	return fmt.Errorf("inventory append failed: too many concurrent writers")
}

// deleteInventory removes the presence marker and the whole decomposed
// structure, wrapping fs.ErrNotExist when the inventory was never initialised.
// The integrity head is left in place, matching the SQL backend (it is a
// separate logical key).
func (b *EtcdBackend) deleteInventory(ctx context.Context) error {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(b.invPhys(etcdInvDataSub)), ">", 0)).
		Then(
			clientv3.OpDelete(b.invPhys(etcdInvDataSub)),
			clientv3.OpDelete(b.invPhys(etcdInvSeqSub)),
			clientv3.OpDelete(b.invPhys(etcdInvEntriesSub), clientv3.WithPrefix()),
			clientv3.OpDelete(b.invPhys(etcdInvSerialSub), clientv3.WithPrefix()),
			clientv3.OpDelete(b.invPhys(etcdInvSubjectSub), clientv3.WithPrefix()),
		).Commit()
	if err != nil {
		return err
	}
	if !resp.Succeeded {
		return &fs.PathError{Op: "delete", Path: KeyInventory, Err: fs.ErrNotExist}
	}
	return nil
}

// --- Legacy blob decomposition ---

// decomposeLegacyInventory upgrades an inventory written by a pre-#138 version
// of this backend — a single text blob at inventory/data — into the decomposed
// per-entry structure. It runs from EnsureReady on every start; when there is
// no legacy blob (fresh cluster, or already decomposed) it is a cheap no-op.
//
// The stored integrity head is deleted as part of the import: it was computed
// under the whole-blob HMAC scheme, which does not match the hash chain the
// decomposed inventory verifies under, and the backend does not hold the HMAC
// key needed to translate it. The next VerifyInventoryHMAC re-establishes the
// baseline from the imported entries — meaning tamper detection does not cover
// the decomposition window itself. That trade is documented in
// docs/development/inventory-store.md; run all replicas on the same version so
// no old replica keeps appending to the blob mid-upgrade (such an append is
// detected via the marker guard and the import restarts, but the window only
// closes once the old writers are gone).
func (b *EtcdBackend) decomposeLegacyInventory(ctx context.Context) error {
	legacy, _, err := b.legacyInventoryBlob(ctx)
	if err != nil || legacy == nil {
		return err
	}

	// Serialise the import across replicas starting up together.
	ul, err := b.AcquireLock(ctx, "inventory-decompose")
	if err != nil {
		return fmt.Errorf("locking for inventory decomposition: %w", err)
	}
	defer func() {
		if err := ul.Unlock(); err != nil {
			slog.Warn("Failed to release inventory-decompose lock", "error", err)
		}
	}()

	for attempt := range etcdMaxTxnRetries {
		// (Re-)read under the lock: another replica may have completed the
		// import while we waited, or an old-version replica may have appended.
		legacy, markerRev, err := b.legacyInventoryBlob(ctx)
		if err != nil {
			return err
		}
		if legacy == nil {
			return nil
		}
		recs, err := parseInventoryRecords(legacy)
		if err != nil {
			return fmt.Errorf("decomposing legacy etcd inventory: %w", err)
		}
		conflict, err := b.replaceInventoryOnce(ctx, recs, markerRev, true)
		if err != nil {
			return fmt.Errorf("decomposing legacy etcd inventory: %w", err)
		}
		if !conflict {
			slog.Info("Decomposed legacy etcd inventory blob into per-entry keys", "entries", len(recs))
			return nil
		}
		if err := b.txnBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("decomposing legacy etcd inventory: too many concurrent writers")
}

// legacyInventoryBlob returns the not-yet-decomposed inventory blob and the
// marker's ModRevision, or nil when there is nothing to decompose (no marker,
// an empty marker, or per-entry keys already present).
func (b *EtcdBackend) legacyInventoryBlob(ctx context.Context) ([]byte, int64, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Txn(ctx).Then(
		clientv3.OpGet(b.invPhys(etcdInvDataSub)),
		clientv3.OpGet(b.invPhys(etcdInvEntriesSub), clientv3.WithPrefix(), clientv3.WithCountOnly()),
	).Commit()
	if err != nil {
		return nil, 0, err
	}
	markerKVs := resp.Responses[0].GetResponseRange().Kvs
	if len(markerKVs) == 0 {
		return nil, 0, nil
	}
	_, payload, err := decodeBlob(markerKVs[0].Value)
	if err != nil {
		return nil, 0, fmt.Errorf("decoding legacy inventory blob: %w", err)
	}
	if len(payload) == 0 {
		return nil, 0, nil
	}
	if resp.Responses[1].GetResponseRange().Count > 0 {
		// Should not happen: decomposition empties the marker in the same
		// transaction that finishes the import. Prefer the decomposed entries
		// (they may hold appends newer than the stale blob) but say so.
		slog.Warn("etcd inventory has both a legacy blob and decomposed entries; ignoring the blob")
		return nil, 0, nil
	}
	return payload, markerKVs[0].ModRevision, nil
}
