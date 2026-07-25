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
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
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

// etcdPruneMaxBatchesPerCall bounds one PruneEntries call to this many
// committed batches (currently 900 entries). Each batch writes an
// intermediate head folded over the entries that remain, so a prune's total
// hashing cost grows with batches × survivors; an unbounded call over a large
// backlog could not finish inside the caller's lock budget. Deferred entries
// stay present and consistent and are removed by subsequent calls (the
// cleanup job runs periodically), which the PruneEntries contract permits.
const etcdPruneMaxBatchesPerCall = 30

// etcdSerialAmbiguous is the by-serial index value recorded for a serial that
// appears on more than one imported record (possible only in a legacy blob:
// blob backends never had a cluster-wide uniqueness guarantee, and every
// other write path rejects duplicates). The one-to-one index cannot name all
// bearers, so instead of silently aliasing certificate-index writes onto an
// arbitrary record, the sentinel makes them explicit no-ops while still
// keeping the serial reserved against reissue.
const etcdSerialAmbiguous = "ambiguous"

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

// etcdIndexedRecord pairs a decoded record with its sequence number.
type etcdIndexedRecord struct {
	seq uint64
	rec CertRecord
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
		out = append(out, etcdIndexedRecord{seq: seq, rec: rec})
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
//
// Per the interface contract, the returned slice contains every entry that
// was durably removed — accumulated across batches and retries, and returned
// even alongside a non-nil error — so the caller's CRL/blob cleanup never
// misses an entry that a partially-completed prune already deleted. One call
// removes at most etcdPruneMaxBatchesPerCall batches' worth of entries;
// matches beyond that stay in the inventory for later calls (the interface
// contract permits bounding, and the periodic cleanup job converges).
func (b *EtcdBackend) PruneEntries(ctx context.Context, keep func(InventoryEntry) bool, advanceHead func(prev []byte, e InventoryEntry) []byte) ([]InventoryEntry, error) {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	// Committed removals accumulate across attempts: a retry re-reads the
	// inventory, so entries deleted by an earlier attempt's batches no longer
	// appear in its view and would otherwise vanish from the result.
	var all []etcdIndexedRecord
	finish := func() []InventoryEntry {
		if len(all) == 0 {
			return nil
		}
		// A conflicting append may add (and a later attempt remove) entries
		// newer than an earlier attempt's, so restore issuance order globally.
		sort.Slice(all, func(i, j int) bool { return all[i].seq < all[j].seq })
		return entriesOf(all)
	}

	for attempt := range etcdMaxTxnRetries {
		committed, conflict, err := b.pruneEntriesOnce(ctx, keep, advanceHead)
		all = append(all, committed...)
		if err != nil {
			return finish(), err
		}
		if !conflict {
			return finish(), nil
		}
		if err := b.txnBackoff(ctx, attempt); err != nil {
			return finish(), err
		}
	}
	return finish(), fmt.Errorf("inventory prune failed: too many concurrent writers")
}

// pruneEntriesOnce performs one prune attempt. It returns the records whose
// delete transactions committed (possibly a subset when a later batch hits a
// fence conflict or an error), plus whether the caller should re-read and
// retry.
//
// Batches are taken from the tail of the removal list, newest first. That
// ordering makes intermediate heads cheap: after committing the batches from
// removal index s onward, every entry older than removed[s] is still intact
// (earlier removals are in not-yet-processed batches), and everything from
// removed[s] onward is survivors only. Each intermediate head is therefore a
// cached prefix fold over the original entries resumed across the survivor
// tail — one O(n) checkpoint pass plus the survivor tails, instead of a full
// O(n) refold per batch (quadratic when a large expiry cleanup prunes most of
// a large inventory).
func (b *EtcdBackend) pruneEntriesOnce(ctx context.Context, keep func(InventoryEntry) bool, advanceHead func(prev []byte, e InventoryEntry) []byte) ([]etcdIndexedRecord, bool, error) {
	recs, seq, err := b.readIndexedRecords(ctx)
	if err != nil {
		return nil, false, err
	}

	var removed []etcdIndexedRecord
	survivors := make([]etcdIndexedRecord, 0, len(recs))
	for _, r := range recs {
		if keep(r.rec.InventoryEntry) {
			survivors = append(survivors, r)
		} else {
			removed = append(removed, r)
		}
	}
	if len(removed) == 0 {
		return nil, false, nil
	}

	// Fence value: unchanged when present; derived from the highest allocated
	// seq otherwise (possible only for indices built before appends ran).
	seqVal := strconv.FormatUint(seq.last, 10)
	if !seq.present {
		seqVal = strconv.FormatUint(recs[len(recs)-1].seq, 10)
	}

	// Batch start offsets into removed, ascending; batches run tail-first.
	var starts []int
	for s := 0; s < len(removed); s += etcdPruneBatch {
		starts = append(starts, s)
	}
	// Bound one call's work (see etcdPruneMaxBatchesPerCall). Batches run
	// tail-first, so keeping the last starts removes the newest matches and
	// defers the older ones — which stay present and consistent — to later
	// calls. Never silently: the caller's log should explain a short count.
	if len(starts) > etcdPruneMaxBatchesPerCall {
		starts = starts[len(starts)-etcdPruneMaxBatchesPerCall:]
		slog.Info("Bounding inventory prune to keep it inside the caller's time budget; later runs will remove the rest",
			"removing", len(removed)-starts[0], "deferred", starts[0])
	}

	// One forward fold over the full record set, checkpointing the chain
	// value just before each batch's oldest removed entry. For the state
	// committed by the batch starting at removed[s], that checkpoint covers
	// exactly the entries older than removed[s] (all still present).
	var prefixAt map[int][]byte
	if advanceHead != nil {
		prefixAt = make(map[int][]byte, len(starts))
		var head []byte
		si := 0
		for _, r := range recs {
			if si < len(starts) && removed[starts[si]].seq == r.seq {
				prefixAt[starts[si]] = head
				si++
			}
			head = advanceHead(head, r.rec.InventoryEntry)
		}
	}

	// Per-subject indices for repointing by-subject keys without rescanning
	// the whole record set per batch.
	subjAll := make(map[string][]etcdIndexedRecord)
	for _, r := range recs {
		subjAll[r.rec.Subject] = append(subjAll[r.rec.Subject], r)
	}
	subjSurvLast := make(map[string]etcdIndexedRecord, len(survivors))
	for _, r := range survivors {
		subjSurvLast[r.rec.Subject] = r
	}

	seqRev := seq.rev
	committedFrom := len(removed) // removal index from which deletes have committed
	for si := len(starts) - 1; si >= 0; si-- {
		s := starts[si]
		batch := removed[s:min(s+etcdPruneBatch, len(removed))]
		cutSeq := removed[s].seq

		ops := make([]clientv3.Op, 0, 3*len(batch)+3)
		subjects := make(map[string]bool, len(batch))
		for _, r := range batch {
			ops = append(ops,
				clientv3.OpDelete(b.entryPhys(r.seq)),
				clientv3.OpDelete(b.invPhys(etcdInvSerialSub+r.rec.Serial)),
			)
			subjects[r.rec.Subject] = true
		}
		// Repoint each affected subject at its newest entry still present in
		// the committed state: entries older than the cut are all present, and
		// from the cut onward only survivors are.
		for subject := range subjects {
			var latest string
			var latestSeq uint64
			entries := subjAll[subject]
			i := sort.Search(len(entries), func(i int) bool { return entries[i].seq >= cutSeq })
			if i > 0 {
				latest = entries[i-1].rec.Serial
				latestSeq = entries[i-1].seq
			}
			if lv, ok := subjSurvLast[subject]; ok && lv.seq > cutSeq && lv.seq > latestSeq {
				latest = lv.rec.Serial
			}
			key := b.invPhys(etcdInvSubjectSub + subject)
			if latest == "" {
				ops = append(ops, clientv3.OpDelete(key))
			} else {
				ops = append(ops, clientv3.OpPut(key, latest))
			}
		}
		if advanceHead != nil {
			head := prefixAt[s]
			j := sort.Search(len(survivors), func(i int) bool { return survivors[i].seq > cutSeq })
			for _, r := range survivors[j:] {
				head = advanceHead(head, r.rec.InventoryEntry)
			}
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvHMACSub), string(encodeBlob(time.Now(), head))))
		}
		ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSeqSub), seqVal))

		txnCtx, cancel := b.callCtx(ctx)
		resp, err := b.client.Txn(txnCtx).If(
			clientv3.Compare(clientv3.ModRevision(b.invPhys(etcdInvSeqSub)), "=", seqRev),
		).Then(ops...).Commit()
		cancel()
		if err != nil {
			return removed[committedFrom:], false, err
		}
		if !resp.Succeeded {
			return removed[committedFrom:], true, nil
		}
		// Our own put moved the fence; subsequent batches guard on the new
		// revision, which every op in this transaction committed at.
		seqRev = resp.Header.Revision
		committedFrom = s
		if b.pruneBatchHook != nil {
			b.pruneBatchHook()
		}
	}
	// All selected batches committed; entries before starts[0] (if any) were
	// deferred by the per-call bound and remain in the inventory.
	return removed[starts[0]:], false, nil
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
		if b.importBatchHook != nil {
			b.importBatchHook()
		}
		return resp.Header.Revision, false, nil
	}

	// Serials appearing on more than one record cannot be pointed at through
	// the one-to-one by-serial index without picking a wrong record for the
	// others; mark them ambiguous so index writes refuse instead of aliasing.
	dupSerials := make(map[string]bool)
	for _, serial := range duplicateSerials(recs) {
		dupSerials[serial] = true
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
		// One put per index key per transaction (etcd rejects duplicate keys
		// within a txn); later occurrences — in the same batch via these maps,
		// across batches via plain overwrite — win, leaving each subject
		// pointing at its newest serial. A serial borne by several records
		// gets the ambiguity sentinel instead of a sequence number.
		subjectLatest := make(map[string]string, len(batch))
		serialValue := make(map[string]string, len(batch))
		for i, rec := range batch {
			val, err := encodeInventoryRecord(rec)
			if err != nil {
				return false, err
			}
			n := uint64(start+i) + 1
			ops = append(ops, clientv3.OpPut(b.entryPhys(n), string(val)))
			if dupSerials[rec.Serial] {
				serialValue[rec.Serial] = etcdSerialAmbiguous
			} else {
				serialValue[rec.Serial] = strconv.FormatUint(n, 10)
			}
			subjectLatest[rec.Subject] = rec.Serial
		}
		for serial, value := range serialValue {
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSerialSub+serial), value))
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
	// This path appends all lines in one transaction (unlike imports and
	// prunes, which batch), so bound it explicitly rather than let the etcd
	// server reject an oversized transaction with an opaque error.
	if len(recs) > etcdImportBatch {
		return fmt.Errorf("appending %d inventory lines in one call exceeds the etcd transaction budget of %d (bounded by the server's --max-txn-ops, default 128); append in smaller chunks", len(recs), etcdImportBatch)
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
// The blob stays authoritative until the import completes: the marker is only
// emptied by the import's final transaction, so an interrupted import (crash,
// etcd error, Ctrl-C) leaves the blob intact and the next start detects the
// partial entry set as a resumable state and redoes the import from the blob.
// Entry keys that are NOT a prefix of the blob mean something else wrote to
// the decomposed structure while the blob still had content — a mixed-version
// cluster — and that is refused with an explicit error rather than guessing
// which side to keep.
//
// Integrity: when both the HMAC key and a stored head are present, the blob's
// whole-blob HMAC is verified before it is trusted, and a mismatch fails
// startup with ErrInventoryTampered exactly as the pre-decomposition code
// would have. The (verified) head is then deleted as part of the import — it
// is not a hash-chain head, so it cannot carry over — and the next
// VerifyInventoryHMAC re-establishes the baseline from the imported entries.
// Only the import window itself is therefore uncovered; run all replicas on
// the same version so no old replica keeps appending to the blob mid-upgrade
// (such an append is detected via the marker guard and the import restarts,
// but the window only closes once the old writers are gone).
func (b *EtcdBackend) decomposeLegacyInventory(ctx context.Context) error {
	// Cheap probe first: on every start after the one-time conversion this
	// path must not transfer the whole inventory keyspace, so read only the
	// marker to decide whether the expensive state read is needed at all.
	payload, err := b.legacyMarkerPayload(ctx)
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		// Nothing to import — but an upgraded CA whose inventory was empty
		// still carries a whole-blob head that no import will ever drop.
		return b.convertLegacyEmptyHead(ctx)
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
		state, err := b.legacyInventoryState(ctx)
		if err != nil {
			return err
		}
		if len(state.blob) == 0 {
			return nil
		}
		recs, err := parseInventoryRecords(state.blob)
		if err != nil {
			return fmt.Errorf("decomposing legacy etcd inventory: %w", err)
		}
		if len(state.entries) > 0 {
			if !recordsArePrefixOf(state.entries, recs) {
				return fmt.Errorf("etcd inventory holds both a non-empty legacy blob and decomposed entries that do not match it; " +
					"this usually means a pre-decomposition replica wrote to the blob after another replica upgraded. " +
					"Refusing to guess: inspect inventory/data and inventory/entries/ under the key prefix and remove whichever is stale")
			}
			slog.Info("Resuming interrupted etcd inventory decomposition", "imported", len(state.entries), "total", len(recs))
		}
		if err := b.verifyLegacyInventoryMAC(ctx, state.blob); err != nil {
			return err
		}
		if dups := duplicateSerials(recs); len(dups) > 0 {
			// Blob backends never had a cluster-wide duplicate-serial
			// guarantee, so a legacy inventory can legitimately carry
			// repeats. Refusing would brick startup; instead every line is
			// imported verbatim (preserving the rendered text), the serials
			// stay reserved against reissue, and certificate-index writes
			// for them are refused (see etcdSerialAmbiguous) so revocation
			// state and projections cannot land on the wrong record.
			slog.Warn("Legacy etcd inventory contains duplicate serials; certificate-index state for them will be unavailable until the duplicates are resolved",
				"serials", dups)
		}
		conflict, err := b.replaceInventoryOnce(ctx, recs, state.markerRev, true)
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

// etcdLegacyState is a snapshot of the inventory keys a decomposition cares
// about: the marker/blob payload (empty when there is nothing to decompose)
// with its ModRevision, and any decomposed entry keys already present.
type etcdLegacyState struct {
	blob      []byte
	markerRev int64
	entries   []etcdIndexedRecord
}

// legacyInventoryState returns the not-yet-decomposed inventory blob together
// with any existing entry keys, read atomically. A zero-length blob means
// there is nothing to decompose (no marker, or an already-emptied one).
func (b *EtcdBackend) legacyInventoryState(ctx context.Context) (etcdLegacyState, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Txn(ctx).Then(
		clientv3.OpGet(b.invPhys(etcdInvDataSub)),
		clientv3.OpGet(b.invPhys(etcdInvEntriesSub), clientv3.WithPrefix()),
	).Commit()
	if err != nil {
		return etcdLegacyState{}, err
	}
	markerKVs := resp.Responses[0].GetResponseRange().Kvs
	if len(markerKVs) == 0 {
		return etcdLegacyState{}, nil
	}
	_, payload, err := decodeBlob(markerKVs[0].Value)
	if err != nil {
		return etcdLegacyState{}, fmt.Errorf("decoding legacy inventory blob: %w", err)
	}
	if len(payload) == 0 {
		return etcdLegacyState{}, nil
	}
	entries, err := decodeIndexedRecords(b.invPhys(etcdInvEntriesSub), resp.Responses[1].GetResponseRange().Kvs)
	if err != nil {
		return etcdLegacyState{}, err
	}
	return etcdLegacyState{blob: payload, markerRev: markerKVs[0].ModRevision, entries: entries}, nil
}

// legacyMarkerPayload returns the marker/blob payload at inventory/data, or
// nil when the marker is absent. This is the cheap every-start probe: it
// reads a single key, unlike legacyInventoryState which also transfers the
// whole entry range.
func (b *EtcdBackend) legacyMarkerPayload(ctx context.Context) ([]byte, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Get(ctx, b.invPhys(etcdInvDataSub))
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	_, payload, err := decodeBlob(resp.Kvs[0].Value)
	if err != nil {
		return nil, fmt.Errorf("decoding legacy inventory blob: %w", err)
	}
	return payload, nil
}

// convertLegacyEmptyHead completes the upgrade for a pre-decomposition CA
// whose inventory was empty. Such a CA always stores a whole-blob HMAC (CA
// bootstrap writes one over the empty inventory before the first cert is ever
// issued), but with no blob content there is no import to drop it as part of,
// so it would survive the upgrade and fail the first chain verification with
// a spurious tampering error that nothing re-baselines away.
//
// The head is deleted only when it verifies as the whole-blob MAC of an empty
// inventory under the stored key — the exact value the legacy code wrote — so
// the next verification re-establishes the chained baseline. Any other
// non-empty head over zero entries is deliberately left in place for
// verification to flag: it is indistinguishable from the residue of a
// decomposed inventory whose entries were tampered away, and deleting it
// would silently accept that.
func (b *EtcdBackend) convertLegacyEmptyHead(ctx context.Context) error {
	keyPhys, err := b.physicalKey(KeyHMACKey)
	if err != nil {
		return err
	}
	for attempt := range etcdMaxTxnRetries {
		readCtx, cancel := b.callCtx(ctx)
		resp, err := b.client.Txn(readCtx).Then(
			clientv3.OpGet(b.invPhys(etcdInvHMACSub)),
			clientv3.OpGet(keyPhys),
			clientv3.OpGet(b.invPhys(etcdInvEntriesSub), clientv3.WithPrefix(), clientv3.WithCountOnly()),
		).Commit()
		cancel()
		if err != nil {
			return err
		}
		if resp.Responses[2].GetResponseRange().Count > 0 {
			return nil // decomposed entries exist; the head is theirs
		}
		headKVs := resp.Responses[0].GetResponseRange().Kvs
		if len(headKVs) == 0 {
			return nil
		}
		_, stored, err := decodeBlob(headKVs[0].Value)
		if err != nil {
			return fmt.Errorf("decoding legacy inventory HMAC: %w", err)
		}
		if len(stored) == 0 {
			return nil // already the chained baseline of an empty inventory
		}
		keyKVs := resp.Responses[1].GetResponseRange().Kvs
		if len(keyKVs) == 0 {
			return nil // cannot verify; leave it for verification to fail closed
		}
		_, key, err := decodeBlob(keyKVs[0].Value)
		if err != nil || len(key) != hmacKeyLen {
			return nil //nolint:nilerr // same: unverifiable, so leave the head alone
		}
		if !hmac.Equal(wholeBlobInventoryMAC(key, nil), stored) {
			return nil
		}

		txnCtx, cancel2 := b.callCtx(ctx)
		txnResp, err := b.client.Txn(txnCtx).
			If(clientv3.Compare(clientv3.ModRevision(b.invPhys(etcdInvHMACSub)), "=", headKVs[0].ModRevision)).
			Then(clientv3.OpDelete(b.invPhys(etcdInvHMACSub))).
			Commit()
		cancel2()
		if err != nil {
			return err
		}
		if txnResp.Succeeded {
			slog.Info("Removed legacy whole-blob inventory HMAC for an empty inventory; the integrity baseline will be re-established on first verification")
			return nil
		}
		if err := b.txnBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("removing legacy inventory HMAC: too many concurrent writers")
}

// recordsArePrefixOf reports whether the stored entries are exactly the
// import-written prefix of recs: sequence numbers 1..len(entries) carrying the
// same canonical fields. That is the state an interrupted import leaves
// behind (the wipe ran, then some batches committed), and the only state a
// re-run may safely overwrite.
func recordsArePrefixOf(entries []etcdIndexedRecord, recs []CertRecord) bool {
	if len(entries) > len(recs) {
		return false
	}
	for i, e := range entries {
		if e.seq != uint64(i)+1 || e.rec.InventoryEntry != recs[i].InventoryEntry {
			return false
		}
	}
	return true
}

// verifyLegacyInventoryMAC checks the legacy blob against its stored
// whole-blob HMAC before the blob is trusted as the import source. Absent
// head: nothing to check (the baseline is established after the import).
// Mismatch: fail startup with ErrInventoryTampered, exactly as the
// pre-decomposition verify would have. A head that cannot be verified —
// because the HMAC key is missing or malformed — also fails startup: the
// pre-decomposition code was fail-closed in that state too (it regenerated
// the key and then flagged the surviving head as tampering), and proceeding
// would silently promote an unverifiable blob to the new trusted baseline.
// The operator acknowledges a lost baseline by deleting the stored head.
func (b *EtcdBackend) verifyLegacyInventoryMAC(ctx context.Context, blob []byte) error {
	keyPhys, err := b.physicalKey(KeyHMACKey)
	if err != nil {
		return err
	}
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Txn(ctx).Then(
		clientv3.OpGet(b.invPhys(etcdInvHMACSub)),
		clientv3.OpGet(keyPhys),
	).Commit()
	if err != nil {
		return err
	}
	headKVs := resp.Responses[0].GetResponseRange().Kvs
	if len(headKVs) == 0 {
		return nil
	}
	_, stored, err := decodeBlob(headKVs[0].Value)
	if err != nil {
		return fmt.Errorf("decoding legacy inventory HMAC: %w", err)
	}
	keyKVs := resp.Responses[1].GetResponseRange().Kvs
	if len(keyKVs) == 0 {
		return fmt.Errorf("legacy etcd inventory has a stored integrity value but no HMAC key to verify it with; "+
			"delete the %s key under the etcd prefix to acknowledge the lost baseline and retry: %w",
			etcdInvHMACSub, ErrInventoryTampered)
	}
	_, key, err := decodeBlob(keyKVs[0].Value)
	if err != nil || len(key) != hmacKeyLen {
		return fmt.Errorf("legacy etcd inventory HMAC key is unreadable or malformed, so the stored integrity value cannot be verified; "+
			"delete the %s key under the etcd prefix to acknowledge the lost baseline and retry: %w",
			etcdInvHMACSub, ErrInventoryTampered)
	}
	if !hmac.Equal(wholeBlobInventoryMAC(key, blob), stored) {
		return fmt.Errorf("legacy etcd inventory failed integrity verification before decomposition: %w", ErrInventoryTampered)
	}
	return nil
}

// duplicateSerials returns each serial that appears on more than one record,
// once, in first-seen order.
func duplicateSerials(recs []CertRecord) []string {
	counts := make(map[string]int, len(recs))
	for _, r := range recs {
		counts[r.Serial]++
	}
	var dups []string
	seen := make(map[string]bool)
	for _, r := range recs {
		if counts[r.Serial] > 1 && !seen[r.Serial] {
			dups = append(dups, r.Serial)
			seen[r.Serial] = true
		}
	}
	return dups
}
