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
//	inventory/data               presence marker (empty payload; a payload is
//	                             a pre-alpha inventory blob, which is refused:
//	                             see errUndecomposedInventory)
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

// etcdImportProgressEvery is how many imported entries pass between progress
// log lines during a bulk inventory import (a migration into etcd). One line
// per ~32 transactions keeps a fleet-scale import observable without flooding
// the log on small ones.
const etcdImportProgressEvery = 1024

// etcdPruneMaxBatchesPerCall bounds one PruneEntries call to this many
// committed batches (currently 900 entries) — a budget shared across the
// call's retry attempts, so a fence conflict cannot grant a fresh allowance.
// Each batch writes an intermediate head folded over the entries that remain,
// so a prune's total hashing cost grows with batches × survivors; an
// unbounded call over a large backlog could not finish inside the caller's
// lock budget. Deferred entries stay present and consistent and are removed
// by subsequent calls (the cleanup job runs periodically), which the
// PruneEntries contract permits.
const etcdPruneMaxBatchesPerCall = 30

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

func decodeIndexedRecords(prefix string, kvs []*mvccpb.KeyValue) ([]indexedRecord, error) {
	out := make([]indexedRecord, 0, len(kvs))
	for _, kv := range kvs {
		seq, err := strconv.ParseUint(strings.TrimPrefix(string(kv.Key), prefix), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing inventory entry key %q: %w", kv.Key, err)
		}
		rec, err := decodeInventoryRecord(kv.Value)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", kv.Key, err)
		}
		out = append(out, indexedRecord{seq: seq, rec: rec})
	}
	return out, nil
}

// readIndexedRecords returns every inventory entry in issuance order together
// with the fence snapshot, read atomically in a single transaction.
func (b *EtcdBackend) readIndexedRecords(ctx context.Context) ([]indexedRecord, etcdSeqState, error) {
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

var _ UndecomposedInventoryRefuser = (*EtcdBackend)(nil)

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

// EntriesWithHead returns every inventory entry in issuance order and the
// stored integrity head, read in one Txn and so at one revision. AppendEntry
// and PruneEntries write the head in the same Txn as the entries it covers,
// so the two always describe the same inventory.
func (b *EtcdBackend) EntriesWithHead(ctx context.Context) ([]InventoryEntry, []byte, bool, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Txn(ctx).Then(
		clientv3.OpGet(b.invPhys(etcdInvEntriesSub), clientv3.WithPrefix()),
		clientv3.OpGet(b.invPhys(etcdInvHMACSub)),
	).Commit()
	if err != nil {
		return nil, nil, false, err
	}
	recs, err := decodeIndexedRecords(b.invPhys(etcdInvEntriesSub), resp.Responses[0].GetResponseRange().Kvs)
	if err != nil {
		return nil, nil, false, err
	}
	headKVs := resp.Responses[1].GetResponseRange().Kvs
	if len(headKVs) == 0 {
		return entriesOf(recs), nil, false, nil
	}
	_, head, err := decodeBlob(headKVs[0].Value)
	if err != nil {
		return nil, nil, false, fmt.Errorf("decoding inventory head: %w", err)
	}
	return entriesOf(recs), head, true, nil
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
	var all []indexedRecord
	finish := func() []InventoryEntry {
		if len(all) == 0 {
			return nil
		}
		// A conflicting append may add (and a later attempt remove) entries
		// newer than an earlier attempt's, so restore issuance order globally.
		sort.Slice(all, func(i, j int) bool { return all[i].seq < all[j].seq })
		return entriesOf(all)
	}

	// The per-call bound is a budget shared across retry attempts: a conflict
	// after some batches committed must not grant the next attempt a fresh
	// allowance, or a call under sustained conflicts could remove many times
	// the documented cap while holding the caller's lock.
	budget := etcdPruneMaxBatchesPerCall
	for attempt := range etcdMaxTxnRetries {
		committed, batches, conflict, err := b.pruneEntriesOnce(ctx, keep, advanceHead, budget)
		all = append(all, committed...)
		budget -= batches
		if err != nil {
			return finish(), err
		}
		if !conflict || budget <= 0 {
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
func (b *EtcdBackend) pruneEntriesOnce(ctx context.Context, keep func(InventoryEntry) bool, advanceHead func(prev []byte, e InventoryEntry) []byte, maxBatches int) ([]indexedRecord, int, bool, error) {
	recs, seq, err := b.readIndexedRecords(ctx)
	if err != nil {
		return nil, 0, false, err
	}

	var removed []indexedRecord
	survivors := make([]indexedRecord, 0, len(recs))
	for _, r := range recs {
		if keep(r.rec.InventoryEntry) {
			survivors = append(survivors, r)
		} else {
			removed = append(removed, r)
		}
	}
	if len(removed) == 0 {
		return nil, 0, false, nil
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
	// Bound this attempt to the call's remaining budget (see
	// etcdPruneMaxBatchesPerCall — PruneEntries threads what is left across
	// retries). Batches run tail-first, so keeping the last starts removes
	// the newest matches and defers the older ones — which stay present and
	// consistent — to later calls. Never silently: the caller's log should
	// explain a short count.
	if len(starts) > maxBatches {
		starts = starts[len(starts)-maxBatches:]
		logFn := slog.Info
		if pruneBacklogGrowing(starts[0], etcdPruneMaxBatchesPerCall*etcdPruneBatch) {
			// More is deferred than a whole call can remove. The CA's cleanup
			// asks for at most sweepStepEntries (internal/ca) entries a
			// call since #347, so it never reaches this; the cap and its
			// warning are a backstop for a caller that asks for more, and say
			// so loudly when one does.
			logFn = slog.Warn
		}
		logFn("Bounding inventory prune to keep it inside the caller's time budget; later runs will remove the rest",
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
	subjAll := make(map[string][]indexedRecord)
	for _, r := range recs {
		subjAll[r.rec.Subject] = append(subjAll[r.rec.Subject], r)
	}
	subjSurvLast := make(map[string]indexedRecord, len(survivors))
	for _, r := range survivors {
		subjSurvLast[r.rec.Subject] = r
	}

	// Bearer counts per serial across the WHOLE record set, so a duplicated
	// legacy serial's shared by-serial key (the ambiguity sentinel) is only
	// deleted when its last bearer goes. Deleting it while another bearer —
	// a survivor, a deferred match, or an entry in a later batch — remains
	// would un-reserve a serial still borne by a stored record and re-enable
	// the index-write aliasing the sentinel exists to prevent.
	bearers := make(map[string]int, len(recs))
	for _, r := range recs {
		bearers[r.rec.Serial]++
	}

	seqRev := seq.rev
	committedFrom := len(removed) // removal index from which deletes have committed
	batchesCommitted := 0
	for si := len(starts) - 1; si >= 0; si-- {
		s := starts[si]
		batch := removed[s:min(s+etcdPruneBatch, len(removed))]
		cutSeq := removed[s].seq

		ops := make([]clientv3.Op, 0, 3*len(batch)+3)
		subjects := make(map[string]bool, len(batch))
		for _, r := range batch {
			ops = append(ops, clientv3.OpDelete(b.entryPhys(r.seq)))
			bearers[r.rec.Serial]--
			if bearers[r.rec.Serial] == 0 {
				// Last bearer of this serial: release the by-serial key
				// (for a unique serial that is every removal; for a
				// duplicated one this frees the ambiguity sentinel only
				// once no stored record carries the serial any more).
				ops = append(ops, clientv3.OpDelete(b.invPhys(etcdInvSerialSub+r.rec.Serial)))
			}
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
			return removed[committedFrom:], batchesCommitted, false, err
		}
		if !resp.Succeeded {
			return removed[committedFrom:], batchesCommitted, true, nil
		}
		// Our own put moved the fence; subsequent batches guard on the new
		// revision, which every op in this transaction committed at.
		seqRev = resp.Header.Revision
		committedFrom = s
		batchesCommitted++
		if b.pruneBatchHook != nil {
			b.pruneBatchHook()
		}
	}
	// All selected batches committed; entries before starts[0] (if any) were
	// deferred by the per-call bound and remain in the inventory.
	return removed[starts[0]:], batchesCommitted, false, nil
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
// fs.ErrNotExist. A marker holding a pre-alpha inventory blob is refused here
// as well as at startup, so an offline reader such as migrate cannot take the
// store for an empty one.
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
	if len(markerKVs) > 0 {
		_, payload, err := decodeBlob(markerKVs[0].Value)
		if err != nil {
			return nil, fmt.Errorf("decoding blob %q: %w", KeyInventory, err)
		}
		if len(payload) > 0 {
			return nil, fmt.Errorf("etcd %s: %w", etcdInvDataSub, errUndecomposedInventory)
		}
	}
	recs, err := decodeIndexedRecords(b.invPhys(etcdInvEntriesSub), entryKVs)
	if err != nil {
		return nil, err
	}
	return renderInventoryText(recs), nil
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
		conflict, err := b.replaceInventoryOnce(ctx, recs)
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
// fence. Returns conflict=true when a guard failed and the caller should
// re-read and retry. recs must hold no duplicate serials: the by-serial index
// is one-to-one, and the caller rejects them first.
func (b *EtcdBackend) replaceInventoryOnce(ctx context.Context, recs []CertRecord) (bool, error) {
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

	commit := func(seqRev int64, ops []clientv3.Op) (int64, bool, error) {
		txnCtx, cancel := b.callCtx(ctx)
		defer cancel()
		resp, err := b.client.Txn(txnCtx).
			If(clientv3.Compare(clientv3.ModRevision(b.invPhys(etcdInvSeqSub)), "=", seqRev)).
			Then(ops...).Commit()
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
		// One put per index key per transaction (etcd rejects duplicate keys
		// within a txn); later occurrences — in the same batch via
		// subjectLatest, across batches via plain overwrite — win, leaving
		// each subject pointing at its newest serial.
		subjectLatest := make(map[string]string, len(batch))
		for i, rec := range batch {
			val, err := encodeInventoryRecord(rec)
			if err != nil {
				return false, err
			}
			n := uint64(start+i) + 1
			ops = append(ops, clientv3.OpPut(b.entryPhys(n), string(val)))
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSerialSub+rec.Serial), strconv.FormatUint(n, 10)))
			subjectLatest[rec.Subject] = rec.Serial
		}
		for subject, serial := range subjectLatest {
			ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSubjectSub+subject), serial))
		}
		ops = append(ops, clientv3.OpPut(b.invPhys(etcdInvSeqSub), strconv.Itoa(start+len(batch))))
		if seqRev, conflict, err = commit(seqRev, ops); err != nil || conflict {
			return conflict, err
		}
		// A fleet-scale import is thousands of sequential transactions;
		// report progress periodically so it reads as a moving import rather
		// than an apparent hang (the same reasoning as the certificate-index
		// backfill's progress log).
		imported := start + len(batch)
		if imported/etcdImportProgressEvery != start/etcdImportProgressEvery && imported < len(recs) {
			slog.Info("Inventory import progress", "imported", imported, "total", len(recs))
		}
	}

	_, conflict, err = commit(seqRev, []clientv3.Op{
		b.markerTouchOp(),
		clientv3.OpPut(b.invPhys(etcdInvSeqSub), strconv.Itoa(len(recs))),
	})
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

// --- Pre-alpha inventory blob ---

// RefuseUndecomposedInventory refuses a store whose presence marker still
// holds an inventory blob (see errUndecomposedInventory and
// UndecomposedInventoryRefuser). It reads the marker alone, so on every ordinary
// start it costs one key.
func (b *EtcdBackend) RefuseUndecomposedInventory(ctx context.Context) error {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	resp, err := b.client.Get(ctx, b.invPhys(etcdInvDataSub))
	if err != nil {
		return err
	}
	if len(resp.Kvs) == 0 {
		return nil
	}
	_, payload, err := decodeBlob(resp.Kvs[0].Value)
	if err != nil {
		return fmt.Errorf("decoding blob %q: %w", KeyInventory, err)
	}
	if len(payload) > 0 {
		return fmt.Errorf("etcd %s: %w", etcdInvDataSub, errUndecomposedInventory)
	}
	return nil
}
