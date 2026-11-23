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
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// The Redis/Valkey backend stores the certificate inventory decomposed into
// hash fields rather than the single append-only inventory:data blob
// (issue #139):
//
//	inventory:entries     HASH seq → JSON-encoded CertRecord, one field per
//	                      issuance; seq is the decimal issuance counter
//	inventory:seq         last allocated sequence number, allocated by INCR
//	                      and doubling as the mutation fence
//	inventory:by-serial   HASH serial → seq; the field the append script
//	                      refuses to overwrite (see redisAppendEntryLua) is
//	                      the atomic, cluster-wide duplicate-serial guard
//	inventory:by-subject  HASH subject → most recently issued serial
//	inventory:data        presence marker (empty payload; a payload is a
//	                      pre-alpha inventory blob, which is refused: see
//	                      errUndecomposedInventory)
//	inventory:hmac        chained integrity head (blob-encoded, still
//	                      addressed by the KeyInventoryHMAC logical key)
//
// Redis executes a Lua script atomically — nothing else runs on the server
// while it does — so unlike etcd, which can only compare-then-op, every
// mutation here commits in a single indivisible step and needs no
// multi-transaction batching to stay observably consistent. What Redis cannot
// do server-side is compute the integrity chain: chainInventoryMAC is
// HMAC-SHA256, and the Lua sandbox has no HMAC primitive (it offers only
// redis.sha1hex). So the one read-compute-write the design cannot avoid is
// resolved optimistically, as issue #139 proposed: the new head is computed in
// Go from the head that was read, the script is handed both, and it aborts if
// the stored head is no longer the one we read. That check is the only reason
// any of these operations retries. When integrity is disabled there is no
// head, no check, and no retry — the script alone is the whole guarantee.
//
// What the chain is and is not: the HMAC key is a backend blob like any other
// (KeyHMACKey, stored here at <prefix>:private:hmac_key), so it shares the
// instance with the entries it covers. The chain therefore detects accidental
// corruption, a lost or reordered write, and a racing writer — not an attacker
// who owns the Redis instance, who holds both the key and the entries and can
// recompute a consistent head.
//
// What decomposition does not change is durability. Redis atomicity is
// single-primary, and replication under Sentinel is asynchronous, so a
// failover can lose an entry the primary had already acknowledged — the same
// window AcquireLock documents for locks, and no better or worse than the
// append-only blob this replaces. The chain notices afterwards (the head will
// not verify against the entries that survived), which is detection, not
// durability. Deployments that need a committed write to survive a leader
// change want the etcd or SQL backends.
//
// Appends are O(1) in the inventory size (a handful of hash writes), where
// the blob path was O(size-of-entire-inventory) per certificate issued. The
// by-serial guard gives Redis the cross-replica duplicate-serial guarantee
// that previously only SQL and etcd had, and — because the entry and the
// integrity head are now written by one script rather than by two unserialised
// round-trips — closes the Redis half of the whole-blob HMAC race in #204.
//
// Hash fields and index values are raw; only blobs addressed by logical keys
// (the marker and the head) carry the encodeBlob mtime header.
//
// Note every script below spans several keys. Redis Cluster would require
// them to share a hash slot; the backend does not support Cluster (it dials
// a single primary, directly or through Sentinel), and a Cluster client
// passed to NewRedisBackendFromClient would need a key prefix containing a
// hash tag — e.g. "{puppet-ca}" — to keep the family in one slot.
const (
	redisInvDataSub    = "inventory:data"
	redisInvHMACSub    = "inventory:hmac"
	redisInvSeqSub     = "inventory:seq"
	redisInvEntriesSub = "inventory:entries"
	redisInvSerialSub  = "inventory:by-serial"
	redisInvSubjectSub = "inventory:by-subject"
)

// redisMaxRetries bounds every optimistic retry loop in this backend.
// Conflicts are transient (another writer advanced the integrity head between
// our read and our commit), so a bounded loop with jittered backoff resolves
// them; hitting the bound means pathological contention and is an error.
const redisMaxRetries = 16

// redisImportBatch is how many records one import script writes. Redis has no
// per-command op budget the way etcd bounds a transaction, but a Lua script
// blocks the whole (single-threaded) server for its duration, so a bulk import
// is split into scripts of a size whose ~1500 hash writes stay comfortably
// sub-millisecond rather than stalling every other client for the length of a
// fleet-scale import.
const redisImportBatch = 512

// redisImportProgressEvery is how many imported entries pass between progress
// log lines during a bulk inventory import (a migration into Redis), so a
// fleet-scale import reads as a moving import rather than a hang.
const redisImportProgressEvery = 4096

// redisPruneMaxPerCall bounds how many entries one PruneEntries call removes.
// The prune itself is a single atomic script, so this is not a consistency
// bound like etcd's batch cap — it is a latency one: the script blocks the
// server for roughly three hash writes per removed entry, and the caller holds
// the cluster CRL lock throughout. Deferred matches stay present and
// consistent and are removed by subsequent calls, which the PruneEntries
// contract permits.
const redisPruneMaxPerCall = 5000

// RedisBackend implements InventoryStore: the inventory lives as hash fields
// keyed by issuance sequence (plus by-serial/by-subject index hashes) instead
// of a single append-only blob, making appends O(1) and giving
// duplicate-serial rejection cluster-wide semantics. The inventory:data key
// remains as a presence marker so the KeyInventory logical key keeps its
// Get/Put/Exists/ModTime behaviour.
var _ InventoryStore = (*RedisBackend)(nil)

var _ UndecomposedInventoryRefuser = (*RedisBackend)(nil)

// invPhys returns the physical Redis key for an inventory sub-path.
func (b *RedisBackend) invPhys(sub string) string { return b.prefix + ":" + sub }

// invKeys returns the six inventory keys in the fixed order every script in
// this file expects as KEYS[1..6]. Keeping one definition of that order is
// what makes the scripts readable, and it is the order to preserve if a
// seventh key is ever added: KEYS[1] entries, [2] seq, [3] by-serial,
// [4] by-subject, [5] hmac (the chain head), [6] data (the presence marker).
// The key-layout block at the top of this file says what each one holds.
func (b *RedisBackend) invKeys() []string {
	return []string{
		b.invPhys(redisInvEntriesSub),
		b.invPhys(redisInvSeqSub),
		b.invPhys(redisInvSerialSub),
		b.invPhys(redisInvSubjectSub),
		b.invPhys(redisInvHMACSub),
		b.invPhys(redisInvDataSub),
	}
}

// Script result codes. Every script returns a flat array whose first element
// is one of these, so the Go side can distinguish "retry" from "give up"
// without parsing an error string.
const (
	redisResultOK        = "ok"
	redisResultDuplicate = "dup"
	redisResultConflict  = "conflict"
	redisResultMissing   = "missing"
)

// redisScriptResult reduces a script's reply to its status code and the rest
// of its elements. Scripts always reply with an array whose first element is
// the status.
func redisScriptResult(v any, err error) (string, []any, error) {
	if err != nil {
		return "", nil, err
	}
	parts, ok := v.([]any)
	if !ok || len(parts) == 0 {
		return "", nil, fmt.Errorf("unexpected inventory script reply %#v", v)
	}
	status, ok := parts[0].(string)
	if !ok {
		return "", nil, fmt.Errorf("unexpected inventory script status %#v", parts[0])
	}
	return status, parts[1:], nil
}

// --- Lua ---
//
// The head guard shared by every mutating script: ARGV[1] is "1" when
// integrity is enabled, ARGV[2] the head payload the caller read (the stored
// value less its 8-byte mtime prefix), ARGV[3] the head to write, ARGV[4] the
// mtime prefix for any blob this script writes. A caller with integrity
// disabled passes "0" and the head is neither checked nor written.

// redisHeadGuardLua is prepended to the scripts that advance the chain. It
// leaves the new head unwritten — each script writes it at the point in its
// own sequence where it belongs — and returns only after the guard holds.
const redisHeadGuardLua = `
local function head_conflicts()
  if ARGV[1] ~= '1' then return false end
  local cur = redis.call('GET', KEYS[5])
  local body = ''
  if cur then body = string.sub(cur, 9) end
  return body ~= ARGV[2]
end
local function write_head()
  if ARGV[1] == '1' then
    redis.call('SET', KEYS[5], ARGV[4] .. ARGV[3])
  end
end
`

// redisAppendEntryLua inserts one record and advances the integrity head in a
// single atomic step. ARGV[5] is the serial, ARGV[6] the subject, ARGV[7] the
// JSON record.
//
// The duplicate check comes first and the sequence number is allocated only
// after both guards hold, so a rejected append leaves no trace at all — no
// index field, no consumed sequence number.
const redisAppendEntryLua = redisHeadGuardLua + `
if redis.call('HEXISTS', KEYS[3], ARGV[5]) == 1 then
  return {'dup'}
end
if head_conflicts() then
  return {'conflict'}
end
local seq = redis.call('INCR', KEYS[2])
redis.call('HSET', KEYS[1], seq, ARGV[7])
redis.call('HSET', KEYS[3], ARGV[5], seq)
redis.call('HSET', KEYS[4], ARGV[6], ARGV[5])
write_head()
redis.call('SET', KEYS[6], ARGV[4])
return {'ok', tostring(seq)}
`

// redisAppendLinesLua appends several parsed inventory lines at once, for the
// direct Backend.AppendLine(KeyInventory, ...) path. It does not touch the
// integrity head (that caller is outside the chained-append path entirely), so
// it takes no head guard; it does check every serial first, so a batch
// containing one duplicate inserts nothing.
//
// ARGV[1] is the mtime prefix; ARGV[2] the record count; then that many
// (serial, subject, json) triples.
const redisAppendLinesLua = `
local n = tonumber(ARGV[2])
for i = 0, n - 1 do
  if redis.call('HEXISTS', KEYS[3], ARGV[3 + i * 3]) == 1 then
    return {'dup', ARGV[3 + i * 3]}
  end
end
local seq = redis.call('GET', KEYS[2])
if seq == false then seq = 0 else seq = tonumber(seq) end
for i = 0, n - 1 do
  local serial, subject, rec = ARGV[3 + i * 3], ARGV[4 + i * 3], ARGV[5 + i * 3]
  seq = seq + 1
  redis.call('HSET', KEYS[1], seq, rec)
  redis.call('HSET', KEYS[3], serial, seq)
  redis.call('HSET', KEYS[4], subject, serial)
end
redis.call('SET', KEYS[2], seq)
redis.call('SET', KEYS[6], ARGV[1])
return {'ok'}
`

// redisPruneLua removes a batch of entries, repoints the affected indices, and
// rewrites the integrity head, atomically. ARGV[5] is the sequence-counter
// value the caller's snapshot was taken at — the fence that detects an
// interleaved append — followed by four counted lists: entry fields to drop,
// by-serial fields to drop, by-subject field/value pairs to repoint, and
// by-subject fields to drop.
//
// The sequence counter is a fence, not a value to update: a prune allocates
// nothing, so it leaves the counter exactly as it found it and survivors keep
// their original sequence numbers (and thus issuance order).
//
// The lists are applied in chunks rather than through one unpack() per list.
// Redis bundles Lua 5.1, whose unpack() raises "too many results to unpack"
// above LUAI_MAXCSTACK (8000) results — and the by-subject repoint list is two
// elements per subject, so it crosses that ceiling well inside
// redisPruneMaxPerCall. Chunking keeps the cap a latency decision rather than
// one silently coupled to the interpreter's stack, and the whole script stays
// atomic regardless of how many commands it issues.
const redisPruneLua = redisHeadGuardLua + `
local seq = redis.call('GET', KEYS[2])
if seq == false then seq = '0' end
if seq ~= ARGV[5] then
  return {'conflict'}
end
if head_conflicts() then
  return {'conflict'}
end
local i = 6
local function take()
  local n = tonumber(ARGV[i])
  local out = {}
  for j = 1, n do out[j] = ARGV[i + j] end
  i = i + n + 1
  return out, n
end
-- stride is even so a field/value pair is never split across two calls.
local function apply(cmd, key, args, n)
  local stride = 500
  local at = 1
  while at <= n do
    local last = at + stride - 1
    if last > n then last = n end
    local chunk = {}
    local c = 1
    for j = at, last do
      chunk[c] = args[j]
      c = c + 1
    end
    redis.call(cmd, key, unpack(chunk))
    at = last + 1
  end
end
local entryFields, nEntries = take()
local serialFields, nSerials = take()
local subjectPairs, nSubjectPairs = take()
local subjectDrops, nSubjectDrops = take()
apply('HDEL', KEYS[1], entryFields, nEntries)
apply('HDEL', KEYS[3], serialFields, nSerials)
apply('HSET', KEYS[4], subjectPairs, nSubjectPairs)
apply('HDEL', KEYS[4], subjectDrops, nSubjectDrops)
write_head()
return {'ok'}
`

// redisReplaceWipeLua is the first step of a whole-inventory replacement: drop
// the decomposed structure and reset the sequence counter, so the import
// batches that follow write into a known-empty state.
//
// ARGV[1] is the sequence-counter value the caller expects (the fence).
const redisReplaceWipeLua = `
local seq = redis.call('GET', KEYS[2])
if seq == false then seq = '0' end
if seq ~= ARGV[1] then return {'conflict'} end
redis.call('DEL', KEYS[1], KEYS[3], KEYS[4])
redis.call('SET', KEYS[2], '0')
return {'ok'}
`

// redisReplaceBatchLua writes one batch of an import. ARGV[1] is the sequence
// counter the previous step left behind (the fence), ARGV[2] the value to
// leave it at, and ARGV[3] the record count followed by that many (seq,
// serial, subject, json) tuples.
const redisReplaceBatchLua = `
local seq = redis.call('GET', KEYS[2])
if seq == false then seq = '0' end
if seq ~= ARGV[1] then return {'conflict'} end
local n = tonumber(ARGV[3])
for i = 0, n - 1 do
  local base = 4 + i * 4
  redis.call('HSET', KEYS[1], ARGV[base], ARGV[base + 3])
  redis.call('HSET', KEYS[3], ARGV[base + 1], ARGV[base])
  redis.call('HSET', KEYS[4], ARGV[base + 2], ARGV[base + 1])
end
redis.call('SET', KEYS[2], ARGV[2])
return {'ok'}
`

// redisReplaceFinishLua completes a replacement by writing the empty presence
// marker, once every record has been imported.
//
// ARGV[1] is the fence and ARGV[2] the fresh mtime prefix.
const redisReplaceFinishLua = `
local seq = redis.call('GET', KEYS[2])
if seq == false then seq = '0' end
if seq ~= ARGV[1] then return {'conflict'} end
redis.call('SET', KEYS[6], ARGV[2])
return {'ok'}
`

// redisDeleteInventoryLua removes the presence marker and the whole decomposed
// structure, reporting whether the inventory existed at all. The integrity
// head is left in place, matching the SQL and etcd backends (it is a separate
// logical key).
const redisDeleteInventoryLua = `
if redis.call('EXISTS', KEYS[6]) == 0 then
  return {'missing'}
end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[6])
return {'ok'}
`

// redisSetRecordLua rewrites one entry iff it still holds the JSON the caller
// decoded, so a concurrent certificate-index write (e.g. SetRevoked racing
// SetProjection during index repair) is re-read rather than clobbered.
// ARGV[1] is the sequence number, ARGV[2] the expected JSON, ARGV[3] the new.
const redisSetRecordLua = `
local cur = redis.call('HGET', KEYS[1], ARGV[1])
if cur == false then
  return {'missing'}
end
if cur ~= ARGV[2] then
  return {'conflict'}
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
return {'ok'}
`

// --- Reads ---

// readInventorySnapshot returns every stored record in issuance order together
// with the sequence-counter value and the integrity head payload, read
// atomically in one MULTI/EXEC so a mutation cannot land between the three.
// headPresent is false when no head is stored.
func (b *RedisBackend) readInventorySnapshot(ctx context.Context) (recs []indexedRecord, seq string, head []byte, headPresent bool, err error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	var (
		seqCmd     *redis.StringCmd
		entriesCmd *redis.MapStringStringCmd
		headCmd    *redis.StringCmd
	)
	if _, err := b.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		seqCmd = p.Get(ctx, b.invPhys(redisInvSeqSub))
		entriesCmd = p.HGetAll(ctx, b.invPhys(redisInvEntriesSub))
		headCmd = p.Get(ctx, b.invPhys(redisInvHMACSub))
		return nil
	}); err != nil && !errors.Is(err, redis.Nil) {
		return nil, "", nil, false, err
	}

	seq = "0"
	if v, err := seqCmd.Result(); err == nil {
		seq = v
	} else if !errors.Is(err, redis.Nil) {
		return nil, "", nil, false, err
	}

	fields, err := entriesCmd.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, "", nil, false, err
	}
	recs, err = decodeEntryFields(fields)
	if err != nil {
		return nil, "", nil, false, err
	}

	if raw, err := headCmd.Bytes(); err == nil {
		if _, head, err = decodeBlob(raw); err != nil {
			return nil, "", nil, false, fmt.Errorf("decoding inventory head: %w", err)
		}
		headPresent = true
	} else if !errors.Is(err, redis.Nil) {
		return nil, "", nil, false, err
	}
	return recs, seq, head, headPresent, nil
}

// decodeEntryFields turns an inventory:entries HGETALL into records sorted by
// sequence number — Redis hashes are unordered, so issuance order is restored
// here rather than relied on from the server.
func decodeEntryFields(fields map[string]string) ([]indexedRecord, error) {
	out := make([]indexedRecord, 0, len(fields))
	for field, value := range fields {
		seq, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing inventory entry field %q: %w", field, err)
		}
		rec, err := decodeInventoryRecord([]byte(value))
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", field, err)
		}
		out = append(out, indexedRecord{seq: seq, rec: rec})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out, nil
}

// Entries returns every inventory entry in issuance order.
func (b *RedisBackend) Entries(ctx context.Context) ([]InventoryEntry, error) {
	recs, _, _, _, err := b.readInventorySnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return entriesOf(recs), nil
}

// EntriesWithHead returns every inventory entry in issuance order and the
// stored integrity head, from the one MULTI/EXEC readInventorySnapshot issues.
func (b *RedisBackend) EntriesWithHead(ctx context.Context) ([]InventoryEntry, []byte, bool, error) {
	recs, _, head, present, err := b.readInventorySnapshot(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	return entriesOf(recs), head, present, nil
}

// LatestSerialForSubject returns the most recently issued serial for subject,
// wrapping fs.ErrNotExist when the subject has no entry. This is a single
// hash-field read of the by-subject index.
func (b *RedisBackend) LatestSerialForSubject(ctx context.Context, subject string) (string, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	serial, err := b.client.HGet(ctx, b.invPhys(redisInvSubjectSub), subject).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", &fs.PathError{Op: "latest-serial", Path: subject, Err: fs.ErrNotExist}
		}
		return "", err
	}
	return serial, nil
}

// --- Append ---

// AppendEntry inserts rec and advances the integrity head atomically. The
// script rejects the append outright if rec's serial is already indexed (the
// cluster-wide duplicate-serial guarantee) and aborts it if the stored head is
// no longer the one newHead was computed from, which is the only way a
// concurrent appender — in this process or on another replica — can interfere.
// A nil newHead means integrity is disabled: there is then nothing to compute
// in Go, the script is the entire operation, and it cannot conflict.
func (b *RedisBackend) AppendEntry(ctx context.Context, rec CertRecord, newHead func(prev []byte) []byte) error {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	val, err := encodeInventoryRecord(rec)
	if err != nil {
		return err
	}

	for attempt := range redisMaxRetries {
		prev, err := b.readHead(ctx)
		if err != nil {
			return err
		}
		argv := b.headArgs(newHead, prev)
		argv = append(argv, rec.Serial, rec.Subject, string(val))
		if b.appendHeadHook != nil {
			b.appendHeadHook()
		}

		status, _, err := b.runInvScript(ctx, b.invAppendEntryScript, argv...)
		if err != nil {
			return err
		}
		switch status {
		case redisResultOK:
			return nil
		case redisResultDuplicate:
			return fmt.Errorf("%w: %s", ErrDuplicateSerial, rec.Serial)
		case redisResultConflict:
			// Another appender advanced the head between our read and our
			// commit; re-read and recompute the chain from where it now is.
			if err := b.scriptBackoff(ctx, attempt); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected inventory append result %q", status)
		}
	}
	return fmt.Errorf("inventory append failed: too many concurrent writers")
}

// readHead returns the stored integrity head's payload, or nil when no head is
// stored yet.
func (b *RedisBackend) readHead(ctx context.Context) ([]byte, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	raw, err := b.client.Get(ctx, b.invPhys(redisInvHMACSub)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	_, head, err := decodeBlob(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding inventory head: %w", err)
	}
	return head, nil
}

// headArgs builds the four leading ARGV entries every chain-advancing script
// shares: whether integrity is on, the head that was read, the head to write,
// and the mtime prefix for blobs the script writes. An absent head and a
// stored-but-empty one are deliberately the same input to the chain (both fold
// as "no previous"), so they compare equal here too.
func (b *RedisBackend) headArgs(newHead func(prev []byte) []byte, prev []byte) []any {
	mtime := string(encodeMtime(time.Now()))
	if newHead == nil {
		return []any{"0", "", "", mtime}
	}
	return []any{"1", string(prev), string(newHead(prev)), mtime}
}

// runInvScript runs script against the six inventory keys and splits the reply
// into its status code and remaining elements.
func (b *RedisBackend) runInvScript(ctx context.Context, script *redis.Script, argv ...any) (string, []any, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	return redisScriptResult(script.Run(ctx, b.client, b.invKeys(), argv...).Result())
}

// --- Prune ---

// PruneEntries removes the entries for which keep returns false, repoints the
// indices, and rewrites the integrity head — all in one script, so the entries
// and the head are never observably out of sync and a prune either happens or
// does not. The returned slice therefore only ever describes a completed
// removal, which is the strongest form of the PruneEntries contract (etcd,
// which cannot commit an arbitrary number of deletions atomically, takes the
// weaker batched form the same contract permits).
//
// One call removes at most redisPruneMaxPerCall entries, oldest first; matches
// beyond that stay in the inventory, consistent and intact, for later calls.
func (b *RedisBackend) PruneEntries(ctx context.Context, keep func(InventoryEntry) bool, advanceHead func(prev []byte, e InventoryEntry) []byte) ([]InventoryEntry, error) {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	for attempt := range redisMaxRetries {
		recs, seq, head, _, err := b.readInventorySnapshot(ctx)
		if err != nil {
			return nil, err
		}

		plan := planRedisPrune(recs, keep)
		if len(plan.removed) == 0 {
			return nil, nil
		}
		if b.pruneSnapshotHook != nil {
			b.pruneSnapshotHook()
		}

		var newHead func(prev []byte) []byte
		if advanceHead != nil {
			survivors := plan.survivors
			newHead = func(prev []byte) []byte {
				// The chain is rebuilt from nothing over the survivors, not
				// advanced from the stored head: removing an entry from the
				// middle of a hash chain invalidates every link after it.
				// prev is ignored for exactly that reason — it is only the
				// value the script compares against.
				_ = prev
				var h []byte
				for _, r := range survivors {
					h = advanceHead(h, r.rec.InventoryEntry)
				}
				return h
			}
		}

		argv := b.headArgs(newHead, head)
		argv = append(argv, seq)
		argv = appendCountedStrings(argv, plan.entryFields)
		argv = appendCountedStrings(argv, plan.serialDrops)
		argv = appendCountedStrings(argv, plan.subjectSets)
		argv = appendCountedStrings(argv, plan.subjectDrops)

		status, _, err := b.runInvScript(ctx, b.invPruneScript, argv...)
		if err != nil {
			return nil, err
		}
		switch status {
		case redisResultOK:
			return entriesOf(plan.removed), nil
		case redisResultConflict:
			if err := b.scriptBackoff(ctx, attempt); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unexpected inventory prune result %q", status)
		}
	}
	return nil, fmt.Errorf("inventory prune failed: too many concurrent writers")
}

// redisPrunePlan is everything one prune script needs, computed in Go from a
// snapshot: which entry fields to drop, which index fields follow them, and
// which records survive (the input to the rebuilt chain).
type redisPrunePlan struct {
	removed      []indexedRecord
	survivors    []indexedRecord
	entryFields  []string
	serialDrops  []string
	subjectSets  []string // flat field/value pairs
	subjectDrops []string
}

// planRedisPrune partitions recs by keep and works out the index repairs the
// removal implies. When more entries match than one call may remove, the
// oldest redisPruneMaxPerCall are taken and the rest are treated as survivors
// for this round — they stay in the inventory, covered by the rewritten chain,
// and the next call takes them.
func planRedisPrune(recs []indexedRecord, keep func(InventoryEntry) bool) redisPrunePlan {
	var plan redisPrunePlan
	matched := 0
	for _, r := range recs {
		if keep(r.rec.InventoryEntry) {
			plan.survivors = append(plan.survivors, r)
			continue
		}
		matched++
		if len(plan.removed) >= redisPruneMaxPerCall {
			// Deferred: still a survivor as far as this round's chain,
			// indices and returned slice are concerned.
			plan.survivors = append(plan.survivors, r)
			continue
		}
		plan.removed = append(plan.removed, r)
	}
	if len(plan.removed) == 0 {
		return plan
	}
	if deferred := matched - len(plan.removed); deferred > 0 {
		// Never silently: a short count must be explicable from the log. The
		// CA's cleanup asks for at most sweepStepEntries (internal/ca, 100)
		// entries a call since #347, so it never reaches this; the cap is a
		// backstop for a caller that asks for more, and a deferral bigger than
		// a whole call warns.
		logFn := slog.Info
		if pruneBacklogGrowing(deferred, redisPruneMaxPerCall) {
			logFn = slog.Warn
		}
		logFn("Bounding inventory prune to keep it inside the caller's time budget; later runs will remove the rest",
			"removing", len(plan.removed), "deferred", deferred)
	}

	// Bearer counts over the surviving set: a by-serial field is released only
	// when no stored record still carries that serial. For a unique serial
	// that is every removal; for a serial duplicated in a converted legacy
	// blob it frees the ambiguity sentinel only once the last bearer goes,
	// so a lone remaining bearer cannot have index writes aliased onto it.
	survivingSerials := make(map[string]int, len(plan.survivors))
	survivingSubject := make(map[string]indexedRecord, len(plan.survivors))
	for _, r := range plan.survivors {
		survivingSerials[r.rec.Serial]++
		if cur, ok := survivingSubject[r.rec.Subject]; !ok || r.seq > cur.seq {
			survivingSubject[r.rec.Subject] = r
		}
	}

	seenSerial := make(map[string]bool, len(plan.removed))
	seenSubject := make(map[string]bool, len(plan.removed))
	for _, r := range plan.removed {
		plan.entryFields = append(plan.entryFields, strconv.FormatUint(r.seq, 10))
		if !seenSerial[r.rec.Serial] {
			seenSerial[r.rec.Serial] = true
			if survivingSerials[r.rec.Serial] == 0 {
				plan.serialDrops = append(plan.serialDrops, r.rec.Serial)
			}
		}
		if !seenSubject[r.rec.Subject] {
			seenSubject[r.rec.Subject] = true
			if latest, ok := survivingSubject[r.rec.Subject]; ok {
				plan.subjectSets = append(plan.subjectSets, r.rec.Subject, latest.rec.Serial)
			} else {
				plan.subjectDrops = append(plan.subjectDrops, r.rec.Subject)
			}
		}
	}
	return plan
}

// appendCountedStrings appends a length-prefixed list to an ARGV slice, the
// encoding the Lua `take` helper reads back.
func appendCountedStrings(argv []any, items []string) []any {
	argv = append(argv, strconv.Itoa(len(items)))
	for _, s := range items {
		argv = append(argv, s)
	}
	return argv
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
func (b *RedisBackend) getInventory(ctx context.Context) ([]byte, error) {
	callCtx, cancel := b.callCtx(ctx)
	defer cancel()

	var (
		markerCmd  *redis.StringCmd
		entriesCmd *redis.MapStringStringCmd
	)
	if _, err := b.client.TxPipelined(callCtx, func(p redis.Pipeliner) error {
		markerCmd = p.Get(callCtx, b.invPhys(redisInvDataSub))
		entriesCmd = p.HGetAll(callCtx, b.invPhys(redisInvEntriesSub))
		return nil
	}); err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	fields, err := entriesCmd.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}

	raw, markerErr := markerCmd.Bytes()
	if markerErr != nil && !errors.Is(markerErr, redis.Nil) {
		return nil, markerErr
	}
	markerPresent := markerErr == nil
	if !markerPresent && len(fields) == 0 {
		return nil, &fs.PathError{Op: "get", Path: KeyInventory, Err: fs.ErrNotExist}
	}
	if markerPresent {
		_, payload, err := decodeBlob(raw)
		if err != nil {
			return nil, fmt.Errorf("decoding blob %q: %w", KeyInventory, err)
		}
		if len(payload) > 0 {
			return nil, fmt.Errorf("redis %s: %w", redisInvDataSub, errUndecomposedInventory)
		}
	}

	recs, err := decodeEntryFields(fields)
	if err != nil {
		return nil, err
	}
	return renderInventoryText(recs), nil
}

// putInventory replaces the entire decomposed inventory with the entries
// parsed from data (an inventory.txt blob) and sets the presence marker. Used
// by TouchInventory (empty data) and by Migrate when importing into Redis. The
// integrity head is not touched: Migrate recomputes it afterwards, and a
// touched-but-empty inventory gets its baseline on first verification.
func (b *RedisBackend) putInventory(ctx context.Context, data []byte) error {
	recs, err := parseInventoryRecords(data)
	if err != nil {
		return err
	}
	if err := rejectDuplicateSerials(recs); err != nil {
		return err
	}

	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	for attempt := range redisMaxRetries {
		conflict, err := b.replaceInventoryOnce(ctx, recs)
		if err != nil {
			return err
		}
		if !conflict {
			return nil
		}
		if err := b.scriptBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("inventory replace failed: too many concurrent writers")
}

// replaceInventoryOnce performs one attempt at replacing the decomposed
// structure with recs: wipe, import in batches, then write the fresh presence
// marker. Every step is guarded on the sequence counter holding the value the
// previous step left, so an interleaved append (which allocates from that
// counter) is detected and the caller restarts. Returns conflict=true when a
// guard failed and the caller should re-read and retry. recs must hold no
// duplicate serials: the by-serial index is one-to-one, and the caller rejects
// them first.
func (b *RedisBackend) replaceInventoryOnce(ctx context.Context, recs []CertRecord) (bool, error) {
	seqCmd, cancel := b.callCtx(ctx)
	seq, err := b.client.Get(seqCmd, b.invPhys(redisInvSeqSub)).Result()
	cancel()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return false, err
		}
		seq = "0"
	}

	status, _, err := b.runInvScript(ctx, b.invReplaceWipeScript, seq)
	if err != nil {
		return false, err
	}
	if status != redisResultOK {
		return true, nil
	}

	written := 0
	for start := 0; start < len(recs); start += redisImportBatch {
		batch := recs[start:min(start+redisImportBatch, len(recs))]
		// One HSET per index field per script; later occurrences overwrite
		// earlier ones, in this batch and across batches, leaving each subject
		// pointing at its newest serial.
		argv := []any{strconv.Itoa(written), strconv.Itoa(written + len(batch)), strconv.Itoa(len(batch))}
		for i, rec := range batch {
			val, err := encodeInventoryRecord(rec)
			if err != nil {
				return false, err
			}
			n := uint64(start+i) + 1
			argv = append(argv, strconv.FormatUint(n, 10), rec.Serial, rec.Subject, string(val))
		}
		status, _, err := b.runInvScript(ctx, b.invReplaceBatchScript, argv...)
		if err != nil {
			return false, err
		}
		if status != redisResultOK {
			return true, nil
		}
		written += len(batch)
		// A fleet-scale import is many sequential scripts; report progress
		// periodically so it reads as a moving import rather than an apparent
		// hang (the same reasoning as the certificate-index backfill's
		// progress log).
		if written/redisImportProgressEvery != start/redisImportProgressEvery && written < len(recs) {
			slog.Info("Inventory import progress", "imported", written, "total", len(recs))
		}
	}

	status, _, err = b.runInvScript(ctx, b.invReplaceFinishScript,
		strconv.Itoa(len(recs)), string(encodeMtime(time.Now())))
	if err != nil {
		return false, err
	}
	return status != redisResultOK, nil
}

// appendInventoryLines appends the entries parsed from data as new records,
// without touching the integrity head. StorageService routes inventory appends
// through AppendEntry; this runs only when a caller invokes
// Backend.AppendLine(KeyInventory, ...) directly. Duplicate serials — within
// data or against the stored inventory — are rejected, mirroring the unique
// index the SQL backend's direct-append path trips over.
func (b *RedisBackend) appendInventoryLines(ctx context.Context, data []byte) error {
	recs, err := parseInventoryRecords(data)
	if err != nil {
		return err
	}
	if err := rejectDuplicateSerials(recs); err != nil {
		return err
	}
	if len(recs) == 0 {
		return nil
	}
	// This path appends every line in one script (unlike imports and prunes,
	// which chunk), so bound it explicitly rather than let a large caller
	// block the single-threaded server for the whole batch. The etcd sibling
	// refuses an oversized batch for the same reason, against its transaction
	// budget rather than a latency one.
	if len(recs) > redisImportBatch {
		return fmt.Errorf("appending %d inventory lines in one call exceeds the redis single-script budget of %d; append in smaller chunks", len(recs), redisImportBatch)
	}

	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	argv := []any{string(encodeMtime(time.Now())), strconv.Itoa(len(recs))}
	for _, rec := range recs {
		val, err := encodeInventoryRecord(rec)
		if err != nil {
			return err
		}
		argv = append(argv, rec.Serial, rec.Subject, string(val))
	}
	status, rest, err := b.runInvScript(ctx, b.invAppendLinesScript, argv...)
	if err != nil {
		return err
	}
	switch status {
	case redisResultOK:
		return nil
	case redisResultDuplicate:
		serial := ""
		if len(rest) > 0 {
			serial, _ = rest[0].(string)
		}
		return fmt.Errorf("%w: %s", ErrDuplicateSerial, serial)
	default:
		return fmt.Errorf("unexpected inventory append result %q", status)
	}
}

// deleteInventory removes the presence marker and the whole decomposed
// structure, wrapping fs.ErrNotExist when the inventory was never initialised.
func (b *RedisBackend) deleteInventory(ctx context.Context) error {
	status, _, err := b.runInvScript(ctx, b.invDeleteScript)
	if err != nil {
		return err
	}
	if status == redisResultMissing {
		return &fs.PathError{Op: "delete", Path: KeyInventory, Err: fs.ErrNotExist}
	}
	return nil
}

// --- Pre-alpha inventory blob ---

// RefuseUndecomposedInventory refuses a store whose presence marker still
// holds an inventory blob (see errUndecomposedInventory and
// UndecomposedInventoryRefuser). It reads the marker alone, so on every ordinary
// start it costs one key.
func (b *RedisBackend) RefuseUndecomposedInventory(ctx context.Context) error {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()
	raw, err := b.client.Get(ctx, b.invPhys(redisInvDataSub)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return err
	}
	_, payload, err := decodeBlob(raw)
	if err != nil {
		return fmt.Errorf("decoding blob %q: %w", KeyInventory, err)
	}
	if len(payload) > 0 {
		return fmt.Errorf("redis %s: %w", redisInvDataSub, errUndecomposedInventory)
	}
	return nil
}
