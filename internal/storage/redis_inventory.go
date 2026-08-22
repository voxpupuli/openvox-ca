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
	"crypto/hmac"
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
//	inventory:data        presence marker (empty payload); also where
//	                      pre-decomposition versions kept the blob
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
// fleet-scale conversion.
const redisImportBatch = 512

// redisImportProgressEvery is how many imported entries pass between progress
// log lines during a bulk inventory import (legacy conversion, migration), so
// a fleet-scale conversion reads as a moving import rather than a hang.
const redisImportProgressEvery = 4096

// redisPruneMaxPerCall bounds how many entries one PruneEntries call removes.
// The prune itself is a single atomic script, so this is not a consistency
// bound like etcd's batch cap — it is a latency one: the script blocks the
// server for roughly three hash writes per removed entry, and the caller holds
// the cluster CRL lock throughout. Deferred matches stay present and
// consistent and are removed by subsequent calls, which the PruneEntries
// contract permits.
const redisPruneMaxPerCall = 5000

// redisDecomposeLockName is the distributed lock serialising the one-time
// legacy inventory blob conversion across replicas starting up together. It is
// deliberately the same name the etcd backend uses (lock names are protocol —
// see docs/development/locking.md — and a deployment only ever has one
// backend, so the two can never contend).
const redisDecomposeLockName = etcdDecomposeLockName

// RedisBackend implements InventoryStore: the inventory lives as hash fields
// keyed by issuance sequence (plus by-serial/by-subject index hashes) instead
// of a single append-only blob, making appends O(1) and giving
// duplicate-serial rejection cluster-wide semantics. The inventory:data key
// remains as a presence marker so the KeyInventory logical key keeps its
// Get/Put/Exists/ModTime behaviour.
var _ InventoryStore = (*RedisBackend)(nil)

// invPhys returns the physical Redis key for an inventory sub-path.
func (b *RedisBackend) invPhys(sub string) string { return b.prefix + ":" + sub }

// invKeys returns the six inventory keys in the fixed order every script in
// this file expects as KEYS[1..6]. Keeping one definition of that order is
// what makes the scripts readable: KEYS[1] is always entries, KEYS[5] always
// the head, and so on.
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
// ARGV[1] is the sequence-counter value the caller expects (the fence), and
// ARGV[2..4] the marker guard described on redisReplaceBatchLua.
const redisReplaceWipeLua = `
local seq = redis.call('GET', KEYS[2])
if seq == false then seq = '0' end
if seq ~= ARGV[1] then return {'conflict'} end
if ARGV[2] == '1' then
  local m = redis.call('GET', KEYS[6])
  if m == false then m = '' end
  if string.sub(m, 1, 8) ~= ARGV[3] or tostring(string.len(m)) ~= ARGV[4] then
    return {'conflict'}
  end
end
redis.call('DEL', KEYS[1], KEYS[3], KEYS[4])
redis.call('SET', KEYS[2], '0')
return {'ok'}
`

// redisReplaceBatchLua writes one batch of an import. ARGV[1] is the sequence
// counter the previous step left behind (the fence), ARGV[2] the value to
// leave it at, ARGV[3..5] the marker guard, and ARGV[6] the record count
// followed by that many (seq, serial, serialValue, subject, json) tuples.
//
// The marker guard is what makes a legacy conversion safe against a replica that
// has not been upgraded yet: such a replica only writes the blob through
// AppendLine or Put, both of which stamp a fresh mtime prefix, so comparing
// the marker's first 8 bytes (and, belt and braces, its length) detects any
// write to it between the conversion's read and each of its commits.
const redisReplaceBatchLua = `
local seq = redis.call('GET', KEYS[2])
if seq == false then seq = '0' end
if seq ~= ARGV[1] then return {'conflict'} end
if ARGV[3] == '1' then
  local m = redis.call('GET', KEYS[6])
  if m == false then m = '' end
  if string.sub(m, 1, 8) ~= ARGV[4] or tostring(string.len(m)) ~= ARGV[5] then
    return {'conflict'}
  end
end
local n = tonumber(ARGV[6])
for i = 0, n - 1 do
  local base = 7 + i * 5
  redis.call('HSET', KEYS[1], ARGV[base], ARGV[base + 4])
  redis.call('HSET', KEYS[3], ARGV[base + 1], ARGV[base + 2])
  redis.call('HSET', KEYS[4], ARGV[base + 3], ARGV[base + 1])
end
redis.call('SET', KEYS[2], ARGV[2])
return {'ok'}
`

// redisReplaceFinishLua completes a replacement: empty the presence marker
// (which is what retires a legacy blob, and only ever happens once every
// record has been imported) and, for a legacy conversion, drop the whole-blob
// integrity head that cannot carry over into the chained scheme.
//
// ARGV[1] is the fence, ARGV[2..4] the marker guard, ARGV[5] the fresh mtime
// prefix, and ARGV[6] "1" to drop the head.
const redisReplaceFinishLua = `
local seq = redis.call('GET', KEYS[2])
if seq == false then seq = '0' end
if seq ~= ARGV[1] then return {'conflict'} end
if ARGV[2] == '1' then
  local m = redis.call('GET', KEYS[6])
  if m == false then m = '' end
  if string.sub(m, 1, 8) ~= ARGV[3] or tostring(string.len(m)) ~= ARGV[4] then
    return {'conflict'}
  end
end
redis.call('SET', KEYS[6], ARGV[5])
if ARGV[6] == '1' then
  redis.call('DEL', KEYS[5])
end
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

// redisDropHeadLua deletes the integrity head iff it still holds the payload
// in ARGV[1], so a concurrent append's freshly chained head is never mistaken
// for the legacy whole-blob value and discarded.
const redisDropHeadLua = `
local cur = redis.call('GET', KEYS[5])
local body = ''
if cur then body = string.sub(cur, 9) end
if body ~= ARGV[1] then
  return {'conflict'}
end
redis.call('DEL', KEYS[5])
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
func (b *RedisBackend) readInventorySnapshot(ctx context.Context) (recs []indexedRecord, seq string, head []byte, err error) {
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
		return nil, "", nil, err
	}

	seq = "0"
	if v, err := seqCmd.Result(); err == nil {
		seq = v
	} else if !errors.Is(err, redis.Nil) {
		return nil, "", nil, err
	}

	fields, err := entriesCmd.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, "", nil, err
	}
	recs, err = decodeEntryFields(fields)
	if err != nil {
		return nil, "", nil, err
	}

	if raw, err := headCmd.Bytes(); err == nil {
		if _, head, err = decodeBlob(raw); err != nil {
			return nil, "", nil, fmt.Errorf("decoding inventory head: %w", err)
		}
	} else if !errors.Is(err, redis.Nil) {
		return nil, "", nil, err
	}
	return recs, seq, head, nil
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
	recs, _, _, err := b.readInventorySnapshot(ctx)
	if err != nil {
		return nil, err
	}
	return entriesOf(recs), nil
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
		recs, seq, head, err := b.readInventorySnapshot(ctx)
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
		// Never silently: a short count must be explicable from the log, and
		// a backlog bigger than a whole call can remove is growing rather
		// than draining at the current cleanup cadence.
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
// fs.ErrNotExist. A non-empty legacy blob that decomposeLegacyInventory has
// not yet processed is returned verbatim so reads stay correct even before
// EnsureReady has run.
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
	if markerPresent && len(fields) == 0 {
		_, legacy, err := decodeBlob(raw)
		if err != nil {
			return nil, fmt.Errorf("decoding blob %q: %w", KeyInventory, err)
		}
		if len(legacy) > 0 {
			return legacy, nil
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
		conflict, err := b.replaceInventoryOnce(ctx, recs, nil, false)
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

// redisMarkerGuard pins the presence marker's stored value for the duration of
// a replacement: its 8-byte mtime prefix and its total length. Every write to
// that key — an old replica's blob append, a Put, a marker touch — stamps a
// fresh mtime, so an unchanged prefix means nothing has written it since the
// caller read it. A nil guard disables the check.
type redisMarkerGuard struct {
	mtime  string
	length int
}

// args renders the guard as the (enabled, mtime, length) ARGV triple the
// replacement scripts expect.
func (g *redisMarkerGuard) args() []any {
	if g == nil {
		return []any{"0", "", ""}
	}
	return []any{"1", g.mtime, strconv.Itoa(g.length)}
}

// replaceInventoryOnce performs one attempt at replacing the decomposed
// structure with recs: wipe, import in batches, then write the fresh presence
// marker. Every step is guarded on the sequence counter holding the value the
// previous step left, so an interleaved append (which allocates from that
// counter) is detected and the caller restarts; guard, when non-nil,
// additionally pins the marker. dropHead also deletes the stored integrity
// head in the final step, for callers whose head is known to be in the wrong
// scheme. Returns conflict=true when a guard failed and the caller should
// re-read and retry.
func (b *RedisBackend) replaceInventoryOnce(ctx context.Context, recs []CertRecord, guard *redisMarkerGuard, dropHead bool) (bool, error) {
	seqCmd, cancel := b.callCtx(ctx)
	seq, err := b.client.Get(seqCmd, b.invPhys(redisInvSeqSub)).Result()
	cancel()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			return false, err
		}
		seq = "0"
	}

	// Serials appearing on more than one record cannot be pointed at through
	// the one-to-one by-serial index without picking a wrong record for the
	// others; mark them ambiguous so index writes refuse instead of aliasing.
	dupSerials := make(map[string]bool)
	for _, serial := range duplicateSerials(recs) {
		dupSerials[serial] = true
	}

	wipeArgs := append([]any{seq}, guard.args()...)
	status, _, err := b.runInvScript(ctx, b.invReplaceWipeScript, wipeArgs...)
	if err != nil {
		return false, err
	}
	if status != redisResultOK {
		return true, nil
	}
	if b.importBatchHook != nil {
		b.importBatchHook()
	}

	written := 0
	for start := 0; start < len(recs); start += redisImportBatch {
		batch := recs[start:min(start+redisImportBatch, len(recs))]
		// One HSET per index field per script; later occurrences overwrite
		// earlier ones, in this batch and across batches, leaving each subject
		// pointing at its newest serial. A serial borne by several records
		// gets the ambiguity sentinel instead of a sequence number.
		argv := []any{strconv.Itoa(written), strconv.Itoa(written + len(batch))}
		argv = append(argv, guard.args()...)
		argv = append(argv, strconv.Itoa(len(batch)))
		for i, rec := range batch {
			val, err := encodeInventoryRecord(rec)
			if err != nil {
				return false, err
			}
			n := uint64(start+i) + 1
			serialValue := strconv.FormatUint(n, 10)
			if dupSerials[rec.Serial] {
				serialValue = serialAmbiguous
			}
			argv = append(argv, strconv.FormatUint(n, 10), rec.Serial, serialValue, rec.Subject, string(val))
		}
		status, _, err := b.runInvScript(ctx, b.invReplaceBatchScript, argv...)
		if err != nil {
			return false, err
		}
		if status != redisResultOK {
			return true, nil
		}
		if b.importBatchHook != nil {
			b.importBatchHook()
		}
		written += len(batch)
		// A fleet-scale conversion is many sequential scripts; report progress
		// periodically so the first post-upgrade start reads as a moving
		// import rather than an apparent hang (the same reasoning as the
		// certificate-index backfill's progress log).
		if written/redisImportProgressEvery != start/redisImportProgressEvery && written < len(recs) {
			slog.Info("Inventory import progress", "imported", written, "total", len(recs))
		}
	}

	finishArgs := []any{strconv.Itoa(len(recs))}
	finishArgs = append(finishArgs, guard.args()...)
	finishArgs = append(finishArgs, string(encodeMtime(time.Now())), boolArg(dropHead))
	status, _, err = b.runInvScript(ctx, b.invReplaceFinishScript, finishArgs...)
	if err != nil {
		return false, err
	}
	return status != redisResultOK, nil
}

func boolArg(v bool) string {
	if v {
		return "1"
	}
	return "0"
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

// --- Legacy blob decomposition ---

// decomposeLegacyInventory upgrades an inventory written by a pre-#139 version
// of this backend — a single text blob at inventory:data — into the decomposed
// hash structure. It runs from EnsureReady on every start; when there is no
// legacy blob (fresh deployment, or already decomposed) it is a cheap no-op.
//
// The blob stays authoritative until the import completes: the marker is only
// emptied by the final script, so an interrupted import (crash, Redis error,
// Ctrl-C) leaves the blob intact and the next start detects the partial entry
// set as a resumable state and redoes the import from the blob. Entries that
// are NOT a prefix of the blob mean something else wrote to the decomposed
// structure while the blob still had content — a mixed-version deployment —
// and that is refused with an explicit error rather than guessing which side
// to keep.
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
func (b *RedisBackend) decomposeLegacyInventory(ctx context.Context) error {
	// Cheap probe first: on every start after the one-time conversion this
	// path must not transfer the whole inventory, so read only the marker to
	// decide whether the expensive state read is needed at all.
	state, err := b.legacyMarkerState(ctx)
	if err != nil {
		return err
	}
	if len(state.blob) == 0 {
		// Nothing to import — but an upgraded CA whose inventory was empty
		// still carries a whole-blob head that no import will ever drop.
		return b.convertLegacyEmptyHead(ctx)
	}

	// Serialise the import across replicas starting up together.
	ul, err := b.AcquireLock(ctx, redisDecomposeLockName)
	if err != nil {
		return fmt.Errorf("locking for inventory decomposition: %w", err)
	}
	defer func() {
		if err := ul.Unlock(); err != nil {
			slog.Warn("Failed to release inventory-decompose lock", "error", err)
		}
	}()

	for attempt := range redisMaxRetries {
		// (Re-)read under the lock: another replica may have completed the
		// import while we waited, or an old-version replica may have appended.
		state, entries, err := b.legacyInventoryState(ctx)
		if err != nil {
			return err
		}
		if len(state.blob) == 0 {
			return nil
		}
		recs, err := parseInventoryRecords(state.blob)
		if err != nil {
			return fmt.Errorf("decomposing legacy redis inventory: %w", err)
		}
		if len(entries) > 0 {
			if !recordsArePrefixOf(entries, recs) {
				return fmt.Errorf("redis inventory holds both a non-empty legacy blob and decomposed entries that do not match it; " +
					"this usually means a pre-decomposition replica wrote to the blob after another replica upgraded. " +
					"Refusing to guess: inspect the inventory:data and inventory:entries keys under the key prefix and remove whichever is stale")
			}
			slog.Info("Resuming interrupted redis inventory decomposition", "imported", len(entries), "total", len(recs))
		}
		if err := b.verifyLegacyInventoryMAC(ctx, state.blob); err != nil {
			return err
		}
		if dups := duplicateSerials(recs); len(dups) > 0 {
			// Blob backends never had a cluster-wide duplicate-serial
			// guarantee, so a legacy inventory can legitimately carry
			// repeats. Refusing would brick startup; instead every line is
			// imported verbatim (preserving the rendered text), the serials
			// stay reserved against reissue, and certificate-index writes for
			// them are refused (see serialAmbiguous) so revocation state and
			// projections cannot land on the wrong record.
			slog.Warn("Legacy redis inventory contains duplicate serials; certificate-index state for them will be unavailable until the duplicates are resolved",
				"serials", dups)
		}
		conflict, err := b.replaceInventoryOnce(ctx, recs, &state.guard, true)
		if err != nil {
			return fmt.Errorf("decomposing legacy redis inventory: %w", err)
		}
		if !conflict {
			slog.Info("Decomposed legacy redis inventory blob into per-entry hash fields", "entries", len(recs))
			return nil
		}
		if err := b.scriptBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("decomposing legacy redis inventory: too many concurrent writers")
}

// redisLegacyState is a snapshot of the presence marker: the payload (empty
// when there is nothing to decompose) plus the guard that pins the stored
// value for the duration of an import.
type redisLegacyState struct {
	blob  []byte
	guard redisMarkerGuard
}

// legacyMarkerState reads the marker alone. This is the cheap every-start
// probe: one key, unlike legacyInventoryState which also transfers the whole
// entry hash.
func (b *RedisBackend) legacyMarkerState(ctx context.Context) (redisLegacyState, error) {
	callCtx, cancel := b.callCtx(ctx)
	defer cancel()
	raw, err := b.client.Get(callCtx, b.invPhys(redisInvDataSub)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return redisLegacyState{}, nil
		}
		return redisLegacyState{}, err
	}
	return decodeLegacyMarker(raw)
}

// legacyInventoryState returns the not-yet-decomposed inventory blob together
// with any decomposed entries already present, read atomically. A zero-length
// blob means there is nothing to decompose (no marker, or an already-emptied
// one).
func (b *RedisBackend) legacyInventoryState(ctx context.Context) (redisLegacyState, []indexedRecord, error) {
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
		return redisLegacyState{}, nil, err
	}

	raw, err := markerCmd.Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return redisLegacyState{}, nil, nil
		}
		return redisLegacyState{}, nil, err
	}
	state, err := decodeLegacyMarker(raw)
	if err != nil || len(state.blob) == 0 {
		return state, nil, err
	}

	fields, err := entriesCmd.Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return redisLegacyState{}, nil, err
	}
	entries, err := decodeEntryFields(fields)
	if err != nil {
		return redisLegacyState{}, nil, err
	}
	return state, entries, nil
}

// decodeLegacyMarker splits a stored marker value into its payload and the
// guard pinning it.
func decodeLegacyMarker(raw []byte) (redisLegacyState, error) {
	_, payload, err := decodeBlob(raw)
	if err != nil {
		return redisLegacyState{}, fmt.Errorf("decoding legacy inventory blob: %w", err)
	}
	return redisLegacyState{
		blob:  payload,
		guard: redisMarkerGuard{mtime: string(raw[:8]), length: len(raw)},
	}, nil
}

// convertLegacyEmptyHead completes the upgrade for a pre-decomposition CA
// whose inventory was empty. Such a CA always stores a whole-blob HMAC (CA
// bootstrap writes one over the empty inventory before the first cert is ever
// issued), but with no blob content there is no import to drop it as part of,
// so it would survive the upgrade and fail the first chain verification with a
// spurious tampering error that nothing re-baselines away.
//
// The head is deleted only when it verifies as the whole-blob MAC of an empty
// inventory under the stored key — the exact value the legacy code wrote — so
// the next verification re-establishes the chained baseline. Any other
// non-empty head over zero entries is deliberately left in place for
// verification to flag: it is indistinguishable from the residue of a
// decomposed inventory whose entries were tampered away, and deleting it would
// silently accept that.
func (b *RedisBackend) convertLegacyEmptyHead(ctx context.Context) error {
	keyPhys, err := b.physicalKey(KeyHMACKey)
	if err != nil {
		return err
	}
	for attempt := range redisMaxRetries {
		callCtx, cancel := b.callCtx(ctx)
		var (
			headCmd  *redis.StringCmd
			keyCmd   *redis.StringCmd
			countCmd *redis.IntCmd
		)
		_, err := b.client.TxPipelined(callCtx, func(p redis.Pipeliner) error {
			headCmd = p.Get(callCtx, b.invPhys(redisInvHMACSub))
			keyCmd = p.Get(callCtx, keyPhys)
			countCmd = p.HLen(callCtx, b.invPhys(redisInvEntriesSub))
			return nil
		})
		cancel()
		if err != nil && !errors.Is(err, redis.Nil) {
			return err
		}

		if n, err := countCmd.Result(); err != nil && !errors.Is(err, redis.Nil) {
			return err
		} else if n > 0 {
			return nil // decomposed entries exist; the head is theirs
		}

		rawHead, err := headCmd.Bytes()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return nil
			}
			return err
		}
		_, stored, err := decodeBlob(rawHead)
		if err != nil {
			return fmt.Errorf("decoding legacy inventory HMAC: %w", err)
		}
		if len(stored) == 0 {
			return nil // already the chained baseline of an empty inventory
		}
		rawKey, err := keyCmd.Bytes()
		if err != nil {
			return nil //nolint:nilerr // cannot verify; leave it for verification to fail closed
		}
		_, key, err := decodeBlob(rawKey)
		if err != nil || len(key) != hmacKeyLen {
			return nil //nolint:nilerr // same: unverifiable, so leave the head alone
		}
		if !hmac.Equal(wholeBlobInventoryMAC(key, nil), stored) {
			return nil
		}

		status, _, err := b.runInvScript(ctx, b.invDropHeadScript, string(stored))
		if err != nil {
			return err
		}
		if status == redisResultOK {
			slog.Info("Removed legacy whole-blob inventory HMAC for an empty inventory; the integrity baseline will be re-established on first verification")
			return nil
		}
		if err := b.scriptBackoff(ctx, attempt); err != nil {
			return err
		}
	}
	return fmt.Errorf("removing legacy inventory HMAC: too many concurrent writers")
}

// verifyLegacyInventoryMAC checks the legacy blob against its stored
// whole-blob HMAC before the blob is trusted as the import source. Absent
// head: nothing to check (the baseline is established after the import).
// Mismatch: fail startup with ErrInventoryTampered, exactly as the
// pre-decomposition verify would have. A head that cannot be verified —
// because the HMAC key is missing or malformed — also fails startup: the
// pre-decomposition code was fail-closed in that state too (it regenerated the
// key and then flagged the surviving head as tampering), and proceeding would
// silently promote an unverifiable blob to the new trusted baseline. The
// operator acknowledges a lost baseline by deleting the stored head.
func (b *RedisBackend) verifyLegacyInventoryMAC(ctx context.Context, blob []byte) error {
	keyPhys, err := b.physicalKey(KeyHMACKey)
	if err != nil {
		return err
	}
	callCtx, cancel := b.callCtx(ctx)
	defer cancel()

	var headCmd, keyCmd *redis.StringCmd
	if _, err := b.client.TxPipelined(callCtx, func(p redis.Pipeliner) error {
		headCmd = p.Get(callCtx, b.invPhys(redisInvHMACSub))
		keyCmd = p.Get(callCtx, keyPhys)
		return nil
	}); err != nil && !errors.Is(err, redis.Nil) {
		return err
	}

	rawHead, err := headCmd.Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return err
	}
	_, stored, err := decodeBlob(rawHead)
	if err != nil {
		return fmt.Errorf("decoding legacy inventory HMAC: %w", err)
	}
	rawKey, err := keyCmd.Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return fmt.Errorf("legacy redis inventory has a stored integrity value but no HMAC key to verify it with; "+
				"delete the %s key under the redis key prefix to acknowledge the lost baseline and retry: %w",
				redisInvHMACSub, ErrInventoryTampered)
		}
		return err
	}
	_, key, err := decodeBlob(rawKey)
	if err != nil || len(key) != hmacKeyLen {
		return fmt.Errorf("legacy redis inventory HMAC key is unreadable or malformed, so the stored integrity value cannot be verified; "+
			"delete the %s key under the redis key prefix to acknowledge the lost baseline and retry: %w",
			redisInvHMACSub, ErrInventoryTampered)
	}
	if !hmac.Equal(wholeBlobInventoryMAC(key, blob), stored) {
		return fmt.Errorf("legacy redis inventory failed integrity verification before decomposition: %w", ErrInventoryTampered)
	}
	return nil
}
