# Locking and concurrency

Reference for contributors (human or AI) touching any code path that reads or
mutates shared CA state. Deploying `openvox-ca` needs none of this. Companion
documents: [storage internals](storage-internals.md) for the backend contract
and [the inventory store](inventory-store.md) for inventory integrity.

The one-paragraph version: **mutations serialise on cluster-wide named locks
taken through `StorageService.WithLock`; read-only paths never take a
distributed lock** — they use in-memory caches and process-local read locks
only. When you add a code path, decide which side of that line it is on first,
and everything else follows.

## The three tiers

Locking happens at three distinct levels. They are not interchangeable — each
protects against a different class of interleaving.

| Tier | Mechanism | Protects against | Defined in |
| --- | --- | --- | --- |
| Cluster-wide named locks | `StorageService.WithLock(ctx, name, fn)` | Concurrent mutations from **other replicas** sharing the same backend | [storage.go](../../internal/storage/storage.go) |
| Storage-service mutexes | `serialMu`, `inventoryMu` (RW), `crlMu` (RW), `fileMu` (RW) | Interleaved compound storage operations **within this process** | [storage.go](../../internal/storage/storage.go) |
| CA in-memory state | `ca.CA.mu` (RW) | Torn reads/writes of the CA's **in-memory caches** | [ca.go](../../internal/ca/ca.go) |

### Tier 1: cluster-wide named locks (`WithLock`)

`StorageService.WithLock` runs `fn` while holding a named lock. When the
backend implements the optional `Locker` capability the lock is coordinated
across every replica sharing that backend; otherwise it falls back to a
process-local named `sync.Mutex`, which is correct for genuinely single-node
backends (filesystem, SQLite).

The lock names are part of the cross-replica protocol: every replica must agree
on them, so they are **stable across releases**. They are defined in
[init.go](../../internal/ca/init.go):

| Lock name | Serialises | Taken by |
| --- | --- | --- |
| `bootstrap` | First-run CA generation; seeding supporting state (CRL/inventory/serial) for a mounted cert+key; whole-store migration | `CA.Init`, `CA.seedSupportingState`, `storage.MigrateService` (which reuses the name deliberately so a migration and a bootstrapping server exclude each other) |
| `crl` | Every CRL read-modify-write (read entries → re-sign → write) | `Revoke`, `ReissueCRL`, `RefreshCRLIfDue`, `CleanupExpiredCerts`, and the revoke step inside `Clean`, `Renew`, `AutoRenew` |
| `subject:<name>` | The whole lifecycle of one subject: evict/save CSR/sign/import/clean | `SaveRequest`, `Sign`, `SignWithTTL`, `Renew`, `AutoRenew`, `Clean`, `ImportCertificate` — but currently **not** `Generate` (see known gaps below) |

How each backend provides the distributed lock:

| Backend | Mechanism | Crash recovery |
| --- | --- | --- |
| etcd | `concurrency.Mutex` under `<prefix>/locks/<name>` on a lease-backed session (30 s TTL) | Lease expires, lock releases |
| Redis/Valkey | `SET NX PX` with a per-acquisition random token; a heartbeat goroutine extends the TTL while held; unlock is a Lua compare-token-and-delete | TTL elapses, lock releases |
| PostgreSQL | `pg_advisory_lock` (session-level) on a dedicated pooled connection | Session ends, lock releases |
| MySQL/MariaDB | `GET_LOCK` on a dedicated connection, polled with a 1 s server-side wait so context cancellation is honoured | Session ends, lock releases |
| SQLite, filesystem | None — `ErrDistributedLockingUnsupported` / no `Locker`; `WithLock` falls back to a process-local mutex | n/a (single process assumed; see [#187](https://github.com/voxpupuli/openvox-ca/issues/187)) |
| Overlay | Delegates to the base backend's `Locker`; reports unsupported when the base has none | as base |

Every distributed implementation first takes a **per-name process-local mutex**
before touching the network. This is load-bearing, not an optimisation: etcd's
`concurrency.Mutex` is not safe for re-entry on one session, and on the SQL
backends it stops N in-process callers each pinning a pooled connection just to
queue on the same lock.

Callers bound lock acquisition *and* the critical section together with
`lockTimeout` (60 s, [init.go](../../internal/ca/init.go)) via
`context.WithTimeout` — long enough to ride out a brief leader election, short
enough that a crashed replica's stale lease doesn't hang requests forever.
Caveat: that timeout bounds only the *distributed* half. The process-local
mutexes (both the fallback path and the per-name gate in front of every
distributed implementation) are plain `sync.Mutex` and do not honour context
cancellation, so same-process waiters queue unboundedly. The in-flight
[PR #186](https://github.com/voxpupuli/openvox-ca/pull/186) adds this caveat
to `StorageService.WithLock`'s godoc.

### Tier 2: storage-service mutexes

`StorageService` guards each family of logical keys with its own process-local
mutex so a compound operation (read blob → transform → write blob) can't
interleave with another goroutine's within the process. Three are
`sync.RWMutex`; `serialMu` is a plain `sync.Mutex`, since the serial counter
has no read-only fast path:

| Mutex | Guards | Why compound |
| --- | --- | --- |
| `inventoryMu` | `inventory` + `inventory_hmac` | An append must scan for duplicate serials and advance the integrity head as one unit |
| `crlMu` | `crl` | Plain read/write pairs |
| `fileMu` | `ca_cert`, `ca_pubkey`, `ca_key`, `csr/<subject>`, `cert/<subject>`, per-subject private keys | One mutex spans all subjects; simple and sufficient at current scale |
| `serialMu` | `serial` | Plain read/write pairs |

These are **internal to `StorageService`** — callers never touch them, and no
`StorageService` method calls another locked method while holding one (they are
non-reentrant; doing so self-deadlocks). Methods that require a caller-held
mutex generally carry the `...Locked` suffix and always say which lock in
their doc comment. The doc comment is authoritative — a couple of helpers
(`readInventoryForHMAC`, `computeInventoryHMAC`) require `inventoryMu`
without carrying the suffix.

### Tier 3: CA in-memory state (`c.mu`)

`ca.CA.mu` protects the fields that make the hot read paths fast:
`CACert`/`CAKey` (readiness), `serialIndex` (OCSP subject lookup), `ocspCache`
(pre-signed responses), and `cachedCRL` (revocation checks for authentication
without a storage round-trip).

Mutating operations hold `c.mu` (write) across the storage mutation *and* the
cache update, so within a process the caches can never be observed out of step
with what the same process just wrote. Read paths take `c.mu.RLock` only.

`c.mu` is non-reentrant. The same `...Locked` suffix convention applies: e.g.
`revokeLocked` requires the cluster `crl` lock **and** `c.mu`; each `...Locked`
function's comment states exactly which locks its caller must hold.

## Lock ordering

Nested acquisition always follows one global order:

```text
subject:<name>  →  crl  →  c.mu  →  (StorageService internal mutexes)
```

- `Clean`, `Renew`, and `AutoRenew` are the paths that take all three: the
  subject lock around the whole operation, then the `crl` lock + `c.mu` for the
  revocation step. Note both release and re-acquire `c.mu` between the signing
  and revocation steps — `c.mu` is not held across a `WithLock` acquisition.
- No code path acquires `subject:<name>` while holding `crl`, and none acquires
  either while holding `c.mu`. Keep it that way; the comments in
  [signing.go](../../internal/ca/signing.go) record this invariant at each
  nesting site.
- Two *different* subject locks are never held at once (bulk operations like
  `SignMultiple` loop, taking one at a time).
- `CA.Init` inverts the order (it holds `c.mu` while acquiring `bootstrap`).
  That is safe only because `Init` runs to completion before the server starts
  serving, so nothing else can be holding a distributed lock while waiting on
  `c.mu`. Do not copy this pattern into anything that runs while serving.
- `MigrateService` holds two `bootstrap` locks (source backend, then
  destination). Pointing both at the same distributed backend would deadlock;
  migrating a store onto itself is unsupported.

## Read paths take no distributed locks — by design

Read-only operations must stay cheap and must keep working while another
replica holds a lock. The pattern:

- **Authentication revocation checks** (`IsRevokedSerial`) and **OCSP**
  (`OCSPResponse` fast path) answer from `cachedCRL`/`ocspCache`/`serialIndex`
  under `c.mu.RLock`.
- **HTTP GETs** (certificate, CRL, status listings) read straight through
  `StorageService` getters, which take only the relevant tier-2 read lock.
- `ReadInventory` verifies the integrity HMAC under `inventoryMu.RLock` but
  takes no cluster lock.

The costs of this choice are deliberate and documented:

- A replica's in-memory caches learn about other replicas' activity only when
  this process next writes them: `cachedCRL` staleness for authentication is
  [#171](https://github.com/voxpupuli/openvox-ca/issues/171) (being fixed by
  [PR #182](https://github.com/voxpupuli/openvox-ca/pull/182)'s background
  sync), and `serialIndex`/`ocspCache` staleness for OCSP is
  [#183](https://github.com/voxpupuli/openvox-ca/issues/183).
- A read racing a mutation sees either the old or the new state, never a torn
  one — every backend's `Put` is atomic with respect to readers (see the
  `Backend` contract in [backend.go](../../internal/storage/backend.go)).

When you add a read-only endpoint or check, follow this pattern. Do not
"defensively" wrap a read in `WithLock`: it adds a cluster round-trip per
request, serialises hot paths behind slow mutations, and — on the fallback
path — still provides no cross-replica guarantee anyway.

## Rules for new or changed code

1. **Classify the operation first.** Pure read → tier-2/3 read locks only,
   never `WithLock`. Any read-modify-write of shared backend state → the
   narrowest applicable cluster lock (`subject:<name>` where the unit of
   contention is one subject; `crl` for the CRL; `bootstrap` only for
   whole-store lifecycle).
2. **Hold the lock across the whole decision, not just the write.** The
   check that justifies a mutation (duplicate cert? already revoked? CRL still
   fresh?) must run *inside* the same `WithLock` as the mutation, or it is a
   TOCTOU bug. `RefreshCRLIfDue` (check-then-re-sign under one lock) and
   `SaveRequest` (evict-then-save-then-autosign under one lock) are the
   patterns to copy. [#173](https://github.com/voxpupuli/openvox-ca/issues/173)
   / [PR #186](https://github.com/voxpupuli/openvox-ca/pull/186) exist because
   a renewal once did such a re-check outside the lock.
3. **Keep expensive, shared-state-free work outside the lock.** Key
   generation and CSR assembly in `Generate` run before any lock is taken;
   parsing and validation in `Renew`/`SaveRequest` likewise. Only the
   storage-touching tail belongs inside.
4. **Respect the ordering** (`subject` → `crl` → `c.mu`), never acquire the
   same lock reentrantly, and release `c.mu` before entering another
   `WithLock`. Use the closure-with-defer shape from `Renew`/`AutoRenew` so a
   panic can't wedge a mutex.
5. **Calling convention:** public CA methods take their own locks and say so
   ("The caller must NOT hold c.mu"); internal `...Locked` helpers document
   which locks the caller must already hold. Preserve both halves when
   refactoring, and never call a public locking method from inside a locked
   region.
6. **A distributed lock is a serialiser, not a guarantee.** All the
   implementations are lease/session-based with no fencing tokens: a process
   paused longer than the TTL (GC pause, VM freeze, network partition) can
   lose the lock while still inside `fn`, and Redis failover can hand the lock
   over early (see the note on `RedisBackend.AcquireLock`). Where corruption
   would be the consequence, back the lock with a storage-level invariant that
   holds even without it — and check the invariant's own scope.
   `AppendInventory`'s duplicate-serial check (`ErrDuplicateSerial`) is the
   worked example, but it is a cluster-wide guarantee only on SQL backends,
   where the database's unique index enforces it; on blob backends the scan
   runs under the process-local `inventoryMu` only, and etcd's CAS-guarded
   append protects the blob against lost updates, not serial uniqueness (the
   doc comment on `ErrDuplicateSerial` in
   [storage.go](../../internal/storage/storage.go) spells this out).
7. **New lock names are protocol.** Add them to the constants in
   [init.go](../../internal/ca/init.go), keep them stable across releases, and
   document them in the table above. All callers using a name contend on one
   lock, so never derive a name from unvalidated input (subject names pass
   `ValidateSubject` first).
8. **SQL pool sizing:** on PostgreSQL/MySQL every *held* distributed lock pins
   one pooled connection. Paths that nest `subject:<name>` → `crl` need two
   simultaneously, plus connections for the queries inside; a `MaxOpenConns`
   set too low turns that into acquisition timeouts under load.
9. **Offline `openvox-ca-ctl` commands** (import, migrate) assume the server
   is stopped. `MigrateService` holds `bootstrap` on both stores, which
   excludes a booting server but deliberately not per-subject signing — and on
   filesystem/SQLite the fallback mutex has no cross-process effect at all
   ([#187](https://github.com/voxpupuli/openvox-ca/issues/187)).

## Known gaps (mostly tracked — check before re-reporting)

- [#195](https://github.com/voxpupuli/openvox-ca/issues/195) — `CA.Generate`
  (the `POST /generate/{subject}` endpoint) is the one issuance path that
  takes only `c.mu`, not the `subject:<name>` cluster lock. On an HA backend,
  a `Generate` on one replica can race a `Sign`/`SaveRequest`/`Generate` for
  the same subject on another and double-issue.
- [#196](https://github.com/voxpupuli/openvox-ca/issues/196) —
  `DELETE /certificate_request/{subject}` deletes the CSR directly through
  `StorageService`, bypassing the subject lock, so a deletion can be outrun
  by an in-flight sign for the same subject.
- [#197](https://github.com/voxpupuli/openvox-ca/issues/197) — OCSP's slow
  path signs responses while holding `c.mu` exclusively (an IPC round trip
  under key isolation), and nonced requests always take it; an efficiency
  gap rather than a correctness one.
- [#187](https://github.com/voxpupuli/openvox-ca/issues/187) — filesystem and
  SQLite backends have no same-host, cross-**process** locking; a `ctl`
  command (or the planned offline `generate`,
  [#175](https://github.com/voxpupuli/openvox-ca/issues/175)) racing a running server on
  the same cadir is uncoordinated. The related blob-backend gap — nothing
  wraps `AppendInventory` in a cluster lock on etcd/redis either — is
  explicitly split out of #187 for an issue of its own.
- [#171](https://github.com/voxpupuli/openvox-ca/issues/171) — `cachedCRL` is
  per-replica, so authentication and renewal keep accepting a certificate
  revoked elsewhere until this process re-signs the CRL.
  [PR #182](https://github.com/voxpupuli/openvox-ca/pull/182) fixes it with a
  background poll (`SyncCRLCache`, monotonic in the CRL number, deliberately
  lock-free).
- [#183](https://github.com/voxpupuli/openvox-ca/issues/183) — OCSP's
  `serialIndex` is built once at startup, so certificates issued on another
  replica answer `unknown`; the `ocspCache` half can even keep serving a
  pre-signed `good` for a certificate revoked elsewhere.
- [#173](https://github.com/voxpupuli/openvox-ca/issues/173) — renewal
  re-checked revocation before acquiring the subject lock.
  [PR #186](https://github.com/voxpupuli/openvox-ca/pull/186) fixes it
  (re-check from *storage* under the subject lock) and also moves `Revoke`
  itself under `subject:<name>` → `crl`, so expect the lock table above to
  need updating when it merges.
- On blob backends (filesystem/etcd/redis), an inventory append and its HMAC
  update are two writes, not one atomic unit; the failure window is documented
  at the write site in `AppendInventory` and the structured (SQL) inventory is
  the durable answer. See [the inventory store](inventory-store.md).

## Tests

`WithLock`'s fallback semantics are covered in
[withlock_test.go](../../internal/storage/withlock_test.go); each distributed
implementation's mutual exclusion is exercised in its backend integration
suite (build-tagged; see [testing](testing.md)).
