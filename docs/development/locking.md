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
on them, so they are **stable across releases**. Names taken through
`WithLock` by the CA layer are defined in
[init.go](../../internal/ca/init.go) — with one mirror: `migrateLockName` in
[migrate.go](../../internal/storage/migrate.go) redefines `"bootstrap"`
independently (the `internal/storage` package cannot import `internal/ca`), so
the two are coupled only by the string literal and must be renamed together.
Backend-internal locks live beside the backend that takes them, for the same
import-direction reason: `etcdDecomposeLockName` (`"inventory-decompose"`) in
[etcd_inventory.go](../../internal/storage/etcd_inventory.go). They are no
less protocol for it.

| Lock name | Serialises | Taken by |
| --- | --- | --- |
| `bootstrap` | First-run CA generation; seeding supporting state (CRL/inventory/serial) for a mounted cert+key; whole-store migration | `CA.Init`, `CA.seedSupportingState`, `storage.MigrateService` (which reuses the name deliberately so a migration and a bootstrapping server exclude each other) |
| `crl` | Every CRL read-modify-write (read entries → re-sign → write) | `Revoke`, `RevokeSerial`, `ReissueCRL`, `RefreshCRLIfDue`, `CleanupExpiredCerts`, and the revoke step inside `Clean`, `Renew`, `AutoRenew` |
| `subject:<name>` | The whole lifecycle of one subject: evict/save CSR/sign/delete CSR/import/clean/revoke | `SaveRequest`, `Sign`, `SignWithTTL`, `DeleteRequest`, `Renew`, `AutoRenew`, `Clean`, `ImportCertificate`, `Revoke` — but currently **not** `Generate` (see known gaps below) |
| `inventory-decompose` | One-time legacy inventory blob conversion (etcd backend only) on the first start after upgrading | `EtcdBackend.decomposeLegacyInventory`, from `EnsureReady` |

How each backend provides the distributed lock (a summary — the full per-backend
mechanism, key layouts and transaction/retry detail lives in
[storage internals](storage-internals.md), which owns it):

| Backend | Mechanism | Crash recovery |
| --- | --- | --- |
| etcd | `concurrency.Mutex` under `<prefix>/locks/<name>` on a lease-backed session (30 s TTL) | Lease expires within the TTL, lock releases |
| Redis/Valkey | `SET NX PX` with a per-acquisition random token; a heartbeat goroutine extends the TTL while held; unlock is a Lua compare-token-and-delete | Key expires within the TTL, lock releases |
| PostgreSQL | `pg_advisory_lock` (session-level) on a dedicated pooled connection | Only when the server reaps the session — no TTL (see below) |
| MySQL/MariaDB | `GET_LOCK` on a dedicated connection, polled with a 1 s server-side wait so context cancellation is honoured | Only when the server reaps the session — no TTL (see below) |
| SQLite, filesystem | None — `ErrDistributedLockingUnsupported` / no `Locker`; `WithLock` falls back to a process-local mutex | n/a (single process assumed; see [#187](https://github.com/voxpupuli/openvox-ca/issues/187)) |
| Overlay | Delegates to the base backend's `Locker`; reports unsupported when the base has none | as base |

Crash recovery is not uniform across those backends. etcd and Redis self-heal
within the lock TTL (30 s): a crashed holder's lease or key expires and the lock
frees itself, which is what the 60 s `lockTimeout` below is sized to ride out.
The SQL advisory locks have **no TTL** — `pg_advisory_lock` and `GET_LOCK`
persist until the database tears the holder's session down, and after a hard
host loss or network partition that is governed by the server's own keepalive
settings (PostgreSQL `tcp_keepalives_idle`, MySQL `wait_timeout`), whose
defaults are measured in hours. A crashed replica can therefore hold `crl` or
`subject:<name>` far beyond `lockTimeout` while every surviving replica's
revoke/sign fails at that timeout; the recovery action is to terminate the
orphaned backend session (`pg_terminate_backend` / `KILL`) or to lower those
server-side keepalives for HA deployments.

Every distributed implementation first takes a **per-name process-local mutex**
before touching the network. This is load-bearing, not an optimisation: etcd's
`concurrency.Mutex` is not safe for re-entry on one session, and on the SQL
backends it stops N in-process callers each pinning a pooled connection just to
queue on the same lock.

CA request paths bound lock acquisition *and* the critical section together
with `lockTimeout` (60 s, [init.go](../../internal/ca/init.go)) via
`context.WithTimeout` — long enough to ride out a brief leader election, short
enough that a crashed replica's stale lease doesn't hang requests forever. Two
things that timeout does *not* cover. First, it bounds only the *distributed*
half: the process-local mutexes (both the fallback path and the per-name gate
in front of every distributed implementation) are plain `sync.Mutex` and do not
honour context cancellation, so same-process waiters queue unboundedly. Second,
the offline `openvox-ca-ctl migrate` path applies no timeout at all —
`MigrateService` inherits the caller's context, which is signal-cancellable but
carries no deadline — so a migration waits indefinitely on a contended
`bootstrap` lock; interrupt it and stop the server rather than waiting.

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

One shared-state key is deliberately absent from this table: `hmac_key`. Its
initialisation (`EnsureHMACKey`, reached via `InitHMAC` *before* any lock is
taken) is an unlocked read-modify-write, guarded by neither a mutex nor a
cluster lock today — a genuine gap, tracked as
[#202](https://github.com/voxpupuli/openvox-ca/issues/202) (see known gaps).

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

`DeleteRequest` is the one mutation that takes no `c.mu` at all: a pending CSR
backs none of these caches, so there is nothing to keep in step with the write.
That is worth knowing beyond cache coherence — it is why a rejection does not
serialise against `Generate` even within a single process, where `c.mu` is what
the two would otherwise have in common.

`c.mu` is also held across the signing call itself. Every issuance path (`Sign`,
`SignWithTTL`, `SaveRequest`'s autosign, `Renew`, `AutoRenew`,
`ImportCertificate`, `Generate`) calls `issueLeafLocked` with `c.mu` held, and
`x509.CreateCertificate` runs inside it — so with an external key provider
(`ca_key_provider: openbao`, or the isolated signer) `c.mu`, not the per-subject
cluster lock, is the process-wide issuance serialiser, and it spans a
network/IPC round trip. Issuance therefore proceeds at roughly one signing
round trip at a time within a process, and a stalled signer backend pins the
mutex and stalls all issuance — see the "Performance and outage behaviour"
section of [the OpenBao Transit guide](../openbao-transit.md). This is the one
deliberate exception to rule 3 (keep expensive work outside the lock): the
signature is inside the lock because the cache update it guards must be atomic
with the issuance.

`c.mu` is non-reentrant. The same `...Locked` suffix convention applies: e.g.
`revokeLocked` requires the cluster `crl` lock **and** `c.mu`; each `...Locked`
function's comment states exactly which locks its caller must hold.

`RevokeSerial` takes the same two as `Revoke` and in the same order, and its
checks run inside them for the reason rule 3 exists: the subject a serial belongs
to, and whether that subject's stored certificate still carries it, are what
justify the CRL write, so resolving either outside the lock would let the answer
go stale before the mutation. That puts an inventory read — on blob backends an
HMAC verification over the whole blob — inside the `crl` lock, which is why the
operation is documented as operator-initiated rather than something to call in a
loop.

## Lock ordering

Nested acquisition always follows one global order:

```text
subject:<name>  →  crl  →  c.mu  →  (StorageService internal mutexes)
```

- `Revoke`, `Clean`, `Renew`, and `AutoRenew` are the paths that take all
  three. For the three issuance paths it is the subject lock around the whole
  operation, then the `crl` lock + `c.mu` for the revocation step; note they
  release and re-acquire `c.mu` between the signing and revocation steps —
  `c.mu` is not held across a `WithLock` acquisition. `Revoke` has the same
  nesting for a different reason: the `crl` lock + `c.mu` cover the revocation
  that is the whole operation, and the subject lock is there only to serialise
  it against an issuance already under way for that subject.
- No code path acquires `subject:<name>` while holding `crl`, and none acquires
  either while holding `c.mu`. Keep it that way; the comments in
  [signing.go](../../internal/ca/signing.go) and
  [revoke.go](../../internal/ca/revoke.go) record this invariant at each
  nesting site.
- Two *different* subject locks are never held at once (bulk operations like
  `SignMultiple` loop, taking one at a time).
- `CA.Init` inverts the order (it holds `c.mu` while acquiring `bootstrap`).
  The inversion itself is safe only because `Init` runs to completion before
  the server starts serving, so nothing else can be holding a distributed lock
  while waiting on `c.mu`; do not copy this pattern into anything that runs
  while serving. Init also has a *separate*, unfixed hazard on the same lock —
  its slow path can re-enter `bootstrap` and deadlock startup
  ([#201](https://github.com/voxpupuli/openvox-ca/issues/201)); see known gaps.
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
   storage-touching tail belongs inside. The deliberate exception is the CA
   signature itself: `x509.CreateCertificate` runs under `c.mu` (see Tier 3),
   because the cache update it guards must be atomic with the issuance.
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
   worked example: it is a cluster-wide guarantee on the structured backends —
   SQL via the database's unique index, etcd via the `by-serial` key's
   `CreateRevision == 0` guard inside the append transaction — but on the
   remaining blob backends (filesystem, redis) the scan runs under the
   process-local `inventoryMu` only (the doc comment on `ErrDuplicateSerial`
   in [storage.go](../../internal/storage/storage.go) spells this out, and
   the blob-backend gap is tracked as
   [#204](https://github.com/voxpupuli/openvox-ca/issues/204)).
7. **New lock names are protocol.** Define CA-layer names as constants in
   [init.go](../../internal/ca/init.go) (keeping `migrateLockName` in
   [migrate.go](../../internal/storage/migrate.go) in sync — it redefines
   `"bootstrap"` independently) and backend-internal names as constants in the
   owning backend package (e.g. `etcdDecomposeLockName` in
   [etcd_inventory.go](../../internal/storage/etcd_inventory.go)); keep them
   all stable across releases, and document them in the table above. All
   callers using a name contend on one lock, so
   never derive a name from unvalidated input (subject names pass
   `ValidateSubject` first). `ValidateSubject` is necessary but not sufficient
   on the SQL backends: there the lock identity is a 64-bit FNV-1a hash of the
   name (`advisoryLockKey`), so distinct names can alias and a crafted subject
   could collide with `crl`/`bootstrap`
   ([#203](https://github.com/voxpupuli/openvox-ca/issues/203)).
8. **SQL pool sizing:** on PostgreSQL/MySQL every *held* distributed lock pins
   one pooled connection. A single in-flight `Revoke`/`Clean`/`Renew`/`AutoRenew`
   needs at least three connections at once — one for the `subject:<name>` lock,
   a second for the nested `crl` lock, and a third for the reads/writes inside
   the revocation step — so `sql_max_open_conns` must be at least 3 per
   concurrently mutating request. `Revoke` joined that list when it took the
   subject lock: revoking many *distinct* subjects at once used to queue on the
   single `crl` gate and hold one lock connection between them, whereas each
   concurrent revocation now pins its own `subject:<name>` connection while it
   waits for `crl`. Set below that and a single request
   hard-stalls (not only under load), bounded only by the 60 s `lockTimeout`.
   See the `sql_max_open_conns` knob in
   [storage backends](../storage-backends.md).
9. **Offline `openvox-ca-ctl` commands** (import, migrate) assume the server
   is stopped. `MigrateService` holds `bootstrap` on both stores, which
   excludes a booting server but deliberately not per-subject signing — and on
   filesystem/SQLite the fallback mutex has no cross-process effect at all
   ([#187](https://github.com/voxpupuli/openvox-ca/issues/187)). It also
   inherits the caller's context with no `lockTimeout`, so it waits
   indefinitely on a contended `bootstrap` lock (see Tier 1).

## Known gaps

Concurrency limitations that are understood and tracked. This list reflects the
state when the document was last updated and is not guaranteed exhaustive.

- [#195](https://github.com/voxpupuli/openvox-ca/issues/195) — `CA.Generate`
  (the `POST /generate/{subject}` endpoint) is the one issuance path that
  takes only `c.mu`, not the `subject:<name>` cluster lock. On an HA backend,
  a `Generate` on one replica can race a `Sign`/`SaveRequest`/`Generate` for
  the same subject on another and double-issue. Two passages retire with this
  gap and are reachable only from here: the `POST /generate/{subject}`
  paragraph under [CSR management](../api.md#csr-management), and the
  `Generate` paragraph in `CA.DeleteRequest`'s godoc
  ([signing.go](../../internal/ca/signing.go)). Delete both when closing it —
  they describe a mechanism that goes away with the lock.
- [#197](https://github.com/voxpupuli/openvox-ca/issues/197) — OCSP's slow
  path signs responses while holding `c.mu` exclusively, so nonced requests
  (which always miss the cache) serialise process-wide behind the signing
  round trip. This is the same "signature under `c.mu`" property as the
  issuance paths (see Tier 3) surfacing on the OCSP responder; an efficiency
  gap rather than a correctness one.
- [#201](https://github.com/voxpupuli/openvox-ca/issues/201) — `CA.Init`'s slow
  path can re-enter the `bootstrap` lock (via `finishLoadExisting` →
  `seedSupportingState`) and deadlock startup, because `WithLock` is not
  reentrant and its process-local gate ignores the context. Reachable when a
  replica loads a CA bootstrapped elsewhere but then finds the CRL absent.
- [#202](https://github.com/voxpupuli/openvox-ca/issues/202) — `hmac_key`
  initialisation (`EnsureHMACKey`, called by `InitHMAC` *before* the
  `bootstrap` lock) is an unlocked read-modify-write, so two replicas
  cold-starting against a fresh shared backend can generate divergent keys and
  one then fails inventory-HMAC verification.
- [#203](https://github.com/voxpupuli/openvox-ca/issues/203) — on the SQL
  backends the distributed-lock identity is a 64-bit FNV-1a hash of the name,
  so distinct names can alias; a crafted subject that passes `ValidateSubject`
  could collide with the `crl`/`bootstrap` key and deny revocation.
- [#187](https://github.com/voxpupuli/openvox-ca/issues/187) — filesystem and
  SQLite backends have no same-host, cross-**process** locking; a `ctl`
  command (or the planned offline `generate`,
  [#175](https://github.com/voxpupuli/openvox-ca/issues/175)) racing a running
  server on the same cadir is uncoordinated. The related blob-backend gap —
  nothing wraps `AppendInventory` in a cluster lock on Redis, so its
  duplicate-serial check is not cross-replica there — is tracked separately
  as [#204](https://github.com/voxpupuli/openvox-ca/issues/204); the etcd
  half of that gap was closed by the decomposed inventory's atomic
  `by-serial` guard ([#138](https://github.com/voxpupuli/openvox-ca/issues/138)).
- [#171](https://github.com/voxpupuli/openvox-ca/issues/171) — `cachedCRL` is
  per-replica, so authentication and renewal keep accepting a certificate
  revoked elsewhere until this process re-signs the CRL.
  [PR #182](https://github.com/voxpupuli/openvox-ca/pull/182) fixes it with a
  background poll (monotonic in the CRL number, deliberately lock-free).
- [#183](https://github.com/voxpupuli/openvox-ca/issues/183) — OCSP's
  `serialIndex` is built once at startup, so certificates issued on another
  replica answer `unknown`; the `ocspCache` half can even keep serving a
  pre-signed `good` for a certificate revoked elsewhere.
- ~~[#196](https://github.com/voxpupuli/openvox-ca/issues/196) —
  `DELETE /certificate_request/{subject}` deleted the CSR directly through
  `StorageService`, bypassing the subject lock.~~ Fixed: the handler now goes
  through `CA.DeleteRequest`, which takes `subject:<name>` for the delete, so a
  rejection orders against an in-flight sign instead of racing it. The HTTP
  layer also stopped reporting a failed deletion as `404`, which had told the
  operator the request was gone at the moment it was still queued; it answers
  `503` now. The one issuance a rejection still cannot wait for is `Generate`,
  which saves and signs a CSR under `c.mu` alone — see the `Generate` gap
  above.
- ~~[#173](https://github.com/voxpupuli/openvox-ca/issues/173) — renewal
  re-checked revocation before acquiring the subject lock.~~ Fixed: both
  renewal paths now call `refuseIfRevoked` again as the first statement inside
  the subject lock, and `Revoke` takes `subject:<name>` → `crl` so nothing can
  revoke in the gap between that answer and the issuance it guards. The one
  issuance path a revocation still cannot wait for is `Generate`, which takes
  no distributed lock — see the `Generate` gap above.
- On blob backends (filesystem/redis), an inventory append and its HMAC
  update are two writes, not one atomic unit; the failure window is documented
  at the write site in `AppendInventory` and the structured (SQL, etcd)
  inventory — which commits the entry and its integrity head in one
  transaction — is the durable answer. See
  [the inventory store](inventory-store.md).

## Tests

`WithLock`'s fallback semantics, its overlay/unsupported delegation, and its
unlock-error handling are covered in
[withlock_test.go](../../internal/storage/withlock_test.go); each distributed
implementation's mutual exclusion is exercised in its backend integration
suite (build-tagged; see [testing](testing.md)).

That a given path takes its lock *at all* is automated for five of them, all in
the same shape: park the operation on a held `subject:<name>` and require it to
wait, since one that stopped taking the lock returns immediately instead.
[renewrace_test.go](../../internal/ca/renewrace_test.go) does this for `Revoke`,
`Clean`, `Renew` and `AutoRenew` alongside the ordering assertions described
below, and
[deleterequest_test.go](../../internal/ca/deleterequest_test.go) for
`DeleteRequest`. That last one also pins the far side — it parks a delete on
the inventory append inside an autosigning `SaveRequest`'s issuance, so it
observes the lock being held from that append until `SaveRequest` returns, not
across the evict/save prefix ahead of it. Dropping `SaveRequest`'s `WithLock`
still fails it, which is what makes `SaveRequest` pinned too. `Sign`,
`SignWithTTL` and `ImportCertificate` are the ones with no such spec: for those
the lock-name table above is the only record, and dropping the lock fails no
assertion. That is the shape to copy when closing one of the gaps above.

The nested lock-ordering invariant *is* now automated, in
[renewrace_test.go](../../internal/ca/renewrace_test.go): for each caller that
holds both locks — `Revoke`, `Clean`, `Renew`, `AutoRenew` — it parks the
operation on a held subject lock and requires `crl` to still be grantable while
it waits. An inverted nesting therefore fails on an assertion rather than
deadlocking the suite to its timeout, which is how an inversion otherwise
presents: every backend serialises same-process callers on a mutex that ignores
the context deadline. These run under the race detector on every unit
run: `mage test:unit` passes `-race` over every unit package, `internal/ca`
included. What is still unraced is the build-tagged backend integration
suites — tracked as
[#205](https://github.com/voxpupuli/openvox-ca/issues/205).
