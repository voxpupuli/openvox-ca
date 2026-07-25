# Decomposing the inventory: the `InventoryStore` capability

## Background

Historically the certificate inventory is a single append-only text blob, the
Puppet-style `inventory.txt`, with one line per issued certificate:

```
SERIAL NOT_BEFORE NOT_AFTER /SUBJECT
```

It is addressed by the logical key `inventory` and manipulated through a handful
of `StorageService` methods (`AppendInventory`, `ReadInventory`,
`TouchInventory`, `HasInventory`). Integrity is provided by an HMAC-SHA256 over
the **entire blob**, stored under `inventory_hmac` and keyed by `hmac_key`
(see [storage-backends.md](../storage-backends.md)).

Despite being a blob, the inventory is only ever used three ways:

1. **Append one entry** when a certificate is signed.
2. **Find the latest serial for a subject** during revocation — a full scan.
3. **Build a serial → subject index** at startup for OCSP — a full scan, then
   held in memory and updated incrementally on each signing.

The inventory is never served over the API; the `inventory.txt` text format is
an internal and on-disk-compatibility concern only.

### Costs of the blob model

- Every append re-hashes the whole inventory (O(n) per append) and every read
  re-verifies it. Fine while inventories are small; wasteful as they grow.
- Lookups (revocation) scan the whole blob.
- A SQL backend stores the entire history as one ever-growing row.

## Goal

Let backends that can do better store the inventory as **structured records**
(e.g. a SQL table, or one etcd key per entry) while preserving exact behaviour
for backends that keep the blob (filesystem, redis/valkey). This is opt-in per
backend.

## Design

### Optional capability interface

Following the existing `Locker` pattern — an optional interface probed by
`StorageService` via a type assertion, with a clean fallback — we add:

```go
// InventoryEntry is one issued-certificate record. NotBefore/NotAfter are
// stored verbatim as the formatted strings the signing path produces, so that
// rendering rows back to inventory.txt is byte-identical to the legacy blob.
type InventoryEntry struct {
    Serial    string
    NotBefore string
    NotAfter  string
    Subject   string
}

// InventoryStore is an optional Backend capability for structured inventory
// storage. Backends that implement it let StorageService skip the
// render → scan → reparse round-trip. Backends that do not implement it keep
// using the KeyInventory blob via AppendLine/Get.
type InventoryStore interface {
    // AppendEntry inserts rec and advances the integrity head atomically.
    // newHead computes the chained head MAC from the previous head (nil when
    // the inventory is empty); the backend MUST invoke it inside the same
    // transaction/lock that serialises appends so the chain cannot fork under
    // concurrent appenders. rec is a CertRecord (see "The certificate index"
    // below); only its canonical InventoryEntry fields feed the chain.
    AppendEntry(ctx context.Context, rec CertRecord, newHead func(prev []byte) []byte) error

    // Entries returns every entry in issuance order, for the OCSP index build
    // and for chain verification.
    Entries(ctx context.Context) ([]InventoryEntry, error)

    // LatestSerialForSubject returns the most recently issued serial for
    // subject, wrapping fs.ErrNotExist when the subject has no entry.
    LatestSerialForSubject(ctx context.Context, subject string) (string, error)
}
```

`StorageService` probes `backend.(InventoryStore)`:

- **`AppendInventory`** → structured: build the `newHead` closure and call
  `AppendEntry`; blob: today's `AppendLine` + whole-blob HMAC recompute.
- **`LatestSerialForSubject`** (new) → structured: backend query; blob: scan the
  bytes from `ReadInventory` (the logic moved out of `ca.findSerialForSubject`).
- **`computeInventoryHMAC`** → structured: fold the chain over `Entries`; blob:
  HMAC over the blob bytes (unchanged).
- **`ReadInventory` / `TouchInventory` / `HasInventory`** keep using the blob
  path; for structured backends they are served by the render/parse shim
  (below), which keeps migration and the OCSP index build working unchanged.

### Integrity: a hash chain

Re-hashing the whole inventory on every append defeats the point of moving to a
table, so structured backends use a **hash chain** instead of a blob HMAC:

```
mac_i = HMAC-SHA256(key, mac_{i-1} ‖ canonical(entry_i))      mac_{-1} = ∅
head  = mac_n
```

- `canonical(entry)` is the exact `SERIAL NB NA /SUBJECT\n` line the signing
  path already writes, so the chain is trivially reproducible and independent of
  any backend's row encoding.
- The **head** (`mac_n`) is stored under the existing `inventory_hmac` blob row
  — no new logical key, and `VerifyInventoryHMAC`/`UpdateInventoryHMAC` keep
  their shape. The key still lives in `StorageService` (`s.hmacKey`); the
  `newHead` closure captures it, so no key handling leaks into backends.
- **Append is O(1)**: read the current head, hash one entry onto it, store the
  new head — all inside the backend's append transaction so the chain cannot
  fork across replicas.
- **Verification** is an O(n) fold over all rows at startup (same cost profile
  as the existing OCSP index build), compared against the stored head; a
  mismatch returns `ErrInventoryTampered`, exactly as today.

This detects modification, insertion, deletion, and truncation of the entry set
— the same tamper-evidence guarantee the blob HMAC provides, with the same
locally-held key threat model.

### Migration

`Migrate` copies blobs opaquely via `Backend.Get`/`Put` keyed by logical key. To
keep filesystem ⇄ SQL migrations working without teaching the migrator about
inventory internals, a structured backend serves the `inventory` logical key
through a **render/parse shim**:

- `Get(KeyInventory)` renders the rows back to byte-identical `inventory.txt`.
- `Put(KeyInventory, data)` parses the text and replaces the table contents
  (also covers the empty `Put` from `TouchInventory`).
- `Exists(KeyInventory)` reports whether the inventory has been seeded.

A chain head is **not** byte-portable across a backend-type change (a filesystem
blob HMAC ≠ a chain head over the same entries). So after the copy,
`MigrateService` — which holds both `StorageService`s and the destination key —
recomputes the destination's integrity head from its entries
(`RebuildInventoryHMAC`). This resolves the otherwise-spurious
`ErrInventoryTampered` that copying a foreign `inventory_hmac` would cause.

### The certificate index (`CertIndex`)

The inventory table doubles as a **certificate index**: alongside the four
canonical columns, each row carries a denormalised display projection
(`fingerprint_sha256`, `dns_alt_names`, `auth_extensions`, filled at signing)
and the one mutable fact, revocation (`state`, `revoked_at`). Backends owning
the rows may advertise a second optional capability:

```go
type CertIndex interface {
    // One record per subject with a stored certificate (latest issuance),
    // optionally filtered by state ("signed"/"revoked").
    Statuses(ctx context.Context, stateFilter string) ([]CertRecord, error)
    SetRevoked(ctx context.Context, serial string, at time.Time) error
    ClearRevoked(ctx context.Context, serial string) error
    SetProjection(ctx context.Context, serial string, proj CertProjection) error
}
```

`GET /certificate_statuses` probes it (via `StorageService.CertStatuses`,
mirroring `asInventoryStore`) and collapses from an O(N) *list-certs →
read-PEM → parse → CRL-check* scan to indexed queries; blob backends keep the
scan path verbatim. Pending CSRs are not issued certificates and stay on the
`csr/` list-and-parse path.

Design rules that keep the index honest:

- **The PEM and the signed CRL stay authoritative.** The projection columns
  are immutable copies of fields fixed at signing (so they cannot drift); the
  revocation columns are written by the revoke path right after the CRL is
  re-signed. Every column is rebuildable from the artefacts.
- **The hash chain covers only the canonical columns.** Chaining the
  projection would add nothing: each projected field is independently
  verifiable against a signed artefact.
- **Blob-imported rows carry no projection** (`fingerprint_sha256` NULL). The
  CA runs an index repair pass at startup (`rebuildCertIndex`) that backfills
  projections from the stored PEMs and reconciles `state` against the CRL —
  this is what makes a `storage migrate` from a blob backend converge. Until
  repair runs, the statuses handler falls back to the PEM per projection-less
  record.
- **Statuses is gated on blob existence.** Historical rows survive cleaning
  (that is the inventory's job), so the index reports only subjects whose
  `cert/<subject>` blob still exists, and only their latest issuance —
  matching what the scan path would have listed.

### The etcd decomposition

The etcd backend implements both capabilities too (issue #138), with a key
layout that plays to etcd's strengths — a sorted keyspace and multi-key
compare-then-op transactions:

```text
<prefix>/inventory/entries/<seq>       one JSON CertRecord per issuance;
                                       <seq> is zero-padded so a range scan
                                       returns issuance order
<prefix>/inventory/seq                 last allocated sequence number; doubles
                                       as the mutation fence (below)
<prefix>/inventory/by-serial/<serial>  serial → seq; existence is the atomic
                                       duplicate-serial guard
<prefix>/inventory/by-subject/<subj>   subject → latest serial (O(1) lookup)
<prefix>/inventory/data                presence marker for the KeyInventory
                                       logical key (empty payload)
<prefix>/inventory/hmac                chain head, unchanged logical key
```

Rules that keep the decomposed structure coherent:

- **One fence, guarded everywhere.** etcd transactions cannot read-compute-
  write, so `chainInventoryMAC` runs in Go between a read and a guarded
  commit. Every mutating transaction — append, prune batch, import batch —
  both *guards on* and *re-puts* `inventory/seq`, so any interleaved writer
  (same or another replica) invalidates the guard and forces a re-read. This
  is the same optimistic ModRevision-retry shape the blob append already used.
- **Appends are O(1)** — six puts guarded on the fence plus
  `CreateRevision(by-serial/<serial>) == 0`, which makes duplicate-serial
  rejection atomic cluster-wide (previously a SQL-only guarantee).
- **Bulk rewrites are batched but every commit is consistent.** Prunes and
  imports larger than one transaction (bounded well under etcd's default
  `--max-txn-ops` of 128) are split into batches, and each batch writes a head
  covering exactly the entries that remain after it. A concurrent verifier
  never sees entries and head out of sync, and a crash mid-prune leaves a
  valid, partially-pruned inventory rather than a spurious tamper alarm.
  Because a batched prune can partially complete, `PruneEntries` returns every
  entry actually removed — accumulated across batches and retries, even
  alongside an error — so `CleanupExpiredCerts` can always finish the CRL and
  blob cleanup for what was deleted (see the contract in `backend.go`). Prune
  batches run newest-first, which keeps the intermediate heads cheap: each is
  a cached prefix fold over the untouched older entries resumed across the
  survivor tail, rather than a full refold per batch.
- **Legacy blobs are decomposed in place.** `EnsureReady` detects a non-empty
  pre-decomposition `inventory/data` blob, takes a distributed lock
  (`inventory-decompose`), verifies the blob against its stored whole-blob
  HMAC (the key is a backend blob, so it is available; a mismatch fails
  startup with `ErrInventoryTampered` exactly as the old code would have),
  imports the lines into entry keys, and empties the marker only in the final
  commit. The verified HMAC is deleted in the same import — it is not a chain
  head, so it cannot carry over — and the next verification re-baselines from
  the imported entries; only the import window itself is uncovered. Because
  the blob stays authoritative until that final commit, an interrupted import
  is detected on the next start (the partial entries are the import-written
  prefix of the blob) and redone from the intact blob; entries that are *not*
  such a prefix mean a mixed-version cluster wrote both forms, which is
  refused with an explicit error rather than guessed at. Duplicate serials in
  the legacy blob — possible, since blob backends never had a cluster-wide
  uniqueness guarantee — are imported verbatim with a warning, with the
  by-serial index pointing at each serial's newest bearer. All replicas must
  still upgrade together: an old-version writer appending to the blob
  mid-import is detected via the marker guard and the import restarts, but
  the race only closes once the old writers are gone.
- **Certificate-index writes stay off the chain.** `SetRevoked` /
  `ClearRevoked` / `SetProjection` rewrite a single entry key guarded on its
  own ModRevision (the mutable fields are not chain input), so index repair
  cannot fork the integrity head.

## Scope

- **SQL backend** (sqlite/postgres/mysql) implements `InventoryStore` with a
  dedicated `puppet_ca_inventory` table indexed on `subject` (and a unique index
  on `serial`, since serials never repeat), plus the render/parse shim. This is
  where decomposition pays off.
- **etcd** implements `InventoryStore` and `CertIndex` with per-entry keys —
  see [The etcd decomposition](#the-etcd-decomposition) above.
- **Filesystem and redis/valkey keep the blob.** They do not implement the
  interface; the type assertion fails and they behave exactly as before. Adding
  the capability to redis later is possible (issue #139) but not currently
  motivated.
- **Wrapper backends unwrap to their base.** The probe is `asInventoryStore`,
  not a bare `s.backend.(InventoryStore)`: it sees through wrappers such as
  `OverlayBackend` (the `ca_cert_file`/`ca_key_file` local-override wrapper) via
  their `Unwrap()` method, so a SQL backend underneath keeps its hash-chain
  scheme rather than being downgraded to the whole-blob HMAC. Overriding only
  the cert/key blobs never touches the inventory, so consulting the base is
  always correct.
- **OCSP is untouched**: the in-memory serial index is still built at startup
  and updated on signing.

## Implementation phases

Each phase is a separate commit.

1. **Interface + routing.** Define `InventoryEntry` / `InventoryStore`; fork the
   `StorageService` inventory methods; move the subject-scan into
   `LatestSerialForSubject`; point `ca.findSerialForSubject` at it. No backend
   implements the interface yet, so behaviour is unchanged everywhere.
2. **SQL backend.** New bun migration creating `puppet_ca_inventory`; implement
   `AppendEntry`/`Entries`/`LatestSerialForSubject`; add the render/parse shim
   for the `inventory` logical key.
3. **Migration integrity rebuild.** Add `RebuildInventoryHMAC` and call it from
   `MigrateService` after the copy.
4. **Tests.** Exercise the inventory contract against both blob and structured
   backends: latest-wins lookups, chain tamper detection (modify / insert /
   delete), byte-identical render, and a filesystem ⇄ sqlite migration
   round-trip that verifies integrity on both sides.
5. **Certificate index** (issue #137, a later extension). Extend the SQL
   inventory table with the projection/state columns, define `CertIndex`,
   serve `certificate_statuses` from it, and add the startup repair pass.
6. **etcd decomposition** (issue #138, a later extension). Implement
   `InventoryStore` and `CertIndex` on the etcd backend with per-entry keys,
   including the in-place legacy blob conversion described above.
