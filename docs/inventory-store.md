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
(see [storage-backends.md](storage-backends.md)).

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
(e.g. a SQL table) while preserving exact behaviour for backends that keep the
blob (filesystem, etcd, redis/valkey). This is opt-in per backend.

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
    // AppendEntry inserts e and advances the integrity head atomically.
    // newHead computes the chained head MAC from the previous head (nil when
    // the inventory is empty); the backend MUST invoke it inside the same
    // transaction/lock that serialises appends so the chain cannot fork under
    // concurrent appenders.
    AppendEntry(ctx context.Context, e InventoryEntry, newHead func(prev []byte) []byte) error

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

## Scope

- **SQL backend** (sqlite/postgres/mysql) implements `InventoryStore` with a
  dedicated `puppet_ca_inventory` table indexed on `subject` and `serial`, plus
  the render/parse shim. This is where decomposition pays off.
- **Filesystem, etcd, redis/valkey keep the blob.** They do not implement the
  interface; the type assertion fails and they behave exactly as before. Adding
  the capability to etcd/redis later is possible but not currently motivated.
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
