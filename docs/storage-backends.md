# Storage backends

`puppet-ca` abstracts its persistent state behind a pluggable **Backend**
interface. Two backends ship today:

| Kind           | Status  | Best for                                                                   |
|----------------|---------|----------------------------------------------------------------------------|
| `filesystem`   | default | single-node installs; drop-in compatibility with Puppet Server's CA layout |
| `etcd`         | stable  | HA clusters where multiple `puppet-ca` replicas share a single CA          |

Regardless of backend, **server-generated per-subject private keys always
live on local disk**. They are issued once, handed back to the requester, and
retained locally for operator convenience only; they are never written to a
remote store.

The CA certificate and/or the CA private key can optionally be pinned to a
local file (e.g. a mounted secret volume) independent of the chosen backend —
see [CA cert/key as local files](#ca-certkey-as-local-files).

---

## Backend contract

Every backend serves the following logical keys:

| Logical key         | Purpose                                                   | Writer                    |
|---------------------|-----------------------------------------------------------|---------------------------|
| `ca_cert`           | CA certificate (PEM)                                      | bootstrap / import        |
| `ca_pubkey`         | CA public key (PEM, companion to `ca_cert`)               | bootstrap                 |
| `ca_key`            | CA private key (PEM, optionally AES-256-GCM encrypted)    | bootstrap / import        |
| `crl`               | Current Certificate Revocation List (PEM)                 | bootstrap, revoke, rotate |
| `serial`            | Next leaf certificate serial counter                      | sign                      |
| `inventory`         | Append-only log of issued/revoked certificates            | sign / revoke             |
| `inventory_hmac`    | HMAC-SHA256 of inventory, for tamper detection            | sign / revoke             |
| `hmac_key`          | Integrity key for `inventory_hmac`                        | first run                 |
| `csr/<subject>`     | Pending certificate signing request (PEM), per subject    | CSR submission            |
| `cert/<subject>`    | Issued certificate (PEM), per subject                     | sign                      |

`inventory` is the only key that supports atomic append semantics; all other
keys are whole-blob read/write/delete.

---

## Filesystem backend (default)

All CA state lives under `--cadir`. The on-disk layout matches Puppet Server's
CA so operators can swap in `puppet-ca` without reorganising their SSL tree:

```
<cadir>/
├── ca_crt.pem                      (KeyCACert)
├── ca_pub.pem                      (KeyCAPubKey)
├── ca_crl.pem                      (KeyCRL)
├── serial                          (KeySerial)
├── inventory.txt                   (KeyInventory)
├── .inventory.hmac                 (KeyInventoryHMAC)
├── private/
│   ├── ca_key.pem                  (KeyCAKey)          0600
│   ├── .inventory_hmac_key         (KeyHMACKey)        0600
│   └── <subject>_key.pem           server-gen keys     0600
├── requests/
│   └── <subject>.pem               (csr/<subject>)
└── signed/
    └── <subject>.pem               (cert/<subject>)
```

File permissions are fixed: `0600` for anything under `private/` and for the
inventory and its HMAC; `0644` for everything else. `puppet-ca` warns at
startup about any `*_key.pem` files in `private/` whose permissions are looser
than `0600` and leaves them for the operator to fix.

### Configuration

Default. Nothing to set.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: filesystem   # optional; this is the default
cadir: /etc/puppetlabs/puppet/ssl/ca
```

---

## etcd backend

Stores every logical key except the local private-key directory in an etcd v3
cluster. Multiple `puppet-ca` replicas can point at the same cluster (and the
same `etcd_key_prefix`) to share CA state: any replica can sign, revoke, or
refresh the CRL, and the other replicas see the update immediately.

### Key layout

With the default prefix `/puppet-ca`:

| Logical key         | etcd key                              |
|---------------------|---------------------------------------|
| `ca_cert`           | `/puppet-ca/ca/cert`                  |
| `ca_pubkey`         | `/puppet-ca/ca/pubkey`                |
| `ca_key`            | `/puppet-ca/ca/key`                   |
| `crl`               | `/puppet-ca/ca/crl`                   |
| `serial`            | `/puppet-ca/serial`                   |
| `inventory`         | `/puppet-ca/inventory/data`           |
| `inventory_hmac`    | `/puppet-ca/inventory/hmac`           |
| `hmac_key`          | `/puppet-ca/private/hmac_key`         |
| `csr/<subject>`     | `/puppet-ca/requests/<subject>`       |
| `cert/<subject>`    | `/puppet-ca/signed/<subject>`         |

Stored values carry an 8-byte big-endian `time.UnixNano` mtime prefix so
`GET /puppet-ca/v1/certificate_revocation_list/ca` still answers
`If-Modified-Since` without a second round-trip.

Inventory appends use an etcd transaction guarded on the key's `ModRevision`
with bounded retry, so concurrent appends across replicas don't lose lines.

### Cross-node coordination

Operations that perform a read-modify-write against shared state — CA
bootstrap, CRL rotation during revocation, CSR-then-autosign sequencing — are
serialised across replicas by distributed locks implemented on top of etcd's
`concurrency.Mutex`. The backend keeps a lease-backed session (30s TTL) and
grabs per-name mutexes under `<prefix>/locks/<name>`:

| Lock name           | Held during                                       |
|---------------------|---------------------------------------------------|
| `bootstrap`         | First-run CA generation (winner writes, loser loads) |
| `crl`               | `Revoke` (read CRL, append entry, write CRL)      |
| `subject:<subject>` | `SaveRequest` and `Sign` for that one subject     |

If a replica holding a lock crashes without calling Unlock, the etcd lease
expires after 30s and the lock is released automatically.

For the filesystem backend (single-node), the same call path falls back to a
process-local `sync.Mutex` per lock name.

### Configuration

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: etcd
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
                                         # and ancillary local state

etcd_endpoints:
  - https://etcd-0.example.com:2379
  - https://etcd-1.example.com:2379
  - https://etcd-2.example.com:2379
etcd_key_prefix: /puppet-ca              # default shown; override to
                                         # share a cluster between CAs
etcd_dial_timeout_sec: 5
etcd_request_timeout_sec: 5

# Optional authentication.
etcd_username: puppet-ca
etcd_password: "..."                     # prefer PUPPET_CA_ETCD_PASSWORD

# Optional mTLS to the etcd cluster.
etcd_tls_ca_file:   /etc/puppet-ca/etcd-ca.pem
etcd_tls_cert_file: /etc/puppet-ca/etcd-client.pem
etcd_tls_key_file:  /etc/puppet-ca/etcd-client-key.pem
```

### CLI flags

```
--storage-backend etcd
--etcd-endpoints  https://etcd-0:2379,https://etcd-1:2379,https://etcd-2:2379
--etcd-key-prefix /puppet-ca
```

### Environment variables

| Config key                 | Env var                               |
|----------------------------|---------------------------------------|
| `storage_backend`          | `PUPPET_CA_STORAGE_BACKEND`           |
| `etcd_endpoints`           | `PUPPET_CA_ETCD_ENDPOINTS` (comma-separated) |
| `etcd_key_prefix`          | `PUPPET_CA_ETCD_KEY_PREFIX`           |
| `etcd_username`            | `PUPPET_CA_ETCD_USERNAME`             |
| `etcd_password`            | `PUPPET_CA_ETCD_PASSWORD`             |
| `etcd_dial_timeout_sec`    | `PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC`     |
| `etcd_request_timeout_sec` | `PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC`  |
| `etcd_tls_ca_file`         | `PUPPET_CA_ETCD_TLS_CA_FILE`          |
| `etcd_tls_cert_file`       | `PUPPET_CA_ETCD_TLS_CERT_FILE`        |
| `etcd_tls_key_file`        | `PUPPET_CA_ETCD_TLS_KEY_FILE`         |

### Operational notes

- **CA cert and key in etcd.** By default the etcd backend stores the CA
  private key in etcd too. That's a deliberate choice — it lets new replicas
  join the cluster without needing the key copied out of band — but it means
  the etcd cluster is now a blast-radius for the CA key. Consider:
  - Restricting etcd ACLs on `/puppet-ca/ca/key` to the `puppet-ca` identity.
  - Enabling CA key encryption at rest (`encrypt_ca_key: true`) so the key
    stored in etcd is AES-256-GCM wrapped with an Argon2id-derived key.
  - Or pinning the key to a local file via `ca_key_file` (see below).
- **Inventory HMAC.** The integrity key lives under
  `/puppet-ca/private/hmac_key`. Back it up alongside the CA key.
- **Bootstrap ordering.** When two replicas race to bootstrap, etcd's
  compare-and-swap semantics prevent double-writes of `ca/cert` and
  `ca/key`; the losing replica fails its bootstrap, observes the winner's
  cert, and continues.
- **Puppet-ca-ctl.** `puppet-ca-ctl setup` and `puppet-ca-ctl import` operate
  on the local filesystem only. To import a CA into an etcd-backed cluster,
  run these commands first against a scratch directory, then point
  `puppet-ca` at a cadir containing the output.

### Integration tests

End-to-end tests against an in-process embedded etcd live behind a build tag
so default builds don't pay the dependency cost:

```bash
go test -tags=etcd_integration ./internal/storage/...
```

---

## CA cert/key as local files

Sometimes you want the benefits of a shared backend (agents, CSRs, signed
certs, CRL) without exposing the CA cert or private key in that backend.
Common scenarios:

- **Secret volume / HSM-adjacent.** The key is mounted from a Kubernetes
  secret, an encrypted tmpfs, or a path an HSM driver populates.
- **Operator-supplied cert.** The CA cert came from an offline ceremony and
  should never be rewritten by the server.

Set either or both of these options and the named asset is read/written
against the given local path instead of the selected backend. Everything
else (CSRs, signed certs, CRL, inventory, serial) still flows through the
configured backend.

### Configuration

```yaml
storage_backend: etcd
cadir: /var/lib/puppet-ca
etcd_endpoints: [https://etcd:2379]

# Keep the CA cert and key out of etcd; mount them from the host.
ca_cert_file: /etc/puppet-ca/secrets/ca_crt.pem
ca_key_file:  /etc/puppet-ca/secrets/ca_key.pem
```

### CLI flags

```
--ca-cert-file /etc/puppet-ca/secrets/ca_crt.pem
--ca-key-file  /etc/puppet-ca/secrets/ca_key.pem
```

### Environment variables

| Config key      | Env var                    |
|-----------------|----------------------------|
| `ca_cert_file`  | `PUPPET_CA_CA_CERT_FILE`   |
| `ca_key_file`   | `PUPPET_CA_CA_KEY_FILE`    |

### Behaviour

- On **first start** with no existing CA, `puppet-ca` bootstraps a new CA
  and writes the cert/key to the configured local paths (not the backend).
- On subsequent starts, the cert and key are loaded from the local paths.
- `puppet-ca` writes the cert at mode `0644` and the key at mode `0600`
  atomically (temp-file + rename). If operators supply pre-existing files,
  they are read as-is and never overwritten unless the server rotates the CA.
- Existing supervision-level protections still apply:
  - `encrypt_ca_key` encrypts the key PEM before writing.
  - `ca_key_passphrase_file` overrides the auto-generated passphrase file.

This override also works with the filesystem backend, e.g. to pull the CA
key out of the cadir tree and onto a separately-mounted volume.

---

## Choosing a backend

|                              | `filesystem`            | `etcd`                            |
|------------------------------|-------------------------|-----------------------------------|
| Replicas                     | one active              | many (A/A)                        |
| Operational dependencies     | none                    | healthy etcd cluster              |
| Bootstrap                    | writes `<cadir>/`       | writes etcd keyspace              |
| CA key exposure              | local file              | in etcd unless `ca_key_file` set  |
| Backup/restore               | tar `<cadir>/`          | etcd snapshot + local dirs        |
| Drop-in for Puppet Server CA | yes                     | no (key paths change)             |

Use `filesystem` for single-node or migration-from-Puppet-Server installs.
Use `etcd` when you need multiple `puppet-ca` replicas to serve the same CA.

---

## Extending

The `Backend` interface is defined in
[internal/storage/backend.go](../internal/storage/backend.go). To add a new
backend, implement the interface, register it in
[internal/storage/spec.go](../internal/storage/spec.go)'s
`NewServiceFromSpec`, and add any backend-specific config fields to
[cmd/puppet-ca/config.go](../cmd/puppet-ca/config.go). The `OverlayBackend`
wrapper (overlay.go) shows how to compose a backend with local-file overrides.
