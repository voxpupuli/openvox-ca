# Storage backends

`puppet-ca` abstracts its persistent state behind a pluggable **Backend**
interface. The following backends ship today:

| Kind                   | Status  | Best for                                                                   |
|------------------------|---------|----------------------------------------------------------------------------|
| `filesystem`           | default | single-node installs; drop-in compatibility with Puppet Server's CA layout |
| `etcd`                 | stable  | HA clusters where multiple `puppet-ca` replicas share a single CA          |
| `redis` (incl. Valkey) | stable  | clusters that already run Redis/Valkey (direct or Sentinel-managed)        |
| `sqlite`               | stable  | single-node installs that prefer a single database file over a cadir tree  |
| `postgres`             | stable  | HA clusters that already run PostgreSQL; shared CA across replicas         |
| `mysql` (incl. MariaDB)| stable  | HA clusters that already run MySQL/MariaDB; shared CA across replicas      |

A single shared SQL backend underpins `sqlite`, `postgres`, and `mysql`: they
differ only in driver, a few SQL clauses, and the cross-node lock mechanism.

Regardless of backend, **server-generated per-subject private keys always
live on local disk**. They are issued once, handed back to the requester, and
retained locally for operator convenience only; they are never written to a
remote store.

The CA certificate and/or the CA private key can optionally be pinned to a
local file (e.g. a mounted secret volume) independent of the chosen backend
(filesystem, etcd, redis/valkey, or a SQL backend) — see
[CA cert/key as local files](#ca-certkey-as-local-files).

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

## Redis / Valkey backend

Stores every logical key except the local private-key directory in a Redis
instance, a Valkey instance (wire-compatible fork of Redis), or a
Sentinel-managed primary. Multiple `puppet-ca` replicas can point at the
same Redis/Valkey (and the same `redis_key_prefix`) to share CA state.

`redis` and `valkey` are accepted as aliases for this backend.

### Key layout

With the default prefix `puppet-ca` (Redis convention uses `:` as a
separator):

| Logical key         | Redis key                          |
|---------------------|------------------------------------|
| `ca_cert`           | `puppet-ca:ca:cert`                |
| `ca_pubkey`         | `puppet-ca:ca:pubkey`              |
| `ca_key`            | `puppet-ca:ca:key`                 |
| `crl`               | `puppet-ca:ca:crl`                 |
| `serial`            | `puppet-ca:serial`                 |
| `inventory`         | `puppet-ca:inventory:data`         |
| `inventory_hmac`    | `puppet-ca:inventory:hmac`         |
| `hmac_key`          | `puppet-ca:private:hmac_key`       |
| `csr/<subject>`     | `puppet-ca:requests:<subject>`     |
| `cert/<subject>`    | `puppet-ca:signed:<subject>`       |

Stored values carry an 8-byte big-endian `time.UnixNano` mtime prefix so
`ModTime` is answered from the same round-trip as the value. Inventory
appends are performed by a Lua script on the server, making a
read-modify-write single-step atomic across all replicas.

### Cross-node coordination

Cross-replica locks are implemented with `SET NX PX` using a per-acquisition
random token. A background heartbeat extends the TTL (default 30s) while the
lock is held; `Unlock` runs a Lua script that deletes the key only when the
stored value still matches the caller's token. Lock names mirror the etcd
backend (`bootstrap`, `crl`, `subject:<subject>`). If a replica holding a
lock crashes, the lock releases automatically when the TTL elapses.

Redis replication under Sentinel is asynchronous, which means an in-flight
failover could in theory hand a lock to a new holder while the old primary
briefly keeps the prior entry. For `puppet-ca`'s workloads the resulting
window is narrow and bounded by the lock TTL; operators who need strict
cross-node linearizability should prefer the etcd backend.

For the filesystem backend (single-node), the same call path falls back to
a process-local `sync.Mutex` per lock name.

### Configuration — direct connection

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: redis                   # or "valkey"
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
                                         # and ancillary local state

redis_addrs:
  - redis-0.example.com:6379             # first address is used in direct mode

redis_key_prefix: puppet-ca              # default shown; override to share
                                         # an instance between CAs
redis_db: 0                              # logical database (default 0)

redis_dial_timeout_sec: 5
redis_request_timeout_sec: 5
redis_lock_ttl_sec: 30                   # heartbeat runs every ttl/3

# Optional auth (ACL user + password; use PUPPET_CA_REDIS_PASSWORD for secrets).
redis_username: puppet-ca
redis_password: "..."

# Optional TLS to the Redis primary.
redis_tls_ca_file:   /etc/puppet-ca/redis-ca.pem
redis_tls_cert_file: /etc/puppet-ca/redis-client.pem
redis_tls_key_file:  /etc/puppet-ca/redis-client-key.pem
```

### Configuration — Sentinel-managed failover

Set `redis_sentinel_master_name` (and leave `redis_addrs` empty) to route
through Sentinels. The client discovers the current primary and follows
failovers automatically.

```yaml
storage_backend: redis
cadir: /var/lib/puppet-ca

redis_sentinel_master_name: mymaster
redis_sentinel_addrs:
  - sentinel-0.example.com:26379
  - sentinel-1.example.com:26379
  - sentinel-2.example.com:26379

# Optional auth against the Sentinels themselves (distinct from Redis auth).
redis_sentinel_username: puppet-ca
redis_sentinel_password: "..."

# Auth / TLS against the primary — same fields as direct mode.
redis_username: puppet-ca
redis_password: "..."
redis_tls_ca_file:   /etc/puppet-ca/redis-ca.pem
redis_tls_cert_file: /etc/puppet-ca/redis-client.pem
redis_tls_key_file:  /etc/puppet-ca/redis-client-key.pem
```

### CLI flags

```
--storage-backend           redis
--redis-addrs               redis-0:6379,redis-1:6379
--redis-sentinel-master-name mymaster
--redis-sentinel-addrs      sentinel-0:26379,sentinel-1:26379
--redis-key-prefix          puppet-ca
```

### Environment variables

| Config key                     | Env var                                   |
|--------------------------------|-------------------------------------------|
| `storage_backend`              | `PUPPET_CA_STORAGE_BACKEND`               |
| `redis_addrs`                  | `PUPPET_CA_REDIS_ADDRS` (comma-separated) |
| `redis_sentinel_master_name`   | `PUPPET_CA_REDIS_SENTINEL_MASTER_NAME`    |
| `redis_sentinel_addrs`         | `PUPPET_CA_REDIS_SENTINEL_ADDRS` (comma-separated) |
| `redis_sentinel_username`      | `PUPPET_CA_REDIS_SENTINEL_USERNAME`       |
| `redis_sentinel_password`      | `PUPPET_CA_REDIS_SENTINEL_PASSWORD`       |
| `redis_db`                     | `PUPPET_CA_REDIS_DB`                      |
| `redis_username`               | `PUPPET_CA_REDIS_USERNAME`                |
| `redis_password`               | `PUPPET_CA_REDIS_PASSWORD`                |
| `redis_key_prefix`             | `PUPPET_CA_REDIS_KEY_PREFIX`              |
| `redis_dial_timeout_sec`       | `PUPPET_CA_REDIS_DIAL_TIMEOUT_SEC`        |
| `redis_request_timeout_sec`    | `PUPPET_CA_REDIS_REQUEST_TIMEOUT_SEC`     |
| `redis_lock_ttl_sec`           | `PUPPET_CA_REDIS_LOCK_TTL_SEC`            |
| `redis_tls_ca_file`            | `PUPPET_CA_REDIS_TLS_CA_FILE`             |
| `redis_tls_cert_file`          | `PUPPET_CA_REDIS_TLS_CERT_FILE`           |
| `redis_tls_key_file`           | `PUPPET_CA_REDIS_TLS_KEY_FILE`            |

### Operational notes

- **Persistence.** Redis/Valkey RDB snapshots and AOF both apply here; make
  sure the deployment is durable enough for the CA state you're storing. A
  pure in-memory instance with no persistence will lose the CA on restart.
- **CA cert and key.** As with the etcd backend, the CA private key lives
  in Redis by default. Restrict ACLs on `puppet-ca:ca:key`, enable
  `encrypt_ca_key` so the key is AES-256-GCM wrapped before it leaves the
  process, or pin the key to a local file via `ca_key_file` (see below).
- **Inventory HMAC.** The integrity key lives under
  `puppet-ca:private:hmac_key`. Back it up alongside the CA key.
- **Puppet-ca-ctl.** `puppet-ca-ctl setup` and `puppet-ca-ctl import` operate
  on the local filesystem only. To import a CA into a Redis-backed cluster,
  run these commands first against a scratch directory, then point
  `puppet-ca` at a cadir containing the output.

### Unit / integration tests

Unit tests run against an in-process miniredis (no external service):

```bash
go test ./internal/storage/
```

An integration suite that talks to a real Redis/Valkey lives behind a build
tag and is opt-in via `PUPPET_CA_TEST_REDIS_ADDR`:

```bash
PUPPET_CA_TEST_REDIS_ADDR=127.0.0.1:6379 \
    go test -tags=redis_integration ./internal/storage/...
```

---

## SQL backends

A single shared backend stores every logical key (except the local
private-key directory) as one row in a key-value table inside a SQL database.
The same implementation drives every dialect; only the driver, a few SQL
clauses, and the cross-node lock mechanism differ. The first dialect to ship
is **SQLite**; PostgreSQL and MySQL/MariaDB build on the same code.

All drivers are pure Go, so the default `CGO_ENABLED=0` and
`GOEXPERIMENT=boringcrypto` (FIPS) builds are unaffected. SQLite uses
[`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) (a pure-Go
translation of SQLite, no CGO).

### Schema and migrations

The schema is a single table, `puppet_ca_blobs`:

| Column        | Purpose                                                       |
|---------------|---------------------------------------------------------------|
| `blob_key`    | logical key (primary key) — e.g. `ca_cert`, `cert/<subject>`  |
| `data`        | blob payload                                                  |
| `kind`        | visibility hint (public/private); recorded, not enforced      |
| `modified_at` | last-write timestamp, used to answer `ModTime`                |

Migrations are managed by [bun](https://bun.uptrace.dev/)'s migrator. On every
start the backend runs any pending migrations and records applied versions in
its own `bun_migrations` table; a `bun_migration_locks` table serialises
concurrent runners so multiple replicas can start against the same database
safely. Migrations are defined as Go functions, so one definition emits
dialect-correct DDL across SQLite, PostgreSQL, and MySQL/MariaDB.

### SQLite backend

Stores the entire CA in one SQLite database file. `sqlite` and `sqlite3` are
accepted as aliases. SQLite is single-node: it is a convenient, dependency-free
alternative to the filesystem backend (one file to back up instead of a
directory tree), not a clustering option.

`cadir` is still required for per-subject generated private keys and ancillary
local state.

#### Configuration

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: sqlite
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
sql_dsn: "file:/var/lib/puppet-ca/ca.db" # SQLite database file path / URI

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
```

The backend appends sensible defaults to the SQLite DSN unless you have
already set them: `_txlock=immediate` (so read-then-write transactions take
the write lock up front and cannot deadlock), `busy_timeout` (writers wait
rather than failing with `SQLITE_BUSY`), and `journal_mode=WAL` (readers do
not block the writer). The connection pool is pinned to a single open
connection, matching SQLite's single-writer model.

#### CLI flags

```
--storage-backend sqlite
--sql-dsn         file:/var/lib/puppet-ca/ca.db
```

#### Environment variables

| Config key                 | Env var                              |
|----------------------------|--------------------------------------|
| `storage_backend`          | `PUPPET_CA_STORAGE_BACKEND`          |
| `sql_dsn`                  | `PUPPET_CA_SQL_DSN`                  |
| `sql_request_timeout_sec`  | `PUPPET_CA_SQL_REQUEST_TIMEOUT_SEC`  |
| `sql_max_open_conns`       | `PUPPET_CA_SQL_MAX_OPEN_CONNS`       |
| `sql_max_idle_conns`       | `PUPPET_CA_SQL_MAX_IDLE_CONNS`       |
| `sql_tls_ca_file`          | `PUPPET_CA_SQL_TLS_CA_FILE`          |
| `sql_tls_cert_file`        | `PUPPET_CA_SQL_TLS_CERT_FILE`        |
| `sql_tls_key_file`         | `PUPPET_CA_SQL_TLS_KEY_FILE`         |

The pool-tuning and TLS settings apply only to the networked SQL dialects;
SQLite ignores them.

#### Cross-node coordination

SQLite is single-node, so it does not provide a distributed lock: the
`WithLock` call path falls back to a process-local `sync.Mutex` per lock name,
exactly as the filesystem backend does.

#### Operational notes

- **Persistence.** The database file *is* the CA. Back it up (and the WAL
  sidecar) the way you would back up a cadir tree.
- **CA cert and key.** As with the etcd/redis backends, the CA private key
  lives in the database by default. Enable `encrypt_ca_key` so the key is
  AES-256-GCM wrapped before it leaves the process, or pin the key to a local
  file via `ca_key_file` (see below).
- **Puppet-ca-ctl.** `puppet-ca-ctl setup` and `puppet-ca-ctl import` operate
  on the local filesystem only; bootstrap/import against a scratch directory,
  then point a SQLite-backed `puppet-ca` at a fresh database to take over.

#### Tests

The SQLite backend tests run in a normal `go test` against a temporary
database file — no external service and no CGO:

```bash
go test ./internal/storage/
```

### PostgreSQL backend

Stores the entire CA in a PostgreSQL database. Multiple `puppet-ca` replicas
can point at the same database to share CA state. `postgres`, `postgresql`,
and `pg` are accepted as aliases. `cadir` is still required for per-subject
generated private keys and ancillary local state.

#### Configuration

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: postgres
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
sql_dsn: "postgres://puppetca:secret@db.example.com:5432/puppetca?sslmode=require"

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
sql_max_open_conns: 0                    # 0 = database/sql default
sql_max_idle_conns: 0                    # 0 = database/sql default

# Optional mTLS to PostgreSQL (alternative to sslmode/ssl params in the DSN).
sql_tls_ca_file:   /etc/puppet-ca/pg-ca.pem
sql_tls_cert_file: /etc/puppet-ca/pg-client.pem
sql_tls_key_file:  /etc/puppet-ca/pg-client-key.pem
```

TLS is driven either by the DSN (`sslmode=require`, etc.) or by the
`sql_tls_*_file` options; when the file options are set they are compiled into
a `*tls.Config` and handed to the driver.

#### CLI flags

```
--storage-backend postgres
--sql-dsn         postgres://puppetca:secret@db.example.com:5432/puppetca?sslmode=require
```

#### Cross-node coordination

Cross-replica locks use PostgreSQL **session-level advisory locks**: the lock
name is hashed to the `bigint` key `pg_advisory_lock` requires, taken on a
dedicated connection, and released with `pg_advisory_unlock` on that same
connection. `pg_advisory_lock` blocks until the lock is granted (or the
request context is cancelled), giving strict cross-node mutual exclusion for
the same lock name; distinct names never contend. A process-local mutex
serialises in-process callers first so they do not each tie up a connection
blocked in the database. If a replica crashes, PostgreSQL drops its session
and releases the advisory lock automatically.

#### Operational notes

- **Persistence.** The database is the CA; back it up with your normal
  PostgreSQL tooling.
- **CA cert and key.** As with the etcd/redis backends, the CA private key
  lives in the database by default. Enable `encrypt_ca_key`, or pin the key to
  a local file via `ca_key_file` (see below).
- **Schema.** The backend owns the `puppet_ca_blobs` table plus bun's
  `bun_migrations` / `bun_migration_locks` bookkeeping tables. Grant the
  configured role rights to create tables on first run (or pre-create the
  schema and grant DML).
- **Puppet-ca-ctl.** `puppet-ca-ctl setup` / `import` operate on the local
  filesystem only; bootstrap/import against a scratch directory, then point a
  PostgreSQL-backed `puppet-ca` at a fresh database to take over.

#### Tests

The PostgreSQL integration suite is behind a build tag and opt-in via
`PUPPET_CA_TEST_POSTGRES_DSN`:

```bash
PUPPET_CA_TEST_POSTGRES_DSN="postgres://user:pass@127.0.0.1:5432/db?sslmode=disable" \
    go test -tags=postgres_integration ./internal/storage/...
```

Or let mage manage a throwaway database end to end:

```bash
mage test:backendsPostgres
```

### MySQL / MariaDB backend

Stores the entire CA in a MySQL or MariaDB database. Multiple `puppet-ca`
replicas can share one database. `mysql` and `mariadb` are accepted as aliases.
`cadir` is still required for per-subject generated private keys and ancillary
local state.

#### Configuration

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: mysql                   # or "mariadb"
cadir: /var/lib/puppet-ca                # still needed for per-subject keys
sql_dsn: "puppetca:secret@tcp(db.example.com:3306)/puppetca"

sql_request_timeout_sec: 10              # per-operation timeout (default 10)

# Optional TLS to the server (registered with the driver and referenced
# automatically; no need to add tls= to the DSN).
sql_tls_ca_file:   /etc/puppet-ca/mysql-ca.pem
sql_tls_cert_file: /etc/puppet-ca/mysql-client.pem
sql_tls_key_file:  /etc/puppet-ca/mysql-client-key.pem
```

The DSN is the [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)
form (`user:pass@tcp(host:3306)/dbname`). `parseTime` is forced on internally
so timestamp columns scan correctly; you do not need to set it in the DSN.

#### CLI flags

```
--storage-backend mysql
--sql-dsn         puppetca:secret@tcp(db.example.com:3306)/puppetca
```

#### Cross-node coordination

Cross-replica locks use named locks via `GET_LOCK` / `RELEASE_LOCK` on a
dedicated connection (these are session-scoped, so lock and release share one
connection). The lock name is hashed to a short, stable identifier within
MySQL's 64-character `GET_LOCK` limit. Acquisition polls `GET_LOCK` with a
one-second server-side wait so caller-context cancellation is honoured between
attempts; a process-local mutex serialises in-process callers first. A crashed
replica's session ends and its named locks release automatically.

#### Operational notes

- **Schema.** On first run the migration widens the `data` column to
  `LONGBLOB` (MySQL's default `BLOB` caps at 64 KiB, too small for the
  append-only inventory). Concurrent inventory appends use a `FOR UPDATE`
  transaction; an InnoDB deadlock (the expected outcome when two replicas race
  to create the same row) is retried transparently.
- **CA cert and key.** As with the other shared backends, the CA private key
  lives in the database by default. Enable `encrypt_ca_key`, or pin the key to
  a local file via `ca_key_file` (see below).
- **Puppet-ca-ctl.** `puppet-ca-ctl setup` / `import` operate on the local
  filesystem only; bootstrap/import against a scratch directory, then point a
  MySQL-backed `puppet-ca` at a fresh database to take over.

#### Tests

The MySQL integration suite is behind a build tag and opt-in via
`PUPPET_CA_TEST_MYSQL_DSN` (it passes against both MySQL 8 and MariaDB 11):

```bash
PUPPET_CA_TEST_MYSQL_DSN="user:pass@tcp(127.0.0.1:3306)/db" \
    go test -tags=mysql_integration ./internal/storage/...
```

Or let mage manage a throwaway database end to end:

```bash
mage test:backendsMySQL
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

|                              | `filesystem`       | `sqlite`                          | `postgres` / `mysql`              | `etcd`                            | `redis` / `valkey`                |
|------------------------------|--------------------|-----------------------------------|-----------------------------------|-----------------------------------|-----------------------------------|
| Replicas                     | one active         | one active                        | many (A/A)                        | many (A/A)                        | many (A/A)                        |
| Operational dependencies     | none               | none (single file)                | SQL server                        | healthy etcd cluster              | Redis/Valkey primary (+ Sentinel) |
| Bootstrap                    | writes `<cadir>/`  | writes the database file          | writes the database               | writes etcd keyspace              | writes Redis keyspace             |
| CA key exposure              | local file         | in DB unless `ca_key_file` set    | in DB unless `ca_key_file` set    | in etcd unless `ca_key_file` set  | in Redis unless `ca_key_file` set |
| Backup/restore               | tar `<cadir>/`     | copy `.db` (+ WAL) + local dirs   | DB dump + local dirs              | etcd snapshot + local dirs        | RDB/AOF + local dirs              |
| Cross-node lock guarantees   | n/a (single node)  | n/a (single node)                 | advisory lock / `GET_LOCK`        | lease-backed `concurrency.Mutex`  | `SET NX PX` + token + heartbeat   |
| Drop-in for Puppet Server CA | yes                | no (key paths change)             | no (key paths change)             | no (key paths change)             | no (key paths change)             |

Use `filesystem` for single-node or migration-from-Puppet-Server installs.
Use `sqlite` for a single-node install that prefers one database file over a
cadir tree (e.g. simpler backups). Use `postgres` or `mysql` when you want
multiple `puppet-ca` replicas backed by a database you already operate. Use
`etcd` when you need multiple replicas and want the strongest cross-node lock
guarantees. Use `redis`/`valkey` when you already run Redis/Valkey (direct or
Sentinel-managed) and are willing to accept the narrower failover window in
exchange for reusing existing infrastructure.

---

## Extending

The `Backend` interface is defined in
[internal/storage/backend.go](../internal/storage/backend.go). To add a new
backend, implement the interface, register it in
[internal/storage/spec.go](../internal/storage/spec.go)'s
`NewServiceFromSpec`, and add any backend-specific config fields to
[cmd/puppet-ca/config.go](../cmd/puppet-ca/config.go). The `OverlayBackend`
wrapper (overlay.go) shows how to compose a backend with local-file overrides.
