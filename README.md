# openvox-ca

---

> 🤖 LLM/AI WARNING 🤖
>
> This project was largely written by [Claude](https://claude.ai/)
> It has been reviewed and tested, but use in production at your own discretion.
>
> 🤖 LLM/AI WARNING 🤖

---

A drop-in replacement for Puppet Server's built-in CA, written in Go. It implements the same HTTP API that Puppet agents and `puppet cert` / `puppetserver ca` tooling use, backed by a flat-file certificate store compatible with existing Puppet CA directories.

> **Migrating from Puppet Server?** See the [migration guide](docs/migrating-from-puppet-server.md) for step-by-step instructions, directory layout mapping, and CLI command translation.

## Features

- **Full Puppet CA API compatibility:** all 13 endpoints used by agents and puppet-server
- **Pluggable storage:** filesystem (default, Puppet Server compatible), SQLite (single database file), or PostgreSQL / MySQL (MariaDB) / etcd / Redis (Valkey) for HA clusters; CA cert/key can be pinned to local files independently. See the [storage backends guide](docs/storage-backends.md)
- **Pluggable CA key custody:** keep the CA private key as a local file (default) or delegate it entirely to an OpenBao Transit secrets engine key, which never leaves OpenBao — works identically on a VM (AppRole/token) or in Kubernetes (native ServiceAccount auth, no sidecar). See [OpenBao Transit-engine CA key](docs/openbao-transit.md)
- **Autosigning:** `true`, glob-pattern file, or executable plugin modes
- **mTLS support:** optional HTTPS with per-endpoint tier-based client certificate authorization
- **CA import:** replace a bootstrapped CA with an external cert/key pair offline
- **Server-side key generation:** issue cert+key pairs without a node-submitted CSR; configurable RSA (2048/3072/4096) or ECDSA (P-256/P-384/P-521)
- **Configurable key algorithms:** CA and leaf certificates can use RSA or ECDSA; ECDSA support for both bootstrapped CAs and generated leaf certs
- **Random serial numbers:** every issued leaf certificate gets a cryptographically random 128-bit serial (CA/Browser Forum guidance)
- **CRL Distribution Points:** optionally embed a CRL URL in every issued certificate (`--crl-url`) so verifiers can automatically fetch the CRL
- **Configurable CRL validity:** control how long each published CRL is valid (`crl_validity_days`)
- **Automatic CRL refresh:** a background job re-signs the CRL before its validity lapses, so a low-churn CA never serves an expired CRL; safe across replicas (serialised on the shared CRL lock) and tunable or disablable. Operators can also force a refresh on demand via `openvox-ca-ctl reissue-crl`
- **Expired-certificate cleanup (opt-in):** a background job removes certificates that expired more than a configurable grace period ago from the inventory and the CRL (and deletes their stored signed certificate), keeping both from growing without bound as nodes are decommissioned; safe across replicas (serialised on the shared CRL lock)
- **OCSP responder:** built-in RFC 6960 OCSP responder; AIA extension embedded in issued certs when `--ocsp-url` is set; in-memory cache with nonce bypass
- **Health probes:** `/healthz/live`, `/healthz/ready`, and `/healthz/startup` endpoints for Kubernetes-style liveness/readiness checks
- **Prometheus exporter:** optional `/metrics` listener (`--metrics-listen`) exposing Go runtime/process and HTTP metrics plus CA certificate, CRL, and per–leaf-certificate expiry and issuance-status series; ships with a [Jsonnet alerting mixin](mixin/). See [metrics & monitoring](docs/metrics.md)
- **Graceful shutdown:** `SIGTERM`/`SIGINT` drains in-flight requests with a configurable window (25s default) before exiting; deferred storage and signer cleanup always runs
- **FIPS-compatible:** standard library only (`crypto/x509`, `net/http`); no CGO by default; FIPS build available via `GOEXPERIMENT=boringcrypto`
- **`openvox-ca-ctl`:** operator CLI matching `puppetserver ca` subcommands

## Building

Requirements: Go 1.25+, [Mage](https://magefile.org/)

```bash
git clone https://github.com/voxpupuli/openvox-ca.git
cd openvox-ca

# Build both binaries to bin/
mage build:all

# Or with plain Go
go build -o bin/openvox-ca     ./cmd/openvox-ca
go build -o bin/openvox-ca-ctl ./cmd/openvox-ca-ctl
```

### FIPS build (Linux/amd64)

```bash
mage build:fips   # → bin/openvox-ca + bin/openvox-ca-ctl  (GOEXPERIMENT=boringcrypto, CGO_ENABLED=1)
```

## openvox-ca -- the server

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `""` | Path to YAML config file (auto-detected at `/etc/puppet-ca/config.yaml`) |
| `--cadir` | `""` | CA storage directory (keys, certs, CSRs, CRL); required via flag, env, or config |
| `--host` | `0.0.0.0` | Listen address |
| `--port` | `8140` | Listen port |
| `--hostname` | `""` | CN suffix for a bootstrapped CA (`Puppet CA: <hostname>`); defaults to `puppet` when empty |
| `--autosign-config` | `""` | Autosign mode: `true`, `false`, or path to a file/executable |
| `--tls-cert` | `""` | Server TLS certificate PEM (enables HTTPS when set with `--tls-key`) |
| `--tls-key` | `""` | Server TLS private key PEM |
| `--puppet-server` | `""` | Comma-separated CNs granted admin API access (mTLS only) |
| `--puppet-server-file` | `""` | Path to a file of CNs granted admin API access (one per line; `#` comments and blank lines ignored) |
| `--no-pp-cli-auth` | `false` | Disable `pp_cli_auth` extension as an admin credential; require CN allow list only |
| `--no-tls-required` | `false` | Allow plain HTTP on non-loopback addresses; use only behind a trusted TLS proxy or in test environments |
| `--allow-public-status` | `false` | Allow unauthenticated `GET /certificate_status`; by default this endpoint requires a CA-signed client cert |
| `--ocsp-url` | `""` | OCSP responder URL to embed in issued certificates |
| `--crl-url` | `""` | CRL distribution point URL to embed in issued certificates |
| `--metrics-listen` | `""` | Address for the Prometheus exporter (e.g. `127.0.0.1:9140`); empty disables it. See [metrics & monitoring](docs/metrics.md) |
| `--encrypt-ca-key` | `false` | Encrypt the CA private key at rest (AES-256-GCM + Argon2id) |
| `--ca-key-passphrase-file` | `""` | Path to file containing the CA key passphrase (first line used) |
| `--csr-rate-limit` | `60` | Max CSR submissions per IP per minute on the public `PUT /certificate_request` endpoint (0 disables) |
| `--single-process` | `false` | Disable CA key isolation (run signer and frontend in a single process) |
| `--storage-backend` | `filesystem` | Storage backend for CA state: `filesystem` or `etcd`. See [storage backends](docs/storage-backends.md) |
| `--etcd-endpoints` | `""` | Comma-separated etcd endpoints (used when `--storage-backend etcd`) |
| `--etcd-key-prefix` | `/puppet-ca` | etcd key namespace for this CA |
| `--ca-cert-file` | `""` | Keep the CA certificate at this local path regardless of backend |
| `--ca-key-file` | `""` | Keep the CA private key at this local path regardless of backend |
| `--ca-key-provider` | `file` | CA private key custody: `file` (default) or `openbao` (OpenBao Transit key). See [OpenBao Transit-engine CA key](docs/openbao-transit.md) for the full `--openbao-*` flag reference |
| `--daemon` | `false` | Fork to background (not recommended in containers) |
| `--logfile` | `""` | Write JSON logs to this file instead of stderr |
| `--verbosity` / `-v` | `0` | Verbosity: `0`=Info, `1`=Debug, `2`=Trace |

### Configuration

All flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

Key generation and CA subject options are intentionally **not** exposed as CLI flags. They are one-time bootstrap decisions that belong in a config file or environment variable. Use the config file or `PUPPET_CA_CA_KEY_ALGO` / `PUPPET_CA_CA_SUBJECT_*` env vars to set them.

The config file is located by checking, in order:
1. `--config /path/to/config.yaml` (explicit flag)
2. `PUPPET_CA_CONFIG` environment variable
3. `/etc/puppet-ca/config.yaml` (auto-detected if the file exists)

**Example `/etc/puppet-ca/config.yaml`:**

```yaml
cadir: /etc/puppetlabs/puppet/ssl/ca
host: 0.0.0.0
port: 8140
hostname: puppet.example.com
tls_cert: /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem
tls_key:  /etc/puppetlabs/puppet/ssl/ca/ca_key.pem
puppet_server: puppet.example.com
puppet_server_file: ""
no_pp_cli_auth: false
no_tls_required: false
allow_public_status: false  # set true to allow unauthenticated GET /certificate_status
autosign_config: ""
logfile: ""
verbosity: 0
ocsp_url: ""
crl_url: ""
shutdown_timeout_sec: 0  # graceful HTTP-drain budget on SIGTERM; 0 = built-in default (25s)
# Key generation options (applied only when bootstrapping a new CA or generating leaf certs).
ca_key_algo: ""       # "rsa" (default) or "ecdsa"
ca_key_size: 0        # RSA: 2048/3072/4096 (default 4096); ECDSA: 256/384/521 (default 256)
leaf_key_algo: ""     # "rsa" (default) or "ecdsa"
leaf_key_size: 0      # RSA: 2048/3072/4096 (default 2048); ECDSA: 256/384/521 (default 256)
# CA certificate subject fields (applied only when bootstrapping a new CA).
ca_subject_org: ""
ca_subject_ou: ""
ca_subject_country: ""
ca_subject_locality: ""
ca_subject_province: ""
# Validity and path length.
# ca_* apply only when bootstrapping a new CA.
# leaf_validity_days and crl_validity_days apply on every signing / revocation operation.
ca_path_length: -1    # -1 = unconstrained, 0 = leaf certs only, N = N levels of intermediates
ca_validity_days: 0   # 0 = built-in default (~5 years); positive integer overrides
leaf_validity_days: 0 # 0 = built-in default (~5 years); positive integer overrides
crl_validity_days: 0  # 0 = built-in default (30 days); positive integer overrides
csr_rate_limit: 60    # max CSR submissions per IP per minute; 0 = disable rate limiting
# Background CRL refresh keeps the CRL's NextUpdate from lapsing on a low-churn CA.
# Safe to run on every replica (serialised on the shared CRL lock).
disable_crl_refresh: false     # true = never auto-refresh the CRL
crl_refresh_interval_sec: 0    # how often to check; 0 = built-in default (1h)
crl_refresh_before_sec: 0      # re-sign when remaining validity < this; 0 = crl_validity/3
# Background expired-certificate cleanup (opt-in). When enabled, a job removes
# certificates that expired more than the retention grace period ago from the
# inventory and the CRL, and deletes their stored signed certificate. Safe to run
# on every replica (serialised on the shared CRL lock).
enable_expired_cert_cleanup: false       # true = run the cleanup job
expired_cert_retention_sec: 0            # grace period after a cert's NotAfter before removal; 0 = built-in default (30d)
expired_cert_cleanup_interval_sec: 0     # how often to run; 0 = built-in default (24h)
# CA key encryption at rest.
encrypt_ca_key: false           # encrypt the CA private key (AES-256-GCM + Argon2id)
ca_key_passphrase_file: ""      # path to passphrase file; auto-generated if omitted
# Date/time format in JSON responses.
puppet_datetime_format: false   # use Puppet CA style "2006-01-02T15:04:05MST" instead of RFC 3339
# Certificate auto-renewal (empty-body POST /certificate_renewal).
revoke_on_auto_renew: true      # false matches OpenVox Server's Clojure CA (no revocation on auto-renewal)
```

**Environment variables (mirrors CLI flags):**

| Flag | Environment variable |
|------|---------------------|
| `--cadir` | `PUPPET_CA_CADIR` |
| `--autosign-config` | `PUPPET_CA_AUTOSIGN_CONFIG` |
| `--host` | `PUPPET_CA_HOST` |
| `--port` | `PUPPET_CA_PORT` |
| `--hostname` | `PUPPET_CA_HOSTNAME` |
| `--verbosity` | `PUPPET_CA_VERBOSITY` |
| `--logfile` | `PUPPET_CA_LOGFILE` |
| `--tls-cert` | `PUPPET_CA_TLS_CERT` |
| `--tls-key` | `PUPPET_CA_TLS_KEY` |
| `--puppet-server` | `PUPPET_CA_PUPPET_SERVER` |
| `--puppet-server-file` | `PUPPET_CA_PUPPET_SERVER_FILE` |
| `--no-pp-cli-auth` | `PUPPET_CA_NO_PP_CLI_AUTH` |
| `--no-tls-required` | `PUPPET_CA_NO_TLS_REQUIRED` |
| `--allow-public-status` | `PUPPET_CA_ALLOW_PUBLIC_STATUS` |
| `--ocsp-url` | `PUPPET_CA_OCSP_URL` |
| `--crl-url` | `PUPPET_CA_CRL_URL` |
| `--metrics-listen` | `PUPPET_CA_METRICS_LISTEN` |
| `--csr-rate-limit` | `PUPPET_CA_CSR_RATE_LIMIT` |
| `--encrypt-ca-key` | `PUPPET_CA_ENCRYPT_CA_KEY` |
| `--ca-key-passphrase-file` | `PUPPET_CA_KEY_PASSPHRASE_FILE` |
| `--storage-backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `--etcd-endpoints` | `PUPPET_CA_ETCD_ENDPOINTS` |
| `--etcd-key-prefix` | `PUPPET_CA_ETCD_KEY_PREFIX` |
| `--ca-cert-file` | `PUPPET_CA_CA_CERT_FILE` |
| `--ca-key-file` | `PUPPET_CA_CA_KEY_FILE` |
| `--ca-key-provider` | `PUPPET_CA_CA_KEY_PROVIDER` |
| `--openbao-addr` | `PUPPET_CA_OPENBAO_ADDR` |
| `--openbao-transit-mount` | `PUPPET_CA_OPENBAO_TRANSIT_MOUNT` |
| `--openbao-key-name` | `PUPPET_CA_OPENBAO_KEY_NAME` |
| `--openbao-auth-method` | `PUPPET_CA_OPENBAO_AUTH_METHOD` |

The full `--openbao-*` flag/environment-variable reference (TLS, AppRole, token-file, and
Kubernetes auth settings) is in [OpenBao Transit-engine CA key](docs/openbao-transit.md#configuration).

The CA key passphrase can also be provided via `PUPPET_CA_KEY_PASSPHRASE` (env var only, no CLI flag to avoid `/proc/cmdline` exposure).

**Environment variables (config file / env var only, no CLI flag):**

| Config key | Environment variable |
|------------|---------------------|
| `ca_key_algo` | `PUPPET_CA_CA_KEY_ALGO` |
| `ca_key_size` | `PUPPET_CA_CA_KEY_SIZE` |
| `leaf_key_algo` | `PUPPET_CA_LEAF_KEY_ALGO` |
| `leaf_key_size` | `PUPPET_CA_LEAF_KEY_SIZE` |
| `ca_subject_org` | `PUPPET_CA_CA_SUBJECT_ORG` |
| `ca_subject_ou` | `PUPPET_CA_CA_SUBJECT_OU` |
| `ca_subject_country` | `PUPPET_CA_CA_SUBJECT_COUNTRY` |
| `ca_subject_locality` | `PUPPET_CA_CA_SUBJECT_LOCALITY` |
| `ca_subject_province` | `PUPPET_CA_CA_SUBJECT_PROVINCE` |
| `ca_path_length` | `PUPPET_CA_CA_PATH_LENGTH` |
| `ca_validity_days` | `PUPPET_CA_CA_VALIDITY_DAYS` |
| `leaf_validity_days` | `PUPPET_CA_LEAF_VALIDITY_DAYS` |
| `crl_validity_days` | `PUPPET_CA_CRL_VALIDITY_DAYS` |
| `disable_crl_refresh` | `PUPPET_CA_DISABLE_CRL_REFRESH` |
| `crl_refresh_interval_sec` | `PUPPET_CA_CRL_REFRESH_INTERVAL_SEC` |
| `crl_refresh_before_sec` | `PUPPET_CA_CRL_REFRESH_BEFORE_SEC` |
| `enable_expired_cert_cleanup` | `PUPPET_CA_ENABLE_EXPIRED_CERT_CLEANUP` |
| `expired_cert_retention_sec` | `PUPPET_CA_EXPIRED_CERT_RETENTION_SEC` |
| `expired_cert_cleanup_interval_sec` | `PUPPET_CA_EXPIRED_CERT_CLEANUP_INTERVAL_SEC` |
| `shutdown_timeout_sec` | `PUPPET_CA_SHUTDOWN_TIMEOUT_SEC` |
| `etcd_username` | `PUPPET_CA_ETCD_USERNAME` |
| `etcd_password` | `PUPPET_CA_ETCD_PASSWORD` |
| `etcd_dial_timeout_sec` | `PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC` |
| `etcd_request_timeout_sec` | `PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC` |
| `etcd_tls_ca_file` | `PUPPET_CA_ETCD_TLS_CA_FILE` |
| `etcd_tls_cert_file` | `PUPPET_CA_ETCD_TLS_CERT_FILE` |
| `etcd_tls_key_file` | `PUPPET_CA_ETCD_TLS_KEY_FILE` |
| `puppet_datetime_format` | `PUPPET_CA_PUPPET_DATETIME_FORMAT` |
| `revoke_on_auto_renew` | `PUPPET_CA_REVOKE_ON_AUTO_RENEW` |

> **Note:** `--daemon` is intentionally excluded from config file and environment
> variable support because `PUPPET_CA_DAEMON` is used internally as the daemon fork
> signal.

Boolean env vars accept any value accepted by `strconv.ParseBool`: `1`, `t`, `true`,
`yes`, `on` (case-insensitive) to enable; `0`, `f`, `false`, `no`, `off` to disable.

### Quick start (plain HTTP, auto-bootstrap CA)

```bash
./bin/openvox-ca --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com
```

On first run the server bootstraps a new CA under `--cadir` and begins serving on port 8140.

### HTTPS with mTLS

```bash
./bin/openvox-ca \
  --cadir /etc/puppetlabs/puppet/ssl \
  --tls-cert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
  --tls-key  /etc/puppetlabs/puppet/ssl/ca/ca_key.pem \
  --puppet-server puppet.example.com
```

When `--tls-cert` and `--tls-key` are both set, the server:
1. Presents those certs to connecting clients
2. Requests (but does not require) a client certificate from every connection
3. Enforces endpoint-level authorization (see [Authorization tiers](#authorization-tiers) below)

### Signal handling

On `SIGTERM` or `SIGINT`, the frontend HTTP server calls `http.Server.Shutdown()` with a drain context (wired via `signal.NotifyContext`) so in-flight requests (signing, CRL, OCSP) drain cleanly before the process exits. The request context is cancelled on signal, and the command returns normally rather than calling `os.Exit` on its error paths, so deferred storage and signer cleanup always runs after all connections are done.

The drain budget defaults to **25 seconds** and is configurable via `shutdown_timeout_sec` (config file) or `PUPPET_CA_SHUTDOWN_TIMEOUT_SEC` (environment); a non-positive value falls back to the default.

In the default isolated-process deployment, the launcher supervisor forwards the signal to both the signer and frontend children and waits the drain budget **plus a 3-second headroom** (28 seconds by default) before hard-killing any child that has not exited. Because the launcher's timer starts when it forwards `SIGTERM` — strictly before the frontend begins its own `Shutdown()` — this headroom guarantees the supervisor always outlasts the frontend's drain rather than truncating it.

This is particularly important for **Kubernetes rolling updates**: pods receive `SIGTERM` with a configurable grace period (`terminationGracePeriodSeconds`, default 30 seconds). The defaults (25s drain, 28s supervisor) nest under that 30-second grace so the server drains and exits cleanly before the platform `SIGKILL`s the pod. If you raise `shutdown_timeout_sec`, raise `terminationGracePeriodSeconds` to at least the drain budget plus 3 seconds.

## Autosigning

The `--autosign-config` flag controls automatic CSR signing:

| Value | Behavior |
|-------|----------|
| `false` / `""` | Manual signing only (default) |
| `true` | Sign every incoming CSR immediately |
| `/path/to/file` (not executable) | Glob-pattern allowlist (one pattern per line, `#` comments ignored) |
| `/path/to/script` (executable) | Custom plugin: called with `argv[1]=CN`, CSR PEM on stdin; exit 0 = sign, non-zero = hold |

Allowlist example:

```
# autosign.conf
*.agent.example.com
compile-*.internal
```

Executable plugin example:

```bash
#!/bin/bash
subject="$1"
csr_pem=$(cat)
# approve only nodes whose name starts with "web-"
[[ "$subject" == web-* ]] && exit 0 || exit 1
```

## Directory layout

```
<cadir>/
  ca_crt.pem          CA certificate
  ca_pub.pem          CA public key
  ca_crl.pem          Certificate Revocation List
  inventory.txt       Signed certificate log (hex serial, dates, subject per line)
  signed/             Issued certificates
  requests/           Pending CSRs
  private/
    ca_key.pem              CA private key (mode 0600; encrypted PEM when --encrypt-ca-key)
    .ca_key_passphrase      Auto-generated passphrase file (mode 0600; only when --encrypt-ca-key
                            is used without an explicit passphrase source)
    {subject}_key.pem       Server-side generated private keys (mode 0600)
```

> **Note:** Serial numbers are now cryptographically random (128-bit). The `serial`
> file used by older Puppet CAs for sequential serial tracking is no longer
> written or read by this server.

## API reference

All endpoints are served under both the bare path and `/puppet-ca/v1/<path>`, so the server can be used directly by agents or placed behind a proxy that strips the prefix.

### Certificate status

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate_status/{subject}` | Get status: `signed`, `requested`, or `revoked` |
| `PUT` | `/certificate_status/{subject}` | Change state (`signed` or `revoked`); supports `cert_ttl` (seconds) |
| `DELETE` | `/certificate_status/{subject}` | Revoke + delete cert and CSR (`puppet cert clean`) |

`PUT` body:

```json
{ "desired_state": "signed", "cert_ttl": 86400 }
```

`GET` response:

```json
{
  "name": "agent.example.com",
  "state": "signed",
  "fingerprint": "AA:BB:...",
  "fingerprints": { "SHA256": "AA:BB:...", "default": "AA:BB:..." },
  "dns_alt_names": ["agent.example.com"],
  "subject_alt_names": ["agent.example.com"],
  "authorization_extensions": {},
  "serial_number": 7329847239485029341,
  "not_before": "2025-01-01T00:00:00Z",
  "not_after": "2030-01-01T00:00:00Z"
}
```

> **Note:** `serial_number` is the low 64 bits of the certificate's cryptographically random 128-bit serial, returned as a signed int64 for API compatibility. It is omitted for certificates in the `requested` state.

### Certificate statuses (list)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate_statuses/{any}` | List all certificates; filter with `?state=requested\|signed\|revoked` |

### CSR management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate_request/{subject}` | Retrieve a pending CSR PEM |
| `PUT` | `/certificate_request/{subject}` | Submit a new CSR (body: raw PEM) |
| `DELETE` | `/certificate_request/{subject}` | Delete a pending CSR |

### Certificate retrieval

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate/{subject}` | Retrieve a signed certificate PEM (`ca` returns the CA cert) |

### Certificate renewal

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/certificate_renewal` | Renew an existing certificate; body: raw CSR PEM, or empty; returns new certificate PEM |

Requires a valid CA-signed client certificate. The new certificate is issued immediately without entering the pending-CSR queue or autosign evaluation, and the certificate it replaces is revoked once the new one is safely stored (see `revoke_on_auto_renew` below for the auto-renewal case).

- **CSR body (re-key):** the CSR Common Name must match the authenticated client CN — an agent can only renew its own certificate, not another's. Issues a certificate for the new key in the CSR. Puppet OID extensions are copied from the CSR **except** authorization-arc OIDs (`1.3.6.1.4.1.34380.1.3.*`, such as `pp_cli_auth`), which are stripped so a submitted CSR cannot request elevated privileges.
- **Empty body (wire-compatible auto-renewal):** matches the request real Puppet/OpenVox agents send by default (`hostcert_renewal_interval`, and the `puppet ssl renew_cert` CLI action). Identity and key possession come solely from the mTLS-presented client certificate; the same public key is reissued with a fresh serial and validity, carrying forward the original certificate's SANs and Puppet OID extensions unchanged. Unlike the CSR path, this **preserves authorization-arc OIDs** (e.g. `pp_cli_auth`): they were already vetted when the presented certificate was issued, so a cert that legitimately holds them keeps them across renewal.

If the presented certificate's (or CSR's) key falls below the CA key-strength policy — for example an RSA-1024 key imported from a legacy CA — the request is rejected with `422 Unprocessable Entity` rather than renewed; the agent must re-key via the CSR path with a compliant key.

`revoke_on_auto_renew` (env `PUPPET_CA_REVOKE_ON_AUTO_RENEW`, default `true`) controls whether the certificate replaced by an auto-renewal (empty body) is revoked. The default keeps only the newest serial per subject valid. Set to `false` to match OpenVox Server's own (Clojure) CA exactly, which leaves the replaced certificate valid — for the same key — until it naturally expires. This setting has no effect on the CSR-body (re-key) path, which always revokes the certificate it replaces.

> **CRL growth:** with the default `true`, every auto-renewal appends the retired serial to the CRL, and the entry stays there until the certificate expires. Entries are only pruned by the expired-certificate cleanup job, which is off by default — enable `enable_expired_cert_cleanup` to bound CRL size on busy CAs, and watch `puppetca_crl_revoked_certificates` to keep an eye on it. Revocation is best-effort (a failure never fails the renewal); the `puppetca_crl_update_failures_total` metric counts any failure to amend the CRL, including a superseded certificate that could not be revoked.

### Bulk signing

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/sign` | Sign one or more CSRs; body: `{"certnames":["a","b"]}` |
| `POST` | `/sign/all` | Sign every pending CSR |

### Bulk clean

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/clean` | Revoke + delete multiple certificates in bulk; body: `{"certnames":["a","b"]}` |

Response:

```json
{ "cleaned": ["a.example.com"], "not-found": ["missing.example.com"], "clean-errors": [] }
```

### CRL

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/certificate_revocation_list/ca` | Download the current CRL PEM |
| `PUT` | `/certificate_revocation_list/ca` | Re-sign the CRL with a fresh validity window (preserves all revocations); admin-only. Returns the new CRL PEM |

### Expirations

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/expirations` | CA cert and CRL expiry dates |

### Server-side key generation

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/generate/{subject}` | Generate key + cert server-side; optional `?dns=alt.name`. Key algorithm follows `--leaf-key-algo` / `--leaf-key-size` (default: RSA 2048) |

Response:

```json
{ "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...", "certificate": "-----BEGIN CERTIFICATE-----\n..." }
```

### Certificate import

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/certificate/{subject}` | Import a certificate issued outside this CA's normal signing flow into the inventory; admin-only |

Shares its path with `GET /certificate/{subject}` (certificate retrieval, above) but is a distinct, admin-only operation. Request body: raw certificate PEM. `{subject}` must match the certificate's CN or one of its DNS Subject Alternative Names — this lets an operator import under a specific identity even when the certificate's SANs list several names.

This is for certificates that were signed by this CA's key but never went through `Sign`/`Generate` — most commonly certificates migrated from a legacy CA installation that shared this CA's key material. The certificate's signature must verify against this CA's certificate (a pure cryptographic check, so an already-expired certificate is still accepted for record-keeping); CA certificates (`IsCA: true`) are rejected — use `openvox-ca-ctl import` for CA bundle import instead.

Once imported, the certificate is tracked exactly like a normally-issued one: it appears in listings and status lookups, is cleaned up by the normal expiry sweep, and can be revoked via the usual `PUT /certificate_status/{subject}` (`desired_state: "revoked"`) mechanism.

Conflict handling, in priority order:

1. If the exact same certificate (same serial, byte-identical) is already the tracked certificate for the subject, the request succeeds as a no-op (`"imported": false` in the response).
2. Otherwise, if the certificate's serial number is already tracked anywhere in the inventory (under this subject or another), the request is rejected with `409 Conflict`.
3. Otherwise, if the subject already has an active (non-revoked) certificate, the request is rejected with `409 Conflict`. If the subject's existing certificate is revoked, it is evicted and the import proceeds.

Invalid certificates — malformed or multi-block PEM, a signature that does not chain to this CA, a CA certificate (`IsCA: true`), a subject that matches neither the CN nor any DNS SAN, a non-positive serial, or a bad validity window — are rejected with `400 Bad Request`. If the CA has not finished initialising, the request returns `503 Service Unavailable` (retry once it is ready).

Response:

```json
{ "subject": "legacy-node.example.com", "serial": "1A2B3C4D5E6F", "not_before": "2020-01-01T00:00:00Z", "not_after": "2025-01-01T00:00:00Z", "imported": true }
```

`serial` is uppercase hex (matching the inventory/CRL/OCSP convention), unlike the decimal `serial_number` field in certificate status responses (which is decimal only to preserve the full 128-bit value without int64 truncation — a constraint that doesn't apply to this string field).

### OCSP

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/ocsp` | RFC 6960 OCSP request; body is DER-encoded `OCSPRequest` |
| `GET` | `/ocsp/{request}` | RFC 6960 GET form; `{request}` is standard or URL-safe base64-encoded DER |

Both paths are also served under `/puppet-ca/v1/`. Responses are signed by the CA key directly (`Content-Type: application/ocsp-response`). GET responses include `Cache-Control: max-age=…, public`; requests carrying a nonce bypass the cache. The AIA extension is embedded in issued certificates when `--ocsp-url` is set.

### Health probes

These endpoints are served at bare paths only (no `/puppet-ca/v1` prefix) and require no client certificate.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz/live` | Liveness probe: always `200` while the process is running |
| `GET` | `/healthz/ready` | Readiness probe: `200` once the CA is initialised, `503` before |
| `GET` | `/healthz/startup` | Startup probe: delegates to the readiness check |

Response body: `{"status":"ok"}` (200) or `{"status":"not_ready"}` (503).

## Authorization tiers

When mTLS is enabled (both `--tls-cert` and `--tls-key` set), each endpoint requires a minimum client certificate tier:

| Tier | Required client cert | Endpoints |
|------|---------------------|-----------|
| **Public** | None | `GET /healthz/*`, `GET /certificate/{subject}`, `GET /certificate_revocation_list/ca`, `PUT /certificate_request/{subject}`, `GET /expirations`, `POST /ocsp`, `GET /ocsp/{request}` |
| **Any client** | Any CA-signed cert | `GET /certificate_status/{subject}` (public with `--allow-public-status`), `POST /certificate_renewal` |
| **Self or admin** | Cert CN matches path subject, OR cert is admin | `GET /certificate_request/{subject}` |
| **Admin** | Cert is admin (see below) | `PUT /certificate_status/{subject}`, `DELETE /certificate_status/{subject}`, `DELETE /certificate_request/{subject}`, `GET /certificate_statuses/*`, `POST /sign`, `POST /sign/all`, `POST /generate/{subject}`, `PUT /clean`, `PUT /certificate_revocation_list/ca`, `PUT /certificate/{subject}` |

In plain HTTP mode (no TLS), all endpoints are accessible without authentication.

> **Note:** `GET /certificate_status/{subject}` requires a CA-signed client certificate by default. Use `--allow-public-status` to make it public for environments where bootstrapping agents need to poll status before obtaining a client certificate. The response exposes state, fingerprint, serial number, and authorization extensions.

### Admin credential resolution

A client certificate is considered an admin credential if **either** condition is met:

1. **CN allow list:** the certificate's Common Name appears in the `--puppet-server` comma-separated list or in the file pointed to by `--puppet-server-file` (one CN per line; `#` comments and blank lines ignored). Both sources can be used simultaneously; their CNs are merged.
2. **`pp_cli_auth` extension:** the certificate carries the Puppet authorization extension OID `1.3.6.1.4.1.34380.1.3.39` with the UTF8String value `"true"`. OpenVox Server embeds this extension in its own certificate by default, so the `puppetserver ca` CLI can authenticate without being listed by CN.

The `pp_cli_auth` check is enabled by default. Disable it with `--no-pp-cli-auth` (or `no_pp_cli_auth: true` in the config file) if you prefer strict CN-only authorization.

> **OID source:** [`lib/puppet/ssl/oids.rb`](https://github.com/puppetlabs/puppet/blob/main/lib/puppet/ssl/oids.rb)

## CA key encryption at rest

By default, the CA private key is stored as unencrypted PEM at `<cadir>/private/ca_key.pem`.
Enable `--encrypt-ca-key` to encrypt the key at rest using AES-256-GCM with an Argon2id-derived key.

### How it works

- The private key is marshalled to PKCS#8 DER, then encrypted with AES-256-GCM.
- The encryption key is derived from a passphrase using Argon2id (time=3, memory=64 MiB, threads=4).
- The encrypted key is stored as a PEM block with type `ENCRYPTED PRIVATE KEY`.
- On startup, the key is decrypted into memory and used for all signing operations.

### Passphrase resolution order

1. **`--ca-key-passphrase-file`:** reads the first line of the specified file.
2. **`PUPPET_CA_KEY_PASSPHRASE`** environment variable: avoids CLI `/proc/cmdline` exposure.
3. **Auto-generated:** if no passphrase source is configured, a cryptographically random
   passphrase is generated and saved to `<cadir>/private/.ca_key_passphrase` (mode `0600`).
   The path is logged at startup so operators know where it is.

### Example usage

```bash
# Bootstrap with encryption (auto-generated passphrase):
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key

# Bootstrap with an explicit passphrase file:
echo "my-secret-passphrase" > /etc/puppet-ca/key-passphrase
chmod 600 /etc/puppet-ca/key-passphrase
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key \
  --ca-key-passphrase-file /etc/puppet-ca/key-passphrase

# Or via environment variable:
export PUPPET_CA_KEY_PASSPHRASE="my-secret-passphrase"
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key

# openvox-ca-ctl setup also supports encryption:
openvox-ca-ctl setup --cadir /var/lib/puppet-ca --encrypt-ca-key
```

### Backward compatibility

Existing CAs with unencrypted keys continue to work without changes. The `--encrypt-ca-key`
flag only affects new CA bootstraps. Loading transparently handles both encrypted and
unencrypted PEM files.

### Security considerations

Encrypting the CA key at rest protects against **offline exfiltration**. If an attacker
obtains the key file from a backup, disk image, or volume snapshot, the key is unusable
without the passphrase. It does **not** protect against a live host compromise where the
attacker can read the passphrase source or dump the process memory.

For stronger protection, either delegate key custody to OpenBao entirely (available
today; see [OpenBao Transit-engine key custody](#openbao-transit-engine-key-custody)
below) or consider a hardware security module (HSM) via PKCS#11 (planned; see
[Planned: PKCS#11 / HSM support](#planned-pkcs11--hsm-support) below).

### OpenBao Transit-engine key custody

`--ca-key-provider openbao` delegates the CA private key entirely to an
[OpenBao](https://openbao.org/) Transit secrets engine key: the key never exists inside
any `openvox-ca` process at all, on disk or in memory — only a digest crosses the wire
to be signed. This works identically whether `openvox-ca` runs as a plain systemd
service (AppRole or a static token file) or as a Kubernetes pod authenticating via its
own ServiceAccount (Kubernetes auth) — with no Vault/OpenBao Agent sidecar required:
`openvox-ca` maintains its own OpenBao token lifecycle, proactively renewing it and
re-authenticating from source credentials whenever renewal fails.

Every existing storage backend keeps working unmodified in this mode — OpenBao only
ever supplants key custody, never CSR/certificate/CRL/inventory storage. See
[OpenBao Transit-engine CA key](docs/openbao-transit.md) for full configuration
reference and setup instructions.

This integration is built and tested against OpenBao specifically, against current
OpenBao releases. It should also work against HashiCorp Vault, since Vault's Transit
engine, AppRole/Kubernetes auth methods, and Go client API are what OpenBao forked from
and remains wire-compatible with — but Vault is not part of the test matrix, so this is
currently unverified. Compatibility bug reports (and fixes) for Vault are welcome.

### Planned: PKCS#11 / HSM support

A future enhancement will add PKCS#11 support so the CA private key can be held in a
hardware security module (HSM), TPM, or software token (e.g. SoftHSM2). The key would
never leave the token. Only signing operations would be delegated via the PKCS#11 API.

The implementation path is straightforward because the CA already stores its key as a
`crypto.Signer` interface (`internal/ca/ca.go`), and the `--ca-key-provider` flag
already exists (`file` default, `openbao` shipped — see above). A PKCS#11-backed signer
would be a third value of the same flag, implementing the same `ca.KeyProvider`
interface the OpenBao integration uses, requiring no changes to the signing,
revocation, or OCSP code paths.

**Planned design:**
- `--ca-key-provider pkcs11`: a PKCS#11 module URI or library path, slot/token label, and PIN
  (via file or env var, same pattern as `--ca-key-passphrase-file`)
- Integration with **p11-kit** for module discovery, allowing operators to configure the
  PKCS#11 backend (SoftHSM2, TPM2 PKCS#11, cloud KMS bridges, Nitrokey, YubiHSM, etc.)
  via the system p11-kit configuration rather than hardcoding library paths
- CGo dependency for the PKCS#11 C bindings (build-time opt-in)

This is tracked as a separate feature. Contributions welcome.

### Monitoring destructive operations

The server tracks the rate of destructive operations (certificate revocation and
deletion) per authenticated client. When a single client exceeds **5 destructive
operations per minute**, a warning is emitted to the structured log:

```
level=WARN msg="High rate of destructive operations detected" client=admin.example.com operation=revoke
```

This is a detective control, not a preventive one. It does not block the operation, but alerts
operators to potentially anomalous administrative activity. Operators should:

- Forward `openvox-ca` logs to a centralized log aggregator (e.g. Loki,
  Elasticsearch, Splunk)
- Create alerts on `"High rate of destructive operations"` log messages
- Investigate any alerts promptly. A burst of revocations may indicate a
  compromised admin certificate or an operational error
- Consider whether the `--allow-list` should be tightened if unexpected clients
  appear in these warnings

The threshold (5 ops/minute) is a sensible default for environments where
bulk revocation is uncommon. Future versions may make this configurable.

## openvox-ca-ctl -- the operator CLI

`openvox-ca-ctl` mirrors the `puppet cert` / `puppetserver ca` subcommands and communicates with a running `openvox-ca` server over HTTP(S).

### Global flags

```
--config       ""                       Path to YAML config file (auto-detected at /etc/puppet-ca/ctl.yaml)
--server-url   https://localhost:8140   openvox-ca server URL
--ca-cert      ""                       CA cert PEM for TLS verification (omit to skip verify)
--client-cert  ""                       Client certificate PEM for mTLS
--client-key   ""                       Client private key PEM for mTLS
--verbose                               Enable debug logging
```

Global flags may be placed before or after the subcommand name.

### Configuration

All global flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

The config file is located by checking, in order:
1. `--config /path/to/ctl.yaml` (explicit flag)
2. `PUPPET_CA_CTL_CONFIG` environment variable
3. `/etc/puppet-ca/ctl.yaml` (auto-detected if the file exists)

**Example `/etc/puppet-ca/ctl.yaml`:**

```yaml
server_url:  https://openvox-ca.example.com:8140
ca_cert:     /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem
client_cert: /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem
client_key:  /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem
verbose:     false
```

**Environment variables:**

| Flag | Environment variable |
|------|---------------------|
| `--server-url` | `PUPPET_CA_CTL_SERVER_URL` |
| `--ca-cert` | `PUPPET_CA_CTL_CA_CERT` |
| `--client-cert` | `PUPPET_CA_CTL_CLIENT_CERT` |
| `--client-key` | `PUPPET_CA_CTL_CLIENT_KEY` |
| `--verbose` | `PUPPET_CA_CTL_VERBOSE` |

### Subcommands

```bash
# List pending CSRs
openvox-ca-ctl list

# List all certificates (signed, revoked, requested)
openvox-ca-ctl list --all

# Sign a pending CSR
openvox-ca-ctl sign --certname agent.example.com

# Sign all pending CSRs
openvox-ca-ctl sign --all

# Revoke a certificate
openvox-ca-ctl revoke --certname agent.example.com

# Revoke + delete cert and CSR
openvox-ca-ctl clean --certname agent.example.com

# Re-sign the CRL with a fresh validity window (preserves all revocations)
openvox-ca-ctl reissue-crl

# Generate a server-side key+cert pair (key saved to ./agent.example.com_key.pem)
openvox-ca-ctl generate --certname agent.example.com
openvox-ca-ctl generate --certname agent.example.com --dns alt.example.com --out-dir /etc/ssl

# Import a certificate issued outside this CA's normal flow (e.g. migrated
# from a legacy CA sharing this CA's key)
openvox-ca-ctl import-cert --certname legacy-node.example.com --cert-file legacy-node_cert.pem

# Bootstrap a new CA offline (no server required)
openvox-ca-ctl setup --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com

# Import an external CA cert/key offline
openvox-ca-ctl import \
  --cadir      /etc/puppetlabs/puppet/ssl \
  --cert-bundle ca_cert.pem \
  --private-key ca_key.pem \
  --crl-chain   ca_crl.pem     # optional; a new CRL is generated if omitted

# Migrate an entire CA between storage backends offline (any pair of backends:
# filesystem, sqlite, postgres, mysql, etcd, redis/valkey). Each backend is
# described by a normal openvox-ca config file. Refuses a non-empty destination
# unless --force.
openvox-ca-ctl migrate \
  --source-config /etc/puppet-ca/filesystem.yaml \
  --dest-config   /etc/puppet-ca/postgres.yaml
```

`setup`, `import` and `migrate` operate directly on storage. No running server is needed.
See [docs/storage-backends.md](docs/storage-backends.md#migrating-between-backends) for migration details.

## Container / Compose

A `Dockerfile` and `compose.yml` are provided for development and integration testing.

```bash
# Build images and run the full integration test suite
mage test:integCompose

# integCompose + concurrency/correctness tests (DO_LOAD=true)
mage test:loadCompose

# k6 load test suite: correctness, throughput benchmarks, saturation ramp
mage test:bench

# Full Puppet stack: CA (TLS) + WEBrick master + OpenVoxDB + agent
mage test:puppet
```

`test:integCompose` and `test:loadCompose` use `compose.yml`, the canonical integration test suite. It runs two containers on an isolated network (openvox-ca + test-runner) and exercises the full API in TAP format across 21 test groups:

| Group | Coverage |
|-------|----------|
| 1 | Endpoint smoke tests (health probes, CA cert, CRL, 404s, expirations) |
| 2 | Full CSR lifecycle: submit → sign → verify → revoke → re-register; issue #8 assertions (no Netscape Comment OID, random serial ≥16 hex digits, CRL Distribution Point present, `authorization_extensions` field, CSR deleted after signing) |
| 3 | `openvox-ca-ctl sign --all` (bulk signing) |
| 4 | `POST /generate` (server-side key+cert generation) |
| 5 | `GET /certificate_statuses?state=` filter; `openvox-ca-ctl list / list --all` |
| 6 | `cert_ttl` custom validity via `PUT /certificate_status` |
| 7 | `subject_alt_names` field in status responses |
| 8 | CSR CN mismatch rejection (400) |
| 9 | Error cases: invalid subjects, bad JSON, conflict (409), `BasicConstraints CA:TRUE` rejection |
| 10 | `PUT /clean` bulk revoke+delete: success, not-found, and error buckets |
| 11 | Protocol features: bare paths, `/puppet-ca/v1/` prefixed paths |
| 12 | `openvox-ca-ctl` offline subcommands: `setup` (bootstrap new CA) and `import` (external CA cert/key/CRL) |
| 13 | `POST /sign` and `POST /sign/all` bulk HTTP signing API |
| 14 | Concurrency / load tests (opt-in via `DO_LOAD=true` / `mage test:loadCompose`) |
| 15 | OCSP: good/revoked status, nonce handling, cache invalidation on revoke, malformed request (400) |
| 16 | Autosign modes: `true`, glob-pattern file, executable plugin |
| 17 | Config drivers: env vars, config file |
| 18 | `pp_cli_auth` mTLS: Phase 1 bootstraps certs (loopback HTTP); Phase 2 asserts pp_cli_auth cert reaches admin endpoints while plain cert is denied |
| 19 | `openvox-ca-ctl` error paths: revoke/clean/sign/generate against non-existent or duplicate subjects; arg validation; `--dns` SAN delivery; full mTLS via `--ca-cert`/`--client-cert`/`--client-key`; unreachable server |
| 20 | Migration from Puppet Server CA: import CA cert/key/CRL via `openvox-ca-ctl import`, copy pre-existing signed certs, verify fetch/sign/revoke/list all work on the migrated CA |
| 21 | `POST /certificate_renewal` over mTLS: agent renews its own certificate; CN-mismatch renewal rejected |

`test:bench` uses `compose-bench.yml` (autosign=true, k6 load runner).
`test:puppet` uses `compose-puppet.yml`, a five-service stack that validates end-to-end catalog compilation, PuppetDB reporting, exported resources, and CRL revocation using a real OpenVox 8 agent and WEBrick puppet master. The CA runs with genuine TLS (a cert with CN=openvox-ca signed by the CA itself); all inter-service traffic verifies it.
`test:migration` uses `compose-migration.yml`, which starts a real VoxPupuli Puppet Server (`voxpupuli/puppetserver:latest`) to create a genuine Puppet CA, then imports its CA material into openvox-ca using `openvox-ca-ctl import` and verifies the full migration path: old certs are fetchable, new certs can be signed, migrated certs can be revoked and cleaned.

The k6 script (`test/load.js`) runs two concurrent scenarios:
- **reads** -- hammers GET /certificate/ca, CRL, and expirations; ramps to 200 VUs
- **workflow** -- POST /generate → GET status → GET cert → DELETE; ramps to 50 VUs (CPU-bound on RSA key generation)

Thresholds that fail the run: error rate ≥ 1%, read p95 ≥ 500 ms, workflow p95 ≥ 5 s.

## Development

```bash
# Run all unit tests
mage test:unit

# Format, vet, and tidy modules
mage dev:check

# Run integration tests using the compose stack
mage test:integCompose

# Run the full Puppet stack (CA TLS + WEBrick master + OpenVoxDB + agent)
mage test:puppet

# Run k6 load tests (correctness + throughput + saturation) via compose
mage test:bench
```

### File permissions

| Content | Mode |
|---------|------|
| Directories | `0750` |
| Private keys | `0600` |
| CRL file | `0600` |
| Public data (certs, CSRs, inventory) | `0644` |

The user running `openvox-ca` must own (or have write access to) `--cadir`.
