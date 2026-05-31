# puppet-ca

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
- **Autosigning:** `true`, glob-pattern file, or executable plugin modes
- **mTLS support:** optional HTTPS with per-endpoint tier-based client certificate authorization
- **CA import:** replace a bootstrapped CA with an external cert/key pair offline
- **Server-side key generation:** issue cert+key pairs without a node-submitted CSR; configurable RSA (2048/3072/4096) or ECDSA (P-256/P-384/P-521)
- **Configurable key algorithms:** CA and leaf certificates can use RSA or ECDSA; ECDSA support for both bootstrapped CAs and generated leaf certs
- **Random serial numbers:** every issued leaf certificate gets a cryptographically random 128-bit serial (CA/Browser Forum guidance)
- **CRL Distribution Points:** optionally embed a CRL URL in every issued certificate (`--crl-url`) so verifiers can automatically fetch the CRL
- **Configurable CRL validity:** control how long each published CRL is valid (`crl_validity_days`)
- **OCSP responder:** built-in RFC 6960 OCSP responder; AIA extension embedded in issued certs when `--ocsp-url` is set; in-memory cache with nonce bypass
- **Health probes:** `/healthz/live`, `/healthz/ready`, and `/healthz/startup` endpoints for Kubernetes-style liveness/readiness checks
- **Graceful shutdown:** `SIGTERM`/`SIGINT` drains in-flight requests with a 30-second window before exiting; deferred storage and signer cleanup always runs
- **FIPS-compatible:** standard library only (`crypto/x509`, `net/http`); no CGO by default; FIPS build available via `GOEXPERIMENT=boringcrypto`
- **`puppet-ca-ctl`:** operator CLI matching `tvaughan-server-ca` subcommands

## Building

Requirements: Go 1.25+, [Mage](https://magefile.org/)

```bash
git clone https://github.com/tvaughan/puppet-ca.git
cd puppet-ca

# Build both binaries to bin/
mage build:all

# Or with plain Go
go build -o bin/puppet-ca     ./cmd/puppet-ca
go build -o bin/puppet-ca-ctl ./cmd/puppet-ca-ctl
```

### FIPS build (Linux/amd64)

```bash
mage build:fips   # → bin/puppet-ca + bin/puppet-ca-ctl  (GOEXPERIMENT=boringcrypto, CGO_ENABLED=1)
```

## puppet-ca -- the server

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
| `--encrypt-ca-key` | `false` | Encrypt the CA private key at rest (AES-256-GCM + Argon2id) |
| `--ca-key-passphrase-file` | `""` | Path to file containing the CA key passphrase (first line used) |
| `--csr-rate-limit` | `60` | Max CSR submissions per IP per minute on the public `PUT /certificate_request` endpoint (0 disables) |
| `--single-process` | `false` | Disable CA key isolation (run signer and frontend in a single process) |
| `--storage-backend` | `filesystem` | Storage backend for CA state: `filesystem` or `etcd`. See [storage backends](docs/storage-backends.md) |
| `--etcd-endpoints` | `""` | Comma-separated etcd endpoints (used when `--storage-backend etcd`) |
| `--etcd-key-prefix` | `/puppet-ca` | etcd key namespace for this CA |
| `--ca-cert-file` | `""` | Keep the CA certificate at this local path regardless of backend |
| `--ca-key-file` | `""` | Keep the CA private key at this local path regardless of backend |
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
# CA key encryption at rest.
encrypt_ca_key: false           # encrypt the CA private key (AES-256-GCM + Argon2id)
ca_key_passphrase_file: ""      # path to passphrase file; auto-generated if omitted
# Date/time format in JSON responses.
puppet_datetime_format: false   # use Puppet CA style "2006-01-02T15:04:05MST" instead of RFC 3339
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
| `--csr-rate-limit` | `PUPPET_CA_CSR_RATE_LIMIT` |
| `--encrypt-ca-key` | `PUPPET_CA_ENCRYPT_CA_KEY` |
| `--ca-key-passphrase-file` | `PUPPET_CA_KEY_PASSPHRASE_FILE` |
| `--storage-backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `--etcd-endpoints` | `PUPPET_CA_ETCD_ENDPOINTS` |
| `--etcd-key-prefix` | `PUPPET_CA_ETCD_KEY_PREFIX` |
| `--ca-cert-file` | `PUPPET_CA_CA_CERT_FILE` |
| `--ca-key-file` | `PUPPET_CA_CA_KEY_FILE` |

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
| `etcd_username` | `PUPPET_CA_ETCD_USERNAME` |
| `etcd_password` | `PUPPET_CA_ETCD_PASSWORD` |
| `etcd_dial_timeout_sec` | `PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC` |
| `etcd_request_timeout_sec` | `PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC` |
| `etcd_tls_ca_file` | `PUPPET_CA_ETCD_TLS_CA_FILE` |
| `etcd_tls_cert_file` | `PUPPET_CA_ETCD_TLS_CERT_FILE` |
| `etcd_tls_key_file` | `PUPPET_CA_ETCD_TLS_KEY_FILE` |
| `puppet_datetime_format` | `PUPPET_CA_PUPPET_DATETIME_FORMAT` |

> **Note:** `--daemon` is intentionally excluded from config file and environment
> variable support because `PUPPET_CA_DAEMON` is used internally as the daemon fork
> signal.

Boolean env vars accept any value accepted by `strconv.ParseBool`: `1`, `t`, `true`,
`yes`, `on` (case-insensitive) to enable; `0`, `f`, `false`, `no`, `off` to disable.

### Quick start (plain HTTP, auto-bootstrap CA)

```bash
./bin/puppet-ca --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com
```

On first run the server bootstraps a new CA under `--cadir` and begins serving on port 8140.

### HTTPS with mTLS

```bash
./bin/puppet-ca \
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

On `SIGTERM` or `SIGINT`, the frontend HTTP server calls `http.Server.Shutdown()` with a 30-second context (wired via `signal.NotifyContext`) so in-flight requests (signing, CRL, OCSP) drain cleanly before the process exits. The request context is cancelled on signal, and the command returns normally rather than calling `os.Exit` on its error paths, so deferred storage and signer cleanup always runs after all connections are done.

In the default isolated-process deployment, the launcher supervisor forwards the signal to both the signer and frontend children and waits up to 30 seconds — matching the frontend's own drain budget — before hard-killing any child that has not exited, so the drain window is honoured end-to-end rather than truncated by the supervisor.

This is particularly important for **Kubernetes rolling updates**: pods receive `SIGTERM` with a configurable grace period (typically 30 seconds). The server will drain in-flight requests within that window and exit cleanly, preventing connection resets during rollouts.

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
| `POST` | `/certificate_renewal` | Renew an existing certificate; body: raw CSR PEM; returns new certificate PEM |

Requires a valid CA-signed client certificate. The CSR Common Name must match the authenticated client CN — an agent can only renew its own certificate, not another's. The new certificate is issued immediately without entering the pending-CSR queue or autosign evaluation.

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
| **Admin** | Cert is admin (see below) | `PUT /certificate_status/{subject}`, `DELETE /certificate_status/{subject}`, `DELETE /certificate_request/{subject}`, `GET /certificate_statuses/*`, `POST /sign`, `POST /sign/all`, `POST /generate/{subject}`, `PUT /clean` |

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
puppet-ca --cadir /var/lib/puppet-ca --encrypt-ca-key

# Bootstrap with an explicit passphrase file:
echo "my-secret-passphrase" > /etc/puppet-ca/key-passphrase
chmod 600 /etc/puppet-ca/key-passphrase
puppet-ca --cadir /var/lib/puppet-ca --encrypt-ca-key \
  --ca-key-passphrase-file /etc/puppet-ca/key-passphrase

# Or via environment variable:
export PUPPET_CA_KEY_PASSPHRASE="my-secret-passphrase"
puppet-ca --cadir /var/lib/puppet-ca --encrypt-ca-key

# puppet-ca-ctl setup also supports encryption:
puppet-ca-ctl setup --cadir /var/lib/puppet-ca --encrypt-ca-key
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

For stronger protection, consider hardware security modules (HSM) via PKCS#11; see
[Planned: PKCS#11 / HSM support](#planned-pkcs11--hsm-support) below.

### Planned: PKCS#11 / HSM support

A future enhancement will add PKCS#11 support so the CA private key can be held in a
hardware security module (HSM), TPM, or software token (e.g. SoftHSM2). The key would
never leave the token. Only signing operations would be delegated via the PKCS#11 API.

The implementation path is straightforward because the CA already stores its key as a
`crypto.Signer` interface (`internal/ca/ca.go`). A PKCS#11-backed signer would implement
the same interface, requiring no changes to the signing, revocation, or OCSP code paths.

**Planned design:**
- A `--ca-key-provider` flag: `file` (default, current behaviour) or `pkcs11`
- For `pkcs11`: a PKCS#11 module URI or library path, slot/token label, and PIN
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

- Forward `puppet-ca` logs to a centralized log aggregator (e.g. Loki,
  Elasticsearch, Splunk)
- Create alerts on `"High rate of destructive operations"` log messages
- Investigate any alerts promptly. A burst of revocations may indicate a
  compromised admin certificate or an operational error
- Consider whether the `--allow-list` should be tightened if unexpected clients
  appear in these warnings

The threshold (5 ops/minute) is a sensible default for environments where
bulk revocation is uncommon. Future versions may make this configurable.

## puppet-ca-ctl -- the operator CLI

`puppet-ca-ctl` mirrors the `tvaughan-server-ca` / `puppetserver ca` subcommands and communicates with a running `puppet-ca` server over HTTP(S).

### Global flags

```
--config       ""                       Path to YAML config file (auto-detected at /etc/puppet-ca/ctl.yaml)
--server-url   https://localhost:8140   puppet-ca server URL
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
server_url:  https://puppet-ca.example.com:8140
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
puppet-ca-ctl list

# List all certificates (signed, revoked, requested)
puppet-ca-ctl list --all

# Sign a pending CSR
puppet-ca-ctl sign --certname agent.example.com

# Sign all pending CSRs
puppet-ca-ctl sign --all

# Revoke a certificate
puppet-ca-ctl revoke --certname agent.example.com

# Revoke + delete cert and CSR
puppet-ca-ctl clean --certname agent.example.com

# Generate a server-side key+cert pair (key saved to ./agent.example.com_key.pem)
puppet-ca-ctl generate --certname agent.example.com
puppet-ca-ctl generate --certname agent.example.com --dns alt.example.com --out-dir /etc/ssl

# Bootstrap a new CA offline (no server required)
puppet-ca-ctl setup --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com

# Import an external CA cert/key offline
puppet-ca-ctl import \
  --cadir      /etc/puppetlabs/puppet/ssl \
  --cert-bundle ca_cert.pem \
  --private-key ca_key.pem \
  --crl-chain   ca_crl.pem     # optional; a new CRL is generated if omitted

# Migrate an entire CA between storage backends offline (any pair of backends:
# filesystem, sqlite, postgres, mysql, etcd, redis/valkey). Each backend is
# described by a normal puppet-ca config file. Refuses a non-empty destination
# unless --force.
puppet-ca-ctl migrate \
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

`test:integCompose` and `test:loadCompose` use `compose.yml`, the canonical integration test suite. It runs two containers on an isolated network (puppet-ca + test-runner) and exercises the full API in TAP format across 21 test groups:

| Group | Coverage |
|-------|----------|
| 1 | Endpoint smoke tests (health probes, CA cert, CRL, 404s, expirations) |
| 2 | Full CSR lifecycle: submit → sign → verify → revoke → re-register; issue #8 assertions (no Netscape Comment OID, random serial ≥16 hex digits, CRL Distribution Point present, `authorization_extensions` field, CSR deleted after signing) |
| 3 | `puppet-ca-ctl sign --all` (bulk signing) |
| 4 | `POST /generate` (server-side key+cert generation) |
| 5 | `GET /certificate_statuses?state=` filter; `puppet-ca-ctl list / list --all` |
| 6 | `cert_ttl` custom validity via `PUT /certificate_status` |
| 7 | `subject_alt_names` field in status responses |
| 8 | CSR CN mismatch rejection (400) |
| 9 | Error cases: invalid subjects, bad JSON, conflict (409), `BasicConstraints CA:TRUE` rejection |
| 10 | `PUT /clean` bulk revoke+delete: success, not-found, and error buckets |
| 11 | Protocol features: bare paths, `/puppet-ca/v1/` prefixed paths |
| 12 | `puppet-ca-ctl` offline subcommands: `setup` (bootstrap new CA) and `import` (external CA cert/key/CRL) |
| 13 | `POST /sign` and `POST /sign/all` bulk HTTP signing API |
| 14 | Concurrency / load tests (opt-in via `DO_LOAD=true` / `mage test:loadCompose`) |
| 15 | OCSP: good/revoked status, nonce handling, cache invalidation on revoke, malformed request (400) |
| 16 | Autosign modes: `true`, glob-pattern file, executable plugin |
| 17 | Config drivers: env vars, config file |
| 18 | `pp_cli_auth` mTLS: Phase 1 bootstraps certs (loopback HTTP); Phase 2 asserts pp_cli_auth cert reaches admin endpoints while plain cert is denied |
| 19 | `puppet-ca-ctl` error paths: revoke/clean/sign/generate against non-existent or duplicate subjects; arg validation; `--dns` SAN delivery; full mTLS via `--ca-cert`/`--client-cert`/`--client-key`; unreachable server |
| 20 | Migration from Puppet Server CA: import CA cert/key/CRL via `puppet-ca-ctl import`, copy pre-existing signed certs, verify fetch/sign/revoke/list all work on the migrated CA |
| 21 | `POST /certificate_renewal` over mTLS: agent renews its own certificate; CN-mismatch renewal rejected |

`test:bench` uses `compose-bench.yml` (autosign=true, k6 load runner).
`test:puppet` uses `compose-puppet.yml`, a five-service stack that validates end-to-end catalog compilation, PuppetDB reporting, exported resources, and CRL revocation using a real OpenVox 8 agent and WEBrick puppet master. The CA runs with genuine TLS (a cert with CN=puppet-ca signed by the CA itself); all inter-service traffic verifies it.
`test:migration` uses `compose-migration.yml`, which starts a real VoxPupuli Puppet Server (`voxpupuli/puppetserver:latest`) to create a genuine Puppet CA, then imports its CA material into puppet-ca using `puppet-ca-ctl import` and verifies the full migration path: old certs are fetchable, new certs can be signed, migrated certs can be revoked and cleaned.

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

The user running `puppet-ca` must own (or have write access to) `--cadir`.
