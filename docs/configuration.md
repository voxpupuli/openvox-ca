# Configuring the server

This is the full configuration reference for the `openvox-ca` server. For the
operator CLI, see [operator CLI (`openvox-ca-ctl`)](operator-cli.md), which also
covers the offline subcommands that run on the `openvox-ca` binary itself
against this configuration — `csr` and `import-ca-cert`, for running under an
external root CA with any `ca_key_provider`.

## Flags

| Flag | Default | Description |
| --- | --- | --- |
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
| `--client-revocation-policy` | `require` | Revocation checking for `client_ca` domains: `require`, `check` or `skip`. Scoped to foreign issuers; this CA always checks its own CRL. See [trusting client certificates from another CA](#trusting-client-certificates-from-another-ca). |
| `--no-pp-cli-auth` | `false` | Disable `pp_cli_auth` extension as an admin credential; require CN allow list only |
| `--no-tls-required` | `false` | Allow plain HTTP on non-loopback addresses; use only behind a trusted TLS proxy or in test environments |
| `--allow-public-status` | `false` | Allow unauthenticated `GET /certificate_status`; by default this endpoint is admin-only, matching Puppet Server's shipped `auth.conf`. "Admin" means an admin CN of the trust domain that verified the client, or `pp_cli_auth` where that domain honours it — see [trusting client certificates from another CA](#trusting-client-certificates-from-another-ca) |
| `--ocsp-url` | `""` | OCSP responder URL to embed in issued certificates |
| `--crl-url` | `""` | CRL distribution point URL to embed in issued certificates |
| `--metrics-listen` | `""` | Address for the Prometheus exporter (e.g. `127.0.0.1:9140`); empty disables it. See [metrics & monitoring](metrics.md) |
| `--encrypt-ca-key` | `false` | Encrypt the CA private key at rest (AES-256-GCM + Argon2id). See [CA key security](ca-key-security.md) |
| `--ca-key-passphrase-file` | `""` | Path to file containing the CA key passphrase (first line used) |
| `--csr-rate-limit` | `60` | Max CSR submissions per IP per minute on the public `PUT /certificate_request` endpoint (0 disables) |
| `--single-process` | `false` | Disable CA key isolation (run signer and frontend in a single process) |
| `--storage-backend` | `filesystem` | Storage backend for CA state: `filesystem`, `sqlite`, `postgres`, `mysql`, `etcd`, or `redis`. See [storage backends](storage-backends.md) |
| `--etcd-endpoints` | `""` | Comma-separated etcd endpoints (used when `--storage-backend etcd`) |
| `--etcd-key-prefix` | `/puppet-ca` | etcd key namespace for this CA |
| `--ca-cert-file` | `""` | Keep the CA certificate at this local path regardless of backend |
| `--ca-key-file` | `""` | Keep the CA private key at this local path regardless of backend |
| `--ca-key-provider` | `file` | CA private key custody: `file` (default) or `openbao` (OpenBao Transit key). See [OpenBao Transit-engine CA key](openbao-transit.md) for the full `--openbao-*` flag reference |
| `--daemon` | `false` | Fork to background (not recommended in containers; incompatible with the `Type=notify` systemd unit — see [running under systemd](systemd.md)) |
| `--logfile` | `""` | Write JSON logs to this file instead of stderr |
| `--verbosity` / `-v` | `0` | Verbosity: `0`=Info, `1`=Debug, `2`=Trace |
| `--version` | | Print the version and exit; includes commit metadata when built from a git checkout |

## Precedence

All flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

Key generation and CA subject options are intentionally **not** exposed as CLI flags. They are one-time bootstrap decisions that belong in a config file or environment variable. Use the config file or `PUPPET_CA_CA_KEY_ALGO` / `PUPPET_CA_CA_SUBJECT_*` env vars to set them.

The config file is located by checking, in order:

1. `--config /path/to/config.yaml` (explicit flag)
2. `PUPPET_CA_CONFIG` environment variable
3. `/etc/puppet-ca/config.yaml` (auto-detected if the file exists)

## Config file

**Example `/etc/puppet-ca/config.yaml`:**

```yaml
cadir: /etc/puppetlabs/puppet/ssl/ca
host: 0.0.0.0
port: 8140
hostname: puppet.example.com
tls_cert: /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem
tls_key:  /etc/puppetlabs/puppet/ssl/ca/private/ca_key.pem
puppet_server: puppet.example.com
puppet_server_file: ""
no_pp_cli_auth: false
no_tls_required: false
allow_public_status: false  # set true to allow unauthenticated GET /certificate_status
                            # (otherwise admin-only: an admin CN of the matched
                            # trust domain, or pp_cli_auth where that domain
                            # honours it)
client_ca: []               # additional client issuers; see "Trusting client certificates from another CA"
client_revocation_policy: require   # require | check | skip (client_ca entries only)
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
# Background CRL sync reloads the stored CRL into the copy this replica's
# revocation checks read, so a revocation performed on another replica takes
# effect here. Read-only, runs on every replica, and is not covered by
# disable_crl_refresh. See "Revocation across replicas" below.
crl_sync_interval_sec: 0       # how often to reload; 0 = built-in default (60s)

# A PEM bundle of upstream CRLs published alongside this CA's own, for agents
# doing full-chain revocation checking. Verified against the stored CA bundle,
# and re-read by the crl-chain-refresh background job.
crl_chain_file: ""
crl_chain_refresh_interval_sec: 0  # how often to re-read it; 0 = built-in default (1h)
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

## Environment variables

Environment variables mirror the CLI flags:

| Flag | Environment variable |
| --- | --- |
| `--cadir` | `PUPPET_CA_CADIR` |
| `--autosign-config` | `PUPPET_CA_AUTOSIGN_CONFIG` |
| `--host` | `PUPPET_CA_HOST` |
| `--port` | `PUPPET_CA_PORT` |
| `--hostname` | `PUPPET_CA_HOSTNAME` |
| `--verbosity` | `PUPPET_CA_VERBOSITY` |
| `--logfile` | `PUPPET_CA_LOGFILE` |
| `--tls-cert` | `PUPPET_CA_TLS_CERT` |
| `--tls-key` | `PUPPET_CA_TLS_KEY` |
| `--tls-self-provision` | `PUPPET_CA_TLS_SELF_PROVISION` |
| `--tls-self-provision-names` | `PUPPET_CA_TLS_SELF_PROVISION_NAMES` |
| `--client-revocation-policy` | `PUPPET_CA_CLIENT_REVOCATION_POLICY` |
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
Kubernetes auth settings) is in [OpenBao Transit-engine CA key](openbao-transit.md#configuration).
Storage-backend environment variables are documented per backend in
[storage backends](storage-backends.md).

The CA key passphrase can also be provided via `PUPPET_CA_KEY_PASSPHRASE` (env var only, no CLI flag to avoid `/proc/cmdline` exposure).

**Config file / env var only, no CLI flag:**

| Config key | Environment variable |
| --- | --- |
| `crl_chain_file` | `PUPPET_CA_CRL_CHAIN_FILE` |
| `maintenance_interval_sec` | `PUPPET_CA_MAINTENANCE_INTERVAL_SEC` |
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
| `crl_sync_interval_sec` | `PUPPET_CA_CRL_SYNC_INTERVAL_SEC` |
| `crl_chain_file` | `PUPPET_CA_CRL_CHAIN_FILE` |
| `crl_chain_refresh_interval_sec` | `PUPPET_CA_CRL_CHAIN_REFRESH_INTERVAL_SEC` |
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

## Revocation across replicas

The CA answers "is this certificate revoked?" from a copy of the CRL it holds in
memory, not from storage — the check is on the hot path of every authenticated
request, and it also backs the OCSP responses this replica signs. The copy is
loaded at startup and rewritten whenever *that* process re-signs the CRL, which
on a single node is the whole story.

On the shared backends (`etcd`, `redis`, `postgres`, `mysql`) it is not: only
the replica that handled the revocation re-signs, so every other
replica would go on accepting the certificate until it happened to re-sign on
its own. `crl_sync_interval_sec` closes that. Each replica re-reads the stored
CRL on the interval and installs it if it has advanced, which makes the interval
the worst-case window in which a revoked certificate still works against a
replica that did not revoke it. The default is 60 seconds.

Two things the window does not cover, both worth knowing before you rely on it:

- **OCSP responses already handed out.** The responder signs each response with
  four hours of validity and clients cache it, so a verifier that asked before
  the revocation can keep treating the certificate as valid for that long. The
  sync drops this replica's own cached responses for newly revoked serials, but
  answers already in a client's or proxy's cache cannot be recalled. This
  applies only if you have enabled the responder with `--ocsp-url`.
- **Certificates issued to the agent before it was locked out.** Revoking one
  serial does not revoke another the same subject already holds. Renewal is not
  a way out — `POST /certificate_renewal` re-reads the CRL from storage rather
  than trusting the cached copy, so a revoked certificate is refused there even
  on a replica that has not synced — but if you are locking out a compromised
  node rather than retiring one certificate, check the inventory for other live
  serials for that subject and retire each one with
  `openvox-ca-ctl revoke --serial <hex>` — see
  [revocation by serial](api.md#revocation-by-serial). `openvox-ca-ctl clean` is
  not a substitute: it revokes the most recently issued serial for the subject
  and removes the stored certificate, leaving the subject's other serials valid.
- **A renewal that coincides with a storage read failure.** That re-read is
  best-effort: if it fails, the check falls back to the CRL already in memory
  rather than refusing every renewal in the fleet over a transient backend
  error. Such a renewal is bounded by the ordinary propagation window instead of
  by the read-through check. `puppetca_crl_sync_failures_total` is what tells
  you it happened.

The read is one small blob, takes no cluster lock, and writes nothing, so it
costs the same on every backend and needs no leader. Lengthening the interval
trades that cost against the window; there is no switch to turn it off, and
`disable_crl_refresh` does not — that setting governs whether this deployment
*re-signs* the CRL on a timer, which is a separate question from whether
revocations reach it.

`filesystem` and `sqlite` are single-node, so the sync has nothing to find and
the setting does not matter there.

To confirm propagation, compare `puppetca_crl_cached_number` (per replica)
against `puppetca_crl_number` (from storage) — see
[metrics](metrics.md#watching-revocation-propagate).

Restarting a replica also reloads its CRL. The sync installs only a CRL this CA
signed, picking out the newest such block wherever it sits in the stored chain —
the same selection the startup loader and the re-sign paths make. A stored chain
carrying nothing of ours leaves the replica on the CRL it already holds and
raises `puppetca_crl_sync_failures_total`; startup warns about the same
condition and the re-sign paths refuse it outright. See
[storage backends](storage-backends.md) for how that state is reached and
repaired.

## Publishing an upstream CRL chain

When openvox-ca runs as an intermediate, agents doing full-chain revocation
checking — Puppet's default `certificate_revocation = chain` — need the
ancestors' CRLs as well as this CA's own. `crl_chain_file` is how they get
there:

```yaml
crl_chain_file: /etc/puppet-ca/upstream-crls.pem
```

It is a PEM bundle of upstream CRLs, re-read by the `crl-chain-refresh`
background job (`crl_chain_refresh_interval_sec`, 1 hour by default) and on
every CRL amendment, and
published alongside this CA's own CRL at
`GET /puppet-ca/v1/certificate_revocation_list/ca`. The file is **declarative**:
whatever it contains is what gets published, so a CRL removed from it disappears
from the served chain. Refresh it by whatever mechanism you already have — a
mounted Secret, a sidecar, a CronJob — and openvox-ca picks the change up.
Getting the file there in the *first* place carries an ordering requirement,
which is what the next section is about.

### Order the writer before the server

**Whatever populates `crl_chain_file` must be ordered before the server starts,
not merely started alongside it.**

The refresh job runs a pass immediately rather than waiting out its first tick,
so a file already in place is picked up at startup. A file that is not there
*yet* is not an error — an absent file is no statement, as below — so the CA
starts, publishes its own CRL alone, and does not look again until
`crl_chain_refresh_interval_sec` elapses. For that whole interval every agent on
the default `certificate_revocation = chain` rejects the CRL it is served.

This is the ordinary shape of the deployment rather than an unusual one: where
the thing that writes the file starts concurrently with the server — a sidecar,
a config-management run, a job fetching a CDP — the server generally wins the
race, having nothing to fetch.

Nothing rescues that window:

- **No counter moves.** An absent file is not a failure, so
  `puppetca_crl_chain_refresh_failures_total` stays flat. The one signal is
  `puppetca_crl_chain_last_read_timestamp_seconds` reading `0`, which
  `PuppetCAUpstreamCRLNeverRead` alerts on — after the shipped mixin's
  `for: 15m`. At the default hourly interval that is a quarter of an hour of
  failing agents before anything fires; at a fifteen-minute interval the outage
  ends about when the alert would have. Neither arrives in time to be a warning.
- **The other trigger does not fire.** The file is re-read on every CRL
  amendment too, but amendments come from revoking or cleaning a certificate —
  operator activity, not something a fleet of agents failing verification
  produces. Nor does the scheduled re-sign of this CA's own CRL, which runs only
  as that CRL nears expiry, and a CA that has just started has just signed one.

So gate the server on the file rather than leaving it to the timer. In
Kubernetes that is a native sidecar: run whatever writes the file as an
`initContainer` with `restartPolicy: Always`, and give *that container* a
`startupProbe` which does not succeed until the file is non-empty. A native
sidecar's startup probe gates the containers after it, so the server cannot
start before the chain exists. Under systemd the equivalent is an ordering
dependency — `Before=` on the unit that writes the file, or an `ExecStartPre=`
that waits for it — rather than two units started together.

Probe for a **non-empty** file, not merely an existing one: a zero-byte file is
a deliberate statement here (see the table below), so a probe testing only for
existence passes on exactly the case that publishes no ancestors at all.

### What each failure to read the file does

Being declarative cuts both ways, so these distinctions matter more than they
look:

| The file is | What gets published | Why |
| --- | --- | --- |
| **absent** | the chain already published, unchanged | An absent file is *no statement*, not a statement that the chain should be empty. It has to be: this path runs on every CRL amendment, so a single revocation on a replica whose Secret has not mounted yet would otherwise truncate the chain for the whole fleet — permanently, because this CA cannot re-sign another CA's list. |
| **empty**, or nothing but whitespace | this CA's own CRL only | An empty file *is* a statement. This is how you say "publish nothing extra". It is also what a failed `cat >` leaves behind, so it is logged at `ERROR` — see the note on atomic writes below. |
| **unparseable** | the chain already published, unchanged | The refresh fails and is counted. Note this also blocks **revocation** until the file is fixed: refusing to publish half a chain is deliberate, but it does couple CRL amendment to a file refreshed outside openvox-ca. |
| **truncated, or not a CRL bundle** | the chain already published, unchanged | Refused, not read as an empty declaration. A file that does not end on a PEM block boundary, or that decodes to no CRL at all — a block cut mid-write, DER, a certificate bundle, an HTML error page — is a read that failed, not the operator asking for an empty chain. Only an empty file means that. Leading and interleaved commentary is fine; see below. |
| **carrying a CRL older than the one published** | the newer, already-published CRL for that ancestor; everything else from the file | Not a failure and **not** a block on revocation: the published chain is correct, so the older CRL is simply passed over and counted by `puppetca_crl_chain_regressed_total`. |
| **present but unreadable** (permissions, or a directory mounted at the path) | the chain already published, unchanged | The refresh fails and is counted, and revocation is blocked as for **unparseable**. A Secret projected `0400` root-owned against an unprivileged container is the usual cause. |
| **larger than 4 MiB** | the chain already published, unchanged | Refused rather than truncated: a half-read PEM blob would silently drop CRLs. A real chain is a handful of CRLs. |
| **holding more than 64 CRLs** | the chain already published, unchanged | Refused. The byte bound does not cover this: one ancestor with a long revocation list is legitimately large, while many small CRLs are what cost, since each one's signer is resolved by trial verification against the whole CA bundle while the CRL lock is held. A chain is one CRL per ancestor, so more than a couple of dozen means a directory concatenated by accident or a file appended to instead of replaced. |

> **The one revocation this does not block is auto-renewal's.** When an agent
> renews, the CA revokes the certificate it just replaced (`revoke_on_auto_renew`,
> on by default) on a best-effort basis: a failure there is logged
> (`AutoRenew: failed to revoke replaced certificate`) and the renewal is allowed
> to stand, with no retry. So a chain file that is unreadable at that moment does
> not block the renewal — it skips that one revocation permanently, and the
> superseded certificate stays valid until it expires. `puppetca_crl_update_failures_total`
> counts it, but nothing records which serial now needs revoking by hand. Grep
> for that message alongside a rising
> `puppetca_crl_chain_refresh_failures_total`, and revoke by subject afterwards
> if the window mattered.

**Write the file atomically** — write to a temporary path, then rename. A read
that catches a `cat >` mid-write sees a file that does not end on a PEM block
boundary, which is refused rather than acted on: revocations fail until the next
complete write lands, and that is deliberate. Treating a truncated read as "the
operator says publish nothing" would delete the ancestor CRLs permanently, since
this CA cannot re-sign them.

The file may carry non-PEM commentary — `openssl crl -text` output is a bundle
of exactly this shape, since its human-readable dump *precedes* each block and
everything before a `-----BEGIN` line is skipped. What is refused is trailing
text after the last block, because that is indistinguishable from a write cut
short. One truncation is inherently undetectable: a write severed exactly on a
block boundary yields a valid, shorter file, and since the file is authoritative
a missing ancestor is a legitimate thing for it to say. Writing atomically is
what closes that case; nothing in the file's content can.

Atomicity does not, however, cover an **empty** write. `cat upstream/*.pem >
bundle.pem` with an empty or unmounted source directory produces a zero-byte
file — and that is the deliberate way to say "publish nothing extra", so it is
honoured, and every ancestor CRL is dropped permanently. A file of nothing but
whitespace counts the same. There is no way to tell that apart from intent, so
it is logged at `ERROR` naming how many CRLs are being dropped. If you generate
the file from a script, have the script refuse to write an empty one.

In Kubernetes, mount the file from **its own volume, not with `subPath`**. A
`subPath`-mounted ConfigMap or Secret never receives updates, so the file reads
successfully forever and never changes — the feature becomes a silent no-op.
No metric distinguishes that from a healthy file:
`puppetca_crl_chain_last_read_timestamp_seconds` advances on every read either
way, because the read genuinely succeeds — it is the content that is frozen.
What catches it is the consequence — `PuppetCAUpstreamCRLExpiringSoon` firing on a CA that
*has* `crl_chain_file` configured is the `subPath` signature.
`puppetca_crl_chain_last_read_timestamp_seconds` does detect the different case
of a file never opened at all: it reads `0`, and `PuppetCAUpstreamCRLNeverRead`
alerts on it.

If one ancestor appears more than once — which is what a CronJob that appends
rather than replaces produces — only the newest of its CRLs is published, by CRL
number, or by `thisUpdate` for a CRL carrying no `cRLNumber` (`openssl ca
-gencrl` omits it unless `crl_extensions` is configured). Publishing both would
let a client that stops at the first match be handed the older list, un-revoking
a certificate. Ancestors are told apart by which certificate signed their CRL,
not by issuer name, so a shared root that issued two sub-CAs with the same
distinguished name still gets both their CRLs published.

**An ancestor that disappears from the file is dropped**, and counted by
`puppetca_crl_chain_removed_total`. The file is authoritative, so this is the
documented way to stop publishing an ancestor — but it is also what a `cat`
glob that matched one file fewer produces, and it cannot be undone here. The
same counter covers a second way an ancestor disappears: its certificate leaving
the CA bundle, so nothing signs its published CRL any more. That one is fixed by
re-importing the bundle rather than by touching the file. Every case is logged
at `ERROR` naming the issuer, and the message says which happened.

**An ancestor's CRL can never move backwards.** A CRL in the file that is older
than the one already published for the same ancestor is passed over and the
published one kept, counted by `puppetca_crl_chain_regressed_total`. Ancestors
are matched by which certificate signed their CRL, and ordered by CRL number, or
by `thisUpdate` where there is none.

There is one legitimate way to trip this: an ancestor CA rebuilt from backup that
resumes numbering from a low value while still signing with the same key. To
adopt it, drop that ancestor from the file for one publish cycle and then add the
new CRL back — with nothing published to compare against, it is accepted. (An
ancestor that *re-keys* needs nothing special: a different signing certificate is
a different ancestor to this comparison.) Publishing
it would un-revoke, fleet-wide, every certificate that ancestor revoked in
between, and there is no legitimate cause for it: a stale copy, a rolled-back
mirror, or a replay. Unlike a corrupt file this does *not* block revocation —
the published chain is already correct, so failing would let anyone who can
write the file deny revocation instead.

**Every CRL in the file is signature-verified** against a certificate in the
stored CA bundle before it is served, and discarded with a warning otherwise.
This content goes to every agent, so an unverified file would be a way to inject
arbitrary bytes into every agent's CRL store. Whether the check can succeed for
a given CRL depends on the stored bundle holding that issuer's certificate:
importing the *complete* chain, up to and including the root, is what makes the
root's own CRL publishable. `openvox-ca-ctl import` does not currently enforce
completeness — a partial chain is accepted, and the CRLs whose issuers are
missing from it are then discarded on every refresh. That is visible rather than
silent: `puppetca_crl_chain_discarded_total` counts it and the shipped mixin
alerts on it as `PuppetCAUpstreamCRLDiscarded`.

A CRL this CA issued is ignored if found in the file — its own is always rebuilt
from the inventory, and a stale copy must not be able to supersede live
revocations.

Refreshing the chain re-signs this CA's own CRL, so its number advances even
when no certificate was revoked. That is harmless (the number need only
increase) and is the price of having one write path rather than a second,
subtler one.

Per-issuer freshness is reported as
`puppetca_crl_chain_next_update_timestamp_seconds{issuer}`, deliberately
separate from `puppetca_crl_next_update_timestamp_seconds`, which continues to
mean *this CA's own* CRL. An expiring upstream CRL is fixed at the parent CA,
not here, so it gets its own alert with its own runbook — see the
[mixin](../mixin/). Four counters cover what would otherwise be one warning per
cycle in the log, and they are separate because their remedies are:
`puppetca_crl_chain_refresh_failures_total` for a file that could not be read or
parsed (fix the file or its mount); `puppetca_crl_chain_discarded_total` for a
CRL dropped because nothing in the bundle signed it (complete the CA bundle) —
the one case where the published chain silently *shrinks*;
`puppetca_crl_chain_regressed_total` for a CRL older than the one already
published (fix whatever refreshes the file); and
`puppetca_crl_chain_removed_total` for an ancestor that has disappeared from the
file altogether (restore it, or accept the removal) — or whose certificate has
left the CA bundle, so its published CRL can no longer be attributed to anyone
(re-import the bundle). A fifth series,
`puppetca_crl_chain_last_read_timestamp_seconds`, reads `0` where the file is
configured but has never been opened.

> **Rolling upgrades.** A replica running a build from before chain preservation
> re-signs the CRL as a single block and silently drops the chain, so one old
> replica handling one revocation undoes it for everyone. Make sure every
> replica is running a build with chain preservation *before* configuring
> `crl_chain_file`. Preservation is a no-op on a single-CRL deployment, so that
> ordering costs nothing.

## Trusting client certificates from another CA

By default openvox-ca authenticates exactly one set of clients: the ones it
issued. `client_ca` adds others.

This is for the topology where the servers and operators administering this CA
hold certificates from a *different* CA — typically a sibling intermediate under
a shared root, one issuing agent certificates and one issuing server
certificates. Without it, those administrators cannot authenticate at all.

**Nothing below applies unless `client_ca` is set.** With it absent there is one
trust domain, it is ours, and admin is `puppet_server` plus `pp_cli_auth`
exactly as it has always been.

```yaml
client_ca:
  - name: server-ca
    file: /etc/openvox-ca/server-ca.pem          # anchors for THIS entry only
    crl_file: /etc/openvox-ca/server-ca-crls.pem # CRLs for THIS entry only
    admin_cns:
      - openvox-server.example.com
    allow_pp_cli_auth: false
client_revocation_policy: require                # require | check | skip
```

### Anchor on the issuing CA, not the root

`file` should contain the **issuing** CA, not the root above it.

A trust anchor need not be self-signed. Anchoring on an intermediate accepts
what that intermediate issued and nothing else — so two sibling CAs under a
shared root stay separate, even when a client presents the shared root and the
sibling CA in its own chain. Putting the root there instead silently extends
this entry's authority, **including its `admin_cns`**, to every intermediate
that root has issued or ever will.

openvox-ca warns at startup when an entry's anchor is self-signed, naming the
entry and the certificate. It warns rather than refuses, because anchoring on a
root is legitimate when the root really is the intended boundary — but it is the
natural mistake, since "the CA bundle" usually means the whole chain.

### A name means something only within its issuer's namespace

Every CA has its own namespace of names it has signed, and a name means nothing
outside the one it was issued in. So:

| Grant | Our own CA | A `client_ca` entry |
| --- | --- | --- |
| Admin CNs | `puppet_server` / `puppet_server_file` — unchanged | that entry's `admin_cns` |
| `pp_cli_auth` | honoured unless `no_pp_cli_auth` — unchanged | honoured only if that entry sets `allow_pp_cli_auth: true` |

Both foreign grants default to off, so adding an entry authenticates an issuer
without granting it anything.

`allow_pp_cli_auth` **delegates admin admission to that CA**: every certificate
it chooses to stamp with the extension is an administrator here. For a Server CA
under the same operator's control that is correct, and is how the Puppet CA CLI
authenticates upstream. For a CA you do not control it is a full delegation.
Enabling it emits a startup warning naming the issuer.

Two operations remain **own-CA only** regardless of any entry, because they act
on this CA's own namespace: renewing a certificate (`POST /certificate_renewal`)
and the self-match on `GET /certificate_request/{subject}`. A foreign
certificate named `agent1.example.com` is not our `agent1.example.com`.

### Revocation

`client_revocation_policy` governs foreign issuers only; our own clients are
always checked against our own CRL.

| Policy | Behaviour |
| --- | --- |
| `require` (default) | A client whose issuer has no currently valid CRL is rejected |
| `check` | Verify against whatever CRLs are loaded; allow where an issuer has none |
| `skip` | No revocation checking for foreign issuers. **Unsafe** |

Checking covers the **whole verified chain**, not just the leaf: a sibling CA
revoked by the shared root must not go on authenticating its leaves.

Under the default `require` policy, **`crl_file` is mandatory** for every entry:
configuration validation rejects a block without one. Separately, and under
*every* policy, the server refuses to start if a `crl_file` that is set cannot
be read or holds a CRL that does not parse — so a stale path left behind on
`skip` stops the server rather than being ignored. That is
deliberate — the anchor bundle beside it already fails closed, and a server that
starts here would reject every client of the domain while its readiness probe
reported healthy.

Every CRL in `crl_file` is signature-verified against an anchor in the same
entry before it is used, and each is bound to the anchor whose key signed it.
The CRL's own Authority Key Identifier is not consulted at all. RFC 5280 §5.2.1
requires a conforming CRL issuer to include it, but not every issuer conforms,
and there is no reason to refuse a CRL whose signature verifies over a field
this CA does not use — so an issuer that omits it is fully supported. Without verification, a writable `crl_file` would be a way to
*clear* revocations, not merely add them.

A client certificate that is *itself* one of your anchors is rejected under
`require`: the chain is one element long, so there is nothing above it to attest
to its revocation status, and a trust anchor is trusted by configuration rather
than by anything it presents. If you meant that certificate to authenticate as a
client, issue it a leaf from the anchor instead.

> **Anchoring on a shared root and using `require` locks everyone out.** The
> walk needs a CRL for every issuer in the chain, **the anchor included** — what
> is never checked is the anchor as a *subject*, which is a different question.
> An intermediate's own CRL is signed by that intermediate — not by the root — so
> it fails the verification above and is discarded, leaving the
> `(leaf, intermediate)` pair with no CRL. Every client of the entry is then
> rejected.
>
> The server warns at startup when any anchor has no currently valid CRL, but it
> **cannot** warn about this case: the root is an anchor and its own CRL does
> verify and is kept, so the entry looks covered from the outside. Nor can
> `puppetca_client_crl_usable` see it — that gauge only reports whether the entry
> holds *anything* current, which it does. What reports it is
> `puppetca_client_crl_refusals_total`, which counts clients actually turned
> away for want of a CRL, because by then the missing issuer is a fact rather
> than a guess. Anchor on the issuing CA
> and the problem does not arise: the chain is then `[leaf, anchor]` and the only
> CRL `crl_file` needs is the one the anchor itself issued.
>
> The fix is to anchor on the issuing CA, which is what scopes the entry anyway.
> **Do not reach for `client_revocation_policy: check`**: it restores service by
> disabling leaf revocation checking for that domain entirely, and nothing
> afterwards says so.

An expired CRL is treated differently by the two policies, and deliberately.
A CRL carrying **no `nextUpdate` at all** is treated as expired, and for the
same reason. The field is `OPTIONAL` in the `TBSCertList` ASN.1, which is why
Go's parser leaves it zero, but RFC 5280 §5.1.2.5 requires a conforming CRL
issuer to include it and declines to specify what a client should do when it is
absent — so treating such a CRL as expired is a conforming choice, and the safe
one: reading its absence as "never expires" would satisfy `require` forever
from a snapshot that says nothing about revocations since. The fix is at the
issuing CA — give it a next-update interval — not here.

Under `require` an expired CRL counts as absent, so the policy does not quietly decay into
`skip`. Under `check` it is still consulted — it is loaded, and the serials it
names are still revoked — because `check` means "tolerate an issuer with no
CRLs", not "stop reading the ones you were given".

> **`crl_file` does not cover the CA named in the same block.** The trust anchor
> is never revocation-checked — it is trusted by configuration, not by anything
> it presents. Revoking a trusted domain is an operator action: remove or
> replace the `client_ca` entry. `crl_file` covers what that CA *issued*.

`crl_file` is re-read on every maintenance cycle. A reload that fails, or that
would cover fewer anchors than the set already in use, keeps the previous set
and logs — so an emptied or half-assembled file does not take revocation
checking down with it, and the file is not authoritative until it loads. **`file` is not**: anchors are
read once at startup, because a half-applied anchor reload locks out every
client of a domain, where a half-applied CRL reload costs at most a stale
revocation. To rotate an anchor, add the new one as a second `client_ca` entry,
roll the fleet, then remove the old entry and roll again.

`puppetca_client_crl_usable{client_ca}` reports whether a domain holds any
currently valid revocation material, and is published **only under `require`** —
`crl_file` is optional under `check` and `skip`, so a domain without CRLs is
correct there and a 0 would alert on a healthy server. It does not report
partial coverage; `puppetca_client_crl_refusals_total{client_ca}` counts clients
actually refused for want of a CRL, and
`puppetca_client_crl_last_reload_timestamp_seconds{client_ca}` goes stale when
`crl_file` has stopped being applied. **Alert on all three**: under `require` a `0` rejects every client
of that issuer, and the first symptom is otherwise an agent-side 403.

> Not to be confused with a CRL this CA *publishes*: those carry its own and its
> ancestors' revocations and are served to agents. `client_ca[].crl_file` is
> inbound, used only by the
> authorisation middleware, and never served.

## Autosigning

The `--autosign-config` flag controls automatic CSR signing:

| Value | Behaviour |
| --- | --- |
| `false` / `""` | Manual signing only (default) |
| `true` | Sign every incoming CSR immediately |
| `/path/to/file` (not executable) | Glob-pattern allowlist (one pattern per line, `#` comments ignored) |
| `/path/to/script` (executable) | Custom plugin: called with `argv[1]=CN`, CSR PEM on stdin; exit 0 = sign, non-zero = hold |

Allowlist example:

```text
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

## Directory layout (filesystem backend)

```text
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

> **Note:** Serial numbers are cryptographically random (128-bit). The `serial`
> file used by older Puppet CAs for sequential serial tracking is no longer
> written or read by this server.

The full on-disk layout, including the inventory HMAC files, is documented in
[storage backends](storage-backends.md#filesystem-backend-default). Other backends
store the same logical state elsewhere.

### File permissions

| Content | Mode |
| --- | --- |
| Directories | `0750` |
| Private keys | `0600` |
| CRL file | `0600` |
| Public data (certs, CSRs, inventory) | `0644` |

The user running `openvox-ca` must own (or have write access to) `--cadir`.

## Graceful shutdown

On `SIGTERM` or `SIGINT`, the frontend HTTP server calls `http.Server.Shutdown()` with a drain context (wired via `signal.NotifyContext`) so in-flight requests (signing, CRL, OCSP) drain cleanly before the process exits. The request context is cancelled on signal, and the command returns normally rather than calling `os.Exit` on its error paths, so deferred storage and signer cleanup always runs after all connections are done.

The drain budget defaults to **25 seconds** and is configurable via `shutdown_timeout_sec` (config file) or `PUPPET_CA_SHUTDOWN_TIMEOUT_SEC` (environment); a non-positive value falls back to the default.

In the default isolated-process deployment, the supervisor gives its child processes the drain budget **plus a 3-second headroom** (28 seconds by default) before force-killing anything that has not exited, so the drain is never truncated.

This is particularly important for **Kubernetes rolling updates**: pods receive `SIGTERM` with a configurable grace period (`terminationGracePeriodSeconds`, default 30 seconds). The defaults (25s drain, 28s supervisor) nest under that 30-second grace so the server drains and exits cleanly before the platform `SIGKILL`s the pod. If you raise `shutdown_timeout_sec`, raise `terminationGracePeriodSeconds` to at least the drain budget plus 3 seconds. Under systemd, raise `TimeoutStopSec` instead — see [running under systemd](systemd.md).

## Reloading configuration

`SIGHUP` re-reads the two file-backed inputs that can be swapped safely while the server is running:

| Input | Effect |
| --- | --- |
| `--tls-cert` / `--tls-key` | The renewed keypair is served to new TLS handshakes; connections in flight keep the certificate they negotiated with |
| `--puppet-server-file` | The admin allow list is rebuilt from the current file contents, merged with the `--puppet-server` value the process started with, and swapped atomically with respect to in-flight requests |

`--puppet-server` (config key `puppet_server`) itself is frozen at startup: a CN removed from it stays an admin until the server restarts. Reload only re-reads the *file*.

Withdrawing admin access has a second caveat: a certificate carrying the `pp_cli_auth` extension is an admin regardless of the allow list (see [admin credential resolution](api.md#admin-credential-resolution)). Revoke that certificate, or run with `--no-pp-cli-auth`, if the reload is meant to decommission a host.

Everything else — the listen address, the storage backend, CA key custody, CA properties, and which autosign configuration is in use — requires a restart.

Two file-backed inputs are consulted live, with no signal needed at all: the autosign allowlist or executable is read on every CSR, and the OpenBao AppRole `role_id`/`secret_id` files are read on every login (see [OpenBao Transit-engine CA key](openbao-transit.md)). Editing those takes effect on the next request; only the settings naming them are fixed at startup.

A reload that fails (an unreadable keypair, a missing allow-list file) is logged and leaves the previous configuration in place; the server keeps serving. Each input is applied independently, so a broken allow list does not block a certificate rotation.

In the default isolated-process deployment, send `SIGHUP` to the supervisor (the process you started); it forwards the signal to the frontend. Under systemd this is `systemctl reload openvox-ca` — see [running under systemd](systemd.md#reloading).

Under `--daemon` the process you started has already forked and exited, so there is nothing left to signal by job control; find the supervisor with `pgrep -f openvox-ca` (the parent of the two child processes) and send `SIGHUP` to that. Running in the foreground under a service manager avoids the question entirely.
