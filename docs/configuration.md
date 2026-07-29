# Configuring the server

This is the full configuration reference for the `openvox-ca` server. For the
operator CLI, see [operator CLI (`openvox-ca-ctl`)](operator-cli.md).

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
| `--tls-self-provision` | `false` | Let the CA issue and renew its own serving certificate (enables HTTPS). Requires `--hostname`; cannot be combined with `--tls-cert`/`--tls-key`. See [self-provisioned serving certificate](#self-provisioned-serving-certificate) |
| `--tls-self-provision-names` | `""` | Extra DNS names for that certificate, beyond `--hostname` |
| `--puppet-server` | `""` | Comma-separated CNs granted admin API access (mTLS only) |
| `--puppet-server-file` | `""` | Path to a file of CNs granted admin API access (one per line; `#` comments and blank lines ignored) |
| `--no-pp-cli-auth` | `false` | Disable `pp_cli_auth` extension as an admin credential; require CN allow list only |
| `--no-tls-required` | `false` | Allow plain HTTP on non-loopback addresses; use only behind a trusted TLS proxy or in test environments |
| `--allow-public-status` | `false` | Allow unauthenticated `GET /certificate_status`; by default this endpoint is admin-only, matching Puppet Server's shipped `auth.conf` |
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
| `--daemon` | `false` | Fork to background (not recommended in containers) |
| `--logfile` | `""` | Write JSON logs to this file instead of stderr |
| `--verbosity` / `-v` | `0` | Verbosity: `0`=Info, `1`=Debug, `2`=Trace |

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
tls_key:  /etc/puppetlabs/puppet/ssl/ca/ca_key.pem
# ... or let the CA issue its own serving certificate instead of the two above.
tls_self_provision: false
tls_self_provision_names: []          # extra DNS SANs beyond hostname
tls_self_provision_renew_before_sec: 0   # 0 = one third of the leaf validity
tls_self_provision_encrypt_key: false    # requires an explicit passphrase source
tls_self_provision_revoke_after_sec: -1   # -1/unset = built-in default (24h); 0 = never revoke
maintenance_interval_sec: 0           # shared maintenance loop; 0 = built-in default (1h)
                                      # raising this needs a matching mixin change; see mixin/README.md
puppet_server: puppet.example.com
puppet_server_file: ""
no_pp_cli_auth: false
no_tls_required: false
allow_public_status: false  # set true to allow unauthenticated GET /certificate_status
                            # (otherwise admin-only: an admin CN of the matched
                            # trust domain, or pp_cli_auth where that domain
                            # honours it)
client_ca: []               # additional client issuers; see "Client trust domains"
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
# A PEM bundle of upstream CRLs published alongside this CA's own, for agents
# doing full-chain revocation checking. Verified against the stored CA bundle.
crl_chain_file: ""
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
| `client_revocation_policy` | `PUPPET_CA_CLIENT_REVOCATION_POLICY` |
| `tls_self_provision_renew_before_sec` | `PUPPET_CA_TLS_SELF_PROVISION_RENEW_BEFORE_SEC` |
| `tls_self_provision_encrypt_key` | `PUPPET_CA_TLS_SELF_PROVISION_ENCRYPT_KEY` |
| `tls_self_provision_revoke_after_sec` | `PUPPET_CA_TLS_SELF_PROVISION_REVOKE_AFTER_SEC` |
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

## Self-provisioned serving certificate

By default `openvox-ca` serves TLS from `tls_cert` and `tls_key` on disk. With
`tls_self_provision: true` it instead issues that certificate to itself, from
its own CA key, and renews it in the background.

This exists for deployments where nothing else can issue it. With the CA key
held at a provider (`ca_key_provider: openbao`) cert-manager cannot act as a CA
issuer, and `openvox-ca-ctl generate` needs an admin client certificate — which
needs a running server, which needs a serving certificate.

```yaml
hostname: openvox-ca.example.com     # required: the CN and first SAN
tls_self_provision: true
tls_self_provision_names:
  - openvox-ca.puppet.svc.cluster.local
  - puppet.example.com
```

`tls_self_provision` and `tls_cert`/`tls_key` are mutually exclusive, and
`hostname` is required. The CA layer rejects an empty serving subject too, but
its error names neither `hostname` nor `tls_self_provision`, so the check is
here for the message rather than for the behaviour.

The certificate and its private key live in the storage backend
(`serving_cert`, `serving_key`), not in `cadir`, so every replica serves the
same certificate and it survives a restart with an ephemeral `cadir`. It is
issued **serverAuth only**, so it is never usable as a client credential.

Otherwise it is an ordinary node certificate issued for the CA's own hostname:
it occupies that subject's certificate slot and inventory row, and it renews and
revokes through exactly the same machinery as any node's. That uniformity is
deliberate — there is nothing about it to special-case — and it is why the CA's
`hostname` **must be a name of its own**. If a node holds the same certname,
both certificates land in one per-subject slot and whichever was issued last
wins: issuing one overwrites the other's stored certificate, and revoking the
CA's hostname to rotate a compromised serving key can revoke the node's
credential instead, leaving the compromised key serving. (Renewal is separately
guarded — the CA refuses to revoke the certificate its own listener is
presenting — but that is a backstop, not a licence to share the name.) `openvox-ca` refuses to start when `hostname` is also
a `puppet_server` CN, but it cannot detect an ordinary agent that happens to
share the name — choose a distinct one.

### Renewal

A background maintenance loop re-checks the certificate every
`maintenance_interval_sec` (default one hour) and reissues once remaining
validity falls below `tls_self_provision_renew_before_sec` — by default a third
of the leaf validity. Zero *or negative* takes that default (unlike
`tls_self_provision_revoke_after_sec`, where `-1` and `0` mean different
things), and a value at or beyond the leaf validity is refused at startup. The
window is also clamped: a certificate's effective lifetime shrinks as the CA
certificate ages, since no leaf outlives its issuer, so a window that was
comfortably inside the configured validity can grow to exceed the real one. When
it reaches or passes that, the CA renews at half-life instead of reissuing on
every pass. Below that it is used exactly as configured — so a window close to
the effective lifetime still means renewing very soon after each issuance. Rotation takes effect on the next TLS handshake; no
restart, and established connections are unaffected.

A certificate is also reissued when it stops being usable for any other reason:
it no longer covers a configured name, it does not verify against the current CA
certificate, or it has been revoked.

**Adding a name reissues; withdrawing one does not.** Every replica evaluates
one shared certificate against its own configuration, which it read at startup,
so the check has to be one-directional or a fleet part-way through a config
change would mint over itself indefinitely. A name added to
`tls_self_provision_names` is picked up on the next maintenance pass; a name
removed stays on the live certificate until it is reissued for some other
reason. To apply a withdrawal immediately, revoke the serving certificate — the
next pass then mints from the configured names alone:

```bash
openvox-ca-ctl revoke --certname openvox-ca.example.com
```

> **This costs an outage.** Revoking the CA's own hostname takes the certificate
> the listener is presenting out of circulation immediately, with none of the
> delay `tls_self_provision_revoke_after_sec` exists to give. Every client that
> checks revocation fails its handshake against the CA until the next
> maintenance pass mints the replacement — up to one `maintenance_interval_sec`,
> an hour at the defaults.
>
> Rolling the fleet immediately after the revoke shortens that gap, because
> startup resolves the certificate too, so each replica mints as it comes back
> instead of waiting for its next tick. It is not an alternative to revoking: a
> restart alone reissues nothing, since a certificate that still parses,
> verifies and covers the configured names is reused.
>
> The same cost applies under *Replacing a compromised serving key* below. It
> does not apply under *Turning it off*, where the switch-over happens first.

A *rename* — adding one name and removing another in the same edit — briefly
carries both while the fleet disagrees, and settles on the union until every
replica has the new configuration and the certificate is revoked once.

Renewal failures are logged and counted as
`puppetca_serving_cert_renewal_failures_total`, leaving the existing certificate
in place. **Alert on that counter** — a persistently failing renewal is
otherwise invisible until the certificate expires.
`puppetca_serving_cert_issued_total` counts issuance; a sustained rate rather
than an occasional increment means replicas disagree about which CA certificate
is current, which a fleet restart resolves.

### Replacing a compromised serving key

Revoke the CA's own hostname:

```bash
openvox-ca-ctl revoke --certname openvox-ca.example.com
```

Revocation is one of the reuse conditions, so the next maintenance pass issues a
replacement. The exposure is one maintenance interval — and so is the outage:
see the warning under [Renewal](#renewal). Roll the fleet straight after the
revoke to shorten it.

### Superseded certificates

When a certificate is replaced the old one stays valid until it expires, which
leaves a second usable credential in circulation.
`tls_self_provision_revoke_after_sec` revokes it after a delay. It has three
states, matching `csr_rate_limit`: unset (`-1`) takes the built-in default of
**24 hours**, `0` never revokes, and a positive value is used as given.

The default is 24 hours rather than "never" because a second valid serving
credential in circulation is the worse outcome, and it matches this project's
existing posture — `revoke_on_auto_renew` is already `true` so that only the
newest serial for a subject stays valid.

The delay is not optional padding. The certificate swap is per-process, so a
sibling replica may still be serving the old certificate; revoking immediately
breaks every client that checks revocation. A replica picks up the replacement
within one maintenance interval, so the value must be at least **twice**
`maintenance_interval_sec` — two hours at the defaults — and the server refuses
to start otherwise.

Only a value you set explicitly is checked against that floor. Left unset, the
delay is the built-in 24 hours *or* the floor, whichever is longer — so raising
`maintenance_interval_sec` past 12 hours lengthens the default rather than
refusing to start over a value you never chose. A delay you did configure is
never silently lengthened, because that would misrepresent how long a
superseded credential stays valid.

That bound assumes maintenance passes succeed. A replica whose passes keep
failing will go on serving a superseded certificate while a healthy replica's
clock runs down and revokes it, which is the other reason to alert on
`puppetca_serving_cert_renewal_failures_total`.

### Turning it off

Clearing `tls_self_provision` stops the CA renewing the certificate, but it does
**not** remove what is already there: `serving_cert` and `serving_key` stay in
the backend, and the key is plaintext unless
`tls_self_provision_encrypt_key` was set. That is a valid CA-signed credential
for the CA's own hostname, so when migrating to an externally supplied
certificate:

1. Switch to `tls_cert`/`tls_key` and restart.
2. *Then* revoke it — `openvox-ca-ctl revoke --certname <hostname>` — so the
   credential is dead even though the blobs remain.

Step 2 assumes the replacement certificate was **not** issued by this CA under
the same name. `revoke --certname` resolves to the newest serial for that
subject, so if you replaced the self-provisioned certificate with one this CA
issued for the same hostname, it would revoke the replacement and leave the
self-provisioned one valid — both the outage and the retained credential. There
is no by-serial revoke ([#177](https://github.com/voxpupuli/openvox-ca/issues/177)),
so take the replacement from a different issuer, or give it a different name.

The order matters. While `tls_self_provision` is still on, revocation is a
*reuse* condition, not a retirement: the next maintenance pass sees the
revocation and mints a replacement. Revoking first would leave you with a fresh,
valid, unrevoked serving certificate — exactly the credential this section
exists to retire.

There is no command to delete the stored blobs; remove them with your backend's
own tooling if you want them gone.

Related: rotating `ca_key_passphrase_file` across a rolling update leaves
replicas briefly unable to decrypt each other's stored key, so each reissues its
own until every replica is on the new passphrase. That churn is harmless — the
reuse predicate treats an undecryptable key as "mint again" rather than failing
— but it does mean a burst of issuance and superseded entries.

### Encryption at rest

`tls_self_provision_encrypt_key: true` encrypts the stored serving key the same
way `encrypt_ca_key` does for the CA key, and **requires** an explicit
passphrase (`ca_key_passphrase_file` or `PUPPET_CA_KEY_PASSPHRASE`). The
auto-generated passphrase is written into `cadir`, so with an ephemeral `cadir`
each replica would encrypt under a different one and none could read the shared
key after a restart.

With encryption off and a SQL backend, the serving private key is stored in your
database in plaintext.

If your CA key is already a backend blob — the default — that is the posture
`ca_key` has by default and this is one blob over. **If you hold the CA key at a
provider (`ca_key_provider: openbao`), behind an external signer, or pinned with
`ca_key_file`, your backend holds no private key today and this changes that.**
`ca_key_file` pins only the CA key; there is no serving-key equivalent, so
`tls_self_provision_encrypt_key` is the protection available — and it applies to
the next key issued, not the one already stored, so enabling it on an existing
deployment leaves the plaintext key in the backend until the certificate is
reissued. See
[CA key security](ca-key-security.md).

### Sharing a backend between replicas

The mint is serialised on a fixed serving lock plus the per-subject lock, both
real distributed locks on etcd, Redis/Valkey, PostgreSQL and MySQL. The fixed
one is what makes replicas exclude each other even when they disagree about the
hostname, and so about which subject lock to take. On the **filesystem and SQLite**
backends it degrades to a process-local mutex, so two replicas can mint
concurrently and the last writer wins; the loser serves a certificate no longer
in storage until its next pass. Those backends are already documented as
unsuitable for sharing between replicas, and the remedy is the same: use a
shared backend.

## Publishing an upstream CRL chain

When openvox-ca runs as an intermediate, agents doing full-chain revocation
checking — Puppet's default `certificate_revocation = chain` — need the
ancestors' CRLs as well as this CA's own. `crl_chain_file` is how they get
there:

```yaml
crl_chain_file: /etc/puppet-ca/upstream-crls.pem
```

It is a PEM bundle of upstream CRLs, re-read on every maintenance cycle
(`maintenance_interval_sec`, 1 hour by default) and on every CRL amendment, and
published alongside this CA's own CRL at
`GET /puppet-ca/v1/certificate_revocation_list/ca`. The file is **declarative**:
whatever it contains is what gets published, so a CRL removed from it disappears
from the served chain. Refresh it by whatever mechanism you already have — a
mounted Secret, a sidecar, a CronJob — and openvox-ca picks the change up.

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
way, and an earlier version of this page wrongly claimed otherwise. What catches
it is the consequence — `PuppetCAUpstreamCRLExpiringSoon` firing on a CA that
*has* `crl_chain_file` configured is the `subPath` signature. That series does
detect the different case of a file never opened at all: it reads `0`, and
`PuppetCAUpstreamCRLNeverRead` alerts on it.

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
glob that matched one file fewer produces, and it cannot be undone here. Both
cases are logged at `ERROR` naming the issuer.

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
[mixin](../mixin/). Three counters cover what would otherwise be one warning per
cycle in the log, and they are separate because their remedies are:
`puppetca_crl_chain_refresh_failures_total` for a file that could not be read or
parsed (fix the file or its mount); `puppetca_crl_chain_discarded_total` for a
CRL dropped because nothing in the bundle signed it (complete the CA bundle) —
the one case where the published chain silently *shrinks*; and
`puppetca_crl_chain_regressed_total` for a CRL older than the one already
published (fix whatever refreshes the file). A fourth series,
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
configuration validation rejects a block without one, and the server refuses to
start if the file cannot be read or holds a CRL that does not parse. That is
deliberate — the anchor bundle beside it already fails closed, and a server that
starts here would reject every client of the domain while its readiness probe
reported healthy.

Every CRL in `crl_file` is signature-verified against an anchor in the same
entry before it is used, and one carrying no Authority Key Identifier is
discarded. Without verification, a writable `crl_file` would be a way to
*clear* revocations, not merely add them.

> **Anchoring on a shared root and using `require` locks everyone out.** The
> walk needs a CRL for every issuer in the chain except the anchor, and an
> intermediate's own CRL is signed by that intermediate — not by the root — so
> it fails the verification above and is discarded. Every client of the entry is
> then rejected. The server warns about this at startup.
>
> The fix is to anchor on the issuing CA, which is what scopes the entry anyway.
> **Do not reach for `client_revocation_policy: check`**: it restores service by
> disabling leaf revocation checking for that domain entirely, and nothing
> afterwards says so.

An expired CRL is treated differently by the two policies, and deliberately.
Under `require` it counts as absent, so the policy does not quietly decay into
`skip`. Under `check` it is still consulted — it is loaded, and the serials it
names are still revoked — because `check` means "tolerate an issuer with no
CRLs", not "stop reading the ones you were given".

> **`crl_file` does not cover the CA named in the same block.** The trust anchor
> is never revocation-checked — it is trusted by configuration, not by anything
> it presents. Revoking a trusted domain is an operator action: remove or
> replace the `client_ca` entry. `crl_file` covers what that CA *issued*.

`crl_file` is re-read on every maintenance cycle. **`file` is not**: anchors are
read once at startup, because a half-applied anchor reload locks out every
client of a domain, where a half-applied CRL reload costs at most a stale
revocation. To rotate an anchor, add the new one as a second `client_ca` entry,
roll the fleet, then remove the old entry and roll again.

`puppetca_client_crl_usable{client_ca}` reports whether a domain has usable
revocation material. **Alert on it**: under `require` a `0` rejects every client
of that issuer, and the first symptom is otherwise an agent-side 403.

> Not to be confused with [`crl_chain_file`](#publishing-an-upstream-crl-chain),
> which points the other way: that carries this CA's own *ancestors'* CRLs and is
> published to agents. `client_ca[].crl_file` is inbound, used only by the
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

This is particularly important for **Kubernetes rolling updates**: pods receive `SIGTERM` with a configurable grace period (`terminationGracePeriodSeconds`, default 30 seconds). The defaults (25s drain, 28s supervisor) nest under that 30-second grace so the server drains and exits cleanly before the platform `SIGKILL`s the pod. If you raise `shutdown_timeout_sec`, raise `terminationGracePeriodSeconds` to at least the drain budget plus 3 seconds.
