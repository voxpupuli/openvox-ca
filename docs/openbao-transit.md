# OpenBao Transit-engine CA key

By default `openvox-ca` holds the CA private key itself: as a local PEM file
(optionally encrypted at rest, see the [main README](../README.md#ca-key-encryption-at-rest)),
or — in the isolated-signer deployment — inside a separate `openvox-ca
[signer]` child process reachable only over an authenticated Unix socketpair.

Setting `--ca-key-provider openbao` changes where the key itself lives: it
never exists inside any `openvox-ca` process at all. Instead it lives in an
[OpenBao](https://openbao.org/) **Transit secrets engine**, and `openvox-ca`
only ever sends OpenBao a digest to sign, getting a signature back. This is
the same `crypto.Signer` seam the isolated-signer feature already uses (and
the seam the README's PKCS#11/HSM plans target); OpenBao is simply the first
concrete backend for it.

Every other storage backend — filesystem, etcd, redis/valkey, sqlite,
postgres, mysql — keeps working exactly as documented in
[storage backends](storage-backends.md). OpenBao only ever supplants **key
custody**: the CA certificate, CSRs, issued certificates, the CRL, and the
inventory are still read and written through whichever storage backend you
have configured. Set `openbao.key_name` and the rest of the `openbao.*`
settings below alongside your existing `storage_backend` config; nothing
about it needs to change.

## Vault compatibility

This integration is built against and tested with **OpenBao** specifically,
against current OpenBao releases. It should also work against **HashiCorp
Vault** — OpenBao is a fork of Vault and remains wire-compatible with its
Transit engine, AppRole/Kubernetes auth methods, and Go client API — but
Vault is not part of the test matrix, so this has not been actively
verified. Compatibility bug reports (and fixes) for Vault are welcome.

## Provisioning the Transit key

**Recommended:** create (or import) the Transit key directly in OpenBao, out
of band, before pointing `openvox-ca` at it, and scope a dedicated policy to
just that key rather than granting broader Transit access.

### Create the key

```bash
bao secrets enable transit   # if not already enabled
bao write -f transit/keys/openvox-ca \
  type=rsa-4096 \
  exportable=false \
  allow_plaintext_backup=false
```

`exportable` and `allow_plaintext_backup` already default to `false`; setting
them explicitly is a reminder that the whole point of this integration is
that the key never leaves OpenBao — don't turn either of these on.

To bring existing CA key material into OpenBao instead of generating a fresh
key, see `bao write transit/keys/<name>/import` (BYOK) in OpenBao's own
documentation — that's an OpenBao-side operation, not an openvox-ca one.

### Create a policy scoped to that key

```bash
bao policy write openvox-ca - <<'EOF'
path "transit/sign/openvox-ca" {
  capabilities = ["update"]
}

path "transit/keys/openvox-ca" {
  capabilities = ["read"]
}
EOF
```

This is the minimum `openvox-ca` needs at steady state: sign with the key,
and read its public component. It deliberately excludes `create`, so this
policy alone cannot be used to provision the key — see "Convenience" below
if you want that instead.

### Bind the policy to a Kubernetes role

This assumes the `kubernetes` auth method is already enabled and configured
with your cluster's API address and CA certificate; that part is generic
OpenBao/Kubernetes setup, not specific to this integration, so see OpenBao's
own Kubernetes auth documentation for it.

```bash
bao write auth/kubernetes/role/openvox-ca \
  bound_service_account_names=openvox-ca \
  bound_service_account_namespaces=openvox-ca \
  token_policies=openvox-ca \
  token_ttl=1h \
  token_max_ttl=4h
```

Change `bound_service_account_names` and `bound_service_account_namespaces`
to match the ServiceAccount name and namespace `openvox-ca` actually runs as.

### Bind the policy to an AppRole role

This assumes the `approle` auth method is already enabled; see OpenBao's own
AppRole documentation for that part.

```bash
bao write auth/approle/role/openvox-ca \
  token_policies=openvox-ca \
  token_ttl=1h \
  token_max_ttl=4h

bao read auth/approle/role/openvox-ca/role-id
bao write -f auth/approle/role/openvox-ca/secret-id
```

Set `secret_id_ttl` and `secret_id_num_uses` on the role to match your own
secret_id rotation practice; there's no single default that's right for
every environment, so they're left unset (unlimited) above rather than
copied blindly.

Then configure `openvox-ca` with `openbao.key_name: openvox-ca` (and the
matching `ca_key_algo`/`ca_key_size` if you want `openvox-ca-ctl setup`'s
offline bootstrap to describe the same algorithm — the key's actual type is
whatever you created in OpenBao). This keeps the running server's OpenBao
policy scoped to `sign` and `read` on that one key — it never needs
`create`/`import` rights.

**Convenience:** if the named key does not exist yet, `openvox-ca` creates
it itself on first boot (mirroring today's local-key bootstrap behaviour),
using `ca_key_algo`/`ca_key_size` to pick the Transit key type. This requires
the server's OpenBao policy to also grant key creation — a stronger
permission than steady-state signing ever needs again afterwards, so the
manual route above is preferred for production.

## Configuration

Every OpenBao-specific setting lives under a top-level `openbao:` YAML key
(flags and environment variables use an `--openbao-*` / `PUPPET_CA_OPENBAO_*`
prefix instead, since there's no flat-file nesting for those).

| Config key | Environment variable | CLI flag | Description |
|---|---|---|---|
| `ca_key_provider` | `PUPPET_CA_CA_KEY_PROVIDER` | `--ca-key-provider` | `file` (default) or `openbao` |
| `openbao.addr` | `PUPPET_CA_OPENBAO_ADDR` | `--openbao-addr` | OpenBao server address as a full URI, including scheme and port, e.g. `https://openbao.example.com:8200`. `http://` is also accepted (e.g. for a plain-HTTP listener in development) |
| `openbao.transit_mount` | `PUPPET_CA_OPENBAO_TRANSIT_MOUNT` | `--openbao-transit-mount` | Transit engine mount path (default `transit`) |
| `openbao.key_name` | `PUPPET_CA_OPENBAO_KEY_NAME` | `--openbao-key-name` | Name of the Transit key backing the CA's private key |
| `openbao.tls_ca_file` | `PUPPET_CA_OPENBAO_TLS_CA_FILE` | `--openbao-tls-ca-file` | PEM CA bundle to verify OpenBao's server certificate |
| `openbao.tls_cert_file` | `PUPPET_CA_OPENBAO_TLS_CERT_FILE` | `--openbao-tls-cert-file` | Client certificate PEM for mTLS to OpenBao |
| `openbao.tls_key_file` | `PUPPET_CA_OPENBAO_TLS_KEY_FILE` | `--openbao-tls-key-file` | Client private key PEM for mTLS to OpenBao |
| `openbao.auth_method` | `PUPPET_CA_OPENBAO_AUTH_METHOD` | `--openbao-auth-method` | `approle`, `token`, or `kubernetes` |

### AppRole auth (VM / systemd deployments)

| Config key | Environment variable | CLI flag | Description |
|---|---|---|---|
| `openbao.approle_mount` | `PUPPET_CA_OPENBAO_APPROLE_MOUNT` | `--openbao-approle-mount` | AppRole mount path (default `approle`) |
| `openbao.approle_role_id` | `PUPPET_CA_OPENBAO_APPROLE_ROLE_ID` | `--openbao-approle-role-id` | AppRole `role_id` |
| `openbao.approle_role_id_file` | `PUPPET_CA_OPENBAO_APPROLE_ROLE_ID_FILE` | `--openbao-approle-role-id-file` | Path to a file containing `role_id`, read fresh on every login |
| `openbao.approle_secret_id_file` | `PUPPET_CA_OPENBAO_APPROLE_SECRET_ID_FILE` | `--openbao-approle-secret-id-file` | Path to a file containing `secret_id`, read fresh on every login |

```yaml
ca_key_provider: openbao
openbao:
  addr: https://openbao.example.com:8200
  key_name: openvox-ca
  auth_method: approle
  approle_role_id: 11111111-2222-3333-4444-555555555555
  approle_secret_id_file: /etc/puppet-ca/openbao-secret-id
```

### Static token file (VM / systemd deployments)

| Config key | Environment variable | CLI flag | Description |
|---|---|---|---|
| `openbao.token_file` | `PUPPET_CA_OPENBAO_TOKEN_FILE` | `--openbao-token-file` | Path to a file containing a pre-issued OpenBao token |

Simplest to set up, at the cost of needing something else to keep that
token's underlying credential rotated/renewed at the source (a periodic
`bao token create` against a role, a secrets-management pipeline, etc.).
`openvox-ca` itself still renews the token's lease proactively and re-reads
the file if it ever needs to fully re-authenticate — see
[token lifecycle](#token-lifecycle) below — but it cannot mint a *new*
underlying credential out of thin air if the one in the file is permanently
revoked.

### Kubernetes auth (native, no sidecar)

| Config key | Environment variable | CLI flag | Description |
|---|---|---|---|
| `openbao.kubernetes_mount` | `PUPPET_CA_OPENBAO_KUBERNETES_MOUNT` | `--openbao-kubernetes-mount` | Kubernetes auth mount path (default `kubernetes`) |
| `openbao.kubernetes_role` | `PUPPET_CA_OPENBAO_KUBERNETES_ROLE` | `--openbao-kubernetes-role` | OpenBao Kubernetes auth role name |
| `openbao.kubernetes_jwt_file` | `PUPPET_CA_OPENBAO_KUBERNETES_JWT_FILE` | `--openbao-kubernetes-jwt-file` | Path to the projected ServiceAccount token (default: the standard in-cluster path) |

```yaml
ca_key_provider: openbao
openbao:
  addr: https://openbao.default.svc:8200
  key_name: openvox-ca
  auth_method: kubernetes
  kubernetes_role: openvox-ca
```

No Vault/OpenBao Agent sidecar, injector, or init container is required — the
pod only needs its own ServiceAccount bound to an OpenBao Kubernetes auth
role; `openvox-ca` logs in and maintains its own token for as long as the
process runs.

## Token lifecycle

`openvox-ca` proactively renews its OpenBao token before it expires, and
re-authenticates from source credentials — re-reading the AppRole
`secret_id` file, the token file, or the projected ServiceAccount JWT —
whenever renewal itself fails (the token hit its `max_ttl`, was revoked
out-of-band, or OpenBao restarted and lost the lease). A Transit `sign`
request that hits a `403` triggers the same re-authentication immediately,
rather than waiting for the background renewal check, so a revoked token is
recovered from within a single retried request.

The projected ServiceAccount JWT is read from disk on every login attempt
rather than cached across the process lifetime: Kubernetes bound
ServiceAccount tokens are short-lived (default 1 hour) and kubelet rewrites
the token file in place before it expires, so each re-authentication picks
up the current token.

## Key rotation detection

The CA certificate's public key and the Transit key's public key have to
match — if they diverge, certificates signed going forward will not verify
against the CA certificate clients already trust. `openvox-ca` checks for
this in two places:

- **At startup**, when the CA certificate and the Transit key are both
  loaded: if they don't match, `openvox-ca` refuses to start rather than
  silently signing with a key that doesn't correspond to the trusted CA
  certificate.
- **On every certificate issuance**, `openvox-ca` re-fetches the Transit
  key's current public component from OpenBao and compares it against what
  was loaded at startup. If someone rotates the key directly at OpenBao
  (`bao write -f transit/keys/<name>/rotate`) while `openvox-ca` is already
  running, this is caught at the next issuance rather than producing a
  certificate that silently fails verification later. The request fails
  with an error instead of returning a certificate.

This works the same way whether or not key isolation (the isolated
`openvox-ca [signer]` process) is in use — the check happens wherever the
Transit key actually lives, not in the frontend.

If you do intend to rotate the Transit key, reissue the CA certificate to
match afterwards (the same offline `openvox-ca-ctl import` process used for
any other CA key change) rather than rotating it in place underneath a
running CA.

## Process isolation

The isolated-signer deployment (the default; see the main README's
[key isolation](../README.md) discussion) keeps working unchanged in OpenBao
mode: the OpenBao client and its token live inside the isolated
`openvox-ca [signer]` child process, exactly where a local private key lives
today. An OpenBao token scoped to `sign`+`read` on one Transit key is still a
credential capable of signing arbitrary certificates on the CA's behalf, so
it gets the same process isolation a local key would. The frontend process
is unaffected either way — it always talks to the signer over the same
authenticated RPC socketpair, whether the signer is holding a local key or an
OpenBao client.

`--single-process` disables that isolation (as it does for local keys):
the one process authenticates to OpenBao and holds the resulting token
itself.
