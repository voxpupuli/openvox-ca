# HTTP API reference

`openvox-ca` implements the same HTTP API that OpenVox and Puppet agents, and
the `puppetserver ca` / `puppet ssl` tooling, already use — the Puppet CA API.

All endpoints are served under both the bare path and `/puppet-ca/v1/<path>`, so the server can be used directly by agents or placed behind a proxy that strips the prefix.

## Certificate status

| Method | Path | Description |
| --- | --- | --- |
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

## Certificate statuses (list)

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate_statuses/{any}` | List all certificates; filter with `?state=requested\|signed\|revoked` |

## CSR management

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate_request/{subject}` | Retrieve a pending CSR PEM |
| `PUT` | `/certificate_request/{subject}` | Submit a new CSR (body: raw PEM) |
| `DELETE` | `/certificate_request/{subject}` | Delete a pending CSR |

## Certificate retrieval

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate/{subject}` | Retrieve a signed certificate PEM (`ca` returns the CA cert) |

## Certificate renewal

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/certificate_renewal` | Renew an existing certificate; body: raw CSR PEM, or empty; returns new certificate PEM |

Requires a valid CA-signed client certificate. The new certificate is issued immediately without entering the pending-CSR queue or autosign evaluation, and the certificate it replaces is revoked once the new one is safely stored (see `revoke_on_auto_renew` below for the auto-renewal case).

- **CSR body (re-key):** the CSR Common Name must match the authenticated client CN — an agent can only renew its own certificate, not another's. Issues a certificate for the new key in the CSR. Puppet OID extensions are copied from the CSR **except** authorization-arc OIDs (`1.3.6.1.4.1.34380.1.3.*`, such as `pp_cli_auth`), which are stripped so a submitted CSR cannot request elevated privileges.
- **Empty body (wire-compatible auto-renewal):** matches the request real OpenVox/Puppet agents send by default (`hostcert_renewal_interval`, and the `puppet ssl renew_cert` CLI action). Identity and key possession come solely from the mTLS-presented client certificate; the same public key is reissued with a fresh serial and validity, carrying forward the original certificate's SANs and Puppet OID extensions unchanged. Unlike the CSR path, this **preserves authorization-arc OIDs** (e.g. `pp_cli_auth`): they were already vetted when the presented certificate was issued, so a cert that legitimately holds them keeps them across renewal.

If the presented certificate's (or CSR's) key falls below the CA key-strength policy — for example an RSA-1024 key imported from a legacy CA — the request is rejected with `422 Unprocessable Entity` rather than renewed; the agent must re-key via the CSR path with a compliant key.

`revoke_on_auto_renew` (env `PUPPET_CA_REVOKE_ON_AUTO_RENEW`, default `true`) controls whether the certificate replaced by an auto-renewal (empty body) is revoked. The default keeps only the newest serial per subject valid. Set to `false` to match OpenVox Server's own (Clojure) CA exactly, which leaves the replaced certificate valid — for the same key — until it naturally expires. This setting has no effect on the CSR-body (re-key) path, which always revokes the certificate it replaces.

> **CRL growth:** with the default `true`, every auto-renewal appends the retired serial to the CRL, and the entry stays there until the certificate expires. Entries are only pruned by the expired-certificate cleanup job, which is off by default — enable `enable_expired_cert_cleanup` to bound CRL size on busy CAs, and watch `puppetca_crl_revoked_certificates` to keep an eye on it. Revocation is best-effort (a failure never fails the renewal); the `puppetca_crl_update_failures_total` metric counts any failure to amend the CRL, including a superseded certificate that could not be revoked.

## Bulk signing

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/sign` | Sign one or more CSRs; body: `{"certnames":["a","b"]}` |
| `POST` | `/sign/all` | Sign every pending CSR |

## Bulk clean

| Method | Path | Description |
| --- | --- | --- |
| `PUT` | `/clean` | Revoke + delete multiple certificates in bulk; body: `{"certnames":["a","b"]}` |

Response:

```json
{ "cleaned": ["a.example.com"], "not-found": ["missing.example.com"], "clean-errors": [] }
```

## CRL

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/certificate_revocation_list/ca` | Download the stored CRL PEM verbatim. When a CRL **chain** was imported (see `--crl-chain`) the response is that whole chain, this CA's own CRL first, so agents can perform full-chain revocation checking (Puppet's default `certificate_revocation = chain`). Ancestor CRLs are preserved across re-signing but are never fetched or refreshed by this CA — they are only ever as current as what was imported |
| `PUT` | `/certificate_revocation_list/ca` | Re-sign **this CA's own** CRL with a fresh validity window (preserves all revocations and every ancestor block); admin-only. Returns the whole stored chain, this CA's own CRL first. Returns `409 Conflict` when the stored CRL was not signed by the CA certificate this process loaded — the usual cause is a replaced CA certificate on an unrestarted replica, and the response body names the remedy |

## Expirations

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/expirations` | CA cert and CRL expiry dates. The CRL date is **this CA's own CRL (block 0) only** — imported ancestor CRLs are not reflected, so an ancestor can be past its `nextUpdate` while this reports a comfortable date. See [metrics](metrics.md#crl) |

## Server-side key generation

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/generate/{subject}` | Generate key + cert server-side; optional `?dns=alt.name`. Key algorithm follows `--leaf-key-algo` / `--leaf-key-size` (default: RSA 2048) |

Response:

```json
{ "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...", "certificate": "-----BEGIN CERTIFICATE-----\n..." }
```

## Certificate import

| Method | Path | Description |
| --- | --- | --- |
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

## OCSP

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/ocsp` | RFC 6960 OCSP request; body is DER-encoded `OCSPRequest` |
| `GET` | `/ocsp/{request}` | RFC 6960 GET form; `{request}` is standard or URL-safe base64-encoded DER |

Both paths are also served under `/puppet-ca/v1/`. Responses are signed by the CA key directly (`Content-Type: application/ocsp-response`). GET responses include `Cache-Control: max-age=…, public`; requests carrying a nonce bypass the cache. The AIA extension is embedded in issued certificates when `--ocsp-url` is set.

## Health probes

These endpoints are served at bare paths only (no `/puppet-ca/v1` prefix) and require no client certificate.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/healthz/live` | Liveness probe: always `200` while the process is running |
| `GET` | `/healthz/ready` | Readiness probe: `200` once the CA is initialised, `503` before |
| `GET` | `/healthz/startup` | Startup probe: delegates to the readiness check |

Response body: `{"status":"ok"}` (200) or `{"status":"not_ready"}` (503).

## Authorization tiers

When mTLS is enabled (both `--tls-cert` and `--tls-key` set), each endpoint requires a minimum client certificate tier:

| Tier | Required client cert | Endpoints |
| --- | --- | --- |
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
