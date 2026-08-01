# Metrics & monitoring

The openvox-ca server ships with an optional [Prometheus](https://prometheus.io/)
exporter. When enabled it serves the standard Go runtime/process metrics and
HTTP request metrics expected of a Go web service, plus CA-specific series
describing the **CA certificate**, its **CRL**, and every known (non-deleted)
**leaf certificate** — including issue/expiry timestamps and issuance status.

A ready-to-import [Jsonnet alerting mixin](../mixin/) is included; see
[Alerting](#alerting) for what it covers.

## Enabling the exporter

The exporter is **disabled by default**. Enable it by setting a listen address:

| Flag | Env | Config (YAML) |
| --- | --- | --- |
| `--metrics-listen 127.0.0.1:9140` | `PUPPET_CA_METRICS_LISTEN=127.0.0.1:9140` | `metrics_listen: 127.0.0.1:9140` |

```sh
openvox-ca --cadir /var/lib/puppet-ca --metrics-listen 127.0.0.1:9140
```

The exporter runs on a **separate listener** from the Puppet API and always
serves plain HTTP at `/metrics`, regardless of the API's TLS configuration. In
the default isolated-process mode it runs inside the frontend process (the
signer process has no network exposure).

> **Security:** the leaf-certificate metrics expose node hostnames (certificate
> subjects) as label values. Bind the exporter to loopback or a trusted
> management network — e.g. `127.0.0.1:9140` scraped via a node exporter sidecar,
> or a dedicated interface protected by a network policy — rather than a public
> address.

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: openvox-ca
    static_configs:
      - targets: ['openvox-ca.internal:9140']
```

The `job_name` is referenced by the alerting mixin's selector (default
`job="openvox-ca"`).

## Metric reference

All CA-specific metrics use the `puppetca_` prefix. Timestamps are seconds since
the Unix epoch, the Prometheus convention for `*_timestamp_seconds` gauges.

### Standard Go / web-application metrics

| Metric | Description |
| --- | --- |
| `go_*` | Go runtime metrics (goroutines, GC, memory) from the standard Go collector. |
| `process_*` | Process metrics (CPU, resident memory, open FDs) where supported by the platform. |
| `puppetca_http_requests_total{method,code}` | Total CA API requests, by HTTP method and response code. |
| `puppetca_http_request_duration_seconds{method,code}` | CA API request latency histogram. |
| `puppetca_http_requests_in_flight` | CA API requests currently being served. |

> HTTP request metrics are intentionally **not** labelled by URL path: the CA's
> API paths embed per-node subjects (e.g. `/certificate_status/<hostname>`),
> which would otherwise explode metric cardinality.

### Exporter health

| Metric | Description |
| --- | --- |
| `puppetca_ca_ready` | `1` when the CA has finished initialising, else `0`. |
| `puppetca_collector_scrape_success` | `1` if the last CA-state gather succeeded, else `0` (e.g. storage unavailable). |
| `puppetca_collector_scrape_duration_seconds` | Time taken to gather the CA, CRL and leaf metrics. |

### CA certificate

| Metric | Labels | Description |
| --- | --- | --- |
| `puppetca_ca_certificate_info` | `common_name`, `serial`, `issuer` | Constant `1`; carries CA identity in labels. |
| `puppetca_ca_certificate_not_before_timestamp_seconds` | — | CA certificate issue time. |
| `puppetca_ca_certificate_not_after_timestamp_seconds` | — | CA certificate expiry time. |

### CRL

| Metric | Description |
| --- | --- |
| `puppetca_crl_number` | Monotonic CRL sequence number (`cRLNumber`). |
| `puppetca_crl_this_update_timestamp_seconds` | CRL `ThisUpdate` time. |
| `puppetca_crl_next_update_timestamp_seconds` | CRL `NextUpdate` (expiry) time. |
| `puppetca_crl_revoked_certificates` | Number of certificates currently listed in the CRL. |
| `puppetca_crl_update_failures_total` | Counter of failures to amend the CRL — a revocation that could not be recorded, or a CRL that could not be re-signed or written (across the revoke, cleanup, reissue and refresh paths). A rising value means the CRL is not being maintained; for revocations it means a superseded certificate may still be a valid credential. Resets to `0` on process restart. |
| `puppetca_crl_cached_number` | CRL number of the copy **this replica** is answering revocation checks from. `number`, `this_update`, `next_update` and `revoked_certificates` above are read from storage and so are identical on every replica; this one and both `*_failures_total` counters are per-process and have to be checked on each. |
| `puppetca_crl_sync_failures_total` | Counter of failures to reload the stored CRL into that in-memory copy — an unreadable or unparseable CRL, or one this CA did not sign. While it rises the replica keeps enforcing whichever CRL it already held. Resets to `0` on process restart. |

Each replica decides revocation from `puppetca_crl_cached_number` and reloads it
from storage every `crl_sync_interval_sec` (60s by default), so after a
revocation it briefly trails `puppetca_crl_number`. A gap that persists is a
replica still admitting certificates the rest of the fleet has revoked — see
[watching revocation propagate](#watching-revocation-propagate) below for the
query, and `puppetca_crl_sync_failures_total` for why it is stuck.

### Leaf certificates

One series per known (non-deleted) leaf certificate or pending request. Cleaned
(`puppet cert clean`) certificates drop out of these series even though their
inventory line persists. The `state` label is one of `requested` (a pending CSR
with no issued certificate), `signed`, or `revoked`.

| Metric | Labels | Description |
| --- | --- | --- |
| `puppetca_leaf_certificate_info` | `subject`, `serial`, `state` | Constant `1`. For `requested`, `serial` is empty. |
| `puppetca_leaf_certificate_not_before_timestamp_seconds` | `subject`, `serial`, `state` | Issue time. Not emitted for `requested`. |
| `puppetca_leaf_certificate_not_after_timestamp_seconds` | `subject`, `serial`, `state` | Expiry time. Not emitted for `requested`. |
| `puppetca_leaf_certificates` | `state` | Count of leaf certificates per state. |

> Expiry is **not** a `state`: it is derived from the `not_after` timestamp by
> alerting rules, so a certificate can be both `signed`/`revoked` and expired.
> To alert on expiry while ignoring revoked certs, filter on `state!="revoked"`,
> as the mixin does.

### Kubernetes export

Only present when [Kubernetes export](kubernetes-export.md) targets are
configured. Export failures are logged but never stop the CA, so these series
are the way to alert on a target that persistently fails. One series per
configured target (cardinality is bounded by the configuration).

| Metric | Labels | Description |
| --- | --- | --- |
| `puppetca_k8s_export_applies_total` | `kind`, `namespace`, `name`, `result` | Apply attempts per target; `result` is `success` or `error`. |
| `puppetca_k8s_export_last_success_timestamp_seconds` | `kind`, `namespace`, `name` | Time of the last successful apply for each target. |
| `puppetca_k8s_export_last_error_timestamp_seconds` | `kind`, `namespace`, `name` | Time of the last failed apply for each target. |

> Exports are event-driven (startup and CRL updates) and can be days apart on a
> quiet CA, so alert by comparing `last_error` against `last_success` (the
> mixin's `PuppetCAKubernetesExportFailing` does this) rather than with rate
> windows or staleness thresholds, which misbehave between sparse attempts. A
> cycle that fails before any target is applied — the cert/CRL cannot be read
> from storage — touches none of these series, but storage failures already
> trip `PuppetCAScrapeFailing` via `puppetca_collector_scrape_success`.

## Example queries

```promql
# CA certificate days until expiry
(puppetca_ca_certificate_not_after_timestamp_seconds - time()) / 86400

# Non-revoked leaf certificates expiring within 7 days
puppetca_leaf_certificate_not_after_timestamp_seconds{state!="revoked"} - time() < 7 * 86400

# Pending certificate requests
puppetca_leaf_certificate_info{state="requested"} == 1

# CA API error rate
sum(rate(puppetca_http_requests_total{code=~"5.."}[5m]))

# Kubernetes export targets whose most recent apply failed
puppetca_k8s_export_last_error_timestamp_seconds
  > puppetca_k8s_export_last_success_timestamp_seconds
or
puppetca_k8s_export_last_error_timestamp_seconds
  unless puppetca_k8s_export_last_success_timestamp_seconds

# Replicas enforcing a CRL behind the stored one (see below)
puppetca_crl_number - puppetca_crl_cached_number > 0
or
puppetca_crl_cached_number unless puppetca_crl_number
```

### Watching revocation propagate

The query above is how you confirm a revocation has reached the whole fleet. It
is normally empty, and briefly non-empty after each revocation while replicas
pick the new CRL up on their `crl_sync_interval_sec` timer. A replica that stays
in it is still admitting certificates the rest of the fleet has revoked.

The second arm matters as much as the first: a replica whose stored CRL cannot
be read or parsed publishes no `puppetca_crl_number` at all, so the subtraction
alone would go quiet in exactly the case worth paging on.

`puppetca_crl_sync_failures_total` usually says why a replica is stuck. If it is
flat, the reads are succeeding and the stored CRL genuinely has not advanced.

Restarting the replica reloads the CRL — but startup verifies it against this
CA's certificate the same way the reload does, so if the stored CRL is not one
this CA signed the process will refuse to start rather than serve from it. That
is the intended outcome: re-sign the CRL with the current CA certificate (or
restore the certificate that signed it) instead of working around the refusal.

## Alerting

See the [`mixin/`](../mixin/) directory for the Jsonnet monitoring mixin and
instructions for rendering or importing it. It alerts on exporter availability,
CA/CRL/leaf expiry, pending requests, CRL update failures
(`puppetca_crl_update_failures_total`), a replica whose CRL has fallen behind
the stored one (`puppetca_crl_cached_number`,
`puppetca_crl_sync_failures_total`), and Kubernetes export failures, with all
thresholds configurable.
