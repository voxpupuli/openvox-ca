# Metrics & monitoring

The puppet-ca server ships with an optional [Prometheus](https://prometheus.io/)
exporter. When enabled it serves the standard Go runtime/process metrics and
HTTP request metrics expected of a Go web service, plus CA-specific series
describing the **CA certificate**, its **CRL**, and every known (non-deleted)
**leaf certificate** — including issue/expiry timestamps and issuance status.

A ready-to-import [Jsonnet alerting mixin](../mixin/) is included for alerting on
impending CA, CRL, and leaf-certificate expiry, and on pending certificate
requests.

## Enabling the exporter

The exporter is **disabled by default**. Enable it by setting a listen address:

| Flag | Env | Config (YAML) |
|------|-----|---------------|
| `--metrics-listen 127.0.0.1:9140` | `PUPPET_CA_METRICS_LISTEN=127.0.0.1:9140` | `metrics_listen: 127.0.0.1:9140` |

```sh
puppet-ca --cadir /var/lib/puppet-ca --metrics-listen 127.0.0.1:9140
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
  - job_name: puppet-ca
    static_configs:
      - targets: ['puppet-ca.internal:9140']
```

The `job_name` is referenced by the alerting mixin's selector (default
`job="puppet-ca"`).

## Metric reference

All CA-specific metrics use the `puppetca_` prefix. Timestamps are seconds since
the Unix epoch, the Prometheus convention for `*_timestamp_seconds` gauges.

### Standard Go / web-application metrics

| Metric | Description |
|--------|-------------|
| `go_*` | Go runtime metrics (goroutines, GC, memory) from the standard Go collector. |
| `process_*` | Process metrics (CPU, resident memory, open FDs) where supported by the platform. |
| `puppetca_http_requests_total{method,code}` | Total CA API requests, by HTTP method and response code. |
| `puppetca_http_request_duration_seconds{method,code}` | CA API request latency histogram. |
| `puppetca_http_requests_in_flight` | CA API requests currently being served. |

> HTTP request metrics are intentionally **not** labelled by URL path: Puppet CA
> paths embed per-node subjects (e.g. `/certificate_status/<hostname>`), which
> would otherwise explode metric cardinality.

### Exporter health

| Metric | Description |
|--------|-------------|
| `puppetca_ca_ready` | `1` when the CA has finished initialising, else `0`. |
| `puppetca_collector_scrape_success` | `1` if the last CA-state gather succeeded, else `0` (e.g. storage unavailable). |
| `puppetca_collector_scrape_duration_seconds` | Time taken to gather the CA, CRL and leaf metrics. |

### CA certificate

| Metric | Labels | Description |
|--------|--------|-------------|
| `puppetca_ca_certificate_info` | `common_name`, `serial`, `issuer` | Constant `1`; carries CA identity in labels. |
| `puppetca_ca_certificate_not_before_timestamp_seconds` | — | CA certificate issue time. |
| `puppetca_ca_certificate_not_after_timestamp_seconds` | — | CA certificate expiry time. |

### CRL

| Metric | Description |
|--------|-------------|
| `puppetca_crl_number` | Monotonic CRL sequence number (`cRLNumber`). |
| `puppetca_crl_this_update_timestamp_seconds` | CRL `ThisUpdate` time. |
| `puppetca_crl_next_update_timestamp_seconds` | CRL `NextUpdate` (expiry) time. |
| `puppetca_crl_revoked_certificates` | Number of certificates currently listed in the CRL. |

### Leaf certificates

One series per known (non-deleted) leaf certificate or pending request. Cleaned
(`puppet cert clean`) certificates drop out of these series even though their
inventory line persists. The `state` label is one of `requested` (a pending CSR
with no issued certificate), `signed`, or `revoked`.

| Metric | Labels | Description |
|--------|--------|-------------|
| `puppetca_leaf_certificate_info` | `subject`, `serial`, `state` | Constant `1`. For `requested`, `serial` is empty. |
| `puppetca_leaf_certificate_not_before_timestamp_seconds` | `subject`, `serial`, `state` | Issue time. Not emitted for `requested`. |
| `puppetca_leaf_certificate_not_after_timestamp_seconds` | `subject`, `serial`, `state` | Expiry time. Not emitted for `requested`. |
| `puppetca_leaf_certificates` | `state` | Count of leaf certificates per state. |

> Expiry is **not** a `state`: it is derived from the `not_after` timestamp by
> alerting rules, so a certificate can be both `signed`/`revoked` and expired.
> To alert on expiry while ignoring revoked certs, filter on `state!="revoked"`,
> as the mixin does.

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
```

## Alerting

See the [`mixin/`](../mixin/) directory for the Jsonnet monitoring mixin and
instructions for rendering or importing it. It alerts on exporter availability,
CA/CRL/leaf expiry, and pending requests, with all thresholds configurable.
