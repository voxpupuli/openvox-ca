# Metrics & monitoring

The openvox-ca server ships with an optional [Prometheus](https://prometheus.io/)
exporter. When enabled it serves the standard Go runtime/process metrics and
HTTP request metrics expected of a Go web service, plus CA-specific series
describing the **CA certificate**, its **CRL**, and every known (non-deleted)
**leaf certificate** — including issue/expiry timestamps and issuance status.

A ready-to-import [Jsonnet alerting mixin](../mixin/) is included for alerting on
impending CA, CRL, and leaf-certificate expiry, on pending certificate requests,
and on Kubernetes export failures.

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
| `puppetca_crl_number` | Monotonic CRL sequence number (`cRLNumber`). Expect it to advance without any revocation having happened: a re-sign bumps it, and with [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain) configured, so does a change to the upstream chain. The number need only increase, so this is harmless — but do not treat a rise as evidence that something was revoked. |
| `puppetca_crl_this_update_timestamp_seconds` | CRL `ThisUpdate` time. |
| `puppetca_crl_next_update_timestamp_seconds` | CRL `NextUpdate` (expiry) time. |
| `puppetca_crl_revoked_certificates` | Number of certificates currently listed in the CRL. |
| `puppetca_crl_update_failures_total` | Counter of failures to amend the CRL — a revocation that could not be recorded, or a CRL that could not be re-signed or written (across the revoke, cleanup, reissue and refresh paths). A rising value means the CRL is not being maintained; for revocations it means a superseded certificate may still be a valid credential. Resets to `0` on process restart. |

The four CRL gauges above describe **this CA's own CRL**, the first block of the
stored blob. When a CRL chain has been imported, the ancestor CRLs that follow it
are not covered: this CA cannot re-sign them, so their expiry is not something a
re-sign can fix and not something these series track. The series below cover
those instead.

### Upstream CRL chain

| Metric | Description |
| --- | --- |
| `puppetca_crl_chain_next_update_timestamp_seconds` | NextUpdate of each **upstream** CRL in the stored blob — every block this CA did not issue — labelled by `issuer`. Deliberately a separate series from the unlabelled CRL metrics above: an expiring upstream CRL is fixed at the parent CA, not here, so it has its own alert and runbook. |
| `puppetca_crl_chain_last_read_timestamp_seconds` | When `crl_chain_file` was last read successfully. **Absent** until the first successful read, which is how a configured-but-never-read file is detected — a wrong path or a mount that never landed moves no counter and would otherwise look healthy. Present but static means the file is being read and never changes, which is what a `subPath` mount does. |
| `puppetca_crl_chain_refresh_failures_total` | Counter of failed `crl_chain_file` refreshes — unreadable, unparseable, or too large. The chain already published is left in place, so the visible symptom is upstream CRLs ageing with nothing renewing them. Zero and static without `crl_chain_file`. Resets to `0` on process restart. |
| `puppetca_crl_chain_discarded_total` | Counter of discards: one per CRL dropped from `crl_chain_file`, each time the file is evaluated, because no certificate in the stored CA bundle signed it. The file is evaluated on every CRL amendment as well as on the maintenance pass, so with a static bad file the value tracks revocation rate rather than the number of bad CRLs — alert on `increase(...) > 0`, not on the value. **Alert on this** — the shipped mixin does. It is the only signal that the published chain is *smaller* than the file says: a discarded CRL has no series of its own to go missing from. Zero and static without `crl_chain_file`. Resets to `0` on process restart. |

The gauge appears whenever the stored blob holds a CRL this CA did not issue —
which includes a chain brought in by `openvox-ca-ctl import --crl-chain` on a
deployment that has never set `crl_chain_file`. That is deliberate: an ancestor
CRL ages the same way whether or not anything is refreshing it, and it is
precisely the import-only deployment where nothing is. The remedy differs,
though, and the alert text names `crl_chain_file` because that is the standing
fix. On an import-only deployment, read
`PuppetCAUpstreamCRLExpiringSoon`/`Expired` as "re-import the chain with a
current one, or configure [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain)
so it stays current by itself".

### Self-provisioned serving certificate

Always exported, so a dashboard or alert can select them whether or not
[`tls_self_provision`](configuration.md#self-provisioned-serving-certificate) is
in use.

Two of them read zero without the feature. The **revocation** counter does not:
the startup sweep that drains pending revocations runs whenever `hostname` is
set, deliberately without regard to `tls_self_provision`, so that entries a
previous configuration recorded are not stranded. A backend error at boot
therefore raises it on a CA that has never enabled the feature — and that is the
case with no retry, since no periodic task is registered. Do not silence
`PuppetCAServingCertRevocationFailing` on non-self-provisioning CAs.

| Metric | Description |
| --- | --- |
| `puppetca_serving_cert_issued_total` | Counter of serving certificates this process has issued to itself. A sustained rate rather than an occasional increment means replicas disagree about which CA certificate is current, each reissuing over the other; a fleet restart resolves it. **Alerted** as `PuppetCAServingCertChurning`, because inferring it otherwise would mean noticing an inventory growing for no reason. Resets to `0` on process restart. |
| `puppetca_serving_cert_renewal_failures_total` | Counter of maintenance passes that failed to renew the serving certificate. The existing certificate stays in place and the next cycle retries. **Alert on this** — the shipped mixin does, as `PuppetCAServingCertRenewalFailing`: a persistent rise is invisible until the certificate expires, and it breaks the bound `tls_self_provision_revoke_after_sec` relies on. Resets to `0` on process restart. |
| `puppetca_serving_cert_revocation_failures_total` | Counter of failures to record or to complete a supersession. The replaced certificate stays a valid credential either way, which is the exposure bound `tls_self_provision_revoke_after_sec` exists to enforce, so the mixin **alerts** on it as `PuppetCAServingCertRevocationFailing`. Some cases retry and some can never be retired; see [Superseded serving certificates](#superseded-serving-certificates) below. Resets to `0` on process restart. |

#### Superseded serving certificates

When `puppetca_serving_cert_revocation_failures_total` rises, the CA log line
says which case it is. They differ in whether anything will clear it.

**Retried on the next pass.** `Could not reconcile superseded serving
certificates`, and `will retry` for one entry the sweep could not revoke. The
pending list is left intact. Because the alert fires only while the counter is
still rising, a firing instance means the retries are *not* succeeding — treat
it as a storage-backend fault rather than waiting.

**Not retried.** The same reconcile line ending `at startup`, when
`tls_self_provision` is off. No periodic task is registered in that
configuration, so the startup sweep is the only one the process runs and nothing
retries until the CA restarts.

**Cannot be retired at all.** `will not be scheduled for revocation` and `can
never be revoked`. The mint has already overwritten what named the old serial,
so no sweep can rediscover it, and there is **no by-serial revoke**
([#177](https://github.com/voxpupuli/openvox-ca/issues/177)) — `openvox-ca-ctl
revoke --certname <hostname>` resolves to the certificate the listener is
currently serving, so running it makes things worse. The orphan stays a valid
CA-signed credential for the CA's hostname until its `notAfter`. Contain it at
the network layer, or rotate the CA.

To record what was orphaned, for the incident:

- the `will not be scheduled for revocation` line carries a `serial` field when
  it knows one;
- when the certificate itself was unreadable it does not, and the orphan is the
  second-newest inventory row for the CA's hostname;
- when the *pending list* could not be parsed it does not either, and there may
  have been **several** — the log line carries the raw list as `raw` and a
  `recovered` count of the entries that still decoded. Reconstruct the rest from
  the inventory rows for the CA's hostname newer than
  `tls_self_provision_revoke_after_sec` ago;
- `can never be revoked` carries only the malformed value that caused it, so use
  the inventory there too.

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
```

## Alerting

See the [`mixin/`](../mixin/) directory for the Jsonnet monitoring mixin and
instructions for rendering or importing it. It alerts on exporter availability,
CA/CRL/leaf expiry, pending requests, CRL update failures
(`puppetca_crl_update_failures_total`), serving-certificate renewal, revocation and issuance churn
(`puppetca_serving_cert_*`), and Kubernetes export
failures, with all thresholds configurable.
