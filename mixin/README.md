# OpenVox CA monitoring mixin

A [monitoring mixin](https://monitoring.mixins.dev/) providing Prometheus
alerting rules for the openvox-ca exporter. It alerts on:

- the exporter being down or unable to read CA state, and the CA not being ready;
- the **CA certificate** nearing expiry (warning) or expiring imminently (critical);
- the **CRL** approaching its `NextUpdate` (warning) or having lapsed (critical).
  This covers **this CA's own CRL only** — block 0 of the stored blob, which the
  background refresher keeps fresh regardless. Ancestor CRLs are covered
  separately, by the upstream-CRL rules below;
- **leaf certificates** nearing/at expiry — excluding revoked ones — and
  certificate **requests that stay pending** too long;
- **CRL update failures** — the CA failing to amend its CRL (a revocation it
  could not record, or a CRL it could not re-sign, write or read), which can
  leave revoked or superseded certificates still valid. On filesystem and
  SQLite a revocation that merely queued too long for its subject's lock is
  counted here too, so the alert distinguishes the two by log line — see
  [metrics](../docs/metrics.md).
- **CRL propagation** — a replica that cannot reload the stored CRL, or that
  keeps enforcing one behind it. On a shared backend each replica decides
  revocation from its own copy, so a replica left behind still accepts
  certificates revoked elsewhere; see `crl_sync_interval_sec` in
  [configuration](../docs/configuration.md).
- **Upstream CRLs** in a published chain nearing or past their `NextUpdate`, and
  the four ways that chain goes wrong, each with its own remedy: a
  [`crl_chain_file`](../docs/configuration.md#publishing-an-upstream-crl-chain)
  that cannot be refreshed (fix the file or its mount); a CRL discarded from it
  because no certificate in the CA bundle signed it (complete the bundle); a CRL
  older than the one already published (fix whatever writes the file); and a
  file that has never been opened at all (wrong path, or a mount that never
  landed). They are four rules rather than one because a responder sent to the
  wrong one of those remedies finds nothing wrong. The per-issuer gauge appears
  only where the stored blob holds a CRL this CA did not issue — including a
  chain brought in by `import --crl-chain`, with no `crl_chain_file` in sight.
  The counters are always exported and read zero without one, while
  `puppetca_crl_chain_last_read_timestamp_seconds` is exported only where
  `crl_chain_file` is set, which is what makes the never-opened case alertable
  without firing across the whole fleet. None of it is fixable here — this CA
  cannot re-sign another CA's list — so every remedy points at the parent CA or
  at the file.

  One case has no rule and cannot have one: a `subPath` mount reads successfully
  forever, so it is indistinguishable from a healthy file on every series. It
  surfaces as *UpstreamCRLExpiringSoon* on a CA that has `crl_chain_file` set.
- **Kubernetes export** targets whose applies keep failing (only when the
  [Kubernetes export](../docs/kubernetes-export.md) feature is in use).

All thresholds and the target selector live in [`config.libsonnet`](config.libsonnet)
and can be overridden without editing the rules.

## Enabling the exporter

The alerts assume the openvox-ca Prometheus exporter is enabled and scraped. Start
the server with `--metrics-listen` (or `PUPPET_CA_METRICS_LISTEN` /
`metrics_listen:` in the config file):

```sh
openvox-ca --cadir /var/lib/puppet-ca --metrics-listen 127.0.0.1:9140
```

The exporter serves `/metrics` over plain HTTP on its own listener. It exposes
node hostnames as label values, so bind it to loopback or a trusted management
network and scrape it from there. A matching Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: openvox-ca
    static_configs:
      - targets: ['openvox-ca.internal:9140']
```

The `job_name` must match `puppetCASelector` in the mixin config (default
`job="openvox-ca"`).

## Rendering the alerts standalone

With [`jsonnet`](https://github.com/google/go-jsonnet) installed:

```sh
jsonnet -S -e "std.manifestYamlDoc((import 'mixin.libsonnet').prometheusAlerts)" \
  > puppet_ca_alerts.yaml
promtool check rules puppet_ca_alerts.yaml
```

## Checking the rules

`mage test:mixin` renders the mixin and runs both promtool checks over it —
`check rules` for syntax and `test rules` against [`tests.yaml`](tests.yaml),
which covers the rules whose expressions are not simple thresholds. CI runs the
same target, so a broken expression fails the build rather than waiting to be
noticed in an alertmanager that never fires. It skips with a message if
`jsonnet` or `promtool` is not on your `PATH`.

## Importing into another repo

Vendor the mixin with [jsonnet-bundler](https://github.com/jsonnet-bundler/jsonnet-bundler):

```sh
jb install https://github.com/voxpupuli/openvox-ca/mixin@main
```

Then combine it with your overrides:

```jsonnet
// mixin.jsonnet
local puppetca = (import 'vendor/openvox-ca/mixin.libsonnet') + {
  _config+:: {
    puppetCASelector: 'job="pki/openvox-ca"',
    caExpiryWarningSeconds: 45 * 24 * 3600,
  },
};

{
  'puppet_ca_alerts.yaml': std.manifestYamlDoc(puppetca.prometheusAlerts),
}
```

```sh
jsonnet -J vendor -m . mixin.jsonnet
```

## Configurable thresholds

| Key | Default | Meaning |
| --- | --- | --- |
| `puppetCASelector` | `job="openvox-ca"` | Label selector matching the exporter targets. |
| `alertLabels` | `{}` | Extra labels merged onto every alert (e.g. routing labels). |
| `caExpiryWarningSeconds` | 30 days | CA certificate expiry warning threshold. |
| `caExpiryCriticalSeconds` | 7 days | CA certificate expiry critical threshold. |
| `crlExpiryWarningSeconds` | 3 days | CRL `NextUpdate` warning threshold. |
| `upstreamCRLExpiryWarningSeconds` | 14 days | Warning threshold for an upstream CRL in a published chain. Longer than `crlExpiryWarningSeconds` because the remedy is at another CA. |
| `crlChainWindow` | `1h` | Window over which chain-refresh failures, discards and regressions are counted. Equals the CA's default `maintenance_interval_sec` with no margin: raise it alongside any increase to that setting, or a single unchanging fault will fire, resolve and re-fire forever. |
| `crlChainFor` | `15m` | `for:` debounce for the four upstream-chain alerts. |
| `leafExpiryWarningSeconds` | 7 days | Leaf certificate expiry warning threshold. |
| `leafExpiryCriticalSeconds` | 1 day | Leaf certificate expiry critical threshold. |
| `pendingFor` | `1h` | How long a request may stay pending before alerting. |
| `crlUpdateWindow` | `1h` | Window over which CRL-update failures are counted (the metric is a restart-resetting counter). |
| `crlUpdateFor` | `15m` | `for:` debounce for the CRL-update-failure alert. |
| `crlSyncWindow` | `1h` | Window over which CRL-reload failures are counted (the metric is a restart-resetting counter). |
| `crlSyncFor` | `5m` | `for:` debounce for the CRL-reload-failure alert. Keep it below `crlLagFor` so the warning precedes the page it explains. |
| `crlLagFor` | `10m` | How long a replica may keep enforcing a CRL behind the stored one before it is paged on. Raise it if you have raised `crl_sync_interval_sec`. |
| `expiryFor` / `scrapeFor` / `readyFor` / `downFor` / `k8sExportFailingFor` | `1h` / `15m` / `10m` / `5m` / `15m` | `for:` debounce durations. |
