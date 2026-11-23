# OpenVox CA monitoring mixin

A [monitoring mixin](https://monitoring.mixins.dev/) providing Prometheus
alerting rules for the openvox-ca exporter. It alerts on:

- the exporter being down or unable to read CA state, and the CA not being ready;
- **administrative activity**: more than 25 subjects revoked or cleaned across
  the CA in five minutes, which is a compromised administrator credential or an
  operational mistake (`OpenVoxCADestructiveOperationsHigh`, a warning; a bulk
  clean counts every subject it removes), and a clean that reported success
  while one of its steps failed (`OpenVoxCACleanIncomplete`, a warning, by
  step);
- an **OpenBao Transit** signer that has been unable to log in for five minutes
  (`OpenVoxCAOpenBaoUnauthenticated`, critical, and only where the CA key is in
  [OpenBao](../docs/openbao-transit.md)). Once the token in hand expires, the CA
  can sign nothing;
- an isolated **signer that has stopped answering** the frontend for five
  minutes while its process is still running (`OpenVoxCASignerUnresponsive`,
  critical, for every key backend; silent under `--single-process`).
  Readiness does not consult the signer, so nothing else reports this before
  the CRL refresh fails hours later. A signer that exits takes the frontend
  with it, which the launcher reports;
- the **CA certificate** nearing expiry (warning) or expiring imminently (critical);
- the **CRL** approaching its `NextUpdate` (warning) or having lapsed (critical).
  This covers **this CA's own CRL only** — block 0 of the stored blob, which the
  background refresher keeps fresh regardless. Ancestor CRLs are covered
  separately, by the upstream-CRL rules below;
- **Upstream CRLs** in a published chain nearing or past their `NextUpdate`,
  and the five ways that chain goes wrong, each with its own remedy: a
  [`crl_chain.file`](../docs/configuration.md#publishing-an-upstream-crl-chain)
  that cannot be refreshed (fix the file or its mount); a CRL discarded from it,
  or from a `crl_chain.urls` entry, because no certificate in the CA bundle
  signed it (complete the bundle, or point the entry at the right CA) or because
  it is a delta or IDP-scoped CRL (point the source at the full CRL); a CRL
  older than the one already published (fix whatever writes the file, or the
  upstream behind the URL; on a CA with several replicas and mirror entries, a
  short burst just after the upstream republishes is a lagging mirror,
  re-counted by the fetch job's retries until it catches up, and needs nothing
  unless it persists); an ancestor whose published CRL has been dropped, which
  is honoured and unrecoverable — the file stopped listing it, or an
  authoritative `crl_chain.urls` round no longer served it (check the file or
  the list was meant to lose it), or its certificate has left the CA bundle
  (re-import the bundle), and the log line says which; and a file that has never
  been opened at all (wrong path, or a mount that never landed). They are five
  rules rather than one because a responder sent to the wrong one of those
  remedies finds nothing wrong. The per-issuer gauge appears only where the
  stored blob holds a CRL this CA did not issue — including a chain brought in
  by `import --crl-chain`, with no `crl_chain.file` in sight. The four
  unlabelled counters are always exported and read zero without one, while the
  per-URL fetch series exist only for configured `crl_chain.urls` entries and
  `openvoxca_crl_chain_last_read_timestamp_seconds` only where `crl_chain.file`
  is set, which is what makes the never-fetched and never-opened cases alertable
  without firing across the whole fleet. None of it is fixable here — this CA
  cannot re-sign another CA's list — so every remedy points at the parent CA, at
  the file or the URL list, or at the CA bundle.

  One case has no rule and cannot have one: a `subPath` mount reads successfully
  forever, so it is indistinguishable from a healthy file on every series. It
  surfaces as `OpenVoxCAUpstreamCRLExpiringSoon` on a CA that has
  `crl_chain.file` set.

  **`OpenVoxCAUpstreamCRLRemoved` is a one-shot notification, not a standing
  one.** The counter it watches increments once, at the evaluation where the
  ancestor drops out of the published chain; on every pass after that the
  ancestor is simply absent, so nothing increments again. The alert therefore
  clears once its window closes and reads healthy from then on, while the
  ancestor stays dropped and its revocations stay unenforced fleet-wide. A
  restart zeroes the counter too. Treat a firing of this rule as an incident to
  track by hand: nothing will re-raise it, and no gauge reports the shortfall.
  The other four upstream rules are standing conditions and do re-fire.

  With [`crl_chain.urls`](../docs/configuration.md#fetching-upstream-crls),
  three more rules name the failing URL: `OpenVoxCAUpstreamCRLFetchFailing`
  when an entry yields nothing usable on `crlChainFetchFailureThreshold` rounds
  in `crlChainFetchWindow` — a 200 carrying an error page, the wrong issuer's
  CRL, a stale mirror's or an expired one counts, not only a transport
  failure, and so does every entry at once when the CRLs they serve together
  would make the published chain larger than 4 MiB —
  `OpenVoxCAUpstreamCRLNeverFetched` when one has not succeeded since
  startup, and `OpenVoxCAUpstreamCRLFetchStale` when one has gone
  `crlChainFetchStaleSeconds` without a usable CRL. The last fires on age
  alone, so it catches a fetch that has stopped counting anything; it is the
  timely signal, because the expiry warning is measured from `nextUpdate` and,
  against a long-lived upstream CRL, stays quiet for days after fetching stops.
- **leaf certificates** nearing/at expiry — excluding revoked ones — and
  certificate **requests that stay pending** too long;
- **CRL update failures** — the CA failing to amend its CRL (a revocation it
  could not record, or a CRL it could not re-sign, write or read), which can
  leave revoked or superseded certificates still valid. Some counts are not
  faults: on filesystem and SQLite a revocation that merely queued too long for
  its subject's lock, and a CRL refresh, `crl_chain.file` refresh,
  `crl_chain.urls` merge or cleanup step that stood aside for foreground CRL
  work for its whole step budget
  (logged with `behind a priority caller`), are counted here too, so the alert
  tells them apart by log line — see [metrics](../docs/metrics.md). It fires on two failures within three hours,
  not one: a backend restart that catches a single amendment stays silent,
  while a CRL that stays unreadable, or whose lock cannot be taken, fails on
  every hourly refresh pass and warns by the second, 15 minutes after it. A
  CRL that reads but cannot be signed or written counts only when the CA
  tries to amend it, because the refresh pass writes only when the CRL is due.
  With `crl_chain.file` or `crl_chain.urls` set, that job's own pass counts
  into the same counter — once per interval, since a failed `crl_chain.urls`
  merge waits the full interval too, except on a fresh store still held unready
  — so a restart that overlaps it and the CRL refresh can count two; see
  `crlUpdateThreshold` below.
  A best-effort revocation the CA does not retry, failing once, is reported by
  a rule that fires on one: `OpenVoxCASupersedeFailing`, below, for a
  certificate a renewal or managed-certificate reissue replaced with immediate
  revocation, and `OpenVoxCACleanIncomplete`, above, for one in a clean. See
  [storage-retry alerts](../docs/metrics.md#storage-retry-alerts).
- **CRL propagation** — a replica that cannot reload the stored CRL, or that
  keeps enforcing one behind it. On a shared backend each replica decides
  revocation from its own copy, so a replica left behind still accepts
  certificates revoked elsewhere; see `crl_sync_interval_sec` in
  [configuration](../docs/configuration.md). The reload warning fires on three
  failed reloads within ten minutes, so a backend restart that costs one or two
  stays silent, while a replica that fails every pass — the usual cause is a
  CA certificate replaced without restarting it — warns about five minutes in,
  ahead of the lag page.
- **OCSP index propagation** — a replica that cannot reload the inventory into
  the serial index its OCSP responder answers from. While that fails the
  responder answers `unknown` for certificates its peers have signed since the
  last successful pass, which is not fail-open but does split a fleet: a
  verifier that hard-fails on `unknown` rejects against that replica and no
  other. See `ocsp_index_sync_interval_sec` in
  [configuration](../docs/configuration.md). It fires on three failed passes
  within 30 minutes, so a backend restart that costs one or two stays silent,
  while an inventory that stays unreadable warns 15 to 20 minutes in. Silent
  when `enable_ocsp` is off, since the series it reads is then not exported.
- **Inventory tampering** — the periodic inventory verification finding the
  stored integrity value no longer matching the inventory, on any backend:
  rows added, removed or edited outside the CA. Critical, and fires on the
  first detection. Keyed on `reason="tampered"` only, so a backend that cannot
  be read does not page as tampering. See `inventory_verify_interval_sec` in
  [configuration](../docs/configuration.md#inventory-verification).
- **Inventory unreadable** — the periodic inventory verification failing to
  read the inventory at all, so nothing is checking it. A warning, on a count
  of failures rather than the first, so a backend restart does not raise it.
  On the filesystem backend nothing else covers this, since readiness
  reflects only the key and certificate in memory and the scrape does not read
  the inventory there; on the structured backends the scrape alert also fires,
  but without naming the inventory.
- **Supersession failures** — the CA failing to retire a certificate a renewal
  or a managed certificate's reissue replaced, which leaves that certificate a
  valid credential. Live on any CA that renews certificates. With an overlap
  window (`superseded_cert_revoke_after_sec`, 24 hours by default) that is a
  supersession it could not record or a sweep that could not carry it out;
  where the window is `0` (or a `managed_certs` entry's `revoke_after` is) the
  revocation happens inside the renewal or reissue, and one that fails fires
  this too, since nothing retries it. A store that cannot
  serve the pending-supersession key also fires it whatever the window, because
  the sweep, every renewal and every subject revocation read that key. See
  [delayed supersession](../docs/configuration.md#delayed-supersession).
- **Client trust domains** in three rules, and only where
  [`client_ca`](../docs/configuration.md#trusting-client-certificates-from-another-ca)
  is configured. Two are critical because they mean clients of a foreign issuer
  are being turned away: `OpenVoxCAClientCRLUnusable`, where an entry has no currently
  valid CRL at all — every one expired, every one discarded as unverifiable, or
  every one discarded as partial-scope — which under the default `require`
  policy rejects every client of that issuer;
  and `OpenVoxCAClientCRLRefusals`, which counts the refusals themselves rather than
  inferring them, so it fires on the thing an operator would otherwise learn from
  an agent-side 403 three layers away. The warning, `OpenVoxCAClientCRLStale`, is the
  early one: the entry's `crl_file` has not been applied for three refresh
  intervals, so the CRLs in use are still valid but revocations published since
  are not being honoured. None of it is fixable here — the remedy is at the
  issuing CA, or at whatever writes the file.
- **Kubernetes export** targets whose applies keep failing, and targets that are
  configured but never attempted at all (only when the
  [Kubernetes export](../docs/kubernetes-export.md) feature is in use).
- **File export** targets that have not been confirmed current for more than
  ten minutes, or have never succeeded since the CA started (only when the
  [file export](../docs/file-export.md) feature is in use). One alert covers
  failed writes, failed storage reads and a write that never returns.
- **Managed certificates** with no usable certificate — never issued at all, or
  holding only revoked ones (only when
  [`managed_certs`](../docs/configuration.md#managed-certificates) or
  [`serving_cert`](../docs/configuration.md#the-cas-own-serving-certificate) is
  in use; the CA's own serving certificate is one such entry).
  It covers an entry whose store has never accepted a write, and an entry whose
  live certificate was revoked and not yet reissued; both leave the component
  with nothing to present, which is why they page under one name. An entry that
  is failing to renew has its own alert, below.
- **Managed certificates failing to reissue**
  (`OpenVoxCAManagedCertificateReissueFailing`, a warning) — an entry whose
  latest reconcile failed and has not succeeded for 30 minutes. A failed store
  write puts the previous certificate back, so the component keeps working, but
  it will not be renewed and the leaf expiry alerts would otherwise be the
  first word of it. It fires for a never-issued entry too, beside the alert
  above.

All thresholds and the target selector live in [`config.libsonnet`](config.libsonnet)
and can be overridden without editing the rules.

## Enabling the exporter

The alerts assume the openvox-ca Prometheus exporter is enabled and scraped. Start
the server with `--metrics-listen` (or `OPENVOX_CA_METRICS_LISTEN` /
`metrics_listen:` in the config file):

```sh
openvox-ca --cadir /srv/openvox-ca --metrics-listen 127.0.0.1:9140
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

The `job_name` must match `openvoxCASelector` in the mixin config (default
`job="openvox-ca"`).

## Rendering the alerts standalone

With [`jsonnet`](https://github.com/google/go-jsonnet) installed:

```sh
jsonnet -S -e "std.manifestYamlDoc((import 'mixin.libsonnet').prometheusAlerts)" \
  > openvox_ca_alerts.yaml
promtool check rules openvox_ca_alerts.yaml
```

## Checking the rules

`mage test:mixin` renders the mixin and runs both promtool checks over it —
`check rules` for syntax and `test rules` against [`tests.yaml`](tests.yaml),
which covers the rules whose firing is not obvious from the PromQL: the ones
built from set operators or a timing argument, and the plain leaf and CRL expiry
thresholds, pinned for how they meet the exporter's hold on a failed gather. CI
runs the same target, so a broken expression fails the build rather than
waiting to be noticed in an alertmanager that never fires. It skips with a message if
`jsonnet` or `promtool` is not on your `PATH`.

The alert names and `_config` keys are public API
([what the version number promises](../docs/development/releasing.md#what-the-version-number-promises)),
so `tests.yaml` has at least one case naming every alert, and `mage test:mixin`
also refuses any name in `publishedMixinAlerts` or `publishedMixinConfigKeys`
(in `magefile.go`) that the mixin no longer renders: renaming or removing one
needs a major release. Additions pass that check, so a change that adds an
alert or a `_config` key also adds it to those lists and gives the alert a
case in `tests.yaml`, or nothing protects it.

## Importing into another repo

Vendor the mixin with [jsonnet-bundler](https://github.com/jsonnet-bundler/jsonnet-bundler):

```sh
jb install https://github.com/voxpupuli/openvox-ca/mixin@v<version>
```

Pin the same release tag as the server you run, and move it with each server
upgrade: the thresholds are tuned to that release's defaults. `@main` tracks
unreleased changes, and the alert names and `_config` keys are
[promised](../docs/development/releasing.md#what-the-version-number-promises)
only as published at a release tag.

Then combine it with your overrides:

```jsonnet
// mixin.jsonnet
local openvoxca = (import 'vendor/openvox-ca/mixin.libsonnet') + {
  _config+:: {
    openvoxCASelector: 'job="pki/openvox-ca"',
    caExpiryWarningSeconds: 45 * 24 * 3600,
  },
};

{
  'openvox_ca_alerts.yaml': std.manifestYamlDoc(openvoxca.prometheusAlerts),
}
```

```sh
jsonnet -J vendor -m . mixin.jsonnet
```

## Configurable thresholds

| Key | Default | Meaning |
| --- | --- | --- |
| `openvoxCASelector` | `job="openvox-ca"` | Label selector matching the exporter targets. |
| `alertLabels` | `{}` | Extra labels merged onto every alert (e.g. routing labels). |
| `caExpiryWarningSeconds` | 30 days | CA certificate expiry warning threshold. |
| `caExpiryCriticalSeconds` | 7 days | CA certificate expiry critical threshold. |
| `crlExpiryWarningSeconds` | 3 days | CRL `NextUpdate` warning threshold. |
| `upstreamCRLExpiryWarningSeconds` | 14 days | Warning threshold for an upstream CRL in a published chain. Longer than `crlExpiryWarningSeconds` because the remedy is at another CA. |
| `crlChainWindow` | `2h` | Window over which chain-refresh failures, discards, regressions and removals are counted (fetch failures have their own, below). Twice the CA's default `crl_chain.refresh_interval_sec`, so that two increments are always in range: at exactly one interval a single unchanging fault fires, resolves and re-fires forever, because the older sample ages out before the next increment lands. Keep it at twice the interval if you change that setting. |
| `crlChainFor` | `15m` | `for:` debounce for the upstream-chain and upstream-fetch alerts. |
| `crlChainFetchStaleSeconds` | 3 hours | How long a `crl_chain.urls` entry may go without a usable, current CRL before `OpenVoxCAUpstreamCRLFetchStale` fires. A healthy entry is never older than about one interval, so it fires only once `crl_chain.refresh_interval_sec` exceeds this plus `crlChainFor`; the margin above one interval is what lets a failed round stay quiet. **Keep it at least twice the interval**, and raise it with that setting, which the mixin cannot see: at the default, an interval above about 97 minutes lets one failed round fire it, and one above about 3h15m fires between healthy rounds. Three times the CA's default `crl_chain.refresh_interval_sec`. |
| `crlChainFetchFailureThreshold` | `2` | Failed rounds of one `crl_chain.urls` entry within `crlChainFetchWindow` before `OpenVoxCAUpstreamCRLFetchFailing` fires. Two, so one blip that the 30-second retry recovers from stays quiet. The retries count as rounds — after 30 seconds, then a minute, then two — so an outage of an upstream that lasts more than about 30 seconds and overlaps a round reaches two at once, and once fired the alert holds until the window has passed the older failure: about three hours at the defaults, after the upstream has recovered. |
| `crlChainFetchWindow` | `3h` | Window for `OpenVoxCAUpstreamCRLFetchFailing`. A persistent fault's backoff is capped at `crl_chain.refresh_interval_sec`, so it steps once per interval, and `increase()` sees only the steps after its first sample: **keep it at least `(crlChainFetchFailureThreshold + 1) x refresh_interval_sec`**, and raise it with that setting, which the mixin cannot see. At `threshold x interval` or less a fault that never clears flaps; the extra interval is margin for retries that land a little more than an interval apart. A fault that starts after a clean round still fires at any interval, because the backoff restarts at 30 seconds, but the alert cannot hold: at this default, an interval of 90 minutes or more flaps, and one of three hours or more resolves while the fault persists. `(2 + 1) x 1h` at the defaults. |
| `clientCRLRefusalWindow` | `1h` | Window over which client-CRL refusals are counted. Event-driven, so unlike the gauge it is not coupled to `client_crl_refresh_interval_sec`. |
| `clientCRLUnusableFor` | `10m` | Shared `for:` debounce for `OpenVoxCAClientCRLUnusable`, `OpenVoxCAClientCRLRefusals` and `OpenVoxCAClientCRLStale`. Raising it to stop the gauge flapping across a refresh pass also delays the event-driven refusals page, which is the immediate one. For the *gauge* rule the detection latency is `client_crl_refresh_interval_sec` **plus** this, since the gauge is only recomputed on the refresh pass; the refusals rule is event-driven and not subject to that. |
| `clientCRLStaleSeconds` | `3h` | How long an entry may go without its `crl_file` being applied before `OpenVoxCAClientCRLStale` fires. Three refresh passes at the 1h default, so a single transient read error does not page — which means it assumes that default: **raise it alongside any increase to `client_crl_refresh_interval_sec`**, or the rule fires permanently on a healthy CA. |
| `leafExpiryWarningSeconds` | 7 days | Leaf certificate expiry warning threshold. |
| `leafExpiryCriticalSeconds` | 1 day | Leaf certificate expiry critical threshold. |
| `pendingFor` | `1h` | How long a request may stay pending before alerting. |
| `destructiveOpsWindow` | `5m` | Window over which `OpenVoxCADestructiveOperationsHigh` sums revocations and cleans across the CA's replicas. |
| `destructiveOpsThreshold` | `25` | Subjects revoked or cleaned within `destructiveOpsWindow` above which `OpenVoxCADestructiveOperationsHigh` fires: the server's per-client warning rate (more than 5 a minute) carried over to the whole CA on average. A burst of up to 25 in one minute stays under it, where the per-client warning fires at the sixth; lower it, or shorten `destructiveOpsWindow`, if that matters. Raise it where routine work cleans nodes in bulk. |
| `cleanFailureWindow` | `1h` | How long one failed clean step keeps `OpenVoxCACleanIncomplete` firing. |
| `signerUnresponsiveFor` | `5m` | `for:` dwell for `OpenVoxCASignerUnresponsive`. The frontend asks the signer once per scrape and waits five seconds, so one slow answer costs one scrape; this keeps that from paging. |
| `openBaoUnauthenticatedFor` | `5m` | `for:` dwell for `OpenVoxCAOpenBaoUnauthenticated`. The signer retries a failed login every five seconds, whether the login was its own or one a request prompted, so this is about sixty attempts. |
| `crlUpdateWindow` | `3h` | Window over which CRL-update failures are counted (the metric is a restart-resetting counter). The CRL refresh job takes the CRL lock and reads the stored CRL on every pass, so a CRL that stays unreadable, or whose lock cannot be taken, fails at least once per `crl_refresh_interval_sec` (1h by default); one that reads but cannot be written counts only when the CA tries to amend it. Keep the window at least `crlUpdateThreshold` + 1 intervals: at exactly the threshold a persistent fault flaps, and below it the alert never fires. Raise it alongside that setting. |
| `crlUpdateThreshold` | `2` | Failures within `crlUpdateWindow` before the CRL-update-failure alert fires. Above one so that a backend restart costing a single amendment stays silent. With `crl_chain.file` or `crl_chain.urls` set, that job counts into the same counter once per `crl_chain.refresh_interval_sec` — the file's refresh pass, or a fetch round whose merge failed, which waits the full interval rather than retrying sooner — so a restart that overlaps both it and the CRL refresh counts two and fires; set this to `3`, and `crlUpdateWindow` to `4h`, if you want those silent. Those numbers assume the hourly default: at a shorter interval that job counts more often (at 900 seconds, a storage outage longer than about 15 minutes reaches two from it alone), so raise the threshold to match. The one exception is a fresh store held unready for `crl_chain.urls`, whose failed merges keep the backoff a failed entry gets (30 seconds, doubling up to the interval): a restart there can count several. |
| `crlUpdateFor` | `15m` | `for:` debounce for the CRL-update-failure alert. Once the threshold is crossed `increase()` stays above it until the window passes the older failures, so this delays the alert rather than filtering a transient. |
| `crlSyncWindow` | `10m` | Window over which CRL-reload failures are counted (the metric is a restart-resetting counter). Keep it at least `crlSyncThreshold` + 1 times `crl_sync_interval_sec` (60s by default), and raise it alongside that setting, or the alert can never fire. |
| `crlSyncThreshold` | `3` | Failed reloads within `crlSyncWindow` before the CRL-reload-failure alert fires. A backend restart costs one; a replica holding a rotated CA certificate fails every pass. |
| `crlSyncFor` | `2m` | `for:` debounce for the CRL-reload-failure alert. Keep the threshold's intervals plus this below `crlLagFor`, so the warning precedes the page it explains. |
| `ocspIndexSyncWindow` | `30m` | Window over which OCSP-index-reload failures are counted (the metric is a restart-resetting counter). Keep it at least `ocspIndexSyncThreshold` + 1 times `ocsp_index_sync_interval_sec` (5m by default), and raise it alongside that setting, or the alert can never fire. |
| `ocspIndexSyncThreshold` | `3` | Failed passes within `ocspIndexSyncWindow` before the OCSP-index-reload-failure alert fires. A backend restart costs one. |
| `ocspIndexSyncFor` | `5m` | `for:` debounce for the OCSP-index-reload-failure alert. As with `crlUpdateFor`, this delays the alert once the threshold is crossed rather than filtering a transient. |
| `inventoryTamperWindow` | `1h` | Window over which inventory tamper detections are counted (the metric is a restart-resetting counter), and so how long one detection keeps `OpenVoxCAInventoryTampered` firing. Keep it at least twice `inventory_verify_interval_sec`: a persisting mismatch counts once per pass, and a window near the interval lets the alert resolve and re-fire between passes. |
| `inventoryUnreadableWindow` | `30m` | Window over which failed inventory reads by the periodic verification are counted. Must hold `inventoryUnreadableThreshold` + 1 intervals of `inventory_verify_interval_sec` (5m by default); widen it alongside a longer interval, or the alert can never fire. |
| `inventoryUnreadableThreshold` | `3` | Failed reads in the window that raise `OpenVoxCAInventoryUnreadable`. A backend restart costs one failed pass and a ten-minute outage two, so neither fires it; an inventory that cannot be read at all crosses it 10 to 15 minutes in. |
| `inventoryUnreadableFor` | `5m` | `for:` dwell for `OpenVoxCAInventoryUnreadable` once the threshold is crossed. It delays the warning; `increase()` then stays above the threshold until the window rolls past the oldest counted failure. |
| `crlLagFor` | `10m` | How long a replica may keep enforcing a CRL behind the stored one before it is paged on. Raise it if you have raised `crl_sync_interval_sec`. |
| `k8sExportNotRunningFor` | `30m` | How long a configured export target may go with no apply attempt at all before alerting. Only has to outlast a slow start: the counters reset on restart and the startup export runs immediately. |
| `k8sExportFailingFor` | `15m` | How long a target's most recent apply may stay failed before alerting. Keep it above the CA's export retry interval, a compile-time constant of two minutes: below that, every blip the retry would have cleared by itself pages. It cannot reach a target that fails once and succeeds on retry every cycle — see [metrics](../docs/metrics.md) for the query that can. |
| `fileExportStaleAfterSeconds` | 600 (10 minutes) | How long a file export target may go without a sync that confirms it current before `OpenVoxCAFileExportStale` counts it stale. The CA syncs every `file_export.interval_sec` (60s by default, at most 300s), so keep this at least twice that ceiling; a spec in `internal/fileexport` fails if it drops below. |
| `fileExportStaleFor` | `5m` | `for:` dwell on top of the threshold. Together they page 15 minutes after the last confirmed sync, and 5 minutes into a CA whose target has never synced. |
| `managedCertNeverIssuedFor` | `1h` | How long a configured managed certificate may go without ever being issued before alerting. Deliberately longer than one reconcile interval: every remedy is manual, and a certificate nothing has yet is not an emergency in the first hour of an install. Raise it if you have raised `managed_cert_interval_sec`. |
| `managedCertReissueFailingFor` | `30m` | How long a managed certificate's latest reconcile may stay failed before alerting. Outlasts one reconcile interval (`managed_cert_interval_sec`, 15 minutes by default) so the free retry of a single failure does not fire it; raise it if you raise that interval. |
| `supersedeWindow` | `1h` | Window over which supersession failures — immediate or delayed — are counted (the metric is a restart-resetting counter). |
| `supersedeFor` | `30m` | `for:` debounce for the supersession-failure alert. Longer than the CRL ones because the sweep retries on its own interval; raise it if you have raised `superseded_cert_sweep_interval_sec`. An immediate revocation is not retried, but one failure still holds the alert for the whole `supersedeWindow`, so it fires all the same. |
| `expiryFor` / `scrapeFor` / `readyFor` / `downFor` | `1h` / `15m` / `10m` / `5m` | `for:` debounce durations. Below `1h`, `expiryFor` lets an expiry alert fire on data the exporter is holding after a failed gather — see [When a gather fails](../docs/metrics.md#when-a-gather-fails). |
