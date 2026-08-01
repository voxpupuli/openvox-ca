{
  _config+:: {
    // puppetCASelector matches the Prometheus targets that scrape the
    // openvox-ca exporter. Override it to pin the alerts to a specific job,
    // namespace, or instance — e.g. 'job="openvox-ca",namespace="pki"'.
    puppetCASelector: 'job="openvox-ca"',

    // alertLabels are merged onto every alert (e.g. a team or severity routing
    // label). 'severity' is set per-alert below and should not be put here.
    alertLabels: {},

    // --- CA certificate expiry ---
    // Warn well ahead of CA expiry (re-keying a CA is disruptive); page when it
    // becomes urgent. Values are in seconds.
    caExpiryWarningSeconds: 30 * 24 * 3600,  // 30 days
    caExpiryCriticalSeconds: 7 * 24 * 3600,  // 7 days

    // --- CRL expiry ---
    // The CA auto-refreshes its CRL, so an approaching NextUpdate usually means
    // the refresher is wedged. Warn a few days out; page once it has lapsed.
    crlExpiryWarningSeconds: 3 * 24 * 3600,  // 3 days

    // --- Upstream CRL expiry ---
    // Deliberately not crlExpiryWarningSeconds. That threshold is short because
    // the CA refreshes its own CRL, so the alert only fires when something is
    // already wedged and three days is ample. An *upstream* CRL is the exact
    // opposite: openvox-ca cannot re-sign an ancestor's list, so clearing this
    // means a human fetching a new CRL from the parent CA — often a different
    // team — and updating crl_chain_file. Two weeks is notice for that, not
    // slack for a self-healing loop.
    upstreamCRLExpiryWarningSeconds: 14 * 24 * 3600,  // 14 days

    // --- Upstream CRL chain health ---
    // Calibrated to the CA's maintenance_interval_sec like the serving windows
    // above. All four chain counters increment per *evaluation*, and the file is
    // evaluated on every CRL amendment as well as on the maintenance pass, so on
    // a busy CA they track revocation rate. What this window is sized against is
    // the floor they share: a quiet CA evaluates the file once per maintenance
    // pass, and a window shorter than that interval makes a single unchanging
    // fault fire, resolve and re-fire forever. This equals the 1h default with no
    // margin, so raise it alongside any increase to maintenance_interval_sec.
    //
    // Do not assume an ordering between the four. An unreadable or unparseable
    // file increments the failure counter alone, because the read stops before
    // the per-CRL loops are reached.
    crlChainWindow: '1h',
    crlChainFor: '15m',

    // --- Leaf certificate expiry ---
    // Agents normally auto-renew; a leaf nearing expiry indicates a node that
    // has stopped checking in. Revoked certs are excluded by the alert exprs.
    leafExpiryWarningSeconds: 7 * 24 * 3600,  // 7 days
    leafExpiryCriticalSeconds: 24 * 3600,  // 1 day

    // --- Pending requests ---
    // How long a certificate request may sit unsigned before alerting. Set to a
    // larger value (or silence the alert) on CAs that sign manually by policy.
    pendingFor: '1h',

    // --- CRL update failures ---
    // The CA may fail to amend its CRL (a revocation it cannot record, or a CRL
    // it cannot re-sign or write). Some of these are best-effort and swallowed
    // — e.g. revoking the certificate a renewal supersedes — leaving the old
    // certificate valid for its key. The counter resets on restart, so the
    // alert looks at increase() over crlUpdateWindow and debounces with
    // crlUpdateFor.
    crlUpdateWindow: '1h',
    crlUpdateFor: '15m',

    // --- Self-provisioned serving certificate ---
    // The CA could not renew the certificate its own listener presents. The
    // exposure bound behind tls_self_provision_revoke_after_sec assumes renewals
    // succeed, so a replica failing this quietly is how a superseded certificate
    // stays valid past its intended window — and how the live one eventually
    // expires. Like the CRL counter, this resets on restart, so the alert looks
    // at increase() over a window.
    servingRenewalWindow: '1h',
    servingRenewalFor: '15m',

    // Superseded serving certificates that could not be revoked. Same shape as
    // the renewal window: the counter resets on restart, so alert on increase().
    servingRevocationWindow: '1h',
    servingRevocationFor: '15m',

    // Where the alert sends a paged responder. The cases differ in what can be
    // recovered and how, which is more than an annotation should carry -- and
    // keeping it here means one place to correct rather than two.
    servingRevocationRunbook:
      'https://github.com/voxpupuli/openvox-ca/blob/main/docs/metrics.md#superseded-serving-certificates',

    // Sustained reissue churn. One reissue per renewal period is normal; more
    // than a handful in six hours means replicas are minting over each other.
    //
    // Stated for operators in mixin/README.md, which is where anyone overriding
    // these will look; keep the two in step.
    // All three windows above are calibrated to the CA's maintenance_interval_sec,
    // which defaults to 1h and is operator-configurable. Raise them in step if
    // you raise that: the two 1h windows are knife-edge at the default (a
    // persistent failure resolves and re-fires between passes), and the churn
    // rule needs servingChurnWindow / maintenance_interval_sec to exceed
    // servingChurnThreshold or it can never fire at all -- at a 2h interval it
    // yields 3 increments against a threshold of 4, and the condition the
    // metric exists to expose becomes permanently invisible.
    servingChurnWindow: '6h',
    servingChurnThreshold: 4,
    servingChurnFor: '15m',

    // --- Kubernetes export ---
    // A target alerts while its most recent apply attempt failed (last-error
    // newer than last-success). Exports are event-driven and can be days apart
    // on a quiet CA, so the alert is stateful and stays firing until a retry
    // succeeds; 'for' only debounces a failure that is corrected moments later.
    k8sExportFailingFor: '15m',

    // 'for' durations applied to the expiry alerts to debounce flapping at the
    // threshold boundary.
    expiryFor: '1h',

    // --- Client trust domains ---
    // A domain with no usable CRL rejects every one of its clients under the
    // require policy, so this is an authentication outage rather than a
    // degradation. Debounced separately from the expiry alerts: those tolerate
    // an hour because expiry is gradual, while this one wants to fire promptly
    // and only needs to ride out a reload.
    clientCRLUnusableFor: '10m',

    // Window for PuppetCAClientCRLRefusals. Unlike the gauge this is
    // event-driven -- it moves when a client is actually refused -- so it is
    // sized like the other increase() windows rather than against the
    // maintenance interval.
    clientCRLRefusalWindow: '1h',
    scrapeFor: '15m',
    readyFor: '10m',
    downFor: '5m',
  },
}
