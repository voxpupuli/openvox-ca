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
    // Calibrated to the CA's crl_chain_refresh_interval_sec. All four chain
    // counters increment per *evaluation*, and the file is evaluated on every
    // CRL amendment as well as on each refresh pass, so on a busy CA they track
    // revocation rate. What the window is sized against is the floor they
    // share: a quiet CA evaluates the file once per refresh pass, so raise this
    // alongside any increase to crl_chain_refresh_interval_sec.
    //
    // Twice the interval, not equal to it. At exactly one interval a persistent
    // fault flaps: consecutive increments sit one window apart, so the last
    // sample carrying the older value ages out of the range before the next
    // increment lands, increase() reads 0 for a scrape or two, the alert
    // resolves and its `for` starts again from zero. Tick drift widens that gap
    // rather than closing it. Doubling the window keeps two increments in range
    // throughout, at the cost of an alert that takes an interval longer to
    // clear once the fault is fixed.
    //
    // Do not assume an ordering between the four. An unreadable or unparseable
    // file increments the failure counter alone, because the read stops before
    // the per-CRL loops are reached.
    crlChainWindow: '2h',
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

    // --- CRL propagation across replicas ---
    // Each replica decides revocation from its own in-memory copy of the CRL
    // and reloads it on a timer (crl_sync_interval_sec, 60s by default), so
    // puppetca_crl_cached_number trails puppetca_crl_number for a moment after
    // every revocation. crlLagFor is how long a replica may keep trailing
    // before that counts as stuck rather than in flight: comfortably longer
    // than the sync interval, and short enough that a revocation is still an
    // incident response rather than a wait. Raise it if you have lengthened the
    // interval. While a replica lags, a certificate revoked elsewhere is still
    // accepted there, which is why that alert pages rather than warns.
    crlLagFor: '10m',

    // Failures to reload the CRL from storage. Same shape as the CRL-update
    // alert — a counter that resets on restart, so increase() over a window.
    // Deliberately shorter than crlLagFor: both symptoms of a stuck replica
    // start at the same instant, so the warning that explains why only reaches
    // the operator before the page it explains if it debounces for less time.
    crlSyncWindow: '1h',
    crlSyncFor: '5m',

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

    // How long a client_ca entry may go without its crl_file being applied
    // before that is worth saying. Three maintenance passes at the 1h default,
    // so a single transient read error does not page.
    clientCRLStaleSeconds: 3 * 3600,
    scrapeFor: '15m',
    readyFor: '10m',
    downFor: '5m',
  },
}
