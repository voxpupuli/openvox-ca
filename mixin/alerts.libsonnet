{
  prometheusAlerts+:: {
    groups+: [
      {
        name: 'openvox-ca-availability',
        rules: [
          {
            alert: 'PuppetCAExporterDown',
            // 'up == 0' only matches an existing series; if the target is absent
            // from service discovery entirely there is no 'up' series to compare,
            // so OR in absent() to catch a wholly-missing exporter too.
            expr: |||
              up{%(selector)s} == 0
              or
              absent(up{%(selector)s})
            ||| % { selector: $._config.puppetCASelector },
            'for': $._config.downFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA metrics exporter is down.',
              description: 'Prometheus cannot scrape the Puppet CA exporter on {{ $labels.instance }}. Certificate and CRL expiry can no longer be monitored.',
            },
          },
          {
            alert: 'PuppetCAScrapeFailing',
            // The exporter answered but could not read CA state from storage.
            expr: 'puppetca_collector_scrape_success{%(selector)s} == 0' % { selector: $._config.puppetCASelector },
            'for': $._config.scrapeFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA exporter cannot read CA state.',
              description: 'The Puppet CA exporter on {{ $labels.instance }} is failing to gather certificate metrics from storage (puppetca_collector_scrape_success=0).',
            },
          },
          {
            alert: 'PuppetCANotReady',
            expr: 'puppetca_ca_ready{%(selector)s} == 0' % { selector: $._config.puppetCASelector },
            'for': $._config.readyFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is not ready.',
              description: 'The Puppet CA on {{ $labels.instance }} has been reporting not-ready (puppetca_ca_ready=0) and cannot serve signing requests.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-certificate-expiry',
        rules: [
          {
            alert: 'PuppetCACertificateExpiringSoon',
            expr: |||
              puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() < %(warn)d
              and
              puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() >= %(crit)d
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.caExpiryWarningSeconds,
              crit: $._config.caExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA certificate is approaching expiry.',
              description: 'The CA certificate ({{ $labels.common_name }}) on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}.',
            },
          },
          {
            alert: 'PuppetCACertificateExpiringCritical',
            expr: 'puppetca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() < %(crit)d' % {
              selector: $._config.puppetCASelector,
              crit: $._config.caExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA certificate expires imminently.',
              description: 'The CA certificate ({{ $labels.common_name }}) on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}. Re-keying the CA is disruptive; act now.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-crl-expiry',
        rules: [
          {
            alert: 'PuppetCACRLExpiringSoon',
            expr: |||
              puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() < %(warn)d
              and
              puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() > 0
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.crlExpiryWarningSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA CRL is approaching its NextUpdate.',
              description: 'The CRL on {{ $labels.instance }} reaches NextUpdate in {{ $value | humanizeDuration }}. The CA normally auto-refreshes it; check the CRL refresher.',
            },
          },
          {
            alert: 'PuppetCACRLExpired',
            expr: 'puppetca_crl_next_update_timestamp_seconds{%(selector)s} - time() <= 0' % { selector: $._config.puppetCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA CRL has expired.',
              description: 'The CRL on {{ $labels.instance }} is past its NextUpdate. Relying parties may reject it and fail revocation checks.',
            },
          },
        ],
      },
      {
        // Upstream CRLs are published by this CA but issued by an ancestor, so
        // they are a separate alert group with a separate runbook: openvox-ca
        // cannot reissue them, and the remedy is always at the parent CA. That
        // is also why they are a separate series rather than an issuer label on
        // puppetca_crl_next_update_timestamp_seconds — relabelling would have
        // made the two alerts above fire for CRLs their descriptions do not
        // describe and their remedies do not fix.
        name: 'openvox-ca-crl-chain',
        rules: [
          {
            alert: 'PuppetCAUpstreamCRLExpiringSoon',
            expr: |||
              puppetca_crl_chain_next_update_timestamp_seconds{%(selector)s} - time() < %(warn)d
              and
              puppetca_crl_chain_next_update_timestamp_seconds{%(selector)s} - time() > 0
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.upstreamCRLExpiryWarningSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'An upstream CRL published by the Puppet CA is approaching its NextUpdate.',
              description: 'The CRL issued by {{ $labels.issuer }} and republished by {{ $labels.instance }} reaches NextUpdate in {{ $value | humanizeDuration }}. openvox-ca cannot reissue it: refresh crl_chain_file from the issuing CA.',
            },
          },
          {
            alert: 'PuppetCAUpstreamCRLExpired',
            expr: 'puppetca_crl_chain_next_update_timestamp_seconds{%(selector)s} - time() <= 0' % { selector: $._config.puppetCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'An upstream CRL published by the Puppet CA has expired.',
              description: 'The CRL issued by {{ $labels.issuer }} and republished by {{ $labels.instance }} is past its NextUpdate. Agents using the default certificate_revocation = chain will fail verification against the whole chain. Refresh crl_chain_file from the issuing CA.',
            },
          },
          {
            alert: 'PuppetCAUpstreamCRLDiscarded',
            // The chain shrinking is not visible in the expiry series above:
            // a discarded CRL simply has no series at all. This is the only
            // signal that the published chain is smaller than crl_chain_file
            // says it should be.
            expr: 'increase(puppetca_crl_chain_discarded_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlChainWindow,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The Puppet CA is discarding CRLs from crl_chain_file.',
              description: '{{ $labels.instance }} dropped a CRL from crl_chain_file because no certificate in its CA bundle signed it, so the published chain is smaller than the file says. Check that the file holds CRLs from this CA\'s own ancestors and that the bundle is complete. If the file is stale rather than the bundle incomplete, PuppetCAUpstreamCRLRegressed is the alert for that.',
            },
          },
          {
            alert: 'PuppetCAUpstreamCRLRegressed',
            // Deliberately not folded into PuppetCAUpstreamCRLDiscarded. Both
            // mean "a CRL in the file was not published", and there the
            // similarity ends: a discard is fixed by completing the CA bundle,
            // a regression by fixing whatever writes the file. Sharing a counter
            // sent a paged responder to verify a bundle that was already
            // complete -- it has to be, or the CRL would have failed the
            // signature check long before this comparison.
            expr: 'increase(puppetca_crl_chain_regressed_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlChainWindow,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The Puppet CA is being offered stale upstream CRLs.',
              description: 'crl_chain_file on {{ $labels.instance }} carries an upstream CRL older than the one already published, so it was passed over and the newer one kept. Revocation is unaffected. The file is stale, rolled back or being replayed: check whatever refreshes it. If the ancestor legitimately restarted its CRL numbering (a CA rebuilt from backup, still using the same key), drop it from the file for one publish cycle and then add the new CRL back -- with nothing published to compare against, it is accepted. Publishing the older list would have un-revoked, fleet-wide, everything that ancestor revoked in between.',
            },
          },
          {
            alert: 'PuppetCAUpstreamCRLRemoved',
            // The most destructive outcome of the feature had the least
            // signal: every lesser one moved a counter, while dropping an
            // ancestor outright produced only a log line. It is not detectable
            // from the expiry gauges either -- those simply stop being
            // produced, and a vanished series fires nothing.
            expr: 'increase(puppetca_crl_chain_removed_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlChainWindow,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The Puppet CA has dropped an ancestor CRL from its published chain.',
              description: 'crl_chain_file on {{ $labels.instance }} stopped listing an ancestor whose CRL was published, so it has been dropped. The file is authoritative, so this is honoured -- and it cannot be undone here, because this CA cannot re-sign another CA\'s list. If you did not mean to remove it, check whatever writes the file: a glob that matched one file fewer produces exactly this. Agents on the default certificate_revocation = chain will stop seeing anything that ancestor revoked. Act on this when you see it rather than waiting: the removal is a single event, so this alert clears after the window closes even though the ancestor stays dropped, a restart zeroes the counter, and that ancestor\'s own expiry series has simply vanished. Nothing afterwards distinguishes the shrunken chain from a correct one.',
            },
          },
          {
            alert: 'PuppetCAUpstreamCRLNeverRead',
            // The darkest corner of the feature: a wrong path or a Secret that
            // never mounted is not a failure -- an absent file makes no
            // statement -- so no counter moves and every dashboard reads
            // healthy while the ancestors age out.
            //
            // This is expressible only because the series is exported wherever
            // crl_chain_file is *configured* rather than once it has been read;
            // gating on first read made absent() mean "never opened" and "not
            // using the feature" indistinguishably, so any alert on it fired
            // across the whole fleet.
            expr: 'puppetca_crl_chain_last_read_timestamp_seconds{%(selector)s} == 0' % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The Puppet CA has never read its configured crl_chain_file.',
              description: 'crl_chain_file is set on {{ $labels.instance }} but has never been opened -- a wrong path, or a Secret that never mounted. The feature is doing nothing, and because an absent file is treated as "no statement" rather than an error, nothing else reports it. Note this does not catch a subPath mount: that reads successfully forever, so it looks healthy here and shows up as PuppetCAUpstreamCRLExpiringSoon instead.',
            },
          },
          {
            alert: 'PuppetCAUpstreamCRLRefreshFailing',
            expr: 'increase(puppetca_crl_chain_refresh_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlChainWindow,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The Puppet CA cannot refresh its upstream CRL chain.',
              description: 'Refreshing crl_chain_file on {{ $labels.instance }} is failing, so the published ancestor CRLs are ageing with nothing renewing them. The existing chain is left in place; check the file is readable, parseable, ends on a PEM block boundary, and is under 4 MiB. Note this also blocks revocation until it is fixed.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-leaf-certificates',
        rules: [
          {
            alert: 'PuppetCALeafCertificateExpiringSoon',
            // state!="revoked" excludes certificates that have been revoked: a
            // revoked cert nearing expiry is expected and not actionable.
            expr: |||
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() < %(warn)d
              and
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() >= %(crit)d
            ||| % {
              selector: $._config.puppetCASelector,
              warn: $._config.leafExpiryWarningSeconds,
              crit: $._config.leafExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A leaf certificate is approaching expiry.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) expires in {{ $value | humanizeDuration }}. The node may have stopped renewing.',
            },
          },
          {
            alert: 'PuppetCALeafCertificateExpiringCritical',
            expr: |||
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() < %(crit)d
              and
              puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() > 0
            ||| % {
              selector: $._config.puppetCASelector,
              crit: $._config.leafExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'A leaf certificate expires imminently.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) expires in {{ $value | humanizeDuration }}.',
            },
          },
          {
            alert: 'PuppetCALeafCertificateExpired',
            expr: 'puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() <= 0' % { selector: $._config.puppetCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A non-revoked leaf certificate has expired.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) on {{ $labels.instance }} has expired but is not revoked.',
            },
          },
          {
            alert: 'PuppetCACertificateRequestPending',
            expr: 'puppetca_leaf_certificate_info{%(selector)s,state="requested"} == 1' % { selector: $._config.puppetCASelector },
            'for': $._config.pendingFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A certificate request has been pending too long.',
              description: 'The request for {{ $labels.subject }} on {{ $labels.instance }} has been awaiting signing for more than %(pendingFor)s.' % { pendingFor: $._config.pendingFor },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-crl-maintenance',
        rules: [
          {
            alert: 'PuppetCACRLUpdateFailing',
            // The CA failed to amend the CRL — a CRL it could not re-sign,
            // write or read, on any of the four paths that write one (revoke,
            // reissue, refresh or expired-cert cleanup). Some callers swallow
            // this (e.g. the best-effort revoke of a superseded cert on
            // renewal), so a revoked/superseded certificate may remain valid.
            // Not every revocation that missed the CRL lands here, and which
            // ones do depends on the backend: one refused at a cross-node lock
            // acquisition fails ahead of any CRL work and is logged only, while
            // on filesystem/SQLite a revocation that merely queued behind an
            // issuance past lockTimeout fails at its first storage read and is
            // counted — a benign cause worth ruling out first on those
            // backends. See docs/metrics.md. The counter resets on restart, so
            // alert on increase() over a window rather than a raw value.
            expr: 'increase(puppetca_crl_update_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlUpdateWindow,
            },
            'for': $._config.crlUpdateFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is failing to update its CRL.',
              description: 'The Puppet CA on {{ $labels.instance }} could not amend its CRL (puppetca_crl_update_failures_total is rising). Revocations may not have taken effect and superseded certificates may still be valid. Check the CA logs to tell the causes apart: "Renew:"/"AutoRenew: failed to revoke replaced certificate"/"Clean:" warnings are a real failure to maintain the CRL, and on filesystem or SQLite a "Revoke failed" warning on a request that took over a minute is instead a revocation that merely queued too long for its subject lock. Then check CRL storage.',
            },
          },
          {
            alert: 'PuppetCACRLSyncFailing',
            // This replica could not reload the stored CRL into the copy its
            // revocation checks read: an unreadable CRL, or one signed by a
            // different CA certificate than the one this process loaded (the
            // usual cause of the latter is a rotated CA certificate on a replica
            // that has not restarted). Counter resets on restart, so alert on
            // increase() over a window. It leads the lag alert below by design —
            // this says why a replica is falling behind, that one says it has.
            expr: 'increase(puppetca_crl_sync_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlSyncWindow,
            },
            'for': $._config.crlSyncFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA cannot reload its CRL from storage.',
              description: 'The Puppet CA on {{ $labels.instance }} could not reload the stored CRL (puppetca_crl_sync_failures_total is rising), so it is enforcing whichever CRL it already held. A certificate revoked on another replica may still be accepted here. Check CRL storage, and whether the CA certificate was replaced without restarting this replica.',
            },
          },
          {
            alert: 'PuppetCACRLStale',
            // The revocation list this replica enforces is behind the stored
            // one. Every replica polls storage on crl_sync_interval_sec, so a
            // gap is normal for a moment after each revocation and abnormal
            // beyond crlLagFor.
            //
            // Both series come from the same exporter, so this compares an
            // instance against itself rather than against the fleet — no fan-in,
            // and it fires on the replica that is actually stale. Subtracting
            // rather than comparing makes $value the size of the gap; a bare
            // '>' would report the stored number instead.
            //
            // The second arm exists because the two series go missing for
            // different reasons, and a subtraction over a missing operand is
            // silence rather than an alert. The exporter drops
            // puppetca_crl_number whenever the stored CRL cannot be read or
            // parsed, while still publishing the cached number — and an
            // unreadable stored CRL is one of the two conditions this rule is
            // meant to page on, so without the arm the worst case would be the
            // quiet one.
            //
            // It is qualified on a successful scrape so that arm covers only
            // the CRL being unreadable, not the whole gather failing: a storage
            // outage drops the same series and is already paged by
            // PuppetCAScrapeFailing, and one cause should not raise two alerts.
            // The reverse asymmetry (cached absent, stored present) means the
            // replica has no CRL in memory at all and is covered by
            // PuppetCANotReady, so it is deliberately left out.
            expr: |||
              puppetca_crl_number{%(selector)s} - puppetca_crl_cached_number{%(selector)s} > 0
              or
              (puppetca_crl_cached_number{%(selector)s}
                 unless puppetca_crl_number{%(selector)s})
                and on(instance) puppetca_collector_scrape_success{%(selector)s} == 1
            ||| % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.crlLagFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA replica is enforcing an out-of-date CRL.',
              description: 'The Puppet CA on {{ $labels.instance }} has not caught up with the CRL in storage for more than %(crlLagFor)s, so certificates revoked on another replica are still being accepted here. Either it is behind the stored CRL, or the stored CRL cannot be read at all (in which case puppetca_crl_number is absent for this instance). Check puppetca_crl_sync_failures_total and the CA logs. A restart reloads the CRL, selecting the newest block this CA signed; if the stored chain carries none, startup warns and the re-sign paths refuse it, so check the stored chain rather than restarting repeatedly.' % { crlLagFor: $._config.crlLagFor },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-kubernetes-export',
        rules: [
          {
            alert: 'PuppetCAKubernetesExportFailing',
            // The most recent apply attempt for a target failed. Exports are
            // event-driven (startup and CRL updates) and can be days apart on
            // a quiet CA, so this compares last-error/last-success timestamps
            // — a state that persists until a retry succeeds — rather than a
            // rate window, which would silently resolve between attempts. The
            // 'unless' arm catches a target that has never succeeded at all.
            expr: |||
              puppetca_k8s_export_last_error_timestamp_seconds{%(selector)s}
                > puppetca_k8s_export_last_success_timestamp_seconds{%(selector)s}
              or
              puppetca_k8s_export_last_error_timestamp_seconds{%(selector)s}
                unless puppetca_k8s_export_last_success_timestamp_seconds{%(selector)s}
            ||| % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.k8sExportFailingFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A Kubernetes export target is failing to apply.',
              description: 'The most recent apply of {{ $labels.kind }}/{{ $labels.name }} in namespace {{ $labels.namespace }} from {{ $labels.instance }} failed; the exported object may hold a stale CA certificate or CRL until the next successful export. Check the CA logs, RBAC, and API server connectivity.',
            },
          },
        ],
      },
    ],
  },
}
