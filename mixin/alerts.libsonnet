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
              description: 'An ancestor CRL has been dropped from the published chain on {{ $labels.instance }}. The file is authoritative, so this is honoured -- and it cannot be undone here, because this CA cannot re-sign another CA\'s list. There are two ways to reach this. Either the file stopped listing the ancestor -- check whatever writes it, since a glob that matched one file fewer produces exactly this -- or the ancestor\'s own certificate has left the stored CA bundle, so nothing signs its CRL any more and it can no longer be published; the log line says which, and the second is fixed by re-importing the bundle rather than by touching the file. Agents on the default certificate_revocation = chain will stop seeing anything that ancestor revoked. Act on this when you see it rather than waiting: the removal is a single event, so this alert clears after the window closes even though the ancestor stays dropped, a restart zeroes the counter, and that ancestor\'s own expiry series has simply vanished. Nothing afterwards distinguishes the shrunken chain from a correct one.',
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
        // client_revocation_policy=require turns "no usable CRL" into a
        // rejection of every client of that domain, and the operator's first
        // symptom is otherwise an agent-side 403 whose cause is three layers
        // away. The two outage rules are critical for that reason: each is an
        // authentication outage scoped to one issuer, not a degradation. The
        // staleness rule is a warning -- nothing is being refused yet, but the
        // CRLs in use have stopped being refreshed.
        name: 'openvox-ca-client-crl',
        rules: [
          {
            alert: 'PuppetCAClientCRLUnusable',
            // A plain == 0 is sufficient because the gauge is published on
            // every reload branch, including a failed one — see
            // refreshClientCRLs. It used to be skipped when the load failed,
            // which meant the series was never created for a domain whose very
            // first load failed, and `== 0` cannot fire on a series that does
            // not exist.
            expr: 'puppetca_client_crl_usable{%(selector)s} == 0' % { selector: $._config.puppetCASelector },
            'for': $._config.clientCRLUnusableFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'A Puppet CA client trust domain has no usable CRL.',
              description: 'client_ca {{ $labels.client_ca }} on {{ $labels.instance }} holds no currently valid CRL at all — every CRL expired, every one was discarded as unverifiable, or every one was discarded as partial-scope (a delta CRL, or one scoped to an issuing distribution point, which lists only a fraction of what its issuer has revoked). Under client_revocation_policy=require every client of that issuer is rejected. Refresh its crl_file from the issuing CA, and if the delivery was recently changed check the server log for discard warnings — a full CRL is required here, since this CA is handed a file and fetches no distribution points. Note this fires only on total loss: a domain holding one anchor\'s CRL and not another\'s reads healthy here, and shows up as PuppetCAClientCRLRefusals instead.',
            },
          },
          {
            alert: 'PuppetCAClientCRLStale',
            // The retain-previous branches are right for availability and
            // invisible everywhere else: the kept CRLs are still current, so
            // the gauge reads 1, and clients are still served, so no refusal is
            // counted. What has stopped is the file being applied, so
            // revocations published since are not honoured -- for as long as
            // the retained CRLs remain within their nextUpdate, which is days.
            expr: 'time() - puppetca_client_crl_last_reload_timestamp_seconds{%(selector)s} > %(stale)d' % {
              selector: $._config.puppetCASelector,
              stale: $._config.clientCRLStaleSeconds,
            },
            'for': $._config.clientCRLUnusableFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The Puppet CA has stopped applying a trust domain\'s crl_file.',
              description: 'crl_file for client_ca {{ $labels.client_ca }} on {{ $labels.instance }} has not been applied for {{ $value | humanizeDuration }}. The previous CRLs are still in use and still current, so nothing else reports a problem -- but revocations published since are not being honoured. Check the server log for a reload error, or for a reload refused because it would have covered fewer anchors than the set in use, dropped an enforced partial CRL, moved an anchor backwards to an older CRL, or could not be shown to be newer at all because this server will not date the CRLs it holds for that anchor -- check this server\'s clock and the issuer\'s.',
            },
          },
          {
            alert: 'PuppetCAClientCRLRefusals',
            // The unambiguous half. The gauge above can only estimate coverage
            // at load time -- which anchors matter depends on chains that have
            // not arrived -- so a partially covered entry reads healthy there.
            // This counts clients actually turned away, so it sees the partial
            // case, and it needs no approximation to do it.
            expr: 'increase(puppetca_client_crl_refusals_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.clientCRLRefusalWindow,
            },
            'for': $._config.clientCRLUnusableFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'The Puppet CA is refusing clients of a trust domain for want of a CRL.',
              description: 'client_ca {{ $labels.client_ca }} on {{ $labels.instance }} is refusing clients because revocation information was missing: an issuer in their chain has no currently valid CRL, or the presented certificate is itself one of the entry\'s anchors, which nothing can attest to. Unlike the gauge this is a fact rather than an estimate: these are requests that were turned away. The usual cause is an anchor whose CRL is missing or expired while the entry\'s other anchors are fine, or an entry anchored on a shared root whose intermediates cannot have their CRLs verified — see the crl_file notes in the configuration guide.',
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
            // ones do depends on the backend: one refused at a lock
            // acquisition fails ahead of any CRL work and is logged only —
            // every backend's cross-node acquisition, and on filesystem/SQLite
            // a wait for another process on the host — while on
            // filesystem/SQLite a revocation that merely queued behind an
            // issuance in this same process past lockTimeout fails at its first
            // storage read and is counted: a benign cause worth ruling out
            // first on those backends. See docs/metrics.md. The counter resets on restart, so
            // alert on increase() over a window rather than a raw value.
            expr: 'increase(puppetca_crl_update_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.crlUpdateWindow,
            },
            'for': $._config.crlUpdateFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is failing to update its CRL.',
              description: 'The Puppet CA on {{ $labels.instance }} could not amend its CRL (puppetca_crl_update_failures_total is rising). Revocations may not have taken effect and superseded certificates may still be valid. Check the CA logs to tell the causes apart: "Renew:"/"AutoRenew:"/"ReconcileManaged: failed to retire replaced certificate"/"Clean:" warnings are a real failure to maintain the CRL, and on filesystem or SQLite a "Revoke failed" warning on a request that took over a minute is instead a revocation that merely queued too long for its subject lock. The superseded-certificate sweep re-signs once per pass rather than once per due entry, so a failing sweep moves this counter once however many certificates were due: read a rising value as a count of failed CRL amendments, not of certificates left unrevoked, and use puppetca_supersede_pending for those. Then check CRL storage.',
            },
          },
          {
            alert: 'PuppetCASupersedeFailing',
            // A certificate a renewal replaced is still a valid credential,
            // because the CA could not schedule or carry out its delayed
            // revocation: a supersession the renewal path could not record, a
            // pending-revocation list it could not read or parse, or a sweep
            // pass that left an entry unrevoked or discarded one whose serial it
            // could never revoke. Live on any CA that renews certificates,
            // since superseded_cert_revoke_after_sec defaults to 24h; only
            // where it is 0 does the revocation happen inside the renewal, and
            // a failure there is a CRL failure counted by the alert above.
            // Even then the sweep, every renewal and every subject revocation
            // read the pending list whatever the setting says, so a store that
            // cannot serve that key fires this with the window closed too.
            // Counter resets on restart, so alert on increase() over a window.
            expr: 'increase(puppetca_supersede_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.supersedeWindow,
            },
            'for': $._config.supersedeFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA is failing to revoke superseded certificates.',
              description: 'The Puppet CA on {{ $labels.instance }} could not schedule or carry out the revocation of a certificate a renewal replaced (puppetca_supersede_failures_total is rising), so that certificate is still a valid credential. Check the CA logs to tell the causes apart: "Superseded-certificate revocation sweep failed" means the sweep could not read the list, take the CRL lock or write the list back, which is the likeliest cause and blocks every pending revocation at once; "failed to retire replaced certificate" means the supersession was never recorded and the serial is in the warning; "Could not revoke superseded certificates" means they were recorded but the sweep could not amend the CRL; it re-signs once for the whole pass, so every entry that pass attempted stays listed and is retried together; "Discarding" means the entry is gone and will never be retried. A store that cannot serve the superseded key raises this even where the overlap window is closed (superseded_cert_revoke_after_sec: 0) — look for "cannot determine supersession status" or "Revoke: could not read pending supersessions", which also mean renewals are being refused. Retire anything the sweep will not with openvox-ca-ctl revoke --serial <hex>. puppetca_supersede_pending shows how many are still waiting.',
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
            alert: 'PuppetCAOCSPIndexSyncFailing',
            // This replica could not reload the inventory into the serial index
            // its OCSP responder answers from: an unreadable inventory, or one
            // whose integrity MAC no longer verifies. While it rises the
            // responder answers "unknown" for every certificate a peer has
            // signed since the last successful pass.
            //
            // Not fail-open — "unknown" is not "good", and the mTLS admission
            // path reads the CRL rather than this index — so it is a warning
            // rather than a critical. It is still worth paging on: a verifier
            // that hard-fails on "unknown" rejects against this replica and no
            // other, which is a split that is unpleasant to diagnose from the
            // client end. Counter resets on restart, hence increase().
            //
            // The fleet-relative comparison of puppetca_ocsp_index_serials is
            // deliberately not shipped: it needs a by (job) aggregation to
            // avoid fanning in across unrelated CAs, and a replica reading
            // above its peers is a deferred removal rather than a fault. See
            // docs/metrics.md for the query to add by hand.
            expr: 'increase(puppetca_ocsp_index_sync_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.puppetCASelector,
              window: $._config.ocspIndexSyncWindow,
            },
            'for': $._config.ocspIndexSyncFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Puppet CA cannot reload its OCSP serial index from storage.',
              description: 'The Puppet CA on {{ $labels.instance }} could not reload the inventory into its OCSP serial index (puppetca_ocsp_index_sync_failures_total is rising), so it is answering "unknown" for certificates its peers have signed since the last successful pass. Check inventory storage, and the inventory integrity MAC if the logs report a mismatch.',
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
            // event-driven (startup, CRL updates, and a retry after a failed
            // cycle) and can be days apart on a quiet CA, so this compares
            // last-error/last-success timestamps — a state that persists until
            // a retry succeeds — rather than a rate window, which would
            // silently resolve between attempts. The 'unless' arm catches a
            // target that has never succeeded at all.
            //
            // What that design cannot see, stated here because understanding
            // why it is right is exactly what stops you noticing: a target
            // that fails and then recovers on retry, every cycle, never fires
            // this rule. The CA retries a failed cycle after two minutes, so
            // last_success overtakes last_error well inside k8sExportFailingFor
            // and the state never holds for 'for'. That silence is deliberate
            // and was ruled on: a failure a retry resolves is transient, and
            // flapping should not page. The uncovered case is the target that
            // fails on its first attempt every single cycle -- it is being
            // exported, just never first time. Catching it needs a different
            // rule, counting advances of last_error over a window rather than
            // comparing it to last_success; do not reach for a longer 'for'
            // here, which makes this rule fire less, not more. Meanwhile
            // puppetca_k8s_export_applies_total{result="error"} counts every
            // failed attempt whether or not a retry rescued it, and
            // docs/metrics.md carries the query.
            //
            // Both arms have last_error on the left, so this rule can only fire
            // for a target the exporter has actually written a series for. That
            // is a contract on the exporter, not an accident: ExportAll must
            // record a metric for every target on every cycle, whatever failed
            // upstream. It once returned before the per-target loop when a
            // material read failed, which wrote no series at all and made this
            // alert unable to report the very outage it exists for.
            // PuppetCAKubernetesExportNotRunning below is the backstop for that
            // whole class, and mixin/tests.yaml exercises both.
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
          {
            alert: 'PuppetCAKubernetesExportNotRunning',
            // A configured target that has never been attempted at all. This
            // is where the two export rules' division of labour is argued;
            // ExportAll and InitTargetMetrics in internal/k8sexport state the
            // invariant they enforce and point here. The separate decision to
            // leave the last_success/last_error gauges unpublished is argued
            // where it is made, at initTargets in internal/k8sexport/metrics.go
            // and, for operators, in docs/metrics.md.
            //
            // Every arm of PuppetCAKubernetesExportFailing has last_error on
            // its left, so that rule can only speak about a target the CA has
            // recorded a result for. It is structurally silent when the CA
            // records nothing — and no PromQL comparison matches an absence, so
            // no reshaping of that expression can fix it from this side. The
            // answer has to come from the CA: publish a series for a target
            // that has done nothing, and "nothing has happened" becomes a value
            // that can be tested.
            //
            // So the CA publishes puppetca_k8s_export_applies_total at zero for
            // every configured target before the first cycle runs, and also on
            // the path where the export gives up before starting — an
            // in-cluster client it cannot build, a pod namespace it cannot
            // resolve. That path is the one worth the trouble: the CA stays up,
            // readiness stays green, the exported objects quietly stop being
            // updated, and a single log line is otherwise the only trace.
            //
            // `without (result)` rather than a `by` allowlist. Both collapse
            // the success/error pair, but an allowlist also discards every
            // label it does not name -- and under the chart's own defaults the
            // label it would keep is not the one it looks like. The shipped
            // ServiceMonitor sets honorLabels: false, so Prometheus resolves
            // the collision on `namespace` in the target's favour and renames
            // the exporter's to `exported_namespace`. A `by (… namespace …)`
            // clause would then group on the CA pod's namespace, identical for
            // every target, and drop the export namespace entirely -- so two
            // targets differing only by namespace, which is the documented way
            // to publish one trust bundle into several, would share a group and
            // an attempted sibling would mask a never-attempted one. `without`
            // keeps whatever labels the deployment actually attached, and
            // leaves this rule carrying the same label set as
            // PuppetCAKubernetesExportFailing so the pair routes and silences
            // alike.
            //
            // Collapsing 'result' means a target that is attempted and always
            // fails is not caught here
            // (that is Failing's job, and the two cannot both fire: a zero sum
            // means no result was ever recorded, so there is no last_error for
            // Failing to match). Only a target attempted zero times matches.
            // The counter resets to zero on restart and the startup export runs
            // immediately, so k8sExportNotRunningFor only has to outlast a slow
            // start.
            //
            // It does not cover a crashlooping CA, and must not be read as
            // doing so. A pod that keeps restarting fails scrapes; Prometheus
            // writes staleness markers, the instance stops being returned, and
            // this rule's 'for' clock resets rather than accumulating. That is
            // PuppetCAExporterDown's job (downFor, 5m), and it is the better
            // alert for it. What this rule covers is the opposite shape: a CA
            // that stays up, scrapes cleanly, and reports readiness while its
            // export job does nothing.
            expr: |||
              sum without (result) (
                puppetca_k8s_export_applies_total{%(selector)s}
              ) == 0
            ||| % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.k8sExportNotRunningFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A Kubernetes export target has never been attempted.',
              description: 'The Puppet CA on {{ $labels.instance }} has {{ $labels.kind }}/{{ $labels.name }} in namespace {{ $labels.namespace }} configured for export but has not attempted a single apply in %(k8sExportNotRunningFor)s. The exported object holds whatever it held before, and PuppetCAKubernetesExportFailing cannot report on a target with no apply results. Check the CA logs for the Kubernetes export job starting, and for errors initialising the in-cluster client.' % { k8sExportNotRunningFor: $._config.k8sExportNotRunningFor },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-managed-certificates',
        rules: [
          {
            alert: 'PuppetCAManagedCertificateNeverIssued',
            // A configured managed certificate that has never produced a
            // certificate at all -- a store that has never accepted a write.
            //
            // Everything else about a managed certificate is an ordinary
            // certificate fact. Once one exists it has an inventory row and the
            // leaf series cover its expiry, so the shipped expiry alerts cover
            // it with nothing new. This is the one outcome that reasoning
            // cannot reach, and for the same structural reason
            // PuppetCAKubernetesExportNotRunning exists: there is no series for
            // a certificate that does not exist, and no PromQL comparison
            // matches an absence. The answer has to come from the CA, which
            // publishes its configuration so that "nothing has happened" is a
            // value.
            //
            // `max without (serial, state)` rather than `unless on (subject)`.
            // Both collapse the leaf series' per-certificate labels, but
            // `on (subject)` also discards every target label, so one replica's
            // certificate would satisfy another replica's entry -- and a
            // replica whose configuration differs from its siblings' is exactly
            // the case worth catching. `without` keeps whatever labels the
            // deployment attached, so the two sides match per scrape target.
            //
            // A revoked certificate still emits its leaf series, so this stays
            // silent for an entry whose certificate was revoked and is awaiting
            // reissue. That is deliberate: the next reconcile pass replaces it,
            // and alerting inside one interval would fire on the mechanism
            // working.
            //
            // It does not cover a crashlooping CA and must not be read as
            // doing so -- that is PuppetCAExporterDown's job. What it covers is
            // a CA that stays up, scrapes cleanly and reports readiness while
            // a certificate something else is waiting for never appears.
            //
            // Qualified on a successful scrape, the same way PuppetCACRLStale
            // is and for the same reason. The two sides of the `unless` come
            // from different places: the configured series is built from the
            // in-process configuration and is published even when the gather
            // fails, deliberately, so that a CA which cannot reach storage
            // still reports what it is meant to be keeping alive. The leaf
            // series are read from storage and all vanish together. So during a
            // storage outage the left side stands and the right side is empty,
            // and without this qualifier every configured entry would match --
            // healthy ones included -- an hour into an outage that
            // PuppetCAScrapeFailing has already been paging for. One cause
            // should not raise two alerts, and the second one here would name
            // the wrong remedy: it would send an operator to check RBAC and
            // store permissions for certificates that exist and are fine.
            expr: |||
              (
                puppetca_managed_certificate_configured{%(selector)s}
                  unless
                max without (serial, state) (
                  puppetca_leaf_certificate_not_after_timestamp_seconds{%(selector)s}
                )
              )
              and on(instance) puppetca_collector_scrape_success{%(selector)s} == 1
            ||| % {
              selector: $._config.puppetCASelector,
            },
            'for': $._config.managedCertNeverIssuedFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A managed certificate has never been issued.',
              description: 'The Puppet CA on {{ $labels.instance }} has {{ $labels.subject }} configured in managed_certs but no certificate for it exists after %(managedCertNeverIssuedFor)s. Whatever depends on that certificate has nothing to present. Check the CA logs for the managed-certificate reconcile pass and for the store it writes to -- a Secret refused by RBAC, an unadoptable Secret holding somebody else\'s material, or a directory that does not exist.' % { managedCertNeverIssuedFor: $._config.managedCertNeverIssuedFor },
            },
          },
        ],
      },
    ],
  },
}
