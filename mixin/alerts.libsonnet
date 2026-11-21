{
  prometheusAlerts+:: {
    groups+: [
      {
        name: 'openvox-ca-availability',
        rules: [
          {
            alert: 'OpenVoxCAExporterDown',
            // 'up == 0' only matches an existing series; if the target is absent
            // from service discovery entirely there is no 'up' series to compare,
            // so OR in absent() to catch a wholly-missing exporter too.
            expr: |||
              up{%(selector)s} == 0
              or
              absent(up{%(selector)s})
            ||| % { selector: $._config.openvoxCASelector },
            'for': $._config.downFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA metrics exporter is down.',
              description: 'Prometheus cannot scrape the OpenVox CA exporter on {{ $labels.instance }}. Certificate and CRL expiry can no longer be monitored.',
            },
          },
          {
            alert: 'OpenVoxCAScrapeFailing',
            // The exporter answered but could not read CA state from storage.
            expr: 'openvoxca_collector_scrape_success{%(selector)s} == 0' % { selector: $._config.openvoxCASelector },
            'for': $._config.scrapeFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA exporter cannot read CA state.',
              description: 'The OpenVox CA exporter on {{ $labels.instance }} is failing to gather certificate metrics from storage (openvoxca_collector_scrape_success=0).',
            },
          },
          {
            alert: 'OpenVoxCANotReady',
            expr: 'openvoxca_ca_ready{%(selector)s} == 0' % { selector: $._config.openvoxCASelector },
            'for': $._config.readyFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA is not ready.',
              description: 'The OpenVox CA on {{ $labels.instance }} has been reporting not-ready (openvoxca_ca_ready=0) and cannot serve signing requests.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-administrative-activity',
        rules: [
          {
            alert: 'OpenVoxCADestructiveOperationsHigh',
            // Subjects revoked or cleaned through the API, summed across the
            // CA's replicas: a compromised administrator credential spreads
            // across them as easily as across one. By job and namespace so
            // that two CAs under one selector are judged apart. The log line
            // naming the client is the server's "High rate of destructive
            // operations detected" warning, which works per client per
            // replica; this works on the whole CA, because a label per client
            // would be unbounded.
            //
            // No `for`: a burst is an event, and increase() over the window
            // keeps it up for as long as the burst is in range.
            expr: |||
              sum by (job, namespace) (
                increase(openvoxca_destructive_operations_total{%(selector)s}[%(window)s])
              ) > %(threshold)d
            ||| % {
              selector: $._config.openvoxCASelector,
              window: $._config.destructiveOpsWindow,
              threshold: $._config.destructiveOpsThreshold,
            },
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'Many certificates are being revoked or cleaned.',
              description: 'The OpenVox CA ({{ $labels.job }}) revoked or cleaned {{ $value | humanize }} subjects in the last %(window)s (openvoxca_destructive_operations_total). That is a compromised administrator credential or an operational mistake. The "High rate of destructive operations detected" warnings in the CA log name the client; see docs/ca-key-security.md.' % {
                window: $._config.destructiveOpsWindow,
              },
            },
          },
          {
            alert: 'OpenVoxCACleanIncomplete',
            // A clean answers success whichever of its steps failed, so this
            // is the only signal that one left something behind. Fires on one
            // failure, by step, since the remedies differ: on revoke the
            // deleted certificate is still a valid credential, on a delete
            // the subject cannot enrol again.
            expr: 'increase(openvoxca_clean_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.openvoxCASelector,
              window: $._config.cleanFailureWindow,
            },
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A clean left something behind.',
              description: 'The OpenVox CA on {{ $labels.instance }} reported a clean as successful while its {{ $labels.step }} step failed (openvoxca_clean_failures_total). After a failed revoke the deleted certificate stays a valid credential until it expires: revoke it by serial. After a failed delete the subject cannot enrol again: clean it once more. The "Clean:" warnings in the CA log name the subject; see docs/api.md.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-key-backend',
        rules: [
          {
            alert: 'OpenVoxCAOpenBaoUnauthenticated',
            // The signer's most recent login to OpenBao failed, so no new
            // token can be had, and issuance, CRL re-signing and OCSP fail once
            // the one in hand expires. It retries every five seconds, so the
            // gauge returns to 1 by itself once a login can succeed. The
            // series exists only where the CA key is an OpenBao Transit key,
            // so this is silent everywhere else. In the default topology it
            // comes from the signer over its Metrics RPC, so a signer that
            // has stopped answering leaves it absent rather than 0, and
            // OpenVoxCASignerUnresponsive below is what fires then.
            expr: 'openvoxca_openbao_authenticated{%(selector)s} == 0' % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.openBaoUnauthenticatedFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA cannot log in to OpenBao.',
              description: 'The OpenVox CA signer on {{ $labels.instance }} has been unable to log in to OpenBao for %(for)s (openvoxca_openbao_authenticated=0). Once its current token expires it cannot sign certificates, CRLs or OCSP responses. Check that OpenBao is reachable and that the source credential (AppRole secret_id, Kubernetes service account or token file) is still valid; see docs/openbao-transit.md.' % {
                'for': $._config.openBaoUnauthenticatedFor,
              },
            },
          },
          {
            alert: 'OpenVoxCASignerUnresponsive',
            // The isolated signer is running but has stopped answering the
            // frontend. Its process_* series are read from /proc by the
            // frontend and so outlive it; its go_* series come over the same
            // RPC as its signatures, with a five-second deadline, and are left
            // out of every scrape it does not answer. A process present with
            // no runtime is a signer that is alive and not responding, which
            // nothing else reports: readiness does not consult the signer, a
            // stalled signature fails only after two minutes and no alert
            // reads that failure, and the CRL refresh notices hours later. A signer that
            // exits takes the frontend with it, which is the launcher's to
            // report, not this rule's.
            //
            // For every key backend. Silent under --single-process, which has
            // no signer role, and on a frontend started without the
            // launcher, which has no signer PID to read /proc from.
            //
            // It joins on instance, so it assumes one instance per pod or
            // process, as the chart's ServiceMonitor gives by default.
            // Relabelling that collapses replicas onto one instance would let
            // a healthy replica's signer mask another's.
            expr: |||
              process_start_time_seconds{%(selector)s,role="signer"}
                unless on(job, instance)
              go_goroutines{%(selector)s,role="signer"}
            ||| % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.signerUnresponsiveFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA signer has stopped answering.',
              description: 'The isolated signer on {{ $labels.instance }} is running but has not answered the frontend for %(for)s: its process series are present and its go_* series, which come over the same connection as its signatures, are not. It cannot be relied on to sign certificates, CRLs or OCSP responses. The frontend logs "Could not read another process\'s Go runtime metrics" with the error on each scrape; restarting the CA restarts the signer. See docs/metrics.md.' % {
                'for': $._config.signerUnresponsiveFor,
              },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-certificate-expiry',
        rules: [
          {
            alert: 'OpenVoxCACertificateExpiringSoon',
            // The expiry series carries no common_name; the info series beside
            // it does, and is published from the same in-memory certificate,
            // so the join cannot drop an alert the expiry alone would raise.
            // Without it the description rendered "The CA certificate ()".
            // ignoring() rather than on(job, instance): it matches on every
            // label the two series share, whatever the scrape adds (cluster,
            // namespace, pod), so a ruler that sees two targets with one job
            // and instance still evaluates the rule instead of refusing the
            // join as many-to-many.
            expr: |||
              (
                openvoxca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() < %(warn)d
                and
                openvoxca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() >= %(crit)d
              )
              * ignoring(common_name, serial, issuer) group_left(common_name)
              openvoxca_ca_certificate_info{%(selector)s}
            ||| % {
              selector: $._config.openvoxCASelector,
              warn: $._config.caExpiryWarningSeconds,
              crit: $._config.caExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA certificate is approaching expiry.',
              description: 'The CA certificate ({{ $labels.common_name }}) on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}.',
            },
          },
          {
            alert: 'OpenVoxCACertificateExpiringCritical',
            // Joined to the info series for common_name, as above.
            expr: |||
              (
                openvoxca_ca_certificate_not_after_timestamp_seconds{%(selector)s} - time() < %(crit)d
              )
              * ignoring(common_name, serial, issuer) group_left(common_name)
              openvoxca_ca_certificate_info{%(selector)s}
            ||| % {
              selector: $._config.openvoxCASelector,
              crit: $._config.caExpiryCriticalSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA certificate expires imminently.',
              description: 'The CA certificate ({{ $labels.common_name }}) on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}. Re-keying the CA is disruptive; act now.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-crl-expiry',
        rules: [
          {
            alert: 'OpenVoxCACRLExpiringSoon',
            expr: |||
              openvoxca_crl_next_update_timestamp_seconds{%(selector)s} - time() < %(warn)d
              and
              openvoxca_crl_next_update_timestamp_seconds{%(selector)s} - time() > 0
            ||| % {
              selector: $._config.openvoxCASelector,
              warn: $._config.crlExpiryWarningSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA CRL is approaching its NextUpdate.',
              description: 'The CRL on {{ $labels.instance }} reaches NextUpdate in {{ $value | humanizeDuration }}. The CA normally auto-refreshes it; check the CRL refresher.',
            },
          },
          {
            alert: 'OpenVoxCACRLExpired',
            expr: 'openvoxca_crl_next_update_timestamp_seconds{%(selector)s} - time() <= 0' % { selector: $._config.openvoxCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA CRL has expired.',
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
        // openvoxca_crl_next_update_timestamp_seconds — relabelling would have
        // made the two alerts above fire for CRLs their descriptions do not
        // describe and their remedies do not fix.
        name: 'openvox-ca-crl-chain',
        rules: [
          {
            alert: 'OpenVoxCAUpstreamCRLExpiringSoon',
            // Fires once less than max(fraction x lifetime, floor) remains.
            // The "> floor or floor" pair is that max: the first arm keeps the
            // fraction where it is larger, and the second supplies the floor
            // for every series the first dropped, including one with no
            // thisUpdate series beside it (a CA from before it was exported).
            expr: |||
              openvoxca_crl_chain_next_update_timestamp_seconds{%(selector)s} - time()
                < (
                    %(fraction)g * (
                      openvoxca_crl_chain_next_update_timestamp_seconds{%(selector)s}
                      - openvoxca_crl_chain_this_update_timestamp_seconds{%(selector)s}
                    ) > %(floor)d
                  or
                    0 * openvoxca_crl_chain_next_update_timestamp_seconds{%(selector)s} + %(floor)d
                )
              and
              openvoxca_crl_chain_next_update_timestamp_seconds{%(selector)s} - time() > 0
            ||| % {
              selector: $._config.openvoxCASelector,
              fraction: $._config.upstreamCRLExpiryWarningFraction,
              floor: $._config.upstreamCRLExpiryWarningSeconds,
            },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'An upstream CRL published by the OpenVox CA is approaching its NextUpdate.',
              description: 'The CRL issued by {{ $labels.issuer }} and republished by {{ $labels.instance }} reaches NextUpdate in {{ $value | humanizeDuration }}. openvox-ca cannot reissue it: get a current one from the issuing CA, through crl_chain.urls or crl_chain.file.',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLExpired',
            expr: 'openvoxca_crl_chain_next_update_timestamp_seconds{%(selector)s} - time() <= 0' % { selector: $._config.openvoxCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'An upstream CRL published by the OpenVox CA has expired.',
              description: 'The CRL issued by {{ $labels.issuer }} and republished by {{ $labels.instance }} is past its NextUpdate. Agents using the default certificate_revocation = chain will fail verification against the whole chain. Get a current CRL from the issuing CA, through crl_chain.urls or crl_chain.file.',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLDiscarded',
            // The chain shrinking is not visible in the expiry series above:
            // a discarded CRL simply has no series at all. For crl_chain.file
            // this is the only signal that the published chain is smaller than
            // the file says it should be. A crl_chain.urls entry's discard keeps
            // the ancestor's published CRL, and counts as that entry's fetch
            // failure too, so OpenVoxCAUpstreamCRLFetchFailing names its URL.
            expr: 'increase(openvoxca_crl_chain_discarded_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.openvoxCASelector,
              window: $._config.crlChainWindow,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA is discarding upstream CRLs it was given.',
              description: '{{ $labels.instance }} dropped an upstream CRL from crl_chain.file or crl_chain.urls because no certificate in its CA bundle signed it, or because it is a delta or IDP-scoped CRL rather than its issuer\'s full list; the CA log says which. From crl_chain.file, the published chain is then smaller than the file says; from a crl_chain.urls entry, that ancestor\'s published CRL is kept, and OpenVoxCAUpstreamCRLFetchFailing names the entry. Check that they hold CRLs from this CA\'s own ancestors and that the bundle is complete. If the source is stale rather than the bundle incomplete, OpenVoxCAUpstreamCRLRegressed is the alert for that.',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLRegressed',
            // Deliberately not folded into OpenVoxCAUpstreamCRLDiscarded. Both
            // mean "a CRL from crl_chain.file or a crl_chain.urls entry was not
            // published", and there the similarity ends: a discard is fixed by
            // completing the CA bundle, a regression by fixing whatever
            // refreshes the source. Sharing a counter
            // sent a paged responder to verify a bundle that was already
            // complete -- it has to be, or the CRL would have failed the
            // signature check long before this comparison.
            expr: 'increase(openvoxca_crl_chain_regressed_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.openvoxCASelector,
              window: $._config.crlChainWindow,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA is being offered stale upstream CRLs.',
              description: 'An upstream CRL offered to {{ $labels.instance }} -- by crl_chain.file, or by a crl_chain.urls entry -- is older than the one already published, so it was passed over and the newer one kept. Revocation is unaffected. The source is stale, rolled back or being replayed: check whatever refreshes the file, or the upstream behind the URL, which OpenVoxCAUpstreamCRLFetchFailing names. If the ancestor legitimately restarted its CRL numbering (a CA rebuilt from backup, still using the same key), drop it from the publish for one cycle and then add it back -- with nothing published to compare against, it is accepted. For crl_chain.file, drop it from the file. For crl_chain.urls, remove its entry, and any mirror of it; the removal then needs an authoritative round -- every entry yielding its issuer\'s full CRL, every entry over https:// or file:///, none serving this CA\'s own CRL, no two naming the same ancestor -- and a list with an http:// entry never has one, so see configuration.md#fetching-upstream-crls for retiring an ancestor from such a list. Publishing the older list would have un-revoked, fleet-wide, everything that ancestor revoked in between. On a CA with several replicas and mirror entries for one ancestor, a short burst of regressions just after the upstream republishes -- re-counted by the fetch job\'s retries until the mirror catches up -- is a mirror a few minutes behind, and needs nothing unless it persists.',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLRemoved',
            // The most destructive outcome of the feature had the least
            // signal: every lesser one moved a counter, while dropping an
            // ancestor outright produced only a log line. It is not detectable
            // from the expiry gauges either -- those simply stop being
            // produced, and a vanished series fires nothing.
            expr: 'increase(openvoxca_crl_chain_removed_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.openvoxCASelector,
              window: $._config.crlChainWindow,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA has dropped an ancestor CRL from its published chain.',
              description: 'An ancestor CRL has been dropped from the published chain on {{ $labels.instance }}. The configured source is authoritative, so this is honoured -- and it cannot be undone here, because this CA cannot re-sign another CA\'s list. It happens one of three ways, and the log line says which: crl_chain.file stopped listing the ancestor (check whatever writes the file -- a glob that matched one file fewer produces exactly this); an authoritative crl_chain.urls round, meaning every entry yielded its issuer\'s full CRL, every entry was fetched over https:// or file:///, none served this CA\'s own CRL and no two named the same ancestor, no longer served it (check the URL list was meant to lose it); or the ancestor\'s own certificate has left the stored CA bundle, so nothing signs its CRL any more (re-import the bundle; the file and the URL list are not at fault). Agents on the default certificate_revocation = chain will stop seeing anything that ancestor revoked. Act on this when you see it rather than waiting: the removal is a single event, so this alert clears after the window closes even though the ancestor stays dropped, a restart zeroes the counter, and that ancestor\'s own expiry series has simply vanished. Nothing afterwards distinguishes the shrunken chain from a correct one.',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLNeverRead',
            // The darkest corner of the feature: a wrong path or a Secret that
            // never mounted is not a failure -- an absent file makes no
            // statement -- so no counter moves and every dashboard reads
            // healthy while the ancestors age out.
            //
            // This is expressible only because the series is exported wherever
            // crl_chain.file is *configured* rather than once it has been read;
            // gating on first read made absent() mean "never opened" and "not
            // using the feature" indistinguishably, so any alert on it fired
            // across the whole fleet.
            expr: 'openvoxca_crl_chain_last_read_timestamp_seconds{%(selector)s} == 0' % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA has never read its configured crl_chain.file.',
              description: 'crl_chain.file is set on {{ $labels.instance }} but has never been opened -- a wrong path, or a Secret that never mounted. The feature is doing nothing, and because an absent file is treated as "no statement" rather than an error, nothing else reports it. Note this does not catch a subPath mount: that reads successfully forever, so it looks healthy here and shows up as OpenVoxCAUpstreamCRLExpiringSoon instead.',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLRefreshFailing',
            expr: 'increase(openvoxca_crl_chain_refresh_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.openvoxCASelector,
              window: $._config.crlChainWindow,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA cannot refresh its upstream CRL chain.',
              description: 'Refreshing crl_chain.file on {{ $labels.instance }} is failing, so the published ancestor CRLs are ageing with nothing renewing them. The existing chain is left in place; check the file is readable, parseable, ends on a PEM block boundary, and is under 4 MiB. Note this also blocks revocation until it is fixed.',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLFetchFailing',
            // Counts every round in which an entry yielded nothing usable,
            // including a transfer that succeeded: a 200 carrying an error
            // page, the wrong issuer's CRL, a stale mirror's or an expired one.
            // Those are exactly the failures nothing else reports: the published
            // chain keeps what it had, and readiness, once released, never
            // turns red again.
            expr: 'increase(openvoxca_crl_chain_fetch_failures_total{%(selector)s}[%(window)s]) >= %(threshold)d' % {
              selector: $._config.openvoxCASelector,
              window: $._config.crlChainFetchWindow,
              threshold: $._config.crlChainFetchFailureThreshold,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA cannot get a usable upstream CRL from one of its crl_chain.urls.',
              description: '{{ $labels.instance }} is not getting a usable, current CRL from {{ $labels.url }}. The CA log names the reason: a connection or HTTP failure, a response that is not exactly one CRL, one over 4 MiB as received or a CRL over 4 MiB as PEM, a CRL nothing in the CA bundle signed, a delta or IDP-scoped CRL, one older than the CRL already published, an expired one, or this CA\'s own CRL. If every entry fails at once while each fetches cleanly, look for the log line \"The upstream CRLs from crl_chain.urls would make the published chain too large\": if it is there, the CRLs together would exceed 4 MiB and the round was refused as a whole. On a CA with several replicas and mirror entries, one short burst just after an upstream republishes is a mirror catching up with the CRL another replica already published. The published chain keeps what it had for that ancestor -- unless the entry served an expired CRL that is still newer, which is published anyway as strictly better -- and revocation is unaffected.',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLNeverFetched',
            // The series is exported at 0 for every configured entry from
            // startup, so this distinguishes "never succeeded" from "not
            // configured", as OpenVoxCAUpstreamCRLNeverRead does for the file.
            //
            // crlChainFor's 15 minutes, deliberately, not a window of hours
            // like its neighbours: on a store that already holds a chain --
            // the usual switchover from crl_chain.file -- the pod is ready
            // either way, so this is the only timely signal of a typo, a wrong
            // issuer path or a TLS failure in the new list.
            expr: 'openvoxca_crl_chain_fetch_last_success_timestamp_seconds{%(selector)s} == 0' % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA has never fetched a usable CRL from one of its crl_chain.urls.',
              description: '{{ $labels.instance }} has not had a usable CRL from {{ $labels.url }} since it started. Check the URL, the NetworkPolicy egress to it, and crl_chain.http_config; the CA log names the reason. On a store with no upstream CRL at all, this CA is also being held unready until a fetch round stores one. If every crl_chain.urls entry on this instance is affected at once and OpenVoxCAUpstreamCRLFetchFailing is silent, the fetches are fine and the merge is failing: see OpenVoxCACRLUpdateFailing and the CA log line "Could not merge fetched upstream CRLs".',
            },
          },
          {
            alert: 'OpenVoxCAUpstreamCRLFetchStale',
            // Fires on age alone, so it catches a fetch that has stopped
            // counting anything, which the failure alert cannot. The expiry
            // alerts are measured from nextUpdate and, against a long-lived
            // upstream CRL, stay silent for days after fetching stops.
            expr: |||
              time() - openvoxca_crl_chain_fetch_last_success_timestamp_seconds{%(selector)s} > %(stale)d
              and
              openvoxca_crl_chain_fetch_last_success_timestamp_seconds{%(selector)s} > 0
            ||| % {
              selector: $._config.openvoxCASelector,
              stale: $._config.crlChainFetchStaleSeconds,
            },
            'for': $._config.crlChainFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'An upstream CRL from crl_chain.urls has not been refreshed recently.',
              description: '{{ $labels.instance }} last had a usable CRL from {{ $labels.url }} {{ $value | humanizeDuration }} ago. The published copy is still being served, so nothing fails until that CRL reaches its nextUpdate; find out why the entry stopped delivering before it does. OpenVoxCAUpstreamCRLFetchFailing says why, if failures are being counted. If every crl_chain.urls entry on this instance is affected at once and OpenVoxCAUpstreamCRLFetchFailing is silent, the fetches are fine and the merge is failing: see OpenVoxCACRLUpdateFailing and the CA log line "Could not merge fetched upstream CRLs".',
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
            alert: 'OpenVoxCAClientCRLUnusable',
            // A plain == 0 is sufficient because the gauge is published on
            // every reload branch, including a failed one — see
            // refreshClientCRLs. It used to be skipped when the load failed,
            // which meant the series was never created for a domain whose very
            // first load failed, and `== 0` cannot fire on a series that does
            // not exist.
            expr: 'openvoxca_client_crl_usable{%(selector)s} == 0' % { selector: $._config.openvoxCASelector },
            'for': $._config.clientCRLUnusableFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'An OpenVox CA client trust domain has no usable CRL.',
              description: 'client_ca {{ $labels.client_ca }} on {{ $labels.instance }} holds no currently valid CRL at all — every CRL expired, every one was discarded as unverifiable, or every one was discarded as partial-scope (a delta CRL, or one scoped to an issuing distribution point, which lists only a fraction of what its issuer has revoked). Under client_revocation_policy=require every client of that issuer is rejected. Refresh its crl_file from the issuing CA, and if the delivery was recently changed check the server log for discard warnings — a full CRL is required here, since this CA is handed a file and fetches no distribution points. Note this fires only on total loss: a domain holding one anchor\'s CRL and not another\'s reads healthy here, and shows up as OpenVoxCAClientCRLRefusals instead.',
            },
          },
          {
            alert: 'OpenVoxCAClientCRLStale',
            // The retain-previous branches are right for availability and
            // invisible everywhere else: the kept CRLs are still current, so
            // the gauge reads 1, and clients are still served, so no refusal is
            // counted. What has stopped is the file being applied, so
            // revocations published since are not honoured -- for as long as
            // the retained CRLs remain within their nextUpdate, which is days.
            expr: 'time() - openvoxca_client_crl_last_reload_timestamp_seconds{%(selector)s} > %(stale)d' % {
              selector: $._config.openvoxCASelector,
              stale: $._config.clientCRLStaleSeconds,
            },
            'for': $._config.clientCRLUnusableFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA has stopped applying a trust domain\'s crl_file.',
              description: 'crl_file for client_ca {{ $labels.client_ca }} on {{ $labels.instance }} has not been applied for {{ $value | humanizeDuration }}. The previous CRLs are still in use and still current, so nothing else reports a problem -- but revocations published since are not being honoured. Check the server log for a reload error, or for a reload refused because it would have covered fewer anchors than the set in use, dropped an enforced partial CRL, moved an anchor backwards to an older CRL, or could not be shown to be newer at all because this server will not date the CRLs it holds for that anchor -- check this server\'s clock and the issuer\'s.',
            },
          },
          {
            alert: 'OpenVoxCAClientCRLRefusals',
            // The unambiguous half. The gauge above can only estimate coverage
            // at load time -- which anchors matter depends on chains that have
            // not arrived -- so a partially covered entry reads healthy there.
            // This counts clients actually turned away, so it sees the partial
            // case, and it needs no approximation to do it.
            expr: 'increase(openvoxca_client_crl_refusals_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.openvoxCASelector,
              window: $._config.clientCRLRefusalWindow,
            },
            'for': $._config.clientCRLUnusableFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'The OpenVox CA is refusing clients of a trust domain for want of a CRL.',
              description: 'client_ca {{ $labels.client_ca }} on {{ $labels.instance }} is refusing clients because revocation information was missing: an issuer in their chain has no currently valid CRL, or the presented certificate is itself one of the entry\'s anchors, which nothing can attest to. Unlike the gauge this is a fact rather than an estimate: these are requests that were turned away. The usual cause is an anchor whose CRL is missing or expired while the entry\'s other anchors are fine, or an entry anchored on a shared root whose intermediates cannot have their CRLs verified — see the crl_file notes in the configuration guide.',
            },
          },
        ],
      },
      {
        name: 'openvox-ca-leaf-certificates',
        rules: [
          {
            alert: 'OpenVoxCALeafCertificateExpiringSoon',
            // state!="revoked" excludes certificates that have been revoked: a
            // revoked cert nearing expiry is expected and not actionable.
            expr: |||
              openvoxca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() < %(warn)d
              and
              openvoxca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() >= %(crit)d
            ||| % {
              selector: $._config.openvoxCASelector,
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
            alert: 'OpenVoxCALeafCertificateExpiringCritical',
            expr: |||
              openvoxca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() < %(crit)d
              and
              openvoxca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() > 0
            ||| % {
              selector: $._config.openvoxCASelector,
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
            alert: 'OpenVoxCALeafCertificateExpired',
            expr: 'openvoxca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,state!="revoked"} - time() <= 0' % { selector: $._config.openvoxCASelector },
            'for': $._config.expiryFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A non-revoked leaf certificate has expired.',
              description: 'Certificate for {{ $labels.subject }} (serial {{ $labels.serial }}) on {{ $labels.instance }} has expired but is not revoked.',
            },
          },
          {
            alert: 'OpenVoxCACertificateRequestPending',
            expr: 'openvoxca_leaf_certificate_info{%(selector)s,state="requested"} == 1' % { selector: $._config.openvoxCASelector },
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
            alert: 'OpenVoxCACRLUpdateFailing',
            // The CA failed to amend the CRL — a CRL it could not re-sign,
            // write or read, on any of the eight paths that write one (see
            // crl_update_failures_total in docs/metrics.md: the crl_chain.urls
            // merge and the crl_chain.file refresh among them). Some callers
            // swallow this (e.g. the best-effort revoke of a superseded cert on
            // renewal), so a revoked/superseded certificate may remain valid.
            // Not every revocation that missed the CRL lands here, and which
            // ones do depends on the backend: one refused at a lock
            // acquisition fails ahead of any CRL work and is not counted here
            // — every backend's cross-node acquisition, and on filesystem/SQLite
            // a wait for another process on the host. Where the CA swallows
            // such a failure it is counted elsewhere: the renewal and reissue
            // retire steps on openvoxca_supersede_failures_total
            // (OpenVoxCASupersedeFailing), a clean's revoke step on
            // openvoxca_clean_failures_total (OpenVoxCACleanIncomplete). Meanwhile on
            // filesystem/SQLite a revocation that merely queued behind an
            // issuance in this same process past lockTimeout fails at its first
            // storage read and is counted: a benign cause worth ruling out
            // first on those backends. See docs/metrics.md. The counter resets on restart, so
            // alert on increase() over a window rather than a raw value, and
            // on crlUpdateThreshold failures rather than one: a backend
            // restart costs a single failed amendment, and config.libsonnet
            // explains why a fault that persists still crosses the threshold.
            expr: 'increase(openvoxca_crl_update_failures_total{%(selector)s}[%(window)s]) >= %(threshold)d' % {
              selector: $._config.openvoxCASelector,
              window: $._config.crlUpdateWindow,
              threshold: $._config.crlUpdateThreshold,
            },
            'for': $._config.crlUpdateFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA is failing to update its CRL.',
              description: 'The OpenVox CA on {{ $labels.instance }} could not amend its CRL %(threshold)d or more times in %(window)s (openvoxca_crl_update_failures_total); a single failure during a backend restart does not fire this. Revocations may not have taken effect and superseded certificates may still be valid. Check the CA logs to tell the causes apart: "Renew:"/"AutoRenew:"/"ReconcileManaged: failed to retire replaced certificate"/"Clean:" warnings are a real failure to maintain the CRL, and on filesystem or SQLite a "Revoke failed" warning on a request that took over a minute is instead a revocation that merely queued too long for its subject lock. The superseded-certificate sweep re-signs once per step of up to 100 due entries rather than once per entry, and stops at the first step it cannot write, so a failing sweep moves this counter once however many certificates were due: read a rising value as a count of failed CRL amendments, not of certificates left unrevoked, and use openvoxca_supersede_pending for those. A log line containing "behind a priority caller" from the CRL refresh, the crl_chain.file refresh, the crl_chain.urls merge or the expired-certificate cleanup is a background job that stood aside for foreground CRL work for its whole 15s budget, and is not a storage fault unless that foreground work is itself failing (look for "Revoke failed" warnings at the same time). With several replicas sweeping a large backlog at once, a step can also run out of its wait behind other replicas\' steps; that warning names the lock it was acquiring rather than a priority caller, and is contention, not a fault, while other replicas log cleanup or sweep progress. With crl_chain.urls or crl_chain.file set, "Could not merge fetched upstream CRLs into the published chain" or "Could not refresh the upstream CRL chain" is that job\'s pass failing, once per crl_chain.refresh_interval_sec. Then check CRL storage.' % {
                threshold: $._config.crlUpdateThreshold,
                window: $._config.crlUpdateWindow,
              },
            },
          },
          {
            alert: 'OpenVoxCASupersedeFailing',
            // A certificate a renewal or a managed certificate's reissue
            // replaced is still a valid credential, because the CA could not
            // retire it: an immediate revocation that failed (where
            // superseded_cert_revoke_after_sec, or the entry's revoke_after, is
            // 0), a supersession the renewal path could not record, a
            // pending-revocation list it could not read or parse, or a sweep
            // pass that left an entry unrevoked or discarded one whose serial it
            // could never revoke. Live on any CA that renews certificates. The
            // immediate arm is here, and not left to the CRL alert above,
            // because that one needs crlUpdateThreshold failures in its window
            // and never sees the CRL lock arm; nothing retries an immediate
            // revocation, so one failure is a certificate left valid (#679).
            // The same holds for a managed reissue's revocation of a
            // certificate it signed and could not store, which counts here too.
            // The sweep, every renewal and every subject revocation read the
            // pending list whatever the setting says, so a store that cannot
            // serve that key fires this with the window closed too.
            // Counter resets on restart, so alert on increase() over a window.
            expr: 'increase(openvoxca_supersede_failures_total{%(selector)s}[%(window)s]) > 0' % {
              selector: $._config.openvoxCASelector,
              window: $._config.supersedeWindow,
            },
            'for': $._config.supersedeFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA is failing to revoke superseded certificates.',
              description: 'The OpenVox CA on {{ $labels.instance }} could not retire a certificate that a renewal or a managed certificate\'s reissue replaced (openvoxca_supersede_failures_total is rising), so that certificate is still a valid credential. Check the CA logs to tell the causes apart: "Superseded-certificate revocation sweep failed" means the sweep could not read the list, take the CRL lock or write the list back, which is the likeliest cause and blocks every pending revocation at once; if that warning also contains "behind a priority caller", the sweep stood aside for foreground CRL work (revocations, cleans and reissues) for its whole 15s budget, which is not a storage fault unless that foreground work is itself failing (look for "Revoke failed" warnings at the same time), and the next pass retries the entries; with several replicas sweeping a large backlog at once, a step can also run out of its wait behind other replicas\' steps; that warning names the lock it was acquiring rather than a priority caller, and is contention, not a fault, while other replicas log cleanup or sweep progress; "failed to retire replaced certificate" means the supersession was never recorded or, with the window closed, the immediate revocation failed, and the serial is in the warning; "could not be stored and could not then be revoked" means a managed reissue could not revoke the certificate it had just signed, and names its serial; "Could not revoke superseded certificates" means they were recorded but the sweep could not amend the CRL; it re-signs once per step of up to 100 due entries and stops at the first step it cannot write, so every entry still due stays listed and is retried on the next pass; "Discarding" means the entry is gone and will never be retried. A store that cannot serve the superseded key raises this even where the overlap window is closed (superseded_cert_revoke_after_sec: 0) — look for "cannot determine supersession status" or "Revoke: could not read pending supersessions", which also mean renewals are being refused. Retire anything the sweep will not with openvox-ca-ctl revoke --serial <hex>. openvoxca_supersede_pending shows how many are still waiting.',
            },
          },
          {
            alert: 'OpenVoxCACRLSyncFailing',
            // This replica could not reload the stored CRL into the copy its
            // revocation checks read: an unreadable CRL, or one signed by a
            // different CA certificate than the one this process loaded (the
            // usual cause of the latter is a rotated CA certificate on a replica
            // that has not restarted). Counter resets on restart, so alert on
            // increase() over a window, and on crlSyncThreshold failures in it:
            // a backend restart costs one failed pass, which the next repairs,
            // while the rotated certificate fails every pass. It leads the lag
            // alert below by design — this says why a replica is falling
            // behind, that one says it has.
            expr: 'increase(openvoxca_crl_sync_failures_total{%(selector)s}[%(window)s]) >= %(threshold)d' % {
              selector: $._config.openvoxCASelector,
              window: $._config.crlSyncWindow,
              threshold: $._config.crlSyncThreshold,
            },
            'for': $._config.crlSyncFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA cannot reload its CRL from storage.',
              description: 'The OpenVox CA on {{ $labels.instance }} could not reload the stored CRL %(threshold)d or more times in %(window)s (openvoxca_crl_sync_failures_total), so it is enforcing whichever CRL it already held; a single failure during a backend restart does not fire this. A certificate revoked on another replica may still be accepted here. Check CRL storage, and whether the CA certificate was replaced without restarting this replica.' % {
                threshold: $._config.crlSyncThreshold,
                window: $._config.crlSyncWindow,
              },
            },
          },
          {
            alert: 'OpenVoxCAOCSPIndexSyncFailing',
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
            // client end. Counter resets on restart, hence increase(), and it
            // takes ocspIndexSyncThreshold failures in the window: a backend
            // restart costs one failed pass, which the next repairs.
            //
            // Live only while enable_ocsp serves the responder. With it off the
            // job does not run and the counter is not exported, so this rule
            // matches nothing, which is right: there is no index to fall behind.
            //
            // The fleet-relative comparison of openvoxca_ocsp_index_serials is
            // deliberately not shipped: it needs a by (job) aggregation to
            // avoid fanning in across unrelated CAs, and a replica reading
            // above its peers is a deferred removal rather than a fault. See
            // docs/metrics.md for the query to add by hand.
            expr: 'increase(openvoxca_ocsp_index_sync_failures_total{%(selector)s}[%(window)s]) >= %(threshold)d' % {
              selector: $._config.openvoxCASelector,
              window: $._config.ocspIndexSyncWindow,
              threshold: $._config.ocspIndexSyncThreshold,
            },
            'for': $._config.ocspIndexSyncFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA cannot reload its OCSP serial index from storage.',
              description: 'The OpenVox CA on {{ $labels.instance }} could not reload the inventory into its OCSP serial index %(threshold)d or more times in %(window)s (openvoxca_ocsp_index_sync_failures_total), so it is answering "unknown" for certificates its peers have signed since the last successful pass; a single failure during a backend restart does not fire this. Check inventory storage, and the inventory integrity MAC if the logs report a mismatch.' % {
                threshold: $._config.ocspIndexSyncThreshold,
                window: $._config.ocspIndexSyncWindow,
              },
            },
          },
          {
            alert: 'OpenVoxCAInventoryTampered',
            // The periodic inventory verification found the stored integrity
            // value (whole-blob HMAC or hash-chain head) no longer matching the
            // inventory: rows were added, removed or edited behind the CA's
            // back. It runs on every backend whatever enable_ocsp says, which
            // the OCSP index sync never did.
            //
            // Keyed on reason="tampered" only. reason="read_error" is an
            // inventory that could not be read at all, a different problem
            // with its own warning below, and paging it as tampering would
            // teach operators to ignore this one.
            //
            // No `for`: a mismatch is not transient, and one pass is enough.
            // increase() over the window latches it until the window rolls past
            // the last failed pass, so a single detection is not missed by
            // somebody who looks a few minutes late.
            expr: 'increase(openvoxca_inventory_verify_failures_total{%(selector)s,reason="tampered"}[%(window)s]) > 0' % {
              selector: $._config.openvoxCASelector,
              window: $._config.inventoryTamperWindow,
            },
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA inventory failed its integrity check.',
              description: 'The OpenVox CA on {{ $labels.instance }} found that its certificate inventory no longer matches its stored integrity value (openvoxca_inventory_verify_failures_total{reason="tampered"} is rising): rows were added, removed or edited outside the CA. Treat the inventory as untrusted. The CA logs carry the scheme and a repair hint on the "inventory HMAC mismatch" line; see docs/metrics.md#inventory-verification, and docs/operator-cli.md (rebuild-inventory-hmac) for the way back once the cause is known.',
            },
          },
          {
            alert: 'OpenVoxCAInventoryUnreadable',
            // The periodic inventory verification could not read the
            // inventory at all, so nothing is checking it. Its own rule
            // because on the filesystem backend nothing else sees this:
            // readiness reflects only the CA's key and certificate in memory,
            // and the scrape does not read the inventory there. On the
            // structured backends the scrape reads it through the certificate
            // index, so OpenVoxCAScrapeFailing fires too, but names the gather
            // rather than the inventory.
            //
            // A warning, on inventoryUnreadableThreshold failures in the
            // window rather than one: a backend restart costs the job one
            // failed pass, which the next repairs, while an inventory that
            // cannot be read fails every pass. config.libsonnet sizes the
            // window. The counter resets on restart, hence increase().
            expr: 'increase(openvoxca_inventory_verify_failures_total{%(selector)s,reason="read_error"}[%(window)s]) >= %(threshold)d' % {
              selector: $._config.openvoxCASelector,
              window: $._config.inventoryUnreadableWindow,
              threshold: $._config.inventoryUnreadableThreshold,
            },
            'for': $._config.inventoryUnreadableFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA cannot read its inventory to verify it.',
              description: 'The OpenVox CA on {{ $labels.instance }} could not read its certificate inventory for the periodic integrity check %(threshold)d or more times in %(window)s (openvoxca_inventory_verify_failures_total{reason="read_error"}), so the inventory is not being verified; a single failure during a backend restart does not fire this. Check inventory storage and the "Inventory verification failed" warnings in the CA log.' % {
                threshold: $._config.inventoryUnreadableThreshold,
                window: $._config.inventoryUnreadableWindow,
              },
            },
          },
          {
            alert: 'OpenVoxCACRLStale',
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
            // openvoxca_crl_number whenever the stored CRL cannot be read or
            // parsed, while still publishing the cached number — and an
            // unreadable stored CRL is one of the two conditions this rule is
            // meant to page on, so without the arm the worst case would be the
            // quiet one.
            //
            // It is qualified on a successful scrape so that arm covers only
            // the CRL being unreadable, not the whole gather failing: a storage
            // outage holds the stored number for an hour and then drops it
            // too, in an outage OpenVoxCAScrapeFailing is already paging for,
            // and one cause should not raise two alerts.
            // The reverse asymmetry (cached absent, stored present) means the
            // replica has no CRL in memory at all and is covered by
            // OpenVoxCANotReady, so it is deliberately left out.
            expr: |||
              openvoxca_crl_number{%(selector)s} - openvoxca_crl_cached_number{%(selector)s} > 0
              or
              (openvoxca_crl_cached_number{%(selector)s}
                 unless openvoxca_crl_number{%(selector)s})
                and on(instance) openvoxca_collector_scrape_success{%(selector)s} == 1
            ||| % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.crlLagFor,
            labels: { severity: 'critical' } + $._config.alertLabels,
            annotations: {
              summary: 'OpenVox CA replica is enforcing an out-of-date CRL.',
              description: 'The OpenVox CA on {{ $labels.instance }} has not caught up with the CRL in storage for more than %(crlLagFor)s, so certificates revoked on another replica are still being accepted here. Either it is behind the stored CRL, or the stored CRL cannot be read at all (in which case openvoxca_crl_number is absent for this instance). Check openvoxca_crl_sync_failures_total and the CA logs. A restart reloads the CRL, selecting the newest block this CA signed; if the stored chain carries none, startup warns and the re-sign paths refuse it, so check the stored chain rather than restarting repeatedly.' % { crlLagFor: $._config.crlLagFor },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-kubernetes-export',
        rules: [
          {
            alert: 'OpenVoxCAKubernetesExportFailing',
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
            // openvoxca_k8s_export_applies_total{result="error"} counts every
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
            // OpenVoxCAKubernetesExportNotRunning below is the backstop for that
            // whole class, and mixin/tests.yaml exercises both.
            expr: |||
              openvoxca_k8s_export_last_error_timestamp_seconds{%(selector)s}
                > openvoxca_k8s_export_last_success_timestamp_seconds{%(selector)s}
              or
              openvoxca_k8s_export_last_error_timestamp_seconds{%(selector)s}
                unless openvoxca_k8s_export_last_success_timestamp_seconds{%(selector)s}
            ||| % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.k8sExportFailingFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A Kubernetes export target is failing to apply.',
              description: 'The most recent apply of {{ $labels.kind }}/{{ $labels.name }} in namespace {{ $labels.namespace }} from {{ $labels.instance }} failed; the exported object may hold a stale CA certificate or CRL until the next successful export. Check the CA logs, RBAC, and API server connectivity.',
            },
          },
          {
            alert: 'OpenVoxCAKubernetesExportNotRunning',
            // A configured target that has never been attempted at all. This
            // is where the two export rules' division of labour is argued;
            // ExportAll and InitTargetMetrics in internal/k8sexport state the
            // invariant they enforce and point here. The separate decision to
            // leave the last_success/last_error gauges unpublished is argued
            // where it is made, at initTargets in internal/k8sexport/metrics.go
            // and, for operators, in docs/metrics.md.
            //
            // Every arm of OpenVoxCAKubernetesExportFailing has last_error on
            // its left, so that rule can only speak about a target the CA has
            // recorded a result for. It is structurally silent when the CA
            // records nothing — and no PromQL comparison matches an absence, so
            // no reshaping of that expression can fix it from this side. The
            // answer has to come from the CA: publish a series for a target
            // that has done nothing, and "nothing has happened" becomes a value
            // that can be tested.
            //
            // So the CA publishes openvoxca_k8s_export_applies_total at zero for
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
            // OpenVoxCAKubernetesExportFailing so the pair routes and silences
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
            // OpenVoxCAExporterDown's job (downFor, 5m), and it is the better
            // alert for it. What this rule covers is the opposite shape: a CA
            // that stays up, scrapes cleanly, and reports readiness while its
            // export job does nothing.
            expr: |||
              sum without (result) (
                openvoxca_k8s_export_applies_total{%(selector)s}
              ) == 0
            ||| % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.k8sExportNotRunningFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A Kubernetes export target has never been attempted.',
              description: 'The OpenVox CA on {{ $labels.instance }} has {{ $labels.kind }}/{{ $labels.name }} in namespace {{ $labels.namespace }} configured for export but has not attempted a single apply in %(k8sExportNotRunningFor)s. The exported object holds whatever it held before, and OpenVoxCAKubernetesExportFailing cannot report on a target with no apply results. Check the CA logs for the Kubernetes export job starting, and for errors initialising the in-cluster client.' % { k8sExportNotRunningFor: $._config.k8sExportNotRunningFor },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-file-export',
        rules: [
          {
            alert: 'OpenVoxCAFileExportStale',
            // A file export target that has not been confirmed current for
            // longer than the export interval can explain. One rule rather
            // than the Kubernetes export's Failing/NotRunning pair, and the
            // difference is the point.
            //
            // The Kubernetes export is event-driven, so its attempts can be
            // weeks apart and only a last_error > last_success comparison
            // survives the gaps. The file export syncs on a fixed interval
            // (60s by default, 300s at most) and stamps last_success on every
            // sync that finds the file current, written or not. So the age of
            // last_success is itself the freshness of the file, and a
            // threshold on it covers every way of going stale at once: writes
            // that fail, a storage read that fails, and a write blocked on a
            // filesystem that has stopped answering -- which records no error
            // at all, and which the Kubernetes rules' shape cannot see.
            //
            // The second arm is a target that has never succeeded since the CA
            // started, including one whose very first write is still blocked.
            // It matches because the CA publishes syncs_total at zero for every
            // configured target before the first sync (see initTargets in
            // internal/fileexport/metrics.go); last_success is deliberately not
            // published that way, so its absence means "never".
            //
            // `sum without (result)` to collapse the success/error pair while
            // keeping every label the deployment attached, so the `unless`
            // matches per target and per scrape target, for the reason
            // OpenVoxCAKubernetesExportNotRunning gives at length.
            //
            // fileExportStaleAfterSeconds must stay at least twice the largest
            // interval the CA accepts (file_export.interval_sec, capped at
            // 300s), or one slow sync on a long interval looks like an outage.
            // fileexportconfig.MaxIntervalSec carries the same argument from
            // the other side.
            expr: |||
              time() - openvoxca_file_export_last_success_timestamp_seconds{%(selector)s}
                > %(staleAfter)d
              or
              (
                sum without (result) (openvoxca_file_export_syncs_total{%(selector)s})
                  unless openvoxca_file_export_last_success_timestamp_seconds{%(selector)s}
              )
            ||| % {
              selector: $._config.openvoxCASelector,
              staleAfter: $._config.fileExportStaleAfterSeconds,
            },
            'for': $._config.fileExportStaleFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A file export target is stale.',
              description: 'The OpenVox CA on {{ $labels.instance }} has not confirmed in the last %(staleAfter)d seconds that {{ $labels.path }} holds the current CA certificate or CRL, or has not confirmed it once since it started. The file keeps whatever it last held: a CRL copy that passes its NextUpdate makes certificate_revocation = chain fail closed. Check the CA logs for "File export failed for target", that the directory exists and is writable by the CA (under systemd, that ReadWritePaths= grants it), and that the filesystem is responding.' % { staleAfter: $._config.fileExportStaleAfterSeconds },
            },
          },
        ],
      },
      {
        name: 'openvox-ca-managed-certificates',
        rules: [
          {
            alert: 'OpenVoxCAManagedCertificateNeverIssued',
            // A configured managed certificate that has never produced a
            // certificate at all -- a store that has never accepted a write.
            //
            // Everything else about a managed certificate is an ordinary
            // certificate fact. Once one exists it has an inventory row and the
            // leaf series cover its expiry, so the shipped expiry alerts cover
            // it with nothing new. This is the one outcome that reasoning
            // cannot reach, and for the same structural reason
            // OpenVoxCAKubernetesExportNotRunning exists: there is no series for
            // a certificate that does not exist, and no PromQL comparison
            // matches an absence. The answer has to come from the CA, which
            // publishes its configuration so that "nothing has happened" is a
            // value.
            //
            // `max without (serial, state)` rather than `unless on (subject)`.
            // Both collapse the leaf series' per-certificate labels, but
            // `on (subject)` also discards every target label, so one replica's
            // series would satisfy another replica's entry. `without` keeps
            // whatever labels the deployment attached, so the two sides match
            // per scrape target.
            //
            // Replicas of one CA share a backing store, so they see the same
            // certificates and the difference this preserves is not a missing
            // certificate on one of them. What it catches is a difference in
            // *configuration*: managed_certs is per-process, so a half-applied
            // rollout -- a new entry live on one replica and not yet on its
            // siblings -- leaves the configured series on one target only. With
            // `on (subject)` a certificate reported by any replica would cancel
            // it, and the rollout would look complete. It also keeps the alert
            // honest across two CAs scraped into one Prometheus, which share no
            // store at all.
            //
            // `state!="revoked"` on the right-hand side, which the other
            // leaf-expiry rules also carry but for a different reason.
            //
            // Without the matcher this rule could not fire for the failures it
            // describes. A store write that fails does not leave the
            // certificate alone: ReconcileManaged revokes the certificate it
            // has just issued and puts the predecessor back, precisely because
            // nothing ever saw the new key. So the RBAC refusal, the
            // unadoptable Secret and the missing directory -- the three causes
            // this rule's own annotation sends an operator to check -- each
            // leave a revoked series behind, and for an entry that has never
            // issued that series is the only one there is. A revoked series on
            // its own must therefore not cancel the rule.
            //
            // With the matcher, the two cases separate properly. An entry with
            // a live certificate keeps its signed series whatever else it has,
            // because `max without (serial, state)` collapses every serial for
            // that subject: a revoked predecessor beside a signed current one
            // still matches, so an ordinary renewal and an ordinary delayed
            // supersession stay silent. What fires is a subject whose *only*
            // certificates are revoked, which is a component with nothing it
            // can present, and a first issuance that never succeeded at all --
            // the same outcome, reached two ways.
            //
            // A failure with a live predecessor is still silent here, and that
            // is intended: the component has a working certificate, so this
            // rule, which is about having nothing, has nothing to say.
            // OpenVoxCAManagedCertificateReissueFailing, below, is the one about
            // the reconcile loop being unhappy.
            //
            // It does not cover a crashlooping CA and must not be read as
            // doing so -- that is OpenVoxCAExporterDown's job. What it covers is
            // a CA that stays up, scrapes cleanly and reports readiness while
            // a certificate something else is waiting for never appears.
            //
            // Qualified on a successful scrape, the same way OpenVoxCACRLStale
            // is and for the same reason. The two sides of the `unless` come
            // from different places: the configured series is built from the
            // in-process configuration and is published even when the gather
            // fails, deliberately, so that a CA which cannot reach storage
            // still reports what it is meant to be keeping alive. The leaf
            // series are read from storage: a failed gather holds them for an
            // hour and then drops them all together. So once the hold runs out
            // the left side stands and the right side is empty, and without
            // this qualifier every configured entry would match -- healthy ones
            // included -- in an outage that OpenVoxCAScrapeFailing has already
            // been paging for. One cause
            // should not raise two alerts, and the second one here would name
            // the wrong remedy: it would send an operator to check RBAC and
            // store permissions for certificates that exist and are fine.
            expr: |||
              (
                openvoxca_managed_certificate_configured{%(selector)s}
                  unless
                max without (serial, state) (
                  openvoxca_leaf_certificate_not_after_timestamp_seconds{%(selector)s,
                    state!="revoked"}
                )
              )
              and on(instance) openvoxca_collector_scrape_success{%(selector)s} == 1
            ||| % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.managedCertNeverIssuedFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A managed certificate has never been issued, or holds only revoked ones.',
              description: 'The OpenVox CA on {{ $labels.instance }} has {{ $labels.subject }} configured in managed_certs or serving_cert but no usable certificate for it after %(managedCertNeverIssuedFor)s: either none was ever issued, or every certificate it has is revoked. Whatever depends on that certificate has nothing to present. Check the CA logs for the managed-certificate reconcile pass and for the store it writes to -- a Secret refused by RBAC, an unadoptable Secret holding somebody else\'s material, or a directory that does not exist. If the subject is the CA\'s own certname it came from serving_cert, and the CA would not have started at all had it never been issued -- so a certificate that existed no longer has a live inventory row. The rule fires on the absence of a non-revoked row, so revocation is the likeliest cause but not the only one -- check the CRL first, then the inventory itself.' % { managedCertNeverIssuedFor: $._config.managedCertNeverIssuedFor },
            },
          },
          {
            alert: 'OpenVoxCAManagedCertificateReissueFailing',
            // The latest attempt to reconcile a managed certificate failed and
            // nothing has succeeded since (#679). The case this exists for is
            // an entry that has issued before: a failed store write revokes
            // what it just signed and puts the predecessor back, so a signed
            // certificate remains, the component keeps working, and the rule
            // above is right to stay quiet. Without this, nothing said so
            // until the expiry alerts took over as the predecessor aged.
            //
            // A gauge compared to 1 rather than increase() over a counter,
            // because after the second consecutive failure the CA withholds
            // the entry's passes on a backoff that doubles from 15m to a day.
            // A counter would rise once and sit flat, and any window short
            // enough to be useful would resolve between attempts while the
            // entry was still broken. A withheld pass leaves the gauge at 1.
            //
            // The first failure is free: the next pass, one
            // managed_cert_interval_sec later, retries it. The dwell outlasts
            // that interval so a failure the retry clears does not fire; see
            // managedCertReissueFailingFor.
            //
            // It also fires for an entry that has never issued, beside the
            // rule above. That overlap is accepted: the rule above still covers
            // the case this gauge cannot see, a reconcile loop that never runs
            // and so never fails.
            //
            // Per replica, like the gauge: every replica reconciles every
            // entry, and a replica that loses the subject lock reads what the
            // winner wrote, which reads as success.
            expr: 'openvoxca_managed_certificate_reconcile_failing{%(selector)s} == 1' % {
              selector: $._config.openvoxCASelector,
            },
            'for': $._config.managedCertReissueFailingFor,
            labels: { severity: 'warning' } + $._config.alertLabels,
            annotations: {
              summary: 'A managed certificate is failing to reissue.',
              description: 'The OpenVox CA on {{ $labels.instance }} has failed to reconcile the managed certificate {{ $labels.subject }} for at least %(managedCertReissueFailingFor)s (openvoxca_managed_certificate_reconcile_failing). If it has issued before, the previous certificate is still in service, but it will not be renewed and the expiry alerts take over as it ages. The CA retries on a backoff of up to a day, and a failed store write revokes the certificate it had just signed each time. Check the CA logs for "Managed certificate not reconciled", and for "Not reissuing a managed certificate yet", whose retry_in says when it will next try, then for the store it writes to -- a Secret refused by RBAC, an unadoptable Secret, or a directory that does not exist or is read-only. If every managed certificate fires at once beside OpenVoxCAScrapeFailing, the cause is the CA\'s own storage instead: each pass takes a lock there. Fixing the store clears this only at the next attempt; restarting the CA retries at once.' % { managedCertReissueFailingFor: $._config.managedCertReissueFailingFor },
            },
          },
        ],
      },
    ],
  },
}
