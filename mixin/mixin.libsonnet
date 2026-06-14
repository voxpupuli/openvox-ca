// Puppet CA monitoring mixin.
//
// A monitoring-mixin (https://monitoring.mixins.dev/) bundling Prometheus
// alerting rules for the Puppet CA exporter. Import it from another repository
// with jsonnet-bundler and render the alerts with jsonnet — see README.md.
//
// Override anything in _config (see config.libsonnet) to tune selectors and
// thresholds, e.g.:
//
//   (import 'openvox-ca-mixin/mixin.libsonnet') + {
//     _config+:: { puppetCASelector: 'job="pki/openvox-ca"' },
//   }
(import 'config.libsonnet') +
(import 'alerts.libsonnet')
