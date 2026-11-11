// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package fileexport

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/voxpupuli/openvox-ca/internal/constants"
)

const (
	metricsNamespace = constants.MetricsNamespace
	metricsSubsystem = "file_export"
)

// Metrics instruments the exporter's sync attempts. A failed sync is otherwise
// only logged -- the export is auxiliary and never stops the CA -- so these
// series are how a stale file gets noticed. Label cardinality is bounded by the
// configured targets.
type Metrics struct {
	syncs       *prometheus.CounterVec
	lastSuccess *prometheus.GaugeVec
	lastError   *prometheus.GaugeVec
}

// NewMetrics constructs the exporter's metrics and registers them with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		syncs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "syncs_total",
			Help:      "File export sync attempts, by target path and result (success or error). A success means the file was confirmed current, whether or not it had to be rewritten.",
		}, []string{"path", "result"}),
		lastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "last_success_timestamp_seconds",
			Help:      "Time each file export target was last confirmed to hold the current material. Syncs run on a fixed interval, so time() minus this is how stale the file may be.",
		}, []string{"path"}),
		lastError: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystem,
			Name:      "last_error_timestamp_seconds",
			Help:      "Time of the last failed sync for each file export target.",
		}, []string{"path"}),
	}
	reg.MustRegister(m.syncs, m.lastSuccess, m.lastError)
	return m
}

// initTargets publishes the syncs_total children for every configured target,
// at zero, before the first sync runs. A nil receiver (metrics disabled) is a
// no-op.
//
// Prometheus does not export a child that has never been touched, and no PromQL
// expression matches an absence. Publishing these is what lets
// OpenVoxCAFileExportStale see a configured target that has never succeeded --
// including one whose very first write is still blocked -- as a counter with no
// last_success beside it, rather than as nothing at all.
//
// The timestamp gauges are left absent until something happens, for the reason
// internal/k8sexport gives for its own: a zero is a claim that the last success
// was in 1970, which every time()-based query would believe.
func (m *Metrics) initTargets(targets []Target) {
	if m == nil {
		return
	}
	for i := range targets {
		m.syncs.WithLabelValues(targets[i].Path, "success")
		m.syncs.WithLabelValues(targets[i].Path, "error")
	}
}

// recordSync counts one sync attempt for a target. A nil receiver (metrics
// disabled) is a no-op.
func (m *Metrics) recordSync(t *Target, err error) {
	if m == nil {
		return
	}
	if err != nil {
		m.syncs.WithLabelValues(t.Path, "error").Inc()
		m.lastError.WithLabelValues(t.Path).SetToCurrentTime()
		return
	}
	m.syncs.WithLabelValues(t.Path, "success").Inc()
	m.lastSuccess.WithLabelValues(t.Path).SetToCurrentTime()
}
