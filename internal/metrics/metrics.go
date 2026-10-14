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

package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/httpserver"
)

// Exporter bundles a dedicated Prometheus registry with the HTTP request
// instrumentation that shares it. Keeping a private registry (rather than the
// global default) means the exporter's metrics are self-contained and tests can
// construct independent instances without cross-talk.
type Exporter struct {
	registry *prometheus.Registry
	inFlight prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewExporter builds an Exporter for the given CA. The registry is populated
// with:
//
//   - the standard Go runtime collector (go_*),
//   - the process collector (process_*),
//   - build-info (openvoxca_build_info via the version collector is omitted; the
//     Go collector already exposes go_info),
//   - the CA/CRL/leaf certificate collector (openvoxca_*), and
//   - HTTP server request metrics (openvoxca_http_*), applied to whatever handler
//     is wrapped with InstrumentHandler.
//
// Together these cover both the "usual" Go web-application metrics and the
// CA-specific certificate/CRL series.
func NewExporter(c *ca.CA) *Exporter {
	reg := prometheus.NewRegistry()

	// Standard Go web-application metrics.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// CA-specific metrics.
	reg.MustRegister(NewCollector(c))

	e := &Exporter{
		registry: reg,
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "requests_in_flight",
			Help:      "Number of HTTP requests currently being served by the CA API.",
		}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests handled by the CA API, by method and response code.",
		}, []string{"method", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request latency for the CA API, by method and response code.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"method", "code"}),
	}
	reg.MustRegister(e.inFlight, e.requests, e.duration)

	return e
}

// Registry returns the exporter's Prometheus registry, e.g. for serving via a
// custom promhttp handler or for test gathering.
func (e *Exporter) Registry() *prometheus.Registry { return e.registry }

// Handler returns an http.Handler that serves the exporter's metrics in the
// Prometheus text/OpenMetrics exposition format. Mount it at /metrics.
func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{
		ErrorHandling:     promhttp.ContinueOnError,
		EnableOpenMetrics: true,
	})
}

// InstrumentHandler wraps next so that every request it serves is counted and
// timed into the openvoxca_http_* metrics. Only the request method and response
// status code are used as labels — never the URL path — because Puppet CA paths
// embed per-node subjects (e.g. /certificate_status/<hostname>) and would
// otherwise explode metric cardinality.
func (e *Exporter) InstrumentHandler(next http.Handler) http.Handler {
	return promhttp.InstrumentHandlerInFlight(e.inFlight,
		promhttp.InstrumentHandlerCounter(e.requests,
			promhttp.InstrumentHandlerDuration(e.duration, next)))
}

// NewServer builds an *http.Server that serves the exporter's metrics at
// /metrics on addr. The caller owns its lifecycle (ListenAndServe / Shutdown).
// Its timeouts are the main API server's, from httpserver.Defaults, so a stuck
// scraper cannot tie up a connection indefinitely.
//
// Sharing them is safe only while the write budget outlasts a scrape.
// WriteTimeout covers the whole handler, and a scrape spends up to the
// collector's gather budget (defaultGatherTimeout) reading storage before it
// writes a byte. A scrape that outran the write budget would be cut off
// mid-response, and Prometheus would record a truncated scrape rather than a
// slow one.
//
// Encoding is the other cost, and it scales with what the gather managed to
// read. Against the filesystem backend, the collector measured about 45µs per
// leaf certificate to read and parse it, and about 5µs more to encode its three
// series and gzip them. A gather that just fits its budget is therefore
// followed by roughly a tenth of that again in encoding, and backends that read
// over the network spend longer per leaf, which shrinks the ratio further. A
// 60s write budget against a 10s gather leaves a margin of several times for
// slow hosts and slow scrapers. A spec fails if the write budget falls below
// twice the gather budget.
func (e *Exporter) NewServer(addr string) *http.Server {
	return e.newServer(addr, httpserver.Defaults())
}

// newServer is NewServer with the timeouts supplied, so a spec can exercise
// them in milliseconds rather than waiting out the real ones.
func (e *Exporter) newServer(addr string, timeouts httpserver.Timeouts) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", e.Handler())
	// A trivial root response makes it obvious the listener is the metrics
	// endpoint when probed by a human or a liveness check.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("OpenVox CA metrics exporter\nSee /metrics\n"))
	})
	return httpserver.New(addr, mux, timeouts)
}
