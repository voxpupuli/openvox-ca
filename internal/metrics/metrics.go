// Copyright (C) 2026 Chris Boot
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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tvaughan/puppet-ca/internal/ca"
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
//   - build-info (puppetca_build_info via the version collector is omitted; the
//     Go collector already exposes go_info),
//   - the CA/CRL/leaf certificate collector (puppetca_*), and
//   - HTTP server request metrics (puppetca_http_*), applied to whatever handler
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
// timed into the puppetca_http_* metrics. Only the request method and response
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
// Timeouts mirror the main API server's conservative defaults so a stuck
// scraper cannot tie up a connection indefinitely.
func (e *Exporter) NewServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", e.Handler())
	// A trivial root response makes it obvious the listener is the metrics
	// endpoint when probed by a human or a liveness check.
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Puppet CA metrics exporter\nSee /metrics\n"))
	})
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}
