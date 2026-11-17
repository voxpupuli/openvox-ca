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
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/httpserver"
)

// RoleLabel is the label on every go_* and process_* series naming the process
// it describes: launcher, signer, frontend or single-process. It is also the
// attribute every log record carries, so a log line and a series about the
// same process share one name.
const RoleLabel = "role"

// Exporter bundles a dedicated Prometheus registry with the HTTP request
// instrumentation that shares it. Keeping a private registry (rather than the
// global default) means the exporter's metrics are self-contained and tests can
// construct independent instances without cross-talk.
type Exporter struct {
	registry *prometheus.Registry
	inFlight prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec

	// runtimes are other processes' go_* series, fetched at scrape time; see
	// AddRuntime.
	mu       sync.Mutex
	runtimes []runtimeSource
}

// runtimeSource is one other process whose Go runtime metrics the exporter
// serves, and the role they are labelled with.
type runtimeSource struct {
	role     string
	gatherer prometheus.Gatherer
}

// NewExporter builds an Exporter for the given CA, served by the process
// running as role. The registry is populated with:
//
//   - the standard Go runtime collector (go_*) and the process collector
//     (process_*), both labelled RoleLabel=role, since in the default
//     deployment they describe one process of three (see AddProcess and
//     AddRuntime for the other two),
//   - build-info (openvoxca_build_info via the version collector is omitted; the
//     Go collector already exposes go_info),
//   - the CA/CRL/leaf certificate collector (openvoxca_*), and
//   - HTTP server request metrics (openvoxca_http_*), applied to whatever handler
//     is wrapped with InstrumentHandler.
//
// Together these cover both the "usual" Go web-application metrics and the
// CA-specific certificate/CRL series. opts are handed to the CA collector. The
// openvoxca_* series carry no role: they describe the CA, not a process.
func NewExporter(c *ca.CA, role string, opts ...Option) *Exporter {
	reg := prometheus.NewRegistry()

	// Standard Go web-application metrics, for this process.
	prometheus.WrapRegistererWith(prometheus.Labels{RoleLabel: role}, reg).MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// CA-specific metrics.
	reg.MustRegister(NewCollector(c, opts...))

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

// AddProcess adds the process_* series of another process, read from
// /proc/<pid> at each scrape and labelled RoleLabel=role. It is how the
// frontend reports the launcher and the signer, which have no listener of
// their own.
//
// Reading another process's /proc entry needs no privilege the frontend lacks:
// all three run as the same user. Where /proc is not available the collector
// reports little or nothing for the sibling: on macOS only its start time,
// elsewhere nothing.
func (e *Exporter) AddProcess(role string, pid int) {
	prometheus.WrapRegistererWith(prometheus.Labels{RoleLabel: role}, e.registry).MustRegister(
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
			PidFn: func() (int, error) { return pid, nil },
		}),
	)
}

// AddRuntime adds another process's Go runtime series, fetched from g at each
// scrape and labelled RoleLabel=role. It is how the frontend reports the
// signer's go_* series, which the signer returns over its RPC.
//
// Only go_* families are taken, and any role label g supplies is replaced: the
// role is the exporter's to assign, not the other process's to claim. A source
// that fails is logged, as sibling=role, and left out of that scrape, so a
// wedged signer costs its own series and nothing else.
func (e *Exporter) AddRuntime(role string, g prometheus.Gatherer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runtimes = append(e.runtimes, runtimeSource{role: role, gatherer: g})
}

// Registry returns the exporter's Prometheus registry, for registering further
// collectors. It does not hold what AddRuntime adds; Gatherer does.
func (e *Exporter) Registry() *prometheus.Registry { return e.registry }

// Gatherer returns everything the exporter serves: its registry and the
// runtime sources AddRuntime added, merged into one set of families. The
// sources are fetched concurrently with the registry, so a slow one adds its
// own wait to a scrape rather than the registry's on top of it.
func (e *Exporter) Gatherer() prometheus.Gatherer {
	return prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
		e.mu.Lock()
		sources := slices.Clone(e.runtimes)
		e.mu.Unlock()

		fetched := make([][]*dto.MetricFamily, len(sources))
		var wg sync.WaitGroup
		for i, src := range sources {
			wg.Go(func() {
				mfs, err := src.gatherer.Gather()
				if err != nil {
					// "sibling", not RoleLabel: the record's role is the
					// process writing it, already on the logger, and slog
					// does not deduplicate keys.
					slog.Warn("Could not read another process's Go runtime metrics; serving this scrape without them",
						"sibling", src.role, "error", err)
					return
				}
				fetched[i] = labelRuntimeFamilies(src.role, mfs)
			})
		}
		mfs, err := e.registry.Gather()
		wg.Wait()

		gatherers := prometheus.Gatherers{prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
			return mfs, err
		})}
		for _, f := range fetched {
			gatherers = append(gatherers, prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
				return f, nil
			}))
		}
		return gatherers.Gather()
	})
}

// labelRuntimeFamilies keeps only the go_* families in mfs and sets
// RoleLabel=role on every metric in them, replacing any role already there.
// mfs is freshly decoded and owned by the caller, so it is modified in place.
func labelRuntimeFamilies(role string, mfs []*dto.MetricFamily) []*dto.MetricFamily {
	out := mfs[:0]
	for _, mf := range mfs {
		if !strings.HasPrefix(mf.GetName(), "go_") {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := slices.DeleteFunc(m.Label, func(lp *dto.LabelPair) bool {
				return lp.GetName() == RoleLabel
			})
			labels = append(labels, &dto.LabelPair{Name: new(RoleLabel), Value: new(role)})
			slices.SortFunc(labels, func(a, b *dto.LabelPair) int {
				return strings.Compare(a.GetName(), b.GetName())
			})
			m.Label = labels
		}
		out = append(out, mf)
	}
	return out
}

// Handler returns an http.Handler that serves the exporter's metrics in the
// Prometheus text/OpenMetrics exposition format. Mount it at /metrics.
func (e *Exporter) Handler() http.Handler {
	return promhttp.HandlerFor(e.Gatherer(), promhttp.HandlerOpts{
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
