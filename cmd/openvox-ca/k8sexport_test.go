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

package main

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// metricValue gathers reg and returns the value of the counter series matching
// name and labels, or false when no such series exists. Absence is the whole
// point of several assertions here, so it is reported rather than failed on.
func metricValue(reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	GinkgoHelper()
	mfs, err := reg.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	metric:
		for _, m := range mf.GetMetric() {
			have := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				have[lp.GetName()] = lp.GetValue()
			}
			for k, v := range labels {
				if have[k] != v {
					continue metric
				}
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue(), true
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue(), true
			}
		}
	}
	return 0, false
}

// runK8sExporter is the wiring that connects the CA's CRL-update notifications
// to the exporter's reconcile. It must export once at startup, re-export on
// every CRL update, and return promptly on context cancellation.
var _ = Describe("runK8sExporter", func() {
	It("exports at startup, re-exports on CRL update, and returns on cancel", func() {
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		// Count server-side applies (a patch) but let the fake tracker handle
		// them so the objects are still created/updated.
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				applies.Add(1)
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())

		// store (*storage.StorageService) satisfies k8sexport.MaterialSource.
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		// An hour of retry interval keeps the retry timer out of this spec:
		// every apply counted below is attributable to startup or the CRL
		// update, not to a retry firing underneath the assertions.
		go func() {
			runK8sExporter(ctx, c, exporter, time.Hour)
			close(done)
		}()

		// (1) The startup export applies the target.
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">=", 1), "startup export did not apply within 2s")
		startupCount := applies.Load()

		// (2) A CRL update wakes the loop and triggers a re-export.
		Expect(c.ReissueCRL(ctx)).To(Succeed())
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">", startupCount), "CRL update did not trigger a re-export within 2s")

		// (3) Cancelling the context stops the loop.
		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runK8sExporter did not return after context cancellation")
	})
	// The retry exists because the CRL-update signal can be weeks away on a
	// quiet CA: without it, one failed cycle leaves every target stale until
	// the CRL next changes. These two specs pin both halves of that — a failed
	// cycle is retried unprompted, and a successful one is not.
	It("retries a failed cycle without waiting for a CRL update", func() {
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		// Fail the first two applies, then let the tracker handle the rest. If
		// the loop only woke on CRL updates the count would stop at 1, because
		// nothing revokes anything for the lifetime of this spec.
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				if applies.Add(1) <= 2 {
					return true, nil, errors.New("boom")
				}
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			runK8sExporter(ctx, c, exporter, 20*time.Millisecond)
			close(done)
		}()

		// Startup (fails), retry (fails), retry (succeeds).
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(BeNumerically(">=", 3), "a failed export cycle was not retried within 2s")

		// ...and then stops. Without this the spec only says "retried until it
		// worked", never "and left off afterwards", so a retry that re-arms on
		// success would pass it.
		Consistently(applies.Load).WithTimeout(300*time.Millisecond).
			WithPolling(20*time.Millisecond).Should(Equal(int32(3)),
			"the exporter kept retrying after a cycle succeeded")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runK8sExporter did not return after context cancellation")
	})

	It("stops retrying once a cycle succeeds", func() {
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				applies.Add(1)
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		go func() {
			runK8sExporter(ctx, c, exporter, 20*time.Millisecond)
			close(done)
		}()

		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(Equal(int32(1)), "startup export did not apply within 2s")

		// Many retry intervals pass with nothing failing. A timer that is armed
		// unconditionally rather than only on failure would turn the export
		// into a busy poll of the API server, and would show up here.
		Consistently(applies.Load).WithTimeout(500*time.Millisecond).
			WithPolling(20*time.Millisecond).Should(Equal(int32(1)),
			"a successful export cycle was retried anyway")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runK8sExporter did not return after context cancellation")
	})
	It("disarms a pending retry when a CRL update gets there first", func() {
		// The one state that exercises retry.Stop() inside runCycle: a cycle
		// failed and armed the timer, then a CRL update ran a cycle before it
		// fired. Without the Stop the stale retry lands moments after the
		// successful export, costing a redundant apply of every target against
		// the API server.
		c, store := newRefresherTestCA()

		client := fake.NewClientset()
		var applies atomic.Int32
		// Only the startup apply fails, so the CRL-driven cycle succeeds and
		// leaves nothing legitimately to retry.
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				if applies.Add(1) == 1 {
					return true, nil, errors.New("boom")
				}
				return false, nil, nil
			})

		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		Expect(cfg.Validate()).To(Succeed())
		exporter := k8sexport.New(client, cfg, store, "", nil)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{})
		// The interval does double duty here, and the margin is deliberate. It
		// is the budget for arming the timer and getting the CRL-driven cycle
		// in ahead of it (goroutine start, a failed apply, the poll below,
		// ReissueCRL re-signing and notifying, a second apply -- tens of
		// milliseconds normally), and it is what the Consistently window has to
		// outlive to observe a retry that was never disarmed. Three seconds
		// against a ~50ms setup leaves a 60x stall before the two collide.
		//
		// If they ever do collide the count walks 1 -> 2 (retry) -> 3 and this
		// spec fails on correct code, so read a failure here as a stalled
		// runner before reading it as a regression. It cannot fail the other
		// way: a missing retry.Stop() always adds an apply, never hides one.
		go func() {
			runK8sExporter(ctx, c, exporter, 3*time.Second)
			close(done)
		}()

		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(Equal(int32(1)), "the startup export did not run within 2s")

		// The CRL update beats the pending retry to it.
		Expect(c.ReissueCRL(ctx)).To(Succeed())
		Eventually(applies.Load).WithTimeout(2*time.Second).
			Should(Equal(int32(2)), "the CRL update did not trigger a re-export within 2s")

		Consistently(applies.Load).WithTimeout(3500*time.Millisecond).
			WithPolling(50*time.Millisecond).Should(Equal(int32(2)),
			"a retry armed by the failed startup cycle fired after a later cycle had already succeeded")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runK8sExporter did not return after context cancellation")
	})
})

// startK8sExport decides whether the export job runs and, when it cannot, makes
// that decision visible to monitoring. Both branches matter: the failure branch
// is the only thing standing between a dead export and complete silence.
var _ = Describe("startK8sExport", func() {
	var cfg k8sexport.Config

	BeforeEach(func() {
		cfg = k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true},
			// Relies on the pod namespace -- which, on this path, is one of the
			// things that may have failed to resolve.
			{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "bundle"}, CRL: true},
		}}
		Expect(cfg.Validate()).To(Succeed())
	})

	It("publishes zeroed counters and starts nothing when the exporter cannot be built", func() {
		c, _ := newRefresherTestCA()
		reg := prometheus.NewRegistry()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		startK8sExport(ctx, c, cfg, k8sexport.NewMetrics(reg),
			func() (*k8sexport.Exporter, error) { return nil, errors.New("no service account token") })

		for _, want := range []struct{ kind, ns, name string }{
			{"Secret", "ns1", "trust"},
			{"ConfigMap", "", "bundle"},
		} {
			v, found := metricValue(reg, "openvoxca_k8s_export_applies_total", map[string]string{
				"kind": want.kind, "namespace": want.ns, "name": want.name, "result": "error",
			})
			Expect(found).To(BeTrue(),
				"no applies_total for %s: a dead export is invisible to both alerts", want.name)
			Expect(v).To(Equal(0.0))
		}
	})

	It("starts the job and leaves no placeholder series when the exporter builds", func() {
		// The hazard InitTargetMetrics' doc comment warns about: publishing the
		// empty-namespace placeholder on a path where the export does start
		// would strand a series recordApply never touches, and
		// OpenVoxCAKubernetesExportNotRunning would fire on a healthy target for
		// ever. The success branch must not call it.
		c, store := newRefresherTestCA()
		reg := prometheus.NewRegistry()
		client := fake.NewClientset()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// One Metrics for both: registering twice against the same registry
		// panics, and the exporter must record against the very series
		// startK8sExport would otherwise have published.
		m := k8sexport.NewMetrics(reg)
		startK8sExport(ctx, c, cfg, m,
			func() (*k8sexport.Exporter, error) {
				return k8sexport.New(client, cfg, store, "pod-ns", m), nil
			})

		// The counter must reach one, not merely exist. New publishes this
		// child at zero as it constructs the exporter, so asserting presence
		// would be satisfied by this spec's own closure and would stay green
		// with the `go runK8sExporter` line deleted -- the single piece of
		// wiring this half of the spec exists to hold down.
		Eventually(func() float64 {
			v, _ := metricValue(reg, "openvoxca_k8s_export_applies_total", map[string]string{
				"kind": "ConfigMap", "namespace": "pod-ns", "name": "bundle", "result": "success",
			})
			return v
		}).WithTimeout(2*time.Second).Should(BeNumerically(">=", 1),
			"the job was never started: applies_total stayed at the zero New published")

		_, found := metricValue(reg, "openvoxca_k8s_export_applies_total", map[string]string{
			"kind": "ConfigMap", "namespace": "", "name": "bundle", "result": "error",
		})
		Expect(found).To(BeFalse(),
			"the success branch published the empty-namespace placeholder, stranding a series")
	})

	It("uses a retry interval the export alert can survive", func() {
		// Anchors the Go half of a coupling nothing else can check.
		// mixin/config.libsonnet documents k8sExportFailingFor (15m) as sitting
		// above this constant, and the retry's justification is that a cycle
		// recovering on the first retry or two clears before the alert would
		// have paged. Raise this past the debounce and that inverts -- every
		// transient blip pages -- with the Go suite and `mage test:mixin` both
		// still green, because neither can see the other side.
		Expect(k8sExportRetryInterval).To(BeNumerically("<", 15*time.Minute),
			"k8sExportRetryInterval must stay below k8sExportFailingFor in mixin/config.libsonnet")
	})
})
