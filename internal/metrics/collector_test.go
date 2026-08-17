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

package metrics_test

import (
	"context"
	"os"
	"path/filepath"

	dto "github.com/prometheus/client_model/go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// gathered indexes a Prometheus gather result by metric family name.
type gathered map[string]*dto.MetricFamily

func gather(c prometheus.Collector) gathered {
	reg := prometheus.NewRegistry()
	ExpectWithOffset(1, reg.Register(c)).To(Succeed())
	mfs, err := reg.Gather()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	out := make(gathered, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}
	return out
}

// labelsOf flattens a metric's label pairs into a map for easy assertions.
func labelsOf(m *dto.Metric) map[string]string {
	out := make(map[string]string, len(m.GetLabel()))
	for _, lp := range m.GetLabel() {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

// findByLabels returns the first metric in family whose labels match every
// key/value in want, or nil when none match.
func (g gathered) findByLabels(name string, want map[string]string) *dto.Metric {
	mf := g[name]
	if mf == nil {
		return nil
	}
	for _, m := range mf.GetMetric() {
		got := labelsOf(m)
		match := true
		for k, v := range want {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			return m
		}
	}
	return nil
}

func gaugeValue(m *dto.Metric) float64 { return m.GetGauge().GetValue() }

func counterValue(m *dto.Metric) float64 { return m.GetCounter().GetValue() }

var _ = Describe("Collector", func() {
	var (
		ctx   context.Context
		myCA  *ca.CA
		store *storage.StorageService
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	signCert := func(subject string) {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
	}

	requestCert := func(subject string) {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
	}

	It("reports CA certificate and CRL metrics", func() {
		g := gather(metrics.NewCollector(myCA))

		Expect(gaugeValue(g.findByLabels("puppetca_collector_scrape_success", nil))).To(Equal(1.0))
		Expect(gaugeValue(g.findByLabels("puppetca_ca_ready", nil))).To(Equal(1.0))

		caInfo := g.findByLabels("puppetca_ca_certificate_info", nil)
		Expect(caInfo).NotTo(BeNil())
		Expect(labelsOf(caInfo)).To(HaveKeyWithValue("common_name", ContainSubstring("Puppet CA")))
		Expect(gaugeValue(caInfo)).To(Equal(1.0))

		notAfter := g.findByLabels("puppetca_ca_certificate_not_after_timestamp_seconds", nil)
		Expect(notAfter).NotTo(BeNil())
		Expect(gaugeValue(notAfter)).To(BeNumerically(">", gaugeValue(
			g.findByLabels("puppetca_ca_certificate_not_before_timestamp_seconds", nil))))

		// A freshly bootstrapped CA has published an (empty) CRL.
		Expect(g.findByLabels("puppetca_crl_next_update_timestamp_seconds", nil)).NotTo(BeNil())
		Expect(gaugeValue(g.findByLabels("puppetca_crl_revoked_certificates", nil))).To(Equal(0.0))

		// The CRL-update failure counter is always exported, starting at zero
		// on a CA that has performed no failed CRL amendments.
		crlUpdateFailures := g.findByLabels("puppetca_crl_update_failures_total", nil)
		Expect(crlUpdateFailures).NotTo(BeNil())
		Expect(counterValue(crlUpdateFailures)).To(Equal(0.0))

		// Likewise the CRL-sync failure counter, which is what tells an operator
		// this replica may be enforcing an out-of-date revocation list.
		crlSyncFailures := g.findByLabels("puppetca_crl_sync_failures_total", nil)
		Expect(crlSyncFailures).NotTo(BeNil())
		Expect(counterValue(crlSyncFailures)).To(Equal(0.0))

		// The OCSP index series are per-process in the same way, and are how an
		// operator spots a replica calling valid certificates unknown.
		ocspFailures := g.findByLabels("puppetca_ocsp_index_sync_failures_total", nil)
		Expect(ocspFailures).NotTo(BeNil())
		Expect(counterValue(ocspFailures)).To(Equal(0.0))
		Expect(gaugeValue(g.findByLabels("puppetca_ocsp_index_serials", nil))).To(Equal(0.0),
			"a freshly bootstrapped CA has issued nothing")

		// The cached CRL number is the copy this replica decides revocation
		// from; on a replica that is up to date it equals the stored one.
		cached := g.findByLabels("puppetca_crl_cached_number", nil)
		Expect(cached).NotTo(BeNil())
		Expect(gaugeValue(cached)).To(Equal(gaugeValue(g.findByLabels("puppetca_crl_number", nil))))
	})

	It("reports a cached CRL number behind the stored one on a replica that has not synced", func() {
		signCert("divergent-node")

		// A second CA over the same storage, with a CRL cache of its own.
		peer := ca.New(storage.New(store.CADir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(peer.Init(ctx)).To(Succeed())

		Expect(myCA.Revoke(ctx, "divergent-node")).To(Succeed())

		g := gather(metrics.NewCollector(peer))
		stored := gaugeValue(g.findByLabels("puppetca_crl_number", nil))
		cached := gaugeValue(g.findByLabels("puppetca_crl_cached_number", nil))
		Expect(cached).To(BeNumerically("<", stored),
			"the gap the alert fires on must be visible in the metrics")

		updated, err := peer.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())

		g = gather(metrics.NewCollector(peer))
		Expect(gaugeValue(g.findByLabels("puppetca_crl_cached_number", nil))).To(Equal(stored))
	})

	It("reports an OCSP index behind the fleet, and the failure count when it cannot catch up", func() {
		signCert("ocsp-index-node")

		// A second CA over the same storage. Its index was built at Init from
		// the inventory as it then stood, so it holds the serial signed above
		// and not the one signed below — which is where the gap comes from.
		peer := ca.New(storage.New(store.CADir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(peer.Init(ctx)).To(Succeed())
		signCert("signed-after-the-peer-started")

		g := gather(metrics.NewCollector(peer))
		behind := gaugeValue(g.findByLabels("puppetca_ocsp_index_serials", nil))
		Expect(gaugeValue(gather(metrics.NewCollector(myCA)).
			findByLabels("puppetca_ocsp_index_serials", nil))).
			To(BeNumerically(">", behind),
				"the gap the fleet-relative query fires on must be visible in the metrics")

		_, err := peer.SyncSerialIndex(ctx)
		Expect(err).NotTo(HaveOccurred())
		g = gather(metrics.NewCollector(peer))
		Expect(gaugeValue(g.findByLabels("puppetca_ocsp_index_serials", nil))).
			To(Equal(gaugeValue(gather(metrics.NewCollector(myCA)).
				findByLabels("puppetca_ocsp_index_serials", nil))),
				"after a sync the two replicas must agree")

		// Now make the read fail. Asserting the value rather than its presence
		// keeps this counter distinguishable from the two CRL ones, which stay
		// at zero throughout: a reload that failed is neither an amendment that
		// failed nor a CRL that could not be read.
		Expect(os.Remove(store.InventoryPath())).To(Succeed())
		_, err = peer.SyncSerialIndex(ctx)
		Expect(err).To(HaveOccurred())

		g = gather(metrics.NewCollector(peer))
		Expect(counterValue(g.findByLabels("puppetca_ocsp_index_sync_failures_total", nil))).
			To(Equal(float64(peer.SerialIndexSyncFailures())))
		Expect(counterValue(g.findByLabels("puppetca_ocsp_index_sync_failures_total", nil))).
			To(BeNumerically(">", 0))
		Expect(counterValue(g.findByLabels("puppetca_crl_sync_failures_total", nil))).
			To(Equal(0.0), "an unreadable inventory is not an unreadable CRL")
	})

	It("reports a nonzero sync-failure count once a replica has failed to reload", func() {
		peer := ca.New(storage.New(store.CADir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(peer.Init(ctx)).To(Succeed())

		// Corrupt the stored CRL so the next sync refuses it.
		Expect(store.UpdateCRL(ctx, []byte("not a CRL"))).To(Succeed())
		_, err := peer.SyncCRLCache(ctx)
		Expect(err).To(HaveOccurred())

		// Asserting the value rather than just its presence is the point: both
		// failure counters start at zero and are otherwise only ever observed
		// there, so transposing their descriptors would go unnoticed.
		g := gather(metrics.NewCollector(peer))
		Expect(counterValue(g.findByLabels("puppetca_crl_sync_failures_total", nil))).
			To(Equal(float64(peer.CRLSyncFailures())))
		Expect(counterValue(g.findByLabels("puppetca_crl_sync_failures_total", nil))).
			To(BeNumerically(">", 0))
		Expect(counterValue(g.findByLabels("puppetca_crl_update_failures_total", nil))).
			To(Equal(0.0), "a failed reload is not a failed amendment")
	})

	// The whole reason these two are emitted ahead of the gather's error return
	// is that a storage outage is when an operator most needs them: it is what
	// makes a replica fall behind in the first place. Worth a spec, since the
	// ordering is a one-line accident away from being lost.
	It("keeps reporting the in-process CRL tallies when the storage gather fails", func() {
		signCert("gather-failure-node")

		before := gather(metrics.NewCollector(myCA))
		cachedBefore := gaugeValue(before.findByLabels("puppetca_crl_cached_number", nil))

		// Replace the directory ListCerts enumerates with a plain file, so the
		// listing returns a real error rather than an empty set.
		signedDir := filepath.Join(store.CADir(), "signed")
		Expect(os.RemoveAll(signedDir)).To(Succeed())
		Expect(os.WriteFile(signedDir, []byte("not a directory"), 0o600)).To(Succeed())

		g := gather(metrics.NewCollector(myCA))
		Expect(gaugeValue(g.findByLabels("puppetca_collector_scrape_success", nil))).To(Equal(0.0),
			"precondition: the gather must actually have failed")
		Expect(g.findByLabels("puppetca_crl_number", nil)).To(BeNil(),
			"precondition: the storage-derived series drop out")

		Expect(counterValue(g.findByLabels("puppetca_crl_sync_failures_total", nil))).
			To(Equal(float64(myCA.CRLSyncFailures())))
		cached := g.findByLabels("puppetca_crl_cached_number", nil)
		Expect(cached).NotTo(BeNil(), "the cached CRL number must survive a failed gather")
		Expect(gaugeValue(cached)).To(Equal(cachedBefore))
	})

	It("omits the cached CRL number rather than reporting zero when no CRL is loaded", func() {
		// The alert subtracts the cached number from the stored one, so a zero
		// here would read as "maximally behind" and page for every replica that
		// has not finished initialising. Absent is the only safe encoding.
		uninitialised := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")

		g := gather(metrics.NewCollector(uninitialised))
		Expect(g.findByLabels("puppetca_crl_cached_number", nil)).To(BeNil())
		Expect(gaugeValue(g.findByLabels("puppetca_ca_ready", nil))).To(Equal(0.0))
	})

	It("drops the CRL gauges and still reports a successful scrape when the CRL is unreadable", func() {
		// The degradation docs/metrics.md warns about: a CRL the exporter
		// cannot parse takes the four CRL gauges out of the output without
		// failing the scrape, so an expiry alert comparing
		// puppetca_crl_next_update_timestamp_seconds against time() matches
		// nothing rather than firing. That is why the note tells operators to
		// pair it with a presence check.
		Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())

		g := gather(metrics.NewCollector(myCA))

		Expect(gaugeValue(g.findByLabels("puppetca_collector_scrape_success", nil))).To(Equal(1.0))
		for _, name := range []string{
			"puppetca_crl_number",
			"puppetca_crl_this_update_timestamp_seconds",
			"puppetca_crl_next_update_timestamp_seconds",
			"puppetca_crl_revoked_certificates",
		} {
			Expect(g.findByLabels(name, nil)).To(BeNil(), "%s must be absent, not stale", name)
		}
		Expect(g.findByLabels("puppetca_crl_update_failures_total", nil)).NotTo(BeNil(),
			"the failure counter is exported regardless")
	})

	It("reports per-leaf metrics with issuance state", func() {
		signCert("signed-node")
		signCert("revoked-node")
		requestCert("pending-node")
		Expect(myCA.Revoke(ctx, "revoked-node")).To(Succeed())

		g := gather(metrics.NewCollector(myCA))

		signed := g.findByLabels("puppetca_leaf_certificate_info", map[string]string{"subject": "signed-node"})
		Expect(signed).NotTo(BeNil())
		Expect(labelsOf(signed)).To(HaveKeyWithValue("state", "signed"))
		Expect(labelsOf(signed)["serial"]).NotTo(BeEmpty())

		revoked := g.findByLabels("puppetca_leaf_certificate_info", map[string]string{"subject": "revoked-node"})
		Expect(revoked).NotTo(BeNil())
		Expect(labelsOf(revoked)).To(HaveKeyWithValue("state", "revoked"))

		pending := g.findByLabels("puppetca_leaf_certificate_info", map[string]string{"subject": "pending-node"})
		Expect(pending).NotTo(BeNil())
		Expect(labelsOf(pending)).To(HaveKeyWithValue("state", "requested"))
		Expect(labelsOf(pending)["serial"]).To(BeEmpty())

		// Pending requests carry no issued certificate, so they have no expiry series.
		Expect(g.findByLabels("puppetca_leaf_certificate_not_after_timestamp_seconds",
			map[string]string{"subject": "pending-node"})).To(BeNil())
		// Signed certs do.
		Expect(g.findByLabels("puppetca_leaf_certificate_not_after_timestamp_seconds",
			map[string]string{"subject": "signed-node"})).NotTo(BeNil())

		// The CRL now lists exactly the one revoked serial.
		Expect(gaugeValue(g.findByLabels("puppetca_crl_revoked_certificates", nil))).To(Equal(1.0))

		// Aggregate per-state counts.
		Expect(gaugeValue(g.findByLabels("puppetca_leaf_certificates",
			map[string]string{"state": "signed"}))).To(Equal(1.0))
		Expect(gaugeValue(g.findByLabels("puppetca_leaf_certificates",
			map[string]string{"state": "revoked"}))).To(Equal(1.0))
		Expect(gaugeValue(g.findByLabels("puppetca_leaf_certificates",
			map[string]string{"state": "requested"}))).To(Equal(1.0))
	})

	It("excludes cleaned (deleted) certificates from the live set", func() {
		signCert("keep-node")
		signCert("clean-node")
		Expect(myCA.Clean(ctx, "clean-node")).To(Succeed())

		g := gather(metrics.NewCollector(myCA))

		Expect(g.findByLabels("puppetca_leaf_certificate_info",
			map[string]string{"subject": "keep-node"})).NotTo(BeNil())
		Expect(g.findByLabels("puppetca_leaf_certificate_info",
			map[string]string{"subject": "clean-node"})).To(BeNil())
	})

	It("exposes Go and process collectors plus HTTP request metrics via the exporter", func() {
		exp := metrics.NewExporter(myCA)
		mfs, err := exp.Registry().Gather()
		Expect(err).NotTo(HaveOccurred())

		names := map[string]bool{}
		for _, mf := range mfs {
			names[mf.GetName()] = true
		}
		Expect(names).To(HaveKey("go_goroutines"))
		Expect(names).To(HaveKey("puppetca_ca_certificate_info"))
		Expect(names).To(HaveKey("puppetca_http_requests_in_flight"))
	})
})
