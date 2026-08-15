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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

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

// findUnlabelled returns the single metric in family name, and fails unless it
// carries no labels at all.
//
// findByLabels(name, nil) cannot express this: an empty want map means the
// match loop never runs, so it returns the first series whatever its labels.
// That reads as coverage while asserting only the family name — and the one
// property this file most needs to hold is that
// puppetca_crl_next_update_timestamp_seconds stays a single unlabelled series,
// because adding an {issuer} label to it would multiply the two shipped expiry
// alerts across CRLs this CA cannot reissue.
func (g gathered) findUnlabelled(name string) *dto.Metric {
	GinkgoHelper()
	mf := g[name]
	Expect(mf).NotTo(BeNil(), "no metric family %q", name)
	Expect(mf.GetMetric()).To(HaveLen(1), "%q must be a single series", name)
	m := mf.GetMetric()[0]
	Expect(m.GetLabel()).To(BeEmpty(), "%q must carry no labels", name)
	return m
}

// upstreamCAWithKeyFixture builds a self-signed CA and returns it with its key,
// so a spec can issue more than one CRL from the same ancestor.
func upstreamCAWithKeyFixture(cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return cert, key
}

func numberedCRLFixture(cert *x509.Certificate, key *ecdsa.PrivateKey, number int64) []byte {
	GinkgoHelper()
	now := time.Now().UTC()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
}

func upstreamCRLFixture(cn string) (*x509.Certificate, []byte) {
	GinkgoHelper()
	cert, key := upstreamCAWithKeyFixture(cn)
	return cert, numberedCRLFixture(cert, key, 7)
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
		//
		// Asserted as unlabelled deliberately: this series means *this CA's
		// own* CRL, and the upstream entries get their own labelled series so
		// the shipped expiry alerts keep their meaning and cardinality.
		Expect(g.findUnlabelled("puppetca_crl_next_update_timestamp_seconds")).NotTo(BeNil())
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

	It("reports no upstream CRL series on a CA with no chain", func() {
		// The common case, and the reason the series is separate: a
		// self-signed root has no upstream, so nothing labelled appears and
		// the shipped expiry alerts see exactly the one series they always saw.
		g := gather(metrics.NewCollector(myCA))
		Expect(g["puppetca_crl_chain_next_update_timestamp_seconds"]).To(BeNil())
	})

	It("exports both chain counters by name, and at their value", func() {
		// Neither name appeared in any spec. Deleting either MustNewConstMetric
		// line, or renaming either series, left the suite green -- while
		// PuppetCAUpstreamCRLDiscarded and PuppetCAUpstreamCRLRefreshFailing
		// route on exactly those names, and docs/metrics.md calls the discard
		// counter "the only signal that the published chain is smaller than the
		// file says".
		g := gather(metrics.NewCollector(myCA))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_refresh_failures_total", nil))).
			To(Equal(0.0))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_discarded_total", nil))).
			To(Equal(0.0))

		// Driven through the real paths, and to distinct values so a
		// transposition between the two series is caught as well as a rename.
		// A CRL from a CA the bundle does not vouch for is discarded; a file
		// that decodes to nothing is a refresh failure.
		dir := GinkgoT().TempDir()
		_, strayCRL := upstreamCRLFixture("Stray CA")
		discardPath := filepath.Join(dir, "stray.pem")
		Expect(os.WriteFile(discardPath, strayCRL, 0o644)).To(Succeed())
		myCA.CRLChainFile = discardPath
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		badPath := filepath.Join(dir, "bad.pem")
		Expect(os.WriteFile(badPath, []byte("<html>502</html>\n"), 0o644)).To(Succeed())
		myCA.CRLChainFile = badPath
		for range 2 {
			Expect(myCA.RefreshCRLChainFile(ctx)).Error().To(HaveOccurred())
		}

		g = gather(metrics.NewCollector(myCA))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_discarded_total", nil))).
			To(Equal(1.0))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_refresh_failures_total", nil))).
			To(Equal(2.0))
	})

	It("reports when the chain file was last read, zero until it has been, "+
		"and nothing at all when the feature is off", func() {
		// An absent or mis-mounted path moves no counter, so every dashboard
		// read healthy while the ancestors aged.
		//
		// The three states have to be distinguishable in PromQL, which is why
		// the emission is gated on the file being *configured* rather than on it
		// having been read. Gating on first read collapsed "configured but never
		// opened" together with "feature not in use", and since no other series
		// tells those apart -- the counters are unconditional and read 0 in both
		// -- absent() could not be put in an alert without firing on every
		// instance in the fleet that never configured a chain file.
		g := gather(metrics.NewCollector(myCA))
		Expect(g["puppetca_crl_chain_last_read_timestamp_seconds"]).To(BeNil(),
			"no crl_chain_file: the series must not exist")

		// Configured, pointing at a path that never mounted. This is the state
		// the series exists for, and the one that had no coverage: the previous
		// absence assertion was taken while the feature was still unconfigured,
		// so moving the stamp to an *attempted* read left the suite green.
		myCA.CRLChainFile = filepath.Join(GinkgoT().TempDir(), "never-mounted.pem")
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		g = gather(metrics.NewCollector(myCA))
		Expect(gaugeValue(g.findUnlabelled("puppetca_crl_chain_last_read_timestamp_seconds"))).
			To(Equal(0.0), "configured but never opened must be reported, and as zero")

		path := filepath.Join(GinkgoT().TempDir(), "empty.pem")
		Expect(os.WriteFile(path, nil, 0o644)).To(Succeed())
		myCA.CRLChainFile = path
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		// Asserted at its value, not merely its sign: the series is documented
		// as seconds since the epoch, and a UnixMilli stamp would make every
		// staleness expression written against it silently never fire.
		g = gather(metrics.NewCollector(myCA))
		Expect(gaugeValue(g.findUnlabelled("puppetca_crl_chain_last_read_timestamp_seconds"))).
			To(BeNumerically("~", float64(time.Now().Unix()), 5),
				"an empty file is still a file we read")
	})

	It("still exports every other series when the chain cannot be decoded", func() {
		// gather()'s upstream branch is best-effort by design: a blob it cannot
		// decode must cost the per-issuer chain gauge and nothing else, because
		// the CA gauges beside it are what an operator pages on. Nothing drove
		// that arm, so a change that returned early -- or let the error escape
		// -- would take the whole scrape down with it, and the two shipped CRL
		// expiry alerts would go quiet rather than fire.
		// Publish a real ancestor first, so the gauge this failure costs is
		// present to begin with. Asserting its absence without that proves
		// nothing: it is absent on any CA with no chain at all.
		upstream, upsKey := upstreamCAWithKeyFixture("Undecodable Chain CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})...))).
			To(Succeed())
		path := filepath.Join(GinkgoT().TempDir(), "chain.pem")
		Expect(os.WriteFile(path, numberedCRLFixture(upstream, upsKey, 3), 0o644)).To(Succeed())
		myCA.CRLChainFile = path
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		healthy := gather(metrics.NewCollector(myCA))
		Expect(healthy).To(HaveKey("puppetca_crl_chain_next_update_timestamp_seconds"),
			"precondition: the gauge this failure costs must exist first")

		// Now a block that decodes as PEM and fails to parse as a CRL, appended
		// after our own so block 0 still parses: the shape a truncated append
		// leaves behind.
		stored, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, stored...),
			pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte("not a CRL")})...))).
			To(Succeed())

		g := gather(metrics.NewCollector(myCA))
		Expect(g.findByLabels("puppetca_crl_number", nil)).NotTo(BeNil(),
			"a chain it cannot read must not cost the CA's own CRL series")
		Expect(g.findByLabels("puppetca_ca_certificate_not_after_timestamp_seconds", nil)).NotTo(BeNil())
		Expect(g).NotTo(HaveKey("puppetca_crl_chain_next_update_timestamp_seconds"),
			"the per-issuer gauge is the one thing the failure costs")
	})

	It("exports the removal counter by name, and at its value", func() {
		// The only one of the four chain counters never gathered in a spec, and
		// the worst to leave uncovered: PuppetCAUpstreamCRLRemoved routes on this
		// name, and the condition behind it is invisible from every other angle
		// -- the ancestor's own expiry series simply stops being produced, and a
		// vanished series fires nothing.
		upstream, upsKey := upstreamCAWithKeyFixture("Departing Ancestor CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})...))).
			To(Succeed())

		path := filepath.Join(GinkgoT().TempDir(), "chain.pem")
		Expect(os.WriteFile(path, numberedCRLFixture(upstream, upsKey, 5), 0o644)).To(Succeed())
		myCA.CRLChainFile = path
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		g := gather(metrics.NewCollector(myCA))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_removed_total", nil))).
			To(Equal(0.0))

		// The file stops listing it. Honoured, unrecoverable, and counted.
		Expect(os.WriteFile(path, nil, 0o644)).To(Succeed())
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		g = gather(metrics.NewCollector(myCA))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_removed_total", nil))).
			To(BeNumerically(">", 0))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_discarded_total", nil))).
			To(Equal(0.0), "an ancestor the file omits is not a CRL the bundle refused")
	})

	It("counts a stale upstream CRL separately from an unvouched-for one", func() {
		// The two share nothing but the word "dropped": a discard means the CA
		// bundle is incomplete, a regression means the file is stale. They had
		// one counter between them, so a rolled-back mirror fired
		// PuppetCAUpstreamCRLDiscarded, whose runbook says to check that the
		// bundle is complete -- which it is, since a signature-invalid CRL never
		// reaches the comparison.
		g := gather(metrics.NewCollector(myCA))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_regressed_total", nil))).
			To(Equal(0.0))

		upstream, upsKey := upstreamCAWithKeyFixture("Rollback CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})...))).
			To(Succeed())

		storedCRL, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, storedCRL...),
			numberedCRLFixture(upstream, upsKey, 99)...))).To(Succeed())

		path := filepath.Join(GinkgoT().TempDir(), "rollback.pem")
		Expect(os.WriteFile(path, numberedCRLFixture(upstream, upsKey, 7), 0o644)).To(Succeed())
		myCA.CRLChainFile = path
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		g = gather(metrics.NewCollector(myCA))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_regressed_total", nil))).
			To(Equal(1.0))
		Expect(counterValue(g.findByLabels("puppetca_crl_chain_discarded_total", nil))).
			To(Equal(0.0), "a rollback must not move the counter whose runbook blames the bundle")
	})

	It("reports one labelled upstream CRL series per ancestor in the published chain", func() {
		// The new series had no coverage at all: not its name, not its label,
		// not its value. A rename would have stopped the mixin's
		// PuppetCAUpstreamCRLExpired firing with the suite green.
		upstream, upsCRL := upstreamCRLFixture("Upstream Root CA")
		Expect(upstream).NotTo(BeNil())
		ours, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ours...), upsCRL...))).To(Succeed())

		g := gather(metrics.NewCollector(myCA))

		chain := g.findByLabels("puppetca_crl_chain_next_update_timestamp_seconds",
			map[string]string{"issuer": "CN=Upstream Root CA"})
		Expect(chain).NotTo(BeNil(), "no series for the upstream issuer")
		// The value, not merely its sign: both ThisUpdate and NextUpdate are
		// large positive timestamps, so "> 0" passes with the fields
		// transposed -- which would make PuppetCAUpstreamCRLExpired a
		// permanent, unclearable critical page.
		Expect(gaugeValue(chain)).To(BeNumerically("~", float64(upstreamCRLNextUpdate(upsCRL).Unix()), 1))

		// And our own series stays unlabelled and single, which is the whole
		// point of not relabelling it.
		Expect(g.findUnlabelled("puppetca_crl_next_update_timestamp_seconds")).NotTo(BeNil())
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

// upstreamCRLNextUpdate reads the NextUpdate out of a PEM-encoded CRL, so a
// spec can assert the gauge carries that field rather than merely a plausible
// timestamp.
func upstreamCRLNextUpdate(crlPEM []byte) time.Time {
	GinkgoHelper()
	block, _ := pem.Decode(crlPEM)
	Expect(block).NotTo(BeNil())
	crl, err := x509.ParseRevocationList(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return crl.NextUpdate
}
