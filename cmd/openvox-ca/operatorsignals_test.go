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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/constants"
	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("openvoxca_destructive_operations_total", func() {
	values := func(reg *prometheus.Registry) map[string]float64 {
		GinkgoHelper()
		mfs, err := reg.Gather()
		Expect(err).NotTo(HaveOccurred())
		Expect(mfs).To(HaveLen(1))
		Expect(mfs[0].GetName()).To(Equal("openvoxca_destructive_operations_total"))
		out := map[string]float64{}
		for _, m := range mfs[0].GetMetric() {
			Expect(m.GetLabel()).To(HaveLen(1))
			Expect(m.GetLabel()[0].GetName()).To(Equal("operation"))
			out[m.GetLabel()[0].GetValue()] = m.GetCounter().GetValue()
		}
		return out
	}

	It("publishes every operation at zero before the first one happens", func() {
		// The mixin's alert is an increase() over this series, and increase()
		// over a series that does not exist yet never fires: the first burst
		// after a restart would go unseen.
		reg := prometheus.NewRegistry()
		newDestructiveOperationsCounter(reg)
		Expect(values(reg)).To(Equal(map[string]float64{"revoke": 0, "clean": 0, "bulk-clean": 0}))
	})

	It("adds each report's subjects to its operation", func() {
		reg := prometheus.NewRegistry()
		report := newDestructiveOperationsCounter(reg)
		report("bulk-clean", 3)
		report("revoke", 1)
		report("bulk-clean", 2)
		Expect(values(reg)).To(Equal(map[string]float64{"revoke": 1, "clean": 0, "bulk-clean": 5}))
	})
})

var _ = Describe("keyProviderCollectors", func() {
	// The helper only. The joins it feeds -- the single-process server's
	// exporter and the signer's Metrics registry -- are driven below and in
	// internal/signer respectively.
	It("returns an OpenBao provider's collector", func() {
		p := openbao.NewKeyProvider(nil, "transit", "ca")
		Expect(keyProviderCollectors(p)).To(ConsistOf(p))
	})

	It("returns nothing for a nil provider, as on the frontend or with a local key", func() {
		Expect(keyProviderCollectors(nil)).To(BeEmpty())
	})
})

// collectingProvider is a key provider that, like the OpenBao one, reports its
// session as a collector. It serves the CA key already in the store, so the
// server starts as it would against a reachable Transit key.
type collectingProvider struct{ store *storage.StorageService }

var collectingProviderDesc = prometheus.NewDesc(constants.OpenBaoAuthenticatedMetric, "stub session", nil, nil)

func (p collectingProvider) Load(ctx context.Context) (crypto.Signer, error) {
	keyPEM, err := p.store.GetCAKey(ctx)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in the stored CA key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if ec, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			return ec, nil
		}
		return nil, err
	}
	return key.(crypto.Signer), nil
}

func (collectingProvider) Generate(context.Context, ca.KeyConfig) (crypto.Signer, error) {
	return nil, fmt.Errorf("collectingProvider.Generate must not be called")
}

func (collectingProvider) Describe(ch chan<- *prometheus.Desc) { ch <- collectingProviderDesc }

func (collectingProvider) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(collectingProviderDesc, prometheus.GaugeValue, 1)
}

// The serve command's own wiring of the series #666 added, which the specs of
// the helpers above cannot reach: it sits inline in the server start-up.
var _ = Describe("the serve command's operator-signal series", func() {
	var caDir, configPath, metricsAddr string

	BeforeEach(func() {
		// Ambient OPENVOX_CA_* would outrank the fixture config.
		clearServerEnv()
		caDir = GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "ca.example.com")
		// The command points the default logger at logfile and leaves it
		// there. Registered before the server starts, so the server is
		// stopped before the logger is restored.
		DeferCleanup(slog.SetDefault, slog.Default())

		metricsAddr = fmt.Sprintf("127.0.0.1:%d", freeLoopbackPort())
		configPath = serveConfig(caDir, "", "127.0.0.1", freeLoopbackPort(), false)
		appendConfig(configPath, fmt.Sprintf("metrics_listen: %s\nlogfile: %s\n",
			metricsAddr, filepath.Join(GinkgoT().TempDir(), "server.log")))
	})

	// Takes a Gomega so that Eventually retries a refused connection: the
	// exporter binds in its own goroutine, unordered against READY=1.
	scrape := func(g Gomega) string {
		resp, err := plainClient().Get("http://" + metricsAddr + "/metrics")
		g.Expect(err).NotTo(HaveOccurred())
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		g.Expect(err).NotTo(HaveOccurred())
		return string(body)
	}

	It("exports openvoxca_destructive_operations_total for every operation", func() {
		startServe(configPath)
		Eventually(scrape).Should(SatisfyAll(
			ContainSubstring(`openvoxca_destructive_operations_total{operation="revoke"} 0`),
			ContainSubstring(`openvoxca_destructive_operations_total{operation="clean"} 0`),
			ContainSubstring(`openvoxca_destructive_operations_total{operation="bulk-clean"} 0`),
		))
	})

	It("serves the key provider's session state from a single-process server", func() {
		original := newKeyProvider
		DeferCleanup(func() { newKeyProvider = original })
		newKeyProvider = func(context.Context, *serverConfig) (func() error, ca.KeyProvider, error) {
			return func() error { return nil }, collectingProvider{store: storage.New(caDir)}, nil
		}
		appendConfig(configPath, "ca_key_provider: openbao\n")

		startServe(configPath)
		Eventually(scrape).Should(ContainSubstring("\n" + constants.OpenBaoAuthenticatedMetric + " 1\n"))
	})

	It("serves no session state without a key provider", func() {
		// The floor under the spec above: a server whose key is local has no
		// session to report, so the series must be absent rather than 0.
		startServe(configPath)
		Eventually(scrape).Should(ContainSubstring("openvoxca_destructive_operations_total"))
		Expect(scrape(Default)).NotTo(ContainSubstring(constants.OpenBaoAuthenticatedMetric))
	})
})
