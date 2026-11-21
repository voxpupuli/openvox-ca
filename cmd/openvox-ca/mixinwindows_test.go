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
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// mixinConfig reads mixin/config.libsonnet's scalar _config values: durations
// written as quoted strings ('30m') and integers, including a product such as
// 3 * 3600. It is a reader for this file's layout, not for Jsonnet.
func mixinConfig() (durations map[string]time.Duration, ints map[string]int) {
	GinkgoHelper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "mixin", "config.libsonnet"))
	Expect(err).NotTo(HaveOccurred())

	durations, ints = map[string]time.Duration{}, map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(\w+):\s*'([0-9]+[smhd])',`).FindAllStringSubmatch(string(raw), -1) {
		d, err := time.ParseDuration(m[2])
		Expect(err).NotTo(HaveOccurred(), "%s: %q", m[1], m[2])
		durations[m[1]] = d
	}
	for _, m := range regexp.MustCompile(`(?m)^\s*(\w+):\s*([0-9][0-9 *]*),`).FindAllStringSubmatch(string(raw), -1) {
		product := 1
		for _, factor := range strings.Split(m[2], "*") {
			n, err := strconv.Atoi(strings.TrimSpace(factor))
			Expect(err).NotTo(HaveOccurred(), "%s: %q", m[1], m[2])
			product *= n
		}
		ints[m[1]] = product
	}
	return durations, ints
}

// The shipped mixin sizes several windows and dwells against the default of a
// server interval: a counter that moves once per pass needs a window holding
// enough passes to cross its threshold, or the alert can never fire, and a
// dwell shorter than the interval pages on a single transient failure.
// releasing.md lets some of those defaults move in a minor release (the
// OCSP index sync interval, for one) provided the release notes say so; this
// is what notices that a move has broken an alert before the notes have to.
//
// Each default is read through the accessor the server applies it with, on the
// configuration loadServerConfig builds from nothing, so it is the default the
// server runs with rather than a constant that might no longer be the one used. Two windows are guarded
// elsewhere, beside the code they depend on: fileExportStaleAfterSeconds in
// internal/fileexport, and expiryFor against the exporter's stale-snapshot
// hold in internal/metrics.
var _ = Describe("the mixin's windows against the server's defaults", func() {
	var (
		d   map[string]time.Duration
		n   map[string]int
		cfg *serverConfig
	)

	BeforeEach(func() {
		d, n = mixinConfig()
		// As the server loads it, sentinels and all: a zero struct reads 0
		// for a setting whose default is a sentinel resolved later.
		clearServerEnv()
		var err error
		cfg, err = loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
	})

	key := func(name string) time.Duration {
		GinkgoHelper()
		v, ok := d[name]
		Expect(ok).To(BeTrue(), "mixin/config.libsonnet has no duration %s", name)
		return v
	}
	count := func(name string) int {
		GinkgoHelper()
		v, ok := n[name]
		Expect(ok).To(BeTrue(), "mixin/config.libsonnet has no integer %s", name)
		return v
	}

	const remedy = "; resize the mixin's default and the server's together, and say so in the release notes"

	// A threshold counted over a window needs threshold + 1 intervals in it:
	// increase() wants a sample from before the oldest counted failure, so a
	// window of exactly threshold intervals drops it as the next arrives.
	DescribeTable("a counted window holds threshold + 1 passes of the server's interval",
		func(window, threshold string, interval func() time.Duration) {
			want := time.Duration(count(threshold)+1) * interval()
			Expect(key(window)).To(BeNumerically(">=", want),
				"%s (%v) must hold %s + 1 passes of %v, or the alert can never fire"+remedy,
				window, key(window), threshold, interval())
		},
		Entry("OpenVoxCACRLUpdateFailing, against crl_refresh_interval_sec",
			"crlUpdateWindow", "crlUpdateThreshold", func() time.Duration { return cfg.crlRefreshInterval() }),
		Entry("OpenVoxCACRLSyncFailing, against crl_sync_interval_sec",
			"crlSyncWindow", "crlSyncThreshold", func() time.Duration { return cfg.crlSyncInterval() }),
		Entry("OpenVoxCAOCSPIndexSyncFailing, against ocsp_index_sync_interval_sec",
			"ocspIndexSyncWindow", "ocspIndexSyncThreshold", func() time.Duration { return cfg.ocspIndexSyncInterval() }),
		Entry("OpenVoxCAInventoryUnreadable, against inventory_verify_interval_sec",
			"inventoryUnreadableWindow", "inventoryUnreadableThreshold", func() time.Duration { return cfg.inventoryVerifyInterval() }),
	)

	// A window with no threshold, counting a fault that recurs once per pass,
	// needs two passes in it, or increase() falls to zero between them and an
	// alert with no dwell resolves and re-fires on every pass.
	DescribeTable("an uncounted window holds two passes of the server's interval",
		func(window string, interval func() time.Duration) {
			Expect(key(window)).To(BeNumerically(">=", 2*interval()),
				"%s (%v) must hold two passes of %v, or the alert flaps"+remedy, window, key(window), interval())
		},
		Entry("the upstream CRL chain rules, against the CRL chain refresh interval",
			"crlChainWindow", func() time.Duration { return cfg.crlChainRefreshInterval() }),
		Entry("OpenVoxCAInventoryTampered, against inventory_verify_interval_sec",
			"inventoryTamperWindow", func() time.Duration { return cfg.inventoryVerifyInterval() }),
	)

	// A dwell meant to ride out one failed pass has to outlast the interval
	// the job retries on, or a single transient failure pages.
	DescribeTable("a dwell outlasts the interval the job retries on",
		func(dwell string, interval func() time.Duration) {
			Expect(key(dwell)).To(BeNumerically(">", interval()),
				"%s (%v) must outlast %v"+remedy, dwell, key(dwell), interval())
		},
		Entry("OpenVoxCASupersedeFailing, against superseded_cert_sweep_interval_sec",
			"supersedeFor", func() time.Duration { return cfg.supersededCertSweepInterval() }),
		Entry("OpenVoxCAManagedCertificateNeverIssued, against managed_cert_interval_sec",
			"managedCertNeverIssuedFor", func() time.Duration { return cfg.managedCertInterval() }),
		Entry("OpenVoxCAManagedCertificateReissueFailing, against managed_cert_interval_sec",
			"managedCertReissueFailingFor", func() time.Duration { return cfg.managedCertInterval() }),
	)

	It("pages for a lagging replica only after the sync warning that explains it", func() {
		// crlSyncThreshold failed passes plus crlSyncFor must come in under
		// crlLagFor, or the page arrives before the warning saying why.
		warn := time.Duration(count("crlSyncThreshold"))*cfg.crlSyncInterval() + key("crlSyncFor")
		Expect(warn).To(BeNumerically("<", key("crlLagFor")),
			"OpenVoxCACRLSyncFailing (after %v) must fire before OpenVoxCACRLStale (crlLagFor %v)"+remedy,
			warn, key("crlLagFor"))
	})

	It("calls a client_ca CRL stale only after three refresh passes", func() {
		interval := (&config.ClientCAConfig{}).ClientCRLRefreshInterval()
		stale := time.Duration(count("clientCRLStaleSeconds")) * time.Second
		Expect(stale).To(BeNumerically(">=", 3*interval),
			"clientCRLStaleSeconds (%v) must cover three passes of client_crl_refresh_interval_sec (%v), "+
				"or OpenVoxCAClientCRLStale fires on a healthy CA"+remedy, stale, interval)
	})
})
