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
	"bytes"
	"log/slog"
	"net"
	"net/rpc"
	"os"
	"runtime"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/signer"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// seriesRoles returns the role label of every metric in the named family.
func seriesRoles(mfs []*dto.MetricFamily, name string) []string {
	for _, mf := range mfs {
		if mf.GetName() == name {
			return familyRoles(mf)
		}
	}
	return nil
}

var _ = Describe("the frontend's view of its siblings", func() {
	var (
		exporter *metrics.Exporter
		logs     *gbytes.Buffer
	)

	BeforeEach(func() {
		if runtime.GOOS != "linux" {
			Skip("a sibling's process_* series is read from /proc, which only Linux has")
		}
		exporter = metrics.NewExporter(
			ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test"), roleFrontend)
		orig := slog.Default()
		DeferCleanup(func() { slog.SetDefault(orig) })
		logs = gbytes.NewBuffer()
		slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	})

	processRoles := func() []string {
		GinkgoHelper()
		mfs, err := exporter.Gatherer().Gather()
		Expect(err).NotTo(HaveOccurred())
		return seriesRoles(mfs, "process_resident_memory_bytes")
	}

	// This process stands in for both siblings: what is asserted is which
	// roles get series, and the exporter specs already show a sibling's series
	// is read from its own PID.
	self := strconv.Itoa(os.Getpid())

	It("reports both siblings at the PIDs the launcher handed over", func() {
		env := map[string]string{launcherPIDEnv: self, signerPIDEnv: self}
		addSiblingTelemetry(exporter, func(k string) string { return env[k] }, nil)
		Expect(processRoles()).To(ConsistOf(roleFrontend, roleLauncher, roleSigner))
	})

	It("reports only itself when started by hand, with no launcher to name them", func() {
		addSiblingTelemetry(exporter, func(string) string { return "" }, nil)
		Expect(processRoles()).To(ConsistOf(roleFrontend))
		Expect(logs).NotTo(gbytes.Say("level=WARN"), "a hand-started frontend is a supported topology")
	})

	DescribeTable("ignores a PID it cannot use, and says so",
		func(value string) {
			env := map[string]string{launcherPIDEnv: self, signerPIDEnv: value}
			addSiblingTelemetry(exporter, func(k string) string { return env[k] }, nil)
			Expect(processRoles()).To(ConsistOf(roleFrontend, roleLauncher))
			Expect(logs).To(gbytes.Say(`level=WARN .* sibling=signer variable=` + signerPIDEnv))
		},
		Entry("not a number", "signer"),
		Entry("zero", "0"),
		Entry("negative", "-1"),
	)
})

// fakeSignerMetrics stands in for the isolated signer's Metrics RPC, answering
// with this process's own Go runtime families.
type fakeSignerMetrics struct{}

func (fakeSignerMetrics) Metrics(_ *signer.MetricsRequest, resp *signer.MetricsResponse) error {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	mfs, err := reg.Gather()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeProtoDelim))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return err
		}
	}
	resp.Families = buf.Bytes()
	return nil
}

// Outside the Linux-only Describe above: what is pinned here needs no /proc.
// A frontend started by hand has no PIDs, but it does have its signer, and the
// signer's go_* series come over the socketpair whatever the PIDs say.
var _ = Describe("a frontend started without the launcher", func() {
	It("still reports the signer's go_* series, and process_* for itself alone", func() {
		serverConn, clientConn := net.Pipe()
		server := rpc.NewServer()
		Expect(server.RegisterName("Signer", fakeSignerMetrics{})).To(Succeed())
		go server.ServeConn(serverConn)
		rs := signer.NewRemoteSigner(clientConn, nil)
		DeferCleanup(rs.Close)

		exporter := metrics.NewExporter(
			ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test"), roleFrontend)
		addSiblingTelemetry(exporter, func(string) string { return "" }, rs)

		mfs, err := exporter.Gatherer().Gather()
		Expect(err).NotTo(HaveOccurred())
		Expect(seriesRoles(mfs, "go_goroutines")).To(ConsistOf(roleFrontend, roleSigner))
		// No sibling's process_*: there are no PIDs to read them at. The
		// frontend's own resident memory is not certain off Linux (macOS
		// reports it only in a cgo build), so only Linux pins it.
		processRoles := seriesRoles(mfs, "process_resident_memory_bytes")
		Expect(processRoles).NotTo(ContainElement(roleSigner))
		Expect(processRoles).NotTo(ContainElement(roleLauncher))
		if runtime.GOOS == "linux" {
			Expect(processRoles).To(ConsistOf(roleFrontend))
		}
	})
})
