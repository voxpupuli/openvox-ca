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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/constants"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// roleValues returns the RoleLabel value of every metric in the named family,
// or nil when the family is absent.
func roleValues(mfs []*dto.MetricFamily, name string) []string {
	var roles []string
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			role := "<none>"
			for _, lp := range m.GetLabel() {
				if lp.GetName() == metrics.RoleLabel {
					role = lp.GetValue()
				}
			}
			roles = append(roles, role)
		}
	}
	return roles
}

// gaugeFor returns the value of the named family's metric labelled role.
func gaugeFor(mfs []*dto.MetricFamily, name, role string) (float64, bool) {
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == metrics.RoleLabel && lp.GetValue() == role {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

// fakeRuntime stands in for the signer's RPC: a Gatherer returning whatever it
// was given.
type fakeRuntime struct {
	mfs []*dto.MetricFamily
	err error
}

func (f fakeRuntime) Gather() ([]*dto.MetricFamily, error) { return f.mfs, f.err }

// runtimeOf gathers a real Go collector, so the families have the help text
// and types the exporter's own carry, as the signer's do in production.
func runtimeOf(extra ...prometheus.Collector) []*dto.MetricFamily {
	GinkgoHelper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(extra...)
	mfs, err := reg.Gather()
	Expect(err).NotTo(HaveOccurred())
	return mfs
}

var _ = Describe("which process the exporter's go_* and process_* series describe", func() {
	var exporter *metrics.Exporter

	BeforeEach(func() {
		exporter = metrics.NewExporter(
			ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test"), "frontend")
	})

	gather := func() []*dto.MetricFamily {
		GinkgoHelper()
		mfs, err := exporter.Gatherer().Gather()
		Expect(err).NotTo(HaveOccurred())
		return mfs
	}

	It("labels its own runtime and process series with the role it serves as", func() {
		mfs := gather()
		Expect(roleValues(mfs, "go_goroutines")).To(Equal([]string{"frontend"}))
		if runtime.GOOS == "linux" {
			Expect(roleValues(mfs, "process_resident_memory_bytes")).To(Equal([]string{"frontend"}))
		}
	})

	It("leaves the CA's own series unlabelled, since they describe the CA and not a process", func() {
		mfs := gather()
		Expect(roleValues(mfs, "openvoxca_http_requests_in_flight")).To(Equal([]string{"<none>"}))
	})

	Describe("AddProcess", func() {
		// A real sibling: a child process that is not this one, so a collector
		// that ignored the PID and read itself would be told apart.
		sibling := func() int {
			GinkgoHelper()
			cmd := exec.Command("sleep", "60")
			Expect(cmd.Start()).To(Succeed())
			DeferCleanup(func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			})
			return cmd.Process.Pid
		}

		It("reports another process's process_* series under its role", func() {
			if runtime.GOOS != "linux" {
				Skip("process_* for another PID is read from /proc, which only Linux has")
			}
			exporter.AddProcess("signer", sibling())
			mfs := gather()
			Expect(roleValues(mfs, "process_resident_memory_bytes")).To(ConsistOf("frontend", "signer"))

			// sleep(1) is a few hundred KiB resident; a Go test binary is tens
			// of MiB. Equal values would mean the sibling's collector read this
			// process instead.
			own, _ := gaugeFor(mfs, "process_resident_memory_bytes", "frontend")
			sib, ok := gaugeFor(mfs, "process_resident_memory_bytes", "signer")
			Expect(ok).To(BeTrue())
			Expect(sib).To(BeNumerically(">", 0))
			Expect(sib).To(BeNumerically("<", own))
		})

		It("adds no go_* series for it, since only its own runtime can report those", func() {
			exporter.AddProcess("launcher", sibling())
			Expect(roleValues(gather(), "go_goroutines")).To(Equal([]string{"frontend"}))
		})
	})

	Describe("AddRuntime", func() {
		It("merges another process's go_* series into the same families under its role", func() {
			exporter.AddRuntime("signer", fakeRuntime{mfs: runtimeOf()})
			mfs := gather()
			Expect(roleValues(mfs, "go_goroutines")).To(ConsistOf("frontend", "signer"))
			Expect(roleValues(mfs, "go_gc_gomemlimit_bytes")).To(ConsistOf("frontend", "signer"))
		})

		// The role is the exporter's to assign. A source that labels its own
		// series, by accident or otherwise, must not be able to pass them off
		// as another process's, or collide with the exporter's own.
		It("replaces any role the source supplies", func() {
			claimed := runtimeOf()
			for _, mf := range claimed {
				for _, m := range mf.GetMetric() {
					m.Label = append(m.Label, &dto.LabelPair{Name: new(metrics.RoleLabel), Value: new("frontend")})
				}
			}
			exporter.AddRuntime("signer", fakeRuntime{mfs: claimed})
			Expect(roleValues(gather(), "go_goroutines")).To(ConsistOf("frontend", "signer"))
		})

		It("takes only go_* families from the source", func() {
			stray := prometheus.NewGauge(prometheus.GaugeOpts{Name: "openvoxca_ca_ready", Help: "stray"})
			exporter.AddRuntime("signer", fakeRuntime{mfs: runtimeOf(stray)})
			mfs := gather()
			Expect(roleValues(mfs, "go_goroutines")).To(ContainElement("signer"))
			for _, mf := range mfs {
				Expect(strings.HasPrefix(mf.GetName(), "openvoxca_") && mf.GetHelp() == "stray").To(BeFalse(),
					"a non-go_* family from the source was served")
			}
		})

		// The one openvoxca_* family the signer may report, because only the
		// process holding the OpenBao token manager can see its state. Kept as
		// sent: like every openvoxca_* series it describes the CA, so it
		// carries no role, and an alert on it must not have to say which
		// process to look at.
		It("takes the OpenBao authentication gauge from the source, without a role", func() {
			gauge := prometheus.NewGauge(prometheus.GaugeOpts{
				Name: constants.OpenBaoAuthenticatedMetric, Help: "from the signer"})
			gauge.Set(0)
			exporter.AddRuntime("signer", fakeRuntime{mfs: runtimeOf(gauge)})
			mfs := gather()
			Expect(roleValues(mfs, constants.OpenBaoAuthenticatedMetric)).To(Equal([]string{"<none>"}),
				"the signer's gauge must be served, once, with no role label")
			for _, mf := range mfs {
				if mf.GetName() == constants.OpenBaoAuthenticatedMetric {
					Expect(mf.GetMetric()[0].GetGauge().GetValue()).To(Equal(0.0),
						"the value must be the signer's, not a default")
				}
			}
		})

		It("serves the rest of the scrape when the source fails", func() {
			exporter.AddRuntime("signer", fakeRuntime{err: errors.New("signer wedged")})
			mfs := gather()
			Expect(roleValues(mfs, "go_goroutines")).To(Equal([]string{"frontend"}))
			Expect(roleValues(mfs, "openvoxca_http_requests_in_flight")).NotTo(BeEmpty())
		})

		// The warning is the operator's only sign that the signer's series are
		// gone. The frontend writes it, through a logger that already carries
		// role=frontend, so naming the failed process with the same key would
		// give the line two roles -- and jq keeps the last, filing a frontend
		// line under the signer.
		It("warns, naming the failed process without claiming the record's role", func() {
			orig := slog.Default()
			DeferCleanup(func() { slog.SetDefault(orig) })
			logs := gbytes.NewBuffer()
			slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)).With(metrics.RoleLabel, "frontend"))

			exporter.AddRuntime("signer", fakeRuntime{err: errors.New("signer wedged")})
			gather()

			line := strings.TrimSpace(string(logs.Contents()))
			Expect(strings.Count(line, "\n")).To(BeZero(), "one record:\n%s", line)
			Expect(strings.Count(line, `"role":`)).To(Equal(1), "exactly one role key:\n%s", line)
			var entry map[string]any
			Expect(json.Unmarshal([]byte(line), &entry)).To(Succeed())
			Expect(entry).To(HaveKeyWithValue("level", "WARN"))
			Expect(entry).To(HaveKeyWithValue("role", "frontend"))
			Expect(entry).To(HaveKeyWithValue("sibling", "signer"))
			Expect(entry).To(HaveKeyWithValue("error", "signer wedged"))
		})

		It("reaches /metrics, not only the Gatherer", func() {
			exporter.AddRuntime("signer", fakeRuntime{mfs: runtimeOf()})
			rec := httptest.NewRecorder()
			exporter.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			Expect(rec.Code).To(Equal(http.StatusOK))
			body, err := io.ReadAll(rec.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(ContainSubstring(`go_goroutines{role="signer"}`))
			Expect(string(body)).To(ContainSubstring(`go_goroutines{role="frontend"}`))
		})
	})
})
