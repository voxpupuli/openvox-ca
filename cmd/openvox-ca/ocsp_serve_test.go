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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The OCSP responder is unauthenticated, and a nonced request costs a CA-key
// signature, so it is served only when enable_ocsp says so. ocsp_url is a
// different question -- what issued certificates advertise -- and must not
// switch the route on.

var _ = Describe("the serve command's /ocsp", func() {
	var caDir, logPath string

	BeforeEach(func() {
		// Ambient OPENVOX_CA_* would outrank the fixture config.
		clearServerEnv()
		caDir = GinkgoT().TempDir()
		logPath = filepath.Join(GinkgoT().TempDir(), "server.log")
		bootstrapCAInDir(caDir, "ca.example.com")
		// The command points the default logger at logfile and leaves it
		// there. Registered before the server starts, so the server is
		// stopped before the logger is restored.
		DeferCleanup(slog.SetDefault, slog.Default())
	})

	// config is a plain-HTTP loopback server logging to logPath, so a spec can
	// read what the command logged without capturing stderr.
	config := func(extra string) string {
		GinkgoHelper()
		path := serveConfig(caDir, GinkgoT().TempDir(), "127.0.0.1", freeLoopbackPort(), false)
		appendConfig(path, fmt.Sprintf("logfile: %s\n", logPath)+extra)
		return path
	}

	serverLog := func() string {
		GinkgoHelper()
		data, err := os.ReadFile(logPath)
		Expect(err).NotTo(HaveOccurred())
		return string(data)
	}

	// An empty POST: malformed, so the responder answers it without signing,
	// and in a body only the responder sends.
	postOCSP := func(addr string) *http.Response {
		GinkgoHelper()
		resp, err := plainClient().Post("http://"+addr+"/puppet-ca/v1/ocsp",
			"application/ocsp-request", strings.NewReader(""))
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(resp.Body.Close)
		return resp
	}

	It("does not serve it by default, and says so at startup", func() {
		addr := startServe(config(""))

		Expect(postOCSP(addr).StatusCode).To(Equal(http.StatusNotFound))
		Expect(serverLog()).To(ContainSubstring("OCSP responder disabled"))
		Expect(serverLog()).NotTo(ContainSubstring("ocsp_url is set but enable_ocsp is not"))
	})

	It("does not serve it when only ocsp_url is set, and warns that certificates advertise it", func() {
		addr := startServe(config("ocsp_url: http://ca.example.com:8140/ocsp\n"))

		Expect(postOCSP(addr).StatusCode).To(Equal(http.StatusNotFound),
			"ocsp_url must not switch the responder on")
		Expect(serverLog()).To(ContainSubstring("ocsp_url is set but enable_ocsp is not"))
	})

	// Through the flag rather than the file, which pins the flag's overlay as
	// well; the file and the environment are pinned in config_test.go.
	It("serves it when --enable-ocsp is set", func() {
		addr := startServe(config("ocsp_url: http://ca.example.com:8140/ocsp\n"), "--enable-ocsp")

		resp := postOCSP(addr)
		Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
		Expect(resp.Header.Get("Content-Type")).To(Equal("application/ocsp-response"))
		Expect(serverLog()).To(ContainSubstring("OCSP responder enabled"))
		Expect(serverLog()).NotTo(ContainSubstring("ocsp_url is set but enable_ocsp is not"))
	})
})

var _ = DescribeTable("ocspURLWithoutResponderNotice",
	func(cfg *serverConfig, warns bool) {
		if warns {
			Expect(ocspURLWithoutResponderNotice(cfg)).To(ContainSubstring("does not serve"))
		} else {
			Expect(ocspURLWithoutResponderNotice(cfg)).To(BeEmpty())
		}
	},
	Entry("neither set", &serverConfig{}, false),
	Entry("enable_ocsp alone", &serverConfig{EnableOCSP: true}, false),
	Entry("both set", &serverConfig{EnableOCSP: true, OCSPUrl: "http://ca.example.com/ocsp"}, false),
	Entry("ocsp_url alone", &serverConfig{OCSPUrl: "http://ca.example.com/ocsp"}, true),
)

// The serial index feeds only the responder, and with it off the index sync job
// does not run (background_jobs_test.go), so its series would be a startup
// count and a constant zero. This pins the join from enable_ocsp to the
// exporter; internal/metrics pins what the option itself removes.
var _ = DescribeTable("metricsOptions: the OCSP index series",
	func(enabled, exported bool) {
		myCA := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "ca.example.com")
		exporter := metrics.NewExporter(myCA, metricsOptions(&serverConfig{EnableOCSP: enabled})...)
		names := gatheredNames(exporter.Registry())
		for _, name := range []string{"openvoxca_ocsp_index_serials", "openvoxca_ocsp_index_sync_failures_total"} {
			if exported {
				Expect(names).To(ContainElement(name))
			} else {
				Expect(names).NotTo(ContainElement(name))
			}
		}
	},
	Entry("are exported when enable_ocsp is set", true, true),
	Entry("are omitted when it is not", false, false),
)

// gatheredNames lists the metric families reg currently exports.
func gatheredNames(reg prometheus.Gatherer) []string {
	GinkgoHelper()
	mfs, err := reg.Gather()
	Expect(err).NotTo(HaveOccurred())
	names := make([]string, 0, len(mfs))
	for _, mf := range mfs {
		names = append(names, mf.GetName())
	}
	return names
}
