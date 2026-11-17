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
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	xocsp "golang.org/x/crypto/ocsp"

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
		// The default limit, which also pins that the resolved value reaches
		// the server rather than the -1 sentinel.
		Expect(serverLog()).To(ContainSubstring(`"msg":"OCSP responder enabled at /ocsp","rate_limit_per_minute":300`))
		Expect(serverLog()).NotTo(ContainSubstring("ocsp_url is set but enable_ocsp is not"))
	})

	// 0 turns the limit off, and the startup line must not read as "zero
	// requests allowed".
	It("says at startup when ocsp_rate_limit turns the limit off", func() {
		addr := startServe(config("enable_ocsp: true\nocsp_rate_limit: 0\n"))

		Expect(postOCSP(addr).StatusCode).To(Equal(http.StatusBadRequest))
		Expect(serverLog()).To(ContainSubstring("OCSP responder enabled at /ocsp without a rate limit"))
		// Scoped to the responder's own record: other startup lines may
		// carry keys with the same suffix.
		Expect(serverLog()).NotTo(ContainSubstring(`"msg":"OCSP responder enabled at /ocsp","rate_limit_per_minute"`))
	})

	Context("with a metrics listener", func() {
		var metricsAddr string

		BeforeEach(func() { metricsAddr = fmt.Sprintf("127.0.0.1:%d", freeLoopbackPort()) })

		// Takes a Gomega so that Eventually retries a refused connection:
		// the exporter binds in its own goroutine, unordered against READY=1.
		// A direct call passes Default.
		scrape := func(g Gomega) string {
			resp, err := plainClient().Get("http://" + metricsAddr + "/metrics")
			g.Expect(err).NotTo(HaveOccurred())
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			g.Expect(err).NotTo(HaveOccurred())
			return string(body)
		}

		// Through the flag, which pins its overlay; the file and the
		// environment are pinned in config_test.go.
		It("refuses a client over --ocsp-rate-limit with tryLater over 429, and counts it", func() {
			addr := startServe(config("enable_ocsp: true\nmetrics_listen: "+metricsAddr+"\n"), "--ocsp-rate-limit=1")

			Expect(postOCSP(addr).StatusCode).To(Equal(http.StatusBadRequest),
				"precondition: the first request is within the limit and reaches the responder")
			resp := postOCSP(addr)
			Expect(resp.StatusCode).To(Equal(http.StatusTooManyRequests))
			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(body).To(Equal(xocsp.TryLaterErrorResponse))

			Eventually(scrape).Should(ContainSubstring("\nopenvoxca_ocsp_rate_limited_total 1\n"))
			// The served responder keeps its index series, which pins the
			// exporter's options from the other side.
			Expect(scrape(Default)).To(ContainSubstring("openvoxca_ocsp_index_serials"))
		})

		It("exports no rate-limit counter while the responder is off", func() {
			startServe(config("metrics_listen: " + metricsAddr + "\n"))

			Eventually(scrape).Should(ContainSubstring("openvoxca_ca_ready"),
				"precondition: the exporter is serving")
			Expect(scrape(Default)).NotTo(ContainSubstring("openvoxca_ocsp_rate_limited_total"))
			// The exporter is built with metricsOptions(cfg), not bare: the
			// metricsOptions table pins the mapping, this its call site.
			Expect(scrape(Default)).NotTo(ContainSubstring("openvoxca_ocsp_index_serials"))
			Expect(scrape(Default)).NotTo(ContainSubstring("openvoxca_ocsp_index_sync_failures_total"))
		})
	})
})

var _ = DescribeTable("resolveOCSPRateLimit",
	func(configured, want int) {
		Expect(resolveOCSPRateLimit(configured)).To(Equal(want))
	},
	Entry("the unset sentinel takes the default", -1, defaultOCSPRateLimit),
	// Any negative value, not only the sentinel: the setting has no lower
	// bound, and passing -5 through would disable the limit in Routes.
	Entry("any other negative value takes the default", -5, defaultOCSPRateLimit),
	Entry("an explicit zero disables the limit", 0, 0),
	Entry("a positive value passes through", 5, 5),
)

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

// The file and environment routes are in config_test.go. The flag is applied
// after loadServerConfig has run its checks, so it needs its own, both ways.
var _ = Describe("--rate-limit-ipv6-prefix-length", func() {
	BeforeEach(func() {
		clearServerEnv()
		DeferCleanup(slog.SetDefault, slog.Default())
	})

	It("refuses a value outside 1-128 before anything starts", func() {
		caDir := GinkgoT().TempDir()
		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{
			"--config", writeTempConfig("cadir: " + caDir + "\n"),
			"--host", "127.0.0.1", "--port", "0",
			"--single-process",
			"--rate-limit-ipv6-prefix-length=0",
		})

		// Bounded: were the check to regress, the command would go on to
		// serve, and a hang would report nothing.
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()
		var err error
		Eventually(done, "30s").Should(Receive(&err))
		Expect(err).To(MatchError(ContainSubstring("rate_limit_ipv6_prefix_length must be between 1 and 128")))

		entries, err := os.ReadDir(caDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty(), "the refusal must come before the store is touched")
	})

	It("reaches the server when valid", func() {
		caDir := GinkgoT().TempDir()
		logPath := filepath.Join(GinkgoT().TempDir(), "server.log")
		bootstrapCAInDir(caDir, "ca.example.com")
		path := serveConfig(caDir, GinkgoT().TempDir(), "127.0.0.1", freeLoopbackPort(), false)
		appendConfig(path, fmt.Sprintf("logfile: %s\n", logPath))

		startServe(path, "--rate-limit-ipv6-prefix-length=64")

		data, err := os.ReadFile(logPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(data)).To(ContainSubstring(`"rate_limit_ipv6_prefix_length":64`))
	})
})
