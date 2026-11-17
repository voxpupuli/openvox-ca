// Copyright (C) 2026 Trevor Vaughan
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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// The CSR rate limit must honour the same "0 disables, unset uses the default"
// contract across every input layer (flag, env, file). The field is sentinelled
// to -1 ("unset") so an explicit 0 is never silently rewritten to the default.
var _ = Describe("CSR rate-limit resolution", func() {
	// Each layer alone: an ambient OPENVOX_CA_* variable would overlay the
	// file, and a malformed one now refuses the load outright.
	BeforeEach(func() { clearServerEnv() })

	Describe("resolveCSRRateLimit", func() {
		It("uses the built-in default when unset (sentinel -1)", func() {
			Expect(resolveCSRRateLimit(-1)).To(Equal(defaultCSRRateLimit))
		})

		It("treats an explicit 0 as disabled, not as the default", func() {
			Expect(resolveCSRRateLimit(0)).To(Equal(0))
		})

		It("passes an explicit positive value through unchanged", func() {
			Expect(resolveCSRRateLimit(30)).To(Equal(30))
		})
	})

	Describe("config-file layer", func() {
		writeConfig := func(body string) string {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "openvox-ca.yaml")
			Expect(os.WriteFile(path, []byte(body), 0o600)).To(Succeed())
			return path
		}

		It("leaves the field at the unset sentinel when the key is absent", func() {
			cfg, err := loadServerConfig(writeConfig("host: 127.0.0.1\n"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.CSRRateLimit).To(Equal(-1),
				"an absent csr_rate_limit must remain unset, not become 0")
		})

		It("preserves an explicit 0 from the file (disable)", func() {
			cfg, err := loadServerConfig(writeConfig("csr_rate_limit: 0\n"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.CSRRateLimit).To(Equal(0))
			Expect(resolveCSRRateLimit(cfg.CSRRateLimit)).To(Equal(0),
				"csr_rate_limit: 0 in the file must disable the limiter, not fall back to 60")
		})

		It("preserves an explicit positive value from the file", func() {
			cfg, err := loadServerConfig(writeConfig("csr_rate_limit: 25\n"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.CSRRateLimit).To(Equal(25))
		})
	})

	Describe("environment layer", func() {
		var saved func()

		setEnvTemp := func(val string) {
			prev, had := os.LookupEnv("OPENVOX_CA_CSR_RATE_LIMIT")
			Expect(os.Setenv("OPENVOX_CA_CSR_RATE_LIMIT", val)).To(Succeed())
			saved = func() {
				if had {
					_ = os.Setenv("OPENVOX_CA_CSR_RATE_LIMIT", prev)
				} else {
					_ = os.Unsetenv("OPENVOX_CA_CSR_RATE_LIMIT")
				}
			}
			DeferCleanup(func() { saved() })
		}

		It("applies an explicit 0 from the environment (disable)", func() {
			setEnvTemp("0")
			cfg := &serverConfig{CSRRateLimit: -1}
			Expect(applyServerEnv(cfg)).To(Succeed())
			Expect(cfg.CSRRateLimit).To(Equal(0))
			Expect(resolveCSRRateLimit(cfg.CSRRateLimit)).To(Equal(0))
		})
	})
})

// The serve command wires the CSR limiter's refusals to
// openvoxca_csr_rate_limited_total on the metrics exporter. Driven through the
// command, since the wiring sits inline in the server start-up.
var _ = Describe("the serve command's CSR rate-limited counter", func() {
	var configPath, metricsAddr string

	BeforeEach(func() {
		// Ambient OPENVOX_CA_* would outrank the fixture config.
		clearServerEnv()
		caDir := GinkgoT().TempDir()
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

	put := func(addr string) int {
		GinkgoHelper()
		csrPEM, err := testutil.GenerateCSR("limited-node")
		Expect(err).NotTo(HaveOccurred())
		req, err := http.NewRequest(http.MethodPut,
			"http://"+addr+"/puppet-ca/v1/certificate_request/limited-node", bytes.NewReader(csrPEM))
		Expect(err).NotTo(HaveOccurred())
		resp, err := plainClient().Do(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Body.Close()).To(Succeed())
		return resp.StatusCode
	}

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

	It("counts a submission refused over --csr-rate-limit, and not the one allowed", func() {
		addr := startServe(configPath, "--csr-rate-limit=1")

		Expect(put(addr)).NotTo(Equal(http.StatusTooManyRequests),
			"precondition: the first submission is within the limit")
		Expect(put(addr)).To(Equal(http.StatusTooManyRequests))

		Eventually(scrape).Should(ContainSubstring("\nopenvoxca_csr_rate_limited_total 1\n"))
	})

	// Exported at 0 rather than absent, so the series is there for a query
	// before the first refusal, and the spec fails if nothing is wired.
	It("exports the counter at 0 when csr_rate_limit is 0, whatever is submitted", func() {
		appendConfig(configPath, "csr_rate_limit: 0\n")
		addr := startServe(configPath)

		for range 3 {
			Expect(put(addr)).NotTo(Equal(http.StatusTooManyRequests))
		}

		Eventually(scrape).Should(ContainSubstring("\nopenvoxca_csr_rate_limited_total 0\n"))
	})
})
