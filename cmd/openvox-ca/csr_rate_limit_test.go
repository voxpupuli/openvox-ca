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
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The CSR rate limit must honour the same "0 disables, unset uses the default"
// contract across every input layer (flag, env, file). The field is sentinelled
// to -1 ("unset") so an explicit 0 is never silently rewritten to the default.
var _ = Describe("CSR rate-limit resolution", func() {
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
			prev, had := os.LookupEnv("PUPPET_CA_CSR_RATE_LIMIT")
			Expect(os.Setenv("PUPPET_CA_CSR_RATE_LIMIT", val)).To(Succeed())
			saved = func() {
				if had {
					_ = os.Setenv("PUPPET_CA_CSR_RATE_LIMIT", prev)
				} else {
					_ = os.Unsetenv("PUPPET_CA_CSR_RATE_LIMIT")
				}
			}
			DeferCleanup(func() { saved() })
		}

		It("applies an explicit 0 from the environment (disable)", func() {
			setEnvTemp("0")
			cfg := &serverConfig{CSRRateLimit: -1}
			applyServerEnv(cfg)
			Expect(cfg.CSRRateLimit).To(Equal(0))
			Expect(resolveCSRRateLimit(cfg.CSRRateLimit)).To(Equal(0))
		})
	})
})
