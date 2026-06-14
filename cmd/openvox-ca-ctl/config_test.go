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

// ctlEnvVars is the full list of env vars read by applyCtlEnv.
var ctlEnvVars = []string{
	"PUPPET_CA_CTL_SERVER_URL",
	"PUPPET_CA_CTL_CA_CERT",
	"PUPPET_CA_CTL_CLIENT_CERT",
	"PUPPET_CA_CTL_CLIENT_KEY",
	"PUPPET_CA_CTL_VERBOSE",
	"PUPPET_CA_CTL_INSECURE",
}

// setCtlEnv saves the current value of key, sets it to val, and registers a
// DeferCleanup that restores the original value (or unsets it if it was unset).
func setCtlEnv(key, val string) {
	orig, had := os.LookupEnv(key)
	Expect(os.Setenv(key, val)).To(Succeed())
	DeferCleanup(func() {
		if had {
			Expect(os.Setenv(key, orig)).To(Succeed())
		} else {
			Expect(os.Unsetenv(key)).To(Succeed())
		}
	})
}

// clearCtlEnv unsets all PUPPET_CA_CTL_* vars and restores them after the spec.
func clearCtlEnv() {
	for _, key := range ctlEnvVars {
		// Empty string is treated as unset by applyCtlEnv; restored via DeferCleanup.
		setCtlEnv(key, "")
	}
}

// writeTempCtlConfig writes content to a ctl.yaml in a fresh temp dir and
// returns its path.
func writeTempCtlConfig(content string) string {
	dir := GinkgoT().TempDir()
	path := filepath.Join(dir, "ctl.yaml")
	Expect(os.WriteFile(path, []byte(content), 0644)).To(Succeed())
	return path
}

// --- resolveConfigFile ---

var _ = Describe("resolveConfigFile", func() {
	const envKey = "PUPPET_CA_CTL_CONFIG_TEST_RESOLVE"

	var (
		dir      string
		existing string
		missing  string
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		existing = filepath.Join(dir, "exists.yaml")
		Expect(os.WriteFile(existing, []byte(""), 0644)).To(Succeed())
		missing = filepath.Join(dir, "missing.yaml")
	})

	DescribeTable("resolution precedence",
		func(cliFlag, envVal string, defaultPathFn func() string, wantFn func() string) {
			setCtlEnv(envKey, envVal)
			defaultPath := defaultPathFn()
			want := wantFn()
			got := resolveConfigFile(cliFlag, envKey, defaultPath)
			Expect(got).To(Equal(want),
				"resolveConfigFile(%q, %q, %q) = %q; want %q",
				cliFlag, envKey, defaultPath, got, want)
		},
		Entry("cli flag wins over env and default",
			"/cli/path.yaml", "/env/path.yaml",
			func() string { return existing },
			func() string { return "/cli/path.yaml" }),
		Entry("env var used when no cli flag",
			"", "/env/path.yaml",
			func() string { return existing },
			func() string { return "/env/path.yaml" }),
		Entry("default path used when it exists",
			"", "",
			func() string { return existing },
			func() string { return existing }),
		Entry("empty when default does not exist",
			"", "",
			func() string { return missing },
			func() string { return "" }),
		Entry("empty when nothing provided",
			"", "",
			func() string { return "" },
			func() string { return "" }),
	)
})

// --- loadCtlConfig: built-in defaults ---

var _ = Describe("loadCtlConfig", func() {
	Context("with built-in defaults", func() {
		BeforeEach(func() {
			clearCtlEnv()
		})

		It("applies the built-in defaults", func() {
			cfg, err := loadCtlConfig("")
			Expect(err).NotTo(HaveOccurred(), "unexpected error")
			Expect(cfg.ServerURL).To(Equal("https://localhost:8140"),
				"ServerURL = %q; want https://localhost:8140", cfg.ServerURL)
			Expect(cfg.CACert).To(Equal(""), "CACert = %q; want empty", cfg.CACert)
			Expect(cfg.ClientCert).To(Equal(""), "ClientCert = %q; want empty", cfg.ClientCert)
			Expect(cfg.ClientKey).To(Equal(""), "ClientKey = %q; want empty", cfg.ClientKey)
			Expect(cfg.Verbose).To(BeFalse(), "Verbose = true; want false")
			Expect(cfg.Insecure).To(BeFalse(), "Insecure = true; want false")
		})
	})

	// --- loadCtlConfig: YAML file ---

	Context("with a YAML file", func() {
		BeforeEach(func() {
			clearCtlEnv()
		})

		It("loads values from the file", func() {
			content := `
server_url: https://openvox-ca:8140
ca_cert: /etc/ssl/ca.pem
client_cert: /etc/ssl/client.pem
client_key: /etc/ssl/client_key.pem
verbose: true
`
			cfgFile := writeTempCtlConfig(content)

			cfg, err := loadCtlConfig(cfgFile)
			Expect(err).NotTo(HaveOccurred(), "unexpected error")
			Expect(cfg.ServerURL).To(Equal("https://openvox-ca:8140"),
				"ServerURL = %v; want https://openvox-ca:8140", cfg.ServerURL)
			Expect(cfg.CACert).To(Equal("/etc/ssl/ca.pem"),
				"CACert = %v; want /etc/ssl/ca.pem", cfg.CACert)
			Expect(cfg.ClientCert).To(Equal("/etc/ssl/client.pem"),
				"ClientCert = %v; want /etc/ssl/client.pem", cfg.ClientCert)
			Expect(cfg.ClientKey).To(Equal("/etc/ssl/client_key.pem"),
				"ClientKey = %v; want /etc/ssl/client_key.pem", cfg.ClientKey)
			Expect(cfg.Verbose).To(BeTrue(), "Verbose = %v; want true", cfg.Verbose)
		})

		// unset YAML keys keep built-in defaults.
		It("keeps built-in defaults for unset keys", func() {
			cfgFile := writeTempCtlConfig("server_url: https://myserver:9000\n")
			cfg, err := loadCtlConfig(cfgFile)
			Expect(err).NotTo(HaveOccurred(), "unexpected error")
			Expect(cfg.ServerURL).To(Equal("https://myserver:9000"),
				"ServerURL = %q; want https://myserver:9000", cfg.ServerURL)
			Expect(cfg.Verbose).To(BeFalse(), "Verbose = true; want default false")
		})

		// insecure: true is loaded from YAML.
		It("loads insecure: true from YAML", func() {
			cfgFile := writeTempCtlConfig("insecure: true\n")
			cfg, err := loadCtlConfig(cfgFile)
			Expect(err).NotTo(HaveOccurred(), "unexpected error")
			Expect(cfg.Insecure).To(BeTrue(), "Insecure = false; want true from YAML")
			// Ensure default server_url is preserved when only insecure is set.
			Expect(cfg.ServerURL).To(Equal("https://localhost:8140"),
				"ServerURL = %q; want default https://localhost:8140", cfg.ServerURL)
		})
	})

	// --- loadCtlConfig: env vars override YAML ---

	Context("when env vars override YAML", func() {
		BeforeEach(func() {
			clearCtlEnv()
		})

		It("prefers the env value over the file value", func() {
			cfgFile := writeTempCtlConfig("server_url: https://from-file:8140\n")
			setCtlEnv("PUPPET_CA_CTL_SERVER_URL", "https://from-env:9999")

			cfg, err := loadCtlConfig(cfgFile)
			Expect(err).NotTo(HaveOccurred(), "unexpected error")
			Expect(cfg.ServerURL).To(Equal("https://from-env:9999"),
				"ServerURL = %q; want env value https://from-env:9999", cfg.ServerURL)
		})
	})

	// --- loadCtlConfig: error cases ---

	Context("error cases", func() {
		It("returns an error for a missing config file", func() {
			_, err := loadCtlConfig("/nonexistent/path/ctl.yaml")
			Expect(err).To(HaveOccurred(), "expected error for missing config file, got nil")
		})

		It("returns an error for invalid YAML", func() {
			cfgFile := writeTempCtlConfig("server_url: [unclosed\n")
			_, err := loadCtlConfig(cfgFile)
			Expect(err).To(HaveOccurred(), "expected error for invalid YAML, got nil")
		})
	})
})

// --- applyCtlEnv: each variable ---

var _ = Describe("applyCtlEnv", func() {
	DescribeTable("applies each variable",
		func(envKey, envVal string, check func(*ctlConfig) bool, desc string) {
			clearCtlEnv()
			setCtlEnv(envKey, envVal)
			cfg := &ctlConfig{}
			applyCtlEnv(cfg)
			Expect(check(cfg)).To(BeTrue(),
				"%s not applied from %s=%s", desc, envKey, envVal)
		},
		Entry("SERVER_URL", "PUPPET_CA_CTL_SERVER_URL", "https://myhost:8140",
			func(c *ctlConfig) bool { return c.ServerURL == "https://myhost:8140" },
			"ServerURL"),
		Entry("CA_CERT", "PUPPET_CA_CTL_CA_CERT", "/etc/ssl/ca.pem",
			func(c *ctlConfig) bool { return c.CACert == "/etc/ssl/ca.pem" },
			"CACert"),
		Entry("CLIENT_CERT", "PUPPET_CA_CTL_CLIENT_CERT", "/etc/ssl/cert.pem",
			func(c *ctlConfig) bool { return c.ClientCert == "/etc/ssl/cert.pem" },
			"ClientCert"),
		Entry("CLIENT_KEY", "PUPPET_CA_CTL_CLIENT_KEY", "/etc/ssl/key.pem",
			func(c *ctlConfig) bool { return c.ClientKey == "/etc/ssl/key.pem" },
			"ClientKey"),
		Entry("VERBOSE_true", "PUPPET_CA_CTL_VERBOSE", "true",
			func(c *ctlConfig) bool { return c.Verbose },
			"Verbose=true"),
		Entry("VERBOSE_1", "PUPPET_CA_CTL_VERBOSE", "1",
			func(c *ctlConfig) bool { return c.Verbose },
			"Verbose=1"),
		Entry("INSECURE_true", "PUPPET_CA_CTL_INSECURE", "true",
			func(c *ctlConfig) bool { return c.Insecure },
			"Insecure=true"),
		Entry("INSECURE_1", "PUPPET_CA_CTL_INSECURE", "1",
			func(c *ctlConfig) bool { return c.Insecure },
			"Insecure=1"),
	)

	// a malformed VERBOSE value is silently ignored.
	It("silently ignores a malformed VERBOSE value", func() {
		clearCtlEnv()
		setCtlEnv("PUPPET_CA_CTL_VERBOSE", "maybe")

		cfg := &ctlConfig{}
		applyCtlEnv(cfg)

		Expect(cfg.Verbose).To(BeFalse(), "Verbose changed on bad input: want false")
	})

	// PUPPET_CA_CTL_INSECURE=false does not set Insecure.
	It("does not set Insecure when env is 'false'", func() {
		clearCtlEnv()
		setCtlEnv("PUPPET_CA_CTL_INSECURE", "false")

		cfg := &ctlConfig{}
		applyCtlEnv(cfg)

		Expect(cfg.Insecure).To(BeFalse(), "Insecure = true; want false when env is 'false'")
	})

	// a malformed INSECURE value is silently ignored.
	It("silently ignores a malformed INSECURE value", func() {
		clearCtlEnv()
		setCtlEnv("PUPPET_CA_CTL_INSECURE", "maybe")

		cfg := &ctlConfig{}
		applyCtlEnv(cfg)

		Expect(cfg.Insecure).To(BeFalse(), "Insecure changed on bad input: want false")
	})
})
