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

package config_test

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// absViaRoot mirrors the production absIfSet resolution (filepath.Abs against
// the test process CWD) so override-path assertions track the real behaviour
// rather than a hardcoded expectation.
func absViaRoot(rel string) string {
	abs, err := filepath.Abs(rel)
	Expect(err).NotTo(HaveOccurred())
	return abs
}

var _ = Describe("ResolveConfigFile", func() {
	const envVar = "PUPPET_CA_TEST_CONFIG"

	// Each spec saves and restores the env var so it never leaks into a
	// sibling; t.Setenv is unavailable inside Ginkgo nodes.
	BeforeEach(func() {
		prev, had := os.LookupEnv(envVar)
		DeferCleanup(func() {
			if had {
				Expect(os.Setenv(envVar, prev)).To(Succeed())
			} else {
				Expect(os.Unsetenv(envVar)).To(Succeed())
			}
		})
		Expect(os.Unsetenv(envVar)).To(Succeed())
	})

	It("returns the CLI flag when it is set, ignoring env and default", func() {
		Expect(os.Setenv(envVar, "/from/env.yaml")).To(Succeed())
		got := config.ResolveConfigFile("/from/flag.yaml", envVar, "/from/default.yaml")
		Expect(got).To(Equal("/from/flag.yaml"))
	})

	It("returns the env var when the flag is empty", func() {
		Expect(os.Setenv(envVar, "/from/env.yaml")).To(Succeed())
		got := config.ResolveConfigFile("", envVar, "/from/default.yaml")
		Expect(got).To(Equal("/from/env.yaml"))
	})

	It("prefers the flag over the env var", func() {
		Expect(os.Setenv(envVar, "/from/env.yaml")).To(Succeed())
		got := config.ResolveConfigFile("/from/flag.yaml", envVar, "")
		Expect(got).To(Equal("/from/flag.yaml"))
	})

	It("falls back to the default path when it exists on disk", func() {
		dir := GinkgoT().TempDir()
		defaultPath := filepath.Join(dir, "openvox-ca.yaml")
		Expect(os.WriteFile(defaultPath, []byte("---\n"), 0o600)).To(Succeed())

		got := config.ResolveConfigFile("", envVar, defaultPath)
		Expect(got).To(Equal(defaultPath))
	})

	It("returns empty string when the default path does not exist", func() {
		dir := GinkgoT().TempDir()
		missing := filepath.Join(dir, "does-not-exist.yaml")

		got := config.ResolveConfigFile("", envVar, missing)
		Expect(got).To(BeEmpty())
	})

	It("returns empty string when flag, env, and default are all unusable", func() {
		got := config.ResolveConfigFile("", envVar, "")
		Expect(got).To(BeEmpty())
	})

	It("prefers the env var over an existing default file", func() {
		dir := GinkgoT().TempDir()
		defaultPath := filepath.Join(dir, "openvox-ca.yaml")
		Expect(os.WriteFile(defaultPath, []byte("---\n"), 0o600)).To(Succeed())
		Expect(os.Setenv(envVar, "/from/env.yaml")).To(Succeed())

		got := config.ResolveConfigFile("", envVar, defaultPath)
		Expect(got).To(Equal("/from/env.yaml"))
	})
})
