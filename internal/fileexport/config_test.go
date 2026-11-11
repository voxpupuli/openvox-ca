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

package fileexport_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/fileexport"
	"github.com/voxpupuli/openvox-ca/internal/fileexport/fileexportconfig"
)

var _ = Describe("Config", func() {
	Describe("Enabled", func() {
		It("is false for an empty or nil config", func() {
			Expect((&fileexport.Config{}).Enabled()).To(BeFalse())
			var nilCfg *fileexport.Config
			Expect(nilCfg.Enabled()).To(BeFalse())
		})

		It("is true once a target is configured", func() {
			cfg := &fileexport.Config{Targets: []fileexport.Target{{Path: "/x", Material: "crl"}}}
			Expect(cfg.Enabled()).To(BeTrue())
		})
	})

	Describe("Interval", func() {
		It("defaults to the CRL sync interval's default when unset", func() {
			Expect((&fileexport.Config{}).Interval()).To(Equal(fileexportconfig.DefaultInterval))
			Expect(fileexportconfig.DefaultInterval).To(Equal(60 * time.Second))
		})

		It("uses interval_sec when set", func() {
			Expect((&fileexport.Config{IntervalSec: 30}).Interval()).To(Equal(30 * time.Second))
		})
	})

	// fileExportStaleAfterSeconds in the mixin assumes the CA never syncs less
	// often than every MaxIntervalSec: at twice the ceiling, two attempts must
	// fail before a target looks stale. Both sides state that coupling and
	// neither can see the other, so raising the ceiling alone would page on
	// every slow sync. This reads the mixin's default and fails if they part.
	It("keeps the interval ceiling at most half the mixin's stale threshold", func() {
		cfg, err := os.ReadFile(filepath.Join("..", "..", "mixin", "config.libsonnet"))
		Expect(err).NotTo(HaveOccurred())
		m := regexp.MustCompile(`(?m)^\s*fileExportStaleAfterSeconds:\s*(\d+),`).FindSubmatch(cfg)
		Expect(m).NotTo(BeNil(), "fileExportStaleAfterSeconds not found in mixin/config.libsonnet")
		staleAfter, err := strconv.Atoi(string(m[1]))
		Expect(err).NotTo(HaveOccurred())
		Expect(staleAfter).To(BeNumerically(">=", 2*fileexportconfig.MaxIntervalSec),
			"the stale threshold must span at least two syncs at the longest interval accepted")
	})

	Describe("Validate", func() {
		valid := func() fileexport.Config {
			return fileexport.Config{Targets: []fileexport.Target{
				{Path: "/etc/puppetlabs/puppet/ssl/crl.pem", Material: "crl"},
				{Path: "/etc/puppetlabs/puppet/ssl/certs/ca.pem", Material: "cert"},
			}}
		}

		It("accepts a valid config and defaults every scope to chain", func() {
			cfg := valid()
			Expect(cfg.Validate()).To(Succeed())
			for _, t := range cfg.Targets {
				Expect(t.Scope).To(Equal(fileexport.ScopeChain))
			}
		})

		It("cleans each path, so equivalent spellings compare equal", func() {
			cfg := fileexport.Config{Targets: []fileexport.Target{
				{Path: "/etc/ssl/./certs//ca.pem", Material: "cert"},
			}}
			Expect(cfg.Validate()).To(Succeed())
			Expect(cfg.Targets[0].Path).To(Equal("/etc/ssl/certs/ca.pem"))
		})

		It("accepts the interval ceiling itself", func() {
			cfg := valid()
			cfg.IntervalSec = fileexportconfig.MaxIntervalSec
			Expect(cfg.Validate()).To(Succeed())
		})

		DescribeTable("refuses",
			func(mutate func(*fileexport.Config), want string) {
				cfg := valid()
				mutate(&cfg)
				Expect(cfg.Validate()).To(MatchError(ContainSubstring(want)))
			},
			Entry("a negative interval",
				func(c *fileexport.Config) { c.IntervalSec = -1 }, "must not be negative"),
			Entry("an interval past the ceiling the stale alert assumes",
				func(c *fileexport.Config) { c.IntervalSec = fileexportconfig.MaxIntervalSec + 1 },
				"must not exceed 300 seconds"),
			Entry("a target with no path",
				func(c *fileexport.Config) { c.Targets[0].Path = "  " }, "path is required"),
			Entry("a relative path",
				func(c *fileexport.Config) { c.Targets[0].Path = "ssl/crl.pem" }, "must be absolute"),
			Entry("the root directory",
				func(c *fileexport.Config) { c.Targets[0].Path = "/" }, "names a directory"),
			Entry("a target with no material",
				func(c *fileexport.Config) { c.Targets[0].Material = "" }, "material is required"),
			Entry("an unknown material",
				func(c *fileexport.Config) { c.Targets[0].Material = "key" }, `invalid material "key"`),
			Entry("a material that differs only in case",
				func(c *fileexport.Config) { c.Targets[0].Material = "CRL" }, `invalid material "CRL"`),
			Entry("an unknown scope",
				func(c *fileexport.Config) { c.Targets[1].Scope = "leaf" }, `invalid scope "leaf"`),
			Entry("root as a CRL scope",
				func(c *fileexport.Config) { c.Targets[0].Scope = "root" }, "for a crl target"),
			Entry("two targets naming one file",
				func(c *fileexport.Config) { c.Targets[1].Path = "/etc/puppetlabs/puppet/ssl/crl.pem" },
				"targets 0 and 1 both write"),
			Entry("two spellings of one file",
				func(c *fileexport.Config) {
					c.Targets[1].Path = "/etc/puppetlabs/puppet/ssl/../ssl/crl.pem"
				}, "targets 0 and 1 both write"),
		)

		It("accepts root as a certificate scope", func() {
			cfg := valid()
			cfg.Targets[1].Scope = "root"
			Expect(cfg.Validate()).To(Succeed())
		})

		It("names the target that failed", func() {
			cfg := valid()
			cfg.Targets[1].Material = ""
			Expect(cfg.Validate()).To(MatchError(HavePrefix("file_export target 1:")))
		})
	})
})
