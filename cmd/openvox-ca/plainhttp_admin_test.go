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
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Without TLS the authorisation middleware is not installed, so anything that
// can reach the listener can sign, revoke and clean. The server says so at
// every start, whatever the bind address.
const plainHTTPAdminWarning = "TLS is not configured, so the admin API is unauthenticated"

var _ = DescribeTable("plainHTTPAdminNotice",
	func(tlsConfigured bool, cfg *serverConfig, wantWarning, wantPuppetServer bool) {
		msg := plainHTTPAdminNotice(cfg, tlsConfigured)
		if !wantWarning {
			Expect(msg).To(BeEmpty())
			return
		}
		Expect(msg).To(SatisfyAll(
			HavePrefix(plainHTTPAdminWarning),
			ContainSubstring("can sign, revoke and clean certificates"),
			ContainSubstring("Configure tls_cert/tls_key or serving_cert"),
		))
		if wantPuppetServer {
			Expect(msg).To(HaveSuffix("--puppet-server / --puppet-server-file have no effect without TLS."))
		} else {
			Expect(msg).NotTo(ContainSubstring("--puppet-server"))
		}
	},
	Entry("warns without TLS", false, &serverConfig{}, true, false),
	Entry("warns without TLS off loopback under no_tls_required",
		false, &serverConfig{Host: "0.0.0.0", NoTLSRequired: true}, true, false),
	Entry("names --puppet-server without TLS when it is set",
		false, &serverConfig{PuppetServer: "admin.example.com"}, true, true),
	Entry("names --puppet-server without TLS when --puppet-server-file is set",
		false, &serverConfig{PuppetServerFile: "/etc/openvox-ca/admins"}, true, true),
	Entry("says nothing with TLS", true, &serverConfig{}, false, false),
	Entry("says nothing with TLS when --puppet-server is set",
		true, &serverConfig{PuppetServer: "admin.example.com"}, false, false),
)

var _ = Describe("the serve command's unauthenticated admin API warning", func() {
	var caDir, servingDir, logPath string

	BeforeEach(func() {
		// Ambient OPENVOX_CA_* would outrank the fixture config.
		clearServerEnv()
		caDir = GinkgoT().TempDir()
		servingDir = GinkgoT().TempDir()
		// Only the serve command writes here, so the fixture above cannot
		// put the line there for it.
		logPath = filepath.Join(GinkgoT().TempDir(), "server.log")
		bootstrapCAInDir(caDir, "ca.example.com")
		// The command points the default logger at logfile and leaves it
		// there. Registered before the server starts, so the server is
		// stopped before the logger is restored.
		DeferCleanup(slog.SetDefault, slog.Default())
	})

	// serveConfig names puppet_server, so the warning carries its clause.
	config := func(withServing bool) string {
		GinkgoHelper()
		path := serveConfig(caDir, servingDir, "127.0.0.1", freeLoopbackPort(), withServing)
		appendConfig(path, fmt.Sprintf("logfile: %s\n", logPath))
		return path
	}

	serverLog := func() string {
		GinkgoHelper()
		data, err := os.ReadFile(logPath)
		Expect(err).NotTo(HaveOccurred())
		return string(data)
	}

	It("warns once at startup without TLS, on loopback", func() {
		startServe(config(false))

		log := serverLog()
		Expect(strings.Count(log, plainHTTPAdminWarning)).To(Equal(1), "log:\n%s", log)
		// The logfile is JSON, and at the default verbosity an Info record
		// reaches it too, so the text alone does not pin the level.
		Expect(log).To(ContainSubstring(`"level":"WARN","msg":"`+plainHTTPAdminWarning),
			"the warning is logged at WARN")
		Expect(log).To(ContainSubstring("have no effect without TLS"))
		Expect(log).NotTo(ContainSubstring("all endpoints are accessible without authentication"),
			"the --puppet-server warning is folded into this one, not repeated beside it")
	})

	It("does not warn with TLS", func() {
		startServe(config(true))

		log := serverLog()
		Expect(log).To(ContainSubstring("Starting Puppet CA"),
			"precondition: the log holds the startup this spec judges")
		Expect(log).NotTo(ContainSubstring(plainHTTPAdminWarning))
	})
})
