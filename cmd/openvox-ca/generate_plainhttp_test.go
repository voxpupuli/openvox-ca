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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// POST /generate returns a private key in its response body, and without TLS
// the auth middleware is not installed either, so the key goes to any caller.
// The handler refuses whenever the server has no TLS, unless the operator sets
// insecure_allow_plain_http_generate.
//
// The refusal used to be computed from the bind address and no_tls_required as
// well, which left it exactly one case: plain HTTP off loopback without
// no_tls_required. The server refuses to start in that case, so the refusal
// never fired. The decision is pinned as a table below, over the axes that
// once entered it, and its wiring by driving the serve command.
var _ = DescribeTable("generateRefusesPlainHTTP",
	func(tlsConfigured, optIn bool, host string, noTLSRequired, want bool) {
		cfg := &serverConfig{
			Host:                           host,
			NoTLSRequired:                  noTLSRequired,
			InsecureAllowPlainHTTPGenerate: optIn,
		}
		Expect(generateRefusesPlainHTTP(cfg, tlsConfigured)).To(Equal(want))
	},
	// The case the issue named: before, no_tls_required let the key out.
	Entry("refuses without TLS off loopback under no_tls_required",
		false, false, "0.0.0.0", true, true),
	Entry("refuses without TLS on loopback", false, false, "127.0.0.1", false, true),
	Entry("allows without TLS when opted in, off loopback", false, true, "0.0.0.0", true, false),
	Entry("allows without TLS when opted in, on loopback", false, true, "127.0.0.1", false, false),
	Entry("allows with TLS", true, false, "0.0.0.0", false, false),
	Entry("allows with TLS when also opted in", true, true, "0.0.0.0", false, false),
)

var _ = Describe("plainHTTPGenerateNotice", func() {
	optedIn := &serverConfig{InsecureAllowPlainHTTPGenerate: true}

	It("says nothing when the setting is off", func() {
		Expect(plainHTTPGenerateNotice(&serverConfig{}, false)).To(BeEmpty())
		Expect(plainHTTPGenerateNotice(&serverConfig{}, true)).To(BeEmpty())
	})

	It("warns that keys go to any caller when it is live", func() {
		Expect(plainHTTPGenerateNotice(optedIn, false)).To(SatisfyAll(
			HavePrefix("INSECURE: insecure_allow_plain_http_generate"),
			ContainSubstring("any caller"),
		))
	})

	It("warns that it has no effect when TLS is configured", func() {
		Expect(plainHTTPGenerateNotice(optedIn, true)).To(SatisfyAll(
			HavePrefix("insecure_allow_plain_http_generate is set but has no effect"),
			ContainSubstring("remove it"),
		))
	})
})

var _ = Describe("the serve command's POST /generate", func() {
	var caDir, servingDir, logPath string

	BeforeEach(func() {
		// Ambient OPENVOX_CA_* would outrank the fixture config.
		clearServerEnv()
		caDir = GinkgoT().TempDir()
		servingDir = GinkgoT().TempDir()
		logPath = filepath.Join(GinkgoT().TempDir(), "server.log")
		bootstrapCAInDir(caDir, "ca.example.com")
		// The command points the default logger at logfile and leaves it
		// there. Registered before the server starts, so the server is
		// stopped before the logger is restored.
		DeferCleanup(slog.SetDefault, slog.Default())
	})

	// config is serveConfig on a free loopback port, logging to logPath, so a
	// spec can read what the command logged without capturing stderr.
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

	Context("without TLS", func() {
		// Loopback, because it is the only plain-HTTP address the server starts
		// on without no_tls_required, and neither enters the decision any more:
		// the table above holds the off-loopback case.
		It("refuses to return a private key", func() {
			addr := startServe(config(false))

			status, body := postGenerate(plainClient(), "http://"+addr, "node.example.com")
			Expect(status).To(Equal(http.StatusForbidden),
				"a server with no TLS handed out a private key; body: %s", body)
			Expect(body).To(ContainSubstring("private key delivery requires TLS"))
			Expect(body).NotTo(ContainSubstring("PRIVATE KEY"))

			Expect(serverLog()).To(ContainSubstring(
				"Generate refused: TLS is not configured; configure TLS, or set insecure_allow_plain_http_generate"),
				"the remedy belongs in the log, where the operator reads it")
		})

		// The case the issue named. no_tls_required used to exempt /generate
		// from the refusal; it lifts only the refusal to start, and the bind
		// is loopback here only because a spec should not listen on a real
		// interface.
		It("refuses under no_tls_required too", func() {
			path := config(false)
			appendConfig(path, "no_tls_required: true\n")
			addr := startServe(path)

			status, body := postGenerate(plainClient(), "http://"+addr, "node.example.com")
			Expect(status).To(Equal(http.StatusForbidden),
				"no_tls_required let a private key out over plain HTTP; body: %s", body)
			Expect(body).To(ContainSubstring("private key delivery requires TLS"))
			Expect(body).NotTo(ContainSubstring("PRIVATE KEY"))
		})

		// Through the flag rather than the file, which pins the flag's overlay
		// as well; the file and the environment are pinned in config_test.go.
		It("returns one when --insecure-allow-plain-http-generate is set, and warns at startup", func() {
			addr := startServe(config(false), "--insecure-allow-plain-http-generate")

			Expect(serverLog()).To(ContainSubstring(
				"INSECURE: insecure_allow_plain_http_generate is set and TLS is not configured"))

			status, body := postGenerate(plainClient(), "http://"+addr, "node.example.com")
			Expect(status).To(Equal(http.StatusOK), "body: %s", body)
			Expect(body).To(ContainSubstring("PRIVATE KEY"))
		})
	})

	Context("with TLS", func() {
		It("returns a private key to an admin without the setting", func() {
			// Minted before the server starts, which then holds the store.
			admin := mintClientCert(caDir, "admin.example.com")
			addr := startServe(config(true))

			status, body := postGenerate(tlsClient(caRoots(caDir), admin), "https://"+addr, "node.example.com")
			Expect(status).To(Equal(http.StatusOK), "body: %s", body)
			Expect(body).To(ContainSubstring("PRIVATE KEY"))
			Expect(serverLog()).NotTo(ContainSubstring("insecure_allow_plain_http_generate"))
		})

		It("warns at startup that the setting has no effect", func() {
			path := config(true)
			appendConfig(path, "insecure_allow_plain_http_generate: true\n")
			startServe(path)

			Expect(serverLog()).To(ContainSubstring(
				"insecure_allow_plain_http_generate is set but has no effect while TLS is configured"))
		})
	})
})

func plainClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// tlsClient verifies the server as "localhost", the name serveConfig's
// serving_cert is issued for, and presents client.
func tlsClient(roots *x509.CertPool, client tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			ServerName:   "localhost",
			Certificates: []tls.Certificate{client},
			MinVersion:   tls.VersionTLS12,
		}},
	}
}

// postGenerate asks the server at base to generate a key and certificate for
// subject, and returns the status and body.
func postGenerate(hc *http.Client, base, subject string) (int, string) {
	GinkgoHelper()
	defer hc.CloseIdleConnections()
	resp, err := hc.Post(base+"/puppet-ca/v1/generate/"+subject, "", nil)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	return resp.StatusCode, string(body)
}
