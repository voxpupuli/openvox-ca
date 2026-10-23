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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The serve command, started for real with a serving_cert and no
// tls_cert/tls_key, and judged by what a client sees.
//
// servingcert_wiring_test.go pins the shape of main.go: that it calls the
// serving-certificate functions, in order, and routes every TLS decision
// through one predicate. That catches a gate open-coded back to tls_cert and
// tls_key, but not every spelling of one, and it says nothing about what the
// gates *do*. These specs close that: they drive the command an operator runs
// and assert the two outcomes that matter if a gate regresses.
//
//   - The admin route refuses a client with no certificate. newAuthMiddleware
//     returns the bare mux for a nil AuthConfig, so a self-provisioned CA whose
//     auth gate stopped firing would answer that client with 200 -- serving
//     HTTPS with no client authentication at all.
//   - A non-loopback address is not refused for want of TLS. Were the
//     plain-HTTP gate to stop seeing serving_cert, every self-provisioning
//     deployment on a real interface would refuse to start.
//
// Each has a twin that must fail the opposite way, so neither can pass because
// its fixture never reached the code: an admin certificate is served the same
// route, and the same address without serving_cert is refused.
var _ = Describe("the serve command with a self-provisioned serving certificate", func() {
	var caDir, servingDir string

	BeforeEach(func() {
		// Ambient PUPPET_CA_* would outrank the fixture config, so a host with
		// PUPPET_CA_TLS_CERT exported would test a different command.
		clearServerEnv()
		caDir = GinkgoT().TempDir()
		// Outside cadir, which the CA reserves against every file store.
		servingDir = GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "ca.example.com")
	})

	It("refuses an admin route to a client that presents no certificate", func() {
		// Minted before the server starts: once it is running it holds the
		// store's instance lock, and nothing else may open the store.
		admin := mintClientCert(caDir, "admin.example.com")
		addr := startServe(serveConfig(caDir, servingDir, "127.0.0.1", freeLoopbackPort(), true))
		roots := caRoots(caDir)

		// The twin first. A 200 for an admin proves the route exists, the
		// listener presents a certificate this CA issued for the name the
		// client asked for, and the allow list is live -- so the refusal below
		// is about the missing certificate and nothing else.
		status, body := getOverTLS(addr, roots, &admin, "/puppet-ca/v1/certificate_statuses/any")
		Expect(status).To(Equal(http.StatusOK),
			"precondition: an admin must reach the route; body: %s", body)

		status, body = getOverTLS(addr, roots, nil, "/puppet-ca/v1/certificate_statuses/any")
		Expect(status).To(Equal(http.StatusForbidden),
			"an admin route answered a client with no certificate: the serve command "+
				"came up serving HTTPS with no client-authentication middleware")
		Expect(body).To(ContainSubstring("client certificate required"))
	})

	Context("on an address that is not loopback", func() {
		// 192.0.2.1 is TEST-NET-1 (RFC 5737): never assigned to a host, so the
		// bind fails with EADDRNOTAVAIL and nothing here listens on a real
		// interface. A refusal for want of TLS comes before the bind, so which
		// of the two errors the command returns says which way the gate went.
		const unassigned = "192.0.2.1"

		It("does not refuse to start for want of TLS", func() {
			err := runServeBounded(serveConfig(caDir, servingDir, unassigned, 8140, true))
			Expect(err).NotTo(MatchError(ContainSubstring("refusing to start")),
				"serving_cert is TLS: the plain-HTTP refusal must not fire for it")
			Expect(err).To(MatchError(ContainSubstring("failed to listen on "+unassigned)),
				"the command must get as far as binding, which is past every gate")
		})

		It("refuses the same address without one", func() {
			err := runServeBounded(serveConfig(caDir, servingDir, unassigned, 8140, false))
			Expect(err).To(MatchError(ContainSubstring("refusing to start: plain HTTP")),
				"precondition: without serving_cert this address must be refused, or "+
					"the spec above could not tell the gate firing from it being absent")
		})

		// The command starts its background jobs -- the managed-certificate
		// reconcile among them -- before it binds, so this path returns with
		// them already running. Until #546 nothing waited for them: a reconcile
		// pass could still be creating a lock file in cadir while the spec's
		// cleanup removed it, which failed "does not refuse to start for want
		// of TLS" in 3 or 4 runs in 150 under load. Checked by stack rather
		// than by the cleanup, so that a regression fails on an unloaded
		// machine too.
		It("leaves nothing it started running once it has returned", func() {
			err := runServeBounded(serveConfig(caDir, servingDir, unassigned, 8140, true))
			Expect(err).To(MatchError(ContainSubstring("failed to listen on "+unassigned)),
				"precondition: the command must have started its jobs, which it does before binding")
			Expect(serveCommandGoroutines()).To(BeEmpty(),
				"the serve command returned while goroutines it started were still running")
		})
	})
})

// serveConfig writes a config file for the serve command. withServing adds a
// serving_cert issued for "localhost", which is the name getOverTLS verifies.
// puppet_server names admin.example.com as the admin allow list.
func serveConfig(caDir, servingDir, host string, port int, withServing bool) string {
	GinkgoHelper()
	doc := fmt.Sprintf(`cadir: %s
hostname: ca.example.com
host: %s
port: %d
puppet_server: admin.example.com
`, caDir, host, port)
	if withServing {
		doc += fmt.Sprintf(`serving_cert:
  certname: localhost
  names: [localhost]
  renew_before: 720h
  key_algo: ecdsa
  key_size: 256
  store:
    files:
      cert: %s
      key: %s
`, filepath.Join(servingDir, "tls.crt"), filepath.Join(servingDir, "tls.key"))
	}
	return writeTempConfig(doc)
}

// startServe runs the serve command in this process until the spec ends, and
// returns the address it is listening on once it has reported READY=1.
//
// --single-process because the launcher would otherwise fork this test binary
// as its children. Readiness comes from the service-manager notification the
// command sends after binding, rather than from polling the port, so a server
// that is slow to start is waited for and one that fails is reported with its
// own error instead of a connection refusal.
func startServe(configPath string) string {
	GinkgoHelper()
	rec := startNotifyRecorder(nil)

	addr, err := readConfigAddr(configPath)
	Expect(err).NotTo(HaveOccurred())

	cmd := newRootCmd()
	cmd.SetOut(GinkgoWriter)
	cmd.SetErr(GinkgoWriter)
	cmd.SetArgs([]string{"--config", configPath, "--single-process"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	exited := false
	DeferCleanup(func() {
		cancel()
		if exited {
			return
		}
		Eventually(done, "60s").Should(Receive(),
			"the serve command did not stop when its context was cancelled")
	})

	deadline := time.After(60 * time.Second)
	for {
		select {
		case msg, ok := <-rec.msgs:
			if ok && strings.Contains(msg, "READY=1") {
				return addr
			}
		case err := <-done:
			exited = true
			Fail(fmt.Sprintf("the serve command exited before it was ready: %v", err))
		case <-deadline:
			Fail("the serve command did not report READY=1 within 60s")
		}
	}
}

// runServeBounded runs the serve command to completion and returns its error.
// Bounded because the specs that call it expect it to fail before serving; if
// it served instead, the deadline stops it and the nil error fails the spec,
// rather than the spec hanging until the binary's own timeout.
func runServeBounded(configPath string) error {
	GinkgoHelper()
	// Not used for its messages, but it pins NOTIFY_SOCKET to a socket this
	// spec owns, so nothing reaches a real service manager.
	startNotifyRecorder(nil)

	cmd := newRootCmd()
	cmd.SetOut(GinkgoWriter)
	cmd.SetErr(GinkgoWriter)
	cmd.SetArgs([]string{"--config", configPath, "--single-process"})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return cmd.ExecuteContext(ctx)
}

// serveCommandGoroutines returns the stack of every goroutine running code from
// the serve command's RunE: its closures appear in the stack as
// main.newRootCmd.func…, whether they are the goroutine's own frames or the
// function that created it.
func serveCommandGoroutines() []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var found []string
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(stack, "main.newRootCmd.") {
			found = append(found, stack)
		}
	}
	return found
}

// readConfigAddr reads back the host and port a config file names, so
// startServe returns the address it actually configured.
func readConfigAddr(configPath string) (string, error) {
	cfg, err := loadServerConfig(configPath)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)), nil
}

// freeLoopbackPort returns a loopback port that was free a moment ago. The
// serve command takes its port from configuration and reports it back only as
// written, so a spec has to choose one; the window between closing this
// listener and the server binding it is the usual, accepted race.
func freeLoopbackPort() int {
	GinkgoHelper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	port := l.Addr().(*net.TCPAddr).Port
	Expect(l.Close()).To(Succeed())
	return port
}

// mintClientCert has the CA in caDir sign a certificate for subject and
// returns it with its key, ready to present.
func mintClientCert(caDir, subject string) tls.Certificate {
	GinkgoHelper()
	ctx := context.Background()
	myCA := ca.New(storage.New(caDir), ca.AutosignConfig{Mode: "off"}, "ca.example.com")
	myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	Expect(myCA.Init(ctx)).To(Succeed())

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, key)
	Expect(err).NotTo(HaveOccurred())

	_, err = myCA.SaveRequest(ctx, subject,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	Expect(err).NotTo(HaveOccurred())
	certPEM, err := myCA.Sign(ctx, subject)
	Expect(err).NotTo(HaveOccurred())

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	pair, err := tls.X509KeyPair(certPEM,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	Expect(err).NotTo(HaveOccurred())
	return pair
}

// caRoots is a pool holding only the CA in caDir, so a client verifies the
// listener against the CA that issued its certificate and nothing else.
func caRoots(caDir string) *x509.CertPool {
	GinkgoHelper()
	caPEM, err := storage.New(caDir).GetCACert(context.Background())
	Expect(err).NotTo(HaveOccurred())
	pool := x509.NewCertPool()
	Expect(pool.AppendCertsFromPEM(caPEM)).To(BeTrue())
	return pool
}

// getOverTLS fetches path from addr, verifying the server as "localhost"
// against roots and presenting client if it is non-nil. It returns the status
// and body. Verification is on, unlike handshakeSerial's: here, trusting the
// listener is part of what the spec claims.
func getOverTLS(addr string, roots *x509.CertPool, client *tls.Certificate, path string) (int, string) {
	GinkgoHelper()
	cfg := &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	if client != nil {
		cfg.Certificates = []tls.Certificate{*client}
	}
	hc := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg},
	}
	defer hc.CloseIdleConnections()

	resp, err := hc.Get("https://" + addr + path)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	return resp.StatusCode, string(body)
}
