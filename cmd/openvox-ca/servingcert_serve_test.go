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
	"os"
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
		// Ambient OPENVOX_CA_* would outrank the fixture config, so a host with
		// OPENVOX_CA_TLS_CERT exported would test a different command.
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

	// The twin of "does not announce a drain when it fails to start" below,
	// so that one cannot pass because the command never announces one at all.
	It("announces a drain when it is stopped deliberately", func() {
		_, rec, stop := startServeRecorded(serveConfig(caDir, servingDir, "127.0.0.1", freeLoopbackPort(), true))
		stop()
		Eventually(rec.msgs).Should(Receive(SatisfyAll(
			HavePrefix("STOPPING=1"),
			ContainSubstring("Shutting down: draining connections"),
		)), "a deliberate stop must tell the service manager it is draining, "+
			"or systemd may take the teardown for a crash")
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
		// machine too. The metrics exporter is enabled because it is the one
		// goroutine that does not watch the group's context: it stops only when
		// the shutdown goroutine shuts it down, and if that ever stops happening
		// the command does not return at all, which runServeRecorded reports.
		It("leaves nothing it started running once it has returned", func() {
			err := runServeBounded(withMetricsListen(serveConfig(caDir, servingDir, unassigned, 8140, true)))
			Expect(err).To(MatchError(ContainSubstring("failed to listen on "+unassigned)),
				"precondition: the command must have started its jobs, which it does before binding")
			Expect(serveCommandGoroutines()).To(BeEmpty(),
				"the serve command returned while goroutines it started were still running")
		})

		// A failed start stops the command's goroutines, the shutdown goroutine
		// among them, but it is not a deliberate teardown. Announcing a drain
		// there makes "Shutting down" the last status systemd shows, in place
		// of the failure.
		It("does not announce a drain when it fails to start", func() {
			rec, err := runServeRecorded(serveConfig(caDir, servingDir, unassigned, 8140, true))
			Expect(err).To(MatchError(ContainSubstring("failed to listen on "+unassigned)),
				"precondition: the command must fail at the bind, after its shutdown goroutine exists")

			var msgs []string
			Consistently(func() []string {
				msgs = append(msgs, drainNotifications(rec)...)
				return msgs
			}, "250ms").ShouldNot(ContainElement(HavePrefix("STOPPING=1")),
				"a failed start told the service manager it was draining connections")
			Expect(msgs).To(ContainElement(ContainSubstring("Starting the HTTP server")),
				"precondition: the recorder must have heard the command, or the absence above proves nothing")
		})
	})

	// An invalid kubernetes_export block is refused only once the background
	// jobs are running, and before the shutdown goroutine and the metrics
	// exporter exist. That is a different return from the failed bind above,
	// and the one window where the order of those two matters. The order is
	// pinned by position in goroutine_group_test.go. This drives the window.
	Context("when the configuration is refused after the background jobs have started", func() {
		It("leaves nothing it started running once it has returned", func() {
			configPath := withMetricsListen(serveConfig(caDir, servingDir, "127.0.0.1", freeLoopbackPort(), true))
			appendConfig(configPath, `kubernetes_export:
  targets:
    - kind: Bogus
      metadata:
        name: trust
      cert: true
`)
			err := runServeBounded(configPath)
			Expect(err).To(MatchError(ContainSubstring("invalid kubernetes_export config")),
				"precondition: the command must be refused at the kubernetes_export check, "+
					"after its jobs have started and before the bind")
			Expect(serveCommandGoroutines()).To(BeEmpty(),
				"the serve command returned while goroutines it started were still running")
		})
	})
})

// The two "leaves nothing it started running" specs above assert an absence,
// which a helper that never matches would satisfy, and serveCommandGoroutines
// parses runtime.Stack text, which a toolchain may change. These pin it from
// the other side.
var _ = Describe("serveCommandGoroutines", func() {
	It("reports a group goroutine that is still running its function", func() {
		g := newGoroutineGroup(context.Background())
		release := make(chan struct{})
		entered := make(chan struct{})
		g.Go(func(context.Context) { blockUntilReleased(entered, release) })
		DeferCleanup(func() {
			close(release)
			g.Stop()
		})
		Eventually(entered).Should(BeClosed())

		Expect(serveCommandGoroutines()).To(ContainElement(ContainSubstring(serveCommandPkg+"blockUntilReleased(")),
			"a goroutine blocked in the function it was given was not counted as running, so the "+
				"specs that expect none would pass whatever the serve command left behind")
	})

	// Only the parsing is exercised here. The window it tolerates, between a
	// goroutine's deferred wg.Done and its exit, cannot be held open from a
	// spec without changing goroutineGroup, so these stacks are written out in
	// the shapes the runtime prints them.
	DescribeTable("returnedFromGroupWork",
		func(frames string, returned bool) {
			Expect(returnedFromGroupWork("goroutine 42 [runnable]:\n" + frames)).To(Equal(returned))
		},
		Entry("is true for the closure alone, past its deferred Done (#556)",
			serveCommandPkg+"(*goroutineGroup).Go.func1()\n"+
				"\t/src/cmd/openvox-ca/goroutine_group.go:56 +0x9c\n"+
				"created by "+serveCommandPkg+"(*goroutineGroup).Go in goroutine 1\n"+
				"\t/src/cmd/openvox-ca/goroutine_group.go:53 +0x8c",
			true),
		Entry("is true inside Done itself",
			"sync.(*WaitGroup).Add(0xc000123450, 0xffffffffffffffff)\n"+
				"\t/go/src/sync/waitgroup.go:118 +0x1a8\n"+
				"sync.(*WaitGroup).Done(...)\n"+
				"\t/go/src/sync/waitgroup.go:156\n"+
				serveCommandPkg+"(*goroutineGroup).Go.func1()\n"+
				"\t/src/cmd/openvox-ca/goroutine_group.go:56 +0x9c\n"+
				"created by "+serveCommandPkg+"(*goroutineGroup).Go in goroutine 1\n"+
				"\t/src/cmd/openvox-ca/goroutine_group.go:53 +0x8c",
			true),
		Entry("is false with the function's own frame above the closure",
			"runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)\n"+
				"\t/go/src/runtime/proc.go:435 +0xc8\n"+
				"runtime.chanrecv1(0x0?, 0x0?)\n"+
				"\t/go/src/runtime/chan.go:506 +0x18\n"+
				serveCommandPkg+"newRootCmd.func1.4({0x1, 0x2})\n"+
				"\t/src/cmd/openvox-ca/main.go:1449 +0x40\n"+
				serveCommandPkg+"(*goroutineGroup).Go.func1()\n"+
				"\t/src/cmd/openvox-ca/goroutine_group.go:55 +0x5c\n"+
				"created by "+serveCommandPkg+"(*goroutineGroup).Go in goroutine 1\n"+
				"\t/src/cmd/openvox-ca/goroutine_group.go:53 +0x8c",
			false),
		Entry("is false for a goroutine RunE started without the group",
			"runtime.gopark(0x0?, 0x0?, 0x0?, 0x0?, 0x0?)\n"+
				"\t/go/src/runtime/proc.go:435 +0xc8\n"+
				serveCommandPkg+"newRootCmd.func1.4()\n"+
				"\t/src/cmd/openvox-ca/main.go:1449 +0x40\n"+
				"created by "+serveCommandPkg+"newRootCmd.func1 in goroutine 1\n"+
				"\t/src/cmd/openvox-ca/main.go:1448 +0x1d4",
			false),
	)
})

// blockUntilReleased closes entered and waits on release. It is a named
// function so that its frame can be found in a stack.
func blockUntilReleased(entered chan<- struct{}, release <-chan struct{}) {
	close(entered)
	<-release
}

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
	addr, _, _ := startServeRecorded(configPath)
	return addr
}

// startServeRecorded is startServe, also returning the recorder the command's
// notifications reach and a function that stops the command as a signal would,
// by cancelling its context, and waits for it to return.
func startServeRecorded(configPath string) (string, *notifyRecorder, func()) {
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
	stop := func() {
		cancel()
		if exited {
			return
		}
		exited = true
		Eventually(done, "60s").Should(Receive(),
			"the serve command did not stop when its context was cancelled")
	}
	DeferCleanup(stop)

	deadline := time.After(60 * time.Second)
	for {
		select {
		case msg, ok := <-rec.msgs:
			if ok && strings.Contains(msg, "READY=1") {
				return addr, rec, stop
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
	// The recorder is not used for its messages here, but it pins
	// NOTIFY_SOCKET to a socket this spec owns, so nothing reaches a real
	// service manager.
	_, err := runServeRecorded(configPath)
	return err
}

// runServeRecorded is runServeBounded, also returning the recorder the
// command's notifications reached.
func runServeRecorded(configPath string) (*notifyRecorder, error) {
	GinkgoHelper()
	rec := startNotifyRecorder(nil)

	cmd := newRootCmd()
	cmd.SetOut(GinkgoWriter)
	cmd.SetErr(GinkgoWriter)
	cmd.SetArgs([]string{"--config", configPath, "--single-process"})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	// The context bounds a command that serves when the spec expected it to
	// fail. This bounds one that cannot return at all, which no context
	// reaches: teardown waiting on a goroutine that never stops.
	select {
	case err := <-done:
		return rec, err
	case <-time.After(90 * time.Second):
		Fail("the serve command did not return within 90s: its teardown is waiting " +
			"on a goroutine that never stops")
		return rec, nil
	}
}

// withMetricsListen adds a metrics_listen on a free loopback port to a config
// file serveConfig wrote, so that the command starts its metrics exporter.
func withMetricsListen(configPath string) string {
	GinkgoHelper()
	appendConfig(configPath, fmt.Sprintf("metrics_listen: 127.0.0.1:%d\n", freeLoopbackPort()))
	return configPath
}

// appendConfig appends top-level YAML to a config file serveConfig wrote.
func appendConfig(configPath, yaml string) {
	GinkgoHelper()
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0)
	Expect(err).NotTo(HaveOccurred())
	_, err = f.WriteString(yaml)
	Expect(err).NotTo(HaveOccurred())
	Expect(f.Close()).To(Succeed())
}

// drainNotifications returns every notification rec holds now, without
// waiting for more.
func drainNotifications(rec *notifyRecorder) []string {
	var msgs []string
	for {
		select {
		case msg, ok := <-rec.msgs:
			if !ok {
				return msgs
			}
			msgs = append(msgs, msg)
		default:
			return msgs
		}
	}
}

// serveCommandGoroutines returns the stack of every goroutine the serve
// command's RunE started and that is still running. Before #546 those were
// created by RunE itself, a closure named newRootCmd.func…; now they are
// created by goroutineGroup.Go. Either name in a stack, as a frame or as its
// creator, counts. The package is named by its import path in a test binary,
// not as "main". A goroutine that has already returned from its work is not
// counted, though it is still in the snapshot: see returnedFromGroupWork.
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
		if (strings.Contains(stack, serveCommandPkg+"newRootCmd.") ||
			strings.Contains(stack, serveCommandPkg+"(*goroutineGroup).")) &&
			!returnedFromGroupWork(stack) {
			found = append(found, stack)
		}
	}
	return found
}

// serveCommandPkg prefixes this package's functions in a stack.
const serveCommandPkg = "github.com/voxpupuli/openvox-ca/cmd/openvox-ca."

// returnedFromGroupWork reports whether stack is a goroutine started by
// goroutineGroup.Go that has already returned from the function it was given.
//
// Stop's Wait returns once every such goroutine has run its deferred wg.Done,
// but the goroutine itself exits an instant later, and a snapshot can catch it
// in between (#556). Its stack then shows goroutineGroup.Go's own closure with
// nothing above it but the runtime and sync frames of Done and of exiting. A
// goroutine still running its function has that function's frames above the
// closure, however it is blocked.
//
// Polling would not do in place of this. The command cancels its own context
// as it returns (signal.NotifyContext's stop), so a goroutine nothing waited
// for still finishes soon afterwards, and a poll would wait for it: dropping
// the deferred Stop, which is the #546 defect, would then pass.
//
// A goroutine that has been started but has not yet run looks the same, with
// only the closure on its stack. Stop's Wait cannot return past one of those,
// so it matters only when nothing waits at all. There the specs catch the
// defect only if some goroutine has entered its function by the snapshot,
// which on a single CPU it often has not, so they are not what guards against
// a dropped Stop. "defers stopping the group after every other teardown it
// defers", in goroutine_group_test.go, pins that by the shape of RunE.
func returnedFromGroupWork(stack string) bool {
	frames := strings.Split(stack, "\n")[1:] // after "goroutine N [state]:"
	for _, frame := range frames {
		switch {
		case strings.HasPrefix(frame, "\t"):
			// A frame's file and line, after its function.
		case strings.HasPrefix(frame, serveCommandPkg+"(*goroutineGroup).Go.func1("):
			return true
		case strings.HasPrefix(frame, "runtime."),
			strings.HasPrefix(frame, "sync."),
			strings.HasPrefix(frame, "internal/"):
		default:
			return false
		}
	}
	return false
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
