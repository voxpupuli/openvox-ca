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
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// runHealthcheck runs `openvox-ca healthcheck` through the root command, as
// the image's HEALTHCHECK does.
func runHealthcheck(args ...string) (string, error) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"healthcheck"}, args...))
	err := root.Execute()
	return out.String(), err
}

// listenerPort is the port an httptest server, or any listener, is bound to.
func listenerPort(ln net.Listener) string {
	_, port, err := net.SplitHostPort(ln.Addr().String())
	Expect(err).NotTo(HaveOccurred())
	return port
}

// healthServer records the paths it was asked for and answers each with
// status.
type healthServer struct {
	mu     sync.Mutex
	paths  []string
	status int
}

func (h *healthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.paths = append(h.paths, r.URL.Path)
	status := h.status
	h.mu.Unlock()
	if status == http.StatusFound {
		http.Redirect(w, r, "/elsewhere", status)
		return
	}
	w.WriteHeader(status)
}

func (h *healthServer) requested() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.paths...)
}

var _ = Describe("healthcheck subcommand", func() {
	var cfgPath string

	// writeConfig replaces the config file the command is pointed at.
	writeConfig := func(body string) {
		Expect(os.WriteFile(cfgPath, []byte(body), 0o600)).To(Succeed())
	}

	BeforeEach(func() {
		cfgPath = filepath.Join(GinkgoT().TempDir(), "config.yaml")
		writeConfig("{}\n")
		// The command reads the environment as the server does; a value
		// inherited from the developer's shell would point it somewhere else,
		// or fail it on a setting it does not use.
		clearServerEnv()
		unsetSpecEnv(configEnvVar)
	})

	Context("when the server speaks TLS", func() {
		It("checks over HTTPS without verifying the server's certificate", func() {
			// httptest's certificate is signed by nothing this process trusts,
			// as the CA's own certificate is when the server serves with it.
			h := &healthServer{status: http.StatusOK}
			srv := httptest.NewTLSServer(h)
			DeferCleanup(srv.Close)
			port := listenerPort(srv.Listener)

			out, err := runHealthcheck("--config", cfgPath, "--port", port)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(Equal("healthy: https://127.0.0.1:" + port + "/healthz/ready\n"))
			Expect(h.requested()).To(Equal([]string{"/healthz/ready"}))
		})
	})

	Context("when the server speaks plain HTTP", func() {
		It("falls back to HTTP", func() {
			h := &healthServer{status: http.StatusOK}
			srv := httptest.NewServer(h)
			DeferCleanup(srv.Close)
			port := listenerPort(srv.Listener)

			out, err := runHealthcheck("--config", cfgPath, "--port", port)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(Equal("healthy: http://127.0.0.1:" + port + "/healthz/ready\n"))
			Expect(h.requested()).To(Equal([]string{"/healthz/ready"}))
		})
	})

	DescribeTable("is unhealthy when the endpoint answers anything but 200",
		func(status int, want string) {
			h := &healthServer{status: status}
			srv := httptest.NewTLSServer(h)
			DeferCleanup(srv.Close)

			out, err := runHealthcheck("--config", cfgPath, "--port", listenerPort(srv.Listener))
			Expect(err).To(MatchError(And(ContainSubstring("unhealthy:"), ContainSubstring(want))))
			Expect(out).To(BeEmpty())
			// A redirect is not followed: following it would check another
			// endpoint and report that one's answer.
			Expect(h.requested()).To(Equal([]string{"/healthz/ready"}))
		},
		Entry("503 while the CA is not ready", http.StatusServiceUnavailable, "answered HTTP 503"),
		Entry("a redirect", http.StatusFound, "answered HTTP 302"),
	)

	It("reports the status code, never the reason phrase the server chose", func() {
		// The reason phrase is the server's own text. Go's client passes its
		// control bytes through, and main prints the error to a terminal as
		// it is, so an escape sequence here would reach the operator's
		// screen. This answers every connection with it, a ClientHello
		// included, so the check falls back to plain HTTP and reads it again.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		done := make(chan struct{})
		DeferCleanup(func() {
			_ = ln.Close()
			<-done
		})
		go func() {
			defer close(done)
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_, _ = conn.Read(make([]byte, 4096))
				_, _ = conn.Write([]byte("HTTP/1.1 503 \x1b[2Jforged\rline\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				_ = conn.Close()
			}
		}()

		_, err = runHealthcheck("--config", cfgPath, "--port", listenerPort(ln))
		Expect(err).To(MatchError(ContainSubstring("answered HTTP 503")))
		Expect(err.Error()).NotTo(ContainSubstring("\x1b"))
		Expect(err.Error()).NotTo(ContainSubstring("forged"))
	})

	It("is unhealthy when nothing is listening", func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		port := listenerPort(ln)
		Expect(ln.Close()).To(Succeed())

		_, err = runHealthcheck("--config", cfgPath, "--port", port)
		Expect(err).To(MatchError(And(ContainSubstring("unhealthy:"), ContainSubstring("refused"))))
	})

	It("is unhealthy within --timeout when the server accepts but never answers", func() {
		// Accepts the connection and says nothing, so the TLS handshake waits
		// for a ServerHello that never comes. That must be reported, not
		// mistaken for a plain-HTTP server and retried in clear.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		var (
			mu    sync.Mutex
			conns []net.Conn
		)
		done := make(chan struct{})
		DeferCleanup(func() {
			_ = ln.Close()
			<-done
			mu.Lock()
			defer mu.Unlock()
			for _, c := range conns {
				_ = c.Close()
			}
		})
		go func() {
			defer close(done)
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				conns = append(conns, conn)
				mu.Unlock()
			}
		}()

		start := time.Now()
		_, err = runHealthcheck("--config", cfgPath, "--port", listenerPort(ln), "--timeout", "200ms")
		Expect(err).To(MatchError(And(ContainSubstring("unhealthy:"), ContainSubstring("deadline exceeded"))))
		// Below the default, so a --timeout that is ignored fails here.
		Expect(time.Since(start)).To(BeNumerically("<", defaultHealthcheckTimeout))
	})

	DescribeTable("does not retry in clear when the TLS handshake fails for another reason",
		func(onClientHello []byte) {
			// Answers a ClientHello with onClientHello and hangs up, and
			// answers plain HTTP with 200. Only a server that answers a
			// ClientHello in HTTP is checked over HTTP; one whose TLS is
			// broken is unhealthy, however it would answer in clear.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			var inClear atomic.Int32
			done := make(chan struct{})
			DeferCleanup(func() {
				_ = ln.Close()
				<-done
			})
			go func() {
				defer close(done)
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					first := make([]byte, 1)
					if _, err := conn.Read(first); err == nil {
						if first[0] == 0x16 {
							_, _ = conn.Write(onClientHello)
						} else {
							inClear.Add(1)
							_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
						}
					}
					_ = conn.Close()
				}
			}()

			_, err = runHealthcheck("--config", cfgPath, "--port", listenerPort(ln))
			Expect(err).To(MatchError(ContainSubstring("unhealthy:")))
			Expect(inClear.Load()).To(BeZero())
		},
		Entry("hanging up", nil),
		// A first record that is not TLS but not HTTP either: a banner from
		// some other service holding the port.
		Entry("answering with another protocol's banner", []byte("SSH-2.0-OpenSSH_9.9\r\n")),
	)

	It("is unhealthy within --timeout when the server never answers the request", func() {
		// The handshake completes and the request is never answered, so the
		// deadline has to bound the HTTP exchange as well as the dial.
		release := make(chan struct{})
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Bounded, so a check that has lost its deadline fails this spec
			// with a 200 rather than hanging the suite.
			select {
			case <-release:
			case <-time.After(10 * time.Second):
			}
		}))
		// LIFO: release the handler before Close waits for it.
		DeferCleanup(srv.Close)
		DeferCleanup(func() { close(release) })

		start := time.Now()
		_, err := runHealthcheck("--config", cfgPath, "--port", listenerPort(srv.Listener), "--timeout", "200ms")
		Expect(err).To(MatchError(And(ContainSubstring("unhealthy:"), ContainSubstring("deadline exceeded"))))
		// Below the default, so a --timeout that is ignored fails here.
		Expect(time.Since(start)).To(BeNumerically("<", defaultHealthcheckTimeout))
	})

	It("gives up before the images' HEALTHCHECK --timeout does", func() {
		// So that a hung server is reported by the check, with a reason,
		// rather than by the runtime killing it with none.
		// Every image at the top of the tree, so an image added later is held
		// to it without anyone extending a list -- and must declare one: an
		// image without it reports no health at all, which is #366 again.
		declares := regexp.MustCompile(`(?m)^HEALTHCHECK\b`)
		timeout := regexp.MustCompile(`(?m)^HEALTHCHECK [^\n]*--timeout=(\d+)s`)
		paths, err := filepath.Glob(filepath.Join("..", "..", "Dockerfile*"))
		Expect(err).NotTo(HaveOccurred())
		checked := 0
		for _, path := range paths {
			src, err := os.ReadFile(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(declares.Match(src)).To(BeTrue(), "%s declares no HEALTHCHECK", path)
			m := timeout.FindSubmatch(src)
			Expect(m).NotTo(BeNil(), "%s declares a HEALTHCHECK with no --timeout", path)
			secs, err := strconv.Atoi(string(m[1]))
			Expect(err).NotTo(HaveOccurred())
			Expect(defaultHealthcheckTimeout).To(BeNumerically("<", time.Duration(secs)*time.Second), path)
			checked++
		}
		// Both images declare one, so a glob that matched nothing cannot pass.
		Expect(checked).To(BeNumerically(">=", 2))
		// The image runs the check with no --timeout, so the flag's default is
		// the value in force, not the constant on its own.
		Expect(newHealthcheckCmd().Flags().Lookup("timeout").DefValue).To(Equal(defaultHealthcheckTimeout.String()))
	})

	DescribeTable("requests the endpoint --probe names",
		func(probe, path string) {
			h := &healthServer{status: http.StatusOK}
			srv := httptest.NewTLSServer(h)
			DeferCleanup(srv.Close)

			_, err := runHealthcheck("--config", cfgPath, "--port", listenerPort(srv.Listener), "--probe", probe)
			Expect(err).NotTo(HaveOccurred())
			Expect(h.requested()).To(Equal([]string{path}))
		},
		Entry("live", "live", "/healthz/live"),
		Entry("ready", "ready", "/healthz/ready"),
		Entry("startup", "startup", "/healthz/startup"),
	)

	It("refuses a --probe it does not know", func() {
		_, err := runHealthcheck("--config", cfgPath, "--probe", "healthz")
		Expect(err).To(MatchError(`--probe must be one of live, ready, startup, not "healthz"`))
	})

	It("refuses a --timeout that is not positive", func() {
		_, err := runHealthcheck("--config", cfgPath, "--timeout", "0s")
		Expect(err).To(MatchError(ContainSubstring("--timeout must be positive")))
	})

	Context("finding the server", func() {
		var (
			h    *healthServer
			port string
		)

		BeforeEach(func() {
			h = &healthServer{status: http.StatusOK}
			srv := httptest.NewTLSServer(h)
			DeferCleanup(srv.Close)
			port = listenerPort(srv.Listener)
		})

		It("takes the port and listen address from the configuration file", func() {
			// 0.0.0.0 is the server's own default; it is checked over loopback.
			writeConfig("host: 0.0.0.0\nport: " + port + "\n")
			out, err := runHealthcheck("--config", cfgPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("https://127.0.0.1:" + port + "/"))
		})

		It("finds the configuration file through OPENVOX_CA_CONFIG", func() {
			writeConfig("port: " + port + "\n")
			setEnv(configEnvVar, cfgPath)
			_, err := runHealthcheck()
			Expect(err).NotTo(HaveOccurred())
			// This spec's server, not whatever else may answer on 8140.
			Expect(h.requested()).To(Equal([]string{"/healthz/ready"}))
		})

		It("takes the port from OPENVOX_CA_PORT", func() {
			setEnv("OPENVOX_CA_PORT", port)
			_, err := runHealthcheck("--config", cfgPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(h.requested()).To(Equal([]string{"/healthz/ready"}))
		})

		It("checks a specific listen address from the configuration file there", func() {
			// A name, not loopback's address: every wildcard maps to
			// 127.0.0.1, so only something else shows the configured host
			// was the one dialled.
			writeConfig("host: localhost\nport: " + port + "\n")
			out, err := runHealthcheck("--config", cfgPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(Equal("healthy: https://localhost:" + port + "/healthz/ready\n"))
		})

		It("lets --port and --host override the configuration", func() {
			writeConfig("host: 192.0.2.1\nport: 1\n")
			out, err := runHealthcheck("--config", cfgPath, "--host", "localhost", "--port", port)
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(Equal("healthy: https://localhost:" + port + "/healthz/ready\n"))
		})

		It("refuses a configuration the server would refuse", func() {
			writeConfig("port: " + port + "\nno_such_setting: true\n")
			_, err := runHealthcheck("--config", cfgPath)
			Expect(err).To(MatchError(ContainSubstring("no_such_setting")))
			Expect(h.requested()).To(BeEmpty())
		})
	})

	DescribeTable("connects to a wildcard listen address over loopback",
		func(host, want string) {
			Expect(healthcheckAddr(host, 8140)).To(Equal(want))
		},
		Entry("unset", "", "127.0.0.1:8140"),
		Entry("IPv4 wildcard", "0.0.0.0", "127.0.0.1:8140"),
		Entry("IPv6 wildcard", "::", "[::1]:8140"),
		Entry("bracketed IPv6 wildcard, as the chart writes it", "[::]", "[::1]:8140"),
		Entry("a specific IPv4 address", "192.0.2.1", "192.0.2.1:8140"),
		Entry("a specific IPv6 address", "[2001:db8::1]", "[2001:db8::1]:8140"),
		Entry("a name", "localhost", "localhost:8140"),
	)

	It("never sends the check through a proxy from the environment", func() {
		// Go exempts loopback from HTTP(S)_PROXY, but not an address the
		// server was bound to with --host, which is where a proxy would take
		// the check somewhere else.
		Expect(healthcheckTransport().Proxy).To(BeNil())
	})
})
