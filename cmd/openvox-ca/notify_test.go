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
	"context"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
)

// notifyRecorder stands in for a service manager listening on $NOTIFY_SOCKET,
// recording every notification the process under test sends.
type notifyRecorder struct {
	msgs chan string
}

// startNotifyRecorder binds a datagram socket, points $NOTIFY_SOCKET at it and
// drains messages until the spec ends. The socket, the temporary directory and
// the environment variables are all restored on cleanup so specs stay isolated.
func startNotifyRecorder(env map[string]string) *notifyRecorder {
	dir, err := os.MkdirTemp("", "notify")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(os.RemoveAll(dir)).To(Succeed()) })

	path := filepath.Join(dir, "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { conn.Close() })

	r := &notifyRecorder{msgs: make(chan string, 64)}
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				close(r.msgs)
				return
			}
			// Never block: a spec that starts the recorder for its side
			// effect and ignores the messages (the heartbeat specs do) would
			// otherwise fill the buffer, park this goroutine for good and stop
			// it draining the socket -- and once the kernel's datagram queue
			// filled too, every send would stall for the notifier's whole
			// write deadline while holding its mutex. Close() only wakes a
			// goroutine blocked in Read, never one blocked here.
			select {
			case r.msgs <- string(buf[:n]):
			default:
			}
		}
	}()

	// setEnv is the package's existing save/restore helper (config_test.go).
	setEnv("NOTIFY_SOCKET", path)
	for k, v := range env {
		setEnv(k, v)
	}
	return r
}

// unsetSpecEnv removes an environment variable for the duration of the spec,
// restoring it afterwards. The counterpart to setEnv, for specs that need a
// variable absent rather than present.
func unsetSpecEnv(key string) {
	prev, had := os.LookupEnv(key)
	ExpectWithOffset(1, os.Unsetenv(key)).To(Succeed())
	DeferCleanup(func() {
		if had {
			Expect(os.Setenv(key, prev)).To(Succeed())
		}
	})
}

var _ = Describe("Service manager status text", func() {
	// A fixed "now" keeps the rendered countdowns deterministic.
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	Describe("humanDuration", func() {
		DescribeTable("renders a single coarse unit",
			func(d time.Duration, expected string) {
				Expect(humanDuration(d)).To(Equal(expected))
			},
			Entry("years become days", 1794*24*time.Hour, "1794d"),
			Entry("exactly two days", 48*time.Hour, "2d"),
			Entry("days", 72*time.Hour, "3d"),
			Entry("just under two days falls back to hours", 47*time.Hour, "47h"),
			Entry("exactly two hours", 2*time.Hour, "2h"),
			Entry("hours", 5*time.Hour, "5h"),
			Entry("just under two hours falls back to minutes", 119*time.Minute, "119m"),
			Entry("minutes", 90*time.Second, "1m"),
			Entry("seconds", 30*time.Second, "30s"),
			Entry("sub-second", 100*time.Millisecond, "0s"),
		)
	})

	Describe("deadlinePhrase", func() {
		It("counts down to a future deadline", func() {
			Expect(deadlinePhrase(now.Add(72*time.Hour), now)).To(Equal("expires in 3d"))
		})

		It("shouts about a deadline that has passed", func() {
			// Capitalised on purpose: this is the line an operator should
			// notice in `systemctl status`.
			Expect(deadlinePhrase(now.Add(-48*time.Hour), now)).To(Equal("EXPIRED 2d ago"))
		})

		It("admits when it does not know", func() {
			Expect(deadlinePhrase(time.Time{}, now)).To(Equal("expiry unknown"))
		})
	})

	Describe("statusReport", func() {
		var report statusReport

		BeforeEach(func() {
			report = statusReport{
				addr:    "0.0.0.0:8140",
				tls:     true,
				caCN:    "puppet.example.com",
				caUntil: now.Add(1794 * 24 * time.Hour),
				crlOK:   true,
				crl: ca.CRLSnapshot{
					Number:     big.NewInt(7),
					NextUpdate: now.Add(29 * 24 * time.Hour),
					Revoked:    3,
				},
			}
		})

		It("summarises the listener, the CA and the CRL", func() {
			Expect(report.line(now)).To(Equal(
				`Serving HTTPS on 0.0.0.0:8140 | CA "puppet.example.com" expires in 1794d | CRL #7 (3 revoked) expires in 29d`))
		})

		It("distinguishes a plain HTTP listener", func() {
			report.tls = false
			Expect(report.line(now)).To(HavePrefix("Serving HTTP on 0.0.0.0:8140 |"))
		})

		It("omits the CA when it is not loaded", func() {
			report.caCN = ""
			Expect(report.line(now)).NotTo(ContainSubstring("CA \""))
			Expect(report.line(now)).To(ContainSubstring("CRL #7"))
		})

		It("says so when no CRL has been loaded", func() {
			report.crlOK = false
			Expect(report.line(now)).To(HaveSuffix("| CRL not loaded"))
		})

		It("copes with a CRL that has no number", func() {
			report.crl.Number = nil
			Expect(report.line(now)).To(ContainSubstring("| CRL (3 revoked) expires in 29d"))
		})

		It("surfaces an expired CA certificate", func() {
			report.caUntil = now.Add(-24 * time.Hour)
			Expect(report.line(now)).To(ContainSubstring(`CA "puppet.example.com" EXPIRED 24h ago`))
		})

		It("surfaces a lapsed CRL", func() {
			report.crl.NextUpdate = now.Add(-72 * time.Hour)
			Expect(report.line(now)).To(ContainSubstring("CRL #7 (3 revoked) EXPIRED 3d ago"))
		})
	})

	Describe("newStatusReport", func() {
		It("maps the CA's certificate and CRL onto the report", func() {
			// Rendering is covered above; this pins where the values come
			// from. Sourcing caUntil from NotBefore, or the CN from the
			// issuer, would render perfectly and report a CA as having
			// decades left on the day it expires.
			testCA, _ := newRefresherTestCA()

			report := newStatusReport(testCA, "0.0.0.0:8140", true)
			Expect(report.caCN).To(Equal(testCA.CACert.Subject.CommonName))
			Expect(report.caUntil).To(BeTemporally("==", testCA.CACert.NotAfter))
			Expect(report.crlOK).To(BeTrue())

			snap, ok := testCA.CRLSnapshot()
			Expect(ok).To(BeTrue())
			Expect(report.crl.Number).To(Equal(snap.Number))
			Expect(report.crl.Revoked).To(Equal(snap.Revoked))
			Expect(report.crl.NextUpdate).To(BeTemporally("==", snap.NextUpdate))
		})

		It("reads the CA's certificate and cached CRL", func() {
			// A CA that has never been initialised still has to produce a
			// status line rather than panic: the heartbeat runs regardless.
			report := newStatusReport(ca.New(nil, ca.AutosignConfig{}, "host"), "127.0.0.1:8140", false)
			Expect(report.caCN).To(BeEmpty())
			Expect(report.crlOK).To(BeFalse())
			Expect(report.line(now)).To(Equal("Serving HTTP on 127.0.0.1:8140 | CRL not loaded"))
		})
	})
})

var _ = Describe("Service manager heartbeat", func() {
	BeforeEach(func() {
		// Start from a known environment: a developer or CI runner invoking
		// the suite from inside a systemd unit would otherwise inherit a live
		// notification socket and watchdog, and these specs assume neither.
		unsetSpecEnv("NOTIFY_SOCKET")
		unsetSpecEnv("WATCHDOG_USEC")
	})

	Describe("heartbeatInterval", func() {
		It("refreshes the status text once a minute without a watchdog", func() {
			startNotifyRecorder(nil)
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(heartbeatInterval(n)).To(Equal(defaultStatusRefresh))
		})

		It("beats twice per watchdog interval", func() {
			startNotifyRecorder(map[string]string{"WATCHDOG_USEC": "30000000"})
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(heartbeatInterval(n)).To(Equal(15 * time.Second))
		})

		It("still halves a watchdog short enough to warn about", func() {
			// Clamping up to a fixed floor here would return an interval longer
			// than the deadline it feeds, guaranteeing the kill the watchdog
			// exists to prevent. Half is still the right answer; the operator
			// gets a warning instead.
			startNotifyRecorder(map[string]string{"WATCHDOG_USEC": "150000"}) // 150ms
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(heartbeatInterval(n)).To(Equal(75 * time.Millisecond))
		})

		It("stops shortening the ticker for an absurd watchdog", func() {
			startNotifyRecorder(map[string]string{"WATCHDOG_USEC": "1000"}) // 1ms
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(heartbeatInterval(n)).To(Equal(absoluteMinHeartbeat))
		})

		DescribeTable("beats strictly inside every deadline it can honour",
			func(usec string) {
				// The invariant that matters: for any WatchdogSec an operator
				// might realistically set, the keep-alive goes out more often
				// than the deadline, or systemd kills a healthy CA. Below 20ms
				// the ticker floor wins instead — deliberately, and loudly; see
				// the spec above.
				startNotifyRecorder(map[string]string{"WATCHDOG_USEC": usec})
				n := sdnotify.New()
				DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

				Expect(heartbeatInterval(n)).To(BeNumerically("<", n.WatchdogInterval()))
			},
			Entry("a minute", "60000000"),
			Entry("two seconds", "2000000"),
			Entry("one second", "1000000"),
			Entry("200ms", "200000"),
			Entry("150ms", "150000"),
			Entry("30ms", "30000"),
			Entry("21ms, just above where the floor takes over", "21000"),
		)

		It("warns when the watchdog is too short to be fed reliably", func() {
			// The operator-facing half of the trade-off: the CA does not
			// silently accept a deadline it cannot meet.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			startNotifyRecorder(map[string]string{"WATCHDOG_USEC": "5000"}) // 5ms
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(heartbeatInterval(n)).To(Equal(absoluteMinHeartbeat))
			Expect(buf.String()).To(ContainSubstring("WatchdogSec is very short"))
			Expect(buf.String()).To(ContainSubstring("heartbeat=10ms"))
		})

		DescribeTable("warns exactly below the documented threshold",
			func(usec string, wantInterval time.Duration, wantWarning bool) {
				// The threshold is half the deadline against
				// shortWatchdogWarnBelow, i.e. a 200ms WatchdogSec. Testing
				// only far from it leaves a >= / > slip invisible.
				var buf bytes.Buffer
				orig := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
				defer slog.SetDefault(orig)

				startNotifyRecorder(map[string]string{"WATCHDOG_USEC": usec})
				n := sdnotify.New()
				DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

				Expect(heartbeatInterval(n)).To(Equal(wantInterval))
				if wantWarning {
					Expect(buf.String()).To(ContainSubstring("WatchdogSec is very short"))
				} else {
					Expect(buf.String()).To(BeEmpty())
				}
			},
			Entry("exactly at the threshold stays quiet", "200000", 100*time.Millisecond, false),
			Entry("one millisecond under it warns", "199000", 99500*time.Microsecond, true),
			Entry("at twice the floor, half is still returned", "20000", absoluteMinHeartbeat, true),
			Entry("below twice the floor, the floor wins", "19000", absoluteMinHeartbeat, true),
		)

		It("says nothing about a watchdog it can honour", func() {
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			startNotifyRecorder(map[string]string{"WATCHDOG_USEC": "60000000"})
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(heartbeatInterval(n)).To(Equal(30 * time.Second))
			Expect(buf.String()).To(BeEmpty())
		})
	})

	// The magefile makes -race mandatory because main.go drives one Notifier
	// from three places at once: the heartbeat, the reload watcher, and a
	// deferred Close. Each was only ever exercised in isolation, so the
	// combination the rationale names was never actually reproduced.
	Describe("the heartbeat, a reload, and a close together", func() {
		It("survives all three running against one notifier", func() {
			// Claim SIGHUP before anything can send one; the default
			// disposition would take the test binary down.
			hupCh := make(chan os.Signal, 1)
			signal.Notify(hupCh, syscall.SIGHUP)
			DeferCleanup(func() { signal.Stop(hupCh) })

			dir := GinkgoT().TempDir()
			cnFile := filepath.Join(dir, "servers.txt")
			Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\n"), 0600)).To(Succeed())
			allowList, err := buildAdminAllowList("", cnFile)
			Expect(err).NotTo(HaveOccurred())
			reloader := &configReloader{auth: api.NewAuthConfig(nil, allowList), cnFile: cnFile}

			startNotifyRecorder(map[string]string{"WATCHDOG_USEC": "20000"})
			n := sdnotify.New()
			Expect(n.Enabled()).To(BeTrue())

			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				runNotifyHeartbeat(ctx, n, time.Millisecond, func() string { return "serving" })
			}()
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				runReloadWatcher(ctx, hupCh, n, reloader, func() string { return "serving" })
			}()

			// Drive a real reload while the heartbeat is ticking.
			Expect(os.WriteFile(cnFile, []byte("compile-2.example.com\n"), 0600)).To(Succeed())
			Expect(syscall.Kill(os.Getpid(), syscall.SIGHUP)).To(Succeed())
			Eventually(func() bool { return reloader.auth.IsOwnAdminCN("compile-2.example.com") }).Should(BeTrue())

			// Close underneath both of them, exactly as the deferred Close in
			// main.go can, before the context is cancelled.
			Expect(n.Close()).To(Succeed())

			// Deliberately widen the window between the close and the cancel,
			// so both goroutines get ticks in against a closed notifier. Not
			// an assertion — there is nothing to poll for here, and dressing
			// the wait up as one would only look like a check.
			time.Sleep(20 * time.Millisecond)

			cancel()
			wg.Wait()
			Expect(n.Enabled()).To(BeFalse())
		})
	})

	Describe("runNotifyHeartbeat", func() {
		It("returns immediately when there is no service manager", func() {
			done := make(chan struct{})
			go func() {
				defer close(done)
				runNotifyHeartbeat(context.Background(), sdnotify.New(), time.Hour, func() string { return "x" })
			}()
			Eventually(done).Should(BeClosed())
		})

		It("feeds the watchdog and republishes the status", func() {
			rec := startNotifyRecorder(map[string]string{"WATCHDOG_USEC": "30000000"})
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			ctx, cancel := context.WithCancel(context.Background())
			DeferCleanup(cancel)

			calls := make(chan struct{}, 16)
			go runNotifyHeartbeat(ctx, n, 10*time.Millisecond, func() string {
				select {
				case calls <- struct{}{}:
				default:
				}
				return "still here"
			})

			Eventually(calls).Should(Receive())
			Eventually(rec.msgs).Should(Receive(Equal("WATCHDOG=1\n")))
			Eventually(rec.msgs).Should(Receive(Equal("STATUS=still here\n")))
		})

		It("stops when the context is cancelled", func() {
			startNotifyRecorder(nil)
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				runNotifyHeartbeat(ctx, n, time.Millisecond, func() string { return "x" })
			}()

			cancel()
			Eventually(done).Should(BeClosed())
		})
	})
})
