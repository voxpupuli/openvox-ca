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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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
			r.msgs <- string(buf[:n])
		}
	}()

	setSpecEnv("NOTIFY_SOCKET", path)
	for k, v := range env {
		setSpecEnv(k, v)
	}
	return r
}

// setSpecEnv sets an environment variable for the duration of the current
// spec. Ginkgo nodes cannot use testing.T.Setenv, so the previous value (or
// its absence) is restored explicitly.
func setSpecEnv(key, value string) {
	prev, had := os.LookupEnv(key)
	ExpectWithOffset(1, os.Setenv(key, value)).To(Succeed())
	DeferCleanup(func() {
		if had {
			Expect(os.Setenv(key, prev)).To(Succeed())
			return
		}
		Expect(os.Unsetenv(key)).To(Succeed())
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
			Entry("days", 72*time.Hour, "3d"),
			Entry("just under two days falls back to hours", 47*time.Hour, "47h"),
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

		It("never beats faster than the floor", func() {
			// A 100ms WatchdogSec would otherwise have the CA spinning.
			startNotifyRecorder(map[string]string{"WATCHDOG_USEC": "100000"})
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(heartbeatInterval(n)).To(Equal(minHeartbeat))
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
			Eventually(rec.msgs).Should(Receive(Equal("WATCHDOG=1")))
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
