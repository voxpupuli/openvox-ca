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

package sdnotify_test

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
)

// fakeManager stands in for the service manager: it owns the datagram socket
// named by $NOTIFY_SOCKET and records every message the Notifier sends.
type fakeManager struct {
	msgs chan string
}

// newFakeManager binds a datagram socket in a temporary directory, points
// $NOTIFY_SOCKET at it, and starts draining messages. Both the socket and the
// environment variable are restored when the spec finishes.
func newFakeManager() *fakeManager {
	dir, err := os.MkdirTemp("", "sdnotify")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { Expect(os.RemoveAll(dir)).To(Succeed()) })

	path := filepath.Join(dir, "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { conn.Close() })

	m := &fakeManager{msgs: make(chan string, 32)}
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				close(m.msgs)
				return
			}
			m.msgs <- string(buf[:n])
		}
	}()

	setEnv("NOTIFY_SOCKET", path)
	return m
}

// next returns the next message received, failing the spec if none arrives.
func (m *fakeManager) next() string {
	var msg string
	EventuallyWithOffset(1, m.msgs).Should(Receive(&msg))
	return msg
}

// setEnv sets an environment variable for the duration of the current spec,
// restoring the previous value (or absence) afterwards. Ginkgo nodes cannot
// use testing.T.Setenv, and specs must not leak state into their siblings.
func setEnv(key, value string) {
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

// unsetEnv removes an environment variable for the duration of the spec.
func unsetEnv(key string) {
	prev, had := os.LookupEnv(key)
	ExpectWithOffset(1, os.Unsetenv(key)).To(Succeed())
	DeferCleanup(func() {
		if had {
			Expect(os.Setenv(key, prev)).To(Succeed())
		}
	})
}

var _ = Describe("Notifier", func() {
	BeforeEach(func() {
		// Every spec starts from a known environment: specs that want a
		// service manager or a watchdog opt in explicitly.
		unsetEnv("NOTIFY_SOCKET")
		unsetEnv("WATCHDOG_USEC")
	})

	Context("when NOTIFY_SOCKET is not set", func() {
		It("is inert and safe to use", func() {
			n := sdnotify.New()
			Expect(n.Enabled()).To(BeFalse())
			Expect(n.WatchdogInterval()).To(BeZero())

			// None of these may panic or block; there is nothing to notify.
			n.Ready("serving")
			n.Status("working")
			n.Reloading("reloading")
			n.Stopping("stopping")
			n.Watchdog()
			Expect(n.Close()).To(Succeed())
		})
	})

	Context("when NOTIFY_SOCKET names an unusable socket", func() {
		It("degrades to inert rather than failing", func() {
			setEnv("NOTIFY_SOCKET", filepath.Join(GinkgoT().TempDir(), "does-not-exist.sock"))
			n := sdnotify.New()
			Expect(n.Enabled()).To(BeFalse())
			n.Ready("serving") // must not panic
		})
	})

	Context("when a service manager is listening", func() {
		var (
			mgr *fakeManager
			n   *sdnotify.Notifier
		)

		BeforeEach(func() {
			mgr = newFakeManager()
			n = sdnotify.New()
			Expect(n.Enabled()).To(BeTrue())
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })
		})

		It("reports readiness with a status line", func() {
			n.Ready("Serving HTTPS on 0.0.0.0:8140")
			Expect(mgr.next()).To(Equal("READY=1\nSTATUS=Serving HTTPS on 0.0.0.0:8140\n"))
		})

		It("omits the status line when no status is given", func() {
			n.Ready("")
			Expect(mgr.next()).To(Equal("READY=1\n"))
		})

		It("updates the status text on its own", func() {
			n.Status("Initialising CA")
			Expect(mgr.next()).To(Equal("STATUS=Initialising CA\n"))
		})

		It("sends nothing for an empty status update", func() {
			n.Status("")
			n.Status("second") // a sentinel that must arrive first if the empty one was dropped
			Expect(mgr.next()).To(Equal("STATUS=second\n"))
		})

		It("reports the start of a reload", func() {
			n.Reloading("Reloading TLS material")
			msg := mgr.next()
			Expect(msg).To(HavePrefix("RELOADING=1\n"))
			Expect(msg).To(HaveSuffix("STATUS=Reloading TLS material\n"))
		})

		It("includes a monotonic timestamp with the reload on Linux", func() {
			// Type=notify-reload rejects a RELOADING=1 that carries no
			// MONOTONIC_USEC, so this field is load-bearing on Linux.
			if runtime.GOOS != "linux" {
				Skip("MONOTONIC_USEC is only sent on Linux")
			}
			n.Reloading("")
			Expect(mgr.next()).To(MatchRegexp(`\ARELOADING=1\nMONOTONIC_USEC=[0-9]+\n\z`))
		})

		It("reports the start of shutdown", func() {
			n.Stopping("Draining connections")
			Expect(mgr.next()).To(Equal("STOPPING=1\nSTATUS=Draining connections\n"))
		})

		It("ignores watchdog keep-alives when the watchdog is disabled", func() {
			n.Watchdog()
			n.Status("sentinel")
			Expect(mgr.next()).To(Equal("STATUS=sentinel\n"))
		})

		It("is safe to close twice", func() {
			Expect(n.Close()).To(Succeed())
			Expect(n.Close()).To(Succeed())
			n.Status("after close") // must not panic
			Expect(n.Enabled()).To(BeFalse())
		})

		Describe("status sanitisation", func() {
			// SECURITY: status text is built from certificate subjects, which
			// are attacker-influenced. A raw newline would let the remainder be
			// parsed as further protocol assignments.
			It("folds newlines so protocol fields cannot be injected", func() {
				n.Status("evil.example.com\nREADY=1\nMAINPID=1")
				msg := mgr.next()
				Expect(msg).To(Equal("STATUS=evil.example.com READY=1 MAINPID=1\n"))
				Expect(strings.Count(msg, "\n")).To(Equal(1))
			})

			It("folds carriage returns and NUL bytes", func() {
				n.Status("a\rb\x00c")
				Expect(mgr.next()).To(Equal("STATUS=a b c\n"))
			})

			It("truncates an over-long status", func() {
				n.Status(strings.Repeat("x", 500))
				msg := mgr.next()
				Expect(msg).To(Equal("STATUS=" + strings.Repeat("x", 256) + "\n"))
			})
		})
	})

	Describe("watchdog configuration", func() {
		var mgr *fakeManager

		BeforeEach(func() {
			mgr = newFakeManager()
		})

		It("adopts the interval published in WATCHDOG_USEC", func() {
			setEnv("WATCHDOG_USEC", "30000000")
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(n.WatchdogInterval()).To(Equal(30 * time.Second))
			n.Watchdog()
			Expect(mgr.next()).To(Equal("WATCHDOG=1"))
		})

		It("keeps feeding the watchdog independently of WATCHDOG_PID", func() {
			// The frontend child, not the unit's main PID, is the process that
			// knows the CA is healthy, so the PID check is deliberately not
			// applied. See watchdogIntervalFromEnv.
			setEnv("WATCHDOG_USEC", "10000000")
			setEnv("WATCHDOG_PID", "1")
			n := sdnotify.New()
			DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

			Expect(n.WatchdogInterval()).To(Equal(10 * time.Second))
		})

		DescribeTable("rejects an unusable interval",
			func(value string) {
				setEnv("WATCHDOG_USEC", value)
				n := sdnotify.New()
				DeferCleanup(func() { Expect(n.Close()).To(Succeed()) })

				Expect(n.WatchdogInterval()).To(BeZero())
				n.Watchdog()
				n.Status("sentinel")
				Expect(mgr.next()).To(Equal("STATUS=sentinel\n"))
			},
			Entry("not a number", "soon"),
			Entry("zero", "0"),
			Entry("negative", "-1"),
			// Would overflow time.Duration's nanoseconds and wrap into a tiny
			// (or negative) interval, causing a keep-alive storm.
			Entry("beyond time.Duration's range", "18446744073709551615"),
		)
	})

	Describe("a nil Notifier", func() {
		It("behaves like a disabled one", func() {
			var n *sdnotify.Notifier
			Expect(n.Enabled()).To(BeFalse())
			Expect(n.WatchdogInterval()).To(BeZero())
			n.Ready("x")
			n.Status("x")
			n.Reloading("x")
			n.Stopping("x")
			n.Watchdog()
			Expect(n.Close()).To(Succeed())
		})
	})
})
