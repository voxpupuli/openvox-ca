// Copyright (C) 2026 Trevor Vaughan
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

package api

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("destructiveOpTracker", func() {
	It("returns false when under threshold", func() {
		t := newDestructiveOpTracker(3, time.Minute)
		Expect(t.Record("admin")).To(BeFalse())
		Expect(t.Record("admin")).To(BeFalse())
		Expect(t.Record("admin")).To(BeFalse())
	})

	It("returns true when threshold is exceeded", func() {
		t := newDestructiveOpTracker(2, time.Minute)
		Expect(t.Record("admin")).To(BeFalse()) // count=1
		Expect(t.Record("admin")).To(BeFalse()) // count=2
		Expect(t.Record("admin")).To(BeTrue())  // count=3 > threshold
	})

	It("tracks identities independently", func() {
		t := newDestructiveOpTracker(1, time.Minute)
		Expect(t.Record("alice")).To(BeFalse()) // alice count=1
		Expect(t.Record("bob")).To(BeFalse())   // bob count=1
		Expect(t.Record("alice")).To(BeTrue())  // alice count=2 > threshold
		Expect(t.Record("bob")).To(BeTrue())    // bob count=2 > threshold
	})

	It("resets after the window expires", func() {
		// Drive the window with an injected clock so the reset is
		// deterministic, avoiding a scheduler-sensitive real sleep.
		clock := time.Now()
		t := newDestructiveOpTracker(1, 10*time.Millisecond)
		t.now = func() time.Time { return clock }

		Expect(t.Record("admin")).To(BeFalse())
		Expect(t.Record("admin")).To(BeTrue())

		clock = clock.Add(15 * time.Millisecond) // advance past the window
		Expect(t.Record("admin")).To(BeFalse())  // window reset
	})
})

var _ = Describe("ipRateLimiter", func() {
	var (
		clock time.Time
		l     *ipRateLimiter
	)

	// at moves the limiter's clock to offset past the start of the spec.
	at := func(offset time.Duration) {
		l.now = func() time.Time { return clock.Add(offset) }
	}

	BeforeEach(func() {
		clock = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		l = newIPRateLimiter("test", 2, time.Minute)
		at(0)
	})

	It("allows maxReqs per window and refuses the rest until it rolls over", func() {
		Expect(l.Allow("192.0.2.1")).To(BeTrue())
		Expect(l.Allow("192.0.2.1")).To(BeTrue())
		Expect(l.Allow("192.0.2.1")).To(BeFalse())
		at(time.Minute)
		Expect(l.Allow("192.0.2.1")).To(BeTrue())
	})

	Context("at its entry cap", func() {
		BeforeEach(func() { l.maxEntries = 2 })

		// The cap used to be advisory: a sweep that freed nothing was
		// followed by an insert anyway, so the map grew without bound and
		// every new address paid a full scan.
		It("refuses a new address while every tracked window is live, and does not grow", func() {
			Expect(l.Allow("192.0.2.1")).To(BeTrue())
			Expect(l.Allow("192.0.2.2")).To(BeTrue())

			Expect(l.Allow("192.0.2.3")).To(BeFalse())
			Expect(l.entries).To(HaveLen(2))
			Expect(l.entries).NotTo(HaveKey("192.0.2.3"))
		})

		It("still serves the addresses it is already tracking", func() {
			Expect(l.Allow("192.0.2.1")).To(BeTrue())
			Expect(l.Allow("192.0.2.2")).To(BeTrue())
			Expect(l.Allow("192.0.2.3")).To(BeFalse())

			Expect(l.Allow("192.0.2.1")).To(BeTrue(), "a tracked address keeps its own budget")
		})

		It("admits a new address once a sweep finds an expired window", func() {
			Expect(l.Allow("192.0.2.1")).To(BeTrue())
			at(time.Second)
			Expect(l.Allow("192.0.2.2")).To(BeTrue())

			at(time.Minute)
			Expect(l.Allow("192.0.2.3")).To(BeTrue(), "192.0.2.1's window has expired")
			Expect(l.entries).To(HaveLen(2))
		})

		// Saturation refuses clients that have done nothing wrong, so it is
		// the one refusal that is logged, once per sweep that frees nothing.
		Context("logging saturation", func() {
			var logs *bytes.Buffer

			BeforeEach(func() {
				logs = new(bytes.Buffer)
				orig := slog.Default()
				slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
				DeferCleanup(func() { slog.SetDefault(orig) })
			})

			warnings := func() int { return strings.Count(logs.String(), "Per-IP rate limiter is full") }

			It("warns once when a sweep frees nothing, and not again before the next sweep", func() {
				Expect(l.Allow("192.0.2.1")).To(BeTrue())
				Expect(l.Allow("192.0.2.2")).To(BeTrue())

				Expect(l.Allow("192.0.2.3")).To(BeFalse())
				Expect(warnings()).To(Equal(1))
				Expect(logs.String()).To(ContainSubstring("limiter=test"))

				Expect(l.Allow("192.0.2.4")).To(BeFalse(), "no sweep due, so no second scan")
				Expect(warnings()).To(Equal(1))

				// Still saturated at the next sweep, so it says so again: a
				// saturation lasting hours is not one line at its start.
				at(6 * time.Second)
				Expect(l.Allow("192.0.2.5")).To(BeFalse())
				Expect(warnings()).To(Equal(2))
			})

			It("does not warn when a sweep finds room", func() {
				Expect(l.Allow("192.0.2.1")).To(BeTrue())
				at(time.Second)
				Expect(l.Allow("192.0.2.2")).To(BeTrue())

				at(time.Minute)
				Expect(l.Allow("192.0.2.3")).To(BeTrue())
				Expect(warnings()).To(BeZero())
			})
		})

		// A tracked address whose window has expired is renewed in place: it
		// does not grow the map, so the cap does not apply to it, and it does
		// not have to wait for a sweep that is not yet due.
		It("renews a tracked address whose window has expired, without waiting for a sweep", func() {
			Expect(l.Allow("192.0.2.1")).To(BeTrue())
			at(time.Second)
			Expect(l.Allow("192.0.2.2")).To(BeTrue())

			at(time.Minute) // 192.0.2.1 expired; a new address sweeps and arms nextSweep
			Expect(l.Allow("192.0.2.3")).To(BeTrue())

			at(time.Minute + 2*time.Second) // 192.0.2.2 expired; no sweep due for 4s
			Expect(l.Allow("192.0.2.2")).To(BeTrue(), "a returning client is not a new one")
			Expect(l.entries).To(HaveLen(2))
		})

		// A sweep is a scan of the whole map under the mutex every request
		// waits on, so a full map is swept at most once per tenth of a window.
		// The cost is that an address expiring between sweeps is not
		// reclaimed until the next one.
		It("sweeps a full map at most once per tenth of a window", func() {
			Expect(l.Allow("192.0.2.1")).To(BeTrue())
			at(time.Second)
			Expect(l.Allow("192.0.2.2")).To(BeTrue())

			at(time.Minute) // sweeps, freeing 192.0.2.1
			Expect(l.Allow("192.0.2.3")).To(BeTrue())

			at(time.Minute + time.Second) // 192.0.2.2 has expired, but no sweep is due
			Expect(l.Allow("192.0.2.4")).To(BeFalse())

			at(time.Minute + 6*time.Second) // a tenth of a window since the last sweep
			Expect(l.Allow("192.0.2.4")).To(BeTrue())
		})
	})
})

var _ = DescribeTable("rateLimitKey",
	func(remoteAddr string, prefixLen int, want string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remoteAddr
		Expect(rateLimitKey(r, prefixLen)).To(Equal(want))
	},
	Entry("IPv4 is per address", "192.0.2.10:1234", 64, "192.0.2.10"),
	Entry("IPv6 at 128 is per address", "[2001:db8:1:2::10]:1234", 128, "2001:db8:1:2::10"),
	Entry("IPv6 at the zero value is per address", "[2001:db8:1:2::10]:1234", 0, "2001:db8:1:2::10"),
	Entry("IPv6 at 64 is its /64", "[2001:db8:1:2::10]:1234", 64, "2001:db8:1:2::/64"),
	Entry("IPv6 at 48 is its /48", "[2001:db8:1:2::10]:1234", 48, "2001:db8:1::/48"),
	// An IPv4 client reaching a dual-stack socket arrives mapped. It must
	// count as the IPv4 address, not as one of 2^32 addresses in ::ffff:0:0/96
	// that a short prefix would put in one budget.
	Entry("IPv4-mapped IPv6 counts as IPv4", "[::ffff:192.0.2.10]:1234", 64, "192.0.2.10"),
	Entry("a zone is dropped", "[fe80::1%eth0]:1234", 128, "fe80::1"),
	Entry("an unparsable peer is used as it stands", "pipe", 64, "pipe"),
)

// The saturation warning names the limiter, and that name is the only thing
// in it telling an operator which endpoint is refusing new clients.
var _ = Describe("the limiters Routes builds", func() {
	It("names each for the endpoint it guards", func() {
		s := New(nil)
		s.CSRRateLimit = 5
		s.OCSPEnabled = true
		s.OCSPRateLimit = 5
		s.Routes()
		Expect(s.csrLimiter.name).To(Equal("csr"))
		Expect(s.ocspLimiter.name).To(Equal("ocsp"))
	})
})
