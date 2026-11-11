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
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// ipRateLimiter is a fixed-window per-IP rate limiter.
// Each IP address is allowed at most maxReqs requests per window duration.
//
// Memory is bounded by maxEntries tracked addresses. Expired windows are
// swept only when the map is full, and then no more than once per tenth of a
// window, so a flood of new addresses costs one map scan per sweep interval
// rather than one per request. A new address that arrives while the map is
// full is refused, as if it were over its limit, unless a sweep is due and
// frees room; between sweeps that holds even for windows that have expired
// since the last one. Past the cap the choice is between refusing new clients
// and not limiting them, and on an endpoint this protects the second is the
// flood winning.
//
// SECURITY: Applied, as two separate limiters, to the unauthenticated
// PUT /certificate_request endpoint to prevent CSR flooding, and to the OCSP
// responder, where a nonced request costs a CA-key signature.
// NIST 800-53: SC-5 (Denial-of-Service Protection)
type ipRateLimiter struct {
	mu sync.Mutex
	// name identifies the limiter in its saturation warning.
	name       string
	window     time.Duration
	maxReqs    int
	maxEntries int
	entries    map[string]*rlEntry
	// nextSweep is the earliest time a full map may be swept again.
	nextSweep time.Time
	// now returns the current time. It defaults to time.Now and is overridden
	// in tests to drive window expiry deterministically without sleeping.
	now func() time.Time
}

type rlEntry struct {
	start time.Time
	count int
}

func newIPRateLimiter(name string, maxReqs int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		name:       name,
		window:     window,
		maxReqs:    maxReqs,
		maxEntries: maxRateLimitEntries,
		entries:    make(map[string]*rlEntry),
		now:        time.Now,
	}
}

// maxRateLimitEntries caps the number of tracked IPs to prevent unbounded
// memory growth under a distributed attack with many unique source IPs.
const maxRateLimitEntries = 100_000

// Allow reports whether the request from ip should be allowed.
// Returns false when the per-window request count has been exceeded, or when
// ip is not tracked, the limiter is already tracking maxEntries addresses, and
// either no sweep is due (at most window/10 since the last) or the sweep frees
// nothing.
//
// A sweep that frees nothing logs a warning: from then on every new client is
// refused, though none has exceeded its own budget, and nothing else on the
// server says so. Sweeps are rationed, so the warning is too. It is written
// after the mutex is released, since every request waits on it.
func (l *ipRateLimiter) Allow(ip string) bool {
	now := l.now()
	var saturated bool
	defer func() {
		if saturated {
			slog.Warn("Per-IP rate limiter is full; refusing every new client address until windows expire",
				"limiter", l.name, "tracked", l.maxEntries, "window", l.window)
		}
	}()
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[ip]
	if ok && now.Sub(e.start) < l.window {
		if e.count >= l.maxReqs {
			return false
		}
		e.count++
		return true
	}
	if !ok && len(l.entries) >= l.maxEntries {
		if !now.Before(l.nextSweep) {
			l.evictExpired(now)
			l.nextSweep = now.Add(l.window / 10)
			saturated = len(l.entries) >= l.maxEntries
		}
		if len(l.entries) >= l.maxEntries {
			return false
		}
	}
	l.entries[ip] = &rlEntry{start: now, count: 1}
	return true
}

// evictExpired removes all entries whose window has elapsed. Must be called
// with l.mu held.
func (l *ipRateLimiter) evictExpired(now time.Time) {
	for ip, e := range l.entries {
		if now.Sub(e.start) >= l.window {
			delete(l.entries, ip)
		}
	}
}

// clientIP extracts the remote IP address from r, stripping the port.
// It does not trust X-Forwarded-For or similar headers since the server
// accepts direct connections (no trusted reverse proxy layer). Behind a proxy
// that does not preserve the client's address, every client therefore shares
// the proxy's budget.
// NIST 800-53: SC-5 (Denial-of-Service Protection)
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimitKey is what the per-IP limiters count r under: the client's IPv4
// address, or its IPv6 address masked to prefixLen bits, so that one host
// holding a routed prefix cannot claim a fresh budget per source address. An
// IPv4-mapped IPv6 address counts as the IPv4 address it carries, and a zone
// is dropped. A prefixLen outside 1-127 keys on the whole address, which is
// the default. A peer address that does not parse is used as it stands.
// NIST 800-53: SC-5 (Denial-of-Service Protection)
func rateLimitKey(r *http.Request, prefixLen int) string {
	host := clientIP(r)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() || prefixLen <= 0 || prefixLen >= 128 {
		return addr.String()
	}
	return netip.PrefixFrom(addr, prefixLen).Masked().String()
}

// destructiveOpTracker is a fixed-window per-identity counter for destructive
// operations (revoke, clean). When a single identity exceeds the threshold
// within the window, a warning is logged for operational awareness.
// NIST 800-53: AU-6 (Audit Record Review, Analysis, and Reporting)
type destructiveOpTracker struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	entries   map[string]*rlEntry
	// now returns the current time. It defaults to time.Now and is overridden
	// in tests to drive window expiry deterministically without sleeping.
	now func() time.Time
}

func newDestructiveOpTracker(threshold int, window time.Duration) *destructiveOpTracker {
	return &destructiveOpTracker{
		window:    window,
		threshold: threshold,
		entries:   make(map[string]*rlEntry),
		now:       time.Now,
	}
}

// Record increments the counter for the given identity (typically a client CN)
// and returns true if the threshold has been exceeded.
func (t *destructiveOpTracker) Record(identity string) bool {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[identity]
	if !ok || now.Sub(e.start) >= t.window {
		t.entries[identity] = &rlEntry{start: now, count: 1}
		return false
	}
	e.count++
	return e.count > t.threshold
}
