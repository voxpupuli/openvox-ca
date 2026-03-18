// Copyright (C) 2026 Trevor Vaughan
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
	"net"
	"net/http"
	"sync"
	"time"
)

// ipRateLimiter is a fixed-window per-IP rate limiter.
// Each IP address is allowed at most maxReqs requests per window duration.
// Old windows are evicted lazily on access so memory stays bounded over time.
//
// SECURITY: Applied to the unauthenticated PUT /certificate_request endpoint
// to prevent CSR flooding attacks.
// NIST 800-53: SC-5 (Denial-of-Service Protection)
type ipRateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	maxReqs int
	entries map[string]*rlEntry
}

type rlEntry struct {
	start time.Time
	count int
}

func newIPRateLimiter(maxReqs int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		window:  window,
		maxReqs: maxReqs,
		entries: make(map[string]*rlEntry),
	}
}

// maxRateLimitEntries caps the number of tracked IPs to prevent unbounded
// memory growth under a distributed attack with many unique source IPs.
const maxRateLimitEntries = 100_000

// Allow reports whether the request from ip should be allowed.
// Returns false when the per-window request count has been exceeded.
func (l *ipRateLimiter) Allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[ip]
	if !ok || now.Sub(e.start) >= l.window {
		// Evict stale entries periodically to bound memory usage.
		if len(l.entries) >= maxRateLimitEntries {
			l.evictExpired(now)
		}
		l.entries[ip] = &rlEntry{start: now, count: 1}
		return true
	}
	if e.count >= l.maxReqs {
		return false
	}
	e.count++
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
// accepts direct connections (no trusted reverse proxy layer).
// NIST 800-53: SC-5 (Denial-of-Service Protection)
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
}

func newDestructiveOpTracker(threshold int, window time.Duration) *destructiveOpTracker {
	return &destructiveOpTracker{
		window:    window,
		threshold: threshold,
		entries:   make(map[string]*rlEntry),
	}
}

// Record increments the counter for the given identity (typically a client CN)
// and returns true if the threshold has been exceeded.
func (t *destructiveOpTracker) Record(identity string) bool {
	now := time.Now()
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
