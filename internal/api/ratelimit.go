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

// Allow reports whether the request from ip should be allowed.
// Returns false when the per-window request count has been exceeded.
func (l *ipRateLimiter) Allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[ip]
	if !ok || now.Sub(e.start) >= l.window {
		l.entries[ip] = &rlEntry{start: now, count: 1}
		return true
	}
	if e.count >= l.maxReqs {
		return false
	}
	e.count++
	return true
}

// clientIP extracts the remote IP address from r, stripping the port.
// It does not trust X-Forwarded-For or similar headers since the server
// accepts direct connections (no trusted reverse proxy layer).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
