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

package api

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// csrRateLimitedWarnInterval is the least time between two Warn lines for
// refused CSR submissions. The caller decides how often a refusal happens, so
// each one cannot be a Warn; once a minute, the limiter's own window, is
// enough for an operator reading logs to see that refusals are going on.
const csrRateLimitedWarnInterval = time.Minute

// refuseCSRRateLimited answers a CSR submission that csr_rate_limit refused,
// and makes the refusal visible: to OnCSRRateLimited on every call, and in the
// log at Warn at most once per csrRateLimitedWarnInterval, at Debug otherwise.
// Nothing from the request body is logged, since it has not been read.
func (s *Server) refuseCSRRateLimited(w http.ResponseWriter, r *http.Request) {
	if s.OnCSRRateLimited != nil {
		s.OnCSRRateLimited()
	}
	if s.csrLimitedWarn.due(csrRateLimitedWarnInterval) {
		slog.Warn("CSR submission refused: client over csr_rate_limit "+
			"(further refusals in the next minute log at Debug)",
			"client_ip", clientIP(r), "csr_rate_limit_per_minute", s.CSRRateLimit)
	} else {
		slog.Debug("CSR submission refused: rate limit exceeded", "client_ip", clientIP(r))
	}
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
}

// logThrottle lets an event through at most once per interval. The zero value
// is ready to use and lets the first event through.
type logThrottle struct {
	mu   sync.Mutex
	next time.Time
	// now returns the current time. It defaults to time.Now and is overridden
	// in tests to move past the interval without sleeping.
	now func() time.Time
}

// due reports whether interval has passed since it last returned true, and if
// so starts a new interval.
func (t *logThrottle) due(interval time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.now != nil {
		now = t.now()
	}
	if now.Before(t.next) {
		return false
	}
	t.next = now.Add(interval)
	return true
}
