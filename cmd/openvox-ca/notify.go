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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
)

// defaultStatusRefresh is how often the service manager's status text is
// refreshed when the unit has no watchdog configured. The text embeds
// countdowns ("expires in 12d"), so it has to be re-sent to stay true; a
// minute is frequent enough for an operator reading `systemctl status` and
// costs one datagram.
const defaultStatusRefresh = time.Minute

// minHeartbeat floors the derived heartbeat interval. A pathologically short
// WatchdogSec= would otherwise have the CA spinning on a ticker.
const minHeartbeat = time.Second

// statusReport is the state summarised into the service manager's status text.
// It is captured as plain values so the rendering below is a pure function of
// the snapshot and the current time — the CA is read once, under its own
// locks, by newStatusReport.
type statusReport struct {
	addr    string // the API listener's address
	tls     bool   // whether the API listener speaks HTTPS
	caCN    string // CA certificate common name; empty if the CA is not loaded
	caUntil time.Time
	crl     ca.CRLSnapshot
	crlOK   bool // whether the CA has a CRL in memory at all
}

// newStatusReport samples the CA's live state. Everything it reads is held in
// memory by the CA (the certificate it loaded at startup and its cached CRL),
// so this is cheap enough to call on a timer. Counting certificates
// deliberately does not appear here: that means listing the inventory in the
// storage backend, which is a scrape-weight operation and not something to do
// every heartbeat.
func newStatusReport(c *ca.CA, addr string, tlsEnabled bool) statusReport {
	r := statusReport{addr: addr, tls: tlsEnabled}
	if cert := c.CACert; cert != nil {
		r.caCN = cert.Subject.CommonName
		r.caUntil = cert.NotAfter
	}
	r.crl, r.crlOK = c.CRLSnapshot()
	return r
}

// line renders the report as a single-line status suitable for `systemctl
// status`. It leads with what the service is doing, then the two pieces of
// state that silently stop a CA from being useful: an expiring CA certificate
// and a lapsing CRL.
func (r statusReport) line(now time.Time) string {
	scheme := "HTTP"
	if r.tls {
		scheme = "HTTPS"
	}
	parts := []string{fmt.Sprintf("Serving %s on %s", scheme, r.addr)}

	if r.caCN != "" {
		// Quoted because a Puppet CA's common name conventionally contains a
		// colon ("Puppet CA: puppet.example.com"), which otherwise runs into
		// the phrase that follows it.
		parts = append(parts, fmt.Sprintf("CA %q %s", r.caCN, deadlinePhrase(r.caUntil, now)))
	}

	switch {
	case !r.crlOK:
		parts = append(parts, "CRL not loaded")
	default:
		crl := "CRL"
		if r.crl.Number != nil {
			crl += " #" + r.crl.Number.String()
		}
		parts = append(parts, fmt.Sprintf("%s (%d revoked) %s",
			crl, r.crl.Revoked, deadlinePhrase(r.crl.NextUpdate, now)))
	}

	return strings.Join(parts, " | ")
}

// deadlinePhrase renders how long is left until deadline, or how long ago it
// passed. An elapsed deadline is spelled in capitals so it stands out in
// `systemctl status` output, which is the point of putting it there at all.
func deadlinePhrase(deadline, now time.Time) string {
	if deadline.IsZero() {
		return "expiry unknown"
	}
	if remaining := deadline.Sub(now); remaining > 0 {
		return "expires in " + humanDuration(remaining)
	}
	return "EXPIRED " + humanDuration(now.Sub(deadline)) + " ago"
}

// humanDuration renders d at a single, coarse unit. Status text is read at a
// glance, so "42d" is more useful than a precise but unreadable breakdown.
func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int64(d/(24*time.Hour)))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int64(d/time.Minute))
	default:
		return fmt.Sprintf("%ds", int64(d/time.Second))
	}
}

// heartbeatInterval derives how often to feed the watchdog and refresh the
// status text. sd_watchdog_enabled(3) advises notifying at least twice per
// WatchdogSec= interval, so half of it leaves a full interval of slack for a
// momentarily busy process before the service manager declares the CA hung.
func heartbeatInterval(n *sdnotify.Notifier) time.Duration {
	watchdog := n.WatchdogInterval()
	if watchdog <= 0 {
		return defaultStatusRefresh
	}
	if half := watchdog / 2; half > minHeartbeat {
		return half
	}
	return minHeartbeat
}

// runNotifyHeartbeat keeps the service manager's view of the CA current: it
// feeds the watchdog (when the unit enables one) and re-publishes the status
// text so its countdowns do not go stale. It returns when ctx is cancelled.
//
// The keep-alive is deliberately sent from the process that serves the API
// rather than the launcher, so a frontend wedged on a stuck backend stops
// feeding the watchdog and gets restarted — which is the failure the watchdog
// exists to catch. A launcher-side ping would only prove the supervisor is
// alive, which it always is.
func runNotifyHeartbeat(ctx context.Context, n *sdnotify.Notifier, interval time.Duration, status func() string) {
	if !n.Enabled() {
		return
	}
	slog.Debug("Starting service manager heartbeat",
		"interval", interval, "watchdog", n.WatchdogInterval())

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.Watchdog()
			n.Status(status())
		}
	}
}
