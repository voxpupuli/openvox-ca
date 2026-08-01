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

// Package sdnotify implements the service-manager notification protocol
// described in sd_notify(3), so openvox-ca can run as a systemd `Type=notify`
// (or `Type=notify-reload`) service.
//
// The protocol is deliberately simple: the service manager passes the path of
// a datagram socket in $NOTIFY_SOCKET, and the service sends newline-separated
// `KEY=value` assignments to it. Nothing is read back, and a lost datagram
// only means a lost status update — so every failure here is logged and
// swallowed rather than propagated. A Notifier constructed without
// $NOTIFY_SOCKET in the environment is inert: every method is a no-op, which
// is the normal case when running in a container, under another supervisor, or
// from a shell.
//
// Notifications are sent from whichever process actually knows the state being
// reported, which in openvox-ca's isolated-process topology (launcher →
// signer + frontend children) is not always the unit's main PID. Units must
// therefore set `NotifyAccess=all`; see docs/systemd.md.
package sdnotify

import (
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// maxStatusLen bounds the STATUS= text. systemd shows the status in
// `systemctl status` output and in `systemctl show -p StatusText`; anything
// longer than a terminal line is noise, and the cap also bounds what an
// attacker-influenced certificate subject can push into the journal.
const maxStatusLen = 256

// Notifier sends state notifications to the service manager over the socket
// named by $NOTIFY_SOCKET. The zero value and a nil *Notifier are both valid
// and inert, so callers never need to guard their calls.
type Notifier struct {
	// mu guards conn, and is held for every read of it (Enabled, send) as well
	// as the write in Close. Datagram writes are atomic per message, but the
	// heartbeat goroutine and the shutdown path notify concurrently while a
	// deferred Close can land at any time, so both sides of that race have to
	// take the lock.
	mu   sync.Mutex
	conn *net.UnixConn

	// watchdog is the WatchdogSec= interval the service manager expects to be
	// fed within, or zero when the watchdog is disabled.
	watchdog time.Duration
}

// New returns a Notifier for the current environment. When $NOTIFY_SOCKET is
// unset — or names a socket that cannot be reached — the returned Notifier is
// inert; the error is logged and never returned, because the inability to talk
// to a service manager must not stop the CA from serving.
//
// The connection is established once and held for the process lifetime rather
// than dialled per message, so the periodic watchdog keep-alive does not churn
// a socket every few seconds.
func New() *Notifier {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return &Notifier{}
	}

	// A leading '@' selects the abstract namespace, which is spelled with a
	// leading NUL byte in sun_path; the socket is otherwise a filesystem path
	// (typically /run/systemd/notify). Go's syscall layer happens to accept
	// either spelling, so this is belt and braces — but sd_notify(3) states the
	// translation as the service's job, and relying on a convenience of the
	// standard library for a protocol requirement is how it breaks quietly.
	if strings.HasPrefix(addr, "@") {
		addr = "\x00" + addr[1:]
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		// Warn, not Debug: $NOTIFY_SOCKET being set means a service manager is
		// expecting notifications, so failing to reach it is a real problem —
		// the unit will sit there until TimeoutStartSec with no READY=1. This
		// runs before the configured logger is installed, so a lower level
		// could not be turned up by the operator even with --verbosity.
		slog.Warn("Service manager notifications disabled: cannot connect to NOTIFY_SOCKET",
			"socket", os.Getenv("NOTIFY_SOCKET"), "error", err)
		return &Notifier{}
	}

	n := &Notifier{conn: conn}
	n.watchdog = watchdogIntervalFromEnv()
	return n
}

// Enabled reports whether notifications are actually going anywhere, i.e.
// whether the process was started by a service manager that asked to be
// notified.
//
// It takes the lock: Close can run concurrently with the heartbeat and reload
// goroutines (neither is joined before the deferred Close in the frontend), so
// reading conn unsynchronised would be a data race even though the value it
// races with is only ever nil.
func (n *Notifier) Enabled() bool {
	if n == nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.conn != nil
}

// WatchdogInterval returns the WatchdogSec= interval configured for the unit,
// or zero when the service manager has not enabled the watchdog. Callers
// should send Watchdog() keep-alives at least twice per interval, as
// recommended by sd_watchdog_enabled(3).
func (n *Notifier) WatchdogInterval() time.Duration {
	if n == nil {
		return 0
	}
	return n.watchdog
}

// Ready reports that startup is complete and the service is serving. status,
// when non-empty, is also published as the unit's status text.
func (n *Notifier) Ready(status string) {
	n.send(assignments("READY=1", statusLine(status)))
}

// Status updates the unit's status text without changing its state. It is safe
// (and useful) to call repeatedly: `systemctl status` shows the most recent
// text, which is the cheapest way for an operator to see what a long startup
// is waiting on.
func (n *Notifier) Status(status string) {
	if status == "" {
		return
	}
	n.send(assignments(statusLine(status)))
}

// Reloading reports that the service has begun reloading its configuration.
// The caller must follow it with Ready once the reload has finished.
//
// MONOTONIC_USEC is included because `Type=notify-reload` requires it: the
// service manager compares it against the time it sent SIGHUP to distinguish
// this reload from a stale notification. It is omitted on platforms where the
// monotonic clock is unavailable, which downgrades cleanly to `Type=notify`
// behaviour.
func (n *Notifier) Reloading(status string) {
	fields := []string{"RELOADING=1"}
	if usec, ok := monotonicUsec(); ok {
		fields = append(fields, "MONOTONIC_USEC="+strconv.FormatUint(usec, 10))
	}
	fields = append(fields, statusLine(status))
	n.send(assignments(fields...))
}

// Stopping reports that the service has begun shutting down, so the service
// manager can distinguish a graceful drain from an unexpected exit.
func (n *Notifier) Stopping(status string) {
	n.send(assignments("STOPPING=1", statusLine(status)))
}

// Watchdog sends a keep-alive, resetting the service manager's watchdog timer.
// It is a no-op when the watchdog is not enabled for the unit.
func (n *Notifier) Watchdog() {
	if n.WatchdogInterval() == 0 {
		return
	}
	n.send(assignments("WATCHDOG=1"))
}

// Close releases the notification socket. Further calls are no-ops.
func (n *Notifier) Close() error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn == nil {
		return nil
	}
	err := n.conn.Close()
	n.conn = nil
	return err
}

// send writes one notification datagram. Errors are logged at debug level and
// dropped: a service manager that has gone away, or a full socket buffer, is
// not a reason to disturb the CA.
func (n *Notifier) send(msg string) {
	if n == nil || msg == "" {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn == nil { // never connected, or closed while this call was queued
		return
	}
	if _, err := n.conn.Write([]byte(msg)); err != nil {
		slog.Debug("Failed to notify the service manager", "error", err)
	}
}

// assignments joins non-empty protocol assignments into a single datagram.
// sd_notify(3) requires them newline-separated; a trailing newline is
// permitted and keeps the payload readable in packet captures.
func assignments(fields ...string) string {
	kept := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			kept = append(kept, f)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "\n") + "\n"
}

// statusLine renders a STATUS= assignment, or "" for empty status.
//
// SECURITY: the status text is built from runtime state that includes
// certificate subjects, which are attacker-influenced. A newline in the value
// would terminate the assignment and let the remainder be parsed as further
// protocol fields — for example injecting READY=1 or MAINPID=. Every control
// character is therefore folded to a space before the value is sent, and the
// result is truncated to maxStatusLen. The fold is deliberately wider than the
// protocol needs: only the newline can break framing, but the status text is
// relayed to a terminal by `systemctl status`, so escape sequences are stripped
// too rather than left for the journal to pass through.
// NIST 800-53: SI-10 (Information Input Validation)
func statusLine(status string) string {
	if status == "" {
		return ""
	}
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, status)
	if len(clean) > maxStatusLen {
		// Trim to a rune boundary so a multi-byte character is never split.
		clean = strings.ToValidUTF8(clean[:maxStatusLen], "")
	}
	return "STATUS=" + clean
}

// watchdogIntervalFromEnv reads the WatchdogSec= interval the service manager
// published in $WATCHDOG_USEC.
//
// Unlike sd_watchdog_enabled(3) this deliberately ignores $WATCHDOG_PID. That
// variable names the unit's main PID, but in openvox-ca's isolated-process
// topology the process that knows whether the CA is actually healthy is the
// frontend child, not the launcher (see cmd/openvox-ca/launcher.go). Units
// already need NotifyAccess=all for that child to notify at all, so honouring
// the PID check here would only disable the watchdog in exactly the
// configuration it is most useful for.
func watchdogIntervalFromEnv() time.Duration {
	raw := os.Getenv("WATCHDOG_USEC")
	if raw == "" {
		return 0
	}
	usec, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || usec == 0 {
		slog.Debug("Ignoring unusable WATCHDOG_USEC", "value", raw, "error", err)
		return 0
	}
	// Guard the multiplication: a bogus value near 2^64 would otherwise wrap
	// into a small or negative interval and cause a keep-alive storm.
	const maxUsec = uint64(1<<63-1) / uint64(time.Microsecond)
	if usec > maxUsec {
		slog.Debug("Ignoring out-of-range WATCHDOG_USEC", "value", raw)
		return 0
	}
	return time.Duration(usec) * time.Microsecond
}
