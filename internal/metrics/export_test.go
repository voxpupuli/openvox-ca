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

package metrics

import (
	"net/http"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/httpserver"
)

// In an _test.go file so these are compiled only for tests and never become
// part of the shipped API.

// DefaultGatherTimeout exposes the collector's gather budget, which the
// metrics listener's write budget has to outlast.
const DefaultGatherTimeout = defaultGatherTimeout

// NewServerWithTimeoutsForTest exposes newServer, so a spec can drive the
// listener's timeouts in milliseconds rather than waiting out the real ones.
func (e *Exporter) NewServerWithTimeoutsForTest(addr string, timeouts httpserver.Timeouts) *http.Server {
	return e.newServer(addr, timeouts)
}

// StaleSnapshotLimit exposes how long a failed gather republishes the last
// successful one.
const StaleSnapshotLimit = staleSnapshotLimit

// SetClockForTest replaces the collector's clock, so a spec can age the last
// successful gather past StaleSnapshotLimit without waiting an hour.
func (c *Collector) SetClockForTest(now func() time.Time) {
	c.now = now
}
