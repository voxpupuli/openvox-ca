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
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("newAPIServer", func() {
	// timeouts reads the four connection timeouts off a server, so the two
	// listeners can be compared whole.
	timeouts := func(s *http.Server) [4]time.Duration {
		return [4]time.Duration{s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout}
	}

	It("caps request headers at 1 MiB", func() {
		Expect(newAPIServer("127.0.0.1:0", http.NotFoundHandler()).MaxHeaderBytes).To(Equal(1 << 20))
	})

	// The metrics listener's comment claims it mirrors this one. Comparing the
	// built servers, not the shared definition, catches either side being given
	// its own literals -- including a change that moves one listener and its
	// own spec together, which two separate literal pins would both accept.
	//
	// It is also what pins this server's values: the metrics listener's specs
	// hold the literals, and this one holds the API server to them.
	It("uses the same timeouts as the metrics listener", func() {
		exporter := metrics.NewExporter(
			ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test"), roleFrontend)
		Expect(timeouts(exporter.NewServer("127.0.0.1:0"))).
			To(Equal(timeouts(newAPIServer("127.0.0.1:0", http.NotFoundHandler()))))
	})
})
