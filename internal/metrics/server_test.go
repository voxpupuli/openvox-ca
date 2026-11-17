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

package metrics_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/httpserver"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("Exporter.NewServer", func() {
	var exporter *metrics.Exporter

	BeforeEach(func() {
		exporter = metrics.NewExporter(
			ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test"), "frontend")
	})

	// Pinned as literals rather than read back from httpserver.Defaults, so a
	// change to the shared budget shows up here as a change to the metrics
	// listener too.
	DescribeTable("bounds every phase of a connection",
		func(field func(*http.Server) time.Duration, want time.Duration) {
			Expect(field(exporter.NewServer("127.0.0.1:0"))).To(Equal(want))
		},
		Entry("ReadHeaderTimeout", func(s *http.Server) time.Duration { return s.ReadHeaderTimeout }, 10*time.Second),
		Entry("ReadTimeout", func(s *http.Server) time.Duration { return s.ReadTimeout }, 30*time.Second),
		Entry("WriteTimeout", func(s *http.Server) time.Duration { return s.WriteTimeout }, 60*time.Second),
		Entry("IdleTimeout", func(s *http.Server) time.Duration { return s.IdleTimeout }, 120*time.Second),
	)

	// WriteTimeout runs through the handler, and the handler gathers before it
	// writes a byte, so a write budget at or below the gather budget would
	// truncate the very scrapes that most need reporting. Twice the gather
	// budget is the floor; NewServer's comment derives why 60s clears it.
	It("leaves the write budget at least twice the collector's gather budget", func() {
		Expect(exporter.NewServer("127.0.0.1:0").WriteTimeout).
			To(BeNumerically(">=", 2*metrics.DefaultGatherTimeout))
	})

	Context("when a client sends its headers and then stalls on the body", func() {
		const budget = 200 * time.Millisecond
		// window is how long both specs below watch the connection. Sharing it
		// is what makes the twin meaningful: it holds the connection open for
		// every moment at which the first spec would accept a close, so the
		// read budget is the only thing that can account for one.
		const window = 10 * budget
		// unrelated is the write and idle budget, kept far outside window so
		// neither deadline can coincide with what the specs observe.
		const unrelated = 30 * time.Second

		// stall serves the exporter with the given read budget, then sends a
		// request that promises a body it never finishes. It returns a channel
		// that closes when the server drops the connection, and what the server
		// had sent by then.
		stall := func(read time.Duration) (<-chan struct{}, *bytes.Buffer) {
			srv := exporter.NewServerWithTimeoutsForTest("", httpserver.Timeouts{
				ReadHeader: budget,
				Read:       read,
				Write:      unrelated,
				Idle:       unrelated,
			})
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			go func() {
				if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					GinkgoWriter.Printf("metrics server: %v\n", err)
				}
			}()
			DeferCleanup(srv.Close)

			conn, err := net.Dial("tcp", ln.Addr().String())
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(conn.Close)
			_, err = fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: metrics.test\r\nContent-Length: 1024\r\n\r\npartial")
			Expect(err).NotTo(HaveOccurred())

			// The handler answers without reading the body, and the server then
			// reads the rest of the body so it can reuse the connection. That
			// read is what stalls, and only the read budget ends it.
			var got bytes.Buffer
			closed := make(chan struct{})
			go func() {
				defer close(closed)
				_, _ = io.Copy(&got, conn)
			}()
			return closed, &got
		}

		It("disconnects it within the read budget", func() {
			closed, got := stall(budget)
			Eventually(closed).Within(window).Should(BeClosed())
			// The request was well formed and served: the disconnect is the
			// read budget expiring, not the server rejecting the request.
			Expect(got.String()).To(HavePrefix("HTTP/1.1 200 OK"))
		})

		// The twin: identical but for the read budget, which leaves only
		// ReadHeaderTimeout -- the state #452 reported. It proves the fixture
		// can still observe a stall across the whole window, so the spec above
		// cannot pass because the connection would have closed anyway.
		It("holds it open past the header budget when there is no read budget", func() {
			closed, _ := stall(0)
			Consistently(closed).WithTimeout(window).ShouldNot(BeClosed())
		})
	})
})
