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

package api_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// A CSR submission over csr_rate_limit is answered 429. The refusal has to be
// visible on the CA side as well, or an operator cannot tell "the CA is
// refusing" from "the agents are broken": OnCSRRateLimited reports each one,
// and a Warn, rationed to once a minute, reaches deployments that read logs.
var _ = Describe("CSR rate limit reporting", func() {
	const refusedMsg = "CSR submission refused: client over csr_rate_limit"

	var (
		srv     *api.Server
		limited int
		clock   time.Time
		logBuf  *bytes.Buffer
		handler http.Handler
		csrPEM  []byte
	)

	BeforeEach(func() {
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		var err error
		csrPEM, err = testutil.GenerateCSR("limited-node")
		Expect(err).NotTo(HaveOccurred())

		limited = 0
		srv = api.New(myCA)
		srv.OnCSRRateLimited = func() { limited++ }
		clock = time.Now()
		api.SetCSRRateLimitedWarnClockForTest(srv, func() time.Time { return clock })

		// Last, after the fixture, so that only the requests under test
		// reach the buffer.
		logBuf = &bytes.Buffer{}
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	JustBeforeEach(func() { handler = srv.Routes() })

	put := func(subject, addr string) int {
		req := httptest.NewRequest("PUT", "/puppet-ca/v1/certificate_request/"+subject, bytes.NewReader(csrPEM))
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// warnLines returns the Warn records for a refused submission.
	warnLines := func() []string {
		var lines []string
		for line := range strings.SplitSeq(logBuf.String(), "\n") {
			if strings.Contains(line, "level=WARN") && strings.Contains(line, refusedMsg) {
				lines = append(lines, line)
			}
		}
		return lines
	}

	Context("with a limit of two per minute", func() {
		BeforeEach(func() { srv.CSRRateLimit = 2 })

		It("reports each refused submission once, and no allowed one", func() {
			Expect(put("limited-node", "192.0.2.1:1000")).NotTo(Equal(http.StatusTooManyRequests))
			Expect(put("limited-node", "192.0.2.1:1001")).NotTo(Equal(http.StatusTooManyRequests))
			Expect(limited).To(BeZero(), "a submission the limiter allowed is not a refusal")

			Expect(put("limited-node", "192.0.2.1:1002")).To(Equal(http.StatusTooManyRequests))
			Expect(limited).To(Equal(1))
			Expect(put("limited-node", "192.0.2.1:1003")).To(Equal(http.StatusTooManyRequests))
			Expect(limited).To(Equal(2))
		})
	})

	Context("with a limit of one per minute", func() {
		BeforeEach(func() { srv.CSRRateLimit = 1 })

		// allow spends addr's one submission in this minute, so that its
		// next is refused. The limiter keeps real time, so a client refused
		// once stays refused however far the Warn's clock is moved.
		allow := func(addr string) {
			GinkgoHelper()
			Expect(put("limited-node", addr)).NotTo(Equal(http.StatusTooManyRequests),
				"precondition: the first submission from %s is within the limit", addr)
		}
		refuse := func(addr string) {
			GinkgoHelper()
			Expect(put("limited-node", addr)).To(Equal(http.StatusTooManyRequests))
		}
		debugLines := func() int {
			return strings.Count(logBuf.String(), `level=DEBUG msg="CSR submission refused: rate limit exceeded"`)
		}

		It("does not warn about an allowed submission", func() {
			allow("192.0.2.1:1000")
			Expect(warnLines()).To(BeEmpty())
		})

		It("names the refused client and the limit in the Warn", func() {
			allow("192.0.2.1:1000")
			refuse("192.0.2.1:1000")
			Expect(warnLines()).To(ConsistOf(SatisfyAll(
				ContainSubstring("client_ip=192.0.2.1"),
				ContainSubstring("csr_rate_limit_per_minute=1"),
			)))
		})

		It("logs the refusals between Warns at Debug", func() {
			allow("192.0.2.1:1000")
			for range 3 {
				refuse("192.0.2.1:1000")
			}
			Expect(warnLines()).To(HaveLen(1))
			Expect(debugLines()).To(Equal(2))
		})

		It("logs nothing from the request body", func() {
			allow("192.0.2.1:1000")
			refuse("192.0.2.1:1000")
			refuse("192.0.2.1:1000")
			Expect(debugLines()).To(Equal(1), "precondition: both the Warn and the Debug line were written")
			Expect(logBuf.String()).NotTo(ContainSubstring("CERTIFICATE REQUEST"))
		})

		// One throttle per process, not per client: otherwise a flood from
		// rotating addresses would write a Warn for each. Each step moves
		// one thing, so neither a per-client throttle nor a shorter
		// interval can pass.
		It("warns at most once a minute across all clients", func() {
			allow("192.0.2.1:1000")
			refuse("192.0.2.1:1000")
			Expect(warnLines()).To(HaveLen(1))

			allow("192.0.2.2:1000")
			refuse("192.0.2.2:1000")
			Expect(warnLines()).To(HaveLen(1), "another client refused inside the minute does not warn")

			clock = clock.Add(time.Minute - time.Second)
			refuse("192.0.2.1:1000")
			Expect(warnLines()).To(HaveLen(1), "59 seconds later is still inside the minute")

			clock = clock.Add(time.Second)
			refuse("192.0.2.2:1000")
			Expect(warnLines()).To(HaveLen(2), "refusals still going on a minute later warn again")
			Expect(warnLines()[1]).To(ContainSubstring("client_ip=192.0.2.2"))
		})

		// Refusals arrive together during exactly the flood the throttle is
		// for. Under -race this also pins the throttle's lock.
		It("warns once and reports every refusal when they arrive concurrently", func() {
			var reported atomic.Int64
			srv.OnCSRRateLimited = func() { reported.Add(1) }
			allow("192.0.2.1:1000")

			const n = 20
			codes := make(chan int, n)
			var wg sync.WaitGroup
			for range n {
				wg.Go(func() { codes <- put("limited-node", "192.0.2.1:1000") })
			}
			wg.Wait()
			close(codes)

			for code := range codes {
				Expect(code).To(Equal(http.StatusTooManyRequests))
			}
			Expect(reported.Load()).To(Equal(int64(n)))
			Expect(warnLines()).To(HaveLen(1))
		})
	})

	// The default deployment shape without a metrics listener: no hook, and
	// the refusal must not depend on one.
	Context("with no OnCSRRateLimited hook", func() {
		BeforeEach(func() {
			srv.CSRRateLimit = 1
			srv.OnCSRRateLimited = nil
		})

		It("still refuses the excess with 429 and warns", func() {
			Expect(put("limited-node", "192.0.2.1:1000")).NotTo(Equal(http.StatusTooManyRequests))
			Expect(put("limited-node", "192.0.2.1:1000")).To(Equal(http.StatusTooManyRequests))
			Expect(warnLines()).To(HaveLen(1))
		})
	})

	Context("with the limit off", func() {
		BeforeEach(func() { srv.CSRRateLimit = 0 })

		It("refuses nothing, reports nothing and warns about nothing", func() {
			for range 5 {
				Expect(put("limited-node", "192.0.2.1:1000")).NotTo(Equal(http.StatusTooManyRequests))
			}
			Expect(limited).To(BeZero())
			Expect(logBuf.String()).NotTo(ContainSubstring("CSR submission refused"))
		})
	})
})
