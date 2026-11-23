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
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The round this job runs, against a real upstream over HTTP. Whether the job
// is scheduled is background_jobs_test.go's half, as for the file's job.
var _ = Describe("CRL chain fetch", func() {
	var (
		ctx      context.Context
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		upstream, upsCRL = chainUpstreamCA("Upstream Root CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...), upstreamPEM...))).To(Succeed())

		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
			GinkgoT().Setenv(k, "")
		}
	})

	// serveCRL serves the upstream CRL as DER, as a distribution point does,
	// counting requests.
	serveCRL := func(hits *atomic.Int32) string {
		block, _ := pem.Decode(upsCRL)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/pkix-crl")
			_, _ = w.Write(block.Bytes)
		}))
		DeferCleanup(ts.Close)
		return ts.URL
	}

	It("publishes the fetched CRL and reports a clean round", func() {
		var hits atomic.Int32
		u := serveCRL(&hits)
		myCA.SetCRLChainURLs([]string{u})

		Expect(fetchCRLChainOnce(ctx, myCA, crlChainFetch{urls: []string{u}, timeout: 5 * time.Second})).To(Equal(roundClean))
		Expect(countCRLPEMBlocks(mustGetStoredCRL(ctx, store))).To(Equal(2))
		Expect(myCA.UpstreamFetchStatuses()[0].LastSuccess).NotTo(BeZero())
	})

	It("reports a round with a failed entry, so the next comes sooner", func() {
		var hits atomic.Int32
		good := serveCRL(&hits)
		bad := httptest.NewServer(http.NotFoundHandler())
		DeferCleanup(bad.Close)
		urls := []string{good, bad.URL}
		myCA.SetCRLChainURLs(urls)

		Expect(fetchCRLChainOnce(ctx, myCA, crlChainFetch{urls: urls, timeout: 5 * time.Second})).To(Equal(roundEntryFailed))
		// The good entry still landed: a partial round updates.
		Expect(countCRLPEMBlocks(mustGetStoredCRL(ctx, store))).To(Equal(2))
		Expect(myCA.UpstreamFetchStatuses()[1].Failures).To(BeEquivalentTo(1))
	})

	It("releases a readiness hold once a round stores a usable CRL, and not before", func() {
		var hits atomic.Int32
		good := serveCRL(&hits)
		bad := httptest.NewServer(http.NotFoundHandler())
		DeferCleanup(bad.Close)
		Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeTrue(), "precondition: a fresh store is held")

		// Nothing usable stored: still held.
		myCA.SetCRLChainURLs([]string{bad.URL})
		fetchCRLChainOnce(ctx, myCA, crlChainFetch{urls: []string{bad.URL}, timeout: 5 * time.Second})
		Expect(myCA.UpstreamChainHeld()).To(BeTrue())

		// A partial round that stores one: released, as a restart would be.
		partial := []string{good, bad.URL}
		myCA.SetCRLChainURLs(partial)
		fetchCRLChainOnce(ctx, myCA, crlChainFetch{urls: partial, timeout: 5 * time.Second})
		Expect(myCA.UpstreamChainHeld()).To(BeFalse())
		Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeFalse(),
			"a restart now would not hold either: the two conditions agree")
	})

	It("hands the job every setting the configuration carries", func() {
		cfg := &serverConfig{CRLChain: config.CRLChainConfig{
			URLs:               []string{"https://pki.test/a.crl"},
			FetchTimeoutSec:    12,
			RefreshIntervalSec: 7200,
			HTTPConfig:         config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: "/run/ca.pem"}},
		}}
		f := crlChainFetchFor(cfg)
		Expect(f.urls).To(Equal(cfg.CRLChain.URLs))
		Expect(f.timeout).To(Equal(12 * time.Second))
		Expect(f.interval).To(Equal(2 * time.Hour))
		Expect(f.retryMin).To(Equal(crlChainFetchRetryMin))
		Expect(f.http.TLSConfig.CAFile).To(Equal("/run/ca.pem"),
			"a dropped http_config would fail every private-CA fetch")
		Expect(f.wait).To(BeNil(), "the job sleeps on a real timer")
	})

	// The mixin's fetch alerts are sized for this job's defaults, which the
	// mixin cannot see: a default interval raised alone would leave
	// FetchFailing flapping and FetchStale firing on a single failed round,
	// with every promtool case still green. This reads the mixin's defaults
	// and fails if the two part.
	It("keeps the mixin's fetch-alert windows sized for the default interval", func() {
		cfg, err := os.ReadFile(filepath.Join("..", "..", "mixin", "config.libsonnet"))
		Expect(err).NotTo(HaveOccurred())
		field := func(name, pattern string) string {
			GinkgoHelper()
			m := regexp.MustCompile(`(?m)^\s*` + name + `:\s*` + pattern + `,`).FindSubmatch(cfg)
			Expect(m).NotTo(BeNil(), name+" not found in mixin/config.libsonnet")
			return string(m[1])
		}
		threshold, err := strconv.Atoi(field("crlChainFetchFailureThreshold", `(\d+)`))
		Expect(err).NotTo(HaveOccurred())
		window, err := time.ParseDuration(field("crlChainFetchWindow", `'([0-9a-z]+)'`))
		Expect(err).NotTo(HaveOccurred())
		staleSec, err := strconv.Atoi(field("crlChainFetchStaleSeconds", `(\d+)`))
		Expect(err).NotTo(HaveOccurred())

		Expect(window).To(BeNumerically(">=", time.Duration(threshold+1)*defaultCRLChainRefreshInterval),
			"crlChainFetchWindow must hold (threshold + 1) intervals")
		Expect(time.Duration(staleSec)*time.Second).To(BeNumerically(">=", 2*defaultCRLChainRefreshInterval),
			"crlChainFetchStaleSeconds must cover at least two intervals")
		Expect(crlChainFetchRetryMin).To(BeNumerically("<", defaultCRLChainRefreshInterval),
			"the threshold's margin assumes a failed round is retried well inside the interval")
	})

	It("fails each http(s) entry, under its own URL, when the client cannot be built, and still reads file:/// entries", func() {
		var hits atomic.Int32
		u := serveCRL(&hits)
		file := filepath.Join(GinkgoT().TempDir(), "root.crl")
		Expect(os.WriteFile(file, upsCRL, 0o600)).To(Succeed())
		urls := []string{u, "file://" + file}
		myCA.SetCRLChainURLs(urls)
		out := fetchCRLChainOnce(ctx, myCA, crlChainFetch{
			urls:    urls,
			timeout: 5 * time.Second,
			http:    config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: filepath.Join(GinkgoT().TempDir(), "absent.pem")}},
		})
		Expect(out).To(Equal(roundEntryFailed))
		st := myCA.UpstreamFetchStatuses()
		Expect(st[0].Failures).To(BeEquivalentTo(1), "the failure must be recorded against the configured URL")
		Expect(hits.Load()).To(BeZero(), "no request can be made without a client")
		Expect(st[1].Failures).To(BeZero(), "a file:/// entry never depends on http_config")
		Expect(st[1].LastSuccess).NotTo(BeZero())
	})

	It("fails every entry under its own URL when the list cannot be built at all", func() {
		// Validate refuses an entry that does not parse, so this is a guard
		// rather than a path a configuration reaches: what it guards is that
		// the failures land on the configured URLs' series, not on none.
		urls := []string{"http://[::1"}
		myCA.SetCRLChainURLs(urls)
		Expect(fetchCRLChainOnce(ctx, myCA, crlChainFetch{urls: urls, timeout: 5 * time.Second})).
			To(Equal(roundEntryFailed))
		st := myCA.UpstreamFetchStatuses()
		Expect(st).To(HaveLen(1))
		Expect(st[0].URL).To(Equal(urls[0]))
		Expect(st[0].Failures).To(BeEquivalentTo(1))
	})

	It("abandons a round cut short by shutdown, blaming no upstream", func() {
		var hits atomic.Int32
		u := serveCRL(&hits)
		myCA.SetCRLChainURLs([]string{u})
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		fetchCRLChainOnce(cancelled, myCA, crlChainFetch{urls: []string{u}, timeout: 5 * time.Second})
		Expect(myCA.UpstreamFetchStatuses()).To(ConsistOf(ca.UpstreamFetchStatus{URL: u}),
			"a stop is not the URL's failure, nor a success")
	})

	It("abandons a round that shutdown cuts short mid-fetch, blaming no upstream", func() {
		// The stop arrives while the entry is in flight, so the check has to
		// come after the fetch: one placed before it would see a live context
		// and let the failed entry through to the merge.
		running, stop := context.WithCancel(ctx)
		DeferCleanup(stop)
		ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			stop()
			<-r.Context().Done()
		}))
		DeferCleanup(ts.Close)
		myCA.SetCRLChainURLs([]string{ts.URL})
		fetchCRLChainOnce(running, myCA, crlChainFetch{urls: []string{ts.URL}, timeout: 5 * time.Second})
		Expect(myCA.UpstreamFetchStatuses()).To(ConsistOf(ca.UpstreamFetchStatus{URL: ts.URL}),
			"a stop is not the URL's failure, nor a success")
	})

	Describe("a round whose merge fails", func() {
		It("reports it, and leaves a readiness hold in place", func() {
			var hits atomic.Int32
			u := serveCRL(&hits)
			myCA.SetCRLChainURLs([]string{u})
			Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeTrue(), "precondition: a fresh store is held")
			// The stored chain then stops decoding: the merge fails before it
			// can land anything, whatever the upstream served.
			Expect(store.Backend().Put(ctx, storage.KeyCRL,
				[]byte("-----BEGIN X509 CRL-----\nnot a CRL\n-----END X509 CRL-----\n"), storage.BlobPublic)).To(Succeed())
			Expect(fetchCRLChainOnce(ctx, myCA, crlChainFetch{urls: []string{u}, timeout: 5 * time.Second})).
				To(Equal(roundMergeFailed))
			Expect(hits.Load()).To(BeEquivalentTo(1), "precondition: the fetch itself worked")
			Expect(myCA.UpstreamChainHeld()).To(BeTrue(), "nothing landed, so nothing may release the hold")
		})
	})

	// The schedule, seen through an injected wait rather than measured on the
	// clock: retryMin after a failed entry, doubling, capped at the interval,
	// back to retryMin after a clean round, and the interval after a merge
	// that failed -- unless readiness is held.
	Describe("the schedule", func() {
		var fail atomic.Bool

		BeforeEach(func() { fail.Store(true) })

		// upstream serves the CRL, or a 404 while fail is set.
		upstreamURL := func() string {
			block, _ := pem.Decode(upsCRL)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if fail.Load() {
					http.NotFound(w, nil)
					return
				}
				_, _ = w.Write(block.Bytes)
			}))
			DeferCleanup(ts.Close)
			myCA.SetCRLChainURLs([]string{ts.URL})
			return ts.URL
		}

		// schedule runs the job for rounds rounds and returns the wait chosen
		// after each. between, if set, runs after each wait is chosen, with how
		// many have been, so a spec can change what the next round sees.
		schedule := func(interval, retryMin time.Duration, rounds int, between func(n int)) []time.Duration {
			GinkgoHelper()
			var waits []time.Duration
			f := crlChainFetch{urls: []string{upstreamURL()}, timeout: 5 * time.Second,
				interval: interval, retryMin: retryMin,
				wait: func(_ context.Context, d time.Duration) bool {
					waits = append(waits, d)
					if between != nil {
						between(len(waits))
					}
					return len(waits) < rounds
				}}
			runCRLChainFetcher(ctx, myCA, f)
			return waits
		}

		It("retries a failed round after retryMin, doubling, up to the interval", func() {
			Expect(schedule(time.Hour, 10*time.Minute, 6, nil)).To(Equal([]time.Duration{
				10 * time.Minute, 20 * time.Minute, 40 * time.Minute, time.Hour, time.Hour, time.Hour,
			}))
		})

		It("waits the full interval after a clean round", func() {
			fail.Store(false)
			Expect(schedule(time.Hour, time.Minute, 2, nil)).To(Equal([]time.Duration{time.Hour, time.Hour}))
		})

		It("goes back to retryMin after a clean round", func() {
			waits := schedule(time.Hour, time.Minute, 5, func(n int) {
				fail.Store(n != 2) // the third round succeeds
			})
			Expect(waits).To(Equal([]time.Duration{
				time.Minute, 2 * time.Minute, time.Hour, time.Minute, 2 * time.Minute,
			}))
		})

		Context("when the merge fails", func() {
			breakStoredChain := func() {
				GinkgoHelper()
				Expect(store.Backend().Put(ctx, storage.KeyCRL,
					[]byte("-----BEGIN X509 CRL-----\nnot a CRL\n-----END X509 CRL-----\n"), storage.BlobPublic)).To(Succeed())
			}

			BeforeEach(func() {
				fail.Store(false)
			})

			It("waits the full interval, so a storage outage costs one failure per round", func() {
				breakStoredChain()
				Expect(schedule(time.Hour, time.Minute, 3, nil)).To(Equal([]time.Duration{time.Hour, time.Hour, time.Hour}))
			})

			It("keeps the backoff while readiness is held, since nothing is served until one lands", func() {
				// Held on the fresh store, before the chain breaks: a chain
				// that does not decode at startup is not held.
				Expect(myCA.HoldReadinessForUpstreamChain(ctx)).To(BeTrue())
				breakStoredChain()
				Expect(schedule(time.Hour, time.Minute, 3, nil)).To(Equal([]time.Duration{
					time.Minute, 2 * time.Minute, 4 * time.Minute,
				}))
			})
		})

		It("leaves the backoff where it was across a failed merge", func() {
			// Failed entry, failed merge, failed entry: the merge waits the
			// interval and must not reset or advance the backoff.
			good := mustGetStoredCRL(ctx, store)
			waits := schedule(time.Hour, time.Minute, 3, func(n int) {
				switch n {
				case 1:
					Expect(store.Backend().Put(ctx, storage.KeyCRL,
						[]byte("-----BEGIN X509 CRL-----\nnot a CRL\n-----END X509 CRL-----\n"), storage.BlobPublic)).To(Succeed())
				case 2:
					Expect(store.Backend().Put(ctx, storage.KeyCRL, good, storage.BlobPublic)).To(Succeed())
				}
			})
			Expect(waits).To(Equal([]time.Duration{time.Minute, time.Hour, 2 * time.Minute}))
		})

		It("never waits longer than the interval, even with retryMin above it", func() {
			Expect(schedule(time.Minute, time.Hour, 2, nil)).To(Equal([]time.Duration{time.Minute, time.Minute}))
		})

		It("stops when its context is cancelled", func() {
			runCtx, cancel := context.WithCancel(ctx)
			cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				runCRLChainFetcher(runCtx, myCA, crlChainFetch{urls: []string{upstreamURL()}, timeout: time.Second,
					interval: time.Hour, retryMin: time.Minute})
			}()
			Eventually(done).WithTimeout(10 * time.Second).Should(BeClosed())
		})
	})
})

func mustGetStoredCRL(ctx context.Context, store *storage.StorageService) []byte {
	GinkgoHelper()
	blob, err := store.GetCRL(ctx)
	Expect(err).NotTo(HaveOccurred())
	return blob
}
