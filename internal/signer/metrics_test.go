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

package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"net/rpc"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/voxpupuli/openvox-ca/internal/constants"
)

// wedgedMetrics accepts a Metrics call and answers only when released.
type wedgedMetrics struct {
	calls   chan struct{}
	release chan struct{}
}

func (w *wedgedMetrics) Metrics(_ *MetricsRequest, resp *MetricsResponse) error {
	w.calls <- struct{}{}
	<-w.release
	return (&Service{runtime: newRuntimeGatherer()}).Metrics(&MetricsRequest{}, resp)
}

// erroringMetrics answers every Metrics call with an error, counting them.
type erroringMetrics struct{ calls atomic.Int32 }

func (e *erroringMetrics) Metrics(_ *MetricsRequest, _ *MetricsResponse) error {
	e.calls.Add(1)
	return errors.New("gather failed in the signer")
}

// garbledMetrics answers with bytes that are not length-delimited protobuf.
type garbledMetrics struct{}

func (garbledMetrics) Metrics(_ *MetricsRequest, resp *MetricsResponse) error {
	resp.Families = []byte{0xff}
	return nil
}

// rpcMethods returns the names of the methods net/rpc would register for rcvr:
// exported, two arguments of which the second is a pointer, returning error.
// It reads the method set rather than trusting a list kept by hand, which is
// the point of the spec that uses it.
func rpcMethods(rcvr any) []string {
	errType := reflect.TypeFor[error]()
	t := reflect.TypeOf(rcvr)
	var names []string
	for i := range t.NumMethod() {
		m := t.Method(i)
		mt := m.Type // receiver first
		if !m.IsExported() || mt.NumIn() != 3 || mt.NumOut() != 1 {
			continue
		}
		if mt.In(2).Kind() != reflect.Pointer || mt.Out(0) != errType {
			continue
		}
		names = append(names, m.Name)
	}
	return names
}

// serveOver connects a RemoteSigner to rcvr, registered as the Signer service
// over an in-memory pipe.
func serveOver(rcvr any, metricsTimeout time.Duration) *RemoteSigner {
	GinkgoHelper()
	serverConn, clientConn := net.Pipe()
	server := rpc.NewServer()
	Expect(server.RegisterName("Signer", rcvr)).To(Succeed())
	go server.ServeConn(serverConn)
	rs := &RemoteSigner{client: rpc.NewClient(clientConn), metricsTimeout: metricsTimeout}
	DeferCleanup(rs.Close)
	return rs
}

func familyNames(mfs []*dto.MetricFamily) []string {
	names := make([]string, 0, len(mfs))
	for _, mf := range mfs {
		names = append(names, mf.GetName())
	}
	return names
}

var _ = Describe("the signer's runtime metrics", func() {
	It("reaches the frontend as the signer's go_* families, and nothing else", func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		rs := serveOver(&Service{key: key, runtime: newRuntimeGatherer()}, 0)

		mfs, err := rs.Gather()
		Expect(err).NotTo(HaveOccurred())
		Expect(familyNames(mfs)).To(ContainElements("go_goroutines", "go_memstats_heap_inuse_bytes",
			"go_gc_gomemlimit_bytes"), "the series that size the signer against its memory share")
		for _, name := range familyNames(mfs) {
			Expect(strings.HasPrefix(name, "go_")).To(BeTrue(),
				"the signer reports its runtime only; process_* comes from /proc on the frontend side, got %q", name)
		}
	})

	// The isolated signer is the only process that can see an OpenBao
	// Transit session's state, so openvoxca_openbao_authenticated has to cross
	// the same RPC the go_* families do. This pins that a collector given to
	// newRuntimeGatherer crosses it. Serve's handing its extra collectors on,
	// and runSignerMode's passing the key provider's, are not driven by any
	// spec: Serve needs the launcher's inherited descriptors.
	It("carries the key provider's collectors beside the go_* families", func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		session := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: constants.OpenBaoAuthenticatedMetric, Help: "the key provider's session"})
		session.Set(1)
		rs := serveOver(&Service{key: key, runtime: newRuntimeGatherer(session)}, 0)

		mfs, err := rs.Gather()
		Expect(err).NotTo(HaveOccurred())
		Expect(familyNames(mfs)).To(ContainElements("go_goroutines", constants.OpenBaoAuthenticatedMetric))
	})

	It("waits for no longer than its deadline on a signer that does not answer", func() {
		wedged := &wedgedMetrics{calls: make(chan struct{}, 4), release: make(chan struct{})}
		rs := serveOver(wedged, 50*time.Millisecond)
		DeferCleanup(func() { close(wedged.release) })

		start := time.Now()
		_, err := rs.Gather()
		Expect(err).To(MatchError(ContainSubstring("timed out")))
		Expect(time.Since(start)).To(BeNumerically("<", 2*time.Second))
		Eventually(wedged.calls).Should(Receive(), "the call reached the signer: wedged, not disconnected")
	})

	// net/rpc keeps an abandoned call in its pending table until a reply
	// arrives, and a scraper asks on its own schedule. One outstanding call at
	// a time is what bounds that table against a signer wedged for hours.
	It("adds no second call while the first is unanswered, and resumes once it is", func() {
		wedged := &wedgedMetrics{calls: make(chan struct{}, 4), release: make(chan struct{})}
		rs := serveOver(wedged, 50*time.Millisecond)

		_, err := rs.Gather()
		Expect(err).To(MatchError(ContainSubstring("timed out")))
		Eventually(wedged.calls).Should(Receive())

		_, err = rs.Gather()
		Expect(err).To(MatchError(ErrMetricsUnanswered))
		Consistently(wedged.calls, 100*time.Millisecond).ShouldNot(Receive(),
			"the refused scrape must not have reached the signer")

		// The late reply frees the slot; the next scrape is answered.
		close(wedged.release)
		Eventually(func() error {
			_, err := rs.Gather()
			return err
		}, 2*time.Second, 20*time.Millisecond).Should(Succeed())
	})

	// Two scrapers overlapping on a healthy signer -- an HA Prometheus pair, an
	// operator's curl during a scheduled scrape -- must both get the series. The
	// one-call bound exists for a signer that is not answering, not for one
	// that simply has not answered yet.
	It("shares one call between scrapes that overlap on a healthy signer", func() {
		slow := &wedgedMetrics{calls: make(chan struct{}, 4), release: make(chan struct{})}
		rs := serveOver(slow, 5*time.Second)

		type result struct {
			mfs []*dto.MetricFamily
			err error
		}
		results := make(chan result, 2)
		gather := func() {
			defer GinkgoRecover()
			mfs, err := rs.Gather()
			results <- result{mfs, err}
		}

		go gather()
		Eventually(slow.calls).Should(Receive(), "the first scrape's call reached the signer")
		go gather()
		Consistently(slow.calls, 200*time.Millisecond).ShouldNot(Receive(),
			"the overlapping scrape must join the outstanding call, not send a second")

		close(slow.release)
		var got [2]result
		for i := range got {
			Eventually(results, 2*time.Second).Should(Receive(&got[i]))
			Expect(got[i].err).NotTo(HaveOccurred())
			Expect(familyNames(got[i].mfs)).To(ContainElement("go_goroutines"))
		}

		// One reply, but two sets of families: the exporter relabels what
		// it is given in place, so two scrapes handed the same objects
		// would race on them.
		for _, a := range got[0].mfs {
			for _, b := range got[1].mfs {
				Expect(a).NotTo(BeIdenticalTo(b), "family %q is shared between callers", a.GetName())
			}
		}
	})

	// A scrape that joins an outstanding call is bounded by that call's
	// deadline, not a fresh one of its own: against a wedged signer a late
	// joiner would otherwise wait up to twice the deadline, past Prometheus's
	// scrape timeout, and lose the whole scrape rather than the signer's series.
	It("lets a scrape that joins an outstanding call wait only for what is left of its deadline", func() {
		const timeout = time.Second
		wedged := &wedgedMetrics{calls: make(chan struct{}, 4), release: make(chan struct{})}
		rs := serveOver(wedged, timeout)
		DeferCleanup(func() { close(wedged.release) })

		first := make(chan error, 1)
		t0 := time.Now() // no later than the call's own start
		go func() {
			defer GinkgoRecover()
			_, err := rs.Gather()
			first <- err
		}()
		Eventually(wedged.calls).Should(Receive())

		// Positioning in time rather than waiting for a condition: the
		// joiner has to arrive well into the first call's deadline.
		time.Sleep(timeout * 6 / 10)

		// Measured from the first call, not the joiner's arrival, and either
		// refusal counts: on a stalled runner the joiner can arrive after the
		// deadline, and then ErrMetricsUnanswered is the right answer. What
		// must not happen is a deadline of its own, which ends near
		// t0 + 1.6 * timeout.
		_, err := rs.Gather()
		Expect(time.Since(t0)).To(BeNumerically("<", timeout*13/10),
			"the joiner waited out a deadline of its own")
		Expect(err).To(Or(MatchError(ContainSubstring("timed out")), MatchError(ErrMetricsUnanswered)))
		Consistently(wedged.calls, 100*time.Millisecond).ShouldNot(Receive(), "the joiner sent no call of its own")
		Eventually(first, 2*time.Second).Should(Receive(MatchError(ContainSubstring("timed out"))))
	})

	// net/rpc writes a request synchronously, and nothing bounds the write. A
	// signer that has stopped reading its end -- frozen, not dead -- must cost
	// a scrape its own series and no more: not a send that holds the lock every
	// later scrape needs, nor one that outlasts the deadline.
	It("bounds a scrape against a signer that has stopped reading its socket", func() {
		// net.Pipe is unbuffered: with nothing reading the far end, every
		// write blocks, which is a frozen signer exactly.
		serverConn, clientConn := net.Pipe()
		rs := &RemoteSigner{client: rpc.NewClient(clientConn), metricsTimeout: 100 * time.Millisecond}
		DeferCleanup(func() {
			_ = serverConn.Close()
			_ = rs.Close()
		})

		done := make(chan error, 2)
		go func() {
			defer GinkgoRecover()
			_, err := rs.Gather()
			done <- err
		}()
		Eventually(done, 2*time.Second).Should(Receive(MatchError(ContainSubstring("timed out"))))

		go func() {
			defer GinkgoRecover()
			_, err := rs.Gather()
			done <- err
		}()
		Eventually(done, 2*time.Second).Should(Receive(MatchError(ErrMetricsUnanswered)),
			"a later scrape must be refused at once, not queue behind the blocked send")
	})

	// The slot has to come back however the call ends. Freed only on a
	// successful reply, one RPC error would turn every later scrape into
	// ErrMetricsUnanswered for the life of the process.
	It("frees the slot when the signer answers with an error", func() {
		failing := &erroringMetrics{}
		rs := serveOver(failing, time.Second)

		_, err := rs.Gather()
		Expect(err).To(MatchError(ContainSubstring("gather failed in the signer")))

		_, err = rs.Gather()
		Expect(err).NotTo(MatchError(ErrMetricsUnanswered))
		Expect(err).To(MatchError(ContainSubstring("gather failed in the signer")))
		Expect(failing.calls.Load()).To(BeEquivalentTo(2), "the second scrape made a call of its own")
	})

	It("reports a reply it cannot decode, rather than serving part of it", func() {
		rs := serveOver(garbledMetrics{}, time.Second)
		mfs, err := rs.Gather()
		Expect(err).To(MatchError(ContainSubstring("decoding signer metrics")))
		Expect(mfs).To(BeEmpty())
	})

	It("defaults to a deadline inside Prometheus's own scrape timeout", func() {
		Expect(defaultRemoteMetricsTimeout).To(BeNumerically("<", 10*time.Second))
	})
})

// SECURITY: net/rpc serves every method of the registered receiver that has
// the right shape, so adding one to Service publishes it to the frontend on
// the process that holds the CA key. docs/ca-key-security.md states the
// surface; this is what makes widening it a deliberate act.
var _ = Describe("the signer's RPC surface", func() {
	It("is Sign and Metrics, and nothing else", func() {
		Expect(rpcMethods(&Service{})).To(ConsistOf("Sign", "Metrics"),
			"a new RPC on the key holder: update docs/ca-key-security.md's description of "+
				"what the signer answers, and this list, in the same commit")
	})

	// The spec above is only as good as rpcMethods. A receiver whose shape is
	// known proves it finds what net/rpc would register and skips the rest.
	It("is counted the way net/rpc counts it", func() {
		server := rpc.NewServer()
		Expect(server.RegisterName("Probe", &erroringMetrics{})).To(Succeed())
		Expect(rpcMethods(&erroringMetrics{})).To(ConsistOf("Metrics"))
		Expect(rpcMethods(garbledMetrics{})).To(ConsistOf("Metrics"))
		Expect(rpcMethods(&struct{ wedgedMetrics }{})).To(ConsistOf("Metrics"))
	})
})
