//go:build !windows

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

package httpclient_test

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/boundedfile"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/httpclient"
)

// A FIFO with no writer stands in for a credentials or CA file on a wedged
// mount: os.Open on it blocks until a writer appears. Not on Windows, which
// has no syscall.Mkfifo.
var _ = Describe("httpclient with a file that never answers", func() {
	var dir string

	BeforeEach(func() { dir = GinkgoT().TempDir() })

	wedged := func(name string) string {
		GinkgoHelper()
		p := filepath.Join(dir, name)
		Expect(syscall.Mkfifo(p, 0o600)).To(Succeed())
		// Unwedge it afterwards, so the stranded read returns and its slot
		// is freed for any later spec.
		DeferCleanup(func() {
			if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
		})
		return p
	}

	It("gives up on a credentials file within the request's deadline, without sending it", func() {
		var requests atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
		DeferCleanup(ts.Close)
		c, err := httpclient.New(context.Background(), config.HTTPClientConfig{
			BasicAuth: &config.BasicAuth{Username: "u", PasswordFile: wedged("pw")},
		}, "http_config")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(c.CloseIdleConnections)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
		Expect(err).NotTo(HaveOccurred())
		start := time.Now()
		_, err = c.Do(req)
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(err).To(MatchError(ContainSubstring("http_config.basic_auth.password_file")))
		Expect(time.Since(start)).To(BeNumerically("<", 3*time.Second))
		Expect(requests.Load()).To(BeZero())
	})

	It("gives up on tls_config.ca_file within the build's deadline", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := httpclient.New(ctx, config.HTTPClientConfig{
			TLSConfig: config.TLSConfig{CAFile: wedged("ca.pem")},
		}, "http_config")
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(err).To(MatchError(ContainSubstring("http_config.tls_config.ca_file")))
		Expect(time.Since(start)).To(BeNumerically("<", 3*time.Second))
	})

	It("gives up on an authorization credentials file within the request's deadline, without sending it", func() {
		var requests atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
		DeferCleanup(ts.Close)
		c, err := httpclient.New(context.Background(), config.HTTPClientConfig{
			Authorization: &config.Authorization{CredentialsFile: wedged("token")},
		}, "http_config")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(c.CloseIdleConnections)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
		Expect(err).NotTo(HaveOccurred())
		start := time.Now()
		_, err = c.Do(req)
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(err).To(MatchError(ContainSubstring("http_config.authorization.credentials_file")))
		Expect(time.Since(start)).To(BeNumerically("<", 3*time.Second))
		Expect(requests.Load()).To(BeZero())
	})

	It("gives up on a client certificate within the build's deadline", func() {
		_, keyFile := clientCertificate(dir)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := httpclient.New(ctx, config.HTTPClientConfig{
			TLSConfig: config.TLSConfig{CertFile: wedged("wedged-client.pem"), KeyFile: keyFile},
		}, "http_config")
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(err).To(MatchError(ContainSubstring("loading http_config.tls_config client certificate")))
		Expect(time.Since(start)).To(BeNumerically("<", 3*time.Second))
	})

	It("gives up on a client certificate re-read at handshake within the handshake timeout, and counts it", func() {
		// The certificate is re-read on every handshake so a renewal is picked
		// up. The handshake's own context is the dial's, which outlives the
		// request that started it and is never cancelled, so the read is
		// bounded by a deadline GetClientCertificate derives from
		// tlsHandshakeTimeout itself. Once boundedfile.Slots reads on a mount
		// that wedged after the build have outlived that deadline, a new
		// handshake on the path is refused at once; reads admitted before then,
		// this spec's own polls among them, are each stranded at their own
		// deadline, since Slots bounds admission rather than the stranded
		// count. The refusal, arriving within about one handshake timeout, is
		// what shows the reads were bounded and counted rather than left
		// blocked for ever behind background dials.
		certFile, keyFile := clientCertificate(dir)
		ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		ts.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
		ts.StartTLS()
		DeferCleanup(ts.Close)
		caFile := filepath.Join(dir, "server-ca.pem")
		Expect(os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}),
			0o600)).To(Succeed())
		c, err := httpclient.New(context.Background(), config.HTTPClientConfig{TLSConfig: config.TLSConfig{
			CAFile: caFile, CertFile: certFile, KeyFile: keyFile,
		}}, "http_config")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(c.CloseIdleConnections)

		// The mount wedges after the build.
		Expect(os.Remove(certFile)).To(Succeed())
		Expect(syscall.Mkfifo(certFile, 0o600)).To(Succeed())
		DeferCleanup(func() {
			if w, err := os.OpenFile(certFile, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = w.Close()
			}
		})

		get := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
			Expect(err).NotTo(HaveOccurred())
			_, err = c.Do(req)
			return err
		}
		start := time.Now()
		for i := range boundedfile.Slots {
			Expect(get()).To(HaveOccurred(), "request %d", i)
		}
		// Once those handshakes time out their reads are counted as stranded,
		// and a new handshake on the path is refused rather than blocked --
		// naming the setting, so the refusal does not read as the server's.
		Eventually(get).WithTimeout(3 * httpclient.TLSHandshakeTimeout).WithPolling(500 * time.Millisecond).
			Should(SatisfyAll(
				MatchError(ContainSubstring("outlived their deadline")),
				MatchError(ContainSubstring("loading http_config.tls_config client certificate")),
			))
		Expect(time.Since(start)).To(BeNumerically("<", httpclient.TLSHandshakeTimeout+httpclient.TLSHandshakeTimeout/2),
			"the stranded reads were given up at the handshake timeout, not later")
	})
})
