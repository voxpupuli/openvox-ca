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
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The readiness hold through the real serve command: the only place it is
// taken in production is the serve path, so a spec that called the CA method
// directly would pass with that call deleted. (It does not pin the call's
// place before the jobs: startServe returns at READY=1, after the listener, so
// a hold moved later still reads as held here.)
var _ = Describe("the serve command's readiness with crl_chain.urls", func() {
	var caDir string

	BeforeEach(func() {
		clearServerEnv()
		caDir = GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "ca.example.com")
		DeferCleanup(slog.SetDefault, slog.Default())
	})

	// upstreamOn serves an ancestor's CRL as a distribution point does, once its
	// certificate is in the stored bundle, or answers 404 when broken, from the
	// server newServer starts.
	upstreamOn := func(newServer func(http.Handler) *httptest.Server, broken bool) *httptest.Server {
		GinkgoHelper()
		cert, crlPEM := chainUpstreamCA("Upstream Root CA")
		store := storage.New(caDir)
		ours, err := store.GetCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(context.Background(), append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...))).To(Succeed())
		block, _ := pem.Decode(crlPEM)
		ts := newServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if broken {
				http.NotFound(w, nil)
				return
			}
			_, _ = w.Write(block.Bytes)
		}))
		DeferCleanup(ts.Close)
		return ts
	}
	upstream := func(broken bool) string { return upstreamOn(httptest.NewServer, broken).URL }

	start := func(extra string) string {
		GinkgoHelper()
		path := serveConfig(caDir, GinkgoT().TempDir(), "127.0.0.1", freeLoopbackPort(), false)
		appendConfig(path, extra)
		return startServe(path)
	}

	status := func(addr, probe string) int {
		GinkgoHelper()
		resp, err := plainClient().Get("http://" + addr + "/healthz/" + probe)
		Expect(err).NotTo(HaveOccurred())
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	It("holds readiness on a fresh store while no upstream answers, but has started", func() {
		addr := start(fmt.Sprintf("crl_chain:\n  urls: [%s]\n", upstream(true)))
		Consistently(func() int { return status(addr, "ready") }).
			WithTimeout(time.Second).Should(Equal(http.StatusServiceUnavailable))
		Expect(status(addr, "startup")).To(Equal(http.StatusOK),
			"startup must pass, or the kubelet restarts a held pod in a loop")
	})

	It("becomes ready once the first round stores an upstream CRL", func() {
		addr := start(fmt.Sprintf("crl_chain:\n  urls: [%s]\n", upstream(false)))
		Eventually(func() int { return status(addr, "ready") }).
			WithTimeout(30 * time.Second).Should(Equal(http.StatusOK))
	})

	// Through the job the serve command actually builds: crl_chain.http_config
	// must reach it, or an upstream whose certificate only ca_file vouches for
	// is refused and the pod stays held.
	It("fetches with crl_chain.http_config, trusting the ca_file it names", func() {
		ts := upstreamOn(httptest.NewTLSServer, false)
		caFile := filepath.Join(GinkgoT().TempDir(), "upstream-ca.pem")
		Expect(os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}),
			0o600)).To(Succeed())
		addr := start(fmt.Sprintf("crl_chain:\n  urls: [%s]\n  http_config:\n    tls_config:\n      ca_file: %s\n",
			ts.URL, caFile))
		Eventually(func() int { return status(addr, "ready") }).
			WithTimeout(30 * time.Second).Should(Equal(http.StatusOK))
	})

	It("holds nothing without crl_chain.urls", func() {
		addr := start("")
		Expect(status(addr, "ready")).To(Equal(http.StatusOK))
	})
})
