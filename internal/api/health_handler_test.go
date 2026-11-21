// Copyright (C) 2026 Trevor Vaughan
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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("Health Endpoints", func() {
	var (
		tmpDir string
		mux    http.Handler
	)

	newMux := func(initialized bool) http.Handler {
		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		if initialized {
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
			Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
			Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
			Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
			Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
			Expect(store.TouchInventory(context.Background())).To(Succeed())
			Expect(myCA.Init(context.Background())).To(Succeed())
		}

		srv := api.New(myCA)
		return srv.Routes()
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-health-test")
		Expect(err).NotTo(HaveOccurred())
		mux = newMux(true)
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	// newAuthedMux wires AuthConfig onto the mux so the auth middleware is active.
	// Used to confirm health endpoints are tierPublic even under mTLS enforcement.
	newAuthedMux := func() http.Handler {
		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
		srv := api.New(myCA)
		srv.AuthConfig = &api.AuthConfig{
			Domains: []api.TrustDomain{api.OwnTrustDomain(myCA.CACert, map[string]bool{"puppet-server": true}, true)},
		}
		return srv.Routes()
	}

	// --- Liveness ---

	Describe("GET /healthz/live", func() {
		It("returns 200 and status ok", func() {
			req := httptest.NewRequest("GET", "/healthz/live", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["status"]).To(Equal("ok"))
		})

		It("sets Content-Type: application/json", func() {
			req := httptest.NewRequest("GET", "/healthz/live", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		})

		It("returns 200 even when CA is not initialized", func() {
			uninitMux := newMux(false)
			req := httptest.NewRequest("GET", "/healthz/live", nil)
			rr := httptest.NewRecorder()
			uninitMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		It("is accessible without a client cert (public tier)", func() {
			req := httptest.NewRequest("GET", "/healthz/live", nil)
			// r.TLS is nil; auth middleware must not block public tier.
			rr := httptest.NewRecorder()
			newAuthedMux().ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		DescribeTable("rejects non-GET methods with 405",
			func(method string) {
				req := httptest.NewRequest(method, "/healthz/live", nil)
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
			},
			Entry("POST", "POST"),
			Entry("PUT", "PUT"),
			Entry("DELETE", "DELETE"),
			Entry("PATCH", "PATCH"),
		)
	})

	// --- Readiness ---

	Describe("GET /healthz/ready", func() {
		It("returns 200 when CA is initialized", func() {
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["status"]).To(Equal("ok"))
		})

		It("sets Content-Type: application/json", func() {
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		})

		It("returns 503 when CA is not initialized", func() {
			uninitMux := newMux(false)
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			uninitMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))

			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp).To(Equal(map[string]string{"status": "not_ready"}),
				"no reason: the upstream hold's reason must not be given for a CA still initialising")
		})

		It("sets Content-Type: application/json even on 503", func() {
			uninitMux := newMux(false)
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			uninitMux.ServeHTTP(rr, req)
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		})

		It("is accessible without a client cert (public tier)", func() {
			req := httptest.NewRequest("GET", "/healthz/ready", nil)
			rr := httptest.NewRecorder()
			newAuthedMux().ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		DescribeTable("rejects non-GET methods with 405",
			func(method string) {
				req := httptest.NewRequest(method, "/healthz/ready", nil)
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
			},
			Entry("POST", "POST"),
			Entry("PUT", "PUT"),
			Entry("DELETE", "DELETE"),
			Entry("PATCH", "PATCH"),
		)
	})

	// --- The upstream CRL chain hold ---

	Describe("with crl_chain.urls set and no upstream CRL stored", func() {
		// The stored chain here is this CA's own CRL alone, so the hold is
		// taken -- as on a fresh store with crl_chain.urls configured.
		var (
			heldMux http.Handler
			heldCA  *ca.CA
		)

		BeforeEach(func() {
			store := storage.New(tmpDir)
			heldCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(heldCA.Init(context.Background())).To(Succeed())
			Expect(heldCA.HoldReadinessForUpstreamChain(context.Background())).To(BeTrue(),
				"precondition: the hold must be taken")
			heldMux = api.New(heldCA).Routes()
		})

		It("is not ready", func() {
			rr := httptest.NewRecorder()
			heldMux.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz/ready", nil))
			Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp).To(Equal(map[string]string{"status": "not_ready", "reason": "waiting_for_upstream_crl_chain"}),
				"the body names the upstream fetch, so a failed probe does not read as a CA that never initialised")
		})

		It("is ready again once the hold is released, on the same server", func() {
			heldCA.ReleaseUpstreamChainHold()
			rr := httptest.NewRecorder()
			heldMux.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz/ready", nil))
			Expect(rr.Code).To(Equal(http.StatusOK))
			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["status"]).To(Equal("ok"))
		})

		It("has still started, so the kubelet does not restart it in a loop", func() {
			rr := httptest.NewRecorder()
			heldMux.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz/startup", nil))
			Expect(rr.Code).To(Equal(http.StatusOK))
			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp).To(Equal(map[string]string{"status": "ok"}),
				"startup does not report the readiness hold's reason")
		})

		It("is live", func() {
			rr := httptest.NewRecorder()
			heldMux.ServeHTTP(rr, httptest.NewRequest("GET", "/healthz/live", nil))
			Expect(rr.Code).To(Equal(http.StatusOK))
		})
	})

	// --- Startup ---

	Describe("GET /healthz/startup", func() {
		It("returns 200 when CA is initialized", func() {
			req := httptest.NewRequest("GET", "/healthz/startup", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp["status"]).To(Equal("ok"))
		})

		It("sets Content-Type: application/json", func() {
			req := httptest.NewRequest("GET", "/healthz/startup", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
		})

		It("returns 503 when CA is not initialized", func() {
			uninitMux := newMux(false)
			req := httptest.NewRequest("GET", "/healthz/startup", nil)
			rr := httptest.NewRecorder()
			uninitMux.ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusServiceUnavailable))
			Expect(rr.Header().Get("Content-Type")).To(ContainSubstring("application/json"))
			var resp map[string]string
			Expect(json.Unmarshal(rr.Body.Bytes(), &resp)).To(Succeed())
			Expect(resp).To(Equal(map[string]string{"status": "not_ready"}))
		})

		It("is accessible without a client cert (public tier)", func() {
			req := httptest.NewRequest("GET", "/healthz/startup", nil)
			rr := httptest.NewRecorder()
			newAuthedMux().ServeHTTP(rr, req)
			Expect(rr.Code).To(Equal(http.StatusOK))
		})

		DescribeTable("rejects non-GET methods with 405",
			func(method string) {
				req := httptest.NewRequest(method, "/healthz/startup", nil)
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)
				Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
			},
			Entry("POST", "POST"),
			Entry("PUT", "PUT"),
			Entry("DELETE", "DELETE"),
			Entry("PATCH", "PATCH"),
		)
	})
})
