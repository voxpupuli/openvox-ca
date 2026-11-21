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
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// openvoxca_destructive_operations_total is what docs/ca-key-security.md and
// the mixin's OpenVoxCADestructiveOperationsHigh alert read in place of the
// "High rate of destructive operations detected" warning, so every route that
// takes a credential out of service has to report to it, once per subject,
// and only when it succeeded.
var _ = Describe("OnDestructiveOperation", func() {
	var (
		ctx      = context.Background()
		myCA     *ca.CA
		store    *storage.StorageService
		mux      http.Handler
		reported map[string]int
	)

	BeforeEach(func() {
		dir := GinkgoT().TempDir()
		store = storage.New(dir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		reported = map[string]int{}
		srv := api.New(myCA)
		srv.OnDestructiveOperation = func(operation string, subjects int) {
			Expect(api.DestructiveOperations).To(ContainElement(operation),
				"the counter publishes only the listed operations at zero")
			reported[operation] += subjects
		}
		mux = srv.Routes()
	})

	issue := func(subject string) string {
		GinkgoHelper()
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return strings.ToUpper(cert.SerialNumber.Text(16))
	}

	serve := func(method, path, body string) int {
		GinkgoHelper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec.Code
	}

	It("counts a revocation by subject", func() {
		issue("node1.test")
		Expect(serve("PUT", "/puppet-ca/v1/certificate_status/node1.test",
			`{"desired_state":"revoked"}`)).To(Equal(http.StatusNoContent))
		Expect(reported).To(Equal(map[string]int{"revoke": 1}))
	})

	It("counts a revocation by serial", func() {
		// A superseded certificate, which the route revokes without force.
		old := issue("node1.test")
		Expect(store.DeleteCert(ctx, "node1.test")).To(Succeed())
		issue("node1.test")

		Expect(serve("PUT", "/puppet-ca/v1/certificate_status_by_serial/"+old,
			`{"desired_state":"revoked"}`)).To(Equal(http.StatusNoContent))
		Expect(reported).To(Equal(map[string]int{"revoke": 1}))
	})

	It("counts a clean", func() {
		issue("node1.test")
		Expect(serve("DELETE", "/puppet-ca/v1/certificate_status/node1.test", "")).
			To(Equal(http.StatusNoContent))
		Expect(reported).To(Equal(map[string]int{"clean": 1}))
	})

	It("counts a bulk clean once per subject it removed", func() {
		// Per subject, not per request, so that one request removing the
		// whole fleet reads as the whole fleet; and only the subjects it
		// removed, so a list of names that were never there reads as nothing.
		issue("node1.test")
		issue("node2.test")
		Expect(serve("PUT", "/puppet-ca/v1/clean",
			`{"certnames":["node1.test","node2.test","absent.test"]}`)).To(Equal(http.StatusOK))
		Expect(reported).To(Equal(map[string]int{"bulk-clean": 2}))
	})

	It("counts nothing for a request that removed nothing", func() {
		Expect(serve("DELETE", "/puppet-ca/v1/certificate_status/absent.test", "")).
			To(Equal(http.StatusNotFound))
		Expect(serve("PUT", "/puppet-ca/v1/certificate_status/absent.test",
			`{"desired_state":"revoked"}`)).To(Equal(http.StatusNotFound))
		Expect(serve("PUT", "/puppet-ca/v1/certificate_status_by_serial/ABCDEF",
			`{"desired_state":"revoked"}`)).To(Equal(http.StatusNotFound))
		Expect(serve("PUT", "/puppet-ca/v1/clean", `{"certnames":["absent.test"]}`)).
			To(Equal(http.StatusOK))
		Expect(reported).To(BeEmpty())
	})

	It("lists exactly the operations the routes report", func() {
		// The label values are public API from 1.0.0, and the high-rate
		// warning's operation attribute spells them the same way so the two
		// can be joined.
		Expect(api.DestructiveOperations).To(ConsistOf("revoke", "clean", "bulk-clean"))
	})
})
