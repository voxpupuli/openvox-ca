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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// generateCSRWithSANs builds a CSR carrying explicit DNS subject alternative
// names, which the signing path copies onto the issued certificate and the
// certificate index projects into dns_alt_names.
func generateCSRWithSANs(commonName string, dnsNames []string) []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		DNSNames:           dnsNames,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
}

// This suite runs the certificate_statuses endpoint against a SQL backend, so
// the handler serves from the certificate index instead of walking the stored
// PEMs. The assertions derive every expected value from the stored PEM — the
// authoritative artefact the fallback path would have parsed — pinning the
// index path to byte-identical output.
var _ = Describe("Certificate statuses via the certificate index", func() {
	var (
		ctx   = context.Background()
		store *storage.StorageService
		myCA  *ca.CA
		mux   http.Handler
	)

	BeforeEach(func() {
		dir := GinkgoT().TempDir()
		backend, err := storage.NewSQLBackend(storage.SQLConfig{
			Dialect: storage.SQLitePure,
			DSN:     "file:" + filepath.Join(dir, "ca.db"),
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = backend.Close() })
		store = storage.NewWithBackend(backend, dir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		mux = api.New(myCA).Routes()
	})

	submitAndSign := func(subject string, csrPEM []byte) {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("PUT", "/certificate_request/"+subject, bytes.NewReader(csrPEM)))
		Expect(rr.Code).To(Equal(http.StatusOK), "PUT certificate_request/"+subject)
		body, err := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
		Expect(err).NotTo(HaveOccurred())
		rr = httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("PUT", "/certificate_status/"+subject, bytes.NewReader(body)))
		Expect(rr.Code).To(Equal(http.StatusNoContent), "PUT certificate_status/"+subject)
	}

	getStatuses := func(query string) []api.CertStatusResponse {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", "/certificate_statuses/any"+query, nil))
		Expect(rr.Code).To(Equal(http.StatusOK), "GET certificate_statuses"+query)
		var statuses []api.CertStatusResponse
		Expect(json.Unmarshal(rr.Body.Bytes(), &statuses)).To(Succeed())
		return statuses
	}

	It("serves indexed statuses identical to what the stored PEM would produce", func() {
		sans := []string{"idx-node.example.com", "idx-node.alt.example.com"}
		submitAndSign("idx-node", generateCSRWithSANs("idx-node", sans))

		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		got := statuses[0]

		// Derive the expected response from the authoritative PEM, exactly as
		// the non-indexed fallback path would.
		certPEM, err := store.GetCert(ctx, "idx-node")
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		wantFP := ca.SHA256ColonFingerprint(block.Bytes)

		Expect(got.Name).To(Equal("idx-node"))
		Expect(got.State).To(Equal("signed"))
		Expect(got.Fingerprint).To(Equal(wantFP))
		Expect(got.Fingerprints).To(Equal(map[string]string{"SHA256": wantFP, "default": wantFP}))
		Expect(got.DNSAltNames).To(Equal(sans))
		Expect(got.SubjectAltNames).To(Equal(sans))
		Expect(got.AuthorizationExtensions).To(BeEmpty())
		Expect(got.AuthorizationExtensions).NotTo(BeNil())
		Expect(got.SerialNumber).NotTo(BeNil())
		Expect(*got.SerialNumber).To(Equal(cert.SerialNumber.Text(10)))
		Expect(got.NotBefore).NotTo(BeNil())
		Expect(*got.NotBefore).To(Equal(cert.NotBefore.UTC().Format(time.RFC3339)))
		Expect(got.NotAfter).NotTo(BeNil())
		Expect(*got.NotAfter).To(Equal(cert.NotAfter.UTC().Format(time.RFC3339)))
	})

	It("partitions signed, revoked, and requested across the state filters", func() {
		submitAndSign("idx-signed", generateCSRWithSANs("idx-signed", []string{"idx-signed"}))
		submitAndSign("idx-revoked", generateCSRWithSANs("idx-revoked", []string{"idx-revoked"}))

		body, err := json.Marshal(api.PutStatusBody{DesiredState: "revoked"})
		Expect(err).NotTo(HaveOccurred())
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("PUT", "/certificate_status/idx-revoked", bytes.NewReader(body)))
		Expect(rr.Code).To(Equal(http.StatusNoContent), "PUT certificate_status (revoke)")

		csrPEM, err := testutil.GenerateCSR("idx-pending")
		Expect(err).NotTo(HaveOccurred())
		rr = httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("PUT", "/certificate_request/idx-pending", bytes.NewReader(csrPEM)))
		Expect(rr.Code).To(Equal(http.StatusOK))

		all := getStatuses("")
		Expect(all).To(HaveLen(3))
		states := map[string]string{}
		for _, s := range all {
			states[s.Name] = s.State
		}
		Expect(states).To(Equal(map[string]string{
			"idx-signed":  "signed",
			"idx-revoked": "revoked",
			"idx-pending": "requested",
		}))

		signed := getStatuses("?state=signed")
		Expect(signed).To(HaveLen(1))
		Expect(signed[0].Name).To(Equal("idx-signed"))

		revoked := getStatuses("?state=revoked")
		Expect(revoked).To(HaveLen(1))
		Expect(revoked[0].Name).To(Equal("idx-revoked"))
		Expect(revoked[0].State).To(Equal("revoked"))

		requested := getStatuses("?state=requested")
		Expect(requested).To(HaveLen(1))
		Expect(requested[0].Name).To(Equal("idx-pending"))
	})

	It("falls back to the stored PEM for a projection-less record, keeping the record's state", func() {
		submitAndSign("idx-legacy", generateCSRWithSANs("idx-legacy", []string{"idx-legacy"}))

		// Append a projection-less inventory row for the same subject, as a
		// legacy blob import (or the crash window between blob and inventory
		// writes) would leave behind. Being the subject's latest issuance it
		// is the row the index serves, its serial does not match the stored
		// PEM, and no repair pass runs between here and the request.
		Expect(store.AppendInventory(ctx,
			"0FFF 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /idx-legacy")).To(Succeed())

		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		got := statuses[0]

		// Every display field must come from the authoritative PEM, not the
		// bogus row: same derivation as the non-indexed path.
		certPEM, err := store.GetCert(ctx, "idx-legacy")
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		Expect(got.Name).To(Equal("idx-legacy"))
		Expect(got.State).To(Equal("signed"))
		Expect(got.Fingerprint).To(Equal(ca.SHA256ColonFingerprint(block.Bytes)))
		Expect(got.SerialNumber).NotTo(BeNil())
		Expect(*got.SerialNumber).To(Equal(cert.SerialNumber.Text(10)),
			"the serial must be the PEM's, not the projection-less row's")
		Expect(got.DNSAltNames).To(Equal([]string{"idx-legacy"}))
	})

	It("suppresses a pending re-submission for an already-certified subject", func() {
		submitAndSign("idx-dual", generateCSRWithSANs("idx-dual", []string{"idx-dual"}))

		// SaveRequest refuses a CSR while a live certificate exists, so plant
		// the pending CSR directly in storage — the state a clean-then-crash
		// or an out-of-band write can produce, and exactly what the handler's
		// seen-map dedup exists for.
		csrPEM, err := testutil.GenerateCSR("idx-dual")
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCSR(ctx, "idx-dual", csrPEM)).To(Succeed())

		// A genuinely pending subject as the positive control.
		csrPEM, err = testutil.GenerateCSR("idx-pending")
		Expect(err).NotTo(HaveOccurred())
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("PUT", "/certificate_request/idx-pending", bytes.NewReader(csrPEM)))
		Expect(rr.Code).To(Equal(http.StatusOK))

		// Unfiltered: the certificate wins; idx-dual appears exactly once.
		all := getStatuses("")
		states := map[string]string{}
		for _, s := range all {
			states[s.Name] = s.State
		}
		Expect(all).To(HaveLen(2))
		Expect(states).To(Equal(map[string]string{
			"idx-dual":    "signed",
			"idx-pending": "requested",
		}))

		// Under the requested filter the certified subject must stay
		// suppressed even though no certificate rows are emitted.
		requested := getStatuses("?state=requested")
		Expect(requested).To(HaveLen(1))
		Expect(requested[0].Name).To(Equal("idx-pending"))
	})

	It("serialises an empty index as [] and projects a promoted CN SAN", func() {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", "/certificate_statuses/any", nil))
		Expect(rr.Code).To(Equal(http.StatusOK))
		Expect(rr.Body.String()).To(MatchJSON("[]"))

		// A SAN-less CSR gets its CN promoted to a DNS SAN at signing
		// (PromoteCNToSAN); the index must reflect the certificate as issued,
		// not the CSR as submitted.
		submitAndSign("idx-plain", generateCSRWithSANs("idx-plain", nil))
		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		Expect(statuses[0].DNSAltNames).To(Equal([]string{"idx-plain"}))
	})
})
