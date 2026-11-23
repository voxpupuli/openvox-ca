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
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// unknownStateBackend wraps a real structured backend, rewriting one
// subject's Statuses record to CertStateUnknown — the value the etcd backend
// reports for serials its one-to-one by-serial index cannot address
// (duplicates imported from a legacy blob). Everything else delegates
// unchanged.
type unknownStateBackend struct {
	*storage.SQLBackend
	subject string
}

func (b *unknownStateBackend) Statuses(ctx context.Context, stateFilter string) ([]storage.CertRecord, error) {
	recs, err := b.SQLBackend.Statuses(ctx, stateFilter)
	for i := range recs {
		if recs[i].Subject == b.subject {
			recs[i].State = storage.CertStateUnknown
			recs[i].RevokedAt = nil
		}
	}
	return recs, err
}

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
		// These fixtures sign CSRs that request DNS alt names, which the default
		// policy refuses; the index projection under test is what needs them.
		myCA.AllowSubjectAltNames = true

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
		// Rendered as OpenVox Server renders them: the fingerprint in upper
		// case, each DNS SAN prefixed.
		wantFP := strings.ToUpper(ca.SHA256ColonFingerprint(block.Bytes))
		wantSANs := []string{"DNS:idx-node.example.com", "DNS:idx-node.alt.example.com"}

		Expect(got.Name).To(Equal("idx-node"))
		Expect(got.State).To(Equal("signed"))
		Expect(got.Fingerprint).To(Equal(wantFP))
		Expect(got.Fingerprints).To(Equal(map[string]string{"SHA256": wantFP, "default": wantFP}))
		Expect(got.DNSAltNames).To(Equal(wantSANs))
		Expect(got.SubjectAltNames).To(Equal(wantSANs))
		Expect(got.AuthorizationExtensions).To(BeEmpty())
		Expect(got.AuthorizationExtensions).NotTo(BeNil())
		Expect(got.SerialNumber).NotTo(BeNil())
		Expect(got.SerialNumber.Cmp(cert.SerialNumber)).To(BeZero())
		Expect(got.NotBefore).NotTo(BeNil())
		Expect(*got.NotBefore).To(Equal(cert.NotBefore.UTC().Format(time.RFC3339)))
		Expect(got.NotAfter).NotTo(BeNil())
		Expect(*got.NotAfter).To(Equal(cert.NotAfter.UTC().Format(time.RFC3339)))
	})

	Context("with status_fingerprint_algorithms set", func() {
		both := []ca.FingerprintAlgorithm{ca.FingerprintSHA1, ca.FingerprintSHA512}

		// serveWith rebuilds the routes with the server reporting algs.
		serveWith := func(algs []ca.FingerprintAlgorithm) {
			srv := api.New(myCA)
			srv.StatusFingerprintAlgorithms = algs
			mux = srv.Routes()
		}

		storedDER := func(subject string) []byte {
			certPEM, err := store.GetCert(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())
			return block.Bytes
		}

		upper := func(alg ca.FingerprintAlgorithm, der []byte) string {
			return strings.ToUpper(ca.ColonFingerprint(alg, der))
		}

		It("answers from the index row's fingerprints", func() {
			myCA.StatusFingerprintAlgorithms = both
			serveWith(both)
			submitAndSign("fp-node", generateCSRWithSANs("fp-node", []string{"fp-node.example.com"}))

			// Overwrite the row's SHA-1 with a value no certificate has, so the
			// response can only carry it if it was read from the index.
			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			proj := recs[0].CertProjection
			proj.Fingerprints = map[string]string{"SHA1": "0a:0b", "SHA512": proj.Fingerprints["SHA512"]}
			Expect(store.SetCertProjection(ctx, recs[0].Serial, proj)).To(Succeed())

			statuses := getStatuses("")
			Expect(statuses).To(HaveLen(1))
			fp := strings.ToUpper(ca.SHA256ColonFingerprint(storedDER("fp-node")))
			Expect(statuses[0].Fingerprints).To(Equal(map[string]string{
				"SHA256": fp, "default": fp,
				"SHA1":   "0A:0B",
				"SHA512": upper(ca.FingerprintSHA512, storedDER("fp-node")),
			}))
		})

		It("falls back to the stored PEM for a row projected before a digest was configured", func() {
			// The CA projects SHA-256 only, as every row is before the setting is
			// first turned on; the repair pass that adds the rest runs at startup.
			serveWith(both)
			submitAndSign("old-node", generateCSRWithSANs("old-node", []string{"old-node.example.com"}))

			statuses := getStatuses("")
			Expect(statuses).To(HaveLen(1))
			der := storedDER("old-node")
			fp := strings.ToUpper(ca.SHA256ColonFingerprint(der))
			Expect(statuses[0].Fingerprints).To(Equal(map[string]string{
				"SHA256": fp, "default": fp,
				"SHA1":   upper(ca.FingerprintSHA1, der),
				"SHA512": upper(ca.FingerprintSHA512, der),
			}))

			// A status read never writes: filling the row is the startup
			// repair pass's job.
			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].Fingerprints).To(BeNil(), "the read must leave the row as it was")
		})

		It("falls back to the stored PEM for a row holding some of the configured digests", func() {
			myCA.StatusFingerprintAlgorithms = []ca.FingerprintAlgorithm{ca.FingerprintSHA1}
			serveWith(both)
			submitAndSign("part-node", generateCSRWithSANs("part-node", []string{"part-node.example.com"}))
			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].Fingerprints).To(HaveKey("SHA1"), "the row must hold some of the configured digests")
			Expect(recs[0].Fingerprints).NotTo(HaveKey("SHA512"), "and lack the rest")

			statuses := getStatuses("")
			Expect(statuses).To(HaveLen(1))
			der := storedDER("part-node")
			fp := strings.ToUpper(ca.SHA256ColonFingerprint(der))
			Expect(statuses[0].Fingerprints).To(Equal(map[string]string{
				"SHA256": fp, "default": fp,
				"SHA1":   upper(ca.FingerprintSHA1, der),
				"SHA512": upper(ca.FingerprintSHA512, der),
			}), "SHA512 must come from the PEM, not as an empty string from the row")
		})

		It("reports them for a stored certificate with no index row", func() {
			// The crash-window shape of "lists a certificate that has no index
			// row at all", below: answered from the stored PEM, with every
			// configured digest.
			serveWith(both)
			submitAndSign("rowless-node", generateCSRWithSANs("rowless-node", []string{"rowless-node.example.com"}))
			_, err := store.PruneInventory(ctx, func(storage.InventoryEntry) bool { return false })
			Expect(err).NotTo(HaveOccurred())

			statuses := getStatuses("")
			Expect(statuses).To(HaveLen(1))
			der := storedDER("rowless-node")
			fp := strings.ToUpper(ca.SHA256ColonFingerprint(der))
			Expect(statuses[0].Fingerprints).To(Equal(map[string]string{
				"SHA256": fp, "default": fp,
				"SHA1":   upper(ca.FingerprintSHA1, der),
				"SHA512": upper(ca.FingerprintSHA512, der),
			}))
		})

		It("reports only the configured digests, whatever the row holds", func() {
			myCA.StatusFingerprintAlgorithms = both
			serveWith(nil)
			submitAndSign("was-node", generateCSRWithSANs("was-node", []string{"was-node.example.com"}))
			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].Fingerprints).To(HaveKey("SHA1"), "the row must hold digests the server does not report")
			Expect(recs[0].Fingerprints).To(HaveKey("SHA512"))

			statuses := getStatuses("")
			Expect(statuses).To(HaveLen(1))
			fp := strings.ToUpper(ca.SHA256ColonFingerprint(storedDER("was-node")))
			Expect(statuses[0].Fingerprints).To(Equal(map[string]string{"SHA256": fp, "default": fp}))
		})
	})

	It("lists an imported certificate's IP SANs from the index exactly as from the stored PEM", func() {
		// Imported rather than signed, so the fixture needs neither a CSR nor
		// allow_subject_alt_names: an import (or a migrated cadir) is one of
		// the ways a certificate carrying IP SANs reaches the index.
		keyBlock, _ := pem.Decode(cachedKeyPEM)
		Expect(keyBlock).NotTo(BeNil())
		caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		crtBlock, _ := pem.Decode(cachedCrtPEM)
		Expect(crtBlock).NotTo(BeNil())
		caCert, err := x509.ParseCertificate(crtBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(0x407),
			Subject:      pkix.Name{CommonName: "idx-ip"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			DNSNames:     []string{"idx-ip"},
			IPAddresses:  []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")},
		}, caCert, &leafKey.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.ImportCertificate(ctx, "idx-ip", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		Expect(err).NotTo(HaveOccurred())

		recs, indexed, err := store.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(indexed).To(BeTrue())
		Expect(recs).To(ConsistOf(HaveField("Fingerprint", Not(BeEmpty()))),
			"the listing must come from the index row, not the PEM fallback")

		want := []string{"IP:192.0.2.10", "IP:2001:db8::1", "DNS:idx-ip"}
		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		Expect(statuses[0].SubjectAltNames).To(Equal(want))
		Expect(statuses[0].DNSAltNames).To(Equal([]string{"DNS:idx-ip"}))

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", "/certificate_status/idx-ip", nil))
		Expect(rr.Code).To(Equal(http.StatusOK))
		var single api.CertStatusResponse
		Expect(json.Unmarshal(rr.Body.Bytes(), &single)).To(Succeed())
		Expect(single.SubjectAltNames).To(Equal(want), "the per-certificate path must agree")
	})

	It("lists only the IP and DNS SANs of a request and of the certificate signed from it", func() {
		// Signing copies all four SAN kinds, but the status response lists the
		// IP and DNS ones only, as OpenVox Server's does (docs/api.md). Pinned
		// in both states a request passes through: pending, where an operator
		// reviews it before signing, and signed, served from the index.
		spiffe, err := url.Parse("spiffe://example.com/idx-kinds")
		Expect(err).NotTo(HaveOccurred())
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:        pkix.Name{CommonName: "idx-kinds"},
			DNSNames:       []string{"idx-kinds.example.com"},
			IPAddresses:    []net.IP{net.ParseIP("192.0.2.30")},
			EmailAddresses: []string{"ops@example.com"},
			URIs:           []*url.URL{spiffe},
		}, key)
		Expect(err).NotTo(HaveOccurred())
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

		statusOf := func() api.CertStatusResponse {
			GinkgoHelper()
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest("GET", "/certificate_status/idx-kinds", nil))
			Expect(rr.Code).To(Equal(http.StatusOK))
			var st api.CertStatusResponse
			Expect(json.Unmarshal(rr.Body.Bytes(), &st)).To(Succeed())
			return st
		}
		want := []string{"IP:192.0.2.30", "DNS:idx-kinds.example.com"}

		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("PUT", "/certificate_request/idx-kinds", bytes.NewReader(csrPEM)))
		Expect(rr.Code).To(Equal(http.StatusOK))
		pending := statusOf()
		Expect(pending.State).To(Equal("requested"))
		Expect(pending.SubjectAltNames).To(Equal(want))
		Expect(pending.DNSAltNames).To(Equal([]string{"DNS:idx-kinds.example.com"}))

		body, err := json.Marshal(api.PutStatusBody{DesiredState: "signed"})
		Expect(err).NotTo(HaveOccurred())
		rr = httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("PUT", "/certificate_status/idx-kinds", bytes.NewReader(body)))
		Expect(rr.Code).To(Equal(http.StatusNoContent))

		// The fixture must really carry the kinds the response leaves out,
		// or the assertions below would hold for the wrong reason.
		cert := storedCert(ctx, store, "idx-kinds")
		Expect(cert.EmailAddresses).To(ConsistOf("ops@example.com"))
		Expect(cert.URIs).To(HaveLen(1))

		signed := statusOf()
		Expect(signed.State).To(Equal("signed"))
		Expect(signed.SubjectAltNames).To(Equal(want))
		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		Expect(statuses[0].SubjectAltNames).To(Equal(want), "the index listing must agree")
		Expect(statuses[0].DNSAltNames).To(Equal([]string{"DNS:idx-kinds.example.com"}))
	})

	It("encodes an indexed serial as a JSON number by default", func() {
		submitAndSign("idx-serial", generateCSRWithSANs("idx-serial", []string{"idx-serial"}))
		cert := storedCert(ctx, store, "idx-serial")

		Expect(rawStatusSerials(mux, "/certificate_statuses/any")).To(
			HaveKeyWithValue("idx-serial", cert.SerialNumber.String()))
	})

	// Each of the index path's three ways of building a status carries the
	// format separately, so each needs its own entry, and each entry checks
	// that the index now serves the row that sends it down its branch: an
	// entry whose damage did not take would pass through the first branch.
	DescribeTable("encodes the serial as colon-separated hex when the server opts in",
		func(damage func(subject string), served types.GomegaMatcher) {
			submitAndSign("idx-hex", generateCSRWithSANs("idx-hex", []string{"idx-hex"}))
			damage("idx-hex")
			cert := storedCert(ctx, store, "idx-hex")

			recs, indexed, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(indexed).To(BeTrue())
			Expect(recs).To(served, "the index must serve the row this entry is named for")

			srv := api.New(myCA)
			srv.SerialNumberFormat = api.SerialNumberAsHex
			Expect(rawStatusSerials(srv.Routes(), "/certificate_statuses/any")).To(
				HaveKeyWithValue("idx-hex", `"`+wantColonHex(cert.SerialNumber)+`"`))
		},
		Entry("from the index row", func(string) {},
			ConsistOf(HaveField("Fingerprint", Not(BeEmpty())))),
		Entry("from the stored PEM, for a projection-less row", func(subject string) {
			Expect(store.AppendInventory(ctx,
				"0FFF 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /"+subject)).To(Succeed())
		}, ConsistOf(HaveField("Fingerprint", BeEmpty()))),
		Entry("from the stored PEM, for a certificate with no row at all", func(string) {
			_, err := store.PruneInventory(ctx, func(storage.InventoryEntry) bool { return false })
			Expect(err).NotTo(HaveOccurred())
		}, BeEmpty()),
	)

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

	It("reports a revocation the index row has not caught up with", func() {
		// State comes from the signed CRL, not from the index row. The write that
		// maintains the row is best-effort -- markCertRevokedIndex logs and carries
		// on -- and the repair pass that reconciles it runs only at startup, so a
		// swallowed write used to make this listing disagree with
		// GET /certificate_status/<subject> for as long as the process ran.
		submitAndSign("idx-lagging", generateCSRWithSANs("idx-lagging", []string{"idx-lagging"}))
		Expect(myCA.Revoke(ctx, "idx-lagging")).To(Succeed())

		// Undo the projection, leaving the CRL as the only record of the fact.
		recs, _, err := store.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(recs).To(HaveLen(1))
		Expect(store.ClearCertRevoked(ctx, recs[0].Serial)).To(Succeed())

		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		Expect(statuses[0].State).To(Equal("revoked"),
			"the CRL is the signed fact; the row is a projection that can lag it")

		// And the filter agrees with the body, rather than filtering on the row.
		Expect(getStatuses("?state=revoked")).To(HaveLen(1))
		Expect(getStatuses("?state=signed")).To(BeEmpty())
	})

	It("lists a certificate that has no index row at all", func() {
		// Statuses reports the intersection of stored certificates and inventory
		// rows, so the crash window between those two writes leaves a subject the
		// index cannot see. The scan path lists it from the blobs, and without the
		// same treatment here the certificate vanished on SQL backends -- and its
		// pending CSR was then reported as "requested" for a host that already
		// holds a certificate this CA serves.
		submitAndSign("idx-rowless", generateCSRWithSANs("idx-rowless", []string{"idx-rowless"}))

		// Drop the inventory rows, keeping the certificate blob -- the state the
		// crash window leaves, reached here by pruning everything.
		_, err := store.PruneInventory(ctx, func(storage.InventoryEntry) bool { return false })
		Expect(err).NotTo(HaveOccurred())

		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		Expect(statuses[0].Name).To(Equal("idx-rowless"))
		Expect(statuses[0].State).To(Equal("signed"))
		Expect(statuses[0].Fingerprint).NotTo(BeEmpty(),
			"the display fields must come from the stored PEM")
	})

	It("falls back to the stored PEM for a projection-less record, re-deriving state from the served certificate", func() {
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
		Expect(got.Fingerprint).To(Equal(strings.ToUpper(ca.SHA256ColonFingerprint(block.Bytes))))
		Expect(got.SerialNumber).NotTo(BeNil())
		Expect(got.SerialNumber.Cmp(cert.SerialNumber)).To(BeZero(),
			"the serial must be the PEM's, not the projection-less row's")
		Expect(got.DNSAltNames).To(Equal([]string{"DNS:idx-legacy"}))
	})

	It("derives the fallback state from the certificate actually served, not the mismatched row", func() {
		// A projection-less row whose serial names a different certificate
		// forces the PEM fallback. The response is built from the stored PEM,
		// so its state must come from that certificate's serial too: deriving
		// it from the row's serial reported a revoked certificate as signed
		// and hid it from ?state=revoked.
		submitAndSign("idx-mismatch", generateCSRWithSANs("idx-mismatch", []string{"idx-mismatch"}))
		Expect(myCA.Revoke(ctx, "idx-mismatch")).To(Succeed())

		// The stale row's serial (0FFF) is not in the CRL; the stored
		// certificate's serial is.
		Expect(store.AppendInventory(ctx,
			"0FFF 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /idx-mismatch")).To(Succeed())

		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		Expect(statuses[0].State).To(Equal("revoked"),
			"the state must describe the served certificate, not the stale row")
		Expect(getStatuses("?state=revoked")).To(HaveLen(1))
		Expect(getStatuses("?state=signed")).To(BeEmpty())
	})

	It("returns a signed certificate to signed when only the stale row's serial is revoked", func() {
		// The mirror direction of the spec above: the fallback's re-derivation
		// must also flip a row-derived "revoked" back to "signed" when the
		// certificate actually served is not in the CRL — without it, a stale
		// row naming a revoked serial would over-report revocation for a
		// certificate the CA still stands behind. Revoke a donor subject,
		// then give another subject a projection-less row carrying the
		// zero-padded variant of the donor's serial: distinct as an inventory
		// string (the duplicate-serial guard rejects a verbatim copy) yet a
		// CRL hit through the same normalisation, so the row-derived state is
		// "revoked" while the served certificate is not.
		submitAndSign("idx-donor", generateCSRWithSANs("idx-donor", []string{"idx-donor"}))
		Expect(myCA.Revoke(ctx, "idx-donor")).To(Succeed())
		submitAndSign("idx-victim", generateCSRWithSANs("idx-victim", []string{"idx-victim"}))

		donorPEM, err := store.GetCert(ctx, "idx-donor")
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(donorPEM)
		Expect(block).NotTo(BeNil())
		donor, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		donorPadded := "00" + fmt.Sprintf("%X", donor.SerialNumber)
		Expect(store.AppendInventory(ctx,
			storage.FormatInventoryLine(donorPadded, donor.NotBefore, donor.NotAfter, "idx-victim"))).To(Succeed())

		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(2))
		states := map[string]string{}
		for _, s := range statuses {
			states[s.Name] = s.State
		}
		Expect(states).To(Equal(map[string]string{
			"idx-donor":  "revoked",
			"idx-victim": "signed",
		}), "the served certificate's serial decides the state, not the stale row's")

		signed := getStatuses("?state=signed")
		Expect(signed).To(HaveLen(1))
		Expect(signed[0].Name).To(Equal("idx-victim"))
		revoked := getStatuses("?state=revoked")
		Expect(revoked).To(HaveLen(1))
		Expect(revoked[0].Name).To(Equal("idx-donor"))
	})

	It("re-derives state from the served certificate when the row serial is not even hex", func() {
		// A non-hex row serial fails both normaliseSerial (so no CRL lookup
		// keys off the row) and certSerialIs (so the fallback treats it as a
		// mismatch). The revoked state of the certificate actually served must
		// still come through — under the pre-fix code the unparseable row's
		// "signed" default was carried into the response, so this spec fails
		// if the fallback re-derivation is removed.
		submitAndSign("idx-nonhex", generateCSRWithSANs("idx-nonhex", []string{"idx-nonhex"}))
		Expect(myCA.Revoke(ctx, "idx-nonhex")).To(Succeed())

		Expect(store.AppendInventory(ctx,
			"zz-not-hex 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /idx-nonhex")).To(Succeed())

		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		Expect(statuses[0].State).To(Equal("revoked"),
			"a row serial that cannot parse must not mask the served certificate's revocation")
		Expect(getStatuses("?state=revoked")).To(HaveLen(1))
		Expect(getStatuses("?state=signed")).To(BeEmpty())
	})

	It("matches a legacy zero-padded row serial against the CRL", func() {
		// The CRL-derived map is keyed by canonical %X serials, while a
		// blob-imported legacy inventory can carry the same serial
		// zero-padded. normaliseSerial is what makes the two meet, and this
		// is the one place it does real work: every other revoked serial in
		// the suite comes from live signing and is already canonical, so a
		// regression to identity comparison fails here and nowhere else.
		submitAndSign("idx-padded", generateCSRWithSANs("idx-padded", []string{"idx-padded"}))
		Expect(myCA.Revoke(ctx, "idx-padded")).To(Succeed())

		certPEM, err := store.GetCert(ctx, "idx-padded")
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Append a fully projected row naming the same certificate through a
		// zero-padded serial; being the latest issuance it is the row the
		// index serves, and its projection keeps the PEM fallback out of the
		// way so the state can only come from the padded-serial CRL match.
		proj := storage.CertProjection{
			Fingerprint:    ca.SHA256ColonFingerprint(block.Bytes),
			DNSAltNames:    cert.DNSNames,
			AuthExtensions: ca.AuthExtensionMap(cert.Extensions),
		}
		padded := "00" + fmt.Sprintf("%X", cert.SerialNumber)
		line := storage.FormatInventoryLine(padded, cert.NotBefore, cert.NotAfter, "idx-padded")
		Expect(store.AppendInventoryRecord(ctx, line, &proj)).To(Succeed())

		statuses := getStatuses("")
		Expect(statuses).To(HaveLen(1))
		Expect(statuses[0].State).To(Equal("revoked"),
			"a zero-padded row serial must still match the CRL's canonical key")
		Expect(getStatuses("?state=revoked")).To(HaveLen(1))
		Expect(getStatuses("?state=signed")).To(BeEmpty())
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

	It("derives an unknown-state record's state from the CRL", func() {
		// The etcd backend reports CertStateUnknown for serials it cannot
		// address one-to-one (duplicated legacy serials): index writes for
		// them are refused, so the record's stored state is meaningless and
		// the handler must consult the signed CRL instead. Simulate that with
		// a backend whose Statuses rewrites one subject's state to unknown.
		dir := GinkgoT().TempDir()
		inner, err := storage.NewSQLBackend(storage.SQLConfig{
			Dialect: storage.SQLitePure,
			DSN:     "file:" + filepath.Join(dir, "unknown.db"),
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = inner.Close() })
		store = storage.NewWithBackend(&unknownStateBackend{SQLBackend: inner, subject: "idx-ambig"}, dir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		// These fixtures sign CSRs that request DNS alt names, which the default
		// policy refuses; the index projection under test is what needs them.
		myCA.AllowSubjectAltNames = true
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())
		mux = api.New(myCA).Routes()

		submitAndSign("idx-ambig", generateCSRWithSANs("idx-ambig", []string{"idx-ambig"}))
		submitAndSign("idx-plainly-signed", generateCSRWithSANs("idx-plainly-signed", []string{"idx-plainly-signed"}))
		Expect(myCA.Revoke(ctx, "idx-ambig")).To(Succeed())

		// The record for idx-ambig reads as unknown from the index, but the
		// CRL says revoked — and the CRL must win.
		all := getStatuses("")
		states := map[string]string{}
		for _, s := range all {
			states[s.Name] = s.State
		}
		Expect(states).To(Equal(map[string]string{
			"idx-ambig":          "revoked",
			"idx-plainly-signed": "signed",
		}), "unknown must resolve against the CRL, never leak through as a state")

		revoked := getStatuses("?state=revoked")
		Expect(revoked).To(HaveLen(1))
		Expect(revoked[0].Name).To(Equal("idx-ambig"))
		signed := getStatuses("?state=signed")
		Expect(signed).To(HaveLen(1))
		Expect(signed[0].Name).To(Equal("idx-plainly-signed"))
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
		Expect(statuses[0].DNSAltNames).To(Equal([]string{"DNS:idx-plain"}))
	})
})
