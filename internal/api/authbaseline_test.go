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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// This file is an authorisation *oracle*, not a feature test.
//
// It records which client certificates the middleware admits to which routes as
// the code stands today. Later work changes that deliberately in a small number
// of places — scoping identity claims to the issuing CA, gating renewal on our
// own certificates, moving certificate_status to admin-only — and the value of
// this table is that it was written and committed *before* those changes, so it
// says what the behaviour was rather than what someone later believed it should
// be.
//
// Rows are always asserted. A change that intends to alter one updates the
// recorded outcome and records why in changedBy, in the same commit; a change
// that alters one without doing so fails here. That distinction — deliberate
// versus accidental — is the whole point, and a blanket "nothing changes"
// assertion could not express it.
//
// changedBy is documentation, not an exemption. An earlier draft carried a
// boolean that skipped assertion for flagged rows, which would have left
// exactly the rows under active change as the only unasserted ones — and on
// `GET /certificate_status/{subject}`, where one cell of seven moves, it would
// have silently retired the foreign-issuer, expired and revoked cells on the
// very route being restructured.
//
// Scope, stated plainly so nobody mistakes this for total coverage:
//
//   - 10 of the 19 routes registered by Routes(). The omitted ones are OCSP and
//     the health probes (public and uninteresting here), and duplicates of a
//     tier already represented by another row.
//   - Both the bare and the /puppet-ca/v1-prefixed forms of each path, which
//     the mux registers separately — see the prefix spec below.
//   - The default AuthConfig, plus the two flags that move a tier
//     (AllowPublicStatus, NoPpCliAuth), covered in their own Describe rather
//     than by multiplying every row.
//
// A second, overlapping oracle lives in auth_test.go ("authorisation matrix"),
// which drives lookupTier directly rather than through the mux. That one pins
// tier assignment; this one pins the observable HTTP outcome. Keep them in
// step: a tier change should move a row in both.

// clientClass is one kind of client certificate the middleware might see.
type clientClass struct {
	name string
	// cert is nil for "no client certificate at all".
	cert *x509.Certificate
}

// routeCase is one endpoint, with the outcome expected for each client class.
type routeCase struct {
	name   string
	method string
	path   string
	// denied maps clientClass.name to whether the middleware rejects it.
	denied map[string]bool
	// changedBy names the change that last altered this row's outcomes, empty
	// for rows still at their original recorded values. Always asserted either
	// way; this only says why a value differs from the first recording.
	changedBy string
}

// middlewareDenied reports whether the response is the *middleware's* rejection.
//
// Status alone is not enough. Handlers on these routes return 403 of their own —
// handlePostCertificateRenewal does so twice (handlers.go:903, :955), and
// handleGetCert once — so a bare code check would record a handler outcome as an
// authorisation outcome and the table would drift without failing. The
// middleware's two messages are matched exactly instead. Note "client
// certificate required" is a strict prefix of the renewal handler's "client
// certificate required for renewal", so this must not become a prefix match.
//
// Every other outcome (404 for an absent subject, 400 for a malformed body)
// means the request got past authorisation, which is what this table measures.
func middlewareDenied(rec *httptest.ResponseRecorder) bool {
	if rec.Code != http.StatusForbidden {
		return false
	}
	switch strings.TrimSpace(rec.Body.String()) {
	case "client certificate required", "access denied":
		return true
	default:
		return false
	}
}

var _ = Describe("Authorisation baseline", Ordered, ContinueOnFailure, func() {
	var (
		ctx        context.Context
		myCA       *ca.CA
		store      *storage.StorageService
		mux        http.Handler
		caCert     *x509.Certificate
		caKey      *rsa.PrivateKey
		newClasses func() []clientClass
		selfName   = "agent1"
	)

	BeforeAll(func() {
		ctx = context.Background()
		tmpDir := GinkgoT().TempDir()

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		// The revoked fixture is issued through the CA, so leaf generation is on
		// the fixture path. Nothing here depends on the leaf algorithm and ECDSA
		// is an order of magnitude cheaper to generate than RSA.
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		block, _ := pem.Decode(cachedCrtPEM)
		var err error
		caCert, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		block, _ = pem.Decode(cachedKeyPEM)
		caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			CACert:    caCert,
			AllowList: map[string]bool{"puppet-server": true},
		}
		mux = server.Routes()

		// Fresh certificates per route, not one shared set.
		//
		// Some routes mutate CA state as a side effect of succeeding: POST
		// /certificate_renewal reissues the caller's certificate and, because
		// RevokeOnAutoRenew defaults to true, revokes the one presented. Reusing
		// certificates across routes therefore makes every later outcome depend
		// on which earlier routes ran — an oracle that changes its answers based
		// on evaluation order is worse than no oracle.
		//
		// The *keys*, though, are generated once and reused. What must be fresh
		// is the certificate — its serial is what the CRL names — and RSA key
		// generation is the whole cost of minting one. Re-minting per route with
		// cached keys keeps the independence and takes the matrix from ~130 key
		// generations to eight.
		keyPool := newRSAKeyPool(4)

		newClasses = func() []clientClass {
			return []clientClass{
				{name: "none", cert: nil},
				{name: "own-ca-plain", cert: clientCertFromKey(keyPool[0], selfName, caCert, caKey, false, false)},
				{name: "own-ca-allowlisted", cert: clientCertFromKey(keyPool[1], "puppet-server", caCert, caKey, false, false)},
				{name: "own-ca-pp-cli-auth", cert: clientCertFromKey(keyPool[2], "cli-user", caCert, caKey, true, false)},
				// Admin by both routes at once, which is the shipped topology-A
				// arrangement: the Puppet Server's own CN is allow-listed and it
				// also presents pp_cli_auth. It exists to catch a change that
				// makes the two grants exclusive rather than additive.
				{name: "own-ca-admin-both", cert: clientCertFromKey(keyPool[3], "puppet-server", caCert, caKey, true, false)},
				{name: "own-ca-expired", cert: clientCertFromKey(keyPool[0], "stale", caCert, caKey, false, true)},
				{name: "own-ca-revoked", cert: revokedClientCert(ctx, myCA)},
				{name: "foreign-ca", cert: foreignClientCert(selfName)},
			}
		}
	})

	// The recorded outcomes. Reading a column top to bottom describes what one
	// kind of client may do; reading a row describes who may reach one endpoint.
	routes := []routeCase{
		{
			name: "public: fetch the CA certificate", method: "GET", path: "/certificate/ca",
			denied: map[string]bool{
				"none": false, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": false,
				"own-ca-revoked": false, "foreign-ca": false,
			},
		},
		{
			name: "public: fetch the CRL", method: "GET", path: "/certificate_revocation_list/ca",
			denied: map[string]bool{
				"none": false, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": false,
				"own-ca-revoked": false, "foreign-ca": false,
			},
		},
		{
			name: "public: submit a CSR", method: "PUT", path: "/certificate_request/newnode",
			denied: map[string]bool{
				"none": false, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": false,
				"own-ca-revoked": false, "foreign-ca": false,
			},
		},
		{
			// Any certificate that chains to our trust anchor is admitted, with
			// no check that the subject matches the caller. Scoped to our own CA
			// only because ours is the only issuer configured today.
			name: "any-client: read a certificate status", method: "GET", path: "/certificate_status/somenode",
			denied: map[string]bool{
				"none": true, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "any-client: renew own certificate", method: "POST", path: "/certificate_renewal",
			denied: map[string]bool{
				"none": true, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			// Self-match: the CN must equal the path subject, or the caller must
			// be an admin.
			name: "self-or-admin: read own CSR", method: "GET", path: "/certificate_request/" + selfName,
			denied: map[string]bool{
				"none": true, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "self-or-admin: read another node's CSR", method: "GET", path: "/certificate_request/othernode",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "admin: list all statuses", method: "GET", path: "/certificate_statuses/all",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "admin: sign all pending", method: "POST", path: "/sign/all",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "admin: reissue the CRL", method: "PUT", path: "/certificate_revocation_list/ca",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
	}

	// probe runs one route against one client class at pathPrefix and reports
	// whether the middleware rejected it.
	probe := func(route routeCase, class clientClass, pathPrefix string) bool {
		req := httptest.NewRequest(route.method, pathPrefix+route.path, strings.NewReader(""))
		if class.cert != nil {
			req = withClientCert(req, class.cert)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return middlewareDenied(rec)
	}

	// One Entry per route rather than a doubly-nested loop inside a single It.
	// Two reasons, both about what happens when a change lands: Gomega aborts a
	// spec at the first failed Expect, so a single It would report one moved
	// cell and stop — defeating the point of a table whose job is to enumerate
	// everything that moved. And every mismatching cell within a route is
	// collected before asserting, so one route reports all of its own
	// disagreements at once.
	routeEntries := make([]TableEntry, 0, len(routes))
	for _, route := range routes {
		routeEntries = append(routeEntries, Entry(route.name, route))
	}

	DescribeTable("records the outcome of every client class",
		func(route routeCase) {
			var mismatches []string
			for _, class := range newClasses() {
				want, ok := route.denied[class.name]
				Expect(ok).To(BeTrue(),
					"route %q has no recorded outcome for client class %q; every combination must be stated",
					route.name, class.name)

				if got := probe(route, class, ""); got != want {
					mismatches = append(mismatches,
						fmt.Sprintf("  client %q: recorded denied=%v, got denied=%v", class.name, want, got))
				}
			}
			provenance := "still at its originally recorded values"
			if route.changedBy != "" {
				provenance = "last changed by: " + route.changedBy
			}
			Expect(mismatches).To(BeEmpty(),
				"route %q no longer matches the recorded baseline:\n%s\n\n"+
					"This row was %s.\n"+
					"If this change is intended, update the recorded outcome and set changedBy "+
					"on the row in the same commit.",
				route.name, strings.Join(mismatches, "\n"), provenance)
		},
		routeEntries,
	)

	It("applies the same authorisation at the /puppet-ca/v1 prefix", func() {
		// Routes() registers every path twice, bare and prefixed, against the
		// same handler. That is half the registered mux, and nothing else here
		// touches it: a prefix-sensitive change to lookupTier — which matches on
		// path prefixes — would move the prefixed surface alone and go unnoticed.
		//
		// Compared against the same recorded table rather than a second copy of
		// it, so the two cannot drift.
		for _, route := range routes {
			for _, class := range newClasses() {
				want := route.denied[class.name]
				Expect(probe(route, class, "/puppet-ca/v1")).To(Equal(want),
					"route %q at the /puppet-ca/v1 prefix, client %q: recorded denied=%v but the prefixed "+
						"path disagrees. Both forms must authorise identically.",
					route.name, class.name, want)
			}
		}
	})

	It("states an outcome for every route and client class", func() {
		// Guards the table itself: a route added without outcomes, or a client
		// class added without extending every route, would otherwise silently
		// test less than it appears to.
		//
		// The class list is pinned by name, not merely counted. Counting alone
		// lets an adversarial fixture be swapped out — delete "foreign-ca", add
		// a second benign class, and the length still matches while the row that
		// mattered is gone.
		Expect(classNames(newClasses())).To(Equal(expectedClientClasses))

		for _, route := range routes {
			Expect(route.denied).To(HaveLen(len(expectedClientClasses)),
				"route %q records %d outcomes but there are %d client classes",
				route.name, len(route.denied), len(expectedClientClasses))
			for _, name := range expectedClientClasses {
				_, ok := route.denied[name]
				Expect(ok).To(BeTrue(), "route %q has no recorded outcome for client class %q", route.name, name)
			}
		}
	})

	It("covers the routes it claims to", func() {
		// Pins the row list for the same reason as the class list: a row
		// silently dropped is coverage silently lost, and the count alone would
		// not notice a swap.
		names := make([]string, 0, len(routes))
		for _, route := range routes {
			names = append(names, route.name)
		}
		Expect(names).To(Equal(expectedRoutes))
	})
})

// expectedClientClasses and expectedRoutes pin the shape of the matrix. They
// exist so that removing a fixture is a deliberate edit to a named list rather
// than an invisible reduction in what the oracle covers.
var expectedClientClasses = []string{
	"none",
	"own-ca-plain",
	"own-ca-allowlisted",
	"own-ca-pp-cli-auth",
	"own-ca-admin-both",
	"own-ca-expired",
	"own-ca-revoked",
	"foreign-ca",
}

var expectedRoutes = []string{
	"public: fetch the CA certificate",
	"public: fetch the CRL",
	"public: submit a CSR",
	"any-client: read a certificate status",
	"any-client: renew own certificate",
	"self-or-admin: read own CSR",
	"self-or-admin: read another node's CSR",
	"admin: list all statuses",
	"admin: sign all pending",
	"admin: reissue the CRL",
}

func classNames(classes []clientClass) []string {
	names := make([]string, 0, len(classes))
	for _, c := range classes {
		names = append(names, c.name)
	}
	return names
}

// newRSAKeyPool generates n reusable client keys.
//
// Key generation dominates fixture cost and nothing in the middleware cares
// which key a certificate binds, so the pool is built once and every minted
// certificate draws from it.
func newRSAKeyPool(n int) []*rsa.PrivateKey {
	GinkgoHelper()
	pool := make([]*rsa.PrivateKey, n)
	for i := range pool {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		pool[i] = key
	}
	return pool
}

// clientCertFromKey mints a client certificate for cn against an existing key,
// optionally carrying the pp_cli_auth extension or already expired.
func clientCertFromKey(key *rsa.PrivateKey, cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey,
	ppCliAuth, expired bool,
) *x509.Certificate {
	GinkgoHelper()
	notBefore, notAfter := time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour)
	if expired {
		notBefore, notAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if ppCliAuth {
		// ASN.1-encoded, not a bare string: hasPpCliAuth unmarshals the value,
		// so a raw []byte("true") parses as absent and the certificate silently
		// stops being an admin — which the oracle catches, being an oracle.
		extValue, err := asn1.Marshal("true")
		Expect(err).NotTo(HaveOccurred())
		template.ExtraExtensions = []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39},
			Value: extValue,
		}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// revokedClientCert issues a certificate through the CA and then revokes it, so
// it is genuinely present in the CRL rather than merely absent from storage.
func revokedClientCert(ctx context.Context, myCA *ca.CA) *x509.Certificate {
	GinkgoHelper()
	// A distinct subject each time: Generate refuses to reissue for a subject
	// that already holds a valid certificate.
	cn := fmt.Sprintf("revoked%d", time.Now().UnixNano())
	res, err := myCA.Generate(ctx, cn, nil)
	Expect(err).NotTo(HaveOccurred())
	Expect(myCA.Revoke(ctx, cn)).To(Succeed())

	block, _ := pem.Decode(res.CertificatePEM)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// foreignClientCert issues a certificate from an unrelated CA, carrying a CN
// this CA's own namespace also uses.
//
// What this row pins is narrow, and worth stating so it is not mistaken for
// more: an issuer that is not configured as a trust anchor is rejected. It
// cannot demonstrate that a *trusted* second issuer fails to inherit identity
// claims, because this fixture's CA will still be unconfigured after that work
// lands — the row would keep passing either way. The cross-issuer case needs a
// certificate from an issuer the server has been told to trust, which is a
// fixture the change that introduces multiple trust anchors has to bring with
// it. The CN collision here is deliberate groundwork for that, not the test.
func foreignClientCert(cn string) *x509.Certificate {
	GinkgoHelper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Unrelated CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	foreignCA, err := x509.ParseCertificate(caDER)
	Expect(err).NotTo(HaveOccurred())

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, foreignCA, &leafKey.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	leaf, err := x509.ParseCertificate(leafDER)
	Expect(err).NotTo(HaveOccurred())
	return leaf
}

// The two AuthConfig flags that move a route between tiers get their own
// Describe rather than a third dimension on the main table. Multiplying every
// row by every flag would triple the fixtures to record four cells that
// actually differ, and would bury them.
//
// Both matter to the later work: AllowPublicStatus and the certificate_status
// tier change touch the same route from opposite directions, and NoPpCliAuth is
// the one input that *narrows* admin authority, so a restructure that drops it
// or wires it per-issuer would otherwise be recorded nowhere.
var _ = Describe("Authorisation baseline: configuration axes", Ordered, ContinueOnFailure, func() {
	var (
		ctx    context.Context
		caCert *x509.Certificate
		caKey  *rsa.PrivateKey
		myCA   *ca.CA
	)

	BeforeAll(func() {
		ctx = context.Background()
		store := storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		// The revoked fixture is issued through the CA, so leaf generation is on
		// the fixture path. Nothing here depends on the leaf algorithm and ECDSA
		// is an order of magnitude cheaper to generate than RSA.
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		block, _ := pem.Decode(cachedCrtPEM)
		var err error
		caCert, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		block, _ = pem.Decode(cachedKeyPEM)
		caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	// muxWith builds a handler under a specific AuthConfig.
	muxWith := func(cfg *api.AuthConfig) http.Handler {
		server := api.New(myCA)
		server.AuthConfig = cfg
		return server.Routes()
	}

	probe := func(handler http.Handler, method, path string, cert *x509.Certificate) bool {
		req := httptest.NewRequest(method, path, strings.NewReader(""))
		if cert != nil {
			req = withClientCert(req, cert)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return middlewareDenied(rec)
	}

	Describe("allow_public_status", func() {
		It("denies a client with no certificate when unset", func() {
			handler := muxWith(&api.AuthConfig{CACert: caCert, AllowList: map[string]bool{"puppet-server": true}})
			Expect(probe(handler, "GET", "/certificate_status/somenode", nil)).To(BeTrue())
		})

		It("admits a client with no certificate when set", func() {
			// The flag moves the route to tierPublic outright. Recorded because
			// the same route is the one moving to admin-only, and the two
			// changes must not silently cancel out: an operator with this flag
			// set should still get public status afterwards, or be told plainly
			// that the flag no longer does anything.
			handler := muxWith(&api.AuthConfig{
				CACert:            caCert,
				AllowList:         map[string]bool{"puppet-server": true},
				AllowPublicStatus: true,
			})
			Expect(probe(handler, "GET", "/certificate_status/somenode", nil)).To(BeFalse())
		})
	})

	Describe("no_pp_cli_auth", func() {
		It("grants admin on the pp_cli_auth extension when unset", func() {
			handler := muxWith(&api.AuthConfig{CACert: caCert, AllowList: map[string]bool{"puppet-server": true}})
			cert := issueClientCertWithPpCliAuth("cli-user", caCert, caKey)
			Expect(probe(handler, "PUT", "/certificate_revocation_list/ca", cert)).To(BeFalse())
		})

		It("refuses that grant when set, leaving only the CN allow list", func() {
			// The one input that narrows admin authority. Every cell in the main
			// table is computed with this false, so without this pair a change
			// that dropped the flag would move nothing the oracle watches.
			handler := muxWith(&api.AuthConfig{
				CACert:      caCert,
				AllowList:   map[string]bool{"puppet-server": true},
				NoPpCliAuth: true,
			})
			byExtension := issueClientCertWithPpCliAuth("cli-user", caCert, caKey)
			Expect(probe(handler, "PUT", "/certificate_revocation_list/ca", byExtension)).To(BeTrue())

			byAllowList := issueClientCert("puppet-server", caCert, caKey)
			Expect(probe(handler, "PUT", "/certificate_revocation_list/ca", byAllowList)).To(BeFalse(),
				"the CN allow list must still grant admin when the extension does not")
		})
	})
})
