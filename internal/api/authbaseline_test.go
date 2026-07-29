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
// It records, exhaustively, which client certificates the middleware admits to
// which routes as the code stands today. Later work changes that deliberately
// in a small number of places — scoping identity claims to the issuing CA,
// gating renewal on our own certificates, moving certificate_status to
// admin-only — and the value of this table is that it was written and committed
// *before* those changes, so it says what the behaviour was rather than what
// someone later believed it should be.
//
// Every row carries an expectChanged flag, currently false everywhere. A change
// that intends to alter a row flips the flag in the same commit; a change that
// alters a row without flipping it fails here. That distinction — deliberate
// versus accidental — is the whole point, and a blanket "nothing changes"
// assertion could not express it.

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
	// expectChanged marks rows a later change is permitted to alter. Flip it in
	// the same commit that changes the behaviour, never before and never after.
	expectChanged bool
}

// deniedStatus reports whether code is the middleware's rejection.
//
// The middleware answers 403 for every authorisation failure and nothing else
// does on these routes, so 403 is a reliable signal. Handler-level outcomes
// (404 for an absent subject, 400 for a malformed body) all mean the request
// got past authorisation, which is what this table measures.
func deniedStatus(code int) bool { return code == http.StatusForbidden }

var _ = Describe("Authorisation baseline", Ordered, func() {
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
		// on evaluation order is worse than no oracle. Minting per route costs a
		// few key generations and buys independence.
		newClasses = func() []clientClass {
			return []clientClass{
				{name: "none", cert: nil},
				{name: "own-ca-plain", cert: issueClientCert(selfName, caCert, caKey)},
				{name: "own-ca-allowlisted", cert: issueClientCert("puppet-server", caCert, caKey)},
				{name: "own-ca-pp-cli-auth", cert: issueClientCertWithPpCliAuth("cli-user", caCert, caKey)},
				{name: "own-ca-expired", cert: expiredClientCert("stale", caCert, caKey)},
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
				"own-ca-pp-cli-auth": false, "own-ca-expired": false,
				"own-ca-revoked": false, "foreign-ca": false,
			},
		},
		{
			name: "public: fetch the CRL", method: "GET", path: "/certificate_revocation_list/ca",
			denied: map[string]bool{
				"none": false, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-expired": false,
				"own-ca-revoked": false, "foreign-ca": false,
			},
		},
		{
			name: "public: submit a CSR", method: "PUT", path: "/certificate_request/newnode",
			denied: map[string]bool{
				"none": false, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-expired": false,
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
				"own-ca-pp-cli-auth": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "any-client: renew own certificate", method: "POST", path: "/certificate_renewal",
			denied: map[string]bool{
				"none": true, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			// Self-match: the CN must equal the path subject, or the caller must
			// be an admin.
			name: "self-or-admin: read own CSR", method: "GET", path: "/certificate_request/" + selfName,
			denied: map[string]bool{
				"none": true, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "self-or-admin: read another node's CSR", method: "GET", path: "/certificate_request/othernode",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "admin: list all statuses", method: "GET", path: "/certificate_statuses/all",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "admin: sign all pending", method: "POST", path: "/sign/all",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
		{
			name: "admin: reissue the CRL", method: "PUT", path: "/certificate_revocation_list/ca",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-expired": true,
				"own-ca-revoked": true, "foreign-ca": true,
			},
		},
	}

	It("records the outcome of every client class against every route", func() {
		for _, route := range routes {
			for _, class := range newClasses() {
				want, ok := route.denied[class.name]
				Expect(ok).To(BeTrue(),
					"route %q has no recorded outcome for client class %q; every combination must be stated",
					route.name, class.name)

				req := httptest.NewRequest(route.method, route.path, strings.NewReader(""))
				if class.cert != nil {
					req = withClientCert(req, class.cert)
				}
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)

				got := deniedStatus(rec.Code)
				if route.expectChanged {
					// A row flagged as intentionally changed is exercised but not
					// asserted here; the commit that flips the flag owns the new
					// expectation and asserts it directly.
					continue
				}
				Expect(got).To(Equal(want),
					"route %q, client %q: recorded denied=%v but got denied=%v (HTTP %d).\n"+
						"If this change is intended, set expectChanged on the row in the same commit.",
					route.name, class.name, want, got, rec.Code)
			}
		}
	})

	It("states an outcome for every route and client class", func() {
		// Guards the table itself: a route added without outcomes, or a client
		// class added without extending every route, would otherwise silently
		// test less than it appears to.
		want := len(newClasses())
		for _, route := range routes {
			Expect(route.denied).To(HaveLen(want),
				"route %q records %d outcomes but there are %d client classes",
				route.name, len(route.denied), want)
		}
	})
})

// expiredClientCert issues a certificate that expired an hour ago.
func expiredClientCert(cn string, caCert *x509.Certificate, caKey *rsa.PrivateKey) *x509.Certificate {
	GinkgoHelper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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
// this CA's own namespace also uses. Today it is rejected because that CA is
// not a trust anchor; the CN collision is what makes the row meaningful once
// more than one issuer can be trusted.
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
