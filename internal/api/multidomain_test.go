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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
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

// Every other AuthConfig in this suite holds exactly one trust domain — our
// own — so IsOwn() is unconditionally true and isAdmin only ever reads domain
// zero's grants. The per-domain decisions this MR exists to add are therefore
// invisible to the rest of the suite: widening isAdmin across domains, or
// dropping the IsOwn() scoping on the self-match, leaves it entirely green.
//
// These specs drive a two-domain AuthConfig through the real mux, so the tier
// switch runs against a certificate that was *trusted* and *foreign* — the one
// combination nothing else produces.
var _ = Describe("Authorisation across trust domains", func() {
	const ownSubject = "agent1"

	var (
		ctx        context.Context
		myCA       *ca.CA
		mux        http.Handler
		caCert     *x509.Certificate
		caKey      *rsa.PrivateKey
		foreignCA  *x509.Certificate
		foreignKey *ecdsa.PrivateKey
	)

	// foreignLeaf issues a client certificate from the foreign issuer, so it
	// verifies under that domain's anchor and no other.
	foreignLeaf := func(cn string, ppCliAuth bool) *x509.Certificate {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if ppCliAuth {
			v, err := asn1.Marshal("true")
			Expect(err).NotTo(HaveOccurred())
			tmpl.ExtraExtensions = []pkix.Extension{{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39},
				Value: v,
			}}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, foreignCA, &key.PublicKey, foreignKey)
		Expect(err).NotTo(HaveOccurred())
		leaf, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())
		return leaf
	}

	// foreignCRL is an empty, currently valid CRL from the foreign issuer.
	foreignCRL := func() *x509.RevocationList {
		GinkgoHelper()
		now := time.Now()
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now.Add(-time.Hour),
			NextUpdate: now.Add(24 * time.Hour),
		}, foreignCA, foreignKey)
		Expect(err).NotTo(HaveOccurred())
		crl, err := x509.ParseRevocationList(der)
		Expect(err).NotTo(HaveOccurred())
		return crl
	}

	// build wires a mux whose second trust domain is the foreign issuer, with
	// the grants under test.
	//
	// The domain is given a real, current CRL. The default revocation policy is
	// require, so without one every foreign client is rejected before the tier
	// switch is reached — which would make these specs pass for the wrong
	// reason. What is under test here is who is authorised; revocation itself is
	// clientcrl_test.go's job.
	build := func(foreignAdmins map[string]bool, foreignPpCliAuth bool) http.Handler {
		GinkgoHelper()
		domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
			[]*x509.Certificate{foreignCA}, foreignAdmins, foreignPpCliAuth)
		domain.SetRevocationSet(api.NewClientCRLSet([]*x509.RevocationList{foreignCRL()}))

		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			Domains: []api.TrustDomain{
				api.OwnTrustDomain(caCert, map[string]bool{"puppet-server": true}, true),
				domain,
			},
		}
		return server.Routes()
	}

	probe := func(handler http.Handler, method, path string, cert *x509.Certificate) int {
		req := httptest.NewRequest(method, path, strings.NewReader(""))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	BeforeEach(func() {
		ctx = context.Background()
		store := storage.New(GinkgoT().TempDir())
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

		foreignCA, foreignKey = mintCert("Server CA", nil, nil, true)
		mux = build(nil, false)
	})

	Describe("admin authority is scoped to the domain that granted it", func() {
		It("does not let our own allow list admit a foreign certificate", func() {
			// puppet-server is an admin CN of domain zero. A foreign issuer
			// naming its client the same thing must not inherit that: a CN only
			// means something inside the namespace of the issuer that signed it.
			Expect(probe(mux, "POST", "/sign/all", foreignLeaf("puppet-server", false))).
				To(Equal(http.StatusForbidden))
		})

		It("does not let a foreign allow list admit our own certificate", func() {
			// The mirror. "ops-admin" is an admin of the foreign domain only, so
			// a certificate we issued with that name gets nothing from it.
			handler := build(map[string]bool{"ops-admin": true}, false)
			ours := issueClientCert("ops-admin", caCert, caKey)
			Expect(probe(handler, "POST", "/sign/all", ours)).To(Equal(http.StatusForbidden))
		})

		It("admits a foreign certificate named in that domain's own allow list", func() {
			// The feature working: an administrator of the Server CA, expressible
			// without trusting that name from anywhere else.
			handler := build(map[string]bool{"ops-admin": true}, false)
			Expect(probe(handler, "POST", "/sign/all", foreignLeaf("ops-admin", false))).
				NotTo(Equal(http.StatusForbidden))
		})
	})

	Describe("pp_cli_auth is honoured per domain", func() {
		It("ignores the extension from a domain that has not opted in", func() {
			// Domain zero honours pp_cli_auth by default. If that setting leaked
			// across domains, any issuer we trust for authentication could stamp
			// itself an administrator of this CA.
			Expect(probe(mux, "POST", "/sign/all", foreignLeaf("cli", true))).
				To(Equal(http.StatusForbidden))
		})

		It("honours it from a domain that has", func() {
			handler := build(nil, true)
			Expect(probe(handler, "POST", "/sign/all", foreignLeaf("cli", true))).
				NotTo(Equal(http.StatusForbidden))
		})
	})

	Describe("own-CA operations reject a trusted foreign certificate", func() {
		It("refuses renewal to a foreign client", func() {
			// tierOwnClient. The certificate authenticates — it is trusted — but
			// renewal mints a credential in our namespace from one in theirs.
			//
			// This pins the observable outcome, not the middleware gate on its
			// own: /certificate_renewal is the only tierOwnClient route, and
			// CA.Renew rejects a foreign certificate too, so removing the gate
			// here leaves this green. That is defence in depth working as
			// intended — the CA-layer gate is the primary and is pinned
			// directly in renewgate_test.go — but it does mean this spec cannot
			// tell the two apart.
			Expect(probe(mux, "POST", "/certificate_renewal", foreignLeaf(ownSubject, false))).
				To(Equal(http.StatusForbidden))
		})

		It("still allows renewal to our own client", func() {
			Expect(probe(mux, "POST", "/certificate_renewal", issueClientCert(ownSubject, caCert, caKey))).
				NotTo(Equal(http.StatusForbidden))
		})
	})

	Describe("the self-match is scoped to our own domain", func() {
		It("refuses a foreign certificate reading the same name's CSR", func() {
			// Without the IsOwn() scoping, a foreign certificate named agent1
			// could read *our* agent1's pending request — a public key and the
			// requested extensions, but the same defect class.
			Expect(probe(mux, "GET", "/certificate_request/"+ownSubject, foreignLeaf(ownSubject, false))).
				To(Equal(http.StatusForbidden))
		})

		It("still allows our own certificate to read its own CSR", func() {
			code := probe(mux, "GET", "/certificate_request/"+ownSubject,
				issueClientCert(ownSubject, caCert, caKey))
			Expect(code).NotTo(Equal(http.StatusForbidden))
		})
	})

	It("rejects a certificate no domain can verify", func() {
		// Attribution is the gate before any of the above: an issuer nobody
		// configured gets nothing, whatever its client is called.
		unrelatedCA, unrelatedKey := mintCert("Unrelated CA", nil, nil, true)
		stranger, _ := mintCert("puppet-server", unrelatedCA, unrelatedKey, false)

		Expect(probe(mux, "GET", "/certificate_status/whatever", stranger)).
			To(Equal(http.StatusForbidden))
	})
})
