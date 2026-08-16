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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log/slog"
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

	// foreignCRLRevoking is a currently valid CRL from the foreign issuer that
	// lists the given serials.
	foreignCRLRevoking := func(serials ...*big.Int) *x509.RevocationList {
		GinkgoHelper()
		now := time.Now()
		var entries []x509.RevocationListEntry
		for _, sn := range serials {
			entries = append(entries, x509.RevocationListEntry{
				SerialNumber:   sn,
				RevocationTime: now.Add(-time.Minute),
			})
		}
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:                    big.NewInt(2),
			ThisUpdate:                now.Add(-time.Hour),
			NextUpdate:                now.Add(24 * time.Hour),
			RevokedCertificateEntries: entries,
		}, foreignCA, foreignKey)
		Expect(err).NotTo(HaveOccurred())
		crl, err := x509.ParseRevocationList(der)
		Expect(err).NotTo(HaveOccurred())
		return crl
	}

	// buildWithRevocation wires the same two-domain mux but lets the spec decide
	// the foreign domain's CRLs and the policy, which is what the middleware's
	// revocation arm is actually parameterised by.
	buildWithRevocation := func(crls []*x509.RevocationList, policy string) http.Handler {
		GinkgoHelper()
		// The domain grants admin to ops-admin, because a foreign client with no
		// grant is denied above the public tier anyway -- so only an admitted
		// client can show that revocation is what took the access away.
		domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
			[]*x509.Certificate{foreignCA}, map[string]bool{"ops-admin": true}, false)
		domain.SetRevocationSet(api.NewClientCRLSet(crls, []*x509.Certificate{foreignCA}))

		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			ClientRevocationPolicy: policy,
			Domains: []api.TrustDomain{
				api.OwnTrustDomain(caCert, map[string]bool{"puppet-server": true}, true),
				domain,
			},
		}
		return server.Routes()
	}

	// buildCounting is buildWithRevocation with the refusal callback wired, so a
	// spec can see which refusals the counter would record.
	buildCounting := func(crls []*x509.RevocationList, policy string, onRefusal func(string)) http.Handler {
		GinkgoHelper()
		domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
			[]*x509.Certificate{foreignCA}, map[string]bool{"ops-admin": true}, false)
		domain.SetRevocationSet(api.NewClientCRLSet(crls, []*x509.Certificate{foreignCA}))

		server := api.New(myCA)
		server.AuthConfig = &api.AuthConfig{
			ClientRevocationPolicy: policy,
			OnRevocationRefusal:    onRefusal,
			Domains: []api.TrustDomain{
				api.OwnTrustDomain(caCert, map[string]bool{"puppet-server": true}, true),
				domain,
			},
		}
		return server.Routes()
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
		domain.SetRevocationSet(api.NewClientCRLSet(
			[]*x509.RevocationList{foreignCRL()}, []*x509.Certificate{foreignCA}))

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

	Describe("revocation, through the middleware", func() {
		// The branch's headline guarantee is that a foreign client is checked
		// against its own issuer's CRLs. Everything that pinned it called
		// checkChainRevocation directly through the test shim, and the only
		// multi-domain fixture always installed a valid, empty CRL -- so the
		// entire revocation arm of the middleware could be deleted, or its
		// policy forced to skip, with the suite green.
		//
		// These drive the real mux, which is where the guarantee has to hold.
		It("takes admin away from a foreign administrator its issuer revoked", func() {
			admin := foreignLeaf("ops-admin", false)

			live := buildWithRevocation([]*x509.RevocationList{foreignCRL()}, "")
			Expect(probe(live, "POST", "/sign/all", admin)).NotTo(Equal(http.StatusForbidden),
				"the control: this administrator is admitted while its CRL says nothing")

			revoked := buildWithRevocation(
				[]*x509.RevocationList{foreignCRLRevoking(admin.SerialNumber)}, "")
			Expect(probe(revoked, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
		})

		It("refuses a foreign client when its issuer has no usable CRL, by default", func() {
			// The fail-closed default asserted where it is resolved rather than
			// where it is configured: this AuthConfig leaves the policy empty.
			admin := foreignLeaf("ops-admin", false)
			handler := buildWithRevocation(nil, "")
			Expect(probe(handler, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
		})

		It("admits a revoked foreign client only when the operator asked for skip", func() {
			admin := foreignLeaf("ops-admin", false)
			handler := buildWithRevocation(
				[]*x509.RevocationList{foreignCRLRevoking(admin.SerialNumber)}, api.RevocationSkip)
			Expect(probe(handler, "POST", "/sign/all", admin)).NotTo(Equal(http.StatusForbidden))
		})

		// The bulk endpoints take a list of names from the request body, and
		// CodeQL flagged both of them: handleSignMultiple and handleCleanMultiple
		// logged body.Certnames verbatim. The elements go through the same
		// sanitiser as a single CN, and the list itself is bounded, because one
		// request may carry thousands of names and a log line naming all of them
		// is write amplification bought with a single POST.
		It("sanitises and bounds a list of names from a request body", func() {
			out := api.SanitiseAllForLogForTest([]string{
				"good.example.com",
				"evil\n2026-01-01 ERROR forged log line",
				"carriage\rreturn",
			})
			Expect(out).To(HaveLen(3))
			Expect(out[0]).To(Equal("good.example.com"))
			Expect(out[1]).NotTo(ContainSubstring("\n"))
			Expect(out[2]).NotTo(ContainSubstring("\r"))

			many := make([]string, 100)
			for i := range many {
				many[i] = "node.example.com"
			}
			bounded := api.SanitiseAllForLogForTest(many)
			Expect(bounded).To(HaveLen(33), "32 names plus the elision marker")
			Expect(bounded[32]).To(Equal("…"))
		})

		It("sanitises a common name before logging it, on the branch that needs no trust", func() {
			// Every other CN log in the middleware needs a certificate that
			// verified against a configured domain. This one is on the failure
			// branch, so any client presenting any self-signed certificate
			// reaches it -- which makes it the worst member of the class, and it
			// was the one a sweep keyed on the clientCN identifier passed over.
			//
			// Pinned through captured output: the helper's own behaviour was
			// tested, but nothing asserted that any call site used it, so all six
			// could be deleted with the suite green.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(99),
				Subject:      pkix.Name{CommonName: "evil\nAuth: forged record"},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().Add(time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			Expect(err).NotTo(HaveOccurred())
			stranger, err := x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())

			handler := buildWithRevocation([]*x509.RevocationList{foreignCRL()}, "")
			Expect(probe(handler, "GET", "/certificate_request/whatever", stranger)).
				To(Equal(http.StatusForbidden))

			// Asserting the substitution, not the absence of a raw newline:
			// slog's TextHandler quotes values, so an unsanitised CN also shows
			// no literal newline and an absence assertion passes either way.
			// That is the false-confidence shape this spec exists to avoid.
			Expect(buf.String()).To(ContainSubstring("\uFFFD"),
				"the control character must be replaced before it reaches the log")
			Expect(buf.String()).NotTo(ContainSubstring("evil\\nAuth"),
				"and not merely escaped by the handler, which a different handler need not do")
		})

		It("counts a refusal only when revocation information was missing", func() {
			// This counter drives the branch's only critical authentication
			// alert. Counting a *successful* revocation on it made that alert
			// driveable at will by the holder of a revoked certificate -- the one
			// population revocation exists to exclude -- while telling the
			// responder to refresh a CRL that was present, current and working.
			admin := foreignLeaf("ops-admin", false)

			var counted []string
			record := func(d string) { counted = append(counted, d) }

			// Revoked by a CRL that is present, current and verifying. Refused,
			// and that is the feature working: nothing to count.
			revoked := buildCounting(
				[]*x509.RevocationList{foreignCRLRevoking(admin.SerialNumber)}, "", record)
			Expect(probe(revoked, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
			Expect(counted).To(BeEmpty(),
				"a revocation that was found is not a refusal for want of a CRL")

			// No CRL at all. Same 403, entirely different cause.
			counted = nil
			missing := buildCounting(nil, "", record)
			Expect(probe(missing, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
			Expect(counted).To(ConsistOf("server-ca"))
		})

		It("neutralises the common name in a handler's own log line, not just the middleware's", func() {
			// The middleware's sanitisation was pinned through captured output.
			// The handler layer was not, so when clientCN stopped sanitising at
			// source, fourteen handler log sites reverted to raw and every spec
			// stayed green -- including the one written for the split, which
			// exercised the two helpers through export hooks and asserted nothing
			// about which one a call site chose. That is the shape the middleware
			// spec above exists to reject, repeated one layer down.
			//
			// PUT /clean is the sharp case: tierAdminOnly, reachable by a foreign
			// issuer with allow_pp_cli_auth, and its rate-limit warning is at Warn
			// so it is on by default.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(orig)

			hostile := foreignLeaf("ops\nlevel=ERROR msg=\"forged\"", true)
			handler := build(map[string]bool{}, true)

			// Six, because the rate-limit warning -- the site whose two siblings
			// were fixed and which was left raw -- only fires once the tracker
			// trips, and a single request never reaches it.
			for range 6 {
				req := httptest.NewRequest("PUT", "/clean",
					strings.NewReader(`{"certnames":["node1.test"]}`))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{hostile}}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				Expect(rec.Code).NotTo(Equal(http.StatusForbidden),
					"pp_cli_auth admits it, which is what makes the log line reachable")
			}
			// Scoped to the warning's own record, not the whole buffer: the other
			// lines in this handler already carry the neutralised name, so a
			// buffer-wide assertion passes with this one line left raw -- which
			// is exactly the line whose two siblings were fixed and it was not.
			var warned string
			for _, line := range strings.Split(buf.String(), "\n") {
				if strings.Contains(line, "High rate of destructive operations") {
					warned = line
				}
			}
			Expect(warned).NotTo(BeEmpty(),
				"the spec must actually reach the warning it exists to cover")
			Expect(warned).To(ContainSubstring("\uFFFD"))

			Expect(buf.String()).NotTo(ContainSubstring("\nlevel=ERROR"),
				"a newline must not survive to start a record of the attacker's choosing; "+
					"asserting the substitution and this, rather than the absence of a raw "+
					"newline alone, because TextHandler escapes one anyway and that check "+
					"would pass unsanitised")
		})

		It("keeps a common name verbatim as an identity, and neutralises it only for logs", func() {
			// clientCN feeds the renewal handler's CN comparison and the subject
			// passed to Renew, so it has to be the certificate's value. It was
			// briefly sanitised at source, on the argument that a per-call-site
			// rule gets missed -- but the middleware reads the field directly
			// anyway, so the class was never closed there, and sanitiseForLog
			// truncates at 256 bytes, which this CA's certname grammar permits.
			// An agent with a long certname then got a permanent 403 on a re-key
			// renewal, its own correct CSR compared against a truncated name.
			long := strings.Repeat("a", 300) + ".example.com"
			req := httptest.NewRequest("GET", "/", nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
				Subject: pkix.Name{CommonName: long},
			}}}

			Expect(api.ClientCNForTest(req)).To(Equal(long),
				"an identity must survive intact, however long")

			// The display form is no longer a second function beside it -- that
			// left the choice at every call site -- but a method on the principal,
			// so a name reaches a record only after passing through it.
			rendered := api.PrincipalLogValueForTest("evil\nforged", nil).String()
			Expect(rendered).NotTo(ContainSubstring("\n"))
			Expect(rendered).To(ContainSubstring("\uFFFD"))
		})

		It("counts destructive operations per issuing domain, not by common name alone", func() {
			// ops-admin from our CA and ops-admin from the partner's are different
			// principals, and keyed on the bare name they shared a rate-limit
			// bucket. Five destructive operations from the partner left ours one
			// request away from an alert it had not earned -- and, read the other
			// way, either could spend the other's allowance to keep its own bulk
			// clean below the threshold.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			// Both domains grant ops-admin, which is the collision: the name is
			// admissible in each, and means a different principal in each.
			domain := api.NewForeignTrustDomain("server-ca", poolOf(foreignCA),
				[]*x509.Certificate{foreignCA}, map[string]bool{"ops-admin": true}, false)
			domain.SetRevocationSet(api.NewClientCRLSet(
				[]*x509.RevocationList{foreignCRL()}, []*x509.Certificate{foreignCA}))
			server := api.New(myCA)
			server.AuthConfig = &api.AuthConfig{
				Domains: []api.TrustDomain{
					api.OwnTrustDomain(caCert, map[string]bool{"ops-admin": true}, true),
					domain,
				},
			}
			handler := server.Routes()

			clean := func(cert *x509.Certificate) {
				GinkgoHelper()
				req := httptest.NewRequest("PUT", "/clean",
					strings.NewReader(`{"certnames":["node1.test"]}`))
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				Expect(rec.Code).NotTo(Equal(http.StatusForbidden),
					"both are administrators of the domain that named them")
			}

			// The threshold is five in a minute, so a sixth request in one bucket
			// warns. Five from theirs and one from ours is six requests across two
			// principals, neither of which has reached its own threshold.
			for range 5 {
				clean(foreignLeaf("ops-admin", false))
			}
			clean(issueClientCert("ops-admin", caCert, caKey))

			Expect(buf.String()).NotTo(ContainSubstring("High rate of destructive operations"),
				"one domain's traffic must not raise the alarm against another's administrator")
		})

		// Key() quotes the CN rather than concatenating it, and the quoting is
		// what stops one principal forging another's key. A CN is attacker-chosen
		// within its own namespace, so without it a name containing the
		// separator could be crafted to collide with a different domain's
		// principal -- and the destructive-operations counter this key feeds is
		// exactly what an attacker would want to attribute elsewhere.
		It("cannot be made to collide by a common name containing the separator", func() {
			own := api.OwnTrustDomain(caCert, nil, false)
			theirs := api.NewForeignTrustDomain("server-ca", nil, nil, nil, false)

			// A name crafted to look like "the server-ca domain's ops-admin"
			// when read as a flat string.
			crafted := api.PrincipalKeyForTest(`ops-admin"`, &own)
			genuine := api.PrincipalKeyForTest("ops-admin", &theirs)
			Expect(crafted).NotTo(Equal(genuine))

			// And the general property: two distinct names never share a key
			// within one domain, however they are punctuated.
			seen := map[string]string{}
			for _, cn := range []string{
				"ops-admin", `ops-admin"`, `"ops-admin`, "ops/admin", `ops\admin`,
				"ops-admin\n", "", " ",
			} {
				key := api.PrincipalKeyForTest(cn, &own)
				Expect(seen).NotTo(HaveKey(key),
					"two names collided on one key: %q and %q", seen[key], cn)
				seen[key] = cn
			}
		})

		It("names the vouching domain in the record, not just the common name", func() {
			// The audit half of the same defect. A warning that a client is running
			// destructive operations at rate is actionable only if the reader can
			// tell which ops-admin it means, and the CN alone cannot say.
			own := api.OwnTrustDomain(caCert, nil, false)
			theirs := api.NewForeignTrustDomain("server-ca", nil, nil, nil, false)

			Expect(api.PrincipalKeyForTest("ops-admin", &own)).
				NotTo(Equal(api.PrincipalKeyForTest("ops-admin", &theirs)),
					"the same name from two issuers is two principals")
			Expect(api.PrincipalKeyForTest("ops-admin", nil)).
				NotTo(Equal(api.PrincipalKeyForTest("ops-admin", &own)),
					"and a name nothing has vouched for is a third")

			Expect(api.PrincipalLogValueForTest("ops-admin", &theirs).String()).
				To(ContainSubstring("server-ca"),
					"a record naming only the CN cannot say which principal acted")
		})

		It("treats an unrecognised policy as require, not as the most permissive arm", func() {
			// Validation rejects a bad policy string, but it lives two packages
			// away and runs on one construction path, so the enforcement point
			// must not read an unknown value as "check".
			admin := foreignLeaf("ops-admin", false)
			handler := buildWithRevocation(nil, "not-a-policy")
			Expect(probe(handler, "POST", "/sign/all", admin)).To(Equal(http.StatusForbidden))
		})
	})

})

var _ = Describe("denial logging", func() {
	// The middleware logs the request path and the client CN on every denial.
	// Both are attacker-influenced: net/http decodes %0A into a real newline, and
	// under client_ca the CN comes from an issuer the operator may not control.
	It("strips control characters from the logged path and CN", func() {
		Expect(api.SanitiseForLogForTest("/certificate_status/a\nFAKE line")).
			To(Equal("/certificate_status/a�FAKE line"))
		Expect(api.SanitiseForLogForTest("ops\r\nadmin")).To(Equal("ops��admin"))
	})

	It("passes an ordinary path through unchanged", func() {
		Expect(api.SanitiseForLogForTest("/certificate_status/agent1.example.com")).
			To(Equal("/certificate_status/agent1.example.com"))
	})

	It("bounds the length, so a large request cannot pad the log", func() {
		got := api.SanitiseForLogForTest(strings.Repeat("a", 500))
		Expect(len([]rune(got))).To(Equal(257), "256 runes plus the ellipsis")
	})

	It("passes a replacement character through unchanged", func() {
		// U+FFFD is not a control character, so it survives -- and a caller
		// supplying one produces output identical to a sanitised newline. That
		// collision is unavoidable with a single-rune replacement and is
		// accepted: what matters is that no control character reaches the log,
		// not that its origin is recoverable. The previous version of this spec
		// claimed to prevent the collision while demonstrating it, and pinned a
		// mapping branch that returned the rune it was given -- so it could not
		// have detected that branch being deleted.
		Expect(api.SanitiseForLogForTest("a�b")).To(Equal("a�b"))
		Expect(api.SanitiseForLogForTest("a\nb")).To(Equal("a�b"))
	})

})
