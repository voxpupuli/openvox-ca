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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
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
//   - 11 rows over 10 of the 19 protocol routes registered by Routes().
//     GET /certificate_request/{subject} gets two rows because the self-match is
//     the only signal separating tierSelfOrAdmin from tierAdminOnly. The three
//     /healthz/ probes are registered separately and are not among the 19. The
//     omitted protocol routes are the two OCSP entries and duplicates of a tier
//     already represented by another row.
//   - Both the bare and the /puppet-ca/v1-prefixed forms of each path, which
//     the mux registers separately — see the prefix spec below.
//   - Only denials emitted by the *middleware*. A handler that refuses with its
//     own 403 is recorded as "got past authorisation", because that is what it
//     is. Of the three changes named above, that makes certificate_status
//     unconditionally observable here; renewal gating only if it lands in the
//     middleware rather than in handlePostCertificateRenewal, where the route's
//     existing refusals live; and issuer-scoping not at all through the
//     foreign-CA row, since this fixture's CA stays unconfigured as a second
//     trust anchor (see foreignClientCert). Anything landing in a handler needs
//     its own anchor in that handler's tests.
//   - The default AuthConfig, an absent one, plus the two flags that move a tier
//     (AllowPublicStatus, NoPpCliAuth), covered in their own Describe rather
//     than by multiplying every row.
//
// A second, overlapping oracle lives in auth_test.go ("lookupTier classification"),
// which drives lookupTier directly rather than through the mux. The same matrix
// is published for operators at docs/api.md#authorization-tiers; a row that
// moves here moves there too. That one pins
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
	// fingerprint is a digest of the denied map as first recorded. It is what
	// makes changedBy enforceable rather than advisory: editing a cell changes
	// the digest, and the spec then requires changedBy to be set in the same
	// commit. Without it nothing distinguished a deliberate change from a
	// silent one, because no copy of the original values was retained
	// anywhere — the header claimed that distinction was "the whole point"
	// while nothing implemented it.
	fingerprint string
	// changedBy names the change that last altered this row's outcomes, empty
	// for rows still at their originally recorded values.
	changedBy string
}

// handler403Bodies are the 403s the *handlers* emit, as opposed to the
// middleware. The set is exactly three:
//
//   - handlePostCertificateRenewal, twice (handlers.go, "client certificate
//     required for renewal" and "CSR CN does not match authenticated client CN")
//   - handlePostGenerate, once ("private key delivery requires TLS"), on
//     POST /generate/{subject}, which this table does not cover
//
// Note "client certificate required" is a strict prefix of the renewal
// handler's "client certificate required for renewal", so these must be
// compared for equality and never by prefix.
var handler403Bodies = map[string]bool{
	"client certificate required for renewal":       true,
	"CSR CN does not match authenticated client CN": true,
	"private key delivery requires TLS":             true,
}

// denialKind classifies a response as an authorisation denial, an admission, or
// something this file does not recognise.
type denialKind int

const (
	admitted denialKind = iota
	deniedByMiddleware
	unrecognised403
)

// classify reports whether the response is the *middleware's* rejection.
//
// Status alone is not enough: the handlers emit 403s of their own, so a bare
// code check would record a handler outcome as an authorisation outcome. But the
// inverse — recognising only the middleware messages we know today — is worse,
// and was the original shape of this function. Every change this table exists to
// precede is a *narrowing*, which adds denials; a narrowing that rejects with a
// new message would have fallen into "not one of our two strings" and been
// recorded as admitted, leaving every row unmoved and the oracle silent on
// exactly the change it was committed ahead of.
//
// So the test is inverted. Any 403 is the middleware's unless its body is one of
// the enumerated handler messages, and a 403 body in neither set is
// unrecognised — which callers must fail on rather than quietly bucket. That way
// introducing a new denial reason forces a deliberate edit here.
//
// Every other outcome (404 for an absent subject, 400 for a malformed body)
// means the request got past authorisation, which is what this table measures.
//
// One dimension remains open, deliberately and stated here rather than
// discovered later: a middleware denial that used some *other* status is still
// bucketed as admitted. 401 and 407 are treated as denials below because they
// are unambiguous and this package emits neither today. A narrowing that hid a
// resource behind 404 — the standard anti-enumeration response, and a plausible
// shape for the certificate_status change, given lookupTier's own comment cites
// enumeration as the reason that route is gated — would be invisible here,
// because 404 is also what the handlers return for an absent subject. A change
// of that shape needs its own anchor.
func classify(rec *httptest.ResponseRecorder) denialKind {
	switch rec.Code {
	case http.StatusUnauthorized, http.StatusProxyAuthRequired:
		return deniedByMiddleware
	case http.StatusForbidden:
	default:
		return admitted
	}
	body := strings.TrimSpace(rec.Body.String())
	switch {
	case body == "client certificate required", body == "access denied":
		return deniedByMiddleware
	case handler403Bodies[body]:
		return admitted
	default:
		return unrecognised403
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
		// caIssuedClientCert and revokedClientCert both issue through the CA, so
		// leaf generation is on the fixture path here and runs twice per class
		// set. Without this the CA falls back to DefaultLeafKeyConfig, which is
		// RSA-2048, and the matrix pays for ~46 of them.
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
		// cached keys keeps the independence and takes the matrix from ~250
		// RSA-2048 generations to four. The CA-issued and revoked fixtures go
		// through myCA.Generate, so they are ECDSA P-256 by virtue of the
		// LeafKeyConfig set above; the foreign fixture generates its own CA and
		// leaf, also P-256. None is worth pooling at that cost.
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
				// Chain-valid *and* recorded in the CA's inventory, unlike every
				// other admitted class here — those are minted by signing a
				// template directly, with serials the CA has never seen. Today
				// nothing distinguishes them: AutoRenew reissues purely from the
				// presented certificate. A gate on "certificates this CA issued"
				// must consult something recorded at issuance, so without this
				// class the renewal row could only record "renewal now denies
				// every ordinary agent" — a fiction, since a genuinely-issued
				// agent would still be admitted.
				{name: "own-ca-issued", cert: caIssuedClientCert(ctx, myCA)},
				{name: "own-ca-revoked", cert: revokedClientCert(ctx, myCA)},
				// Chain-valid but carrying only serverAuth EKU. The middleware
				// requires ExtKeyUsageClientAuth in its Verify call, and no
				// other class distinguishes that: every one of them carries
				// clientAuth, so relaxing the requirement to ExtKeyUsageAny
				// would move no cell. That predicate sits inside the block the
				// multi-trust-anchor work has to rewrite.
				{name: "own-ca-server-eku", cert: serverEKUClientCert(keyPool[1], "server-only", caCert, caKey)},
				// pp_cli_auth present but not "true". isAdmin compares the
				// extension value for equality; reducing it to a presence test
				// would grant admin to this certificate and, again, move no
				// existing cell.
				{name: "own-ca-pp-cli-auth-false", cert: ppCliAuthValueCert(keyPool[2], "cli-false", caCert, caKey, "false")},
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
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": false,
				"own-ca-expired": false, "own-ca-revoked": false, "own-ca-server-eku": false,
				"own-ca-pp-cli-auth-false": false, "foreign-ca": false,
			},
			fingerprint: "20efd5d41098722c",
		},
		{
			name: "public: fetch the CRL", method: "GET", path: "/certificate_revocation_list/ca",
			denied: map[string]bool{
				"none": false, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": false,
				"own-ca-expired": false, "own-ca-revoked": false, "own-ca-server-eku": false,
				"own-ca-pp-cli-auth-false": false, "foreign-ca": false,
			},
			fingerprint: "20efd5d41098722c",
		},
		{
			name: "public: submit a CSR", method: "PUT", path: "/certificate_request/newnode",
			denied: map[string]bool{
				"none": false, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": false,
				"own-ca-expired": false, "own-ca-revoked": false, "own-ca-server-eku": false,
				"own-ca-pp-cli-auth-false": false, "foreign-ca": false,
			},
			fingerprint: "20efd5d41098722c",
		},
		{
			// Has its own branch in the classifier rather than sharing one with
			// a covered route, which is why it earns a row of its own. It
			// returns certificate expiry metadata to any caller with no client
			// certificate, and it is the obvious sibling question when
			// certificate_status narrows to admin-only — so a change that
			// tightens, loosens or reorders this case relative to the one above
			// it moves a cell here.
			name: "public: read expiry metadata", method: "GET", path: "/expirations",
			denied: map[string]bool{
				"none": false, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": false,
				"own-ca-expired": false, "own-ca-revoked": false, "own-ca-server-eku": false,
				"own-ca-pp-cli-auth-false": false, "foreign-ca": false,
			},
			fingerprint: "20efd5d41098722c",
		},
		{
			// Any certificate that chains to our trust anchor is admitted, with
			// no check that the subject matches the caller. Scoped to our own CA
			// only because ours is the only issuer configured today.
			name: "any-client: read a certificate status", method: "GET", path: "/certificate_status/somenode",
			denied: map[string]bool{
				"none": true, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": false,
				"own-ca-expired": true, "own-ca-revoked": true, "own-ca-server-eku": true,
				"own-ca-pp-cli-auth-false": false, "foreign-ca": true,
			},
			fingerprint: "bca6da2164bcceeb",
		},
		{
			name: "any-client: renew own certificate", method: "POST", path: "/certificate_renewal",
			denied: map[string]bool{
				"none": true, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": false,
				"own-ca-expired": true, "own-ca-revoked": true, "own-ca-server-eku": true,
				"own-ca-pp-cli-auth-false": false, "foreign-ca": true,
			},
			fingerprint: "bca6da2164bcceeb",
		},
		{
			// Self-match: the CN must equal the path subject, or the caller must
			// be an admin.
			name: "self-or-admin: read own CSR", method: "GET", path: "/certificate_request/" + selfName,
			denied: map[string]bool{
				"none": true, "own-ca-plain": false, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": true,
				"own-ca-expired": true, "own-ca-revoked": true, "own-ca-server-eku": true,
				"own-ca-pp-cli-auth-false": true, "foreign-ca": true,
			},
			fingerprint: "97f9f0c0deb8b53d",
		},
		{
			name: "self-or-admin: read another node's CSR", method: "GET", path: "/certificate_request/othernode",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": true,
				"own-ca-expired": true, "own-ca-revoked": true, "own-ca-server-eku": true,
				"own-ca-pp-cli-auth-false": true, "foreign-ca": true,
			},
			fingerprint: "a5e45fefd4a8d0ef",
		},
		{
			name: "admin: list all statuses", method: "GET", path: "/certificate_statuses/all",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": true,
				"own-ca-expired": true, "own-ca-revoked": true, "own-ca-server-eku": true,
				"own-ca-pp-cli-auth-false": true, "foreign-ca": true,
			},
			fingerprint: "a5e45fefd4a8d0ef",
		},
		{
			name: "admin: sign all pending", method: "POST", path: "/sign/all",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": true,
				"own-ca-expired": true, "own-ca-revoked": true, "own-ca-server-eku": true,
				"own-ca-pp-cli-auth-false": true, "foreign-ca": true,
			},
			fingerprint: "a5e45fefd4a8d0ef",
		},
		{
			name: "admin: reissue the CRL", method: "PUT", path: "/certificate_revocation_list/ca",
			denied: map[string]bool{
				"none": true, "own-ca-plain": true, "own-ca-allowlisted": false,
				"own-ca-pp-cli-auth": false, "own-ca-admin-both": false, "own-ca-issued": true,
				"own-ca-expired": true, "own-ca-revoked": true, "own-ca-server-eku": true,
				"own-ca-pp-cli-auth-false": true, "foreign-ca": true,
			},
			fingerprint: "a5e45fefd4a8d0ef",
		},
	}

	// probe runs one route against one client class at pathPrefix and reports
	// whether the middleware rejected it.
	probe := func(route routeCase, class clientClass, pathPrefix string) bool {
		req := httptest.NewRequest(route.method, pathPrefix+route.path, strings.NewReader(""))
		if class.cert != nil {
			req = withClientCert(req, class.cert)
		} else {
			// A TLS connection that presented no client certificate, which is
			// what a real mTLS listener produces. Leaving r.TLS nil instead
			// would reach the middleware's other disjunct — the one the
			// production code itself calls "shouldn't happen" — so the whole
			// "none" column would have recorded the defensive branch rather
			// than the case operators actually hit. The sibling oracle in
			// auth_test.go models it this way for the same reason.
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		switch classify(rec) {
		case deniedByMiddleware:
			return true
		case unrecognised403:
			Fail(fmt.Sprintf("route %q, client %q: 403 with body %q is neither a known middleware "+
				"denial nor a known handler refusal. Classify it in classify()/handler403Bodies "+
				"before trusting this table: an unrecognised denial recorded as an admission is "+
				"how this oracle goes quiet on the change it exists to watch.",
				route.name, class.name, strings.TrimSpace(rec.Body.String())))
			return false
		default:
			return false
		}
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

	// One Entry per route, matching the bare-path table, for the same two
	// reasons: a single It aborts at the first moved cell, and this surface is
	// half the registered mux — a prefix-sensitive change to lookupTier, which
	// matches on path prefixes, would move it alone.
	//
	// Compared against the same recorded table rather than a second copy, so the
	// two cannot drift.
	DescribeTable("applies the same authorisation at the /puppet-ca/v1 prefix",
		func(route routeCase) {
			var mismatches []string
			for _, class := range newClasses() {
				want := route.denied[class.name]
				if got := probe(route, class, "/puppet-ca/v1"); got != want {
					mismatches = append(mismatches,
						fmt.Sprintf("  client %q: recorded denied=%v, got denied=%v", class.name, want, got))
				}
			}
			Expect(mismatches).To(BeEmpty(),
				"route %q disagrees between its bare and /puppet-ca/v1 forms:\n%s\n\n"+
					"Both must authorise identically.",
				route.name, strings.Join(mismatches, "\n"))
		},
		routeEntries,
	)

	// Without this, editing a recorded cell and leaving changedBy empty was a
	// green suite: nothing retained the original values, so no assertion could
	// tell a deliberate change from a silent one. The digest is that retained
	// copy, in one line per row.
	It("requires a changed row to say what changed it", func() {
		var undocumented []string
		for _, route := range routes {
			got := fingerprintDenied(route.denied)
			if got == route.fingerprint {
				continue
			}
			if route.changedBy == "" {
				undocumented = append(undocumented, fmt.Sprintf(
					"  %q: recorded outcomes have been edited but changedBy is empty.\n"+
						"    Set changedBy to the change that did it, and update fingerprint to %q.",
					route.name, got))
			}
		}
		Expect(undocumented).To(BeEmpty(),
			"the recorded baseline was edited without saying why:\n%s\n\n"+
				"That distinction — deliberate versus accidental — is what this table is for.",
			strings.Join(undocumented, "\n"))
	})

	It("keeps every fingerprint in step with the row it digests", func() {
		// The other half: a row whose fingerprint is stale (updated outcomes,
		// updated changedBy, forgotten digest) would silently stop enforcing.
		var stale []string
		for _, route := range routes {
			if got := fingerprintDenied(route.denied); got != route.fingerprint && route.changedBy != "" {
				stale = append(stale, fmt.Sprintf("  %q: set fingerprint to %q", route.name, got))
			}
		}
		Expect(stale).To(BeEmpty(),
			"these rows changed and were documented, but their fingerprints were not "+
				"updated, so the next edit would go unnoticed:\n%s", strings.Join(stale, "\n"))
	})

	// The table above cannot tell "denied by the middleware" from "this path is
	// not registered at all": Routes() wraps the mux, so an unknown path is
	// tier-classified and refused before routing ever happens. Dropping
	// "/puppet-ca/v1" from the prefix list would therefore leave every recorded
	// cell satisfied. This pins existence separately.
	//
	// It presents the allow-listed admin certificate, because with no
	// certificate only the four public rows reach the mux at all — the other
	// seven are refused at auth.go before routing, so a 404 could never be
	// observed for them and those iterations would assert nothing. That was the
	// first version of this spec, and dropping the prefix still failed it, which
	// is how the gap survived: the failure came from the public rows alone.
	//
	// Its own server and store, because admission has side effects: POST
	// /sign/all signs pending CSRs, PUT /certificate_revocation_list/ca
	// reissues, and POST /certificate_renewal reaches AutoRenew.
	It("actually registers the prefixed routes", func() {
		store := storage.New(GinkgoT().TempDir())
		scratchCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		scratchCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(scratchCA.Init(ctx)).To(Succeed())

		scratch := api.New(scratchCA)
		scratch.AuthConfig = &api.AuthConfig{
			CACert:    caCert,
			AllowList: map[string]bool{"puppet-server": true},
		}
		scratchMux := scratch.Routes()
		// A fresh admin certificate per route, for the reason the class fixtures
		// give: POST /certificate_renewal succeeds here and, with
		// RevokeOnAutoRenew defaulting to true, revokes the certificate it was
		// shown. Reusing one across the loop revoked it midway and every later
		// route came back "access denied" from the CRL check — which looked
		// exactly like an authorisation failure.
		adminKey := newRSAKeyPool(1)[0]

		var missing []string
		for _, route := range routes {
			req := httptest.NewRequest(route.method, "/puppet-ca/v1"+route.path, strings.NewReader(""))
			req = withClientCert(req, clientCertFromKey(adminKey, "puppet-server", caCert, caKey, false, false))
			rec := httptest.NewRecorder()
			scratchMux.ServeHTTP(rec, req)
			// A bare 404 is ambiguous: the handlers return one for an absent
			// subject, which several of these routes legitimately do against a
			// scratch store. Go's ServeMux writes its own body for a path it has
			// no pattern for, and that is the one that means "unregistered".
			if rec.Code == http.StatusNotFound &&
				strings.Contains(rec.Body.String(), "404 page not found") {
				missing = append(missing, "  "+route.method+" /puppet-ca/v1"+route.path)
			}
			Expect(classify(rec)).NotTo(Equal(deniedByMiddleware),
				"%s %s: the admin certificate should reach the mux, so a denial here means this "+
					"spec has stopped testing registration (code=%d body=%q)",
				route.method, route.path, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		Expect(missing).To(BeEmpty(),
			"these prefixed paths returned 404, so the prefix is no longer registered "+
				"for them:\n%s", strings.Join(missing, "\n"))
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
	"own-ca-issued",
	"own-ca-revoked",
	"own-ca-server-eku",
	"own-ca-pp-cli-auth-false",
	"foreign-ca",
}

var expectedRoutes = []string{
	"public: fetch the CA certificate",
	"public: fetch the CRL",
	"public: submit a CSR",
	"public: read expiry metadata",
	"any-client: read a certificate status",
	"any-client: renew own certificate",
	"self-or-admin: read own CSR",
	"self-or-admin: read another node's CSR",
	"admin: list all statuses",
	"admin: sign all pending",
	"admin: reissue the CRL",
}

// fingerprintDenied digests a row's recorded outcomes. Sorted so it does not
// depend on map iteration order, and truncated because it only has to detect a
// change, not resist an adversary.
func fingerprintDenied(denied map[string]bool) string {
	names := make([]string, 0, len(denied))
	for name := range denied {
		names = append(names, name)
	}
	sort.Strings(names)

	h := sha256.New()
	for _, name := range names {
		fmt.Fprintf(h, "%s=%v;", name, denied[name])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
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

// serverEKUClientCert mints a chain-valid certificate carrying serverAuth EKU
// only, so it fails the middleware's ExtKeyUsageClientAuth requirement rather
// than its chain check. Nothing else in the matrix distinguishes those two.
func serverEKUClientCert(key *rsa.PrivateKey, cn string, caCert *x509.Certificate,
	caKey *rsa.PrivateKey,
) *x509.Certificate {
	GinkgoHelper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// ppCliAuthValueCert mints a certificate carrying pp_cli_auth with an arbitrary
// value, so a change from equality against "true" to a bare presence test is
// visible. clientCertFromKey can only encode "true".
func ppCliAuthValueCert(key *rsa.PrivateKey, cn string, caCert *x509.Certificate,
	caKey *rsa.PrivateKey, value string,
) *x509.Certificate {
	GinkgoHelper()
	extValue, err := asn1.Marshal(value)
	Expect(err).NotTo(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39},
			Value: extValue,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

// caIssuedClientCert issues a certificate through the CA's real issuance path,
// so it exists in the inventory and serial records. A fresh subject each time,
// since Generate refuses to reissue for a subject that already holds a valid
// certificate.
func caIssuedClientCert(ctx context.Context, myCA *ca.CA) *x509.Certificate {
	GinkgoHelper()
	cn := fmt.Sprintf("issued%d", time.Now().UnixNano())
	res, err := myCA.Generate(ctx, cn, nil)
	Expect(err).NotTo(HaveOccurred())
	block, _ := pem.Decode(res.CertificatePEM)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
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
		// No LeafKeyConfig here: this block mints its certificates directly with
		// issueClientCert and never issues through the CA, so the setting had no
		// consumer and its rationale described a fixture path this Describe does
		// not have.
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
		} else {
			req.TLS = &tls.ConnectionState{}
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		kind := classify(rec)
		Expect(kind).NotTo(Equal(unrecognised403),
			"%s %s: unrecognised 403 body %q; classify it before trusting this result",
			method, path, strings.TrimSpace(rec.Body.String()))
		return kind == deniedByMiddleware
	}

	// The widest branch in auth.go, and the one asserted nowhere in the
	// repository before this. It matters most on this stack: sub-CA support
	// restructures AuthConfig for per-issuer trust anchors, and a restructure
	// that changes what an unpopulated config means — or introduces a path where
	// cfg is nil where it was not — would move no row in the table above and
	// fail no spec anywhere.
	Describe("an absent AuthConfig", func() {
		It("disables authorisation entirely, admitting an admin route with no certificate", func() {
			handler := muxWith(nil)
			Expect(probe(handler, "POST", "/sign/all", nil)).To(BeFalse(),
				"with no AuthConfig the middleware is not installed at all")
		})

		It("admits an any-client route with no certificate", func() {
			handler := muxWith(nil)
			Expect(probe(handler, "GET", "/certificate_status/somenode", nil)).To(BeFalse())
		})

		It("admits a self-or-admin route for a foreign certificate", func() {
			// Not merely "no certificate is enough": a certificate from an
			// unrelated CA is equally unexamined, because nothing examines it.
			handler := muxWith(nil)
			Expect(probe(handler, "GET", "/certificate_request/othernode",
				foreignClientCert("intruder"))).To(BeFalse())
		})
	})

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
