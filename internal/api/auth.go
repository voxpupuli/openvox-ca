// Copyright (C) 2026 Trevor Vaughan
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

package api

import (
	"crypto/x509"
	"encoding/asn1"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// hasPpCliAuth reports whether cert carries the ca.OIDPpCliAuth extension
// with the UTF8String value "true".
func hasPpCliAuth(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ca.OIDPpCliAuth) {
			var value string
			if rest, err := asn1.Unmarshal(ext.Value, &value); err == nil && len(rest) == 0 {
				return value == "true"
			}
			return false
		}
	}
	return false
}

// isAdmin reports whether the client is authorized for admin-only operations,
// **within the domain that verified it**.
//
// A CN-based identity claim is only meaningful inside the namespace of the
// issuer that made it: every CA has its own namespace of names it has signed,
// and a name means nothing outside the one it was issued in. So the allow list
// consulted is the matched domain's, never a global one — which is what makes
// "an administrator of the Server CA" expressible without also trusting that
// name from anywhere else.
//
// pp_cli_auth is honoured per domain for the same reason. For our own CA it is
// on unless no_pp_cli_auth says otherwise, exactly as before; for a foreign
// issuer it is off unless that entry opts in, because honouring it delegates
// admin admission to that CA entirely.
func isAdmin(domain *TrustDomain, clientCert *x509.Certificate, clientCN string) bool {
	return domain.AdminCNs[clientCN] || (domain.PpCliAuth && hasPpCliAuth(clientCert))
}

type authTier int

const (
	tierPublic      authTier = iota // no client cert required
	tierOwnClient                   // a client certificate THIS CA issued
	tierSelfOrAdmin                 // own cert or an admin CN
	tierAdminOnly                   // admin CN only
)

// newAuthMiddleware returns an http.Handler that wraps next with mTLS authorization.
// If cfg is nil (no TLS configured) all requests pass through unconditionally,
// preserving plain HTTP / dev-mode compatibility.
//
// SECURITY: This is the primary access control enforcement point.
// All non-public requests are validated through a four-tier model:
//   - tierPublic: no client cert required (bootstrap endpoints)
//   - tierOwnClient: a client certificate this CA itself issued
//   - tierSelfOrAdmin: own cert or admin CN
//   - tierAdminOnly: admin CN only (signing, revocation, generation)
//
// tierOwnClient was tierAnyClient ("any certificate that chains to our trust
// anchor"). The two only ever coincided because there was a single issuer; once
// a client can be issued by a foreign CA they are different questions, and the
// endpoints in this tier act on *our* namespace. Renaming rather than
// redefining forces every call site to be re-read.
//
// NIST 800-53: AC-3 (Access Enforcement), IA-3 (Device Identification and Authentication)
func newAuthMiddleware(cfg *AuthConfig, myCA *ca.CA, next http.Handler) http.Handler {
	if cfg == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tier := lookupTier(r.Method, r.URL.Path, cfg)

		// Public endpoints need no cert.
		if tier == tierPublic {
			next.ServeHTTP(w, r)
			return
		}

		// Non-TLS connections (shouldn't happen when TLS is configured, but be safe).
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}

		clientCert := r.TLS.PeerCertificates[0]

		// SECURITY: attribute the certificate to exactly one trust domain, by
		// verifying against each domain's anchors alone. The domain that
		// verifies establishes both trust and identity namespace; everything
		// below — admin, revocation, CN scoping — is decided by it.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication)
		verified, err := attribute(cfg.Domains, clientCert, r.TLS.PeerCertificates[1:])
		if err != nil {
			slog.Warn("Auth: client cert verification failed",
				"cn", clientCert.Subject.CommonName, "error", err)
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}
		domain := verified.Domain

		clientCN := clientCert.Subject.CommonName

		// SECURITY: revocation. For our own domain this is the check it has
		// always been: the presented certificate's serial against our own CRL,
		// not the certificate on disk for the same CN, so an old revoked
		// credential is rejected even after re-issuance. Fail-closed — a CRL
		// read error is a denial.
		//
		// For a foreign domain our CRL says nothing, and serial numbers are
		// unique only per issuer, so consulting it could even reject a valid
		// client on a collision. Those go to that domain's own CRLs, and the
		// walk covers the whole verified chain rather than just the leaf: a
		// sibling CA revoked by the shared root must not go on authenticating
		// its leaves.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication), SC-17 (PKI Certificates)
		if domain.IsOwn() {
			if revoked, err := myCA.IsRevokedSerial(r.Context(), clientCert.SerialNumber); err != nil || revoked {
				if err != nil {
					slog.Warn("Auth: CRL check failed (denying)", "cn", clientCN, "error", err)
				} else {
					slog.Warn("Auth: client cert is revoked", "cn", clientCN)
				}
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
		} else if err := checkChainRevocation(verified.Chain, domain.RevocationSet(),
			cfg.revocationPolicy(), time.Now()); err != nil {
			slog.Warn("Auth: foreign client cert failed revocation checking",
				"cn", clientCN, "domain", domain.Describe(), "error", err)
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}

		switch tier {
		case tierOwnClient:
			// Operations on our own namespace: renewing a certificate we
			// issued. A foreign certificate is authenticated but has no
			// standing here, whatever name it carries.
			if domain.IsOwn() {
				next.ServeHTTP(w, r)
			} else {
				slog.Warn("Auth: rejecting a foreign client certificate for an own-CA operation",
					"cn", clientCN, "domain", domain.Describe())
				http.Error(w, "access denied", http.StatusForbidden)
			}

		case tierSelfOrAdmin:
			// The self-match is scoped to our own domain for the same reason:
			// without it, a foreign certificate named agent1.example.com could
			// read *our* agent1.example.com's pending CSR. Only an information
			// leak — a public key and requested extensions — but the same
			// defect class, and the rule closes it for free.
			subject := extractPathSubject(r.URL.Path)
			selfMatch := domain.IsOwn() && subject != "" && clientCN == subject
			if isAdmin(domain, clientCert, clientCN) || selfMatch {
				next.ServeHTTP(w, r)
			} else {
				denyWithLog(w, r, clientCN, "not an admin and not the subject of the request")
			}

		case tierAdminOnly:
			if isAdmin(domain, clientCert, clientCN) {
				next.ServeHTTP(w, r)
			} else {
				denyWithLog(w, r, clientCN, "route requires admin access")
			}

		default:
			denyWithLog(w, r, clientCN, "unclassified route")
		}
	})
}

// denyWithLog rejects a request and records who was refused what, and why.
//
// The HTTP metrics carry no path label, so a 403 is otherwise invisible beyond a
// counter: an operator whose tooling broke against a tier change has nothing to
// correlate against. Logged at Warn because a denial on these routes is either a
// misconfiguration or an attempt, and both are worth seeing. The client CN is
// included; it comes from a certificate that has already been verified against
// the trust anchor, so it is not attacker-controlled free text.
func denyWithLog(w http.ResponseWriter, r *http.Request, clientCN, reason string) {
	slog.Warn("Request denied by authorisation middleware",
		"method", r.Method, "path", r.URL.Path, "client_cn", clientCN, "reason", reason)
	http.Error(w, "access denied", http.StatusForbidden)
}

// lookupTier classifies a request into an authorization tier based on method and path.
func lookupTier(method, path string, cfg *AuthConfig) authTier {
	// Strip the /puppet-ca/v1 prefix if present for uniform matching.
	p := strings.TrimPrefix(path, "/puppet-ca/v1")

	switch {
	// Health check probes: always public; orchestrators poll without client certs.
	case method == "GET" && strings.HasPrefix(p, "/healthz/"):
		return tierPublic

	// Public: no cert needed.
	// Signed certs contain no secrets; bootstrapping nodes fetch their cert
	// before they have a client cert, matching Puppet Server 8 behaviour.
	case method == "GET" && strings.HasPrefix(p, "/certificate/"):
		return tierPublic
	case method == "GET" && strings.HasPrefix(p, "/certificate_revocation_list/"):
		return tierPublic
	case method == "PUT" && strings.HasPrefix(p, "/certificate_request/"):
		return tierPublic
	case strings.HasPrefix(p, "/ocsp"):
		// OCSP is always public: clients query before they have a client cert
		// and intermediate caches must be able to fetch responses unauthenticated.
		return tierPublic

	// certificate_status exposes cert metadata (serial numbers, authorization
	// extensions) that could aid infrastructure enumeration, so it is admin-only,
	// matching Puppet Server's shipped auth.conf — which grants both
	// certificate_status and certificate_statuses to pp_cli_auth holders and to
	// nothing else. Operators can still opt in to public access with
	// --allow-public-status for bootstrapping agents that poll status before
	// obtaining a client certificate.
	// NIST 800-53: AC-3 (Access Enforcement)
	case method == "GET" && strings.HasPrefix(p, "/certificate_status/"):
		if cfg != nil && cfg.AllowPublicStatus {
			return tierPublic
		}
		return tierAdminOnly
	case method == "GET" && p == "/expirations":
		return tierPublic

	// Self or admin reads.
	case method == "GET" && strings.HasPrefix(p, "/certificate_request/"):
		return tierSelfOrAdmin

	// Certificate renewal: a client certificate THIS CA issued may renew
	// itself. The handler enforces that the CSR CN matches the authenticated
	// client CN, so an agent can only renew its own certificate — and the tier
	// enforces that the name was ours to begin with, since a CN asserted by a
	// foreign issuer says nothing about our namespace.
	case method == "POST" && p == "/certificate_renewal":
		return tierOwnClient

	// Admin only: all other operations.
	default:
		return tierAdminOnly
	}
}

// extractPathSubject returns the {subject} segment from certificate/status/request paths.
func extractPathSubject(path string) string {
	path = strings.TrimPrefix(path, "/puppet-ca/v1")
	for _, prefix := range []string{
		"/certificate/",
		"/certificate_status/",
		"/certificate_request/",
	} {
		if strings.HasPrefix(path, prefix) {
			return strings.TrimPrefix(path, prefix)
		}
	}
	return ""
}
