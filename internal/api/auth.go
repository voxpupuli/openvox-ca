// Copyright (C) 2026 Trevor Vaughan
// Copyright (C) 2026 Chris Boot
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

	"github.com/tvaughan/puppet-ca/internal/ca"
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

// isAdmin reports whether the client is authorized for admin-only operations.
// A client is an admin if its CN is in the allow list, or (unless NoPpCliAuth
// is set) if the certificate carries the pp_cli_auth extension
// (ca.OIDPpCliAuth) with value "true".
func isAdmin(cfg *AuthConfig, clientCert *x509.Certificate, clientCN string) bool {
	return cfg.AllowList[clientCN] || (!cfg.NoPpCliAuth && hasPpCliAuth(clientCert))
}

type authTier int

const (
	tierPublic      authTier = iota // no client cert required
	tierAnyClient                   // any cert signed by this CA
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
//   - tierAnyClient: any CA-signed client cert
//   - tierSelfOrAdmin: own cert or admin CN
//   - tierAdminOnly: admin CN only (signing, revocation, generation)
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

		// SECURITY: Verify the client cert was signed by our CA.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication)
		pool := x509.NewCertPool()
		pool.AddCert(cfg.CACert)
		if _, err := clientCert.Verify(x509.VerifyOptions{
			Roots:     pool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			slog.Warn("Auth: client cert verification failed",
				"cn", clientCert.Subject.CommonName, "error", err)
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}

		clientCN := clientCert.Subject.CommonName

		// SECURITY: CRL-based revocation check on the presented certificate's
		// serial number. Checks the actual presented cert, not the cert on
		// disk for the same CN, so old revoked credentials are rejected even
		// after re-issuance. Fail-closed: a CRL read error is also treated
		// as a denial.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication), SC-17 (PKI Certificates)
		if revoked, err := myCA.IsRevokedSerial(r.Context(), clientCert.SerialNumber); err != nil || revoked {
			if err != nil {
				slog.Warn("Auth: CRL check failed (denying)", "cn", clientCN, "error", err)
			} else {
				slog.Warn("Auth: client cert is revoked", "cn", clientCN)
			}
			http.Error(w, "access denied", http.StatusForbidden)
			return
		}

		switch tier {
		case tierAnyClient:
			next.ServeHTTP(w, r)

		case tierSelfOrAdmin:
			subject := extractPathSubject(r.URL.Path)
			if isAdmin(cfg, clientCert, clientCN) || (subject != "" && clientCN == subject) {
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "access denied", http.StatusForbidden)
			}

		case tierAdminOnly:
			if isAdmin(cfg, clientCert, clientCN) {
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "access denied", http.StatusForbidden)
			}

		default:
			http.Error(w, "access denied", http.StatusForbidden)
		}
	})
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
	// extensions) that could aid infrastructure enumeration. By default,
	// require a CA-signed client cert. Operators can opt in to public access
	// with --allow-public-status for backward compatibility with bootstrapping
	// agents that poll status before obtaining a client certificate.
	// NIST 800-53: AC-3 (Access Enforcement)
	case method == "GET" && strings.HasPrefix(p, "/certificate_status/"):
		if cfg != nil && cfg.AllowPublicStatus {
			return tierPublic
		}
		return tierAnyClient
	case method == "GET" && p == "/expirations":
		return tierPublic

	// Self or admin reads.
	case method == "GET" && strings.HasPrefix(p, "/certificate_request/"):
		return tierSelfOrAdmin

	// Certificate renewal: any CA-signed client cert may renew itself.
	// The handler enforces that the CSR CN matches the authenticated client CN,
	// so an agent can only renew its own certificate.
	case method == "POST" && p == "/certificate_renewal":
		return tierAnyClient

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
