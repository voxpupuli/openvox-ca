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
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// maxJSONBody caps the size of JSON request bodies accepted by the POST/PUT
// handlers, matching the 1 MiB limit already applied to CSR submissions. It
// prevents an authenticated client from streaming an unbounded body (e.g. a
// huge certnames array) and exhausting server memory.
const maxJSONBody = 1 << 20 // 1 MiB

// AuthConfig is the mTLS authorization configuration wired into the server.
// Nil means no mTLS enforcement (plain HTTP / dev mode).
type AuthConfig struct {
	CACert            *x509.Certificate
	AllowList         map[string]bool // admin CNs (puppet-server hostnames)
	NoPpCliAuth       bool            // when true, pp_cli_auth extension does not grant admin access
	AllowPublicStatus bool            // when true, GET /certificate_status is public (no client cert required)
}

type Server struct {
	CA         *ca.CA
	AuthConfig *AuthConfig
	// CSRRateLimit is the maximum number of CSR submissions allowed per IP
	// address per minute on the unauthenticated PUT /certificate_request
	// endpoint. Zero (the default) disables rate limiting.
	CSRRateLimit int
	// PlainHTTP is set when the server is running without TLS.
	// The /generate endpoint refuses to serve private keys when this is true.
	PlainHTTP bool
	// SignBatchLimit is the maximum number of certificates that can be signed
	// in a single POST /sign or POST /sign/all request. Zero disables the limit.
	SignBatchLimit int
	// PuppetDateTimeFormat when true formats date/time fields using the original
	// Puppet CA style ("2006-01-02T15:04:05MST") instead of RFC 3339. Useful
	// when integrating with tooling that expects exact Puppet Server output.
	PuppetDateTimeFormat bool

	csrLimiter     *ipRateLimiter
	destructiveOps *destructiveOpTracker
}

func New(c *ca.CA) *Server {
	return &Server{
		CA:             c,
		destructiveOps: newDestructiveOpTracker(5, time.Minute),
	}
}

// Routes registers all handlers and returns the handler (with auth middleware if configured).
// Puppet agents use the /puppet-ca/v1/ prefix; we support both bare and prefixed paths
// so the Go CA can be used directly or behind a stripping proxy.
func (s *Server) Routes() http.Handler {
	if s.CSRRateLimit > 0 {
		s.csrLimiter = newIPRateLimiter(s.CSRRateLimit, time.Minute)
	}

	mux := http.NewServeMux()

	routes := []struct {
		method, path string
		handler      http.HandlerFunc
	}{
		{"GET", "/certificate_status/{subject}", s.handleGetStatus},
		{"PUT", "/certificate_status/{subject}", s.handlePutStatus},
		{"DELETE", "/certificate_status/{subject}", s.handleDeleteStatus},
		{"GET", "/certificate_statuses/{ignored}", s.handleGetStatuses},
		{"GET", "/certificate_request/{subject}", s.handleGetRequest},
		{"PUT", "/certificate_request/{subject}", s.handlePutRequest},
		{"DELETE", "/certificate_request/{subject}", s.handleDeleteRequest},
		{"GET", "/certificate/{subject}", s.handleGetCert},
		{"PUT", "/certificate/{subject}", s.handlePutCert},
		{"GET", "/certificate_revocation_list/ca", s.handleGetCRL},
		{"PUT", "/certificate_revocation_list/ca", s.handleReissueCRL},
		{"POST", "/ocsp", s.handleOCSP},
		{"GET", "/ocsp/{request}", s.handleOCSP},
		{"GET", "/expirations", s.handleGetExpirations},
		{"POST", "/sign", s.handlePostSign},
		{"POST", "/sign/all", s.handlePostSignAll},
		{"PUT", "/clean", s.handlePutClean},
		{"POST", "/generate/{subject}", s.handlePostGenerate},
		{"POST", "/certificate_renewal", s.handlePostCertificateRenewal},
	}

	prefixes := []string{"", "/puppet-ca/v1"}
	for _, r := range routes {
		for _, pfx := range prefixes {
			mux.HandleFunc(r.method+" "+pfx+r.path, r.handler)
		}
	}

	// Health check endpoints are registered only at bare paths (no /puppet-ca/v1
	// prefix) since they are infrastructure probes, not Puppet CA protocol paths.
	mux.HandleFunc("GET /healthz/live", s.handleLive)
	mux.HandleFunc("GET /healthz/ready", s.handleReady)
	mux.HandleFunc("GET /healthz/startup", s.handleStartup)

	return newAuthMiddleware(s.AuthConfig, s.CA, mux)
}

// --- Status ---

type CertStatusResponse struct {
	Name            string            `json:"name"`
	State           string            `json:"state"`
	Fingerprint     string            `json:"fingerprint"`
	Fingerprints    map[string]string `json:"fingerprints"`
	DNSAltNames     []string          `json:"dns_alt_names"`
	SubjectAltNames []string          `json:"subject_alt_names"`
	// AuthorizationExtensions contains Puppet auth-arc OID values keyed by short
	// name (e.g. "pp_auth_role") or raw OID string when no short name is known.
	// Always present, empty map when none exist.
	AuthorizationExtensions map[string]string `json:"authorization_extensions"`
	// Populated when signed or revoked.
	// SerialNumber is a decimal string to preserve the full 128-bit value
	// without loss; int64 would silently truncate random CA/B-Forum serials.
	SerialNumber *string `json:"serial_number,omitempty"`
	NotBefore    *string `json:"not_before,omitempty"`
	NotAfter     *string `json:"not_after,omitempty"`
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("GET certificate_status", "subject", subject, "client", clientCN(r))

	// Check signed dir first.
	certPEM, err := s.CA.Storage.GetCert(r.Context(), subject)
	if err == nil {
		state := "signed"
		if s.CA.IsRevoked(r.Context(), subject) {
			state = "revoked"
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(certStatusFromCert(subject, certPEM, state, s.timeFormat())); err != nil {
			slog.Warn("encode response failed", "error", err)
		}
		return
	}

	// Check CSR (requested).
	csrPEM, err := s.CA.Storage.GetCSR(r.Context(), subject)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(certStatusFromCSR(subject, csrPEM)); err != nil {
			slog.Warn("encode response failed", "error", err)
		}
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

type PutStatusBody struct {
	DesiredState string `json:"desired_state"`
	CertTTL      *int   `json:"cert_ttl,omitempty"` // seconds; 0/absent → default validity
}

func (s *Server) handlePutStatus(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("PUT certificate_status", "subject", subject, "client", clientCN(r))

	var body PutStatusBody
	if !decodeJSONBody(w, r, &body) {
		return
	}

	switch body.DesiredState {
	case "signed":
		var err error
		if body.CertTTL != nil && *body.CertTTL > 0 {
			_, err = s.CA.SignWithTTL(r.Context(), subject, time.Duration(*body.CertTTL)*time.Second)
		} else {
			_, err = s.CA.Sign(r.Context(), subject)
		}
		if err != nil {
			slog.Warn("Sign failed", "subject", subject, "error", err)
			if strings.Contains(err.Error(), "CSR not found") {
				http.Error(w, "CSR not found", http.StatusNotFound)
			} else if strings.Contains(err.Error(), "found extensions that disallow signing") {
				// Signing-policy rejection: the message lists only disallowed
				// OIDs (no filesystem paths), so it is safe to surface and is a
				// useful operator signal.
				http.Error(w, err.Error(), http.StatusConflict)
			} else {
				http.Error(w, "conflict", http.StatusConflict)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case "revoked":
		if err := s.CA.Revoke(r.Context(), subject); err != nil {
			slog.Warn("Revoke failed", "subject", subject, "error", err)
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		if cn := clientCN(r); cn != "" && s.destructiveOps != nil && s.destructiveOps.Record(cn) {
			slog.Warn("High rate of destructive operations detected",
				"client", cn, "operation", "revoke")
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "desired_state must be 'signed' or 'revoked'", http.StatusBadRequest)
	}
}

// --- Certificate ---

func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	slog.Debug("GET certificate", "subject", subject, "client", clientCN(r))

	// Special case: "ca" returns the CA cert.
	if subject == "ca" {
		certPEM, err := s.CA.Storage.GetCACert(r.Context())
		if err != nil {
			http.Error(w, "CA cert not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(certPEM)
		return
	}

	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}

	certPEM, err := s.CA.Storage.GetCert(r.Context(), subject)
	if err != nil {
		http.Error(w, "certificate not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(certPEM)
}

// ImportResponse is returned by PUT /certificate/{subject} on success.
type ImportResponse struct {
	Subject   string `json:"subject"`
	Serial    string `json:"serial"`
	NotBefore string `json:"not_before"` // UTC timestamp, rendered with the server's configured time format (timeFormat())
	NotAfter  string `json:"not_after"`  // UTC timestamp, rendered with the server's configured time format (timeFormat())
	Imported  bool   `json:"imported"`   // false if this was a no-op (already tracked)
}

// handlePutCert imports a certificate that was issued OUTSIDE this CA's
// normal signing flow (e.g. migrated from a legacy CA sharing this CA's
// key) into the inventory under subject, so it appears in listings, has its
// lifetime tracked, and can be revoked via the normal PUT
// certificate_status desired_state=revoked mechanism. This is the only way
// to directly set a subject's certificate outside the CSR-based signing
// flow, hence sharing this path with GET certificate/{subject}. Admin-only
// (enforced by the auth middleware, which defaults non-GET methods on this
// path to tierAdminOnly).
func (s *Server) handlePutCert(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("PUT certificate (import)", "subject", subject, "client", clientCN(r))

	certPEM, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody))
	if err != nil {
		slog.Error("read import cert body failed", "subject", subject, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	result, err := s.CA.ImportCertificate(r.Context(), subject, certPEM)
	if err != nil {
		switch {
		case errors.Is(err, ca.ErrNotInitialized):
			http.Error(w, "CA not ready", http.StatusServiceUnavailable)
		case errors.Is(err, ca.ErrImportInvalid):
			slog.Warn("Import rejected", "subject", subject, "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		case errors.Is(err, ca.ErrSerialExists), errors.Is(err, ca.ErrCertExists):
			slog.Warn("Import conflict", "subject", subject, "error", err)
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			slog.Error("Import failed", "subject", subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(ImportResponse{
		Subject:   result.Subject,
		Serial:    result.Serial,
		NotBefore: result.NotBefore.UTC().Format(s.timeFormat()),
		NotAfter:  result.NotAfter.UTC().Format(s.timeFormat()),
		Imported:  result.Imported,
	}); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- CRL ---

func (s *Server) handleGetCRL(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GET certificate_revocation_list/ca", "client", clientCN(r))

	// Honor If-Modified-Since.
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil {
			if mt, err := s.CA.Storage.CRLModTime(r.Context()); err == nil && !mt.IsZero() {
				if !mt.After(t) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
	}

	crlPEM, err := s.CA.Storage.GetCRL(r.Context())
	if err != nil {
		http.Error(w, "CRL not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(crlPEM)
}

// handleReissueCRL re-signs the CRL with a fresh validity window, preserving
// all existing revocation entries. Admin-only (enforced by the auth middleware,
// which defaults non-GET methods on this path to tierAdminOnly). This lets an
// operator refresh a CRL whose NextUpdate has lapsed (or is about to) without
// having to revoke a certificate.
func (s *Server) handleReissueCRL(w http.ResponseWriter, r *http.Request) {
	slog.Debug("PUT certificate_revocation_list/ca", "client", clientCN(r))

	if err := s.CA.ReissueCRL(r.Context()); err != nil {
		slog.Warn("CRL reissue failed", "error", err)
		http.Error(w, "failed to reissue CRL", http.StatusInternalServerError)
		return
	}

	crlPEM, err := s.CA.Storage.GetCRL(r.Context())
	if err != nil {
		http.Error(w, "CRL not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(crlPEM)
}

// --- CSR ---

func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("GET certificate_request", "subject", subject, "client", clientCN(r))

	csrPEM, err := s.CA.Storage.GetCSR(r.Context(), subject)
	if err != nil {
		http.Error(w, "CSR not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(csrPEM)
}

func (s *Server) handlePutRequest(w http.ResponseWriter, r *http.Request) {
	// SECURITY: Per-IP rate limiting on the unauthenticated CSR submission
	// endpoint. Prevents CSR flooding denial-of-service attacks.
	// NIST 800-53: SC-5 (Denial-of-Service Protection)
	if s.csrLimiter != nil && !s.csrLimiter.Allow(clientIP(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("PUT certificate_request", "subject", subject, "client", clientCN(r))

	// SECURITY: Limit CSR body to 1 MiB to prevent memory exhaustion.
	// NIST 800-53: SC-5 (Denial-of-Service Protection)
	csrPEM, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		slog.Error("read CSR body failed", "subject", subject, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	signed, err := s.CA.SaveRequest(r.Context(), subject, csrPEM)
	if err != nil {
		if errors.Is(err, ca.ErrCertExists) {
			// A signed certificate already exists for this subject. Return 200 so
			// the node continues its poll loop and retrieves its cert via GET.
			// Returning 409 here causes the node (e.g. openvox-agent) to treat the
			// submission as fatal and abort the run entirely.
			w.WriteHeader(http.StatusOK)
		} else if csrValidationError(err) {
			// Client-actionable validation failure (malformed or mis-signed CSR,
			// or CN/subject mismatch). The message is path-free and useful to the
			// agent, so surface it as a 400.
			slog.Warn("SaveRequest rejected", "subject", subject, "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			// Internal storage/autosign fault whose message embeds absolute
			// filesystem paths. On this unauthenticated endpoint we must not leak
			// it: log the detail and return a generic 500.
			slog.Error("SaveRequest internal failure", "subject", subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Puppet CA always returns 200 for PUT /certificate_request, regardless of
	// whether the CSR was autosigned immediately or queued for manual signing.
	_ = signed
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteRequest(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("DELETE certificate_request", "subject", subject, "client", clientCN(r))

	if err := s.CA.Storage.DeleteCSR(r.Context(), subject); err != nil {
		http.Error(w, "CSR not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Server-side cert generation ---

type generateResponse struct {
	PrivateKey  string `json:"private_key"`
	Certificate string `json:"certificate"`
}

func (s *Server) handlePostGenerate(w http.ResponseWriter, r *http.Request) {
	// SECURITY: Refuse to serve private keys over plain HTTP: the response
	// body contains the generated private key in cleartext. Without TLS, any
	// on-path observer can capture the key.
	// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity), SC-12 (Cryptographic Key Establishment and Management)
	if s.PlainHTTP {
		http.Error(w, "private key delivery requires TLS", http.StatusForbidden)
		return
	}

	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("POST generate", "subject", subject, "client", clientCN(r))

	// Optional DNS alt names from query params (?dns=a&dns=b).
	dnsAltNames := r.URL.Query()["dns"]

	result, err := s.CA.Generate(r.Context(), subject, dnsAltNames)
	if err != nil {
		if errors.Is(err, ca.ErrCertExists) {
			slog.Warn("Generate conflict", "subject", subject, "error", err)
			http.Error(w, "certificate already exists", http.StatusConflict)
		} else {
			slog.Error("Generate failed", "subject", subject, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(generateResponse{
		PrivateKey:  string(result.PrivateKeyPEM),
		Certificate: string(result.CertificatePEM),
	}); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// decodeJSONBody caps the request body at maxJSONBody and decodes it into dst.
// On success it returns true. On failure it writes an appropriate error
// response (413 when the size cap is exceeded, otherwise 400 with a safe static
// message) and returns false; the caller must stop processing the request.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

// csrValidationError reports whether err from CA.SaveRequest is a
// client-actionable CSR validation failure whose message is safe to return
// verbatim. These messages contain only the (already-validated) subject name
// and crypto/ASN.1 detail — no filesystem paths. SaveRequest's other failures
// (storage writes, autosign execution) wrap absolute paths, so the handler
// treats anything NOT matched here as internal and returns a generic message.
// Matching is fail-safe: an unrecognised error is treated as internal (no leak),
// at worst returning a less specific message.
func csrValidationError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "does not match requested key") ||
		strings.Contains(s, "failed to decode CSR PEM") ||
		strings.Contains(s, "failed to parse CSR") ||
		strings.Contains(s, "invalid CSR signature")
}

// clientCN extracts the Common Name from the TLS client certificate, if any.
// Returns "" when TLS is not configured or no client cert is presented.
func clientCN(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName
	}
	return ""
}

// signInBatches signs subjects in chunks of SignBatchLimit (if set) and merges
// the results. This prevents unbounded bulk signing while still completing the
// full request rather than rejecting it.
func (s *Server) signInBatches(ctx context.Context, subjects []string) ca.SignResult {
	if s.SignBatchLimit <= 0 || len(subjects) <= s.SignBatchLimit {
		return s.CA.SignMultiple(ctx, subjects)
	}

	merged := ca.SignResult{
		Signed:        []string{},
		NoCSR:         []string{},
		SigningErrors: []string{},
	}
	for i := 0; i < len(subjects); i += s.SignBatchLimit {
		end := min(i+s.SignBatchLimit, len(subjects))
		batch := s.CA.SignMultiple(ctx, subjects[i:end])
		merged.Signed = append(merged.Signed, batch.Signed...)
		merged.NoCSR = append(merged.NoCSR, batch.NoCSR...)
		merged.SigningErrors = append(merged.SigningErrors, batch.SigningErrors...)
	}
	return merged
}

// --- Helpers ---

func parseCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return c, nil
}

func parseCSR(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM")
	}
	c, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	return c, nil
}

// authExtensions extracts Puppet authorization extensions (OID arc 1.3.6.1.4.1.34380.1.3)
// from a certificate or CSR extension list and returns them as a name→value map.
// The key is the Puppet short name when known (e.g. "pp_auth_role"), otherwise
// the raw dotted OID string. The value is the decoded UTF-8 string.
// Always returns a non-nil map (empty when no auth extensions are present).
func authExtensions(exts []pkix.Extension) map[string]string {
	result := make(map[string]string)
	for _, ext := range exts {
		if !ca.IsAuthOID(ext.Id) {
			continue
		}
		key := ca.OIDKey(ext.Id)
		var s string
		if _, err := asn1.Unmarshal(ext.Value, &s); err == nil {
			result[key] = s
		} else {
			result[key] = hex.EncodeToString(ext.Value)
		}
	}
	return result
}

func fingerprint(data []byte) string {
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	// Puppet formats fingerprints as colon-separated hex pairs.
	raw := hex.EncodeToString(sum[:])
	var parts []string
	for i := 0; i < len(raw); i += 2 {
		parts = append(parts, raw[i:i+2])
	}
	return strings.Join(parts, ":")
}

// noNilSlice returns s unchanged when non-nil, or an empty non-nil slice.
// This ensures dns_alt_names serialises as [] rather than null in JSON.
func noNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// timeFormat returns the time layout string to use for JSON date/time fields.
func (s *Server) timeFormat() string {
	if s.PuppetDateTimeFormat {
		return "2006-01-02T15:04:05MST"
	}
	return time.RFC3339
}

// certStatusFromCert builds a CertStatusResponse from a signed or revoked certificate.
func certStatusFromCert(subject string, certPEM []byte, state string, timeFmt string) CertStatusResponse {
	cert, err := parseCert(certPEM)
	if err != nil {
		slog.Warn("Failed to parse cert for status response", "subject", subject, "error", err)
		fp := fingerprint(certPEM)
		return CertStatusResponse{
			Name:                    subject,
			State:                   state,
			Fingerprint:             fp,
			Fingerprints:            map[string]string{"SHA256": fp, "default": fp},
			DNSAltNames:             []string{},
			SubjectAltNames:         []string{},
			AuthorizationExtensions: map[string]string{},
		}
	}
	fp := fingerprint(certPEM)
	serial := cert.SerialNumber.Text(10) // decimal string; preserves full 128-bit value
	nb := cert.NotBefore.UTC().Format(timeFmt)
	na := cert.NotAfter.UTC().Format(timeFmt)
	dnsNames := noNilSlice(cert.DNSNames)
	return CertStatusResponse{
		Name:                    subject,
		State:                   state,
		Fingerprint:             fp,
		Fingerprints:            map[string]string{"SHA256": fp, "default": fp},
		DNSAltNames:             dnsNames,
		SubjectAltNames:         dnsNames,
		AuthorizationExtensions: authExtensions(cert.Extensions),
		SerialNumber:            &serial,
		NotBefore:               &nb,
		NotAfter:                &na,
	}
}

// certStatusFromCSR builds a CertStatusResponse for a pending (requested) CSR.
func certStatusFromCSR(subject string, csrPEM []byte) CertStatusResponse {
	fp := fingerprint(csrPEM)
	csr, err := parseCSR(csrPEM)
	if err != nil {
		slog.Warn("Failed to parse CSR for status response", "subject", subject, "error", err)
		return CertStatusResponse{
			Name:                    subject,
			State:                   "requested",
			Fingerprint:             fp,
			Fingerprints:            map[string]string{"SHA256": fp, "default": fp},
			DNSAltNames:             []string{},
			SubjectAltNames:         []string{},
			AuthorizationExtensions: map[string]string{},
		}
	}
	dnsNames := noNilSlice(csr.DNSNames)
	return CertStatusResponse{
		Name:                    subject,
		State:                   "requested",
		Fingerprint:             fp,
		Fingerprints:            map[string]string{"SHA256": fp, "default": fp},
		DNSAltNames:             dnsNames,
		SubjectAltNames:         dnsNames,
		AuthorizationExtensions: authExtensions(csr.Extensions),
	}
}

// --- Delete status (puppet cert clean) ---

func (s *Server) handleDeleteStatus(w http.ResponseWriter, r *http.Request) {
	subject := r.PathValue("subject")
	if err := ca.ValidateSubject(subject); err != nil {
		http.Error(w, "invalid subject", http.StatusBadRequest)
		return
	}
	slog.Debug("DELETE certificate_status", "subject", subject, "client", clientCN(r))

	if err := s.CA.Clean(r.Context(), subject); err != nil {
		slog.Warn("Clean failed", "subject", subject, "error", err)
		if errors.Is(err, ca.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
		} else {
			http.Error(w, "conflict", http.StatusConflict)
		}
		return
	}
	if cn := clientCN(r); cn != "" && s.destructiveOps != nil && s.destructiveOps.Record(cn) {
		slog.Warn("High rate of destructive operations detected",
			"client", cn, "operation", "clean")
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Certificate statuses (list all) ---

func (s *Server) handleGetStatuses(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GET certificate_statuses", "client", clientCN(r))

	stateFilter := r.URL.Query().Get("state") // "requested", "signed", "revoked", or ""

	certs, err := s.CA.Storage.ListCerts(r.Context())
	if err != nil {
		slog.Error("list certs failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	csrs, err := s.CA.Storage.ListCSRs(r.Context())
	if err != nil {
		slog.Error("list CSRs failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	statuses := make([]CertStatusResponse, 0, len(certs)+len(csrs))

	seen := make(map[string]bool)
	for _, subject := range certs {
		seen[subject] = true
		certPEM, err := s.CA.Storage.GetCert(r.Context(), subject)
		if err != nil {
			continue
		}
		state := "signed"
		if s.CA.IsRevoked(r.Context(), subject) {
			state = "revoked"
		}
		if stateFilter != "" && state != stateFilter {
			continue
		}
		statuses = append(statuses, certStatusFromCert(subject, certPEM, state, s.timeFormat()))
	}
	for _, subject := range csrs {
		if seen[subject] {
			continue
		}
		if stateFilter != "" && stateFilter != "requested" {
			continue
		}
		csrPEM, err := s.CA.Storage.GetCSR(r.Context(), subject)
		if err != nil {
			continue
		}
		statuses = append(statuses, certStatusFromCSR(subject, csrPEM))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(statuses); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- Expirations ---

type ExpirationsResponse struct {
	CACrl         CRLExpiration  `json:"ca_crl"`
	CACertificate CertExpiration `json:"ca_certificate"`
}

type CRLExpiration struct {
	NextUpdate string `json:"next_update"`
}

type CertExpiration struct {
	Expiration string `json:"expiration"`
}

func (s *Server) handleGetExpirations(w http.ResponseWriter, r *http.Request) {
	slog.Debug("GET expirations", "client", clientCN(r))

	// Without this guard a request that reaches the handler before Init()
	// finishes would dereference a nil CACert below and panic the server.
	if !s.CA.IsReady() {
		http.Error(w, "CA not ready", http.StatusServiceUnavailable)
		return
	}
	certExp := s.CA.CACert.NotAfter.UTC().Format(s.timeFormat())

	crlNextUpdate := ""
	if crlPEM, err := s.CA.Storage.GetCRL(r.Context()); err == nil {
		if block, _ := pem.Decode(crlPEM); block != nil {
			if crl, err := x509.ParseRevocationList(block.Bytes); err == nil {
				crlNextUpdate = crl.NextUpdate.UTC().Format(s.timeFormat())
			}
		}
	}

	resp := ExpirationsResponse{
		CACrl:         CRLExpiration{NextUpdate: crlNextUpdate},
		CACertificate: CertExpiration{Expiration: certExp},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- Bulk sign ---

type SignRequestBody struct {
	Certnames []string `json:"certnames"`
}

func (s *Server) handlePostSign(w http.ResponseWriter, r *http.Request) {
	cn := clientCN(r)
	slog.Debug("POST sign", "client", cn)

	var body SignRequestBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if len(body.Certnames) == 0 {
		http.Error(w, "certnames must not be empty", http.StatusBadRequest)
		return
	}

	slog.Debug("Signing certificates", "count", len(body.Certnames), "subjects", body.Certnames, "client", cn)
	result := s.signInBatches(r.Context(), body.Certnames)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- Certificate renewal ---

func (s *Server) handlePostCertificateRenewal(w http.ResponseWriter, r *http.Request) {
	// Renewal requires an authenticated client cert to establish identity.
	cn := clientCN(r)
	if cn == "" {
		http.Error(w, "client certificate required for renewal", http.StatusForbidden)
		return
	}
	slog.Debug("POST certificate_renewal", "client", cn)

	// SECURITY: Limit body to 1 MiB to prevent memory exhaustion.
	// NIST 800-53: SC-5 (Denial-of-Service Protection)
	csrPEM, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		slog.Error("read renewal CSR body failed", "client", cn, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	csr, err := parseCSR(csrPEM)
	if err != nil {
		http.Error(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}

	// SECURITY: CSR CN must match the authenticated client CN. Without this
	// check an agent could renew another agent's certificate by sending a CSR
	// with a different CN while authenticating as itself.
	// NIST 800-53: IA-5(2) (PKI-Based Authentication)
	if csr.Subject.CommonName != cn {
		slog.Warn("Renewal rejected: CN mismatch", "client_cn", cn, "csr_cn", csr.Subject.CommonName)
		http.Error(w, "CSR CN does not match authenticated client CN", http.StatusForbidden)
		return
	}

	certPEM, err := s.CA.Renew(r.Context(), cn, csrPEM)
	if err != nil {
		slog.Warn("Renewal failed", "subject", cn, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(certPEM)
}

func (s *Server) handlePostSignAll(w http.ResponseWriter, r *http.Request) {
	cn := clientCN(r)
	slog.Debug("POST sign/all", "client", cn)

	pending, err := s.CA.Storage.ListCSRs(r.Context())
	if err != nil {
		slog.Error("list pending CSRs failed", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	result := s.signInBatches(r.Context(), pending)
	slog.Debug("Signed all pending CSRs", "signed", len(result.Signed), "errors", len(result.SigningErrors), "client", cn)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}

// --- Bulk clean ---

func (s *Server) handlePutClean(w http.ResponseWriter, r *http.Request) {
	cn := clientCN(r)
	slog.Debug("PUT clean", "client", cn)

	var body SignRequestBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if len(body.Certnames) == 0 {
		http.Error(w, "certnames must not be empty", http.StatusBadRequest)
		return
	}

	slog.Debug("Cleaning certificates", "count", len(body.Certnames), "subjects", body.Certnames, "client", cn)
	result := s.CA.CleanMultiple(r.Context(), body.Certnames)
	if cn != "" && s.destructiveOps != nil && s.destructiveOps.Record(cn) {
		slog.Warn("High rate of destructive operations detected", "client", cn, "operation", "bulk-clean")
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Warn("encode response failed", "error", err)
	}
}
