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

package ca

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"
	"time"
)

const (
	// certValidity is the lifetime issued to CA and leaf certificates.
	certValidity = 5 * 365 * 24 * time.Hour
	// CRLValidity is the default validity window written into every CRL.
	CRLValidity = 30 * 24 * time.Hour
)

// crlValidity returns the CA's configured CRL validity period.
// When CRLValidityDays is zero the package-level CRLValidity default is used.
func (c *CA) crlValidity() time.Duration {
	if c.CRLValidityDays > 0 {
		return time.Duration(c.CRLValidityDays) * 24 * time.Hour
	}
	return CRLValidity
}

// serialHexStr formats a serial number as uppercase hexadecimal without
// leading zeros. This is the canonical key used in the serial index and
// OCSP cache, and the form written to the inventory file.
func serialHexStr(n *big.Int) string {
	return fmt.Sprintf("%X", n)
}

// ErrCertExists is returned by SaveRequest when a valid (non-revoked) certificate
// already exists for the requested subject.
var ErrCertExists = errors.New("certificate already exists")

// ErrNotInitialized is returned by signing helpers when the CA's certificate
// or private key has not been loaded — typically because Init has not been
// called or it failed. Exposed as a sentinel so HTTP handlers can detect the
// init-order case via errors.Is and answer with a controlled status (e.g.
// 503 Service Unavailable) rather than treating it as a generic signing
// failure.
var ErrNotInitialized = errors.New("CA not initialized")

// evictRevokedLocked checks whether a certificate already exists for subject.
//   - No cert on disk → returns nil (proceed with issuance).
//   - Cert exists and is NOT revoked → returns ErrCertExists (block issuance).
//   - Cert exists and IS revoked → deletes it and returns nil (allow re-issuance).
//
// c.mu must be held by the caller. This method checks revocation via the
// in-memory CRL cache directly to avoid re-acquiring the lock.
func (c *CA) evictRevokedLocked(ctx context.Context, subject string) error {
	if !c.Storage.HasCert(ctx, subject) {
		return nil
	}

	// Check revocation against cachedCRL directly (no lock acquisition).
	certPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}

	revoked := false
	if c.cachedCRL != nil {
		for _, entry := range c.cachedCRL.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				revoked = true
				break
			}
		}
	}

	if !revoked {
		return fmt.Errorf("certificate already exists for %s: %w", subject, ErrCertExists)
	}
	slog.Debug("Removing revoked certificate", "subject", subject)
	if err := c.Storage.DeleteCert(ctx, subject); err != nil {
		slog.Warn("Could not remove revoked certificate", "subject", subject, "error", err)
	}
	return nil
}

var subjectRegex = regexp.MustCompile(`^[a-z0-9._-]+$`)

// ValidateSubject returns an error if subject contains unsafe characters.
// It is the single source of truth for subject name validation used by both
// the CA layer and the API layer. Rejects path traversal (e.g. "..") and
// any characters outside the safe set.
// NIST 800-53: SI-10 (Information Input Validation)
func ValidateSubject(subject string) error {
	if !subjectRegex.MatchString(subject) || strings.Contains(subject, "..") {
		return fmt.Errorf("invalid subject name %q: must match ^[a-z0-9._-]+$ and must not contain ..", subject)
	}
	return nil
}

// Sign creates and persists a certificate for the pending CSR of subject.
// The caller must NOT hold c.mu. Serialises on the cluster-wide per-subject
// lock so concurrent sign attempts from different replicas cannot produce
// two certificates for the same subject.
func (c *CA) Sign(ctx context.Context, subject string) ([]byte, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	var out []byte
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		pem, err := c.signWithDuration(ctx, subject, 0)
		if err != nil {
			return err
		}
		out = pem
		return nil
	})
	return out, err
}

// SignWithTTL signs subject's pending CSR with a custom validity duration.
// ttl=0 falls back to the default certValidity.
// The caller must NOT hold c.mu. Same cross-node guarantees as Sign.
func (c *CA) SignWithTTL(ctx context.Context, subject string, ttl time.Duration) ([]byte, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	var out []byte
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		pem, err := c.signWithDuration(ctx, subject, ttl)
		if err != nil {
			return err
		}
		out = pem
		return nil
	})
	return out, err
}

// sign is the internal (unlocked) signing implementation using the default TTL.
// c.mu must be held by the caller.
func (c *CA) sign(ctx context.Context, subject string) ([]byte, error) {
	return c.signWithDuration(ctx, subject, 0)
}

// signWithDuration is the actual internal signing implementation.
// ttl=0 means use the default certValidity.
// c.mu must be held by the caller.
func (c *CA) signWithDuration(ctx context.Context, subject string, ttl time.Duration) ([]byte, error) {
	// Defensive: a nil CACert here means the caller skipped Init() (or it
	// failed). Without this guard the c.CACert.NotAfter dereference below
	// would panic the entire frontend.
	if c.CACert == nil || c.CAKey == nil {
		return nil, ErrNotInitialized
	}
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}

	slog.Debug("Signing certificate", "subject", subject)

	csrPEM, err := c.Storage.GetCSR(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("CSR not found for %s: %w", subject, err)
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM for %s", subject)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR for %s: %w", subject, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature for %s: %w", subject, err)
	}

	// SECURITY: Reject CSRs that request CA capabilities (BasicConstraints:
	// CA:TRUE, OID 2.5.29.19). Without this check a submitted CSR could produce
	// a subordinate CA certificate, enabling the holder to sign arbitrary certs.
	// NIST 800-53: CM-7 (Least Functionality), IA-5(2) (PKI-Based Authentication)
	oidBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidBasicConstraints) {
			var bc struct {
				IsCA bool `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &bc); err == nil && bc.IsCA {
				return nil, fmt.Errorf("Found extensions that disallow signing: [2.5.29.19]")
			}
		}
	}

	// SECURITY: Generate a random 128-bit serial number (CA/Browser Forum guidance).
	// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialInt, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial for %s: %w", subject, err)
	}
	serialStr := serialHexStr(serialInt)

	now := time.Now().UTC()

	validity := certValidity
	if ttl > 0 {
		validity = ttl
	} else if c.LeafValidityDays > 0 {
		validity = time.Duration(c.LeafValidityDays) * 24 * time.Hour
	}

	// Cap validity to the CA certificate's remaining lifetime.
	// A leaf cert must never outlive the CA that signed it; if it did, the cert
	// would appear valid after the CA cert expired, breaking chain verification.
	caRemaining := time.Until(c.CACert.NotAfter)
	if caRemaining <= 0 {
		return nil, fmt.Errorf("CA certificate has expired")
	}
	if validity > caRemaining {
		validity = caRemaining
	}

	// SubjectKeyIdentifier: SHA1 of the SubjectPublicKeyInfo DER (RFC 5280 §4.2.1.2).
	pubKeyDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key for %s: %w", subject, err)
	}
	subjectKeyID := sha1.Sum(pubKeyDER)

	template := &x509.Certificate{
		SerialNumber: serialInt,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(validity),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},

		BasicConstraintsValid: true,
		IsCA:                  false,

		SubjectKeyId:   subjectKeyID[:],
		AuthorityKeyId: c.CACert.SubjectKeyId,

		DNSNames: csr.DNSNames,
	}

	// RFC 2818 §3.1: TLS clients match the server name against SANs, not the
	// CN. When the CSR carries no SANs and promotion is enabled, add the CN as
	// a DNS SAN so that the issued certificate works with modern TLS stacks.
	if c.PromoteCNToSAN && len(template.DNSNames) == 0 && csr.Subject.CommonName != "" {
		template.DNSNames = []string{csr.Subject.CommonName}
	}

	// CRL Distribution Points: embed CRL URL(s) when configured so that
	// verifiers can automatically fetch the CRL (RFC 5280 §4.2.1.13).
	if len(c.CRLURLs) > 0 {
		template.CRLDistributionPoints = c.CRLURLs
	}

	// Authority Information Access: embed OCSP URL when configured.
	if len(c.OCSPURLs) > 0 {
		aiaValue, err := buildAIAExtension(c.OCSPURLs)
		if err != nil {
			return nil, fmt.Errorf("failed to build AIA extension for %s: %w", subject, err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    OIDAIA,
			Value: aiaValue,
		})
	}

	// SECURITY: Copy Puppet OID extensions from the CSR, excluding
	// authorization-arc OIDs (1.3.6.1.4.1.34380.1.3.*). Allowing CSRs to
	// inject auth OIDs like pp_cli_auth would let any agent request admin
	// privileges, which is a direct privilege escalation.
	// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
	for _, ext := range csr.Extensions {
		if IsPuppetOID(ext.Id) && !IsAuthOID(ext.Id) {
			template.ExtraExtensions = append(template.ExtraExtensions, ext)
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, c.CACert, csr.PublicKey, c.CAKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate for %s: %w", subject, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	if err := c.Storage.SaveCert(ctx, subject, certPEM); err != nil {
		return nil, fmt.Errorf("failed to save cert for %s: %w", subject, err)
	}

	inventoryEntry := fmt.Sprintf("%s %s %s /%s",
		serialStr,
		template.NotBefore.Format("2006-01-02T15:04:05UTC"),
		template.NotAfter.Format("2006-01-02T15:04:05UTC"),
		subject,
	)
	if err := c.Storage.AppendInventory(ctx, inventoryEntry); err != nil {
		// Roll back the cert so storage and inventory stay in sync. Log but don't
		// propagate the cleanup error; the caller already has an error to handle.
		if delErr := c.Storage.DeleteCert(ctx, subject); delErr != nil {
			slog.Warn("Failed to roll back cert after inventory write failure",
				"subject", subject, "error", delErr)
		}
		return nil, fmt.Errorf("failed to update inventory for %s: %w", subject, err)
	}

	// Update in-memory serial index for O(1) OCSP lookups.
	c.serialIndex[serialStr] = subject

	// Remove the pending CSR now that we have a signed cert.
	if err := c.Storage.DeleteCSR(ctx, subject); err != nil {
		slog.Warn("Could not delete CSR after signing", "subject", subject, "error", err)
	}

	slog.Debug("Certificate signed",
		"subject", subject,
		"serial", serialStr,
		"not_before", template.NotBefore.Format(time.RFC3339),
		"not_after", template.NotAfter.Format(time.RFC3339),
	)
	return certPEM, nil
}

// Clean revokes (if signed) and removes both the certificate and any pending CSR
// for subject. It is the "puppet cert clean" equivalent: the subject must have at
// least a cert or CSR on disk, otherwise ErrNotFound is returned.
//
// Errors from individual operations (revoke, delete) are best-effort and logged
// but do not prevent the others from running.
var ErrNotFound = fmt.Errorf("certificate or CSR not found")

func (c *CA) Clean(ctx context.Context, subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	// Hold the per-subject lock for the entire check+revoke+delete sequence to
	// prevent TOCTOU races with concurrent Sign() or SaveRequest() calls. Without
	// the lock, a Sign() completing between HasCert() and DeleteCert() would leave
	// an unrevoked certificate in storage after Clean() returns.
	//
	// Lock ordering: subject-lock (distributed) → CRL-lock (distributed) → c.mu.
	// No existing code path acquires CRL-lock then subject-lock, so no deadlock.
	lockErr := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		hasCert := c.Storage.HasCert(ctx, subject)
		hasCSR := c.Storage.HasCSR(ctx, subject)

		if !hasCert && !hasCSR {
			return ErrNotFound
		}

		if hasCert {
			// Revoke first so the CRL is updated before the file is removed.
			// Acquire the CRL lock directly here (inside the subject lock) and
			// call revokeLocked to avoid double-locking via the public Revoke().
			if err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.revokeLocked(ctx, subject)
			}); err != nil {
				slog.Warn("Clean: revoke failed (proceeding with delete)", "subject", subject, "error", err)
			}
			if err := c.Storage.DeleteCert(ctx, subject); err != nil {
				slog.Warn("Clean: delete cert failed", "subject", subject, "error", err)
			}
		}

		if hasCSR {
			if err := c.Storage.DeleteCSR(ctx, subject); err != nil {
				slog.Warn("Clean: delete CSR failed", "subject", subject, "error", err)
			}
		}

		return nil
	})
	if lockErr != nil {
		return lockErr
	}

	slog.Debug("Certificate cleaned", "subject", subject)
	return nil
}

// SignResult holds the outcome of a bulk signing operation.
type SignResult struct {
	Signed        []string `json:"signed"`
	NoCSR         []string `json:"no-csr"`
	SigningErrors []string `json:"signing-errors"`
}

// SignMultiple signs the CSRs for the given subjects.
// Subjects with no pending CSR are collected in NoCSR; those that fail signing
// are collected in SigningErrors.
func (c *CA) SignMultiple(ctx context.Context, subjects []string) SignResult {
	result := SignResult{
		Signed:        []string{},
		NoCSR:         []string{},
		SigningErrors: []string{},
	}
	for _, subject := range subjects {
		if !c.Storage.HasCSR(ctx, subject) {
			result.NoCSR = append(result.NoCSR, subject)
			continue
		}
		if _, err := c.Sign(ctx, subject); err != nil {
			slog.Warn("Bulk sign failed", "subject", subject, "error", err)
			result.SigningErrors = append(result.SigningErrors, subject)
		} else {
			result.Signed = append(result.Signed, subject)
		}
	}
	return result
}

// SignAll signs every pending CSR currently on disk.
func (c *CA) SignAll(ctx context.Context) (SignResult, error) {
	subjects, err := c.Storage.ListCSRs(ctx)
	if err != nil {
		return SignResult{}, fmt.Errorf("listing CSRs: %w", err)
	}
	return c.SignMultiple(ctx, subjects), nil
}

// CleanResult holds the outcome of a bulk clean operation.
type CleanResult struct {
	Cleaned     []string `json:"cleaned"`
	NotFound    []string `json:"not-found"`
	CleanErrors []string `json:"clean-errors"`
}

// CleanMultiple revokes and removes the cert and CSR for each subject.
// Subjects not found are collected in NotFound; other errors in CleanErrors.
func (c *CA) CleanMultiple(ctx context.Context, subjects []string) CleanResult {
	result := CleanResult{
		Cleaned:     []string{},
		NotFound:    []string{},
		CleanErrors: []string{},
	}
	for _, subject := range subjects {
		if err := c.Clean(ctx, subject); err != nil {
			if errors.Is(err, ErrNotFound) {
				result.NotFound = append(result.NotFound, subject)
			} else {
				slog.Warn("Bulk clean failed", "subject", subject, "error", err)
				result.CleanErrors = append(result.CleanErrors, subject)
			}
		} else {
			result.Cleaned = append(result.Cleaned, subject)
		}
	}
	return result
}

// SaveRequest validates, persists the CSR, and triggers autosigning if configured.
func (c *CA) SaveRequest(ctx context.Context, subject string, csrPEM []byte) (bool, error) {
	if err := ValidateSubject(subject); err != nil {
		return false, err
	}

	// Validate the CSR PEM before writing anything to disk.
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return false, fmt.Errorf("failed to decode CSR PEM for %s", subject)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse CSR for %s: %w", subject, err)
	}

	// SECURITY: Verify the CSR's proof-of-possession signature before storing.
	// Without this check an attacker can submit a CSR with someone else's
	// public key (identity theft). The signature proves the submitter holds
	// the private key corresponding to the CSR's public key.
	// NIST 800-53: IA-5(2) (PKI-Based Authentication)
	if err := csr.CheckSignature(); err != nil {
		return false, fmt.Errorf("invalid CSR signature for %s: %w", subject, err)
	}

	// SECURITY: CN in the CSR must match the URL subject. Without this check
	// an attacker could submit a CSR for "admin.example.com" via the URL path
	// for "node1.example.com", obtaining a certificate for a different identity.
	// NIST 800-53: IA-5(2) (PKI-Based Authentication), SI-10 (Information Input Validation)
	if csr.Subject.CommonName != subject {
		return false, fmt.Errorf("Instance name %s does not match requested key %s",
			csr.Subject.CommonName, subject)
	}

	// SECURITY: Warn if the CSR carries authorization-arc OIDs. These will be
	// stripped during signing but the submission itself is suspicious and may
	// indicate a privilege escalation attempt.
	// NIST 800-53: AU-6 (Audit Record Review, Analysis, and Reporting)
	for _, ext := range csr.Extensions {
		if IsAuthOID(ext.Id) {
			slog.Warn("CSR contains authorization extension that will be stripped",
				"subject", subject, "oid", ext.Id.String())
		}
	}

	slog.Debug("Received CSR", "subject", subject)

	// Acquire the cluster-wide per-subject lock for the entire evict + save +
	// autosign sequence. This prevents TOCTOU races where two concurrent
	// SaveRequest calls (same or different replicas) both pass eviction and
	// produce duplicate certificates.
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	var autosigned bool
	lockErr := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		c.mu.Lock()
		defer c.mu.Unlock()

		// Reject if a cert already exists and is not revoked; clear it if
		// revoked so the node can re-register with a fresh key.
		if err := c.evictRevokedLocked(ctx, subject); err != nil {
			return err
		}

		if err := c.Storage.SaveCSR(ctx, subject, csrPEM); err != nil {
			return fmt.Errorf("failed to save CSR for %s: %w", subject, err)
		}

		shouldSign, err := CheckAutosign(c.AutosignConfig, csr, csrPEM)
		if err != nil {
			return fmt.Errorf("autosign check failed for %s: %w", subject, err)
		}

		if shouldSign {
			slog.Debug("Autosigning CSR", "subject", subject)
			if _, err := c.sign(ctx, subject); err != nil {
				return err
			}
			autosigned = true
			return nil
		}

		slog.Debug("CSR saved, awaiting manual signing", "subject", subject)
		return nil
	})
	if lockErr != nil {
		return false, lockErr
	}
	return autosigned, nil
}
