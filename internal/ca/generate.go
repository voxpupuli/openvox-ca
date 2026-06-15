// Copyright (C) 2026 Trevor Vaughan
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

package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"regexp"
)

// maxDNSAltNames is the maximum number of DNS alt names allowed per certificate.
const maxDNSAltNames = 100

// maxDNSNameLen is the maximum length of a single DNS alt name (RFC 1035 limit).
const maxDNSNameLen = 253

// dnsNameRegex matches valid DNS hostnames (RFC 952 / RFC 1123).
var dnsNameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// validateDNSAltNames checks that DNS alt names are well-formed hostnames
// within reasonable bounds.
func validateDNSAltNames(names []string) error {
	if len(names) > maxDNSAltNames {
		return fmt.Errorf("too many DNS alt names (%d > %d)", len(names), maxDNSAltNames)
	}
	for _, name := range names {
		if len(name) > maxDNSNameLen {
			return fmt.Errorf("DNS alt name %q exceeds maximum length (%d > %d)", name, len(name), maxDNSNameLen)
		}
		if !dnsNameRegex.MatchString(name) {
			return fmt.Errorf("invalid DNS alt name %q: must be a valid hostname", name)
		}
	}
	return nil
}

// GenerateResult holds the PEM-encoded private key and signed certificate
// produced by a server-side Generate call.
type GenerateResult struct {
	PrivateKeyPEM  []byte
	CertificatePEM []byte
}

// Generate creates a fresh key pair for subject, signs a certificate for it
// without requiring a client-submitted CSR, saves the private key to
// private/{subject}_key.pem, and returns both PEMs.
//
// The key algorithm and size are controlled by CA.LeafKeyConfig; defaults
// to RSA 2048 when not set.
//
// Returns ErrCertExists (wrapped) if a valid (non-revoked) certificate already
// exists for subject.
func (c *CA) Generate(ctx context.Context, subject string, dnsAltNames []string) (*GenerateResult, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}

	// Validate DNS alt names: must be valid hostnames, bounded count and length.
	if err := validateDNSAltNames(dnsAltNames); err != nil {
		return nil, err
	}

	// Resolve leaf key config; fall back to default if not set.
	leafCfg := c.LeafKeyConfig
	if leafCfg.Algo == "" {
		leafCfg = DefaultLeafKeyConfig
	}

	// Key generation and CSR creation are CPU-bound and do not touch shared
	// state, so they run outside the lock.
	key, err := generateKey(leafCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key for %s: %w", subject, err)
	}

	// Build an internal CSR so sign() can process it normally.
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: subject},
		DNSNames: dnsAltNames,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal CSR for %s: %w", subject, err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Acquire lock for the entire evict + save + sign sequence to prevent
	// TOCTOU races.
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.evictRevokedLocked(ctx, subject); err != nil {
		return nil, err
	}

	if err := c.Storage.SaveCSR(ctx, subject, csrPEM); err != nil {
		return nil, fmt.Errorf("failed to save internal CSR for %s: %w", subject, err)
	}

	certPEM, err := c.sign(ctx, subject)
	if err != nil {
		_ = c.Storage.DeleteCSR(ctx, subject)
		return nil, fmt.Errorf("failed to sign generated cert for %s: %w", subject, err)
	}

	// Encode and save the private key.
	keyPEM, err := marshalPrivateKeyPEM(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key for %s: %w", subject, err)
	}
	if err := c.Storage.SavePrivateKey(ctx, subject, keyPEM); err != nil {
		// Clean up the just-issued certificate to avoid inconsistent state
		// where a cert exists on disk but the corresponding private key doesn't.
		if delErr := c.Storage.DeleteCert(ctx, subject); delErr != nil {
			slog.Warn("Failed to clean up cert after private key save failure",
				"subject", subject, "error", delErr)
		}
		return nil, fmt.Errorf("failed to save private key for %s: %w", subject, err)
	}

	// SECURITY: Log that a private key has been persisted to server storage.
	// Generated keys remain on disk indefinitely; operators should implement
	// external lifecycle controls (rotation, cleanup) for these keys.
	// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
	slog.Debug("Generated private key persisted to server filesystem",
		"subject", subject, "path", c.Storage.PrivateKeyPath(subject))
	slog.Debug("Certificate generated", "subject", subject, "algo", string(leafCfg.Algo))
	return &GenerateResult{
		PrivateKeyPEM:  keyPEM,
		CertificatePEM: certPEM,
	}, nil
}
