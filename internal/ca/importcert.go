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

package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// ErrImportInvalid is returned by ImportCertificate for any client-supplied
// input problem: malformed/undecodable PEM, a signature that does not chain
// to this CA, a CA certificate (IsCA=true), a subject that fails
// ValidateSubject or does not match the certificate's CN/SANs, or a
// malformed validity window. The wrapped message is safe to return to the
// caller verbatim (contains no filesystem paths).
var ErrImportInvalid = errors.New("invalid certificate for import")

// ErrSerialExists is returned by ImportCertificate when the certificate's
// serial number is already present in the inventory, under this subject or
// another one.
var ErrSerialExists = errors.New("serial number already tracked in inventory")

// ImportResult describes the outcome of a successful ImportCertificate call.
type ImportResult struct {
	Subject   string
	Serial    string // uppercase hex, no leading zeros — the form used in the inventory, CRL, and OCSP responses
	NotBefore time.Time
	NotAfter  time.Time
	Imported  bool // false when this call was a no-op (cert already tracked identically)
}

// certMatchesSubject reports whether subject equals the certificate's CN or
// one of its DNS Subject Alternative Names.
func certMatchesSubject(cert *x509.Certificate, subject string) bool {
	if cert.Subject.CommonName == subject {
		return true
	}
	for _, name := range cert.DNSNames {
		if name == subject {
			return true
		}
	}
	return false
}

// ImportCertificate registers a certificate that was issued OUTSIDE this
// CA's normal signing flow (e.g. migrated from a legacy CA sharing this
// CA's key, or produced by some other offline process) into the inventory
// under the given subject, so it appears in listings, has its lifetime
// tracked, and can be revoked via Revoke(subject).
//
// certPEM must contain exactly one CERTIFICATE block whose signature
// verifies against this CA's certificate. No other x509.Verify constraint
// (validity window, key usage) is enforced, so an already-expired legacy
// certificate can still be imported for record-keeping/CRL purposes. The
// certificate's CN or one of its DNS SANs must equal subject.
//
// The caller must NOT hold c.mu. Serialises on the same cluster-wide
// per-subject lock as Sign/SignWithTTL/Renew.
//
// Returns, for errors.Is branching:
//   - ErrNotInitialized — the CA certificate or key has not been loaded.
//   - ErrImportInvalid — any client-supplied input problem (see its doc).
//   - ErrSerialExists — the certificate's serial is already tracked.
//   - ErrCertExists — a live certificate already exists for subject.
func (c *CA) ImportCertificate(ctx context.Context, subject string, certPEM []byte) (*ImportResult, error) {
	if c.CACert == nil || c.CAKey == nil {
		return nil, ErrNotInitialized
	}
	if err := ValidateSubject(subject); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrImportInvalid, err)
	}

	block, rest := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode certificate PEM", ErrImportInvalid)
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, fmt.Errorf("%w: PEM input contains more than one block; submit a single certificate", ErrImportInvalid)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrImportInvalid, err)
	}

	// SECURITY: prove this certificate was genuinely issued by this CA's key
	// before it can enter the trusted inventory (which feeds OCSP "good"
	// responses and by-subject revocation). CheckSignatureFrom is a pure
	// cryptographic signature check — unlike cert.Verify, it does not enforce
	// current-time validity, so an intentionally-expired legacy certificate
	// being archived is still accepted.
	if err := cert.CheckSignatureFrom(c.CACert); err != nil {
		return nil, fmt.Errorf("%w: certificate was not signed by this CA: %v", ErrImportInvalid, err)
	}

	if cert.IsCA {
		return nil, fmt.Errorf("%w: refusing to import a CA certificate (use openvox-ca-ctl import for CA bundles)", ErrImportInvalid)
	}

	if !certMatchesSubject(cert, subject) {
		return nil, fmt.Errorf("%w: subject %q matches neither the certificate's CN nor its DNS SANs", ErrImportInvalid, subject)
	}

	serialStr := serialHexStr(cert.SerialNumber)
	if cert.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("%w: certificate has a non-positive serial number", ErrImportInvalid)
	}

	if !cert.NotAfter.After(cert.NotBefore) {
		return nil, fmt.Errorf("%w: NotAfter (%s) is not after NotBefore (%s)", ErrImportInvalid, cert.NotAfter, cert.NotBefore)
	}

	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	var out *ImportResult
	err = c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		res, err := c.importCertificateLocked(ctx, subject, serialStr, cert, certPEM)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	return out, err
}

// importCertificateLocked performs the storage-mutating part of
// ImportCertificate. c.mu must be held by the caller.
func (c *CA) importCertificateLocked(ctx context.Context, subject, serialStr string, cert *x509.Certificate, certPEM []byte) (*ImportResult, error) {
	// Idempotent-duplicate check: if the exact same certificate is already
	// the live cert tracked for this subject, accept with no further writes.
	if c.Storage.HasCert(ctx, subject) {
		existingPEM, err := c.Storage.GetCert(ctx, subject)
		if err == nil {
			if block, _ := pem.Decode(existingPEM); block != nil {
				if existingCert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if existingCert.SerialNumber.Cmp(cert.SerialNumber) == 0 && bytes.Equal(existingCert.Raw, cert.Raw) {
						return &ImportResult{
							Subject:   subject,
							Serial:    serialStr,
							NotBefore: cert.NotBefore,
							NotAfter:  cert.NotAfter,
							Imported:  false,
						}, nil
					}
				}
			}
		}
	}

	// Global serial-conflict check (ordering pre-check only — see
	// AppendInventory below for the authoritative, race-safe enforcement).
	// This exists purely so that a request tripping both the serial-conflict
	// and active-certificate-conflict conditions reports ErrSerialExists,
	// matching the documented priority order, rather than whichever check
	// happened to run first.
	exists, err := c.Storage.SerialExists(ctx, serialStr)
	if err != nil {
		return nil, fmt.Errorf("failed to check serial uniqueness for %s: %w", subject, err)
	}
	if exists {
		return nil, fmt.Errorf("%w: serial %s", ErrSerialExists, serialStr)
	}

	// Active-certificate check / revoked eviction: blocks if a live cert
	// already exists for this subject, evicts it if revoked.
	if err := c.evictRevokedLocked(ctx, subject); err != nil {
		return nil, err
	}

	if err := c.Storage.SaveCert(ctx, subject, certPEM); err != nil {
		return nil, fmt.Errorf("failed to save imported cert for %s: %w", subject, err)
	}

	inventoryEntry := storage.FormatInventoryLine(serialStr, cert.NotBefore, cert.NotAfter, subject)
	if err := c.Storage.AppendInventory(ctx, inventoryEntry); err != nil {
		// Roll back the cert so storage and inventory stay in sync, same as
		// signWithDuration's rollback-on-failure.
		if delErr := c.Storage.DeleteCert(ctx, subject); delErr != nil {
			slog.Warn("Failed to roll back cert after inventory write failure",
				"subject", subject, "error", delErr)
		}
		if errors.Is(err, storage.ErrDuplicateSerial) {
			return nil, fmt.Errorf("%w: %v", ErrSerialExists, err)
		}
		return nil, fmt.Errorf("failed to update inventory for %s: %w", subject, err)
	}

	// Update in-memory serial index for O(1) OCSP lookups.
	c.serialIndex[serialStr] = subject

	slog.Info("Certificate imported",
		"subject", subject,
		"serial", serialStr,
		"not_before", cert.NotBefore.Format(time.RFC3339),
		"not_after", cert.NotAfter.Format(time.RFC3339),
	)

	return &ImportResult{
		Subject:   subject,
		Serial:    serialStr,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Imported:  true,
	}, nil
}
