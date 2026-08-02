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

package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"
)

// Revoke serialises on the cluster-wide "crl" lock so concurrent revocations
// (and any future CRL rotation) on different replicas cannot both read the
// same CRL, each append their own entry, and clobber one another's write.
//
// It takes the per-subject lock first, as Clean does. Without it reassertNotRevoked
// would still be a check-then-act: a revocation resolving the outgoing serial
// while the replacement is being minted is defeated exactly as one landing
// during the lock wait is, only over a shorter window. Holding the subject lock
// leaves a revocation two orderings against a renewal for the same subject, and
// both are answers rather than races — it commits first and the re-check refuses
// the renewal, or the renewal completes and the revocation then retires the
// serial that renewal issued.
//
// The cost is that a revocation now waits for an issuance already under way for
// that subject, which is the same trade Clean has always made (see the lock note
// there); PUT /certificate_status is not on a latency budget, and one signing
// operation is the most it can wait behind.
//
// Lock ordering: subject-lock (distributed) → CRL-lock (distributed) → c.mu,
// matching Clean, and no path takes those two in the other order. Callers must
// therefore not already hold the subject lock: those that do — Clean, and the
// post-issue revokes in Renew and AutoRenew — reach revokeLocked or
// revokeSerialLocked directly rather than coming through here.
func (c *CA) Revoke(ctx context.Context, subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	return c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		return c.Storage.WithLock(ctx, lockNameCRL, func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.revokeLocked(ctx, subject)
		})
	})
}

// revokeLocked performs the actual CRL read-modify-write. The cluster CRL
// lock and c.mu must both be held by the caller.
func (c *CA) revokeLocked(ctx context.Context, subject string) error {
	slog.Debug("Revoking certificate", "subject", subject)

	serialStr, err := c.findSerialForSubject(ctx, subject)
	if err != nil {
		return fmt.Errorf("could not find certificate for subject %s: %w", subject, err)
	}

	if err := c.revokeSerialLocked(ctx, serialStr); err != nil {
		return err
	}

	slog.Debug("Certificate revoked", "subject", subject, "serial", serialStr)
	return nil
}

// revokeSerialLocked adds serialStr to the CRL, unless it is already present.
// The cluster CRL lock and c.mu must both be held by the caller.
//
// This is split out from revokeLocked so Renew and AutoRenew can revoke the
// exact serial of the certificate they are replacing. By the time either
// wants to revoke, issueLeafLocked has already appended the new cert's row
// to the inventory, so findSerialForSubject (latest-issued-for-subject) would
// resolve to the new serial rather than the one being retired.
func (c *CA) revokeSerialLocked(ctx context.Context, serialStr string) error {
	serialInt := new(big.Int)
	if _, ok := serialInt.SetString(serialStr, 16); !ok {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("malformed serial %q", serialStr)
	}

	// 1. Load CRL
	crl, err := c.readStoredCRL(ctx)
	if err != nil {
		c.crlUpdateFailures.Add(1)
		return err
	}

	// 2. Check for duplicate revocation: a serial that's already in the CRL
	// should not be appended again (prevents unbounded CRL growth on retries).
	if serialInCRL(crl, serialInt) {
		slog.Debug("Certificate already revoked", "serial", serialStr)
		return nil
	}

	// 3. Append the new entry and re-sign. signCRLLocked counts its own
	// sign/write failures into crlUpdateFailures, so this path does not
	// double-count them.
	newRevoked := x509.RevocationListEntry{
		SerialNumber:   serialInt,
		RevocationTime: time.Now(),
	}

	revokedCerts := crl.RevokedCertificateEntries
	revokedCerts = append(revokedCerts, newRevoked)

	if err := c.signCRLLocked(ctx, crl.Number, revokedCerts); err != nil {
		return err
	}

	// Invalidate the cached OCSP response for this serial so the next query
	// returns the correct Revoked status instead of a stale Good response.
	// Use the same normalised key as the OCSP index (uppercase hex, no padding).
	delete(c.ocspCache, serialHexStr(serialInt))

	return nil
}

// parseInventoryLine parses a single line of the certificate inventory file.
// The format is: SERIAL NOT_BEFORE NOT_AFTER /SUBJECT
// Returns (serial, subject, true) on success; ("", "", false) for blank or malformed lines.
// The returned subject has its leading "/" stripped.
func parseInventoryLine(line string) (serial, subject string, ok bool) {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return "", "", false
	}
	return parts[0], strings.TrimPrefix(parts[3], "/"), true
}

// findSerialForSubject returns the most-recently issued serial for subject.
// It delegates to storage, which uses an indexed lookup on structured backends
// and a verified blob scan otherwise.
func (c *CA) findSerialForSubject(ctx context.Context, subject string) (string, error) {
	return c.Storage.LatestSerialForSubject(ctx, subject)
}

// IsRevokedSerial reports whether the given serial number appears in the
// current CRL.  Unlike IsRevoked, this checks the serial of the certificate
// directly rather than looking up whatever cert happens to be on disk for a
// given CN.  The caller should pass cert.SerialNumber from the certificate
// that is actually being evaluated (e.g. the TLS-presented peer certificate).
//
// Returns (false, err) when the CRL cannot be read or parsed; callers that use
// this result for an authentication decision should treat an error as a denial
// (fail-closed).
func (c *CA) IsRevokedSerial(ctx context.Context, serial *big.Int) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cachedCRL == nil {
		return false, fmt.Errorf("CRL not loaded")
	}
	return serialInCRL(c.cachedCRL, serial), nil
}

// serialInCRL reports whether serial appears among crl's revoked entries. The
// one definition of "is this certificate revoked according to this CRL" for
// every caller that needs only the yes or no — against the cached CRL, one
// freshly read from storage, or one mid-amendment under the CRL lock.
//
// ocsp.go's isRevokedSerial is the deliberate exception: it answers the same
// question but must return the entry's RevocationTime with it, which a bool
// cannot carry. Change the predicate here and change it there too.
//
// crl may not be nil; every caller guards that first, since a missing CRL is
// not "nothing is revoked" and each has its own answer for it.
func serialInCRL(crl *x509.RevocationList, serial *big.Int) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// IsRevoked checks whether the certificate for subject appears in the CRL.
// It looks up the cert currently on disk for subject and checks that cert's
// serial; it is suitable for display purposes (e.g. certificate status
// responses) but NOT for authentication decisions.  For auth, use
// IsRevokedSerial with the serial of the presented certificate instead.
// Returns false (not an error) if the subject has no signed cert.
func (c *CA) IsRevoked(ctx context.Context, subject string) bool {
	certPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	c.mu.RLock()
	crl := c.cachedCRL
	c.mu.RUnlock()

	if crl == nil {
		slog.Warn("IsRevoked: CRL not loaded, assuming not revoked (fail-open for display only)", "subject", subject)
		return false
	}

	return serialInCRL(crl, cert.SerialNumber)
}
