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
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
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
func (c *CA) Revoke(ctx context.Context, subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	return c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.revokeLocked(ctx, subject)
	})
}

// revokeLocked performs the actual CRL read-modify-write. The cluster CRL
// lock and c.mu must both be held by the caller.
func (c *CA) revokeLocked(ctx context.Context, subject string) error {
	slog.Debug("Revoking certificate", "subject", subject)

	// 1. Find Serial
	serialStr, err := c.findSerialForSubject(ctx, subject)
	if err != nil {
		return fmt.Errorf("could not find certificate for subject %s: %w", subject, err)
	}

	serialInt := new(big.Int)
	if _, ok := serialInt.SetString(serialStr, 16); !ok {
		return fmt.Errorf("malformed serial %q for subject %s in inventory", serialStr, subject)
	}

	// 2. Load CRL
	crlPEM, err := c.Storage.GetCRL(ctx)
	if err != nil {
		return fmt.Errorf("failed to load CRL: %w", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CRL PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %w", err)
	}

	// 3. Check for duplicate revocation: a serial that's already in the CRL
	// should not be appended again (prevents unbounded CRL growth on retries).
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serialInt) == 0 {
			slog.Debug("Certificate already revoked", "subject", subject, "serial", serialStr)
			return nil
		}
	}

	// 4. Prepare New CRL
	newRevoked := x509.RevocationListEntry{
		SerialNumber:   serialInt,
		RevocationTime: time.Now(),
	}

	revokedCerts := crl.RevokedCertificateEntries
	revokedCerts = append(revokedCerts, newRevoked)

	// Increment CRL Number
	nextNum := big.NewInt(1)
	if crl.Number != nil {
		nextNum.Add(crl.Number, big.NewInt(1))
	}

	template := &x509.RevocationList{
		Number:                    nextNum,
		RevokedCertificateEntries: revokedCerts,
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(c.crlValidity()),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, c.CACert, c.CAKey)
	if err != nil {
		return fmt.Errorf("failed to sign CRL: %w", err)
	}

	newCRLPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err := c.Storage.UpdateCRL(ctx, newCRLPEM); err != nil {
		return fmt.Errorf("failed to write CRL: %w", err)
	}

	// Update the in-memory CRL cache so auth checks use the new CRL
	// immediately without reading from disk.
	parsedCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return fmt.Errorf("failed to parse new CRL for cache: %w", err)
	}
	c.cachedCRL = parsedCRL

	// Invalidate the cached OCSP response for this serial so the next query
	// returns the correct Revoked status instead of a stale Good response.
	// Use the same normalised key as the OCSP index (uppercase hex, no padding).
	delete(c.ocspCache, serialHexStr(serialInt))

	slog.Debug("Certificate revoked", "subject", subject, "serial", serialStr)
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
// It reads through storage to honour the inventory mutex.
func (c *CA) findSerialForSubject(ctx context.Context, subject string) (string, error) {
	data, err := c.Storage.ReadInventory(ctx)
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	last := ""
	lineNum := 0
	badLines := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		serial, subj, ok := parseInventoryLine(line)
		if !ok {
			badLines++
			continue
		}
		if subj == subject {
			last = serial
		}
	}
	if badLines > 0 {
		slog.Warn("Inventory file contains unparseable lines", "count", badLines)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if last == "" {
		return "", fmt.Errorf("subject %s not found in inventory", subject)
	}
	return last, nil
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
	for _, entry := range c.cachedCRL.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true, nil
		}
	}
	return false, nil
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

	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}
