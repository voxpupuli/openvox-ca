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
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// signCRLLocked re-signs the CRL with the given revoked entries, bumping the
// CRL number past prevNumber and stamping fresh ThisUpdate/NextUpdate. It
// writes the result to storage and refreshes the in-memory cache. The cluster
// CRL lock (lockNameCRL) and c.mu must both be held by the caller.
//
// This is the single point through which CRL re-signs are signalled to
// consumers via crlNotify/CRLUpdated(): the sole crlNotify send lives here. Any
// CRL write reachable while the server is serving must route through this
// function, or consumer wake-ups will be silently dropped. The direct
// Storage.UpdateCRL writes in init.go and caImport.go deliberately bypass it:
// they run at bootstrap/import before any consumer exists, and the exporter's
// startup reconcile covers that initial state.
func (c *CA) signCRLLocked(ctx context.Context, prevNumber *big.Int, revoked []x509.RevocationListEntry) error {
	nextNum := big.NewInt(1)
	if prevNumber != nil {
		nextNum.Add(prevNumber, big.NewInt(1))
	}

	now := time.Now()
	template := &x509.RevocationList{
		Number:                    nextNum,
		RevokedCertificateEntries: revoked,
		ThisUpdate:                now,
		NextUpdate:                now.Add(c.crlValidity()),
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, c.CACert, c.CAKey)
	if err != nil {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("failed to sign CRL: %w", err)
	}

	newCRLPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err := c.Storage.UpdateCRL(ctx, newCRLPEM); err != nil {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("failed to write CRL: %w", err)
	}

	// Update the in-memory CRL cache so auth checks use the new CRL
	// immediately without reading from storage.
	parsedCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return fmt.Errorf("failed to parse new CRL for cache: %w", err)
	}
	c.cachedCRL = parsedCRL

	// Signal consumers (e.g. the Kubernetes exporter) that the CRL changed.
	// Non-blocking: a full buffer means a notification is already pending, and a
	// nil channel (CA built without New) is never ready — both fall through to
	// default so signing is never blocked. Holding c.mu here is fine; the send
	// does not contend on it.
	select {
	case c.crlNotify <- struct{}{}:
	default:
	}
	return nil
}

// ReissueCRL re-signs the current CRL with a fresh validity window, preserving
// every existing revocation entry. It exists so the CRL can be kept current
// even when no certificates are being revoked: without periodic reissuance the
// CRL's NextUpdate eventually lapses and clients reject it as expired.
//
// It serialises on the cluster-wide CRL lock so it is safe to call from any
// replica (and concurrently with Revoke) against shared storage; the last
// writer under the lock wins and bumps the CRL number monotonically.
func (c *CA) ReissueCRL(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	return c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.reissueCRLLocked(ctx)
	})
}

// reissueCRLLocked reads the stored CRL and re-signs it unchanged but for a
// bumped number and a fresh validity window. The cluster CRL lock and c.mu
// must both be held by the caller.
func (c *CA) reissueCRLLocked(ctx context.Context) error {
	crl, err := c.readStoredCRL(ctx)
	if err != nil {
		return err
	}
	return c.signCRLLocked(ctx, crl.Number, crl.RevokedCertificateEntries)
}

// readStoredCRL loads and parses the CRL currently in storage.
func (c *CA) readStoredCRL(ctx context.Context) (*x509.RevocationList, error) {
	crlPEM, err := c.Storage.GetCRL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load CRL: %w", err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CRL PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}
	return crl, nil
}

// RefreshCRLIfDue re-signs the CRL only when its remaining validity has dropped
// below refreshBefore, and reports whether it re-signed. The check and the
// re-sign happen together under the cluster CRL lock, so when several replicas
// run this concurrently only the first re-signs (pushing NextUpdate far out)
// and the rest observe a fresh CRL and return (false, nil). This makes the
// background refresh job safe to run on any number of replicas sharing storage.
func (c *CA) RefreshCRLIfDue(ctx context.Context, refreshBefore time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	var reissued bool
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()

		crl, err := c.readStoredCRL(ctx)
		if err != nil {
			return err
		}
		if time.Until(crl.NextUpdate) > refreshBefore {
			return nil
		}
		if err := c.signCRLLocked(ctx, crl.Number, crl.RevokedCertificateEntries); err != nil {
			return err
		}
		reissued = true
		return nil
	})
	return reissued, err
}

// DefaultCRLRefreshBefore returns the default refresh window: the CRL is
// re-signed once less than a third of its validity remains (i.e. at ~2/3 of
// its lifetime), leaving ample margin to ride out replica outages before the
// CRL would lapse.
func (c *CA) DefaultCRLRefreshBefore() time.Duration {
	return c.crlValidity() / 3
}
