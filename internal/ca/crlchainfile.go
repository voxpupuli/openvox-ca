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
	"io/fs"
	"log/slog"
	"os"
	"time"
)

// upstreamCRLs loads and verifies the CRLs in CRLChainFile.
//
// Whatever the file contains wins for non-self issuers, so the configuration is
// declarative: an operator refreshes the file by whatever mechanism they
// already have — a mounted Secret, a sidecar, a CronJob — and openvox-ca picks
// it up. Returning nil when no file is configured makes the whole feature a
// no-op for a self-signed root.
//
// SECURITY: every CRL is signature-verified against a certificate in the stored
// CA bundle before it is accepted, and discarded with a warning otherwise.
// openvox-ca serves this content verbatim to every agent, so an unverified file
// would be a way to inject arbitrary bytes into every agent's CRL store. The
// check is always satisfiable because import-ca-cert requires a complete chain:
// the stored bundle necessarily contains the root, so the root's CRL — the one
// an agent most needs for chain checking — always has a verifier available.
func (c *CA) upstreamCRLs(ctx context.Context) ([]*x509.RevocationList, error) {
	if c.CRLChainFile == "" {
		return nil, nil
	}

	// The path is the operator's own crl_chain_file setting. The content is
	// verified below regardless of where it came from.
	data, err := os.ReadFile(c.CRLChainFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A configured-but-absent file is not fatal: a Secret may not be
			// mounted yet, and refusing to serve would turn a slow rollout into
			// an outage. The chain simply carries nothing extra this pass.
			slog.Warn("crl_chain_file does not exist yet; no upstream CRLs merged",
				"path", c.CRLChainFile)
			return nil, nil
		}
		return nil, fmt.Errorf("reading crl_chain_file %s: %w", c.CRLChainFile, err)
	}

	crls, err := decodeCRLChain(data)
	if err != nil {
		return nil, fmt.Errorf("crl_chain_file %s: %w", c.CRLChainFile, err)
	}

	issuers, err := c.bundleCertificates(ctx)
	if err != nil {
		return nil, err
	}

	verified := make([]*x509.RevocationList, 0, len(crls))
	for _, crl := range crls {
		if c.ownsCRL(crl) {
			// Ours is assembled from the inventory on every re-sign; taking it
			// from a file would let a stale copy supersede live revocations.
			slog.Warn("Ignoring a CRL in crl_chain_file that this CA issued; "+
				"its own CRL is always rebuilt from the inventory", "path", c.CRLChainFile)
			continue
		}
		issuer := issuerFor(issuers, crl)
		if issuer == nil {
			slog.Warn("Discarding a CRL in crl_chain_file that no certificate in the CA bundle signed",
				"path", c.CRLChainFile, "issuer", crl.Issuer.String())
			continue
		}
		verified = append(verified, crl)
	}
	return verified, nil
}

// issuerFor returns the certificate whose key signed crl, or nil.
func issuerFor(candidates []*x509.Certificate, crl *x509.RevocationList) *x509.Certificate {
	for _, cert := range candidates {
		if crlSignedBy(cert, crl) {
			return cert
		}
	}
	return nil
}

// bundleCertificates parses the stored CA certificate bundle.
func (c *CA) bundleCertificates(ctx context.Context) ([]*x509.Certificate, error) {
	bundlePEM, err := c.Storage.GetCACert(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the CA bundle to verify crl_chain_file: %w", err)
	}
	var certs []*x509.Certificate
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d in the stored CA bundle: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("the stored CA bundle contains no certificates")
	}
	return certs, nil
}

// RefreshCRLChainFile re-reads crl_chain_file and, when its contents differ
// from what is stored, rewrites the CRL so the change reaches agents.
//
// Reading the file into memory would change nothing an agent can see:
// handleGetCRL serves Storage.GetCRL verbatim. So a detected change goes
// through the ordinary re-sign path — CRL lock, then c.mu, then signCRLLocked,
// the order ReissueCRL already uses — which reassembles the chain, persists it,
// refreshes the cache, fires the notification and wakes the exporter, all for
// free.
//
// One consequence, accepted deliberately: this bumps our own CRL number even
// though our revocation set is unchanged. The number need only increase, so it
// is harmless, and it is the price of having one write path rather than a
// second subtler one.
//
// Returns whether a rewrite happened.
func (c *CA) RefreshCRLChainFile(ctx context.Context) (bool, error) {
	if c.CRLChainFile == "" {
		return false, nil
	}

	wanted, err := c.upstreamCRLs(ctx)
	if err != nil {
		return false, err
	}

	current, err := c.Storage.GetCRL(ctx)
	if err != nil {
		return false, fmt.Errorf("reading the stored CRL: %w", err)
	}
	stored, err := decodeCRLChain(current)
	if err != nil {
		return false, fmt.Errorf("decoding the stored CRL chain: %w", err)
	}

	var storedUpstream []*x509.RevocationList
	for _, crl := range stored {
		if !c.ownsCRL(crl) {
			storedUpstream = append(storedUpstream, crl)
		}
	}
	if sameCRLSet(storedUpstream, wanted) {
		return false, nil
	}

	slog.Info("Upstream CRLs changed; rewriting the published chain",
		"path", c.CRLChainFile, "stored", len(storedUpstream), "configured", len(wanted))

	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	err = c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.reissueCRLLocked(ctx)
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

// sameCRLSet reports whether two CRL lists are byte-identical in order.
func sameCRLSet(a, b []*x509.RevocationList) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Raw, b[i].Raw) {
			return false
		}
	}
	return true
}

// UpstreamCRLStatus describes one upstream CRL for metrics reporting.
type UpstreamCRLStatus struct {
	// Issuer is the CRL issuer's distinguished name, used as a metric label.
	Issuer string
	// NextUpdate is when the CRL expires.
	NextUpdate time.Time
}

// UpstreamCRLStatuses reports the non-self CRLs currently published, for the
// per-issuer freshness metric.
//
// Deliberately separate from the existing unlabelled
// puppetca_crl_next_update_timestamp_seconds, which keeps meaning exactly what
// it means today: *this CA's own* CRL. Adding an issuer label to that series
// would multiply it and make the two shipped expiry alerts fire for upstream
// CRLs this CA cannot reissue — a real page with a wrong runbook, since the
// remedy is at the parent.
func (c *CA) UpstreamCRLStatuses(ctx context.Context) ([]UpstreamCRLStatus, error) {
	blob, err := c.Storage.GetCRL(ctx)
	if err != nil {
		return nil, err
	}
	crls, err := decodeCRLChain(blob)
	if err != nil {
		return nil, err
	}
	var out []UpstreamCRLStatus
	for _, crl := range crls {
		if c.ownsCRL(crl) {
			continue
		}
		out = append(out, UpstreamCRLStatus{
			Issuer:     crl.Issuer.String(),
			NextUpdate: crl.NextUpdate,
		})
	}
	return out, nil
}
