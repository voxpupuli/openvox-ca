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
	"log/slog"
)

// crlOwnership classifies a stored CRL relative to this CA.
type crlOwnership int

const (
	// crlOwnershipUnknown means the comparison cannot be made — this CA's
	// certificate carries no Subject Key Identifier, or the CRL carries no
	// Authority Key Identifier. Treated conservatively everywhere.
	crlOwnershipUnknown crlOwnership = iota
	// crlOwnershipOurs means the CRL was issued by this CA.
	crlOwnershipOurs
	// crlOwnershipForeign means the CRL was issued by some other CA — in a
	// sub-CA deployment, an ancestor.
	crlOwnershipForeign
)

// classifyCRL decides whether crl was issued by this CA.
//
// The comparison is Authority Key Identifier against Subject Key Identifier,
// not issuer distinguished name. A DN comparison would be wrong in exactly the
// deployment this code exists for: a shared root can issue two sub-CAs with the
// same DN, and rewriting the wrong block would silently destroy an upstream
// CRL while appearing to work. Puppet Server keys its own CRL handling on the
// same extension and rejects CRLs that lack it.
//
// Both operands must be present. When either is missing the answer is Unknown
// rather than a guess, and every caller treats Unknown as "do what this code
// did before chains existed".
func (c *CA) classifyCRL(crl *x509.RevocationList) crlOwnership {
	if c.CACert == nil || len(c.CACert.SubjectKeyId) == 0 || len(crl.AuthorityKeyId) == 0 {
		return crlOwnershipUnknown
	}
	if bytes.Equal(crl.AuthorityKeyId, c.CACert.SubjectKeyId) {
		return crlOwnershipOurs
	}
	return crlOwnershipForeign
}

// decodeCRLChain splits a stored CRL blob into its constituent revocation
// lists, preserving order. Blocks that are not X509 CRLs, or that fail to
// parse, are skipped: the blob is served verbatim to every agent, so carrying
// something unparseable forward would push the failure out to the fleet.
func decodeCRLChain(blob []byte) []*x509.RevocationList {
	var out []*x509.RevocationList
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			slog.Warn("Skipping unparseable CRL block in stored CRL", "error", err)
			continue
		}
		out = append(out, crl)
	}
}

// encodeCRLChain renders revocation lists back to a PEM blob in order.
func encodeCRLChain(crls []*x509.RevocationList) []byte {
	var buf bytes.Buffer
	for _, crl := range crls {
		_ = pem.Encode(&buf, &pem.Block{Type: "X509 CRL", Bytes: crl.Raw})
	}
	return buf.Bytes()
}

// crlChainLocked assembles the blob to store: this CA's freshly signed CRL
// first, followed by every upstream CRL already present, in their original
// order.
//
// Our CRL leads because readStoredCRL and loadCRLCache both take block 0, and
// because it mirrors the certificate bundle's nearest-first convention. Only
// CRLs classified Foreign are carried across — an Unknown block is dropped,
// which on a CA whose certificate has no Subject Key Identifier means every
// block is dropped and the result is exactly the single-CRL behaviour this
// function replaces.
//
// c.mu must be held by the caller.
func (c *CA) crlChainLocked(ctx context.Context, ourCRL *x509.RevocationList) []byte {
	chain := []*x509.RevocationList{ourCRL}

	existing, err := c.Storage.GetCRL(ctx)
	if err != nil {
		// No stored CRL yet, or it cannot be read. Either way there is nothing
		// upstream to preserve; the caller's own CRL stands alone.
		return encodeCRLChain(chain)
	}

	for _, crl := range decodeCRLChain(existing) {
		if c.classifyCRL(crl) == crlOwnershipForeign {
			chain = append(chain, crl)
		}
	}
	return encodeCRLChain(chain)
}

// orderCRLChain arranges an incoming CRL bundle so the CRL issued by cert leads,
// returning the reordered blob and whether such a CRL was found.
//
// Import accepts a chain in whatever order an operator assembled it, but every
// reader takes block 0 as this CA's own. Reordering at import is cheaper than
// making each reader search, and it means a mis-ordered bundle is corrected once
// rather than misinterpreted repeatedly.
func orderCRLChain(blob []byte, cert *x509.Certificate) ([]byte, bool) {
	crls := decodeCRLChain(blob)
	if len(crls) == 0 {
		return blob, false
	}

	var ours *x509.RevocationList
	var others []*x509.RevocationList
	for _, crl := range crls {
		if ours == nil && len(cert.SubjectKeyId) > 0 && len(crl.AuthorityKeyId) > 0 &&
			bytes.Equal(crl.AuthorityKeyId, cert.SubjectKeyId) {
			ours = crl
			continue
		}
		others = append(others, crl)
	}
	if ours == nil {
		return blob, false
	}
	return encodeCRLChain(append([]*x509.RevocationList{ours}, others...)), true
}
