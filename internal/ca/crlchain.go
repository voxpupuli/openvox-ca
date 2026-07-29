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
)

// crlSignedBy reports whether crl was issued by cert — that is, whether cert's
// key signed it.
//
// The test is the signature itself, not a comparison of key identifiers and not
// a comparison of issuer distinguished names. Both alternatives are wrong here,
// for different reasons:
//
//   - Issuer DN is forgeable in exactly the deployment this code exists for. A
//     shared root can issue two sub-CAs with the same DN, and rewriting the
//     wrong block would destroy an upstream CRL while appearing to work.
//   - Authority Key Identifier is an optional extension. `openssl ca -gencrl`
//     omits it unless crl_extensions is configured, which the stock openssl.cnf
//     leaves commented out. Keying on it means a legitimate ancestor CRL — or
//     worse, the operator's own — is unrecognisable, and the code then either
//     discards it or supersedes it with an empty list.
//
// A signature check has neither failure mode: it cannot be forged, it needs no
// optional extension, and it answers the question every caller actually asks.
// The cost does not signify — a handful of verifications per re-sign, against a
// chain two or three blocks long.
func crlSignedBy(cert *x509.Certificate, crl *x509.RevocationList) bool {
	if cert == nil || crl == nil {
		return false
	}
	return crl.CheckSignatureFrom(cert) == nil
}

// ownsCRL reports whether crl was issued by this CA.
func (c *CA) ownsCRL(crl *x509.RevocationList) bool {
	return crlSignedBy(c.CACert, crl)
}

// decodeCRLChain splits a stored CRL blob into its constituent revocation
// lists, preserving order.
//
// Every X509 CRL block must parse. The blob is served verbatim to every agent,
// and Puppet's default certificate_revocation = chain makes an agent parse all
// of it, so carrying an unparseable block forward turns one bad import into a
// fleet-wide verification failure. Blocks of other types are skipped: an
// operator pasting a bundle exported by another tool may legitimately carry
// commentary, and none of it reaches storage, because callers re-encode from
// the parsed list rather than passing the original bytes through.
func decodeCRLChain(blob []byte) ([]*x509.RevocationList, error) {
	var out []*x509.RevocationList
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out, nil
		}
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing CRL %d in chain: %w", len(out)+1, err)
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
// because it mirrors the certificate bundle's nearest-first convention. Every
// block that is not ours is carried across, because an ancestor's CRL cannot be
// regenerated here: dropping one is unrecoverable, while keeping one costs a
// wasted block at worst.
//
// c.mu must be held by the caller.
func (c *CA) crlChainLocked(ctx context.Context, ourCRL *x509.RevocationList) ([]byte, error) {
	chain := []*x509.RevocationList{ourCRL}

	existing, err := c.Storage.GetCRL(ctx)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			// Not "nothing to preserve" — this is a read that failed. Treating
			// it as an empty chain writes a single block over upstream CRLs
			// that are still there, permanently, because this CA cannot
			// re-sign an ancestor's list. Fail the re-sign instead: the caller
			// counts the failure and the next attempt finds the chain intact.
			return nil, fmt.Errorf("reading the stored CRL to preserve its upstream blocks: %w", err)
		}
		// Genuinely absent. Defensive rather than routine: every caller of
		// signCRLLocked has already read the CRL successfully through
		// readStoredCRL, so reaching here means the blob was deleted between
		// the two reads. Bootstrap and import do not come through here at all —
		// both call Storage.UpdateCRL directly.
		return encodeCRLChain(chain), nil
	}

	stored, err := decodeCRLChain(existing)
	if err != nil {
		return nil, fmt.Errorf("decoding the stored CRL chain: %w", err)
	}
	for _, crl := range stored {
		if !c.ownsCRL(crl) {
			chain = append(chain, crl)
		}
	}

	// Every block that is not ours is kept, so the length can only change by
	// collapsing duplicates of our own CRL — worth a line, because it is also
	// the only signal available here. Loss caused by a replica running an older
	// build during a rolling upgrade is invisible from inside this function:
	// that replica writes a single block and the next re-sign simply finds
	// nothing upstream. Every CRL metric derives from block 0, so such a chain
	// going 2 -> 1 moves crl_number upward and looks healthy. Detection is the
	// operator's, via the log below and the chain length they expect.
	if before, after := len(stored), len(chain); after != before {
		slog.Info("Stored CRL chain length changed while re-signing",
			"blocks_read", before, "blocks_written", after)
	}
	return encodeCRLChain(chain), nil
}

// orderCRLChain arranges an incoming chain so the CRL issued by cert leads,
// returning the reordered list and whether such a CRL was found.
//
// Import accepts a chain in whatever order an operator assembled it, but every
// reader takes block 0 as this CA's own. Reordering at import is cheaper than
// making each reader search, and it means a mis-ordered bundle is corrected
// once rather than misinterpreted repeatedly.
// When more than one block is ours — which a bundle assembled from a backup
// directory easily produces — the one with the highest CRL number wins and the
// rest are dropped rather than kept as though they were ancestors. Taking the
// first encountered made the outcome depend on the operator's concatenation
// order: a stale copy leading would become block 0, loadCRLCache would cache
// it, and the next re-sign would advance from its number and discard the newer
// block. Chain length and CRL number both look healthy while revocations
// recorded after the stale copy silently stop being seen.
func orderCRLChain(crls []*x509.RevocationList, cert *x509.Certificate) ([]*x509.RevocationList, bool) {
	var ours *x509.RevocationList
	superseded := 0
	others := make([]*x509.RevocationList, 0, len(crls))
	for _, crl := range crls {
		if crlSignedBy(cert, crl) {
			if ours == nil {
				ours = crl
				continue
			}
			superseded++
			if newerCRL(crl, ours) {
				ours = crl
			}
			continue
		}
		others = append(others, crl)
	}
	if ours == nil {
		return crls, false
	}
	if superseded > 0 {
		slog.Warn("Discarding superseded copies of this CA's own CRL from the imported chain",
			"discarded", superseded, "kept_crl_number", ours.Number)
	}
	return append([]*x509.RevocationList{ours}, others...), true
}

// newerCRL reports whether a supersedes b, by CRL number where both carry one
// and by ThisUpdate otherwise. RFC 5280 requires cRLNumber on a conforming CRL,
// but a hand-rolled one may omit it and the comparison still has to terminate.
func newerCRL(a, b *x509.RevocationList) bool {
	if a.Number != nil && b.Number != nil {
		return a.Number.Cmp(b.Number) > 0
	}
	return a.ThisUpdate.After(b.ThisUpdate)
}
