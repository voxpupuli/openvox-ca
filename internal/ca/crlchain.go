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
	"fmt"
	"log/slog"
	"time"
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
//
// The cost is a few verifications per CRL per re-sign -- signedByAny filters,
// then dedupeCRLs and monotonicUpstream each resolve the signer again, and
// monotonicUpstream also resolves one per published block. Against a chain two
// or three blocks long that is immaterial. It would not be at the 4 MiB bound
// maxCRLChainFileBytes allows, since this runs with both the CRL lock and c.mu
// held; if that bound is ever raised, resolve the signer once in upstreamCRLs
// and thread it through instead.
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
	out, _, err := decodeCRLChainRest(blob)
	return out, err
}

// decodeCRLChainStrict is decodeCRLChain for content whose *absence of CRLs is
// meaningful* -- currently crl_chain_file, which is authoritative, so "no CRLs"
// deletes every ancestor.
//
// pem.Decode cannot tell a truncated block from trailing rubbish: it returns nil
// for a block with no END line, for DER, for a certificate bundle and for an
// HTML error page. The lenient decoder reports all of those as an empty chain
// with no error, so a `cat >` caught mid-write -- the refresh mechanism the
// documentation recommends -- published a chain with the ancestors silently
// removed, permanently, because this CA cannot re-sign another CA's list.
//
// So: an empty file is the empty declaration. Anything else that decodes to no
// CRL, or that leaves bytes the decoder could not consume, is a failure. The
// caller keeps what is already published rather than acting on it.
func decodeCRLChainStrict(blob []byte) ([]*x509.RevocationList, error) {
	out, rest, err := decodeCRLChainRest(blob)
	if err != nil {
		return nil, err
	}
	// The file must end on a block boundary. Anything else non-whitespace after
	// the last block is a write that was cut short.
	//
	// Commentary is still free where bundles actually carry it: pem.Decode
	// skips everything before a BEGIN line, so `openssl crl -text` output --
	// which prints its human-readable dump *first* and ends with
	// `-----END X509 CRL-----` -- passes unchanged, as does commentary between
	// blocks. Only a trailing footer is refused.
	//
	// An earlier revision here judged only whether the tail had started a block
	// (`bytes.Contains(rest, "-----BEGIN")`). That was too weak, and weak in the
	// silent direction: a write cut inside the *text* preamble of the next block
	// leaves a tail with no BEGIN in it, so the file decoded as a valid, shorter
	// declaration -- and because the file is authoritative, a missing issuer
	// reads as a deliberate removal. The chain shrank with no error and no
	// counter. Refusing the tail costs a loud failure on a hand-written footer;
	// tolerating it costs ancestors, permanently, in silence.
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("the file does not end on a PEM block boundary: " +
			"it is truncated, which usually means it was read while being rewritten")
	}
	if len(out) == 0 && len(bytes.TrimSpace(blob)) > 0 {
		return nil, fmt.Errorf("no X509 CRL blocks, but the file is not empty: " +
			"an empty file means publish no upstream CRLs; this does not")
	}
	return out, nil
}

// decodeCRLChainRest also reports what it could not decode, so a caller that
// needs to tell "nothing there" from "could not read it" can.
func decodeCRLChainRest(blob []byte) ([]*x509.RevocationList, []byte, error) {
	var out []*x509.RevocationList
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out, rest, nil
		}
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing CRL %d in chain: %w", len(out)+1, err)
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
// first, followed by the upstream CRLs.
//
// Our CRL leads because readStoredCRL and loadCRLCache both take block 0, and
// because it mirrors the certificate bundle's nearest-first convention.
//
// Where the upstream blocks come from depends on configuration. With
// crl_chain_file set, that file is authoritative: it is the operator's
// declarative statement of which ancestor CRLs to publish, refreshed by
// whatever mechanism they already have, so a CRL dropped from the file is meant
// to disappear. Without it, every stored block that is not ours is carried
// across — an ancestor's CRL cannot be regenerated here, so dropping one is
// unrecoverable while keeping one costs a wasted block at worst.
//
// storedBlob is the blob readStoredCRL already read, not a fresh fetch. It used
// to fetch its own copy, which cost a second backend round trip inside the
// cluster CRL lock and, worse, could disagree with the first: the number and
// entries being carried forward came from one read and the ancestors from
// another. A nil blob means there was no previous read at all, which no caller
// does today — bootstrap and import write through Storage.UpdateCRL directly.
//
// c.mu must be held by the caller.
func (c *CA) crlChainLocked(ctx context.Context, ourCRL *x509.RevocationList, storedBlob []byte) ([]byte, error) {
	chain := []*x509.RevocationList{ourCRL}

	// With crl_chain_file set, the file is authoritative: it is the operator's
	// declarative statement of which ancestor CRLs to publish, so a CRL dropped
	// from it is meant to disappear and the stored blob's own upstream blocks
	// are not carried across.
	if c.CRLChainFile != "" {
		upstream, stated, err := c.upstreamCRLs(ctx)
		if err != nil {
			return nil, err
		}
		// Only a file this process could actually read is authoritative. An
		// absent one makes no statement, so fall through and preserve whatever
		// is already published — see upstreamCRLs for why the distinction
		// matters on this path in particular.
		if stated {
			return encodeCRLChain(append(chain, upstream...)), nil
		}
	}

	stored, err := decodeCRLChain(storedBlob)
	if err != nil {
		return nil, fmt.Errorf("decoding the stored CRL chain: %w", err)
	}
	for _, crl := range stored {
		if !c.ownsCRL(crl) {
			chain = append(chain, crl)
		}
	}

	// Every block that is not ours is kept, so on a healthy CA the length never
	// changes here: it can only move by collapsing duplicates of our own CRL,
	// which import already drops. That makes any change worth a Warn rather than
	// an Info — it means the stored blob held something orderCRLChain would have
	// rejected, and the operator has no other signal for it. Every CRL metric
	// derives from block 0, so a chain going 2 -> 1 moves crl_number upward and
	// looks healthy on every dashboard.
	//
	// Loss caused by a replica running an older build during a rolling upgrade is
	// invisible even here: that replica writes a single block, and the next
	// re-sign on an upgraded replica reads one block and writes one block, with
	// nothing to compare against. docs/metrics.md names that blind spot and the
	// order to upgrade in; this line covers only what is observable in-process.
	if before, after := len(stored), len(chain); after != before {
		slog.Warn("Stored CRL chain length changed while re-signing",
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
// The count of superseded copies is returned rather than logged here, so the one
// import that runs this twice -- once to validate, once under the lock -- reports
// the problem once. warnAboutAncestors was hoisted to the caller for the same
// reason.
func orderCRLChain(crls []*x509.RevocationList, cert *x509.Certificate) ([]*x509.RevocationList, int, bool) {
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
		return crls, 0, false
	}
	return append([]*x509.RevocationList{ours}, others...), superseded, true
}

// warnAboutAncestors reports ancestor blocks that will make agents reject the
// published chain.
//
// The reason every block must parse — the blob is served verbatim and Puppet's
// default certificate_revocation = chain makes an agent parse all of it —
// applies just as well to a block whose nextUpdate has already lapsed, or to
// two copies of one ancestor's CRL. Neither is refused, because an operator
// importing a chain they know is stale is a legitimate intermediate step.
// Duplicate copies are only detectable here -- import writes through
// Storage.UpdateCRL and never reaches dedupeCRLs. Expiry is no longer: the
// per-issuer gauge and PuppetCAUpstreamCRLExpired cover it from the stored
// blob, so this warning is an earlier signal rather than the only one.
//
// Called once on the final chain about to be written, rather than from
// orderCRLChain. It used to live there, after the early return taken when the
// supplied bundle carries no CRL of ours — which is exactly the ancestors-only
// shape the migration guide recommends, so the only detector of an undetectable
// condition was skipped on the one path that needs it.
func warnAboutAncestors(others []*x509.RevocationList) {
	now := time.Now()
	seen := make(map[string]int, len(others))
	for _, crl := range others {
		if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
			slog.Warn("Ancestor CRL has already expired; agents doing full-chain "+
				"revocation checking will reject the published chain",
				"issuer", crl.Issuer.String(), "next_update", crl.NextUpdate.UTC().Format(time.RFC3339))
		}
		seen[string(crl.RawIssuer)]++
	}
	for _, crl := range others {
		if n := seen[string(crl.RawIssuer)]; n > 1 {
			slog.Warn("The chain carries more than one CRL for the same ancestor; "+
				"all of them are published",
				"issuer", crl.Issuer.String(), "copies", n)
			seen[string(crl.RawIssuer)] = 0
		}
	}
}

// newerCRL reports whether a supersedes b: by CRL number where both carry one, by
// the presence of a number where only one does, and by ThisUpdate otherwise.
//
// RFC 5280 requires cRLNumber on a conforming CRL, but `openssl ca -gencrl` under
// the stock openssl.cnf emits a V1 list, which cannot carry one at all -- so a
// numberless CRL of ours is a routine import, not a curiosity. A numbered block
// therefore wins outright over a numberless one, whatever their timestamps say:
// whichever block ends up at position 0 is what the next re-sign advances from,
// and advancing from a numberless block restarts the sequence at 1. That
// regresses a number docs/metrics.md publishes as monotonic, and an RFC 5280
// client comparing cRLNumber may keep serving the copy it already has -- so a
// revocation recorded afterwards is never seen.
//
// The comparison still has to terminate on any input, which the ThisUpdate
// fallback gives it.
func newerCRL(a, b *x509.RevocationList) bool {
	switch {
	case a.Number != nil && b.Number != nil:
		return a.Number.Cmp(b.Number) > 0
	case a.Number != nil:
		return true
	case b.Number != nil:
		return false
	}
	return a.ThisUpdate.After(b.ThisUpdate)
}

// selectOwnCRL picks the block a reader should treat as this CA's own CRL: the
// newest one we signed, wherever it sits in the blob.
//
// One function because three readers need the same answer and reached it three
// different ways. Import selected the newest; the cache loader and the re-sign
// read took block 0 unless it was *foreign*. A stale block 0 of our own passes an
// ownership check, so on a blob holding two of ours -- which the released build's
// import stored verbatim -- the cache answered revocation from a list missing
// every serial revoked since, and the next re-sign advanced from the stale number
// and destroyed the newer block.
//
// A blob that will not decode past block 0 returns the decode error, and each
// caller keeps its existing policy for that case rather than having one imposed
// here.
func (c *CA) selectOwnCRL(blob []byte) (*x509.RevocationList, int, error) {
	chain, err := decodeCRLChain(blob)
	if err != nil {
		return nil, -1, err
	}
	ours := ownCRLIn(chain, c.CACert)
	if ours == nil {
		return nil, -1, nil
	}
	return ours, indexOfCRL(chain, ours), nil
}
