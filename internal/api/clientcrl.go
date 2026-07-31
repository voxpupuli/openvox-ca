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

package api

import (
	"crypto/x509"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// Revocation policies, re-exported so the api package does not force every
// caller to import internal/config for a string constant.
const (
	RevocationRequire = config.RevocationRequire
	RevocationCheck   = config.RevocationCheck
	RevocationSkip    = config.RevocationSkip
)

// ClientCRLSet is the revocation material for one foreign trust domain,
// swapped atomically when the domain's crl_file is reloaded.
//
// Keyed by the certificate that actually signed each CRL.
//
// SECURITY: never by the CRL's own Authority Key Identifier. The AKI sits
// inside the signed TBS, so the CA that signs a CRL chooses what it claims --
// and a client_ca entry may name a CA the operator does not control, which is
// the whole reason the entry exists. Keying on the claim let any anchor in an
// entry supply the CRL consulted for any other: a co-anchor mints an empty CRL
// asserting a sibling's key identifier, that CRL verifies (the co-anchor really
// did sign it), it files under the sibling, and it then satisfies `require` for
// the sibling while saying nothing about the sibling's revocations. A client
// that sibling revoked is admitted -- as an administrator, if its CN is in the
// entry's admin_cns.
//
// crypto/x509's RevocationList.CheckSignatureFrom validates IsCA,
// KeyUsageCRLSign and the signature, and nothing about names or key
// identifiers, so "some anchor signed this" is the only property a verification
// pass establishes. Which anchor is the part that matters, and it is recorded
// here rather than re-derived, so the trust decision is made once at load.
//
// Not by distinguished name either: under a shared root two sibling CAs can
// hold the same DN.
type ClientCRLSet struct {
	// bySigner maps an anchor's DER to the CRLs its key signed.
	bySigner map[string][]*x509.RevocationList
}

// NewClientCRLSet builds a set from crls, keeping only those an anchor signed
// and filing each under the anchor that signed it.
//
// Taking anchors rather than trusting the caller to have verified already: the
// set is the thing consulted per request, so the binding between a CRL and the
// issuer it speaks for belongs here, not in a loader that could be bypassed.
func NewClientCRLSet(crls []*x509.RevocationList, anchors []*x509.Certificate) *ClientCRLSet {
	set := &ClientCRLSet{bySigner: map[string][]*x509.RevocationList{}}
	for _, crl := range crls {
		signer := SignerOfCRL(crl, anchors)
		if signer == nil {
			continue
		}
		key := string(signer.Raw)
		set.bySigner[key] = append(set.bySigner[key], crl)
	}
	return set
}

// forIssuer returns every CRL issued by cert, and whether any of them is
// currently valid.
//
// The two answers are separate because the policies want different things. For
// `require`, an expired CRL counts as absent: without that the policy silently
// degrades to `skip` over time, an expired CRL going on satisfying the "has a
// CRL" test while saying nothing about revocations since.
//
// For `check` — "verify against whatever CRLs are loaded" — an expired CRL is
// still loaded and still names serials that were revoked. Discarding it would
// turn a stale CRL into no revocation checking at all, which is the outcome
// `check` exists to avoid; the operator asked to tolerate an issuer without
// CRLs, not to stop reading the ones they supplied.
func (s *ClientCRLSet) forIssuer(cert *x509.Certificate, now time.Time) (crls []*x509.RevocationList, anyValid bool) {
	if s == nil {
		return nil, false
	}
	for _, crl := range s.bySigner[string(cert.Raw)] {
		crls = append(crls, crl)
		if currentAt(crl, now) {
			anyValid = true
		}
	}
	return crls, anyValid
}

// currentAt reports whether crl is currently valid.
//
// A CRL with no nextUpdate is *not* current. RFC 5280 makes the field optional
// and x509.ParseRevocationList leaves it zero when absent, so reading absent as
// "never expires" handed `require` a snapshot that satisfies it forever: the
// issuer's later revocations stay invisible, the policy decays to `skip` with
// no moment at which it decayed, and puppetca_client_crl_usable reports 1
// indefinitely so the alert cannot fire. That is exactly the decay the expiry
// rule exists to prevent, arriving through the one CRL shape it did not cover.
func currentAt(crl *x509.RevocationList, now time.Time) bool {
	return !crl.NextUpdate.IsZero() && crl.NextUpdate.After(now)
}

// Usable reports whether *every* anchor has a currently valid CRL. Drives
// puppetca_client_crl_usable, because under `require` the recoverable
// conditions — a CRL expired, or discarded as unverifiable — reject clients of
// the affected issuer, and the first symptom is otherwise a 403 three layers
// from where an operator would look.
//
// Every, not any, because that is what enforcement asks: checkChainRevocation
// refuses as soon as one issuer in the chain has no valid CRL. Reporting "any"
// meant a two-anchor entry whose second anchor's CRL had expired published 1
// while every client of that anchor was already being refused, so the alert
// this metric exists for could not see a partial outage at all.
//
// Anchors rather than every issuer in every possible chain: an intermediate
// below an anchor needs its own CRL too, but that CRL cannot verify against the
// anchor and so is never loaded — which is the shared-root footgun the
// documentation steers operators away from, not a state this gauge can report
// on. For the topology the docs recommend, one anchor per issuing CA, the two
// sets coincide.
func (s *ClientCRLSet) Usable(now time.Time, anchors []*x509.Certificate) bool {
	if s == nil {
		return false
	}
	if len(anchors) == 0 {
		return false
	}
	for _, anchor := range anchors {
		if _, anyValid := s.forIssuer(anchor, now); !anyValid {
			return false
		}
	}
	return true
}

// clientCRLs holds the atomically-swappable CRL set for a domain.
type clientCRLs struct {
	current atomic.Pointer[ClientCRLSet]
}

// Set installs a reloaded CRL set.
func (c *clientCRLs) Set(s *ClientCRLSet) { c.current.Store(s) }

// Get returns the current set, which may be nil before the first load.
func (c *clientCRLs) Get() *ClientCRLSet { return c.current.Load() }

// checkChainRevocation walks a verified chain and reports the first revoked
// certificate, or an error when the policy demands a CRL that is not there.
//
// **The whole chain, not just the leaf.** A sibling CA revoked by the shared
// root must not go on authenticating its leaves — the same argument that makes
// `certificate_revocation = leaf` a downgrade for agents applies to this CA
// checking its clients.
//
// **The anchor is never checked**, because it has no issuer inside the chain. A
// trust anchor is trusted by configuration, not by anything it presents, and
// the parent's CRL is not something this CA is positioned to evaluate for an
// anchor it was told to trust. The consequence is worth stating plainly:
// revoking a trusted domain is an operator action — remove or replace the
// client_ca entry — not a CRL event. An operator who has diligently wired up
// crl_file will reasonably assume it covers the CA named in the same block. It
// does not: crl_file covers what that CA *issued*, never that CA itself.
//
// A chain of length one — the presented certificate *is* a configured anchor,
// which a client_ca entry makes reachable — yields no issuer pairs at all.
// Under `require` that is a rejection rather than a silent pass, because
// nothing can attest to its revocation status.
func checkChainRevocation(chain []*x509.Certificate, set *ClientCRLSet, policy string, now time.Time) error {
	// An unrecognised value is treated as `require`, not as `check`. Validation
	// rejects a bad policy string, but it lives two packages away and runs on
	// one construction path, so a value that never passed it must not arrive
	// here as the most permissive arm. Only the two names that mean "check less"
	// get to mean it.
	if policy != RevocationSkip && policy != RevocationCheck {
		policy = RevocationRequire
	}
	if policy == RevocationSkip {
		return nil
	}
	if len(chain) < 2 {
		if policy == RevocationRequire {
			return fmt.Errorf("the presented certificate is itself a trust anchor, " +
				"so nothing can attest to its revocation status")
		}
		return nil
	}

	for i := 0; i < len(chain)-1; i++ {
		subject, issuer := chain[i], chain[i+1]
		crls, anyValid := set.forIssuer(issuer, now)
		if policy == RevocationRequire && !anyValid {
			return fmt.Errorf("no currently valid CRL for issuer %q", issuer.Subject.CommonName)
		}
		if len(crls) == 0 {
			continue
		}
		for _, crl := range crls {
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(subject.SerialNumber) == 0 {
					return fmt.Errorf("certificate %q is revoked by %q",
						subject.Subject.CommonName, issuer.Subject.CommonName)
				}
			}
		}
	}
	return nil
}

// SignerOfCRL returns the anchor whose key signed crl, or nil.
//
// The identity, not merely the fact: see ClientCRLSet for why a CRL must be
// bound to the certificate that signed it rather than to what it claims.
func SignerOfCRL(crl *x509.RevocationList, anchors []*x509.Certificate) *x509.Certificate {
	for _, anchor := range anchors {
		if crl.CheckSignatureFrom(anchor) == nil {
			return anchor
		}
	}
	return nil
}

// VerifyCRLAgainst reports whether crl was signed by one of anchors.
//
// SECURITY: every CRL is verified at load, against its own entry's anchors and
// never against another entry's or against client-supplied intermediates —
// those would confuse a load-time trust decision with a per-request one.
// Without this, a writable crl_file is a way to *clear* revocations, not merely
// to add them: an attacker who can write the file could replace a CRL listing
// their revoked certificate with an empty one.
func VerifyCRLAgainst(crl *x509.RevocationList, anchors []*x509.Certificate) bool {
	return SignerOfCRL(crl, anchors) != nil
}
