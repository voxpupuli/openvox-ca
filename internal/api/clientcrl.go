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
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
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
// here rather than re-derived per request. (The loader verifies too, to produce
// its discard warning, so the signature work happens twice at startup -- once
// there and once here. Only this one decides anything.)
//
// Not by distinguished name either: under a shared root two sibling CAs can
// hold the same DN.
type ClientCRLSet struct {
	// bySignerKey maps an anchor's SubjectPublicKeyInfo to the CRLs that key
	// signed.
	//
	// The public key, not the certificate DER. CheckSignatureFrom establishes
	// that a *key* signed the CRL, so keying on the certificate is one level
	// tighter than the property actually verified -- and the gap is a shape
	// operators really ship: a CA that renews its own certificate keeping its
	// key, with both certificates in the bundle during the overlap. Its one CRL
	// would file under whichever certificate came first in the file, and when
	// that one expired every client would be refused while a valid, verifying
	// CRL sat in crl_file. Keying on the key gives up nothing: a co-anchor's CRL
	// still files under the co-anchor's key, so it is still never consulted for
	// a sibling.
	bySignerKey map[string][]*x509.RevocationList

	// anchors is what the set was built against, kept so that questions about
	// coverage are answered by the set itself rather than by a caller supplying
	// a list again and hoping it matches.
	anchors []*x509.Certificate

	// partialBySignerKey holds CRLs that cannot stand in for their issuer's
	// full list -- deltas and IDP-scoped ones. Read for the serials they name,
	// never for coverage or currency, so a partial CRL can deny a client but
	// can never satisfy `require` on its own.
	partialBySignerKey map[string][]*x509.RevocationList

	// discarded holds "issuer (reason)" for each CRL refused at construction,
	// for the caller to report with the entry and path it knows.
	discarded []string
}

// NewClientCRLSet builds a set from crls, keeping only those an anchor signed
// and filing each under the anchor that signed it.
//
// Taking anchors rather than trusting the caller to have verified already: the
// set is the thing consulted per request, so the binding between a CRL and the
// issuer it speaks for belongs here, not in a loader that could be bypassed.
func NewClientCRLSet(crls []*x509.RevocationList, anchors []*x509.Certificate) *ClientCRLSet {
	set := &ClientCRLSet{
		bySignerKey:        map[string][]*x509.RevocationList{},
		partialBySignerKey: map[string][]*x509.RevocationList{},
		anchors:            anchors,
	}
	for _, crl := range crls {
		signer := SignerOfCRL(crl, anchors)
		if signer == nil {
			continue
		}
		if reason, partial := coversPartially(crl); partial {
			// Admitted on the signature alone, a partial-scope CRL would satisfy
			// `require` while listing only some of what its issuer has revoked.
			// A delta CRL names only the changes since a base it does not carry;
			// an issuing-distribution-point CRL may cover only one reason code or
			// only CA certificates. Either is a valid CRL its issuer meant for a
			// client that also fetches the rest, and this CA fetches nothing --
			// it is handed a file. Refusing beats silently covering less than the
			// operator believes.
			// Recorded rather than logged here: the api package does not know
			// which client_ca entry or file this came from, and an operator
			// holding several entries needs both to act. The caller reports it.
			set.discarded = append(set.discarded,
				fmt.Sprintf("%s (%s)", sanitiseForLog(crl.Issuer.String()), reason))
			// Filed apart rather than dropped. It cannot answer "is this
			// issuer covered", but the serials it does name are genuinely
			// revoked, and a bundle holding a base CRL beside its delta -- what
			// concatenating an issuer's CDP and freshestCRL gives you -- would
			// otherwise re-admit every client revoked since the base was
			// signed. The same argument forIssuer makes for keeping expired
			// CRLs readable: discarding one does not make the policy stricter.
			pkey := string(signer.RawSubjectPublicKeyInfo)
			set.partialBySignerKey[pkey] = append(set.partialBySignerKey[pkey], crl)
			continue
		}
		key := string(signer.RawSubjectPublicKeyInfo)
		set.bySignerKey[key] = append(set.bySignerKey[key], crl)
	}
	return set
}

// OID registry for the two extensions that narrow a CRL's scope (RFC 5280
// s5.2.3 and s5.2.5).
var (
	oidDeltaCRLIndicator      = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPnt = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// coversPartially reports whether a CRL declares itself narrower than its
// issuer's full revocation list, and which extension says so.
//
// Presence is the whole test. An issuing distribution point can in principle
// describe a scope equal to the full list, but parsing it to find out means
// implementing a decision this CA has no way to act on: if the IDP names a
// distribution point, the complete picture lives at a URL nobody here fetches.
func coversPartially(crl *x509.RevocationList) (string, bool) {
	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidDeltaCRLIndicator):
			return "delta CRL", true
		case ext.Id.Equal(oidIssuingDistributionPnt):
			return "issuing distribution point", true
		}
	}
	return "", false
}

// forRevocationLookup is forIssuer plus the partial-scope CRLs, for deciding
// whether a serial is revoked.
//
// anyValid still comes from the full CRLs alone: a delta is evidence that a
// serial *is* revoked and never evidence that an issuer is covered, so it must
// not be able to satisfy `require` for an issuer whose full CRL is missing.
func (s *ClientCRLSet) forRevocationLookup(cert *x509.Certificate, now time.Time) (crls []*x509.RevocationList, anyValid bool) {
	crls, anyValid = s.forIssuer(cert, now)
	if s == nil {
		return crls, anyValid
	}
	return append(crls, s.partialBySignerKey[string(cert.RawSubjectPublicKeyInfo)]...), anyValid
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
	for _, crl := range s.bySignerKey[string(cert.RawSubjectPublicKeyInfo)] {
		crls = append(crls, crl)
		if currentAt(crl, now) {
			anyValid = true
		}
	}
	return crls, anyValid
}

// currentAt reports whether crl is currently valid.
//
// A CRL with no nextUpdate is *not* current. The field is OPTIONAL in the
// TBSCertList ASN.1 -- which is why x509.ParseRevocationList leaves it zero --
// but RFC 5280 §5.1.2.5 requires a conforming issuer to include it and does not
// say what a client should do without it, so this is a conforming choice. It is
// also the safe one: reading absent as
// "never expires" handed `require` a snapshot that satisfies it forever: the
// issuer's later revocations stay invisible, the policy decays to `skip` with
// no moment at which it decayed, and puppetca_client_crl_usable reports 1
// indefinitely so the alert cannot fire. That is exactly the decay the expiry
// rule exists to prevent, arriving through the one CRL shape it did not cover.
func currentAt(crl *x509.RevocationList, now time.Time) bool {
	return !crl.NextUpdate.IsZero() && crl.NextUpdate.After(now)
}

// Discarded lists the CRLs this set refused to admit, as "issuer (reason)".
//
// Non-empty means the file held CRLs that cannot stand in for their issuer's
// full list, so the coverage this set reports is not the coverage the operator
// believed they were delivering.
func (s *ClientCRLSet) Discarded() []string {
	if s == nil {
		return nil
	}
	return s.discarded
}

// Usable reports whether this entry holds any current revocation material at
// all. Drives puppetca_client_crl_usable.
//
// Deliberately *any*, not *every*, and the reasoning is worth keeping because
// both readings have been shipped and both were wrong in their own direction.
//
// "Any" under-reports: an entry with two anchors, one covered and one not,
// reads healthy while every client of the second is refused. That is real, and
// it is what CoverageGaps and the refusal counter exist to report instead.
//
// "Every" over-reports, and worse. Enforcement does not ask for a CRL per
// anchor; it asks for one per issuer *in the chain a client actually presents*.
// A bundle holding an issuing CA and the root above it — how a partner usually
// ships their anchors — needs only the issuing CA's CRL, because no client's
// chain terminates at the root. Demanding one for the root too made a perfectly
// healthy entry report 0 permanently, fire the mixin's only critical
// authentication alert forever, and print "every client of this entry will be
// rejected" while nobody was being rejected. An alert that fires on a working
// configuration is an alert that gets silenced, taking the real case with it.
//
// Which anchors matter cannot be known here: it depends on chains that have not
// arrived yet. So this answers the question it can answer honestly — is there
// anything current to check against — and the question it cannot is answered at
// enforcement time, where a refusal is a fact rather than an estimate.
func (s *ClientCRLSet) Usable(now time.Time) bool {
	if s == nil {
		return false
	}
	for _, crls := range s.bySignerKey {
		for _, crl := range crls {
			if currentAt(crl, now) {
				return true
			}
		}
	}
	return false
}

// CoverageGaps names the anchors this set holds no current CRL for.
//
// Advisory, not a verdict: an anchor with no CRL only matters if some client's
// chain terminates there, which is why this reports rather than decides. It is
// what the startup warning uses, so an operator is told which anchor is
// uncovered instead of being told the entry is broken.
//
// Names, for humans. Anything comparing coverage must use Coverage instead --
// a common name is not an identity here, which is the same reason CRLs are not
// keyed by one.
func (s *ClientCRLSet) CoverageGaps(now time.Time) []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, anchor := range s.anchors {
		if _, anyValid := s.forIssuer(anchor, now); !anyValid {
			out = append(out, anchor.Subject.CommonName)
		}
	}
	return out
}

// Coverage reports, per anchor key, whether this set holds any CRL for it and
// whether it holds a currently valid one.
//
// Keyed on SubjectPublicKeyInfo, the identity bySignerKey uses. Comparing
// coverage by common name collapsed two anchors that share one -- a CA that
// renews *and* rekeys keeps its subject, so a bundle holding both certificates
// during the overlap has two independent coverage slots under one name -- and
// the reload guard built on that comparison then let a strictly narrower set
// install, which is the failure it exists to prevent.
//
// Both answers, because the policies want different things. `require` needs a
// currently valid CRL; `check` consults whatever is loaded, expired included,
// so losing an expired CRL that named a serial silently re-admits it. A guard
// that watched only currency could not see that, and VerifyCRLAgainst's comment
// is explicit that clearing revocations is the threat, not only forging them.
func (s *ClientCRLSet) Coverage(now time.Time) (present, current map[string]bool) {
	present, current = map[string]bool{}, map[string]bool{}
	if s == nil {
		return present, current
	}
	for _, anchor := range s.anchors {
		key := string(anchor.RawSubjectPublicKeyInfo)
		crls, anyValid := s.forIssuer(anchor, now)
		if len(crls) > 0 {
			present[key] = true
		}
		if anyValid {
			current[key] = true
		}
	}
	return present, current
}

// freshness reports, per anchor key, the newest CRL this set holds for that
// anchor -- by CRL number where the issuer publishes one, and by ThisUpdate
// otherwise, since cRLNumber is required of a conforming issuer but not
// universally present (`openssl ca -gencrl` omits it under the stock config).
//
// It exists so a reload can refuse to go backwards. A CRL that verifies, has
// not expired, and covers every anchor the current set covers still must not
// replace a newer one: an attacker who can write crl_file, or a mirror serving
// a stale copy, would otherwise re-admit every serial revoked since it was
// signed, and nothing else in the reload path would notice.
func (s *ClientCRLSet) freshness(now time.Time) map[string]crlFreshness {
	out := map[string]crlFreshness{}
	if s == nil {
		return out
	}
	for _, anchor := range s.anchors {
		key := string(anchor.RawSubjectPublicKeyInfo)
		crls, _ := s.forIssuer(anchor, now)
		for _, crl := range crls {
			f := crlFreshness{subject: anchor.Subject.String(), thisUpdate: crl.ThisUpdate}
			if crl.Number != nil {
				f.number = new(big.Int).Set(crl.Number)
			}
			if best, ok := out[key]; !ok || f.newerThan(best) {
				out[key] = f
			}
		}
	}
	return out
}

// crlFreshness is a CRL's position in its issuer's sequence.
type crlFreshness struct {
	// subject names the anchor in a refusal message; the map key is its raw
	// SubjectPublicKeyInfo, which is binary and cannot be logged.
	subject    string
	number     *big.Int
	thisUpdate time.Time
}

// newerThan orders two CRLs from one issuer: by cRLNumber where both publish
// one, and by ThisUpdate otherwise -- the one dimension every CRL carries.
//
// It deliberately does *not* follow internal/ca's newerCRL in treating a
// published number as beating an absent one. That rule is safe there, where
// this CA issues both CRLs and controls whether the extension appears. Here the
// CRLs come from a foreign issuer through a file, and deciding on the presence
// of an extension is unsafe in both directions:
//
//   - An installed unnumbered CRL against a numbered candidate would say "not a
//     regression" whatever the dates, so a numbered CRL three weeks old could
//     replace a current one and re-admit everything revoked since.
//   - An installed numbered CRL against an unnumbered candidate would say
//     "regression" whatever the dates, pinning the anchor: once any numbered
//     CRL is installed, an issuer that stops publishing the extension can never
//     update it again, and the refusal is indistinguishable from an attack.
//
// Comparing the dates instead costs nothing against a replay, which is the
// threat this exists for: an attacker who cannot forge a signature can only
// replay CRLs the issuer really published, and a genuinely older one carries a
// genuinely older ThisUpdate. The steady state between refreshes is the same
// file, equal on both fields, so this still reports no regression.
func (f crlFreshness) newerThan(other crlFreshness) bool {
	if f.number != nil && other.number != nil {
		if c := f.number.Cmp(other.number); c != 0 {
			return c > 0
		}
		// Equal numbers: an issuer that reissues without incrementing leaves
		// ThisUpdate as the only ordering there is, and calling the pair equal
		// would let the older of the two install.
	}
	return f.thisUpdate.After(other.thisUpdate)
}

// PartialsDropped reports whether candidate holds fewer partial-scope CRLs than
// this set for some anchor whose full CRL has not moved forward, naming that
// anchor's issuer.
//
// Needed because partials are deliberately invisible to the other two guards:
// they are filed apart, so an anchor's Coverage and freshness are identical
// whether or not its delta is present. Once a delta can deny a client -- which
// is the point of keeping it -- a reload that silently drops it re-admits every
// serial only it named, and neither losesCoverage nor Regresses can see that.
//
// Conditioned on the full CRL not advancing, because a shrinking delta is the
// normal case and not a fault: when an issuer publishes a new base, the serials
// accumulated in the old delta fold into it and the delta legitimately resets.
// Refusing on the count alone would reject every ordinary base rotation.
func (s *ClientCRLSet) PartialsDropped(candidate *ClientCRLSet, now time.Time) (string, bool) {
	if s == nil {
		return "", false
	}
	currentF := s.freshness(now)
	candidateF := candidate.freshness(now)
	for key, partials := range s.partialBySignerKey {
		if candidate != nil && len(candidate.partialBySignerKey[key]) >= len(partials) {
			continue
		}
		if cand, ok := candidateF[key]; ok && cand.newerThan(currentF[key]) {
			continue // the base moved on, so the delta resetting is expected
		}
		return partials[0].Issuer.String(), true
	}
	return "", false
}

// Regresses reports whether candidate would move any anchor backwards, naming
// one of the anchors it would, so a refusal can say which issuer regressed.
//
// One rather than the first: the scan is over a map, so where several anchors
// regress at once the name reported varies between passes. That is sufficient
// for its purpose -- an operator needs a thread to pull, and the reload is
// refused whole either way -- but it is not a stable identifier to match on.
func (s *ClientCRLSet) Regresses(candidate *ClientCRLSet, now time.Time) (string, bool) {
	currentF := s.freshness(now)
	candidateF := candidate.freshness(now)
	for key, cur := range currentF {
		cand, ok := candidateF[key]
		if !ok {
			continue // a lost anchor is losesCoverage's business, not this one
		}
		if cur.newerThan(cand) {
			return cur.subject, true
		}
	}
	return "", false
}

// clientCRLs holds the atomically-swappable CRL set for a domain.
type clientCRLs struct {
	current atomic.Pointer[ClientCRLSet]
}

// Set installs a reloaded CRL set.
func (c *clientCRLs) Set(s *ClientCRLSet) { c.current.Store(s) }

// Get returns the current set, which may be nil before the first load.
func (c *clientCRLs) Get() *ClientCRLSet { return c.current.Load() }

// ErrNoUsableCRL marks a refusal caused by the absence of revocation
// information, as opposed to a revocation that was found.
//
// The distinction is the whole meaning of the refusals counter. Both outcomes
// deny the request, but one says "this CA cannot tell whether the client is
// revoked" and the other says "it is revoked" -- and the second is the feature
// working. Counting them together made the branch's only critical
// authentication alert fire whenever a revoked client retried, driveable at
// will by precisely the population revocation exists to exclude, with a runbook
// telling the responder to refresh a CRL that was present and current.
var ErrNoUsableCRL = errors.New("revocation status unavailable")

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
			return fmt.Errorf("%w: the presented certificate is itself a trust anchor, "+
				"so nothing can attest to its revocation status", ErrNoUsableCRL)
		}
		return nil
	}

	for i := 0; i < len(chain)-1; i++ {
		subject, issuer := chain[i], chain[i+1]
		crls, anyValid := set.forRevocationLookup(issuer, now)
		if policy == RevocationRequire && !anyValid {
			return fmt.Errorf("%w: no currently valid CRL for issuer %q",
				ErrNoUsableCRL, issuer.Subject.CommonName)
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
