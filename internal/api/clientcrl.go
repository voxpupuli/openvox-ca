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
// Only the partials are added: forIssuer's slice already carries every full CRL
// this set holds for the anchor, not-yet-issued ones included, because it gates
// the date test on anyValid rather than on what it returns.
//
// anyValid still comes from the full, believably-dated CRLs alone: a delta is
// evidence that a serial *is* revoked and never that an issuer is covered, and
// neither is a CRL this host thinks has not been issued -- so neither can
// satisfy `require` for an issuer whose current full CRL is missing.
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
		// The slice is every full CRL this set holds for the anchor,
		// unfiltered. It answers Coverage's `present` and freshness's map-entry
		// existence, both of which are questions about what the file contains
		// rather than about this host's clock -- and gating it here emptied
		// coverage and zeroed both marks together, disarming losesCoverage and
		// Regresses at once.
		//
		// The date test guards anyValid alone, which is the currency claim: a
		// CRL this host thinks is not yet issued is not yet anybody's word. The
		// one consumer needing a dated view of the slice, freshness's `latest`,
		// applies notYetIssued itself and records that it did.
		crls = append(crls, crl)
		if !notYetIssued(crl, now) && currentAt(crl, now) {
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
// clockSkewTolerance is how far ahead of this host's clock a CRL's ThisUpdate
// may sit and still be treated as issued.
//
// Signers and this CA keep separate clocks and neither is authoritative, so a
// small forward difference is ordinary rather than suspicious. Beyond it, the
// CRL is treated as not yet issued -- which is what X.509 already does with a
// certificate's notBefore, and the reason this borrows that rule rather than
// inventing one.
const clockSkewTolerance = 5 * time.Minute

// notYetIssued reports whether a CRL claims an issue date meaningfully ahead of
// now, and so cannot yet be treated as the issuer's current word.
//
// A predicate over one CRL and one time, deliberately: the mistake this
// replaces was a filter applied to one side of a comparison and not the other,
// twice, in opposite directions. Something that takes a single CRL has no sides
// to get wrong.
//
// Such a CRL still denies the serials it names: forIssuer returns it in the
// slice and gates only anyValid, so every reader of the serials sees it. It
// is refused as *evidence of currency*, which is a claim about the issuer's
// timeline, and believed as *evidence of revocation*, which is a claim the
// signature already backs. Discarding the second would let a clock difference
// re-admit revoked clients.
func notYetIssued(crl *x509.RevocationList, now time.Time) bool {
	return crl.ThisUpdate.After(now.Add(clockSkewTolerance))
}

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
	// Derived from Coverage rather than repeating the currency rule over the
	// map. The rule has been placed wrongly six times, and this gauge
	// disagreeing with enforcement is the worst shape of all -- so it is read
	// from where enforcement reads it rather than restated. Coverage returns
	// empty maps for a nil receiver, so the nil check this used to carry is
	// covered.
	_, current := s.Coverage(now)
	return len(current) > 0
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

// freshness reports, per anchor key, how far that anchor's revocation
// information has advanced: the highest cRLNumber and the latest ThisUpdate
// seen among its full CRLs, tracked as two independent marks.
//
// Not "the newest CRL": cRLNumber is required of a conforming issuer but not
// universally present (`openssl ca -gencrl` omits it under the stock config),
// so a bundle can hold numbered and unnumbered CRLs for one anchor and neither
// field can serve alone. See crlFreshness for why that ruled out electing one.
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
		// Full CRLs only. A delta's cRLNumber exceeds the base it is relative
		// to, so folding partials into the watermark would leave every later
		// base rotation looking like a regression and pin the anchor.
		crls, _ := s.forIssuer(anchor, now)
		for _, crl := range crls {
			f := out[key]
			f.subject = anchor.Subject.String()
			// The date gate applies to the marks here, and to currency in
			// forIssuer's anyValid -- those are the two clock-dependent
			// answers. What it must not touch is forIssuer's slice, which also
			// answers Coverage's `present` and this map's entry existence,
			// both questions about the file rather than about the clock:
			// gating it there emptied
			// coverage and zeroed both marks together.
			//
			// Gating the mark without recording that it was gated is what made
			// this look like the wrong home twice: a suppressed mark is zero,
			// zero.Before(real) is true and real.After(zero) is true, so a
			// suppressed mark compared against a real one reads as a regression
			// in one direction and an advance in the other. `dated` makes the
			// two non-comparable instead -- see regressedFrom.
			if !notYetIssued(crl, now) {
				f.dated = true
				if crl.ThisUpdate.After(f.latest) {
					f.latest = crl.ThisUpdate
				}
			}
			if crl.Number != nil && (f.maxNumber == nil || crl.Number.Cmp(f.maxNumber) > 0) {
				f.maxNumber = new(big.Int).Set(crl.Number)
			}
			out[key] = f
		}
	}
	return out
}

// crlFreshness is how far an anchor's revocation information has advanced, as
// two independent high-water marks rather than a single "newest CRL".
//
// Two marks because electing a single newest CRL needs a comparator, and the
// comparator this replaced switched axis on whether *both* sides published a
// cRLNumber -- number when they did, ThisUpdate when they did not. That switch
// is what made it intransitive, and it needs mixed presence of the extension to
// bite, not merely numbers and dates that disagree: with A(num 1, date 3),
// B(num 2, date 1) and C(unnumbered, date 2), B beats A by number, C beats B by
// date, and A beats C by date. Which CRL was elected then depended on the order
// they appeared in the file. Taking the maximum of each field separately is
// order-independent whatever the inputs, so the question does not arise.
type crlFreshness struct {
	// subject names the anchor in a refusal message; the map key is its raw
	// SubjectPublicKeyInfo, which is binary and cannot be logged.
	subject string

	// maxNumber is the highest cRLNumber seen for this anchor, nil where no CRL
	// for it published one. latest is the latest ThisUpdate seen.
	maxNumber *big.Int
	latest    time.Time

	// dated is true where at least one full CRL for this anchor carried a
	// ThisUpdate this host is prepared to believe, so latest means something.
	// A zero latest is otherwise ambiguous -- it reads as both "no believable
	// date" and "the beginning of time" -- and comparing the second reading
	// against a real date is the whole of the fifth and sixth regressions.
	dated bool
}

// advancedOver reports whether the anchor's full CRLs have genuinely moved on,
// used to tell an ordinary base rotation from a delta silently disappearing.
//
// The date must advance, and the number must not go backwards. A higher number
// alone is not enough, and allowing it was a hole: an attacker who can write
// crl_file has only to append a genuine archived CRL numbered above the base to
// satisfy "the base rotated", at which point PartialsDropped reports nothing
// and an enforced delta can be dropped -- re-admitting every serial only that
// delta named. Archived material is what such an attacker has; a *later date*
// is the thing they cannot manufacture without the issuer's key.
func (f crlFreshness) advancedOver(other crlFreshness) bool {
	// An undated mark on either side means no advance can be demonstrated, so
	// the delta drop is refused. Without those conjuncts an installed set whose
	// full CRL is dated ahead has a zero latest, any full CRL at all reads as
	// an advance, and an enforced delta can be dropped -- the same overload the
	// hadBase guard exists to prevent, arriving through the other door.
	return f.dated && other.dated && f.latest.After(other.latest) && !f.regressedFrom(other)
}

// regressedFrom reports whether f has gone backwards from other on either axis.
//
// Either, not both: an attacker who can write crl_file cannot forge a
// signature, so they can only replay CRLs the issuer genuinely published, at a
// time of their choosing. A replay is older on at least one axis, and requiring
// both to regress would let them replay using whichever axis their target
// issuer keeps badly.
//
// Arm 1 compares numbers only where both sides have one. Ranking a numbered CRL
// above an unnumbered one *on that basis alone* was shipped once and was unsafe
// in both directions -- it let an older numbered CRL displace a newer unnumbered
// one, and pinned any anchor whose issuer stopped publishing the extension.
//
// Arm 2 does consult presence, and is not that mistake returning. It fires only
// where the installed side is undated, so the dates have already dropped out of
// the comparison and presence is the last thing left to reason from -- and it
// refuses rather than ranking, which is the direction that cannot admit a
// replay. Arm 1 still never ranks on presence.
func (f crlFreshness) regressedFrom(other crlFreshness) bool {
	if f.maxNumber != nil && other.maxNumber != nil && f.maxNumber.Cmp(other.maxNumber) < 0 {
		return true
	}
	// The installed side carries full CRLs this host will not date. Ordering
	// then rests entirely on the numbers, and where either side has none there
	// is nothing left to order by -- so refuse rather than install a file that
	// cannot be shown to be newer. Self-limiting: once now passes those
	// ThisUpdates the anchor is dated again and this arm stops firing. Without
	// it, an unnumbered issuer whose CRLs sit beyond the skew tolerance has no
	// replay guard at all, which is what suppressing `latest` would cost.
	if !other.dated {
		return f.maxNumber == nil || other.maxNumber == nil
	}
	// The candidate is the undated one: a forward-skewed issuer's genuine new
	// CRL. The numbers above have already had their say, and its date must not
	// be read as the beginning of time and called a regression.
	if !f.dated {
		return false
	}
	return f.latest.Before(other.latest)
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
		// "The base moved on" is only meaningful if there was a base. Where the
		// anchor holds partials and no full CRL, currentF has no entry and the
		// zero mark would make any full CRL at all -- however old -- read as an
		// advance, which is enough to excuse dropping an enforced delta.
		if cur, hadBase := currentF[key]; hadBase {
			if cand, ok := candidateF[key]; ok && cand.advancedOver(cur) {
				continue // the base moved on, so the delta resetting is expected
			}
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
		if cand.regressedFrom(cur) {
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
