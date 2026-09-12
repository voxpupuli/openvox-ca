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
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"time"
)

// A managed certificate is a named leaf this CA keeps alive: it issues it,
// renews it on a loop, and supersedes the predecessor with a delay. It is
// described by three things -- a spec (what the certificate must be), a store
// (where the certificate and its key live), and the lock that serialises
// replicas working on it.
//
// The private key never reaches the backing store, and never reaches the local
// cadir either. It is generated inside the subject lock, handed to the store,
// and dropped. That is the invariant this mechanism exists to preserve: the
// backing store holds exactly one private key, the CA's own, and only under
// ca_key_provider: file. POST /generate still writes leaf keys to
// <cadir>/private/ and is unchanged by any of this.

// CertSpec describes what a managed certificate must be. It is fixed by
// configuration and never derived from anything a client submits, which is what
// makes issueManagedUnderSubjectLock's place on the issuance seam defensible;
// see issuanceseam_test.go, which pins that caller set.
type CertSpec struct {
	// Subject is the certname. It becomes the certificate's Common Name, the
	// key it occupies in the inventory, and the subject recorded on the
	// pending-supersession list -- so it must be the same validated string
	// Revoke would be called with, or `revoke --certname` cannot find this
	// certificate's in-window predecessors.
	Subject string

	// DNSNames are the subjectAltName DNS entries the certificate must carry.
	// At least one is required, and the Subject is not added automatically.
	//
	// These are used exactly as configured. Two behaviours that apply to names
	// arriving on a submitted CSR deliberately do not apply here, and both are
	// properties this type promises rather than accidents of the call graph:
	//
	//   - PromoteCNToSAN does not add the Subject. A managed certificate's names
	//     are configuration, and an entry that wanted its certname as a SAN can
	//     say so; adding it silently is how a certificate comes to answer to a
	//     name nobody asked it to.
	//   - AllowSubjectAltNames does not gate them. That setting governs what a
	//     *request* may ask for, and there is no request here -- the names come
	//     from a file an administrator wrote. checkSubjectAltNames is reached
	//     only from signWithDuration, which issuanceseam_test.go pins.
	//
	// Requiring at least one name of some kind is what stops the first of those
	// becoming a trap. With no promotion and no names, the certificate carries
	// no SAN extension at all, and RFC 2818 clients ignore the Common Name --
	// so it would be refused for every name including its own, while looking
	// well-formed.
	DNSNames []string

	// IPAddresses, EmailAddresses and URIs are the other three subjectAltName
	// types, carried with the same semantics as DNSNames: used exactly as
	// configured, never promoted into, never gated.
	//
	// issueLeafLocked has supported all four since before managed certificates
	// existed, and AutoRenew carries all four forward. A managed certificate
	// that could only be named by DNS would be the odd one out -- and an IP SAN
	// is the case that makes it concrete, since a component reached at a fixed
	// address has nothing else to be named by.
	IPAddresses []net.IP

	// EmailAddresses are rfc822Name SAN entries.
	EmailAddresses []string

	// URIs are uniformResourceIdentifier SAN entries.
	URIs []*url.URL

	// ExtKeyUsage is what the certificate may be used for. Nil means the
	// serverAuth+clientAuth pair every other issuance path uses.
	//
	// SECURITY: clientAuth is what makes a certificate usable as a CA client,
	// and a certname listed in puppet_server is an administrator -- so the two
	// together are an admin credential. The listing is what grants the
	// authority; the usage is what lets it be presented. A deployment whose
	// certificate only ever answers handshakes can narrow this and lose
	// nothing, which is a decision for whoever configures the entry rather than
	// one this type should prejudge.
	// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
	ExtKeyUsage []x509.ExtKeyUsage

	// TTL is the certificate lifetime. Zero means the CA's configured
	// LeafValidityDays, or the built-in default when that is unset. Whatever it
	// says, issueLeafLocked caps the result at the CA certificate's remaining
	// life -- which is the fact renewWindowFor exists to survive.
	TTL time.Duration

	// RenewBefore is how far ahead of expiry a replacement is issued. It must
	// be positive: a managed certificate whose window is zero is renewed only
	// once it has already expired, which is not a renewal loop.
	//
	// It is an upper bound on the window, not the window itself. See
	// renewWindowFor for what is actually applied and why the difference
	// matters.
	RenewBefore time.Duration

	// KeyConfig is the algorithm and size of the key generated for this
	// certificate. The zero value inherits the CA's LeafKeyConfig, which in
	// turn falls back to DefaultLeafKeyConfig.
	//
	// Per-entry because the things a managed certificate serves need not agree
	// with the fleet: a component whose clients are all modern can take an
	// ECDSA key where agent certificates stay on RSA for compatibility.
	KeyConfig KeyConfig

	// ReuseKey reissues against the private key already in the entry's store
	// rather than generating a fresh one. False (the zero value) re-keys on
	// every renewal, which is the better default: a key that is replaced
	// regularly is one a disclosure stops mattering about.
	//
	// True exists for the cases where the key is the identity rather than an
	// implementation detail — a TLSA record or an SPKI pin names the key, and
	// re-keying breaks it. That is uncommon but real, and it is a decision the
	// configuration makes rather than one this mechanism should foreclose.
	//
	// Two consequences worth knowing. This is the only path in the tree that
	// reads a leaf private key back: nothing else has any use for one, which is
	// what makes `SavePrivateKey` write-only. It stays true that no leaf key
	// reaches the backing store — the read is from the entry's own store, and
	// the key is dropped when the issuance returns.
	//
	// And KeyConfig describes what to *generate*. A reused key keeps whatever
	// algorithm and size it already has, so the two settings do not interact:
	// changing KeyConfig under ReuseKey takes effect only when there is no key
	// to reuse.
	ReuseKey bool

	// SupersedeAfter is how long this certificate's predecessor stays valid
	// after a replacement is issued. Nil inherits the CA's SupersedeAfter.
	//
	// A pointer because zero is a meaningful value rather than an absence: it
	// means revoke inside the reconcile pass, with no overlap at all. An entry
	// that wants that on a CA whose default grants a window has no other way to
	// say so.
	//
	// Per-entry because the overlap is a property of whatever depends on the
	// certificate — how long it takes to notice a replacement and pick it up —
	// and two managed certificates need not agree about that.
	SupersedeAfter *time.Duration
}

// keyConfigFor resolves the key algorithm and size for spec, preferring the
// entry's own setting and falling back to the CA's.
//
// The CA-level fallback is leafKeyConfig's, deliberately rather than a second
// reading of the same field: this used to test Algo-or-Size where generate.go
// tests Algo alone, and the two then disagreed about `leaf_key_size: 4096` with
// no `leaf_key_algo` -- a configuration an operator can write today, which
// main.go and ValidateKeyConfig both accept. One CA, two paths, two key sizes.
func (c *CA) keyConfigFor(spec CertSpec) KeyConfig {
	if spec.KeyConfig.Algo != "" || spec.KeyConfig.Size != 0 {
		return spec.KeyConfig
	}
	return c.leafKeyConfig()
}

// supersedeAfterFor resolves the overlap window for spec, preferring the
// entry's own setting and falling back to the CA's.
func (c *CA) supersedeAfterFor(spec CertSpec) time.Duration {
	if spec.SupersedeAfter != nil {
		return *spec.SupersedeAfter
	}
	return c.SupersedeAfter
}

// Validate reports whether the spec can be issued from at all. Called for every
// entry before a reconcile pass touches storage, so a mistyped certname or an
// impossible window is refused as configuration rather than discovered as a
// certificate.
func (s CertSpec) Validate() error {
	if err := ValidateSubject(s.Subject); err != nil {
		return err
	}
	if len(s.DNSNames)+len(s.IPAddresses)+len(s.EmailAddresses)+len(s.URIs) == 0 {
		return fmt.Errorf("managed certificate %s: at least one subject alternative name "+
			"is required -- DNS, IP, email or URI; a certificate with none is refused by "+
			"every RFC 2818 client, including for its own certname", s.Subject)
	}
	if err := validateDNSAltNames(s.DNSNames); err != nil {
		return err
	}
	for _, ip := range s.IPAddresses {
		// A nil or zero-length net.IP marshals into an empty SAN entry rather
		// than failing, so it would produce a certificate carrying a name that
		// matches nothing. Refused as configuration.
		if len(ip) == 0 {
			return fmt.Errorf("managed certificate %s: an IP address entry is empty; "+
				"an unparsed address reaches the certificate as a name matching nothing",
				s.Subject)
		}
	}
	for _, addr := range s.EmailAddresses {
		if addr == "" {
			return fmt.Errorf("managed certificate %s: an email address entry is empty; "+
				"it reaches the certificate as a name matching nothing", s.Subject)
		}
	}
	for _, u := range s.URIs {
		// Nil would panic in leafCarriesNames and in marshalling; a zero-value
		// URL stringifies to "" and reaches the certificate as an empty
		// uniformResourceIdentifier. Both satisfy the at-least-one-name check
		// above while naming nothing, which is what that check exists to stop.
		if u == nil {
			return fmt.Errorf("managed certificate %s: a URI entry is nil", s.Subject)
		}
		if u.String() == "" {
			return fmt.Errorf("managed certificate %s: a URI entry is empty; "+
				"it reaches the certificate as a name matching nothing", s.Subject)
		}
	}
	// Bounded like the DNS names, and for the same reason: the count is what
	// reaches the certificate, and nothing downstream caps it.
	if n := len(s.EmailAddresses) + len(s.URIs) + len(s.IPAddresses); n > maxDNSAltNames {
		return fmt.Errorf("managed certificate %s: too many non-DNS alternative names "+
			"(%d > %d)", s.Subject, n, maxDNSAltNames)
	}
	if s.TTL < 0 {
		return fmt.Errorf("managed certificate %s: ttl must not be negative", s.Subject)
	}
	if s.RenewBefore <= 0 {
		return fmt.Errorf("managed certificate %s: renew_before must be positive, "+
			"or the certificate is only replaced after it has already expired", s.Subject)
	}
	// Refused here as well as at generation. issueLeafLocked enforces the
	// key-strength policy on the public key it is handed, which is the
	// structural guarantee -- but that fires after a pass has taken the subject
	// lock and generated a key, once per interval, for ever. A spec that can
	// never succeed should fail as configuration.
	if err := ValidateKeyConfig(s.KeyConfig); err != nil {
		return fmt.Errorf("managed certificate %s: %w", s.Subject, err)
	}
	if s.SupersedeAfter != nil && *s.SupersedeAfter < 0 {
		return fmt.Errorf("managed certificate %s: revoke_after must not be negative "+
			"(zero revokes the predecessor inside the reconcile pass)", s.Subject)
	}
	return nil
}

// ManagedCert is one entry of the reconcile loop: a spec, plus the store that
// holds the material it describes.
//
// The store is two function fields rather than an interface, and that is a
// decision rather than an omission. The stores this mechanism serves differ in
// failure semantics and not merely in mechanism -- a serving store must be
// readable before the listener starts and its absence is fatal, whereas a
// component store's absence is routine and self-heals on the next pass. An
// interface spanning both would have to express that difference in its
// contract, which is a worse place for it than in the two callers. Each caller
// loads and saves its own way and asks the same question.
type ManagedCert struct {
	Spec CertSpec

	// Load reads the current material. An empty store is not an error: absent
	// material is an input to the decision, and reporting it as a failure would
	// stop the very pass that repairs it. A real read failure IS an error and
	// stops this entry for this pass -- reconciling against material we could
	// not read would reissue on every pass for as long as the store is down.
	Load func(ctx context.Context) (certPEM, keyPEM []byte, err error)

	// Save writes the certificate and its key together. It must be atomic with
	// respect to readers: a store holding one issuance's certificate and
	// another's key is well-formed and fails every handshake made against it.
	//
	// This is called inside the subject lock, which is why #189's EmitKey hook
	// is not used here. EmitKey fires before the lock is taken -- correct for a
	// single operator at a terminal, a race for a replicated loop, where two
	// replicas can each generate a key and each emit it before either takes the
	// lock.
	Save func(ctx context.Context, certPEM, keyPEM []byte) error
}

// issueReason says why a reconcile pass did or did not issue. Each value is a
// distinct diagnosis rather than a shade of the same one, because this is what
// an operator reads in the log when a certificate is being reissued more often
// than they expect.
type issueReason int

const (
	// reasonCurrent is the steady state: the stored material satisfies the
	// spec and is not yet inside its renew window.
	reasonCurrent issueReason = iota
	// reasonAbsent means the store holds no certificate. The first pass on a
	// fresh deployment, and the state after a store is deleted externally.
	reasonAbsent
	// reasonUnparseable means the store holds bytes that are not a certificate.
	reasonUnparseable
	// reasonKeyUnusable means the store holds a certificate but no key, or a
	// key that cannot be parsed. The "process died between signing and writing"
	// case lands here.
	reasonKeyUnusable
	// reasonKeyMismatch means the key parses but is not the certificate's.
	// Two replicas writing a pair non-atomically would produce this.
	reasonKeyMismatch
	// reasonNotOurs means the certificate was not issued by this CA. Reissuing
	// is right -- but note that nothing revokes the certificate being replaced
	// here, because its serial is not ours to put on our CRL.
	reasonNotOurs
	// reasonNamesMissing means the certificate does not carry every name the
	// spec requires, its Common Name included.
	reasonNamesMissing
	// reasonUsageMismatch means the certificate's extended key usages are not
	// the spec's.
	reasonUsageMismatch
	// reasonRevoked means the certificate is on the CRL.
	reasonRevoked
	// reasonRenewWindow means the certificate is inside its renew window --
	// which includes having expired outright.
	reasonRenewWindow
)

// String names the reason for a log line.
func (r issueReason) String() string {
	switch r {
	case reasonCurrent:
		return "current"
	case reasonAbsent:
		return "absent"
	case reasonUnparseable:
		return "unparseable"
	case reasonKeyUnusable:
		return "key-unusable"
	case reasonKeyMismatch:
		return "key-mismatch"
	case reasonNotOurs:
		return "not-issued-by-this-ca"
	case reasonNamesMissing:
		return "names-missing"
	case reasonUsageMismatch:
		return "usage-mismatch"
	case reasonRevoked:
		return "revoked"
	case reasonRenewWindow:
		return "renew-window"
	default:
		return fmt.Sprintf("issueReason(%d)", int(r))
	}
}

// renewWindowFor returns the renew-before window actually in force for leaf,
// which is not always the one the spec asks for.
//
// issueLeafLocked caps a leaf's validity at the CA certificate's *remaining*
// life. So a window that sits comfortably inside the configured lifetime grows
// larger than the certificate's real one as the CA certificate ages: with a
// 90-day ttl and a 30-day window, a CA certificate with 20 days left issues a
// 20-day leaf that is inside its window the moment it is signed. Every pass
// then reissues, for ever. That is the failure nine review rounds of the
// serving-certificate work closed, and it is why startup validation is not
// enough -- the configuration never changes, the CA certificate's remaining
// life does.
//
// The floor is half the certificate's own forward lifetime, derived from the
// certificate in hand rather than from configuration, so no setting can defeat
// it. It guarantees the loop makes progress: every issuance serves at least
// half the life it was actually granted before its successor is due. In an
// ordinary deployment it is invisible -- a 30-day window on a 90-day
// certificate is nowhere near the 45-day floor -- which is the property to
// want. It only binds when the alternative is a reissue loop.
//
// Forward lifetime, not NotAfter-NotBefore: issueLeafLocked backdates
// NotBefore so a verifier with a slow clock still accepts a certificate we
// have just signed, and counting that backdate as life the certificate has to
// serve would reintroduce the same loop at short ttls (with a 24-hour backdate
// a one-hour certificate has a 25-hour span, and half of that is longer than
// the certificate lasts).
//
// backdate is the CA's current setting, which is not necessarily the one in
// force when leaf was signed. Changing the setting therefore mis-measures
// certificates already issued, by exactly the difference between the two
// values -- bounded, one-way, and corrected at the next issuance. Nothing in
// the certificate records the backdate it was issued under, so the current
// setting is the only value available; the alternative, assuming a constant,
// was wrong for every deployment that changed it.
//
// This is only ever reached for certificates this CA issued: reasonNotOurs is
// decided first, so the backdate assumption never has to hold for a foreign
// certificate.
func renewWindowFor(leaf *x509.Certificate, want CertSpec, backdate time.Duration) time.Duration {
	forward := leaf.NotAfter.Sub(leaf.NotBefore) - backdate
	if forward <= 0 {
		// A certificate with no forward life at all. Nothing to hold back;
		// letting the caller renew it immediately is the only useful answer.
		return 0
	}
	return min(want.RenewBefore, forward/2)
}

// issueDecision reports whether the material a store handed back satisfies
// want, and if not, why.
//
// Pure: no I/O, no locks, no clock of its own. Callers load their own material,
// establish revocation against whatever CRL they hold, and pass now in. That is
// the whole point of extracting it -- the alternative was a second copy of this
// reasoning for a second store, and the copies would diverge on exactly the
// kind of fix renewWindowFor is.
//
// certPEM and keyPEM are the raw bytes rather than parsed values so that
// "absent" and "unparseable" are decided here too. Splitting the parse out
// would put two of the reasons in the caller and the rest here, which is how a
// second caller comes to disagree about one of them.
//
// The parsed certificate is returned so the caller need not decode it again to
// reach the serial it must supersede. It is nil when there was nothing usable
// to parse.
func issueDecision(certPEM, keyPEM []byte, want CertSpec, issuer *x509.Certificate,
	backdate time.Duration, now time.Time, revoked bool) (issue bool, reason issueReason, current *x509.Certificate) {
	if len(certPEM) == 0 {
		return true, reasonAbsent, nil
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true, reasonUnparseable, nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true, reasonUnparseable, nil
	}

	// Ownership before anything that reasons about how this certificate was
	// built. Every check below -- the renew window's leafBackdate arithmetic
	// most of all -- assumes we issued it, and a foreign certificate is
	// replaced whatever else is true of it. Note what the caller must not do
	// with the returned certificate on this arm: its serial is not ours and
	// must never reach our CRL.
	if issuer == nil {
		// An uninitialised CA cannot judge ownership, and answering "ours"
		// would be the unsafe direction. reconcileManagedCert refuses before
		// reaching here; this is the guard for a caller that does not.
		return true, reasonNotOurs, leaf
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return true, reasonNotOurs, leaf
	}

	// The key, before the certificate's contents: a certificate whose key we do
	// not have is not a credential, however well it matches the spec.
	if len(keyPEM) == 0 {
		return true, reasonKeyUnusable, leaf
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return true, reasonKeyUnusable, leaf
	}
	key, err := parsePrivateKeyDER(keyBlock.Type, keyBlock.Bytes)
	if err != nil {
		return true, reasonKeyUnusable, leaf
	}
	if !publicKeysEqual(key.Public(), leaf.PublicKey) {
		return true, reasonKeyMismatch, leaf
	}

	if !leafCarriesNames(leaf, want) {
		return true, reasonNamesMissing, leaf
	}
	if !leafCarriesUsages(leaf, want) {
		return true, reasonUsageMismatch, leaf
	}

	// Revocation before the window: a revoked certificate is replaced now, not
	// when its window opens, and the caller wants to hear the more urgent of
	// the two reasons.
	if revoked {
		return true, reasonRevoked, leaf
	}

	if !now.Before(leaf.NotAfter.Add(-renewWindowFor(leaf, want, backdate))) {
		return true, reasonRenewWindow, leaf
	}
	return false, reasonCurrent, leaf
}

// publicKeysEqual reports whether two public keys are the same key.
//
// Every public key type crypto/x509 parses implements Equal; a type that does
// not is one this CA cannot reason about, and answering "equal" for it would
// mean accepting a certificate whose key we have not established we hold.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// leafCarriesNames reports whether leaf answers to every name want requires.
//
// Extra names are not a mismatch. A store's certificate may legitimately carry
// names an operator has since removed from the configuration, and reissuing to
// *narrow* a certificate on the next pass would drop names something may still
// be dialling, without the certificate having done anything wrong. Widening is
// what the spec asks for; narrowing waits for natural renewal.
// All four SAN types are checked, not just DNS. A type the decision ignored
// would be a setting an operator could change with no effect until natural
// expiry -- decorative configuration, which is the same defect as an extended
// key usage that never takes hold.
func leafCarriesNames(leaf *x509.Certificate, want CertSpec) bool {
	if leaf.Subject.CommonName != want.Subject {
		return false
	}
	for _, name := range want.DNSNames {
		if !slices.Contains(leaf.DNSNames, name) {
			return false
		}
	}
	for _, want := range want.IPAddresses {
		// Compared with net.IP.Equal rather than slices.Contains: the same
		// address has more than one representation (a 4-byte form and a
		// 16-byte IPv4-in-IPv6 form), and x509 parsing does not promise which
		// one comes back. Bytewise equality would report a mismatch on every
		// pass and reissue for ever.
		if !slices.ContainsFunc(leaf.IPAddresses, want.Equal) {
			return false
		}
	}
	for _, addr := range want.EmailAddresses {
		if !slices.Contains(leaf.EmailAddresses, addr) {
			return false
		}
	}
	for _, u := range want.URIs {
		target := u.String()
		if !slices.ContainsFunc(leaf.URIs, func(got *url.URL) bool {
			return got != nil && got.String() == target
		}) {
			return false
		}
	}
	return true
}

// leafCarriesUsages reports whether leaf's extended key usages are exactly the
// ones want asks for.
//
// Exactly, not "at least": what the spec says is what gets issued, in both
// directions. A subset test would leave an existing serverAuth+clientAuth
// certificate satisfying a serverAuth-only spec until it expired of its own
// accord -- and that is the one drift where waiting is the wrong answer, since
// the certificate still in the store is a usable admin credential for a name in
// puppet_server. Narrowing the usage has to take effect when the operator
// narrows it, or the setting is decorative.
//
// The issue this implements did not list a usage mismatch among its reasons;
// it is here because without it a change to the setting has no effect until
// natural expiry, and the setting's only purpose is security.
func leafCarriesUsages(leaf *x509.Certificate, want CertSpec) bool {
	wanted := want.ExtKeyUsage
	if len(wanted) == 0 {
		wanted = defaultLeafExtKeyUsage()
	}
	// Both sides are compacted, and that symmetry is the whole point. crypto/x509
	// de-duplicates extended key usages neither on write nor on parse, so a spec
	// naming the same usage twice yields a certificate carrying it twice --
	// which, compared against a compacted want, never matches. The certificate
	// would then fail the very spec that produced it, on every pass, for ever:
	// the unbounded reissue loop renewWindowFor exists to close, reached through
	// a door the clamp cannot see. Compacting one side only is how that happens.
	got := slices.Compact(slices.Sorted(slices.Values(leaf.ExtKeyUsage)))
	wanted = slices.Compact(slices.Sorted(slices.Values(wanted)))
	return slices.Equal(got, wanted)
}

// ReconcileManaged runs one pass over c.ManagedCerts, issuing whatever is due.
// It reports how many certificates it issued.
//
// One pass, not a loop: the timer belongs to the caller, which is what lets the
// server run it as an ordinary background job alongside the CRL refresher and
// the superseded sweep. Renewal is time-driven, so it cannot hang off
// CRLUpdated() the way the Kubernetes exporter does -- that channel can be
// silent for days on a quiet CA, and a certificate does not stop expiring
// because nothing was revoked.
//
// Entries are independent. One that fails is logged, counted as a failure, and
// left for the next pass; the rest still run. A single unreachable store must
// not stop every other managed certificate from renewing.
//
// Safe on every replica: each entry's work is serialised on that subject's
// cluster lock, and a replica that loses the race reads the certificate the
// winner just wrote and does nothing.
func (c *CA) ReconcileManaged(ctx context.Context) (int, error) {
	if len(c.ManagedCerts) == 0 {
		return 0, nil
	}

	issued := 0
	var firstErr error
	for _, m := range c.ManagedCerts {
		did, err := c.reconcileManagedCert(ctx, m, time.Now().UTC())
		if err != nil {
			slog.Warn("Managed certificate not reconciled",
				"subject", m.Spec.Subject, "error", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if did {
			issued++
		}
	}
	return issued, firstErr
}

// reconcileManagedCert runs one entry: load, decide, and issue if the decision
// says so, all inside that subject's cluster lock.
//
// Holding the lock across all three is what makes the mechanism converge. Two
// replicas reaching this at once do not both issue: the loser blocks, and its
// load then returns the certificate the winner just wrote, which the decision
// finds current. Splitting the lock so that only the issuance were inside it
// would leave both replicas deciding against the same stale material and both
// issuing -- one certificate wasted per replica per pass, each superseding the
// last.
//
// Lock ordering: subject-lock (distributed) -> c.mu for the issuance, and
// subject-lock -> crl -> c.mu for the supersession, both of which are the
// orders every other issuance path already takes. The lock is derived from the
// subject rather than configured: the serving certificate's dedicated lock on
// the closed #165 existed because replicas shared one blob and were allowed to
// disagree about their own hostname, and neither premise survives a managed
// certificate having a configured name and a store of its own.
//
// The caller must NOT hold c.mu.
func (c *CA) reconcileManagedCert(ctx context.Context, m ManagedCert, now time.Time) (bool, error) {
	if err := m.Spec.Validate(); err != nil {
		return false, err
	}
	if m.Load == nil || m.Save == nil {
		return false, fmt.Errorf("managed certificate %s: store is not configured", m.Spec.Subject)
	}

	c.mu.RLock()
	issuer, initialised := c.CACert, c.CACert != nil && c.CAKey != nil
	c.mu.RUnlock()
	if !initialised {
		return false, ErrNotInitialized
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	subject := m.Spec.Subject
	issued := false
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		certPEM, keyPEM, err := m.Load(ctx)
		if err != nil {
			return fmt.Errorf("reading the stored material for %s: %w", subject, err)
		}

		// Revocation is an input to the decision but needs a serial, and the
		// serial needs a parse the decision is about to do anyway. Parsing
		// twice is the cost of keeping issueDecision pure, and it is a parse of
		// bytes already in memory. A certificate that will not parse here is
		// one issueDecision reports as unparseable a moment later, so treating
		// the failure as "not revoked" decides nothing.
		revoked := c.storedMaterialRevoked(ctx, certPEM, subject)

		issue, reason, current := issueDecision(certPEM, keyPEM, m.Spec, issuer, c.leafBackdate(), now, revoked)
		if !issue {
			slog.Debug("Managed certificate is current",
				"subject", subject, "not_after", current.NotAfter.Format(time.RFC3339))
			return nil
		}
		// Report, before issuing, any certificate this CA holds for the name
		// that the entry does not account for. The issuance proceeds either
		// way -- refusing would stall the self-heal #242's failure table
		// requires -- but a credential that stops being reachable by certname
		// is not something to let pass silently.
		c.warnIfDisplacingUnderSubjectLock(ctx, subject, current)

		slog.Info("Issuing managed certificate", "subject", subject, "reason", reason.String())

		did, err := c.issueManagedUnderSubjectLock(ctx, m, reason, current, keyPEM)
		issued = did
		return err
	})
	if err != nil {
		return false, err
	}
	return issued, nil
}

// warnIfDisplacingUnderSubjectLock reports a certificate this CA holds for the subject
// that the managed entry is about to replace and does not account for.
//
// issueLeafLocked ends in an unconditional SaveCert, so whatever is at
// cert/<subject> is replaced. The predecessor the ordinary path retires is
// `current`, which came from the entry's own store -- and on the absent,
// unparseable and key-unusable arms that is either nothing or something older
// than the CA has on file. The replaced certificate then stays valid while the
// CA's record points at its successor, so `revoke --certname` reaches the new
// one and the old one is addressable only by serial.
//
// This says so, loudly, and then lets the issuance proceed. Two earlier designs
// were tried and a third was considered and refused; all three are recorded
// here because each is tempting:
//
//   - Refuse whenever the incumbent is not `current`. That is what the first
//     version did, and it refused exactly the cases #242's failure table
//     requires to self-heal -- a store emptied externally, a store whose
//     contents will not parse, a pass that died between signing and the write
//     -- because on all three the entry's store cannot account for anything.
//     The entry then stalled for ever and the real certificate expired.
//   - Retire the incumbent when it satisfies the entry's spec, on the reasoning
//     that such a certificate is indistinguishable from one the entry issued.
//     It is indistinguishable, and that is the problem: an ordinary agent
//     certificate for the same certname satisfies the obvious managed spec
//     exactly -- matching CN, the CN promoted to a DNS SAN, and the default
//     serverAuth+clientAuth pair -- so the loop would revoke a node's live
//     credential to take its name. A signature check does not separate them
//     either; this CA issued both.
//   - Mark managed issuances with an extension and adopt only what carries it.
//     That is the only exact test, and it needs an OID. The Puppet arc is
//     Puppet's, not this project's, so minting one there would be squatting on
//     a namespace we do not own.
//
// So the CA revokes nothing it cannot prove is its to revoke, and the operator
// gets the serial and the remedy instead. The certificate is not lost: it keeps
// its inventory row, and `openvox-ca-ctl revoke --serial` addresses it.
//
// The check is one-directional, and deliberately so for now. Renew and
// AutoRenew also end in issueLeafLocked's unconditional SaveCert, so the holder
// of a displaced certificate can renew and take cert/<subject> back -- leaving
// the *managed* certificate reachable only by serial, with no warning, because
// neither renewal path consults c.ManagedCerts. Making it symmetric means
// teaching the renewal paths about a mechanism nothing configures yet, so it is
// recorded here rather than built: #243 must not inherit the asymmetry as
// settled.
//
// The caller must hold subject's lock and must NOT hold c.mu: IsRevokedSerial
// takes c.mu.RLock, which is not reentrant. Named for the lock it runs under
// rather than with this package's `...Locked` suffix, which everywhere else
// means "c.mu is held by the caller" -- the opposite of what is wanted here,
// and a reader who followed the usual reading would wedge the reconcile
// goroutine on a mutex that honours no deadline, while it holds the subject's
// cluster lock.
func (c *CA) warnIfDisplacingUnderSubjectLock(ctx context.Context, subject string, current *x509.Certificate) {
	storedPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			// Not fatal: the issuance is going ahead either way, and this is a
			// diagnostic. Say that the check could not be made rather than
			// implying there was nothing to report.
			slog.Warn("Could not read the stored certificate for a managed subject; "+
				"cannot say whether this issuance displaces one",
				"subject", subject, "error", err)
		}
		return
	}
	block, _ := pem.Decode(storedPEM)
	if block == nil {
		return
	}
	stored, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	if current != nil && stored.SerialNumber.Cmp(current.SerialNumber) == 0 {
		return
	}
	revoked, err := c.IsRevokedSerial(ctx, stored.SerialNumber)
	if err == nil && revoked {
		return
	}
	// SECURITY: a credential this CA issued stays valid while the record that
	// names it is replaced, so by-name revocation will no longer reach it. That
	// is an authorisation fact an operator has to be told, with the address they
	// need to act on it.
	// NIST 800-53: AU-2 (Event Logging), AC-6 (Least Privilege)
	slog.Warn("A managed certificate is replacing a different certificate stored for its name; "+
		"the replaced certificate stays valid and is no longer reachable by certname. "+
		"Retire it with 'openvox-ca-ctl revoke --serial <hex>' if it must go, or give the "+
		"managed certificate a name of its own",
		"subject", subject, "displaced_serial", serialHexStr(stored.SerialNumber),
		"displaced_not_after", stored.NotAfter.UTC().Format(time.RFC3339))
}

// storedMaterialRevoked reports whether the certificate in certPEM is on this
// CA's CRL.
//
// Fails toward "not revoked", which is the safe direction *here* and only here:
// the answer is used to decide whether to replace a certificate, and a false
// negative costs one deferred reissue that the renew window will make anyway,
// while a false positive would reissue on every pass for as long as the CRL is
// unreadable. This is not an authentication decision and must not be reused as
// one -- refuseIfRevoked, which is, fails closed.
func (c *CA) storedMaterialRevoked(ctx context.Context, certPEM []byte, subject string) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	revoked, err := c.IsRevokedSerial(ctx, leaf.SerialNumber)
	if err != nil {
		slog.Warn("Could not check the stored managed certificate against the CRL; "+
			"treating it as not revoked for this pass",
			"subject", subject, "error", err)
		return false
	}
	return revoked
}

// issueManagedUnderSubjectLock generates a key, signs a certificate for m's spec, writes
// the pair to m's store, and retires the predecessor. The caller must hold
// subject's lock and must NOT hold c.mu.
//
// The key is generated here and dropped when this returns. It is written to m's
// store and to nowhere else: not to the backing store, and not to the local
// cadir either. That is why RetainPrivateKeyInStorage has no equivalent on this
// path -- there is nothing to opt out of.
func (c *CA) issueManagedUnderSubjectLock(ctx context.Context, m ManagedCert, reason issueReason,
	current *x509.Certificate, storedKeyPEM []byte) (bool, error) {
	subject := m.Spec.Subject

	// The predecessor's bytes, kept so the CA's record can be put back if the
	// store write fails after issueLeafLocked has already replaced it.
	var currentPEM []byte
	if current != nil {
		currentPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: current.Raw})
	}

	// CPU-bound and touching no shared state, so outside c.mu -- but inside the
	// subject lock, unlike GenerateWithOptions, because the key must not exist
	// before this replica has established that it is the one issuing.
	key, err := c.issuanceKeyFor(m, reason, current, storedKeyPEM)
	if err != nil {
		return false, err
	}
	keyPEM, err := marshalPrivateKeyPEM(key)
	if err != nil {
		return false, fmt.Errorf("marshalling the key for %s: %w", subject, err)
	}

	certPEM, err := func() ([]byte, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.issueLeafLocked(ctx, subject,
			pkix.Name{CommonName: subject}, key.Public(),
			subjectAltNames{
				DNSNames:       m.Spec.DNSNames,
				IPAddresses:    m.Spec.IPAddresses,
				EmailAddresses: m.Spec.EmailAddresses,
				URIs:           m.Spec.URIs,
			}, nil,
			m.Spec.ExtKeyUsage, m.Spec.TTL)
	}()
	if err != nil {
		return false, fmt.Errorf("signing a certificate for %s: %w", subject, err)
	}

	// The serial of what we just signed, for the rollback below. Read from the
	// PEM rather than plumbed out of issueLeafLocked so the rollback revokes
	// the bytes that were actually produced.
	newSerial, err := certSerialFromPEM(certPEM)
	if err != nil {
		// Unreachable for bytes issueLeafLocked just signed, and there is
		// nothing useful to do about it: the certificate exists either way.
		slog.Warn("Could not read the serial of a just-issued managed certificate; "+
			"a store write failure will not be able to revoke it",
			"subject", subject, "error", err)
	}

	if err := m.Save(ctx, certPEM, keyPEM); err != nil {
		// Nothing ever saw this key: it was generated in this call, under this
		// lock, and the store refused it. So the certificate is revoked
		// immediately rather than superseded with a delay -- a window exists to
		// let relying parties pick up a replacement, and there are none. The
		// predecessor is left exactly as it was, still valid and still in the
		// store, and the next pass retries.
		if newSerial != "" {
			// Its own budget, detached from the pass's. The likeliest reason a
			// store write fails is that it hung, and by then the deadline this
			// pass started with is spent -- so a rollback sharing it would find
			// the context already done, fail to take the CRL lock, and leave
			// exactly the orphan it exists to prevent. The same reasoning, and
			// the same shape, as CleanupExpiredCerts and the superseded
			// write-back.
			revokeCtx, cancelRevoke := context.WithTimeout(
				context.WithoutCancel(ctx), LockTimeout/2)
			defer cancelRevoke()
			// Deliberately not withCRLLockCounted, matching Clean: the failures
			// inside this closure are already counted by revokeSerialLocked and
			// signCRLLocked, so wrapping would add only the arm where the lock
			// could not be taken at all. docs/metrics.md names this path as
			// uncounted on the lock arm.
			if rerr := c.Storage.WithLock(revokeCtx, lockNameCRL, func() error {
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.revokeSerialLocked(revokeCtx, newSerial)
			}); rerr != nil {
				// Counted by revokeSerialLocked and signCRLLocked where it
				// reached them. Say plainly what is left behind: a live
				// certificate whose key is gone, which nothing else will
				// retire before it expires.
				slog.Error("A managed certificate could not be stored and could not then be revoked; "+
					"it is live until it expires",
					"subject", subject, "serial", newSerial, "error", rerr)
			}
		}
		// Put the CA's own record back. issueLeafLocked overwrote cert/<subject>
		// before the store was asked, so it now names the revoked orphan while
		// the certificate actually in service is the predecessor still sitting
		// in the entry's store.
		//
		// What this restores, precisely: the blob every reader of
		// cert/<subject> consults -- certificate status, IsRevoked, and the
		// next pass's displacement check. What it does NOT restore is
		// `revoke --certname`, which resolves through the inventory
		// (LatestSerialForSubject), whose newest row still names the orphan
		// because issueLeafLocked appended it before the store was asked. So
		// the predecessor's serial is logged unconditionally below, alongside
		// the remedy that does reach it.
		//
		// Only when the predecessor is ours. On the not-ours arm `current` is a
		// certificate this CA did not issue, and installing that in the CA's own
		// certificate store would leave it serving material of unknown
		// provenance with no inventory row -- which evictRevokedLocked would
		// then read as ErrCertExists for ever, since a foreign serial can never
		// reach this CA's CRL.
		//
		// Its own deadline, for the reason the revocation above gives: the
		// likeliest cause of a failed store write is that it hung, and a repair
		// sharing the spent budget cannot run in the one case it exists for.
		if current != nil && reason != reasonNotOurs {
			restoreCtx, cancelRestore := context.WithTimeout(
				context.WithoutCancel(ctx), LockTimeout/2)
			defer cancelRestore()
			if serr := c.Storage.SaveCert(restoreCtx, subject, currentPEM); serr != nil {
				slog.Error("A managed certificate could not be stored, and the CA's own record "+
					"could not be put back; it now names a revoked certificate while the "+
					"predecessor is still live",
					"subject", subject, "predecessor_serial", serialHexStr(current.SerialNumber),
					"error", serr)
			}
		}
		// Reported on every arm where a predecessor exists, including the one
		// where the restore succeeded: that is the arm with no other trace of
		// its serial, and it is the serial an operator needs, because by-name
		// revocation resolves to the orphan instead.
		//
		// The remedy differs by provenance. A predecessor this CA issued can be
		// retired by serial; one it did not has no inventory row, so
		// RevokeSerial answers ErrSerialUnknown, which force does not override.
		// Offering that command there would send the operator at a refusal.
		switch {
		case current != nil && reason == reasonNotOurs:
			slog.Warn("A managed certificate could not be stored; the predecessor remains in "+
				"service, and this CA did not issue it, so it cannot be revoked here. "+
				"Retire it wherever it was issued, or remove it from the entry's store",
				"subject", subject, "predecessor_serial", serialHexStr(current.SerialNumber))
		case current != nil:
			slog.Warn("A managed certificate could not be stored; the predecessor remains in "+
				"service and by-name revocation will not reach it. Retire it with "+
				"'openvox-ca-ctl revoke --serial <hex>' if it must go",
				"subject", subject, "predecessor_serial", serialHexStr(current.SerialNumber))
		}
		return false, fmt.Errorf("writing the material for %s to its store: %w", subject, err)
	}

	// Retire the predecessor -- the certificate the entry's own store held --
	// now that its replacement is signed AND stored. This is the only
	// certificate this path retires; one the CA held that the entry could not
	// account for is reported by warnIfDisplacingUnderSubjectLock and left alone.
	//
	// Only when we have one that is ours and not already revoked. A foreign
	// certificate's serial must never reach our CRL -- it identifies a
	// different certificate under a different issuer -- and an already-revoked
	// one needs nothing further. Best effort in every case: the replacement is
	// written and a failure here must not undo it.
	if current != nil && reason != reasonNotOurs && reason != reasonRevoked {
		oldSerial := serialHexStr(current.SerialNumber)
		// Its own budget too, and for the same reason: by this point the pass
		// has spent its deadline on a load, a key generation, a signature and a
		// store write, and a retirement that cannot be recorded is one nothing
		// retries -- the next pass finds the new certificate current.
		supersedeCtx, cancelSupersede := context.WithTimeout(
			context.WithoutCancel(ctx), LockTimeout/2)
		defer cancelSupersede()
		if err := c.supersedeReplacedAfter(supersedeCtx, subject, oldSerial,
			c.supersedeAfterFor(m.Spec)); err != nil {
			// Counted already -- crlUpdateFailures on the immediate path,
			// supersedeFailures on the delayed one.
			//
			// The wording is the documented one, deliberately: docs/metrics.md
			// tells an operator responding to PuppetCASupersedeFailing to grep
			// for "failed to retire replaced certificate" and retire what it
			// names by serial. Renew and AutoRenew emit that string; a third
			// caller phrasing it differently is a path the runbook silently
			// misses.
			slog.Warn("ReconcileManaged: failed to retire replaced certificate",
				"subject", subject, "serial", oldSerial, "error", err)
		}
	}
	return true, nil
}

// issuanceKeyFor returns the key this issuance signs against: the one already in
// the entry's store when ReuseKey asks for it, and a freshly generated one
// otherwise.
//
// Falling back to generating is right on exactly one arm — there is nothing to
// reuse. On a first issuance the store is empty by definition, so an entry with
// ReuseKey set still has to start somewhere, and that is not worth a warning.
//
// A key that is present but will not parse is a different matter and is said
// out loud: the operator asked for this certificate's key to be pinned, and it
// is about to stop being the key it was. Generating anyway is still the right
// action -- refusing would leave the certificate to expire over a key nobody
// can use -- but silently is not.
//
// A reused key that is below the CA's key-strength policy is refused, not
// quietly replaced. issueLeafLocked runs validatePublicKey over whatever public
// key it is handed, so the refusal needs no code here; the effect is that such
// an entry fails every pass until the operator fixes it. That is the right way
// round: silently re-keying would defeat the pin the setting exists to provide,
// and a pin the CA abandons without saying so is worse than one it refuses.
//
// # Revocation outranks the pin
//
// A revoked certificate is replaced with a NEW key, whatever ReuseKey says.
// Reissuing over the same key would hand back, with a fresh serial and a full
// lifetime, exactly the material an operator revoking for key disclosure was
// trying to retire -- and no CRL would list the replacement. That is the hazard
// refuseIfSuperseded closes on the two renewal paths; this path reaches it by a
// different door and has to close it too. The pin loses, loudly: a revocation
// is a deliberate act and the operator needs telling that it broke the pin.
func (c *CA) issuanceKeyFor(m ManagedCert, reason issueReason, current *x509.Certificate,
	storedKeyPEM []byte) (crypto.Signer, error) {
	subject := m.Spec.Subject
	switch {
	case !m.Spec.ReuseKey:
		// Nothing to say: re-keying every renewal is the default.
	case reason == reasonRevoked:
		slog.Warn("Not reusing the stored private key for a managed certificate: its "+
			"certificate was revoked, and reissuing over the same key would return the "+
			"material the revocation retired. Generating a new one, which breaks any "+
			"pin on the old key",
			"subject", subject)
	case len(storedKeyPEM) == 0 && current == nil:
		// A first issuance has an empty store by definition. Nothing was
		// pinned yet, so there is nothing to report.
	case len(storedKeyPEM) == 0:
		// A certificate with no key beside it -- a pass that died between
		// signing and the store write. Not a first issuance, so a pin really
		// is being broken.
		slog.Warn("Cannot reuse the stored private key for a managed certificate: the "+
			"store holds a certificate but no key. Generating a new one, which breaks "+
			"any pin on the old key",
			"subject", subject)
	default:
		block, _ := pem.Decode(storedKeyPEM)
		if block == nil {
			slog.Warn("Cannot reuse the stored private key for a managed certificate: "+
				"it is not PEM. Generating a new one, which breaks any pin on the old key",
				"subject", subject)
		} else if key, err := parsePrivateKeyDER(block.Type, block.Bytes); err != nil {
			slog.Warn("Cannot reuse the stored private key for a managed certificate. "+
				"Generating a new one, which breaks any pin on the old key",
				"subject", subject, "error", err)
		} else {
			slog.Debug("Reissuing a managed certificate against its existing key",
				"subject", subject)
			return key, nil
		}
	}

	key, err := generateKey(c.keyConfigFor(m.Spec))
	if err != nil {
		return nil, fmt.Errorf("generating a key for %s: %w", subject, err)
	}
	return key, nil
}

// certSerialFromPEM returns the canonical serial of the first certificate in
// certPEM, in the same form serialHexStr produces everywhere else -- which is
// what revokeSerialLocked and the pending-supersession list both compare
// against.
func certSerialFromPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return serialHexStr(cert.SerialNumber), nil
}
