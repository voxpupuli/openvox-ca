// Copyright (C) 2026 Trevor Vaughan
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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// Revoke serialises on the per-subject lock and then the cluster-wide "crl"
// lock, so a revocation neither overlaps an issuance for the same subject nor
// races another replica's CRL read-modify-write — two revocations that both
// read the same CRL and each append their own entry would clobber one another.
//
// It takes the per-subject lock first, as Clean does. Without it the renewal
// paths' re-check would still be a check-then-act: a revocation resolving the
// outgoing serial while the replacement is being minted is defeated exactly as
// one landing during the lock wait is, only over a shorter window. Holding the
// subject lock leaves a revocation two orderings against a renewal for the same
// subject, and both are answers rather than races — it commits first and the
// re-check refuses the renewal, or the renewal completes and the revocation
// then retires the serial that renewal issued.
//
// The second ordering leaves the agent nothing usable only where the renewal
// retired the certificate it replaced, because this retires the subject's
// latest serial and no other. That is the default rather than a guarantee:
// under revoke_on_auto_renew=false AutoRenew keeps the predecessor
// deliberately, and on both paths the post-issue revoke is best-effort and only
// warns when it fails. A predecessor left behind stays valid for its own key
// and still authenticates, since admission tests the serial presented rather
// than whatever certificate is on disk. Retiring every unexpired serial a
// subject holds would close that; it is a change to what revocation means, not
// to when it happens, so it is not this one's business.
//
// One class of predecessor *is* this one's business, and revokeLocked retires
// it: one that superseded_cert_revoke_after_sec has put on the pending list.
// Those are already scheduled for revocation by this CA's own decision, so
// bringing that forward when the subject is revoked changes only when it lands.
// Without it a window would make the gap above the common case rather than the
// exception — every recent renewal would leave a live predecessor — and
// `revoke --certname` would quietly stop being containment. See
// retireSupersededForSubjectLocked.
//
// The cost is that a revocation now waits for an issuance already under way for
// that subject — the same trade Clean has always made, so DELETE
// /certificate_status has always paid it. Do not read that wait as short: a
// renewal holds the subject lock across its own acquisition of the cluster-wide
// CRL lock, and SaveRequest holds it across an autosign signature. Nor does
// LockTimeout bound it in the case that matters most, since WithLock's ctx
// covers only the other-process half of an acquisition (see its godoc).
//
// It does not bound that wait, but it is spent by it, so a wait longer than
// LockTimeout ends in a failure rather than a late commit — on every backend,
// just in two different places. Where there is a cross-node acquisition the
// revocation is rejected there, before any of the work below. Where there is
// not (SQLite, the filesystem) the lock is granted after the wait with the
// deadline already gone, so the first storage read in revokeLocked fails
// instead — and that one is counted into crlUpdateFailures, unlike the other,
// because a spent deadline is not fs.ErrNotExist. Those backends have one
// acquisition that can reject a spent deadline: a wait for another *process* on
// the host, which since #187 they coordinate with an flock. That refusal lands
// with the cross-node case, ahead of any CRL work, and is likewise uncounted. A revocation that fails is
// safe to retry either way: revokeSerialLocked short-circuits a serial already
// listed, so revocation is idempotent.
//
// Every issuance path waits on this lock, Generate included: GenerateWithOptions
// takes subject:<name> across its whole evict-and-issue sequence, so a
// server-side key generation on another replica is serialised against a
// revocation here rather than racing it. That closed issue #195, which this
// comment used to describe as the standing exception.
//
// Lock ordering: subject-lock (distributed) → CRL-lock (distributed) → c.mu,
// matching Clean, and no path takes those two in the other order. Callers must
// therefore not already hold the subject lock: those that do — Clean, the
// post-issue revokes in Renew and AutoRenew, and GenerateWithOptions' revoke of
// the certificate it replaces — reach revokeLocked or revokeSerialLocked
// directly rather than coming through here.
func (c *CA) Revoke(ctx context.Context, subject string) error {
	if err := ValidateSubject(subject); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	// Both properties, from two branches that changed this call independently:
	// the subject lock outside the CRL lock, so a revoke cannot interleave with
	// a sign or a clean for the same name; and the CRL acquisition counted, so
	// a revocation an operator asked for that never took the lock moves
	// crl_update_failures rather than failing silently.
	// unknownCause is declared out here, not inside the closures, so the
	// diagnostic is emitted once every lock is released -- c.mu, and both of
	// the cluster-wide names above it. See logUnknownSubjectCause.
	var unknownCause error
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		return c.withCRLLockCounted(ctx, func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.revokeLocked(ctx, subject, &unknownCause)
		})
	})
	logUnknownSubjectCause(subject, unknownCause)
	return err
}

// ErrSubjectUnknown is returned by Revoke for a subject the inventory has no
// entry for.
//
// The by-subject counterpart to ErrSerialUnknown, and a sentinel for the same
// reason: absence has to be distinguishable from failure at the API boundary,
// which answers it 404 rather than 409. It cannot be left to the caller to
// recognise fs.ErrNotExist, because every Backend.Get wraps that when a key is
// absent, so a missing CRL blob reaches the same caller carrying the same
// error — and a CA that has lost its CRL must not report the subject as
// unknown. This value is the one place that distinction is recorded.
//
// Worded for what was observed rather than for what it usually implies. The
// common case is a subject that was never issued, but Clean reaches this same
// branch through revokeLocked with a certificate in storage (see the hasCert
// arm in signing.go), and emits this text into an operator warning about
// deleting that certificate. "No certificate has been issued" would be false
// there. A blob backend can reach it without an issuance history too, when the
// inventory has gone missing along with its integrity MAC: that is
// indistinguishable here from an absent entry in a readable inventory. (With
// the MAC still present the missing blob fails verification instead and leaves
// by a different, counted branch, so it is the pair going together that lands
// here.) So the message does not claim an issuance history the CA cannot see.
var ErrSubjectUnknown = errors.New("no inventory entry for this subject")

// logUnknownSubjectCause emits the diagnostic revokeLocked deliberately does
// not wrap into its returned error, because that error reaches an HTTP response
// body and the cause can name a storage path.
//
// Callers MUST invoke this after releasing c.mu, which is the whole reason it
// is a separate function rather than a line inside revokeLocked. Verbosity 0
// maps to LevelInfo, so this record always writes — and writing it under c.mu
// would make the most common failure of the revoke endpoint, a mistyped
// certname, a process-wide serialisation point for every c.mu.RLock reader,
// including the IsRevokedSerial call on the authentication path. That is #197's
// finding about the OCSP responder (see the comment in ocsp.go), reached by a
// different route: there the expensive thing under the lock was a signature,
// here it is an io.Writer nobody can bound.
//
// A no-op when cause is nil, so callers need not branch.
func logUnknownSubjectCause(subject string, cause error) {
	if cause == nil {
		return
	}
	slog.Info("No inventory entry for subject; revocation cannot proceed",
		"subject", subject, "error", cause)
}

// revokeLocked performs the actual CRL read-modify-write. The cluster CRL
// lock and c.mu must both be held by the caller.
//
// unknownCause is an out-parameter, set only when the subject has no inventory
// entry, and carries the storage error behind ErrSubjectUnknown so the caller
// can log it once c.mu is released — see logUnknownSubjectCause. Both callers
// pass a pointer; it is not optional.
func (c *CA) revokeLocked(ctx context.Context, subject string, unknownCause *error) error {
	slog.Debug("Revoking certificate", "subject", subject)

	// Ahead of the subject's own serial, and best-effort. Any predecessor
	// inside its overlap window is a second working credential for this
	// subject, and containment means retiring it too — see
	// retireSupersededForSubjectLocked. Doing it first means a subject whose
	// inventory lookup below fails still loses its superseded credentials
	// rather than none of them; each of these needs only the CRL, which is
	// already locked.
	c.retireSupersededForSubjectLocked(ctx, subject)

	serialStr, err := c.findSerialForSubject(ctx, subject)
	if err != nil {
		// A read failure is counted; a subject that was simply never issued is
		// not. The metric's documented meaning is "a revocation that could not be
		// recorded", and an inventory read that fails is one. On the blob backend
		// (filesystem) that includes an HMAC verification failure -- a tamper
		// signal -- since the read goes through ReadInventory; the structured
		// backends (SQL, etcd, redis) answer from an indexed lookup, which
		// verifies nothing, so there the counted cases are connection and query
		// failures. An *absent* inventory reaches fs.ErrNotExist, and is
		// returned as ErrSubjectUnknown rather than counted, only under the
		// conditions ErrSubjectUnknown's godoc sets out; on a blob backend with
		// the integrity MAC still present the read fails verification instead
		// and is counted by the sentence above. It matters
		// because Clean swallows this error and deletes anyway, so without the
		// increment a clean silently became delete-without-revoke with one WARN
		// line and a flat counter, leaving the alert the mixin ships unable to
		// fire. Not-found is excluded deliberately: a typo'd certname would
		// otherwise page someone.
		// Both the blob and the SQL inventory report a missing subject by
		// wrapping fs.ErrNotExist, so one check covers every backend.
		//
		// Converted to ErrSubjectUnknown here rather than passed through,
		// exactly as revokeSerialCheckedLocked does with ErrSerialUnknown.
		// What this frame knows, and no caller downstream can recover, is
		// *which read* produced the fs.ErrNotExist: the inventory lookup above,
		// rather than one of the CRL reads that follow. Both wrap the same
		// sentinel, so an errors.Is further out would conflate a subject the
		// inventory does not list with a CA that has lost its CRL. It does not
		// distinguish an absent entry from an absent inventory — see
		// ErrSubjectUnknown's godoc, which is why the message does not claim
		// one. The counter split is unchanged: a subject the inventory does not
		// list is not a CRL update failure, so this arm still does not
		// increment.
		if errors.Is(err, fs.ErrNotExist) {
			// Log the cause rather than wrap it: the returned value reaches an
			// HTTP response body, and the underlying error names a storage
			// path. The security reason applies to the response, not to the
			// log, so the cause is logged here instead of being lost -- before
			// this sentinel existed it travelled inside the returned error and
			// reached the WARN both callers already emit (the handler's "Revoke
			// failed" and Clean's "deleting the certificate anyway"). This arm
			// moves no counter and now answers 404, so without a default-level
			// line a lost inventory would be invisible in production: every
			// revoke would report the subject absent and nothing would say why.
			//
			// Info, not Warn, and the level is the whole argument. Verbosity 0
			// maps to LevelInfo, so this is in production logs either way; what
			// Warn would add is a second WARN for every mistyped certname,
			// beside the one each caller already emits, for a client error the
			// API now answers 404. What the line adds over the caller's is the
			// cause, and that is worth something only on a blob backend: there
			// a lost inventory is a real *fs.PathError naming the file, while
			// an unlisted subject is synthesised by latestSerialFromBlob and
			// names no path. The structured backends answer from an index that
			// verifies nothing and synthesise *fs.PathError for both, with Path
			// set to the subject, so the two states are indistinguishable there
			// -- which is also why the level cannot be chosen per case, since
			// errors.As sees the same type either way. docs/api.md says as much
			// to operators, and sends them to the certificate index instead.
			//
			// Handed to the caller rather than logged here: this runs under
			// c.mu, and the record always writes at the shipped verbosity. See
			// logUnknownSubjectCause for why that matters on this arm in
			// particular.
			*unknownCause = err
			return fmt.Errorf("%w: %s", ErrSubjectUnknown, subject)
		}
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("could not find certificate for subject %s: %w", subject, err)
	}

	if err := c.revokeSerialLocked(ctx, serialStr); err != nil {
		// Name the serial. Clean logs this error and deletes the certificate
		// anyway, so this is often the last place the serial of a certificate
		// that is still a valid credential is recorded — and it is what
		// RevokeSerial needs to retire it once the cause is fixed.
		return fmt.Errorf("revoking serial %s for subject %s: %w", serialStr, subject, err)
	}

	slog.Debug("Certificate revoked", "subject", subject, "serial", serialStr)
	return nil
}

// ErrSerialUnknown is returned by RevokeSerial for a serial no inventory entry
// carries. It is deliberately not overridable by force: a serial this CA has no
// record of issuing cannot be cleaned out of the CRL again, because
// CleanupExpiredCerts drops CRL entries only for serials it finds in the
// inventory. Admitting one would grow the CRL — served to every agent — by an
// entry with no expiry, forever.
var ErrSerialUnknown = errors.New("serial number not found in inventory")

// ErrSerialIsCurrent is returned by RevokeSerial when the serial is the one on
// the certificate currently stored for its subject — the live credential. That
// is the case revoke --certname already covers, so reaching it by serial is far
// more likely a mistyped digit than an intent, and the consequence (a working
// node loses its certificate) is the expensive direction to be wrong in.
var ErrSerialIsCurrent = errors.New("serial belongs to the certificate currently in use")

// ErrSerialStateUnknown is returned by RevokeSerial when the certificate stored
// for the serial's subject cannot be read, so it cannot be shown that revoking
// the serial would not take a working credential out of circulation.
//
// It is separate from ErrSerialIsCurrent because the remedy differs and the
// operator cannot tell them apart otherwise: this one may clear on its own once
// storage is healthy, and forcing past it revokes without the guard ever having
// run. It carries no wrapped storage error — those name paths, and this value
// reaches the API response.
var ErrSerialStateUnknown = errors.New("cannot determine whether the serial is the certificate currently in use")

// RevokeSerial revokes one specific serial number, rather than whatever serial
// is currently newest for a subject.
//
// Revocation is otherwise only ever by subject: Revoke resolves through
// findSerialForSubject, which answers with the *latest* serial issued for that
// name. That leaves a superseded certificate unreachable once a replacement has
// been issued — the state a failed supersession record leaves behind — since
// asking to revoke the subject now takes the working certificate out of
// circulation and leaves the superseded one valid.
//
// force overrides the two live-certificate guards, and nothing else:
// ErrSerialIsCurrent, where the serial is demonstrably the one in circulation,
// and the fail-closed ErrSerialStateUnknown, where that could not be determined
// at all. It is the escape hatch for deliberately retiring a live certificate by
// serial — a compromise where the operator has the serial in hand and not the
// name. It does NOT admit a serial this CA never issued: ErrSerialUnknown is
// refused with or without it, for the reason given on that sentinel.
//
// Locking is the cluster-wide "crl" lock, then c.mu, so concurrent revocations
// on different replicas cannot clobber one another's CRL write. Revoke takes a
// per-subject lock outside that, which a revocation by serial has no subject to
// take: the serial is the identifier here precisely because the name resolves
// to a different certificate.
//
// The CRL lock goes through withCRLLockCounted, like every other revocation an
// operator asked for. The three sites in signing.go that take it directly say
// "deliberately not withCRLLockCounted" and justify it on exactly that
// distinction -- they are best-effort revocations inside an operation that has
// already succeeded, so a contended lock there is not a revocation that did not
// happen. This one is: it is the openvox-ca-ctl revoke --serial path, and the
// only way to retire a superseded certificate, which docs/api.md sends the
// operator here to do. A lock it could not take must move crl_update_failures
// rather than reaching a log line and nothing else.
func (c *CA) RevokeSerial(ctx context.Context, serial string, force bool) error {
	normalised, err := storage.NormaliseSerial(serial)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	return c.withCRLLockCounted(ctx, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.revokeSerialCheckedLocked(ctx, normalised, force)
	})
}

// revokeSerialCheckedLocked is RevokeSerial's body: resolve the serial to a
// subject, refuse the live certificate unless forced, then revoke. serial must
// already be normalised. The cluster CRL lock and c.mu must both be held.
func (c *CA) revokeSerialCheckedLocked(ctx context.Context, serial string, force bool) error {
	subject, err := c.Storage.SubjectForSerial(ctx, serial)
	if err != nil {
		// Same split as revokeLocked: a serial that was simply never issued is
		// operator error and is not counted, but an inventory read that *failed*
		// is a revocation that could not be recorded, which is what
		// crlUpdateFailures means. On a blob backend that includes an HMAC
		// verification failure — a tamper signal — because SubjectForSerial
		// verifies before scanning, as its by-subject twin does.
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %s", ErrSerialUnknown, serial)
		}
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("looking up serial %s in inventory: %w", serial, err)
	}

	live, err := c.storedCertSerial(ctx, subject)
	switch {
	case err != nil:
		// Fail closed. The question this answers is "would revoking this serial
		// take a working credential out of circulation", and an unreadable
		// certificate is precisely the case where we cannot say it would not.
		// Deleted material reaches fs.ErrNotExist and is handled below; anything
		// else is an I/O or parse failure, and treating that as "not live" would
		// let the guard evaporate exactly when storage is unhealthy.
		if !errors.Is(err, fs.ErrNotExist) {
			if !force {
				// The underlying error names a storage path, and this value is
				// rendered into the API response, so it is logged rather than
				// wrapped. The message still has to be actionable on its own.
				slog.Warn("Refusing to revoke by serial: the stored certificate could not be read",
					"serial", serial, "subject", subject, "error", err)
				// Worded for both audiences: this reaches an HTTP response as
				// well as the CLI, so it names the operation and mentions the
				// flag only as a parenthetical, rather than telling an API
				// caller to pass a flag that is not in the contract.
				return fmt.Errorf("%w: the certificate stored for %s could not be read, so it cannot be "+
					"shown that serial %s is not the one in use; retry once storage is healthy, or repeat "+
					"the request with force set to revoke it without that check "+
					"(openvox-ca-ctl: --force). See the server log for the cause",
					ErrSerialStateUnknown, subject, serial)
			}
			slog.Warn("Revoking by serial without confirming the stored certificate",
				"serial", serial, "subject", subject, "error", err)
		}
	case live == serial && !force:
		// As above: the same string is rendered into an HTTP response body and
		// printed by the CLI, so the remedy is named as an operation first.
		return fmt.Errorf("%w: %s is the certificate stored for %s; revoke that subject by name "+
			"instead, or repeat the request with force set to revoke it by serial anyway "+
			"(openvox-ca-ctl: --certname %s, or --force)",
			ErrSerialIsCurrent, serial, subject, subject)
	case live == serial:
		slog.Warn("Revoking the certificate currently stored for a subject, by serial and forced",
			"serial", serial, "subject", subject)
	}

	slog.Debug("Revoking certificate by serial", "serial", serial, "subject", subject, "force", force)
	if err := c.revokeSerialLocked(ctx, serial); err != nil {
		return err
	}
	// force is on the durable record, not only the Debug line: it is the
	// difference between a revocation the guards cleared and one that overrode
	// them, and for a subject with no stored certificate the guard is a silent
	// no-op, so nothing else in the log would distinguish the two.
	slog.Info("Certificate revoked by serial", "serial", serial, "subject", subject, "force", force)
	return nil
}

// storedCertSerial returns the normalised serial of the certificate currently
// stored for subject, wrapping fs.ErrNotExist when no certificate is stored.
//
// It reads the stored certificate rather than asking LatestSerialForSubject
// because the two answer different questions. The inventory's newest row for a
// subject is the newest *issuance*; the stored certificate is the credential in
// circulation. They diverge after a clean (the inventory rows outlive the
// deleted blob) and while an issuance is only partly complete, and it is the
// second that this guard is about.
func (c *CA) storedCertSerial(ctx context.Context, subject string) (string, error) {
	certPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("stored certificate for %s is not valid PEM", subject)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing stored certificate for %s: %w", subject, err)
	}
	return serialHexStr(cert.SerialNumber), nil
}

// revokeSerialLocked adds serialStr to the CRL, unless it is already present.
// The cluster CRL lock and c.mu must both be held by the caller.
//
// This is split out from revokeLocked so Renew and AutoRenew can revoke the
// exact serial of the certificate they are replacing. By the time either
// wants to revoke, issueLeafLocked has already appended the new cert's row
// to the inventory, so findSerialForSubject (latest-issued-for-subject) would
// resolve to the new serial rather than the one being retired.
func (c *CA) revokeSerialLocked(ctx context.Context, serialStr string) error {
	serialInt := new(big.Int)
	if _, ok := serialInt.SetString(serialStr, 16); !ok {
		c.crlUpdateFailures.Add(1)
		return fmt.Errorf("malformed serial %q", serialStr)
	}

	// 1. Load CRL. readStoredCRL counts its own failures now, so this path must
	// not add a second increment for the same event.
	stored, err := c.readStoredCRL(ctx)
	if err != nil {
		return err
	}

	// 2. Check for duplicate revocation: a serial that's already in the CRL
	// should not be appended again (prevents unbounded CRL growth on retries).
	for _, entry := range stored.own.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serialInt) == 0 {
			slog.Debug("Certificate already revoked", "serial", serialStr)
			// Still project the state into the certificate index: a retried
			// revocation may be exactly the case where the CRL write landed
			// but the index update did not.
			c.markCertRevokedIndex(ctx, serialStr, entry.RevocationTime)
			return nil
		}
	}

	// 3. Append the new entry and re-sign. signCRLLocked counts its own
	// sign/write failures into crlUpdateFailures, so this path does not
	// double-count them.
	newRevoked := x509.RevocationListEntry{
		SerialNumber:   serialInt,
		RevocationTime: time.Now(),
	}

	revokedCerts := stored.own.RevokedCertificateEntries
	revokedCerts = append(revokedCerts, newRevoked)

	if err := c.signCRLLocked(ctx, stored, revokedCerts); err != nil {
		return err
	}

	// Project the revocation into the certificate index. The signed CRL just
	// written is the source of truth; the index column is a display cache of
	// it, so a failure here is logged, not propagated — the revocation has
	// already happened, and the startup index repair reconverges the column.
	c.markCertRevokedIndex(ctx, serialStr, newRevoked.RevocationTime)

	// Invalidate the cached OCSP response for this serial so the next query
	// returns the correct Revoked status instead of a stale Good response.
	// Use the same normalised key as the OCSP index (uppercase hex, no padding).
	delete(c.ocspCache, serialHexStr(serialInt))

	return nil
}

// markCertRevokedIndex is the log-and-continue wrapper around
// StorageService.MarkCertRevoked used by the revocation paths.
func (c *CA) markCertRevokedIndex(ctx context.Context, serialStr string, at time.Time) {
	if err := c.Storage.MarkCertRevoked(ctx, serialStr, at); err != nil {
		slog.Warn("Failed to project revocation into certificate index",
			"serial", serialStr, "error", err)
	}
}

// findSerialForSubject returns the most-recently issued serial for subject.
// It delegates to storage, which uses an indexed lookup on structured backends
// and a verified blob scan otherwise.
func (c *CA) findSerialForSubject(ctx context.Context, subject string) (string, error) {
	return c.Storage.LatestSerialForSubject(ctx, subject)
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
	return serialInCRL(c.cachedCRL, serial), nil
}

// serialInCRL reports whether serial appears among crl's revoked entries. The
// one definition of "is this certificate revoked according to this CRL" for
// every caller that needs only the yes or no — against the cached CRL or one
// freshly read from storage.
//
// Two callers deliberately keep their own loop, because a bool cannot carry
// what they need from the matched entry: ocsp.go's decideOCSPStatus wants the
// RevocationTime for the OCSP response, and revokeSerialLocked wants it to
// project into the certificate index. Change the predicate here and check
// those two.
//
// crl may not be nil; every caller guards that first, since a missing CRL is
// not "nothing is revoked" and each has its own answer for it.
func serialInCRL(crl *x509.RevocationList, serial *big.Int) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
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

	return serialInCRL(crl, cert.SerialNumber)
}
