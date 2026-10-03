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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"sort"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// supersededEntry records one certificate that a renewal has replaced and that
// is to be revoked once its delay has elapsed.
//
// Subject is functional, not decorative: retireSupersededForSubjectLocked matches
// on it by exact string equality, so it is the sole key by which
// `revoke --certname` and DELETE /certificate_status find a subject's in-window
// predecessors. It must therefore be the same validated subject string Revoke
// will be called with. An entry carrying anything else — a differently-spelled
// name from a future consumer, or the empty string a partly-decodable list can
// yield — is skipped by that lookup and stays a working credential until the
// sweep retires it.
//
// Revocation itself is always by Serial, which is a separate point: Revoke
// resolves a subject to its *current* certificate, so revoking by subject here
// would retire the replacement rather than the thing it replaced.
type supersededEntry struct {
	Serial   string    `json:"serial"`
	Subject  string    `json:"subject"`
	RevokeAt time.Time `json:"revoke_at"`
}

// ErrCertSuperseded is returned by the renewal paths when the certificate
// presented for renewal is one a previous renewal already replaced and that is
// waiting out its overlap window.
//
// It wraps ErrCertRevoked rather than standing alone, so every caller that
// already refuses a revoked certificate refuses this one too without being
// changed — and a future one gets that behaviour by default. That is the
// fail-safe direction: a superseded certificate is one this CA has already
// decided to revoke, and the window is a grace period for relying parties, not
// a reprieve for the credential itself.
var ErrCertSuperseded = fmt.Errorf("%w: superseded and awaiting revocation", ErrCertRevoked)

// refuseIfSuperseded refuses a renewal presented with a certificate that is on
// the pending-supersession list.
//
// Without this the window would not bound the exposure it advertises, it would
// end it. A superseded certificate is not on the CRL — that is the whole point
// of the delay — so nothing else on the renewal path turns it away, and neither
// path requires the presented certificate to be the one currently stored for
// the subject. A holder of the replaced credential could therefore present it,
// be issued a fresh full-lifetime successor with every authorisation OID
// carried forward, and walk out of the window entirely. On the CSR-body path
// that holder is whoever has the *previous* private key, which after a re-key is
// exactly the party the renewal was meant to cut out; and on that path the
// successor's issuance also schedules the legitimate current certificate for
// revocation, because Renew retires the subject's latest serial rather than the
// one presented.
//
// Before delayed supersession existed the synchronous revoke closed all of
// this: the predecessor was on the CRL by the time its replacement was stored.
// This restores that property.
//
// It fails closed. A list that cannot be read is treated as a refusal, matching
// how IsRevokedSerial's error is treated a few lines above — there is no cached
// copy to fall back on, and admitting a renewal here is the one decision that
// cannot be walked back later. The cost is that a store whose superseded key
// alone is unreadable refuses renewals while the rest of the CA keeps serving;
// that is loud (counted into supersedeFailures, so PuppetCASupersedeFailing
// fires) and the remedy is in docs/storage-backends.md. An *absent* list is not
// a failure — it is the steady state of every CA that has never enabled a
// window, and it is the common case this stays cheap for.
func (c *CA) refuseIfSuperseded(ctx context.Context, presentedCert *x509.Certificate, subject string) error {
	if presentedCert == nil {
		return nil
	}
	serial := serialHexStr(presentedCert.SerialNumber)
	data, err := c.loadSuperseded(ctx)
	if err != nil {
		c.supersedeFailures.Add(1)
		return fmt.Errorf("rejecting renewal for %s: cannot determine supersession status: %w", subject, err)
	}
	entries, perr := parseSuperseded(data)
	if perr != nil {
		// Not counted here: this runs on the renewal path, which may be busy,
		// and readSuperseded already counts the same bytes once per sweep pass.
		// Refused all the same — an unparseable list may well have named this
		// serial, and it is the sweep's job to clear the bytes.
		return fmt.Errorf("rejecting renewal for %s: %w: the pending-supersession list is unreadable",
			subject, ErrCertSuperseded)
	}
	for _, e := range entries {
		// Normalised rather than compared raw, even though recordSuperseded now
		// canonicalises on write. Belt and braces on purpose: this is an
		// authorisation decision, the two sides are produced by different code,
		// and a list written by an earlier build of this branch — or by any
		// future caller that appends without going through recordSuperseded —
		// would otherwise silently fail to match. An entry whose serial will not
		// parse cannot be the presented certificate's, since that one came from
		// a *big.Int; skip it and let the sweep discard it.
		stored, err := storage.NormaliseSerial(e.Serial)
		if err != nil {
			continue
		}
		if stored == serial {
			slog.Warn("Renewal: refusing to renew a superseded certificate",
				"subject", subject, "serial", serial, "revoke_at", e.RevokeAt.Format(time.RFC3339))
			return fmt.Errorf("rejecting renewal for %s: %w", subject, ErrCertSuperseded)
		}
	}
	return nil
}

// supersedeReplaced retires the certificate identified by oldSerial now that
// subject's replacement has been signed and stored.
//
// Which of the two it does is decided by SupersedeAfter, and the zero value is
// the behaviour every deployment had before this existed:
//
//   - SupersedeAfter <= 0 — revoke immediately, in this call, exactly as the
//     renewal paths used to inline.
//   - SupersedeAfter > 0 — record oldSerial for revocation that far in the
//     future and return. ReconcileSuperseded does the revoking.
//
// Best-effort in both modes: the caller has a signed replacement in hand and a
// failure here must not undo it. The error is returned either way and no caller
// treats it as fatal, but the two modes are counted in different places and
// neither logs here — the caller does, so the log line can name the path:
//
//   - immediate — revokeSerialLocked and signCRLLocked count their own failures
//     into crlUpdateFailures. A failure to acquire the CRL lock is counted
//     nowhere, which is the pre-existing behaviour of both renewal paths.
//   - delayed — recordSuperseded counts every failure into supersedeFailures,
//     the lock acquisition included, because an unrecorded supersession is lost
//     outright rather than merely unwritten to the CRL.
//
// The caller must hold subject's lock and must NOT hold c.mu or the CRL lock:
// both modes acquire the CRL lock themselves, keeping the documented
// subject → crl → c.mu order.
func (c *CA) supersedeReplaced(ctx context.Context, subject, oldSerial string) error {
	return c.supersedeReplacedAfter(ctx, subject, oldSerial, c.SupersedeAfter)
}

// supersedeReplacedAfter is supersedeReplaced with the window supplied rather
// than read from the CA.
//
// The renewal paths have one window for the whole deployment, which is what
// SupersedeAfter is. A managed certificate can carry its own: the overlap a
// relying party needs to pick up a replacement is a property of what depends on
// that certificate, and two managed certificates need not agree about it.
//
// Same contract as supersedeReplaced in every other respect, including that
// `after <= 0` revokes inline rather than recording anything.
func (c *CA) supersedeReplacedAfter(ctx context.Context, subject, oldSerial string,
	after time.Duration) error {
	if after <= 0 {
		return c.Storage.WithLock(ctx, lockNameCRL, func() error {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.revokeSerialLocked(ctx, oldSerial)
		})
	}
	return c.recordSuperseded(ctx, subject, oldSerial, after)
}

// recordSuperseded appends one entry to the pending-revocation list.
//
// The list is durable and shared rather than held in memory for two reasons:
// the replica that signed the replacement may be gone before the delay
// elapses, and nothing else records the fact. It cannot be recovered from the
// inventory either — the inventory says which serials exist for a subject, not
// which of them a renewal retired, nor when the delay started.
//
// The whole read-modify-write runs under the cluster CRL lock, the same lock
// ReconcileSuperseded rewrites the list under. That is what makes the two
// mutual: without it, a sweep landing between this read and this write erases
// the entry, and the certificate it named stays a valid credential for its full
// remaining life with nothing recording that it should not be. The subject lock
// the caller already holds cannot serve — two renewals for *different* subjects
// hold different subject locks and would race each other. Reusing the CRL lock
// rather than introducing a fourth name keeps the lock order at
// subject → crl → c.mu and the SQL connection-nesting depth at two; see
// docs/development/locking.md.
func (c *CA) recordSuperseded(ctx context.Context, subject, serial string, after time.Duration) error {
	// storage.NormaliseSerial rather than a local SetString, so both sides of
	// the comparison refuseIfSuperseded makes are produced by the *same*
	// function. One definition of canonical is the entire point: the bug this
	// replaced was the write side and the read side disagreeing about form.
	//
	// It is also stricter than SetString in two useful ways — it trims
	// surrounding whitespace, and it rejects a negative value, which SetString
	// would happily parse from a leading "-" and which could never be a real
	// serial.
	canonical, nerr := storage.NormaliseSerial(serial)
	if nerr != nil {
		// Refused here rather than written and discarded by the sweep: the
		// caller is about to log a warning naming this serial, which is a far
		// better place for an operator to see it than a sweep hours later.
		c.supersedeFailures.Add(1)
		return fmt.Errorf("malformed serial %q: %w", serial, nerr)
	}
	// Stored canonical, not as handed in. The two callers disagree about form:
	// AutoRenew passes serialHexStr of the presented certificate, already
	// canonical, while Renew passes LatestSerialForSubject, which returns
	// inventory text *verbatim* — and an inventory written by an older version,
	// or migrated from Puppet Server, carries zero-padded sequential serials
	// (see storage.NormaliseSerial and the comment above SubjectForSerial).
	//
	// refuseIfSuperseded compares this against serialHexStr of a presented
	// certificate. Storing "000A" where the gate computes "A" would make that
	// comparison miss, and the gate is the only thing stopping a superseded
	// credential renewing itself into a fresh full-lifetime successor. The
	// parse above already establishes the value; re-rendering it costs nothing
	// and makes the stored form the same one every reader computes.
	serial = canonical
	revokeAt := time.Now().UTC().Add(after)
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		entries, _, err := c.readSuperseded(ctx)
		if err != nil {
			// Appending to what we could not read would write a one-entry list
			// over however many were pending, so every one of those
			// certificates would stay valid with nothing recording otherwise.
			// Corrupt bytes need no such care: readSuperseded returns what it
			// could recover, and the write below is the overwrite they need.
			return err
		}
		entries = append(entries, supersededEntry{
			Serial:   serial,
			Subject:  subject,
			RevokeAt: revokeAt,
		})
		return c.writeSuperseded(ctx, entries)
	})
	if err != nil {
		c.supersedeFailures.Add(1)
		return err
	}
	slog.Info("Recorded superseded certificate for delayed revocation",
		"subject", subject, "serial", serial, "revoke_at", revokeAt.Format(time.RFC3339))
	return nil
}

// ReconcileSuperseded revokes every recorded certificate whose delay has
// elapsed and rewrites the list with the survivors. It reports how many it
// revoked.
//
// Each entry carries its own revoke_at, fixed when the supersession was
// recorded, and this honours that rather than re-deriving it from the current
// configuration. Shortening SupersedeAfter — or setting it back to zero —
// therefore changes what future renewals record, not the window already granted
// to a certificate other parties may be mid-way through replacing; lengthening
// it does not extend one either. What must not depend on the setting is whether
// this runs at all: entries recorded under an earlier configuration have to
// drain whatever the delay is now, or a certificate the operator believes was
// retired stays a live credential for its full remaining life. See
// runSupersededSweeper, which is why the sweep is not gated on the delay.
//
// RevokeOnAutoRenew does not gate this either. That setting decides whether the
// auto-renewal path *records* a supersession at all; once one is on the list
// the replacement has happened and the entry is honoured. Turning the setting
// off does not un-replace certificates already superseded.
//
// Idempotent and self-healing: revoking a serial already in the CRL is a no-op,
// so any replica finishes work another one started, and a pass that fails
// part-way leaves the unfinished entries to be retried on the next.
//
// # Lock discipline
//
// The whole read-modify-write and the revocations it drives run under the
// cluster CRL lock — the same lock recordSuperseded appends under, and the same
// one revokeSerialLocked requires. One acquisition covers all three, so the
// order stays subject → crl → c.mu and this adds no new nesting. On the
// single-node backends the window this closes is invisible; on etcd, Redis or
// SQL — the multi-replica deployments delayed supersession exists for — it is
// real.
func (c *CA) ReconcileSuperseded(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	// Fast path, before the lock: the overwhelming majority of deployments
	// never enable a window, and this job runs on every replica every interval
	// forever. Acquiring a cluster-wide lock to discover an absent key would
	// make the idle cost a distributed round-trip on etcd/Redis/SQL — and on
	// PostgreSQL and MySQL pin a pooled connection for it — four times an hour,
	// for nothing. A read is enough to rule the work out.
	//
	// Only an empty, cleanly-parsed list may skip. An unreadable or unparseable
	// one must reach the locked path: the first needs counting, the second
	// needs overwriting. An append landing just after this read is picked up on
	// the next tick, which the interval already tolerates by design.
	if data, err := c.loadSuperseded(ctx); err == nil {
		if entries, perr := parseSuperseded(data); perr == nil && len(entries) == 0 {
			return 0, nil
		}
	}

	var revoked int
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		entries, corrupt, err := c.readSuperseded(ctx)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			if corrupt {
				// Overwrite rather than return early. Those bytes will never
				// parse, so leaving them re-warns and re-counts on every pass
				// forever — which latches the alert with nothing an operator
				// can do to clear it, and the realistic response to a
				// permanently firing warning is to silence it.
				return c.writeSuperseded(ctx, nil)
			}
			return nil
		}

		now := time.Now().UTC()
		var due, pending []supersededEntry
		for _, e := range entries {
			if now.Before(e.RevokeAt) {
				pending = append(pending, e)
				continue
			}
			due = append(due, e)
		}
		if len(due) == 0 && !corrupt {
			return nil
		}
		// With entries recovered from a corrupt blob the normal path is right:
		// they are swept like any others, and the write-back below persists the
		// survivors — which is the same overwrite the corrupt bytes need.

		// Oldest first. This used to be what made stopping part-way safe, when
		// a pass could run out of deadline mid-drain; since #176 batched the
		// re-sign a pass attempts every due entry or none of them, so what it
		// buys now is a deterministic order for the entries the batch appends
		// to the CRL — the same list, swept on two replicas, produces the same
		// sequence of revocation entries rather than one that depends on the
		// order the store happened to return.
		sort.Slice(due, func(i, j int) bool { return due[i].RevokeAt.Before(due[j].RevokeAt) })

		outcome := func() drainOutcome {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.drainDueLocked(ctx, due)
		}()
		revoked = outcome.revoked

		// A pass that left certificates past their window unrevoked is the
		// condition this counter exists to surface, for either of the two
		// reasons that can now produce one: a batch that could not be written,
		// and an entry discarded as unrevocable. Without it a backlog looks like
		// a high pending gauge that never falls and nothing else — and the
		// gauge's own guidance sends the operator to this counter.
		//
		// outcome.deferred is still tested rather than dropped from the
		// condition, because drainOutcome keeps the field for a future
		// implementation that has to stop part-way; see its godoc. It is always
		// empty today, so the middle term never fires.
		if len(outcome.failed) > 0 || len(outcome.deferred) > 0 || outcome.discarded > 0 {
			c.supersedeFailures.Add(1)
		}
		// The drain may have spent most (or, on a deadline error, all) of ctx's
		// budget, and that is exactly when a partial pass is most likely. The
		// write-back has to survive it or the pass loses its own bookkeeping:
		// entries it revoked would stay on the list, the pending gauge would
		// never fall, and every later pass would re-walk them — a re-walk that
		// now costs one CRL read for the whole pass rather than one per entry,
		// but is still a pass that can never finish — while holding the CRL lock
		// for the full budget. Same reasoning, and the same modest budget, as
		// CleanupExpiredCerts gives its post-prune cleanup: the CRL lock is
		// still held, and a concurrent revocation waits on it with a LockTimeout
		// of its own.
		writeCtx, cancelWrite := context.WithTimeout(context.WithoutCancel(ctx), LockTimeout/2)
		defer cancelWrite()
		// Built explicitly rather than by chained appends: pending, failed and
		// deferred each have their own backing array, and a chained append can
		// write into one of them. Everything still owed a revocation goes back.
		keep := make([]supersededEntry, 0, len(pending)+len(outcome.failed)+len(outcome.deferred))
		keep = append(keep, pending...)
		keep = append(keep, outcome.failed...)
		keep = append(keep, outcome.deferred...)
		return c.writeSuperseded(writeCtx, keep)
	})
	if err != nil {
		// A pass that could not take the lock, could not read the list, or
		// could not write it back left every entry unrevoked. Counted here, once
		// per pass, so the one alert that bounds this exposure can fire: without
		// it a storage fault that blocks every sweep leaves both new signals
		// reading clean — a flat counter and, because an unreadable list is not
		// a drained one, a pending gauge that has to be omitted rather than
		// reported as zero. readSuperseded's parse arm counts separately and
		// does not return an error, so this cannot double-count it.
		c.supersedeFailures.Add(1)
	}
	return revoked, err
}

// retireSupersededForSubjectLocked revokes every pending entry recorded for
// subject, using revoke, and rewrites the list without the ones that succeeded.
// It is a no-op when the list is empty or names no such subject.
//
// The cluster CRL lock and c.mu must both be held by the caller, which is what
// lets this call revokeSerialLocked directly.
//
// Why revocation of a subject has to reach these: Revoke retires the subject's
// *latest* serial and no other, so during an overlap window it retires the
// replacement and leaves the certificate that replacement displaced valid —
// with, on the re-key path, a private key of its own. An operator containing a
// compromised node with `revoke --certname` would be told the node was revoked
// while a second working credential for it stayed in circulation.
//
// This is narrower than the open question revokeLocked's godoc scopes out
// ("retiring every unexpired serial a subject holds ... is a change to what
// revocation means"). These serials are already scheduled for revocation by
// this CA's own decision; bringing that forward when the subject is revoked
// changes when it happens, not what revocation covers. A serial the subject
// holds that was never superseded is still none of Revoke's business.
//
// Revoke-then-write, never write-then-revoke. An entry is removed from the list
// only once its serial is on the CRL; one whose revocation failed stays
// recorded so the sweep retries it. Pruning first would put a failed revocation
// in the one state nothing recovers from — absent from the CRL and absent from
// the only record that it is owed one — which is the same trap
// ReconcileSuperseded's `failed` handling avoids.
//
// A read failure is counted and swallowed: the caller's own revocation has
// either happened or is about to, and failing it because the pending list was
// unreadable would turn a partial containment into no containment at all. The
// entries stay on the list and the sweep still retires them.
func (c *CA) retireSupersededForSubjectLocked(ctx context.Context, subject string) {
	entries, _, err := c.readSuperseded(ctx)
	if err != nil {
		c.supersedeFailures.Add(1)
		slog.Warn("Revoke: could not read pending supersessions for this subject; any predecessor "+
			"inside its window stays valid until the sweep retires it", "subject", subject, "error", err)
		return
	}

	var mine []supersededEntry
	kept := make([]supersededEntry, 0, len(entries))
	for _, e := range entries {
		if e.Subject != subject {
			kept = append(kept, e)
			continue
		}
		mine = append(mine, e)
	}
	if len(mine) == 0 {
		return
	}

	var failed int
	for _, e := range mine {
		if err := c.revokeSerialLocked(ctx, e.Serial); err != nil {
			// Kept, so the sweep retries it. Logged rather than returned: the
			// revocation the caller asked for has not happened yet and must not
			// be lost to a predecessor that could not be retired.
			slog.Warn("Revoke: could not retire a superseded certificate for this subject; "+
				"it stays a valid credential until the sweep retires it",
				"subject", subject, "serial", e.Serial, "error", err)
			kept = append(kept, e)
			failed++
			continue
		}
		slog.Info("Revoked superseded certificate alongside its subject",
			"subject", subject, "serial", e.Serial)
	}
	if failed > 0 {
		c.supersedeFailures.Add(1)
	}
	if err := c.writeSuperseded(ctx, kept); err != nil {
		// The revocations already landed on the CRL, so the cost of this is a
		// list naming serials that are already revoked — which the sweep
		// re-revokes as a no-op. Harmless, unlike the reverse ordering.
		c.supersedeFailures.Add(1)
		slog.Warn("Revoke: could not prune pending supersessions; the sweep will re-check them",
			"subject", subject, "error", err)
	}
}

// drainOutcome is what one drain pass did to the entries it was given. Every
// due entry lands in exactly one disposition, and the four together account for
// all of them:
//
//	revoked   — on the CRL now
//	failed    — revocation was attempted and refused; stays listed, retried
//	deferred  — never attempted; stays listed (always empty, see below)
//	discarded — can never be revoked; dropped from the list, loudly
//
// That total is not bookkeeping pedantry. The list is the only record that a
// replaced certificate is owed a revocation, so an entry that falls out of all
// four is a credential left valid with nothing tracking it — which is exactly
// the defect review round 2 found here, where deferred entries were counted in
// the log line and then dropped from the write-back.
//
// deferred has been empty since #176 batched the re-sign, and is kept rather
// than removed. It existed because N entries cost N re-signs, so a large
// backlog could not fit in one lock hold; one re-sign for all of them removes
// the budget problem that produced it. What it still buys is the shape of the
// contract: a future implementation that has to stop part-way — a chunked batch
// for a backlog too large for one CRL, say — reports it here without reshaping
// the caller, and the write-back that carries it forward is already written and
// already specified. Nothing sets it today, and the specs assert that it stays
// empty.
type drainOutcome struct {
	revoked   int
	failed    []supersededEntry
	deferred  []supersededEntry
	discarded int
}

// drainDueLocked revokes the due entries in one batched CRL re-sign, and
// reports what happened to each. The cluster CRL lock and c.mu must both be
// held.
//
// # The batch, and what it is worth
//
// This partitions first and batches second: every entry whose serial is
// canonical hexadecimal goes into a single appendCRLEntriesLocked call, which
// costs one CRL read, one signature and one write however many entries there
// are. It used to call revokeSerialLocked once per entry, each a whole
// read-modify-write of a document carrying the fleet's entire revocation
// history, with the CRL lock — the one every revocation and every OCSP lookup
// on every replica waits for — held across all of them, and under
// ca_key_provider: openbao a remote Transit round trip per signature. That was
// tolerable while N was normally one. Since delayed supersession ships with a
// 24h default (#174) the pending list spans subjects: every node renewal and
// every managed certificate feeds one sweep, so N is structurally larger in
// steady state on every CA that renews anything, and the per-entry cost stopped
// being an occasional stall and became the normal cost of a pass. That is #176.
//
// # The partition is a safety property, not an optimisation
//
// A malformed serial must never reach the batch. One entry that cannot be
// parsed would fail the single re-sign and take every valid entry in the pass
// down with it — where the per-entry loop merely lost that one. Worse, it would
// keep doing so on every subsequent pass, because a failed batch carries all of
// its entries forward: one unparseable serial would permanently stall every
// pending revocation on the CA. So the loop below validates and canonicalises
// every serial up front and discards what can never be revoked, and only what
// survives is handed to the batch.
//
// Canonicalisation is storage.NormaliseSerial, the same validator
// recordSuperseded writes the list through, rather than a bare big.Int parse.
// Inventory serials are not canonical — a store migrated from Puppet carries
// zero-padded ones — so "000ABC" and "ABC" are one certificate, and comparing
// them raw is how a duplicate slips into a batch that appends its entries in
// one go. NormaliseSerial is also stricter than the parse it replaces, in the
// two directions that make the pending list and the CRL agree: it accepts a
// serial with surrounding whitespace, which recordSuperseded already stores
// canonically and which the old check discarded outright, and it rejects a
// negative one, which the old check handed on as revocable although no
// certificate can carry it.
//
// # Failure granularity
//
// A batched re-sign either lands or it does not, so failed is all-or-nothing:
// every entry the batch tried comes back in it, stays on the list, and is
// retried on the next pass. That is what the shared failure always was — a CRL
// this replica cannot read, sign or write fails the whole pass however the
// entries are grouped — and the one genuinely per-entry failure, the malformed
// serial, is discarded above and never reaches it. The carry-forward spec
// ("keeps an entry whose revocation failed for a reason that may pass") is the
// single-entry case of that and still holds.
//
// crlUpdateFailures follows the batch: readStoredCRL and signCRLLocked each
// count their own failure, so a failed pass moves that counter once rather than
// once per due entry. mixin/alerts.libsonnet says so.
func (c *CA) drainDueLocked(ctx context.Context, due []supersededEntry) drainOutcome {
	var out drainOutcome

	// Partition first, then batch. See the godoc: an unparseable serial inside
	// the batch fails every valid entry beside it, on this pass and on every
	// pass after it.
	type dueSerial struct {
		entry supersededEntry
		// canon is the key the CRL, the OCSP cache and the certificate index
		// all agree on, and the form logged.
		canon  string
		number *big.Int
	}
	batch := make([]dueSerial, 0, len(due))
	for _, e := range due {
		canon, err := storage.NormaliseSerial(e.Serial)
		if err != nil {
			// Retrying is right for a transient failure and wrong for a
			// permanent one. A serial that is not a hexadecimal number can
			// never be revoked, so carrying it forward would retry it on every
			// pass forever, latching both this counter's alert and the CRL one
			// with nothing an operator could do to clear them. Discarded,
			// loudly — and never handed to the batch, so it does not fail the
			// entries around it and does not count as a CRL failure as well.
			slog.Error("Discarding superseded-certificate entry with a malformed serial; "+
				"it can never be revoked", "serial", e.Serial, "subject", e.Subject, "error", err)
			out.discarded++
			continue
		}
		number, ok := new(big.Int).SetString(canon, 16)
		if !ok {
			// Unreachable: canon is NormaliseSerial's own rendering of a
			// non-negative big.Int in uppercase hex. Handled as a discard
			// rather than asserted, because the alternative to the branch is a
			// nil SerialNumber reaching x509.CreateRevocationList, which fails
			// the whole batch for a reason no log line explains.
			slog.Error("Discarding superseded-certificate entry whose canonical serial will "+
				"not parse; it can never be revoked", "serial", e.Serial, "canonical", canon,
				"subject", e.Subject)
			out.discarded++
			continue
		}
		batch = append(batch, dueSerial{entry: e, canon: canon, number: number})
	}
	if len(batch) == 0 {
		return out
	}

	serials := make([]*big.Int, 0, len(batch))
	for _, d := range batch {
		serials = append(serials, d.number)
	}
	revokedAt, err := c.appendCRLEntriesLocked(ctx, serials)
	if err != nil {
		// All-or-nothing by construction: one re-sign covers the whole batch,
		// so none of these is on the CRL. They stay listed and the next pass
		// retries them, which is what the per-entry loop did for each failure
		// it saw.
		//
		// Every affected identity is named, not just counted. These
		// certificates are still valid credentials past the window their
		// supersession granted them, so "which ones" is the question
		// PuppetCASupersedeFailing sends an operator to the log to answer, and
		// that alert's runbook closes by telling them to retire what the sweep
		// will not with `openvox-ca-ctl revoke --serial <hex>` — which needs a
		// serial this line has to carry. The per-entry loop named each one as
		// it failed; collapsing N revocations into one re-sign must not also
		// collapse N identities into a count.
		//
		// Both slices, in the same order, on the one line the runbook greps
		// for: the serial is what the remedy takes as an argument and the
		// subject is what an operator recognises. One line rather than N keeps
		// the alert text accurate, and is less log volume than the success path
		// below already emits for the same batch.
		failedSerials := make([]string, 0, len(batch))
		failedSubjects := make([]string, 0, len(batch))
		out.failed = make([]supersededEntry, 0, len(batch))
		for _, d := range batch {
			failedSerials = append(failedSerials, d.canon)
			failedSubjects = append(failedSubjects, d.entry.Subject)
			out.failed = append(out.failed, d.entry)
		}
		slog.Warn("Could not revoke superseded certificates; will retry",
			"entries", len(batch), "serials", failedSerials,
			"subjects", failedSubjects, "error", err)
		return out
	}

	out.revoked = len(batch)
	for _, d := range batch {
		// Project the revocation into the certificate index, per serial and
		// after the batch, exactly as revokeSerialLocked did per call. Not
		// folded into the batch because it is not the same kind of write: the
		// index column is one indexed row update on the backends that have an
		// index and a no-op on the rest, never a re-sign of a whole document,
		// and it is a display cache of the CRL rather than the record itself —
		// so a failure is logged and the startup index repair reconverges it.
		//
		// revokedAt carries a time for entries the batch found already listed
		// as well as for the ones it appended, which is deliberate: a retried
		// revocation is exactly the case where the CRL write landed and the
		// index update did not.
		c.markCertRevokedIndex(ctx, d.canon, revokedAt[d.canon])
		slog.Info("Revoked superseded certificate", "subject", d.entry.Subject, "serial", d.canon)
	}
	return out
}

// appendCRLEntriesLocked adds every serial in add to the CRL in a single
// read-modify-write: one read, one signature and one write however long add is.
// It is a no-op — no re-sign — when every serial is already listed. The cluster
// CRL lock and c.mu must both be held by the caller.
//
// This is the addition-side mirror of dropCRLEntriesLocked, which is what
// CleanupExpiredCerts already does on the removal side: collect the serials,
// then amend the CRL once. It lives here, beside its only caller, for the same
// reason that one lives beside its own.
//
// It returns the revocation time now recorded for each serial in add, keyed by
// serialHexStr. Serials it appended carry this call's timestamp; serials the
// CRL already listed carry the one it already held, so a caller projecting the
// revocation elsewhere records when it happened rather than when it was
// noticed.
//
// Deduplication is by canonical serial, against the stored CRL and within add
// itself. Both matter. A serial listed twice grows the CRL without bound, which
// is what revokeSerialLocked's duplicate check exists to prevent one entry at a
// time; and a batch can carry the same certificate twice where a loop could
// not, because the loop's second pass re-read a CRL its first had already
// amended. Callers pass parsed *big.Int values, so the keying is on the number
// rather than on the text a serial arrived as.
//
// Nothing invalidates the OCSP cache here, and nothing needs to: signCRLLocked
// installs the new list through installCachedCRLLocked, which drops the cached
// response for every serial the new CRL revokes and the old one did not. That
// is the whole batch, in one pass, and it is the same mechanism that already
// covers a revocation performed on another replica.
func (c *CA) appendCRLEntriesLocked(ctx context.Context, add []*big.Int) (map[string]time.Time, error) {
	stored, err := c.readStoredCRL(ctx)
	if err != nil {
		return nil, err
	}

	listed := make(map[string]time.Time, len(stored.own.RevokedCertificateEntries))
	for _, entry := range stored.own.RevokedCertificateEntries {
		listed[serialHexStr(entry.SerialNumber)] = entry.RevocationTime
	}

	now := time.Now()
	revokedAt := make(map[string]time.Time, len(add))
	revoked := stored.own.RevokedCertificateEntries
	appended := 0
	for _, n := range add {
		key := serialHexStr(n)
		if at, already := listed[key]; already {
			revokedAt[key] = at
			continue
		}
		listed[key] = now
		revokedAt[key] = now
		revoked = append(revoked, x509.RevocationListEntry{
			SerialNumber:   n,
			RevocationTime: now,
		})
		appended++
	}
	if appended == 0 {
		// Every serial was already on the CRL, so there is nothing to sign.
		// This is the idempotent re-run — another replica finished the work, or
		// an earlier pass wrote the CRL and then failed to prune the list — and
		// it must not cost a signature, which on a Transit-backed key is a
		// remote round trip and on every backend a CRL write the fleet re-reads.
		return revokedAt, nil
	}

	if err := c.signCRLLocked(ctx, stored, revoked); err != nil {
		return nil, err
	}
	return revokedAt, nil
}

// PendingSupersessions returns the number of certificates currently recorded
// for delayed revocation, for diagnostics and metrics. An absent list is zero.
//
// It takes no cluster lock: a count read a moment before a sweep is still a
// useful count, and blocking a metrics scrape behind a CRL re-sign is not a
// trade worth making.
//
// It also neither logs nor counts a corrupt list, deliberately — it is called
// on a scrape interval, and a blob that will never parse would otherwise emit
// the same warning and increment the same counter every few seconds until an
// operator noticed. The sweep is what reports that condition, once per pass,
// and it is also what clears it. A corrupt list is counted here as whatever
// decoded before the failure, which under-reports; the counter is where the
// discrepancy shows up.
func (c *CA) PendingSupersessions(ctx context.Context) (int, error) {
	data, err := c.loadSuperseded(ctx)
	if err != nil {
		return 0, err
	}
	entries, _ := parseSuperseded(data)
	return len(entries), nil
}

// SupersedeFailures returns the number of times the CA failed to schedule or
// carry out a delayed revocation: a supersession it could not record, and each
// sweep that left an entry unrevoked or discarded one it never could revoke. A
// rising value means a certificate a renewal replaced may still be a valid
// credential; the metrics exporter surfaces it as
// puppetca_supersede_failures_total.
func (c *CA) SupersedeFailures() uint64 {
	return c.supersedeFailures.Load()
}

// readSuperseded loads the pending-revocation list.
//
// An absent list is empty and not an error: that is the steady state before the
// first supersession, and on any CA whose delay has never been enabled. A read
// that *fails* is reported, because both mutating callers go on to write the
// list back — and a failed read reported as "empty" would have them persist an
// empty list over entries that are still there, silently un-scheduling every
// pending revocation.
//
// An unparseable list is treated as recoverable-then-empty, deliberately and
// with a warning: whatever decoded before the failure is real, revocable
// serials and is returned, while the rest is unrecoverable.
//
// That tolerance is scoped to the callers that *maintain* the list — the sweep
// and subject revocation — which have work to do either way and would otherwise
// stall on bytes only they can clear. The renewal path does not share it:
// refuseIfSuperseded reads the same blob and refuses on a parse failure,
// because an unparseable list may well have named the serial being presented
// and admitting it is the one decision here that cannot be walked back. See
// that function's godoc.
//
// The corrupt return says the bytes were unusable, as distinct from absent. A
// caller that can write must overwrite them: an unparseable blob is not
// self-clearing, and left alone it re-warns on every pass forever.
func (c *CA) readSuperseded(ctx context.Context) (entries []supersededEntry, corrupt bool, err error) {
	data, err := c.loadSuperseded(ctx)
	if err != nil {
		return nil, false, err
	}
	entries, perr := parseSuperseded(data)
	if perr != nil {
		// entries keeps whatever decoded before the failure, which is not
		// always nothing: encoding/json validates the whole input before
		// decoding any of it, so a syntax error or a truncated write recovers
		// zero entries, while a well-formed list carrying one badly-typed field
		// recovers the rest. The second case is worth the handling — those are
		// real serials, returned rather than discarded, and the sweep retires
		// them normally while its write-back drops the part that will never
		// parse. A recovered entry can itself be the malformed one (its bad
		// field decodes to the zero value), which the sweep's own
		// malformed-serial arm then discards.
		//
		// Counted, because however many entries these bytes named, they are
		// gone: nothing can rediscover them, so those certificates stay valid
		// for their full remaining life with nothing recording that they should
		// not be. Left uncounted, the one alert that bounds that exposure could
		// not fire.
		//
		// Logged as a fingerprint, not as bytes. This is the one arm that can
		// name no serial — there may have been several, and the sweep is about
		// to overwrite them — so something has to identify the blob across
		// passes and tell corruption apart from a foreign value that landed
		// under this key. What it must not do is emit the value: the argument
		// that it holds only serials, subjects and timestamps rests on it being
		// the structure that has just failed to parse, and the key is written
		// BlobPrivate precisely because its contents are not for a log that is
		// typically group-readable and shipped off the host. Length, digest and
		// the offset the decoder stopped at answer every diagnostic question
		// without that risk.
		c.supersedeFailures.Add(1)
		slog.Warn("Discarding unparseable pending certificate revocations; whatever they named "+
			"will not be scheduled for revocation",
			"error", perr, "recovered", len(entries), "bytes", len(data),
			"sha256", blobFingerprint(data), "offset", jsonErrorOffset(perr))
		return entries, true, nil
	}
	return entries, false, nil
}

// loadSuperseded fetches the stored list's raw bytes. An absent list yields
// (nil, nil): that is the steady state before the first supersession, and
// parseSuperseded decodes nil to an empty list.
func (c *CA) loadSuperseded(ctx context.Context) ([]byte, error) {
	data, err := c.Storage.GetSuperseded(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		// Without the backend's error text: a SQL driver's connection error can
		// carry the DSN, and this error reaches a Warn line on the renewal path.
		return nil, errors.New("reading pending certificate revocations")
	}
	return data, nil
}

// parseSuperseded decodes the stored list, returning whatever decoded before a
// failure alongside the failure. Pure: it neither logs nor counts, so callers
// on a scrape interval can use it without turning one corrupt blob into a
// stream of identical warnings. Absent or empty bytes decode to no entries and
// no error.
func parseSuperseded(data []byte) ([]supersededEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var entries []supersededEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return entries, err
	}
	return entries, nil
}

// writeSuperseded persists the pending-revocation list. An empty list is
// written as `[]` rather than deleted: one key that is always present is easier
// for a backup or a migration to reason about than one that comes and goes.
func (c *CA) writeSuperseded(ctx context.Context, entries []supersededEntry) error {
	if len(entries) == 0 {
		entries = []supersededEntry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("encoding pending certificate revocations: %w", err)
	}
	if err := c.Storage.SaveSuperseded(ctx, data); err != nil {
		// Without the backend's error text, for the reason readSuperseded
		// gives: both reach the same Warn line on the renewal path.
		return errors.New("saving pending certificate revocations")
	}
	return nil
}

// blobFingerprint identifies a stored blob in a log line without reproducing
// it: the first eight bytes of its SHA-256, hex-encoded. Enough to correlate
// the same unparseable value across passes and replicas, and to tell "the same
// corruption is still there" from "it changed", while revealing nothing about
// content whose shape is by definition unknown at the point this is called.
func blobFingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// jsonErrorOffset reports where the decoder gave up, or -1 when the error
// carries no position. Together with the length it distinguishes a truncated
// write from corruption in the middle of an otherwise intact blob, which is the
// question an operator actually has.
func jsonErrorOffset(err error) int64 {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return syn.Offset
	}
	var typ *json.UnmarshalTypeError
	if errors.As(err, &typ) {
		return typ.Offset
	}
	return -1
}
