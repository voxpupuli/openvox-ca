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
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/boundedfile"
)

// Fetched upstream CRLs (crl_chain.urls).
//
// The file path (crlchainfile.go) treats crl_chain.file as a *source*: it is
// re-read under the CRL lock on every amendment, and is authoritative each
// time. Fetched CRLs cannot work that way. Reading them on every amendment
// would put network I/O under the cluster-wide CRL lock, or else need a
// per-replica cache -- and replicas' caches disagree, so a replica still
// holding an older copy would count a regression on every revocation, and one
// that had not fetched yet would read as removals.
//
// So a fetch round *writes into the store* instead. The fetch and the decode
// happen outside the lock (internal/crlfetch); MergeFetchedUpstreamCRLs then
// verifies each result against the stored CA bundle and merges it into the
// stored chain under the lock, deciding there, as RefreshCRLChainFile does, so
// the first replica to merge rewrites and the rest find nothing to do.
// Verifying under the lock is deliberate: the bundle is read there, in the same
// critical section as the chain it judges, so a bundle an import has just
// replaced takes effect on the next round rather than racing it. It costs a
// few signature checks per round, on at most 64 entries
// (config.MaxCRLChainURLs). Between rounds every amendment takes
// crlChainLocked's no-file path and carries the stored ancestors forward
// unchanged, so a revocation never touches the network and no upstream can
// block one.

// UpstreamFetch is one crl_chain.urls entry's fetch, as handed to
// MergeFetchedUpstreamCRLs: exactly one of CRL and Err is set.
type UpstreamFetch struct {
	URL string
	CRL *x509.RevocationList
	Err error
}

// upstreamFetchStatus is one entry's metric state.
type upstreamFetchStatus struct {
	lastSuccess atomic.Int64
	failures    atomic.Uint64
}

// UpstreamFetchStatus reports one entry for the per-URL metrics.
type UpstreamFetchStatus struct {
	URL string
	// LastSuccess is when the entry last yielded a usable, current CRL, or
	// the zero time if it never has.
	LastSuccess time.Time
	Failures    uint64
}

// SetCRLChainURLs records the configured crl_chain.urls entries. Called once,
// while the CA is configured, so each entry's series exists -- at zero -- from
// startup: "never fetched" is then something an alert can see rather than an
// absent series.
func (c *CA) SetCRLChainURLs(urls []string) {
	c.crlChainURLs = append([]string(nil), urls...)
	c.upstreamFetch = make(map[string]*upstreamFetchStatus, len(urls))
	for _, u := range urls {
		c.upstreamFetch[u] = &upstreamFetchStatus{}
	}
}

// UpstreamFetchStatuses reports every configured entry, in configured order.
func (c *CA) UpstreamFetchStatuses() []UpstreamFetchStatus {
	out := make([]UpstreamFetchStatus, 0, len(c.crlChainURLs))
	for _, u := range c.crlChainURLs {
		s := c.upstreamFetch[u]
		if s == nil {
			continue
		}
		st := UpstreamFetchStatus{URL: u, Failures: s.failures.Load()}
		if sec := s.lastSuccess.Load(); sec != 0 {
			st.LastSuccess = time.Unix(sec, 0)
		}
		out = append(out, st)
	}
	return out
}

// HoldReadinessForUpstreamChain decides, once at startup, whether readiness
// waits for a crl_chain.urls round to store an upstream CRL, and returns
// whether it does.
//
// It waits only when the stored chain holds no upstream CRL at all -- in
// practice a fresh store. There, serving would hand every agent on
// certificate_revocation = chain a chain with an ancestor missing, which it
// rejects, so a pod that is not ready is the better state. A store that holds
// any upstream CRL is ready at once, even when every one has lapsed: a running
// pod in that state stays ready (a failing fetch never makes it unready), so a
// restarted one must too, or restarting a degraded CA -- a node drain, a chart
// upgrade -- would take it out of its Service until the upstream recovered. A
// lapse is the expiry and fetch alerts' to report, not readiness's.
//
// Readiness only, never startup: the startup probe passes once the CA is
// initialised, so a held pod stays running and retrying rather than being
// restarted in a loop.
//
// The hold is released on the same condition it is taken on -- a round that
// leaves an upstream CRL stored (UpstreamMergeResult.Usable), an expired one
// that is still newer than nothing included -- so a held pod and a restarted
// one agree. A stored chain that cannot be read is treated as empty, so the
// hold is taken; the first round that stores a CRL releases it, which it can
// once storage answers again.
//
// A stored chain that reads but does not decode is not held, nor one that
// decodes to no CRL at all -- not even this CA's own, which Init always
// writes. Every merge fails on either until it is repaired, so no round could
// release the hold, and a running pod that met the same chain would stay
// ready; holding would take a restarted pod out of its Service for good. The
// failing merges are counted as CRL update failures, which is what reports it.
func (c *CA) HoldReadinessForUpstreamChain(ctx context.Context) bool {
	blob, err := c.Storage.GetCRL(ctx)
	if err != nil {
		// Held, and said here: the caller's startup line does not say why the
		// hold was taken, and this one carries the error.
		slog.Warn("Could not read the stored CRL chain to decide the readiness hold; holding", "error", err)
	} else if crls, err := decodeCRLChain(blob); err != nil || len(crls) == 0 {
		if err == nil {
			err = errors.New("it holds no CRL")
		}
		slog.Warn("Could not decode the stored CRL chain; not holding readiness, since no fetch round "+
			"can merge into it until it is repaired", "error", err)
		return false
	} else if c.hasUpstream(crls) {
		return false
	}
	c.upstreamHeld.Store(true)
	return true
}

// ReleaseUpstreamChainHold lets readiness through, reporting whether it had
// been held. Called after a round that leaves an upstream CRL stored.
func (c *CA) ReleaseUpstreamChainHold() bool {
	return c.upstreamHeld.Swap(false)
}

// UpstreamChainHeld reports whether readiness is waiting for a crl_chain.urls
// round to store an upstream CRL.
func (c *CA) UpstreamChainHeld() bool {
	return c.upstreamHeld.Load()
}

// hasUpstream reports whether crls holds any CRL this CA did not issue,
// expired or not.
func (c *CA) hasUpstream(crls []*x509.RevocationList) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, crl := range crls {
		if !c.ownsCRL(crl) {
			return true
		}
	}
	return false
}

// mergeEvent is a log line decided under the lock and emitted after it is
// released: logging is I/O, and nothing should wait on it while every
// replica's revocations queue behind the CRL lock.
type mergeEvent struct {
	level slog.Level
	msg   string
	args  []any
}

// UpstreamMergeResult is what one fetch round's merge did.
type UpstreamMergeResult struct {
	// Rewritten is whether the published chain changed.
	Rewritten bool
	// Usable is whether the chain as it stands after the merge holds any
	// upstream CRL -- the condition HoldReadinessForUpstreamChain checks at
	// startup, and so the one that releases the hold.
	Usable bool
	// Verdicts holds each entry's outcome, in order: nil when it yielded a
	// usable, current CRL, the reason otherwise.
	Verdicts []error
}

// MergeFetchedUpstreamCRLs judges a round's results and merges the usable ones
// into the published chain, re-signing when the chain changes.
//
// An entry succeeds only when its CRL verifies against the stored CA bundle,
// has not expired, is newer than or equal to the one already published for
// the same ancestor ("equal" being already current), and the round it arrived
// in fits the size bound. Everything else is a failure for that entry even
// when the transport succeeded, because a fetch that returns 200 and nothing
// usable is the failure an operator most needs named:
//
//   - not a CRL, or not exactly one (crlfetch has already said so);
//   - this CA's own CRL, a misconfiguration: it is ignored, so it neither
//     publishes anything nor stops the round being complete, but the round
//     may not remove (see below);
//   - a CRL nothing in the bundle signed (also counted as discarded);
//   - a CRL older than the published one (also counted as regressed, and
//     never merged: publishing it would un-revoke, fleet-wide, everything that
//     ancestor revoked in between);
//   - an expired CRL. One that is still newer than the published one is merged
//     anyway, since it is strictly better than what agents hold, but the entry
//     still fails: an upstream that has stopped re-signing is broken, and the
//     alert should name its URL rather than wait for the expiry alert;
//   - a delta CRL, or one with an issuing distribution point: genuinely signed,
//     but not its issuer's full list, so it cannot stand in for one (also
//     counted as discarded);
//   - any CRL at all, in a round that would write an upstream chain larger
//     than boundedfile.MaxCRLBytes. The published chain is kept, and every
//     entry that met the conditions above fails -- one already current
//     included, since the round as a whole is refused -- counted against its
//     URL, as the size is what those entries served together. A round that
//     changes nothing writes nothing, so a stored chain already over the
//     bound (an import can leave one) does not fail it.
//
// Two entries naming the same ancestor are mirrors: the newer CRL is merged,
// and the one that lags still succeeds if it is as new as the published one.
//
// Only an authoritative round may remove an ancestor: a published ancestor no
// entry served is then dropped and counted in crl_chain_removed_total, as the
// file does when it stops listing one. Authoritative means four things:
//
//   - complete: every entry yielded its issuer's full CRL from a certificate in
//     the bundle, so the round knows which ancestors the list covers. A
//     partial round -- an entry unreachable, unsigned, or serving a delta or
//     IDP-scoped CRL -- only updates, so a failing upstream can never shrink
//     the chain;
//   - authenticated: every entry was fetched over https:// or read from a
//     file:/// path. Nothing ties an entry to the ancestor it is meant to
//     serve, so over plain http:// an attacker on the path could answer one
//     entry with another ancestor's (public) CRL, complete the round without
//     the real ancestor, and have it removed -- after which the monotonic check
//     has nothing to compare against, and an older CRL from before a
//     revocation could be published as though the ancestor were new. A list
//     with an http:// entry therefore only ever updates;
//   - no entry served this CA's own CRL. Such an entry names no ancestor yet
//     leaves the round complete, and this CA's CRL is public, so whoever
//     controls an entry's origin could serve it in place of the ancestor's,
//     have that ancestor removed, and later re-introduce an older CRL for it
//     as above. Ignoring it keeps every round from going partial over a
//     misconfiguration; refusing removal keeps it from shrinking the chain;
//   - unambiguous: no two entries named the same ancestor. Two that do may be
//     mirrors, or one may be pointed at the wrong CA; either way the round
//     cannot tell which ancestor the list meant to cover.
//
// What this does not close: an https:// or file:/// origin that serves the
// CRL of a certificate in the bundle that no entry serves -- genuinely signed,
// and naming an ancestor the round does not otherwise cover -- still completes
// the round without its own ancestor. Removal therefore trusts each such
// origin to serve the ancestor it is configured for; the operator docs say so.
//
// Per-entry metrics are recorded here. When the merge itself fails -- the lock,
// a storage read, the re-sign -- no entry is recorded as a success, and the
// failure is counted as a CRL update failure rather than against any URL,
// whose fault it is not.
//
// Background work, so the merge runs as one sweep step through sweepStep and
// withCRLLockYielding: a revocation waiting in this process goes first, and one
// arriving after it starts waits for no longer than a step's budget plus the CA
// signature it has in flight (#347). Only the merge and its re-sign hold the
// lock; the fetch that feeds them ran before this was called.
func (c *CA) MergeFetchedUpstreamCRLs(ctx context.Context, fetched []UpstreamFetch) (UpstreamMergeResult, error) {
	verdicts := make([]error, len(fetched))
	for i, f := range fetched {
		switch {
		case f.Err != nil:
			verdicts[i] = f.Err
		case f.CRL == nil:
			verdicts[i] = errors.New("no CRL")
		}
	}

	var events []mergeEvent
	rewritten := false
	usable := false
	now := time.Now()
	err := c.sweepStep(ctx, c.withCRLLockYielding, func(ctx context.Context) error {
		c.mu.Lock()
		defer c.mu.Unlock()

		stored, err := c.readStoredCRL(ctx)
		if err != nil {
			return err
		}
		issuers, err := c.bundleCertificates(ctx)
		if err != nil {
			c.crlUpdateFailures.Add(1)
			return err
		}
		published, err := c.publishedUpstream(stored.blob)
		if err != nil {
			c.crlUpdateFailures.Add(1)
			return err
		}

		plan := c.planUpstreamMerge(issuers, published, fetched, verdicts, now)
		events = plan.events
		usable = len(plan.upstream) > 0
		if sameCRLSet(published, plan.upstream) {
			return nil
		}
		// The same bound crl_chain.file is held to, on the whole chain rather
		// than per entry: 64 entries of 4 MiB each would otherwise publish a
		// chain decoded under this lock on every revocation, and handed whole to
		// every agent. Over it, the round fails and nothing is written.
		if size := len(encodeCRLChain(plan.upstream)); size > boundedfile.MaxCRLBytes {
			oversize := fmt.Errorf("the merged upstream chain would be %d bytes, over the %d-byte bound "+
				"crl_chain.file is also held to; the published chain is kept", size, boundedfile.MaxCRLBytes)
			for i := range verdicts {
				if verdicts[i] == nil {
					verdicts[i] = oversize
				}
			}
			events = append(events, mergeEvent{slog.LevelError,
				"The upstream CRLs from crl_chain.urls would make the published chain too large; keeping it as it is",
				[]any{"bytes", size, "limit", boundedfile.MaxCRLBytes}})
			usable = len(published) > 0
			return nil
		}

		// Through signCRLLocked like every other write, handed a stored blob
		// that already carries the merged ancestors: crlChainLocked's no-file
		// path carries a stored blob's ancestors forward, so this publishes
		// exactly plan.upstream behind a freshly signed CRL of ours, with the
		// notification, cache refresh and exporter wake-up that path brings.
		merged := &storedCRL{
			own:  stored.own,
			blob: encodeCRLChain(append([]*x509.RevocationList{stored.own}, plan.upstream...)),
		}
		if err := c.signCRLLocked(ctx, merged, stored.own.RevokedCertificateEntries); err != nil {
			return err
		}
		rewritten = true
		events = append(events, mergeEvent{slog.LevelInfo, "Published an updated upstream CRL chain from crl_chain.urls",
			[]any{"before", len(published), "after", len(plan.upstream)}})
		// Counted only once the shrunken chain is actually written: a removal
		// is a transition, and one that failed to land did not happen.
		for _, r := range plan.removed {
			c.crlChainRemoved.Add(1)
			events = append(events, r)
		}
		return nil
	})

	for _, e := range events {
		slog.Log(ctx, e.level, e.msg, e.args...)
	}
	if err != nil {
		// Recorded failures stand -- an entry that fetched nothing failed
		// whatever happened next, and one judged before the write failed was
		// judged on what it served -- but no entry is credited with a success
		// that did not land. Before judging, verdicts holds only fetch
		// failures; after, the plan's too.
		for i, f := range fetched {
			if verdicts[i] != nil {
				c.recordFetchFailure(f.URL, verdicts[i])
			}
		}
		return UpstreamMergeResult{Verdicts: verdicts}, err
	}
	for i, f := range fetched {
		if verdicts[i] != nil {
			c.recordFetchFailure(f.URL, verdicts[i])
			continue
		}
		if s := c.upstreamFetch[f.URL]; s != nil {
			s.lastSuccess.Store(now.Unix())
		}
	}
	return UpstreamMergeResult{Rewritten: rewritten, Usable: usable, Verdicts: verdicts}, nil
}

// recordFetchFailure counts and logs an entry that did not yield a usable,
// current CRL. The reason says what happened; whether the round still merged
// something for that ancestor is in the round's own log line.
func (c *CA) recordFetchFailure(entry string, reason error) {
	if s := c.upstreamFetch[entry]; s != nil {
		s.failures.Add(1)
	}
	slog.Warn("Could not use an upstream CRL from crl_chain.urls", "url", entry, "error", reason)
}

// authenticatedEntry reports whether a crl_chain.urls entry's content arrives
// over a channel an attacker on the path cannot rewrite: https:// (the client
// never follows a redirect to http://) or a local file:/// path.
func authenticatedEntry(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "file")
}

// upstreamMergePlan is what a round would publish.
type upstreamMergePlan struct {
	upstream []*x509.RevocationList
	// removed holds one log line per ancestor an authoritative round drops; the
	// caller counts and logs them once the write lands.
	removed []mergeEvent
	events  []mergeEvent
}

// planUpstreamMerge judges each fetched CRL, filling verdicts, and works out
// the upstream blocks to publish. It changes nothing but verdicts and the
// discard and regression counters, which describe what was offered rather than
// what was published.
//
// c.mu must be held by the caller.
func (c *CA) planUpstreamMerge(issuers []*x509.Certificate, published []*x509.RevocationList,
	fetched []UpstreamFetch, verdicts []error, now time.Time) upstreamMergePlan {

	var plan upstreamMergePlan
	note := func(level slog.Level, msg string, args ...any) {
		plan.events = append(plan.events, mergeEvent{level, msg, args})
	}

	// Each entry's ancestor, by signing certificate rather than issuer DN; see
	// signerOf for why.
	signers := make([]*x509.Certificate, len(fetched))
	ignored := make([]bool, len(fetched))
	for i, f := range fetched {
		if verdicts[i] != nil {
			continue
		}
		if c.ownsCRL(f.CRL) {
			// Ignored rather than left to make every round partial: the entry
			// names no ancestor, so it says nothing about which ones the list
			// covers. Still a failure, so the alert names the URL to fix.
			ignored[i] = true
			verdicts[i] = errors.New("it serves this CA's own CRL, which is always rebuilt from the inventory")
			continue
		}
		s := signerOf(issuers, f.CRL)
		if s == nil {
			c.crlChainDiscarded.Add(1)
			verdicts[i] = fmt.Errorf("no certificate in the CA bundle signed its CRL (issuer %q)",
				f.CRL.Issuer.String())
			continue
		}
		if scope, partial := PartialScope(f.CRL); partial {
			// Genuinely signed, but not the ancestor's whole list: published in
			// its place it would un-revoke what it leaves out, and then block
			// the real full CRL as a regression. Over plain http:// an attacker
			// on the path could serve one, so refusing it is what keeps "the
			// most such an attacker can do is withhold" true. Discarded, as in
			// crl_chain.file, and the entry names no ancestor for the round.
			c.crlChainDiscarded.Add(1)
			verdicts[i] = fmt.Errorf("its CRL is partial (%s), not its issuer's full list (issuer %q)",
				scope, f.CRL.Issuer.String())
			continue
		}
		signers[i] = s
	}
	complete, authenticated, unambiguous, noneOwn := true, true, true, true
	named := make(map[string]bool, len(fetched))
	for i, f := range fetched {
		if !authenticatedEntry(f.URL) {
			authenticated = false
		}
		if ignored[i] {
			noneOwn = false
			continue
		}
		if signers[i] == nil {
			complete = false
			continue
		}
		if named[string(signers[i].Raw)] {
			unambiguous = false
		}
		named[string(signers[i].Raw)] = true
	}
	removing := complete && authenticated && noneOwn && unambiguous

	// The newest published CRL per ancestor, as monotonicUpstream takes it.
	current := newestPerAncestor(issuers, published)
	// The newest this round offers per ancestor, when two entries serve one.
	// Mirrors are a supported configuration, so two serving the same CRL say
	// nothing; one that differs is worth an Info line naming both, since a
	// lagging mirror is the usual cause. A mirror pointed at the wrong CA does
	// not reach here -- it names another ancestor -- and the round's loss of
	// authority over the unserved one is logged below.
	best := make(map[string]*x509.RevocationList, len(fetched))
	bestURL := make(map[string]string, len(fetched))
	for i, f := range fetched {
		if s := signers[i]; s != nil {
			key := string(s.Raw)
			if prev, ok := best[key]; ok {
				if bytes.Equal(prev.Raw, f.CRL.Raw) {
					continue
				}
				used, other := bestURL[key], f.URL
				if newerCRL(f.CRL, prev) {
					used, other = other, used
				}
				note(slog.LevelInfo, "Two crl_chain.urls entries for the same ancestor served different CRLs; "+
					"using the newer", "issuer", f.CRL.Issuer.String(), "used", used, "other", other)
				if !newerCRL(f.CRL, prev) {
					continue
				}
			}
			best[key] = f.CRL
			bestURL[key] = f.URL
		}
	}

	for i, f := range fetched {
		s := signers[i]
		if s == nil {
			continue
		}
		// Judged against the published CRL, not against a sibling entry: a
		// mirror that lags another but is as new as what agents already hold
		// is current, which is the success rule.
		prev, hasPrev := current[string(s.Raw)]
		switch {
		case hasPrev && newerCRL(prev, f.CRL):
			c.crlChainRegressed.Add(1)
			verdicts[i] = fmt.Errorf("its CRL (number %v) is older than the one already published "+
				"(number %v); keeping the published one", f.CRL.Number, prev.Number)
			note(slog.LevelError, "crl_chain.urls served an upstream CRL older than the one already "+
				"published; keeping the published one", "url", f.URL, "issuer", f.CRL.Issuer.String())
		case !f.CRL.NextUpdate.IsZero() && now.After(f.CRL.NextUpdate):
			verdicts[i] = fmt.Errorf("its CRL expired at %s; the upstream has stopped re-signing it",
				f.CRL.NextUpdate.UTC().Format(time.RFC3339))
		}
	}

	// The CRL to publish per ancestor: the published one unless this round
	// offers a newer one. Never older, so a round cannot move an ancestor
	// backwards whatever it was served.
	final := make(map[string]*x509.RevocationList, len(current)+len(best))
	for key, crl := range current {
		final[key] = crl
	}
	for key, crl := range best {
		if prev, ok := final[key]; !ok || newerCRL(crl, prev) {
			final[key] = crl
		}
	}
	covered := make(map[string]bool, len(best))
	for key := range best {
		covered[key] = true
	}

	// Published order first, so an unchanged chain is byte-identical and
	// sameCRLSet sees no change; each ancestor once, at its first position.
	emitted := make(map[string]bool, len(final))
	unattributable := make(map[string]bool)
	for _, crl := range published {
		s := signerOf(issuers, crl)
		if s == nil {
			if !removing {
				plan.upstream = append(plan.upstream, crl)
				continue
			}
			if !unattributable[crl.Issuer.String()] {
				unattributable[crl.Issuer.String()] = true
				plan.removed = append(plan.removed, mergeEvent{slog.LevelError, msgUnattributableDropped,
					[]any{"issuer", crl.Issuer.String()}})
			}
			continue
		}
		key := string(s.Raw)
		if emitted[key] {
			continue
		}
		emitted[key] = true
		if removing && !covered[key] {
			plan.removed = append(plan.removed, mergeEvent{slog.LevelError,
				"No crl_chain.urls entry serves an ancestor whose CRL is published; dropping it. " +
					"Every entry was fetched over an authenticated channel, so the list is authoritative " +
					"-- but this cannot be undone here, because this CA cannot re-sign another CA's list",
				[]any{"issuer", crl.Issuer.String()}})
			continue
		}
		if complete && !removing && !covered[key] {
			// The list names every ancestor it covers and this is not one of
			// them -- most often an entry removed to retire it -- but the round
			// may not remove. Said each round, so an operator who meant to
			// retire it learns why it stays before its expiry alert does.
			reason := "two entries name the same ancestor"
			switch {
			case !authenticated:
				reason = "an entry is fetched over plain http://"
			case !noneOwn:
				reason = "an entry serves this CA's own CRL"
			}
			plan.events = append(plan.events, mergeEvent{slog.LevelWarn,
				"No crl_chain.urls entry serves a published ancestor, but the round may not remove it; " +
					"keeping it. See configuration.md#fetching-upstream-crls for retiring an ancestor",
				[]any{"issuer", crl.Issuer.String(), "reason", reason}})
		}
		plan.upstream = append(plan.upstream, final[key])
	}
	// Ancestors new to the chain, in configured order.
	for i := range fetched {
		s := signers[i]
		if s == nil || emitted[string(s.Raw)] {
			continue
		}
		emitted[string(s.Raw)] = true
		plan.upstream = append(plan.upstream, final[string(s.Raw)])
	}
	return plan
}
