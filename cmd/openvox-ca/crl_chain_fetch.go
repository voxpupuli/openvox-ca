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

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/crlfetch"
)

// crlChainFetchRetryMin is the first wait after a round in which any entry
// failed. It doubles on each further failed round, up to the refresh interval:
// soon enough that a blip at startup costs seconds rather than an hour, and
// spaced out enough that an upstream that stays down is not hammered.
const crlChainFetchRetryMin = 30 * time.Second

// crlChainFetch is what the fetch job needs: what each round fetches, and when
// the rounds run.
type crlChainFetch struct {
	urls     []string
	http     config.HTTPClientConfig
	timeout  time.Duration
	interval time.Duration
	retryMin time.Duration
	// wait sleeps for d, or until ctx is done, reporting whether it slept the
	// whole time. nil is a real timer; a spec supplies one to see the
	// schedule without depending on the clock.
	wait func(ctx context.Context, d time.Duration) bool
}

// crlChainFetchFor is what the job needs, from the configuration. A function
// of its own so a spec can see that every setting reaches the job -- a dropped
// http_config would discard tls_config.ca_file, and every fetch from a
// private-CA upstream would then fail TLS with nothing in the job to say why.
// The interval and the first retry are named fields rather than two durations
// passed side by side, so they cannot be swapped without the spec noticing.
func crlChainFetchFor(cfg *serverConfig) crlChainFetch {
	return crlChainFetch{
		urls:     cfg.CRLChain.URLs,
		http:     cfg.CRLChain.HTTPConfig,
		timeout:  cfg.crlChainFetchTimeout(),
		interval: cfg.crlChainRefreshInterval(),
		retryMin: crlChainFetchRetryMin,
	}
}

func (f crlChainFetch) sleep(ctx context.Context, d time.Duration) bool {
	if f.wait != nil {
		return f.wait(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// roundOutcome is how a fetch round went, which decides when the next runs.
type roundOutcome int

const (
	// roundClean: every entry yielded a usable, current CRL.
	roundClean roundOutcome = iota
	// roundEntryFailed: at least one entry did not; what the others yielded
	// was merged. Also what a round abandoned for shutdown returns, though
	// nothing was merged or counted then: the caller is stopping anyway.
	roundEntryFailed
	// roundMergeFailed: the merge itself failed -- the CRL lock, a storage
	// read or write -- so nothing landed.
	roundMergeFailed
)

// runCRLChainFetcher fetches crl_chain.urls on the refresh interval and merges
// what it gets into the published chain.
//
// One timer, on a fixed interval, rather than one keyed to each CRL's
// nextUpdate: an upstream that revokes publishes a new CRL at once, and
// nextUpdate is a deadline rather than a publication schedule, so waiting for
// a fraction of a CRL's life would hold an upstream revocation back by that
// much. The interval is what bounds how long one takes to reach agents.
//
// The first round runs immediately: on a fresh store nothing else will
// publish the chain. After a round with a failed entry the next comes sooner,
// backing off from retryMin to the interval. A round whose merge failed is a
// storage fault rather than an upstream one, and is retried at the interval,
// like every other CRL writer's: each such failure counts into
// crl_update_failures_total, and retrying on the backoff would turn a backend
// restart of a minute or two into several counts and a page. The exception is
// a pod whose readiness is held, which has nothing to serve until a merge
// lands, and so keeps the backoff.
//
// Every replica runs it. The merge decides inside the CRL lock, so the first
// replica to merge a change writes it and the rest find nothing to do; no
// coordination beyond the stored chain is needed. It returns when ctx is
// cancelled (i.e. on shutdown).
func runCRLChainFetcher(ctx context.Context, c *ca.CA, f crlChainFetch) {
	slog.Info("Starting CRL chain fetch job", "urls", len(f.urls), "interval", f.interval)
	backoff := f.retryMin
	for {
		wait := f.interval
		switch out := fetchCRLChainOnce(ctx, c, f); {
		case out == roundClean:
			backoff = f.retryMin
		case out == roundMergeFailed && !c.UpstreamChainHeld():
			// The interval, as above; the backoff is left where it was.
		default:
			wait = min(backoff, f.interval)
			backoff = min(backoff*2, f.interval)
		}
		if !f.sleep(ctx, wait) {
			slog.Debug("CRL chain fetch job stopping")
			return
		}
	}
}

// fetchCRLChainOnce runs one round and reports how it went. A round that
// leaves an upstream CRL stored also releases the readiness hold, if one was
// taken. Failures are logged and counted by the CA, per entry; nothing here
// stops the job.
//
// The fetcher, and with it the HTTP client, is built per round, so a rotated
// tls_config.ca_file is picked up at the next round. A client that cannot be
// built fails every http(s) entry with the reason, which is what the per-URL
// failure counter and its alert then name; file:/// entries are read as usual.
func fetchCRLChainOnce(ctx context.Context, c *ca.CA, f crlChainFetch) roundOutcome {
	fetches := make([]ca.UpstreamFetch, len(f.urls))
	fetcher, err := crlfetch.New(ctx, f.urls, f.http, f.timeout)
	if err != nil {
		// Only an entry that does not parse fails New, and Validate has
		// already refused one; a client that cannot be built is not this
		// branch, but each http(s) entry's own result above.
		for i, u := range f.urls {
			fetches[i] = ca.UpstreamFetch{URL: u, Err: err}
		}
	} else {
		for i, r := range fetcher.Fetch(ctx) {
			fetches[i] = ca.UpstreamFetch{URL: r.URL, CRL: r.CRL, Err: r.Err}
		}
		fetcher.Close()
	}
	// A shutdown that overlaps a round fails every entry still in flight,
	// through no upstream's fault, so abandon the round: merging it would
	// count it against each URL and log a failure per entry, for what is only
	// a stop.
	if ctx.Err() != nil {
		slog.Debug("CRL chain fetch round abandoned for shutdown")
		return roundEntryFailed
	}

	res, err := c.MergeFetchedUpstreamCRLs(ctx, fetches)
	if err != nil {
		slog.Error("Could not merge fetched upstream CRLs into the published chain", "error", err)
		return roundMergeFailed
	}
	if res.Rewritten {
		slog.Debug("CRL chain fetch round published a change")
	}
	// Readiness is released on the same condition it was held on: once the
	// stored chain holds an upstream CRL. Releasing on anything stricter would
	// make readiness depend on a pod's age -- a restart would find the CRL
	// stored and never hold at all, while the pods already running stayed out
	// of the Service.
	if res.Usable && c.ReleaseUpstreamChainHold() {
		slog.Info("Fetched the upstream CRL chain; readiness is no longer held")
	}
	for _, v := range res.Verdicts {
		if v != nil {
			return roundEntryFailed
		}
	}
	return roundClean
}
