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
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// sharedStorageBackend reports whether name is a backend more than one CA
// process can be serving from at once, and echoes the parsed kind for logging.
//
// Only filesystem and SQLite are not: both are a local file with no
// cross-process coordination (see docs/development/locking.md on #187), so a
// second writer is not a configuration this project supports rather than one it
// merely does not expect. Everything else is reachable by several replicas by
// design, which is what makes an in-memory index built at startup go stale.
//
// A name that will not parse is treated as shared. The cost of that mistake is
// a periodic inventory read; the cost of the opposite one is a responder
// quietly answering `unknown` for certificates its peers have signed.
func sharedStorageBackend(name string) (bool, storage.BackendKind) {
	kind, err := storage.ParseBackendKind(name)
	if err != nil {
		return true, storage.BackendKind(name)
	}
	return kind != storage.BackendFilesystem && kind != storage.BackendSQLite, kind
}

// Background job names, as reported by backgroundJobs. Constants rather than
// literals so a spec asserting which jobs a configuration starts cannot drift
// from the thing it is asserting about.
const (
	jobCRLRefresh      = "crl-refresh"
	jobCRLSync         = "crl-sync"
	jobOCSPIndexSync   = "ocsp-index-sync"
	jobCertCleanup     = "expired-cert-cleanup"
	jobSupersededSweep = "superseded-cert-revocation"
	jobCRLChainRefresh = "crl-chain-refresh"
)

// backgroundJob is one periodic job the serve command runs for the lifetime of
// its context.
type backgroundJob struct {
	name string
	run  func(ctx context.Context)
}

// backgroundJobs decides which periodic jobs a configuration starts, without
// starting them.
//
// The deciding is separated from the doing for one reason: which jobs a
// configuration runs is a promise this project makes to operators, and inline
// `go` statements in a cobra RunE are a promise nothing can check. In
// particular, CRL sync must run whatever `disable_crl_refresh` says — that
// switch governs whether this deployment re-signs the CRL, not whether
// revocations performed elsewhere reach this replica — and before this function
// existed the only thing keeping the two apart was which side of a brace the
// statement sat on. Now a spec can say so.
//
// The returned closures each block until ctx is cancelled; the caller runs them
// in their own goroutines.
func backgroundJobs(cfg *serverConfig, myCA *ca.CA) []backgroundJob {
	var jobs []backgroundJob

	// Keeps the CRL's NextUpdate from lapsing on a low-churn CA. Safe on every
	// replica: the work is serialised on the shared CRL lock, so only the first
	// to take it re-signs. Disablable, for a deployment that drives re-signing
	// externally.
	if !cfg.DisableCRLRefresh {
		refreshBefore := myCA.DefaultCRLRefreshBefore()
		if cfg.CRLRefreshBeforeSec > 0 {
			refreshBefore = time.Duration(cfg.CRLRefreshBeforeSec) * time.Second
		}
		interval := cfg.crlRefreshInterval()
		jobs = append(jobs, backgroundJob{jobCRLRefresh, func(ctx context.Context) {
			runCRLRefresher(ctx, myCA, interval, refreshBefore)
		}})
	} else {
		slog.Info("CRL auto-refresh disabled by configuration")
	}

	// Reloads the stored CRL into the copy this process's revocation checks
	// read, so a certificate revoked on another replica stops working here
	// within an interval rather than whenever this replica happens to re-sign.
	// Read-only, takes no cluster lock, and runs unconditionally — see the note
	// above about disable_crl_refresh.
	syncInterval := cfg.crlSyncInterval()
	jobs = append(jobs, backgroundJob{jobCRLSync, func(ctx context.Context) {
		runCRLSync(ctx, myCA, syncInterval)
	}})

	// Reloads the inventory into the serial index this process's OCSP responder
	// answers from, so a certificate signed on another replica stops being
	// reported as `unknown` within an interval rather than never. Read-only and
	// takes no cluster lock.
	//
	// Not gated on ocsp_url: the /ocsp endpoint answers whatever that setting
	// says, so gating on it would leave the responder wrong for anyone
	// distributing the URL another way. It *is* gated on the backend, which is a
	// different question with a different answer.
	//
	// The staleness needs a second process *issuing* certificates this one will
	// never hear about, and on these two backends there is not supposed to be
	// one. A backend without distributed locking supports exactly one running
	// instance: nothing reconciles the serial index, OCSP cache and cached CRL
	// that each process holds privately, so a second instance issues
	// certificates the first never learns of and a revocation on one leaves the
	// other still authenticating the revoked certificate. The server takes a
	// store-wide lock at startup to hold operators to that — a second
	// `openvox-ca` fails to start, and an `openvox-ca-ctl` or offline command
	// run beside a live server is refused and told which process holds it.
	//
	// The gate rests on that rule and deliberately not on a list of the callers
	// that write, which is what this comment used to do: it enumerated them
	// ("nothing under cmd/ outside the server calls AppendInventory,
	// issueLeafLocked, CA.Generate or SignWithTTL", pinned to 65a00adb51f9) and
	// #189's offline `generate` falsified it by calling CA.Generate on every
	// backend. The conclusion survived, which is the whole reason to state a
	// rule instead: #189 documents filesystem and SQLite as *stop the server*
	// for that command (docs/operator-cli.md, "Running alongside a live
	// server"), and a server stopped while a certificate was minted offline
	// rebuilds its serial index when it next starts, so the index cannot fall
	// behind. An enumeration is falsified by any new caller. The rule is not.
	//
	// Running the job on those two backends would read the whole inventory
	// every interval, for ever, on the default backend, to mitigate one symptom
	// of a configuration that is not supported and that the startup lock now
	// refuses on the host where it can be detected at all.
	//
	// An unrecognised backend name runs the job. Being wrong in that direction
	// costs a periodic read; being wrong in the other costs correct OCSP
	// answers, silently, until a restart.
	if shared, kind := sharedStorageBackend(cfg.StorageBackend); shared {
		ocspIndexInterval := cfg.ocspIndexSyncInterval()
		jobs = append(jobs, backgroundJob{jobOCSPIndexSync, func(ctx context.Context) {
			runOCSPIndexSync(ctx, myCA, ocspIndexInterval)
		}})
	} else {
		slog.Info("OCSP serial index sync not started: this storage backend supports one running "+
			"instance, so no other process should be issuing certificates this one would not "+
			"already know about",
			"backend", kind)
	}

	// Prunes certificates that expired more than the retention grace period ago
	// from the inventory and the CRL. Opt-in; safe on every replica.
	if cfg.EnableExpiredCertCleanup {
		interval, retention := cfg.expiredCertCleanupInterval(), cfg.expiredCertRetention()
		jobs = append(jobs, backgroundJob{jobCertCleanup, func(ctx context.Context) {
			runCertCleaner(ctx, myCA, interval, retention)
		}})
	}

	// Revokes the certificates renewals have replaced, once the configured
	// delay has elapsed. Runs unconditionally — including when the delay is
	// zero — because it is the only thing that drains a list an earlier
	// configuration may have filled; see runSupersededSweeper. Idle passes take
	// no cluster lock, so that costs a read per interval on a CA that never
	// enables a window. Safe on every replica: the work, when there is any, is
	// serialised on the shared CRL lock.
	sweepInterval := cfg.supersededCertSweepInterval()
	jobs = append(jobs, backgroundJob{jobSupersededSweep, func(ctx context.Context) {
		runSupersededSweeper(ctx, myCA, sweepInterval)
	}})
	// Re-reads crl_chain_file and republishes the CRL when the upstream CRLs it
	// names have changed.
	//
	// Gated on crl_chain_file alone, and deliberately not on any other feature:
	// an operator publishing an upstream chain need not be running expired-cert
	// cleanup or re-signing on a timer. Under Puppet's default
	// certificate_revocation = chain, an expired ancestor CRL is not stale data
	// but a scheduled fleet-wide verification failure that clears only on
	// restart, so the job that notices must not be reachable only through
	// somebody else's switch.
	if cfg.CRLChainFile != "" {
		chainInterval := cfg.crlChainRefreshInterval()
		jobs = append(jobs, backgroundJob{jobCRLChainRefresh, func(ctx context.Context) {
			runCRLChainRefresher(ctx, myCA, cfg.CRLChainFile, chainInterval)
		}})
	}

	return jobs
}
