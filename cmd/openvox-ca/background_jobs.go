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
	jobCRLRefresh    = "crl-refresh"
	jobCRLSync       = "crl-sync"
	jobOCSPIndexSync = "ocsp-index-sync"
	jobCertCleanup   = "expired-cert-cleanup"
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
	// distributing the URL another way. It *is* gated on the backend being one
	// several processes can share, which is a different question with a
	// different answer — the staleness needs a second process writing
	// certificates this one will never hear about, and on filesystem and SQLite
	// there is no supported way to have one. Running it there would read the
	// whole inventory every interval, for ever, on the default backend, to
	// detect something that cannot happen.
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
		slog.Info("OCSP serial index sync not started: the storage backend is single-node, "+
			"so no other process can issue certificates this one would not already know about",
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

	return jobs
}
