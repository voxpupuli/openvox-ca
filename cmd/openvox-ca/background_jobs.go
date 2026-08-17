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
)

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
	// reported as `unknown` within an interval rather than never. Read-only,
	// takes no cluster lock, and — like crl-sync — runs unconditionally: the
	// /ocsp endpoint answers whatever ocsp_url says, so gating this on it would
	// leave the responder wrong for anyone distributing the URL another way.
	ocspIndexInterval := cfg.ocspIndexSyncInterval()
	jobs = append(jobs, backgroundJob{jobOCSPIndexSync, func(ctx context.Context) {
		runOCSPIndexSync(ctx, myCA, ocspIndexInterval)
	}})

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
