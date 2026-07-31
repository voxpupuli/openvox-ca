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

// maintenanceTask is one unit of periodic upkeep. Each is individually gated,
// and the loop runs whenever any of them is enabled.
//
// The loop is named for itself rather than for its first tenant, and that is
// not cosmetic. The obvious alternatives both have the same bug in different
// clothes: folding these into runCRLRefresher means disable_crl_refresh
// silently disables serving-certificate renewal too, and gating the goroutine
// on tls_self_provision means a deployment that supplies its certificate from a
// Secret never runs any of the other tasks. Naming an interval after one
// feature is what makes gating it on that feature look reasonable.
type maintenanceTask struct {
	name string
	run  func(ctx context.Context)
}

// runMaintenance runs tasks on a fixed interval until ctx is cancelled.
//
// Every task runs once immediately, so work that fell due while all replicas
// were down is picked up without waiting a full interval.
//
// A task that fails logs and is retried on the next tick; it never stops the
// loop and never stops its siblings. Startup is where a failure is fatal —
// there is no certificate to fall back on — whereas here there is one already
// in place, and the renewal window leaves roughly a third of the leaf lifetime
// of runway for a transient storage outage to clear.
func runMaintenance(ctx context.Context, interval time.Duration, tasks []maintenanceTask) {
	if len(tasks) == 0 {
		return
	}
	names := make([]string, 0, len(tasks))
	for _, t := range tasks {
		names = append(names, t.name)
	}
	slog.Info("Starting maintenance loop", "interval", interval, "tasks", names)

	runAll := func() {
		for _, t := range tasks {
			t.run(ctx)
		}
	}
	runAll()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Maintenance loop stopping")
			return
		case <-ticker.C:
			runAll()
		}
	}
}

// supersededRevocationTask revokes serving certificates whose delay has
// elapsed, and reconciles the list when the delay is switched off.
//
// Registered whenever self-provisioning is on, including when the delay is
// zero: with the delay at zero the pass discards entries a previously non-zero
// setting recorded, so turning revocation off does not strand a revocation that
// would then fire much later if it were turned back on.
func supersededRevocationTask(myCA *ca.CA, cfg *serverConfig) maintenanceTask {
	return maintenanceTask{
		name: "serving-cert-superseded-revocation",
		run: func(ctx context.Context) {
			if err := myCA.ReconcileSuperseded(ctx, servingConfigFrom(cfg)); err != nil {
				// The list is left intact, so the next pass retries. A
				// superseded certificate staying valid is better than a
				// revocation this replica cannot record — but only until the
				// sweep succeeds, so a pass that keeps failing is counted as
				// well as logged. crlUpdateFailures does not cover it: the
				// failures this path hits first are a lock timeout or a storage
				// error on the pending list, neither of which is a CRL
				// amendment.
				myCA.IncServingRevocationFailures()
				slog.Error("Could not reconcile superseded serving certificates", "error", err)
			}
		},
	}
}

// crlChainFileTask re-reads crl_chain_file and republishes the CRL when the
// upstream CRLs it names have changed.
//
// Gated on crl_chain_file rather than on any other feature. That is the whole
// reason runMaintenance is a shared loop with per-task gates: in the chart's
// own recommended shape — a certificate from a Secret, self-provisioning off —
// a tls_self_provision-gated loop would never run, and the ancestor CRLs would
// be read once at startup and never again. Under Puppet's default
// certificate_revocation = chain an expired ancestor CRL is not stale data but
// a scheduled fleet-wide verification failure, clearing only on restart.
func crlChainFileTask(myCA *ca.CA, cfg *serverConfig) maintenanceTask {
	return maintenanceTask{
		name: "crl-chain-file",
		run: func(ctx context.Context) {
			rewritten, err := myCA.RefreshCRLChainFile(ctx)
			switch {
			case err != nil:
				slog.Error("Could not refresh the upstream CRL chain",
					"path", cfg.CRLChainFile, "error", err)
			case rewritten:
				slog.Info("Published an updated CRL chain", "path", cfg.CRLChainFile)
			default:
				slog.Debug("Upstream CRL chain unchanged", "path", cfg.CRLChainFile)
			}
		},
	}
}

// servingRenewalTask reissues the serving certificate when it falls into its
// renewal window, and swaps the holder so the next handshake uses it.
func servingRenewalTask(myCA *ca.CA, cfg *serverConfig, holder *servingCertHolder) maintenanceTask {
	return maintenanceTask{
		name: "serving-cert-renewal",
		run: func(ctx context.Context) {
			if err := ensureServingCert(ctx, myCA, cfg, holder); err != nil {
				// Leave the existing certificate in place and retry next cycle.
				// The counter matters more than the log line: a permanently
				// failing renewal is otherwise invisible until the certificate
				// expires, and it is also what breaks the bound on how long a
				// superseded certificate stays in use.
				myCA.IncServingRenewalFailures()
				slog.Error("Serving certificate renewal failed; keeping the current certificate",
					"error", err)
			}
		},
	}
}

// crlChainMaintenanceTasks returns the tasks crl_chain_file needs, and none at
// all when it is unset.
//
// Independently gated: an operator publishing an upstream CRL chain need not
// also be self-provisioning a certificate, which is the chart's own recommended
// shape. Collected here rather than inlined in the serve command so that gate
// is a proposition a spec can check -- inline, registering it under the wrong
// condition compiled, passed, and left the ancestor CRLs read once at startup
// and never again.
func crlChainMaintenanceTasks(myCA *ca.CA, cfg *serverConfig) []maintenanceTask {
	if cfg.CRLChainFile == "" {
		return nil
	}
	return []maintenanceTask{crlChainFileTask(myCA, cfg)}
}
