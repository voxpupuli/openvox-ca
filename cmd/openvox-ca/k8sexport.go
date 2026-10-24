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
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// k8sExportRetryInterval is how long a failed export cycle waits before it is
// retried. Exports are otherwise driven only by startup and CRL updates, which
// on a low-churn CA can be weeks apart, so without a retry a single transient
// storage or API-server error leaves every target holding a stale CA
// certificate or CRL until the CRL next changes.
//
// Two minutes sits well inside k8sExportFailingFor (15m), the debounce on
// PuppetCAKubernetesExportFailing: a cycle that recovers on the first retry or
// two resolves before the alert would have paged, while one that keeps failing
// keeps re-stamping last_error and stays firing. A failure that outlasts the
// debounce still pages, as it should.
//
// Deliberate consequence, not an oversight: a target that fails its first
// attempt and succeeds on retry every cycle never pages, because last_success
// always overtakes last_error inside the debounce. Before this retry existed
// such a target did page. See docs/kubernetes-export.md.
const k8sExportRetryInterval = 2 * time.Minute

// startK8sExport constructs the exporter and starts its job, or -- if it cannot
// be constructed -- makes that failure reportable.
//
// The failure branch is why this is a function rather than wiring in its
// caller. newExporter fails when there is no in-cluster client to build or no
// pod namespace to resolve, and the CA then carries on serving with readiness
// green while the configured targets silently freeze at whatever they last
// held. Publishing the apply counters at zero is what turns that into something
// PuppetCAKubernetesExportNotRunning can match; the log line alone reaches
// nobody who is not already reading logs.
//
// newExporter is a parameter so a spec can drive both branches. This lived
// inside a cobra RunE before, which meant the one line closing that alerting
// gap could be deleted without a single test noticing.
//
// The job runs in g, so the serve command waits for it on the way out.
func startK8sExport(g *goroutineGroup, c *ca.CA, cfg k8sexport.Config, m *k8sexport.Metrics,
	newExporter func() (*k8sexport.Exporter, error),
) {
	exporter, err := newExporter()
	if err != nil {
		k8sexport.InitTargetMetrics(cfg, m)
		slog.Error("Kubernetes export disabled: failed to initialise client", "error", err)
		return
	}
	g.Go(func(ctx context.Context) {
		runK8sExporter(ctx, c, exporter, k8sExportRetryInterval)
	})
}

// runK8sExporter publishes the CA certificate and CRL into the configured
// Kubernetes Secrets/ConfigMaps. It exports once at startup (reconciling state
// after restarts, config changes, or a CA import) and then re-exports whenever
// the CRL is updated (revoke, reissue, background refresh, or expired-cert
// cleanup), so CRL-bearing objects stay current.
//
// A cycle in which any target failed is retried after retryInterval, and keeps
// being retried until one succeeds completely. The CRL-update signal alone is
// not enough: it can be weeks away on a quiet CA, which would leave a target
// stale for that long after a momentary failure.
//
// It runs in the frontend process, reading the cert/CRL through the storage
// service. Export failures are logged and swallowed: the export is auxiliary
// and must never take down the CA. It returns when ctx is cancelled (i.e. on
// shutdown).
func runK8sExporter(ctx context.Context, c *ca.CA, exporter *k8sexport.Exporter, retryInterval time.Duration) {
	slog.Info("Starting Kubernetes export job", "retry_interval", retryInterval)

	// Created disarmed; armed only while the last cycle failed. Go 1.23+ timer
	// semantics mean Stop and Reset need no channel drain, and a fire that
	// races with Stop cannot be received afterwards.
	retry := time.NewTimer(retryInterval)
	retry.Stop()
	defer retry.Stop()

	// runCycle exports once and re-arms (or disarms) the retry timer to match
	// the outcome, so a recovered cycle stops retrying and a still-failing one
	// keeps going.
	runCycle := func() {
		retry.Stop()
		if !exportK8sOnce(ctx, exporter) {
			retry.Reset(retryInterval)
		}
	}

	runCycle()

	for {
		select {
		case <-ctx.Done():
			slog.Debug("Kubernetes export job stopping")
			return
		case <-c.CRLUpdated():
			slog.Debug("CRL updated, re-exporting to Kubernetes")
			runCycle()
		case <-retry.C:
			slog.Debug("Retrying failed Kubernetes export cycle")
			runCycle()
		}
	}
}

// exportK8sOnce runs a single reconcile, logging the outcome, and reports
// whether every target succeeded. Per-target errors are already logged by
// ExportAll; here we log only that the cycle had failures.
func exportK8sOnce(ctx context.Context, exporter *k8sexport.Exporter) bool {
	if err := exporter.ExportAll(ctx); err != nil {
		slog.Warn("Kubernetes export cycle completed with errors", "error", err)
		return false
	}
	slog.Debug("Kubernetes export cycle complete")
	return true
}
