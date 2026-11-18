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
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/certstore"
	"github.com/voxpupuli/openvox-ca/internal/fileexport"
)

// checkFileExport validates the file_export block and refuses a target that
// would write over a file something else in this configuration owns.
//
// Called before the role dispatch and the --daemon fork, for the reason the
// other preflights there give: a refusal raised past the fork goes to a stderr
// nobody reads, after the operator has been told the CA started. Every process
// runs it -- the launcher, then each child as it re-enters the command -- and
// it is a pure check on the configuration, so repeating it costs nothing.
//
// The reserved set is the managed-certificate check's -- cadir as a tree, the
// CA's own files, the serving pair, every trust anchor and CRL a client_ca
// entry reads, the config file itself -- plus every path a managed certificate
// or the CA's serving certificate writes. A target over the first group would
// replace CA state or an input the CA trusts with a published copy -- scope
// self over ca_cert_file, say, would cut the CA's own bundle down to its first
// block. A target over the second group would fight
// another writer: each pass would undo the other's write, and over a managed
// key the reconcile loop would see a key that is not its certificate's and
// reissue, revoking a serial each time.
//
// Like the managed-certificate check, this compares spellings, not inodes: a
// target reached through a symlinked directory is not caught. It is a typo
// backstop, and directory permissions are what keep the export out of places
// it should not be.
// NIST 800-53: CM-6 (Configuration Settings)
func checkFileExport(cfg *serverConfig, absCADir, configPath string) error {
	if !cfg.FileExport.Enabled() {
		return nil
	}
	if err := cfg.FileExport.Validate(); err != nil {
		return fmt.Errorf("invalid file_export config: %w", err)
	}
	reserved, err := caOwnedPaths(cfg, absCADir, configPath)
	if err != nil {
		return err
	}
	reserved = append(reserved, managedStorePaths(cfg)...)
	return checkTargetsAgainst(cfg.FileExport.Targets, reserved)
}

// checkTargetsAgainst refuses the first target that lands on a reserved path.
//
// Apart from checkFileExport so that the relative-path refusal can be driven by
// a spec. Both producers of the reserved set resolve every path with
// filepath.Abs, so no configuration reaches that branch today; it stands
// against a future producer that forgets to, and a refusal nothing can reach is
// one nothing notices being deleted.
func checkTargetsAgainst(targets []fileexport.Target, reserved []certstore.ReservedPath) error {
	for i := range targets {
		t := &targets[i]
		for _, r := range reserved {
			if strings.TrimSpace(r.Path) == "" {
				continue
			}
			if !filepath.IsAbs(r.Path) {
				// Loudly, as CheckReservedPaths does: a relative path can never
				// equal an absolute target, so skipping it would be a gap that
				// looks like a passing check.
				return fmt.Errorf("cannot compare file_export targets against %s %q: "+
					"it is not an absolute path", r.Setting, r.Path)
			}
			if !r.Covers(t.Path) {
				continue
			}
			where := "is"
			if r.Tree {
				where = "is inside"
			}
			return fmt.Errorf("invalid file_export config: target %d writes %s, which %s %s (%s): "+
				"the export replaces that file whenever it differs from storage, so give "+
				"the target a path of its own", i, t.Path, where, r.Setting, filepath.Clean(r.Path))
		}
	}
	return nil
}

// managedStorePaths lists every file a managed certificate or the CA's serving
// certificate writes, resolved as caOwnedPaths resolves its own. caOwnedPaths
// already carries the serving cert and key, so only the serving chain is added
// for that entry; a duplicate would be harmless but would name the setting
// twice.
func managedStorePaths(cfg *serverConfig) []certstore.ReservedPath {
	var out []certstore.ReservedPath
	add := func(setting, path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		out = append(out, certstore.ReservedPath{Setting: setting, Path: path})
	}
	for i := range cfg.ManagedCerts {
		f := cfg.ManagedCerts[i].Store.Files
		if f == nil {
			continue
		}
		name := fmt.Sprintf("managed_certs[%d] (%s).store.files", i, cfg.ManagedCerts[i].Certname)
		add(name+".cert", f.Cert)
		add(name+".key", f.Key)
		add(name+".ca", f.CA)
	}
	if f := servingCertFiles(cfg); f != nil {
		add("serving_cert.store.files.ca", f.CA)
	}
	return out
}

// startFileExport constructs the file exporter and starts its job in g, so the
// serve command waits for it on the way out.
//
// Unlike the Kubernetes export there is no construction step that can fail:
// the configuration was refused or accepted before the fork, and everything
// else -- a directory that is missing, a mount that is read-only -- is a sync
// failure the job reports and retries on every interval.
func startFileExport(g *goroutineGroup, cfg fileexport.Config, src fileexport.MaterialSource,
	m *fileexport.Metrics) {
	exporter := fileexport.New(cfg, src, m)
	g.Go(func(ctx context.Context) {
		runFileExporter(ctx, exporter, cfg.Interval(), len(cfg.Targets))
	})
}

// runFileExporter syncs the configured files once at startup and then every
// interval, until ctx is cancelled.
//
// A timer and nothing else, deliberately, and not the CRLUpdated() channel the
// Kubernetes exporter wakes on. That channel has one consumer, which is that
// exporter, and SyncCRLCache does not signal it when this replica picks up a
// CRL another replica re-signed -- correctly, for a Kubernetes object every
// replica writes to the same place. A file is per host. Driven by the channel,
// this replica's copy would miss every revocation made anywhere else, on
// exactly the shared backends this feature exists for.
//
// Each tick reads the material from storage and compares it with the file, so
// the files are written only when something changed: a revocation here or on
// another replica, a CA bundle change, or a file someone else edited. A
// revocation reaches the file within one interval, the same bound
// crl_sync_interval_sec puts on it reaching another replica's own checks.
//
// Failures are logged and retried on the next tick; the export never takes
// down the CA. What it cannot do is give up on a write the kernel has not
// returned from, such as one to a hung network mount. That blocks this loop,
// and the serve command's shutdown waits for it. The stale alert reports the
// first, since last_success stops moving; a service manager's stop timeout
// ends the second.
func runFileExporter(ctx context.Context, exporter *fileexport.Exporter, interval time.Duration, targets int) {
	slog.Info("Starting file export job", "interval", interval, "targets", targets)

	syncFilesOnce(ctx, exporter)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("File export job stopping")
			return
		case <-ticker.C:
			syncFilesOnce(ctx, exporter)
		}
	}
}

// syncFilesOnce runs a single sync. Per-target failures are already logged by
// SyncAll, which names each one with its error; this logs only how many there
// were. Repeating the joined error here would print every failure twice, once a
// minute, for as long as a misconfiguration lasts.
func syncFilesOnce(ctx context.Context, exporter *fileexport.Exporter) {
	if err := exporter.SyncAll(ctx); err != nil {
		failed := 1
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			failed = len(joined.Unwrap())
		}
		slog.Warn("File export cycle completed with errors", "failed_targets", failed)
		return
	}
	slog.Debug("File export cycle complete")
}
