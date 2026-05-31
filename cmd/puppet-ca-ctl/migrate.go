// Copyright (C) 2026 Chris Boot
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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/tvaughan/puppet-ca/internal/config"
	"github.com/tvaughan/puppet-ca/internal/storage"
	"go.yaml.in/yaml/v3"
)

// migrateFileConfig is the subset of a puppet-ca server config file needed to
// open a storage backend for migration: the backend selection and its
// parameters (via the shared config.StorageConfig), plus cadir. cadir is the
// backend root for the filesystem backend and, for remote backends, the local
// directory the spec validator requires (migration never touches the
// per-subject private keys kept there).
type migrateFileConfig struct {
	CADir                string `yaml:"cadir"`
	config.StorageConfig `yaml:",inline"`
}

// loadMigrateConfig reads and parses one backend config file.
func loadMigrateConfig(path string) (migrateFileConfig, error) {
	var c migrateFileConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("parsing %s: %w", path, err)
	}
	return c, nil
}

// backendSpec turns the file config into a storage.BackendSpec, resolving
// cadir to an absolute path so logs and errors show canonical locations.
func (c migrateFileConfig) backendSpec() (storage.BackendSpec, error) {
	localDir := c.CADir
	if localDir != "" {
		abs, err := filepath.Abs(localDir)
		if err != nil {
			return storage.BackendSpec{}, fmt.Errorf("resolving cadir %q: %w", localDir, err)
		}
		localDir = abs
	}
	return c.StorageConfig.ToBackendSpec(localDir)
}

func newMigrateCmd() *cobra.Command {
	var sourceConfig, destConfig string
	var force bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Copy all CA data from one storage backend to another (offline)",
		Long: `Copy every stored CA asset from a source storage backend to a destination
backend: the CA certificate and key, public key, CRL, serial, inventory (with
its integrity HMAC), all pending CSRs and all signed certificates.

Both backends are described by ordinary puppet-ca config files (the same YAML
format the server reads): --source-config selects the backend to read from and
--dest-config the backend to write to. Any pair of backends may be combined, so
this can import a filesystem CA into a database, move data between databases
(e.g. Valkey to PostgreSQL), or export a database back to a directory of files.

By default migrate refuses to write into a destination that already holds a CA
certificate; pass --force to overwrite it.

The server must not be running against either backend during migration.

Per-subject generated private keys are NOT migrated: they always live on the
local filesystem under cadir, never in a storage backend.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			srcCfg, err := loadMigrateConfig(sourceConfig)
			if err != nil {
				return fmt.Errorf("source config: %w", err)
			}
			dstCfg, err := loadMigrateConfig(destConfig)
			if err != nil {
				return fmt.Errorf("destination config: %w", err)
			}

			srcSpec, err := srcCfg.backendSpec()
			if err != nil {
				return fmt.Errorf("source backend: %w", err)
			}
			dstSpec, err := dstCfg.backendSpec()
			if err != nil {
				return fmt.Errorf("destination backend: %w", err)
			}

			srcSvc, err := storage.NewServiceFromSpec(srcSpec)
			if err != nil {
				return fmt.Errorf("opening source backend: %w", err)
			}
			defer func() { _ = srcSvc.Backend().Close() }()

			dstSvc, err := storage.NewServiceFromSpec(dstSpec)
			if err != nil {
				return fmt.Errorf("opening destination backend: %w", err)
			}
			defer func() { _ = dstSvc.Backend().Close() }()

			report, err := storage.MigrateService(cmd.Context(), srcSvc, dstSvc, storage.MigrateOptions{
				Force: force,
				Logf: func(format string, a ...any) {
					if globalVerbose {
						fmt.Fprintf(os.Stderr, format+"\n", a...)
					}
				},
			})
			if err != nil {
				return err
			}

			fmt.Printf("Migration complete: %d CA/state blob(s), %d CSR(s), %d signed cert(s) copied (%d total)\n",
				report.Singletons, report.CSRs, report.Certs, report.Total())
			return nil
		},
	}
	cmd.Flags().StringVar(&sourceConfig, "source-config", "", "Path to puppet-ca config file describing the SOURCE backend")
	cmd.Flags().StringVar(&destConfig, "dest-config", "", "Path to puppet-ca config file describing the DESTINATION backend")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing CA in the destination backend")
	_ = cmd.MarkFlagRequired("source-config")
	_ = cmd.MarkFlagRequired("dest-config")
	return cmd
}
