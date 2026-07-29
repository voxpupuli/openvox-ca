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
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// newCSRCmd builds the "csr" subcommand, which emits a PKCS#10 certificate
// signing request for this CA's own key so an external parent can sign it and
// make this an intermediate CA.
//
// It lives on the server binary rather than openvox-ca-ctl because it must
// reach the configured storage backend and key provider, and openvox-ca-ctl can
// address only a local filesystem directory through a different configuration
// schema. Driving it from the server's own config file is also what makes it
// work identically for every ca_key_provider without special-casing.
func newCSRCmd() *cobra.Command {
	var (
		configFile string
		caDir      string
		hostname   string
		outFile    string
		createKey  bool
	)

	cmd := &cobra.Command{
		Use:   "csr",
		Short: "Emit a certificate signing request for this CA's own key",
		Long: `Emit a PKCS#10 certificate signing request for this CA's own key, for an
external parent CA to sign.

The request carries the same subject this CA would otherwise self-sign, so the
certificate that comes back is a drop-in replacement. Sign it with the parent,
then load the resulting chain with "openvox-ca import-ca-cert".

The CA key is reached through the configured ca_key_provider, so this works
identically whether the key is a local PEM file or lives in OpenBao Transit.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadServerConfig(resolveConfigFile(configFile, "PUPPET_CA_CONFIG", "/etc/puppet-ca/config.yaml"))
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("cadir") {
				cfg.CADir = caDir
			}
			if cmd.Flags().Changed("hostname") {
				cfg.Hostname = hostname
			}

			rt, err := resolveRuntime(cmd.Context(), cfg, true)
			if err != nil {
				return err
			}
			defer func() { _ = rt.Close() }()

			myCA := ca.New(rt.Store, ca.AutosignConfig{Mode: "off"}, cfg.Hostname)
			if err := applyCAConfig(myCA, cfg); err != nil {
				return err
			}
			myCA.KeyProvider = rt.KeyProvider

			csrPEM, err := myCA.BuildCSR(cmd.Context(), cfg.Hostname, createKey)
			if err != nil {
				if errors.Is(err, ca.ErrKeyProviderKeyNotFound) {
					return fmt.Errorf("no CA key exists yet: pass --create-key to create one, "+
						"or provision it out of band first: %w", err)
				}
				return err
			}

			if outFile == "" {
				_, err := cmd.OutOrStdout().Write(csrPEM)
				return err
			}
			if err := writePublicFile(outFile, csrPEM); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.ErrOrStderr(), "Certificate signing request written to %s\n", outFile)
			return err
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/config.yaml if it exists)")
	f.StringVar(&caDir, "cadir", "", "CA storage directory (overrides the config file)")
	f.StringVar(&hostname, "hostname", "", "Hostname for the CA subject, when no CA certificate exists yet")
	f.StringVar(&outFile, "out", "", "Write the request to this file instead of stdout")
	f.BoolVar(&createKey, "create-key", false, "Create the CA key if it does not exist yet")

	return cmd
}
