// Copyright (C) 2026 Trevor Vaughan
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
	"os"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// ctlConfig holds all configuration for openvox-ca-ctl.
// Fields are populated from (lowest → highest priority):
//
//	built-in defaults → config file → env vars → CLI flags
type ctlConfig struct {
	ServerURL  string `yaml:"server_url"`
	CACert     string `yaml:"ca_cert"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
	Verbose    bool   `yaml:"verbose"`
	Insecure   bool   `yaml:"insecure"`
}

// loadCtlConfig applies built-in defaults, optionally loads a YAML config
// file, then overlays environment variables. configFile may be "" to skip file
// loading.
func loadCtlConfig(configFile string) (*ctlConfig, error) {
	cfg := &ctlConfig{
		ServerURL: "https://localhost:8140",
	}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("reading config file %s: %w", configFile, err)
		}
		// Strict, like the server's: a misspelt key refuses to run rather
		// than leaving the real setting at its default.
		if err := config.DecodeStrict(data, cfg, "openvox-ca-ctl"); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", configFile, err)
		}
	}

	if err := applyCtlEnv(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyCtlEnv overlays OPENVOX_CA_CTL_* environment variables onto cfg. A
// boolean variable whose value does not parse is an error naming it.
func applyCtlEnv(cfg *ctlConfig) error {
	if v := os.Getenv("OPENVOX_CA_CTL_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("OPENVOX_CA_CTL_CA_CERT"); v != "" {
		cfg.CACert = v
	}
	if v := os.Getenv("OPENVOX_CA_CTL_CLIENT_CERT"); v != "" {
		cfg.ClientCert = v
	}
	if v := os.Getenv("OPENVOX_CA_CTL_CLIENT_KEY"); v != "" {
		cfg.ClientKey = v
	}
	return errors.Join(
		config.EnvBool("OPENVOX_CA_CTL_VERBOSE", &cfg.Verbose),
		config.EnvBool("OPENVOX_CA_CTL_INSECURE", &cfg.Insecure),
	)
}

// resolveConfigFile delegates to the shared config.ResolveConfigFile.
var resolveConfigFile = config.ResolveConfigFile

// defaultCtlConfigFile is the file openvox-ca-ctl reads when neither --config
// nor OPENVOX_CA_CTL_CONFIG names one. It sits beside the server's own
// config.yaml; mage test:magefile checks that it does, and that it is spelt
// out only here.
const defaultCtlConfigFile = "/etc/openvox-ca/ctl.yaml"
