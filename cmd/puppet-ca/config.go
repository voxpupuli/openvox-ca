// Copyright (C) 2026 Trevor Vaughan
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
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// serverConfig holds all configuration for the puppet-ca server.
// Fields are populated from (lowest → highest priority):
//
//	built-in defaults → config file → env vars → CLI flags
type serverConfig struct {
	CADir            string `yaml:"cadir"`
	AutosignConfig   string `yaml:"autosign_config"`
	Host             string `yaml:"host"`
	Port             int    `yaml:"port"`
	Hostname         string `yaml:"hostname"`
	Verbosity        int    `yaml:"verbosity"`
	LogFile          string `yaml:"logfile"`
	TLSCert          string `yaml:"tls_cert"`
	TLSKey           string `yaml:"tls_key"`
	PuppetServer     string `yaml:"puppet_server"`
	PuppetServerFile string `yaml:"puppet_server_file"`
	NoPpCliAuth      bool   `yaml:"no_pp_cli_auth"`
	NoTLSRequired    bool   `yaml:"no_tls_required"`
	OCSPUrl          string `yaml:"ocsp_url"`
}

// loadServerConfig applies built-in defaults, optionally loads a YAML config
// file, then overlays environment variables. configFile may be "" to skip file
// loading.
func loadServerConfig(configFile string) (*serverConfig, error) {
	cfg := &serverConfig{
		Host: "0.0.0.0",
		Port: 8140,
	}

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("reading config file %s: %w", configFile, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", configFile, err)
		}
	}

	applyServerEnv(cfg)
	return cfg, nil
}

// applyServerEnv overlays PUPPET_CA_* environment variables onto cfg.
func applyServerEnv(cfg *serverConfig) {
	if v := os.Getenv("PUPPET_CA_CADIR"); v != "" {
		cfg.CADir = v
	}
	if v := os.Getenv("PUPPET_CA_AUTOSIGN_CONFIG"); v != "" {
		cfg.AutosignConfig = v
	}
	if v := os.Getenv("PUPPET_CA_HOST"); v != "" {
		cfg.Host = v
	}
	if v := os.Getenv("PUPPET_CA_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Port = n
		}
	}
	if v := os.Getenv("PUPPET_CA_HOSTNAME"); v != "" {
		cfg.Hostname = v
	}
	if v := os.Getenv("PUPPET_CA_VERBOSITY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Verbosity = n
		}
	}
	if v := os.Getenv("PUPPET_CA_LOGFILE"); v != "" {
		cfg.LogFile = v
	}
	if v := os.Getenv("PUPPET_CA_TLS_CERT"); v != "" {
		cfg.TLSCert = v
	}
	if v := os.Getenv("PUPPET_CA_TLS_KEY"); v != "" {
		cfg.TLSKey = v
	}
	if v := os.Getenv("PUPPET_CA_PUPPET_SERVER"); v != "" {
		cfg.PuppetServer = v
	}
	if v := os.Getenv("PUPPET_CA_PUPPET_SERVER_FILE"); v != "" {
		cfg.PuppetServerFile = v
	}
	if v := os.Getenv("PUPPET_CA_NO_PP_CLI_AUTH"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.NoPpCliAuth = b
		}
	}
	if v := os.Getenv("PUPPET_CA_NO_TLS_REQUIRED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.NoTLSRequired = b
		}
	}
	if v := os.Getenv("PUPPET_CA_OCSP_URL"); v != "" {
		cfg.OCSPUrl = v
	}
}

// loadPuppetServerFile reads a file containing puppet-server CNs, one per
// line. '#' characters and everything after them are stripped (covering both
// full-line and inline comments). Blank lines are skipped. Returns nil, nil
// when path is empty.
func loadPuppetServerFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading puppet-server file %s: %w", path, err)
	}
	defer f.Close()
	var cns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// Strip inline comments (anything from '#' onward).
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		cns = append(cns, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading puppet-server file %s: %w", path, err)
	}
	return cns, nil
}

// resolveConfigFile returns the config file path to use:
// cliFlag → envVar → defaultPath (if it exists) → "".
func resolveConfigFile(cliFlag, envVar, defaultPath string) string {
	if cliFlag != "" {
		return cliFlag
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	return ""
}
