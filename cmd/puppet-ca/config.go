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

	"github.com/tvaughan/puppet-ca/internal/config"
	"go.yaml.in/yaml/v3"
)

// serverConfig holds all configuration for the puppet-ca server.
// Fields are populated from (lowest → highest priority):
//
//	built-in defaults → config file → env vars → CLI flags
type serverConfig struct {
	CADir             string `yaml:"cadir"`
	AutosignConfig    string `yaml:"autosign_config"`
	Host              string `yaml:"host"`
	Port              int    `yaml:"port"`
	Hostname          string `yaml:"hostname"`
	Verbosity         int    `yaml:"verbosity"`
	LogFile           string `yaml:"logfile"`
	TLSCert           string `yaml:"tls_cert"`
	TLSKey            string `yaml:"tls_key"`
	PuppetServer      string `yaml:"puppet_server"`
	PuppetServerFile  string `yaml:"puppet_server_file"`
	NoPpCliAuth       bool   `yaml:"no_pp_cli_auth"`
	NoTLSRequired     bool   `yaml:"no_tls_required"`
	AllowPublicStatus bool   `yaml:"allow_public_status"`
	OCSPUrl           string `yaml:"ocsp_url"`
	CRLUrl            string `yaml:"crl_url"`

	// Key generation options (apply only when bootstrapping a new CA).
	CAKeyAlgo   string `yaml:"ca_key_algo"`
	CAKeySize   int    `yaml:"ca_key_size"`
	LeafKeyAlgo string `yaml:"leaf_key_algo"`
	LeafKeySize int    `yaml:"leaf_key_size"`

	// CA certificate subject fields (apply only when bootstrapping a new CA).
	CASubjectOrg      string `yaml:"ca_subject_org"`
	CASubjectOU       string `yaml:"ca_subject_ou"`
	CASubjectCountry  string `yaml:"ca_subject_country"`
	CASubjectLocality string `yaml:"ca_subject_locality"`
	CASubjectProvince string `yaml:"ca_subject_province"`

	// Validity and path length options (apply only when bootstrapping a new CA,
	// except LeafValidityDays and CRLValidityDays which apply on every
	// signing/revocation operation).
	CAPathLength     int `yaml:"ca_path_length"`     // -1=unconstrained (default), 0=leaf-only, N=N levels
	CAValidityDays   int `yaml:"ca_validity_days"`   // 0 = built-in default (~5 years)
	LeafValidityDays int `yaml:"leaf_validity_days"` // 0 = built-in default (~5 years)
	CRLValidityDays  int `yaml:"crl_validity_days"`  // 0 = built-in default (30 days)
	CSRRateLimit     int `yaml:"csr_rate_limit"`     // max CSR submissions per IP per minute; 0 = use built-in default (60)

	// CA key encryption at rest.
	EncryptCAKey        bool   `yaml:"encrypt_ca_key"`         // encrypt the CA private key at rest (AES-256-GCM + Argon2id)
	CAKeyPassphraseFile string `yaml:"ca_key_passphrase_file"` // path to file containing the CA key passphrase

	// Storage backend selection. "filesystem" (default) stores all CA data
	// under CADir; "etcd" keeps CA cert, key, CRL, inventory, serial, CSRs
	// and signed certs in an etcd cluster (per-subject generated private
	// keys always remain on local disk under CADir).
	StorageBackend       string   `yaml:"storage_backend"`
	EtcdEndpoints        []string `yaml:"etcd_endpoints"`
	EtcdKeyPrefix        string   `yaml:"etcd_key_prefix"`
	EtcdUsername         string   `yaml:"etcd_username"`
	EtcdPassword         string   `yaml:"etcd_password"`
	EtcdDialTimeoutSec   int      `yaml:"etcd_dial_timeout_sec"`
	EtcdRequestTimeoutSec int     `yaml:"etcd_request_timeout_sec"`
	EtcdTLSCAFile        string   `yaml:"etcd_tls_ca_file"`
	EtcdTLSCertFile      string   `yaml:"etcd_tls_cert_file"`
	EtcdTLSKeyFile       string   `yaml:"etcd_tls_key_file"`

	// Local-file overrides. When set, the named asset is read/written via
	// this filesystem path regardless of the selected backend. Typical use:
	// keep the CA cert and/or key on local disk (or a mounted secret volume)
	// while storing CSRs, signed certs, CRL and inventory in etcd.
	CACertFile string `yaml:"ca_cert_file"`
	CAKeyFile  string `yaml:"ca_key_file"`
}

// loadServerConfig applies built-in defaults, optionally loads a YAML config
// file, then overlays environment variables. configFile may be "" to skip file
// loading.
func loadServerConfig(configFile string) (*serverConfig, error) {
	cfg := &serverConfig{
		Host:         "0.0.0.0",
		Port:         8140,
		CAPathLength: -1, // unconstrained; 0 = leaf-only, N = N levels of intermediates
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
	if v := os.Getenv("PUPPET_CA_ALLOW_PUBLIC_STATUS"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.AllowPublicStatus = b
		}
	}
	if v := os.Getenv("PUPPET_CA_OCSP_URL"); v != "" {
		cfg.OCSPUrl = v
	}
	if v := os.Getenv("PUPPET_CA_CRL_URL"); v != "" {
		cfg.CRLUrl = v
	}
	if v := os.Getenv("PUPPET_CA_CA_KEY_ALGO"); v != "" {
		cfg.CAKeyAlgo = v
	}
	if v := os.Getenv("PUPPET_CA_CA_KEY_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CAKeySize = n
		}
	}
	if v := os.Getenv("PUPPET_CA_LEAF_KEY_ALGO"); v != "" {
		cfg.LeafKeyAlgo = v
	}
	if v := os.Getenv("PUPPET_CA_LEAF_KEY_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.LeafKeySize = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_ORG"); v != "" {
		cfg.CASubjectOrg = v
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_OU"); v != "" {
		cfg.CASubjectOU = v
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_COUNTRY"); v != "" {
		cfg.CASubjectCountry = v
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_LOCALITY"); v != "" {
		cfg.CASubjectLocality = v
	}
	if v := os.Getenv("PUPPET_CA_CA_SUBJECT_PROVINCE"); v != "" {
		cfg.CASubjectProvince = v
	}
	if v := os.Getenv("PUPPET_CA_CA_PATH_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CAPathLength = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CA_VALIDITY_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CAValidityDays = n
		}
	}
	if v := os.Getenv("PUPPET_CA_LEAF_VALIDITY_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.LeafValidityDays = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CRL_VALIDITY_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CRLValidityDays = n
		}
	}
	if v := os.Getenv("PUPPET_CA_CSR_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CSRRateLimit = n
		}
	}
	if v := os.Getenv("PUPPET_CA_ENCRYPT_CA_KEY"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.EncryptCAKey = b
		}
	}
	if v := os.Getenv("PUPPET_CA_KEY_PASSPHRASE_FILE"); v != "" {
		cfg.CAKeyPassphraseFile = v
	}
	if v := os.Getenv("PUPPET_CA_STORAGE_BACKEND"); v != "" {
		cfg.StorageBackend = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_ENDPOINTS"); v != "" {
		cfg.EtcdEndpoints = splitAndTrim(v, ",")
	}
	if v := os.Getenv("PUPPET_CA_ETCD_KEY_PREFIX"); v != "" {
		cfg.EtcdKeyPrefix = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_USERNAME"); v != "" {
		cfg.EtcdUsername = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_PASSWORD"); v != "" {
		cfg.EtcdPassword = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.EtcdDialTimeoutSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.EtcdRequestTimeoutSec = n
		}
	}
	if v := os.Getenv("PUPPET_CA_ETCD_TLS_CA_FILE"); v != "" {
		cfg.EtcdTLSCAFile = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_TLS_CERT_FILE"); v != "" {
		cfg.EtcdTLSCertFile = v
	}
	if v := os.Getenv("PUPPET_CA_ETCD_TLS_KEY_FILE"); v != "" {
		cfg.EtcdTLSKeyFile = v
	}
	if v := os.Getenv("PUPPET_CA_CA_CERT_FILE"); v != "" {
		cfg.CACertFile = v
	}
	if v := os.Getenv("PUPPET_CA_CA_KEY_FILE"); v != "" {
		cfg.CAKeyFile = v
	}
}

// splitAndTrim splits s on sep, trims whitespace around each element, and
// drops empty entries. Used for comma-separated list env vars.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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

// resolveConfigFile delegates to the shared config.ResolveConfigFile.
var resolveConfigFile = config.ResolveConfigFile
