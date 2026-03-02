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
	"os"
	"path/filepath"
	"testing"
)

// serverEnvVars is the full list of env vars read by applyServerEnv.
var serverEnvVars = []string{
	"PUPPET_CA_CADIR",
	"PUPPET_CA_AUTOSIGN_CONFIG",
	"PUPPET_CA_HOST",
	"PUPPET_CA_PORT",
	"PUPPET_CA_HOSTNAME",
	"PUPPET_CA_VERBOSITY",
	"PUPPET_CA_LOGFILE",
	"PUPPET_CA_TLS_CERT",
	"PUPPET_CA_TLS_KEY",
	"PUPPET_CA_PUPPET_SERVER",
	"PUPPET_CA_PUPPET_SERVER_FILE",
	"PUPPET_CA_NO_PP_CLI_AUTH",
	"PUPPET_CA_NO_TLS_REQUIRED",
	"PUPPET_CA_OCSP_URL",
	"PUPPET_CA_CA_KEY_ALGO",
	"PUPPET_CA_CA_KEY_SIZE",
	"PUPPET_CA_LEAF_KEY_ALGO",
	"PUPPET_CA_LEAF_KEY_SIZE",
	"PUPPET_CA_CA_SUBJECT_ORG",
	"PUPPET_CA_CA_SUBJECT_OU",
	"PUPPET_CA_CA_SUBJECT_COUNTRY",
	"PUPPET_CA_CA_SUBJECT_LOCALITY",
	"PUPPET_CA_CA_SUBJECT_PROVINCE",
	"PUPPET_CA_CA_PATH_LENGTH",
	"PUPPET_CA_CA_VALIDITY_DAYS",
	"PUPPET_CA_LEAF_VALIDITY_DAYS",
}

// clearServerEnv unsets all PUPPET_CA_* vars and restores them after the test.
func clearServerEnv(t *testing.T) {
	t.Helper()
	for _, key := range serverEnvVars {
		t.Setenv(key, "") // t.Setenv restores; empty string is treated as unset by applyServerEnv
	}
}

// --- resolveConfigFile ---

func TestResolveConfigFile(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.yaml")
	if err := os.WriteFile(existing, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yaml")

	const envKey = "PUPPET_CA_CONFIG_TEST_RESOLVE"

	tests := []struct {
		name        string
		cliFlag     string
		envVal      string
		defaultPath string
		want        string
	}{
		{
			name:        "cli flag wins over env and default",
			cliFlag:     "/cli/path.yaml",
			envVal:      "/env/path.yaml",
			defaultPath: existing,
			want:        "/cli/path.yaml",
		},
		{
			name:        "env var used when no cli flag",
			envVal:      "/env/path.yaml",
			defaultPath: existing,
			want:        "/env/path.yaml",
		},
		{
			name:        "default path used when it exists",
			defaultPath: existing,
			want:        existing,
		},
		{
			name:        "empty when default does not exist",
			defaultPath: missing,
			want:        "",
		},
		{
			name: "empty when nothing provided",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envKey, tc.envVal)
			got := resolveConfigFile(tc.cliFlag, envKey, tc.defaultPath)
			if got != tc.want {
				t.Errorf("resolveConfigFile(%q, %q, %q) = %q; want %q",
					tc.cliFlag, envKey, tc.defaultPath, got, tc.want)
			}
		})
	}
}

// --- loadServerConfig: built-in defaults ---

func TestLoadServerConfigDefaults(t *testing.T) {
	clearServerEnv(t)

	cfg, err := loadServerConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host = %q; want 0.0.0.0", cfg.Host)
	}
	if cfg.Port != 8140 {
		t.Errorf("Port = %d; want 8140", cfg.Port)
	}
	if cfg.CADir != "" {
		t.Errorf("CADir = %q; want empty", cfg.CADir)
	}
	if cfg.NoTLSRequired {
		t.Error("NoTLSRequired = true; want false")
	}
	if cfg.Verbosity != 0 {
		t.Errorf("Verbosity = %d; want 0", cfg.Verbosity)
	}
	if cfg.CAPathLength != -1 {
		t.Errorf("CAPathLength = %d; want -1 (unconstrained)", cfg.CAPathLength)
	}
}

// --- loadServerConfig: YAML file ---

func TestLoadServerConfigYAML(t *testing.T) {
	clearServerEnv(t)

	content := `
cadir: /tmp/myca
host: 127.0.0.1
port: 9090
hostname: myhost
no_tls_required: true
tls_cert: /etc/ssl/cert.pem
tls_key: /etc/ssl/key.pem
puppet_server: puppet-master
puppet_server_file: /etc/puppet-ca/servers.txt
no_pp_cli_auth: true
autosign_config: "true"
logfile: /var/log/puppet-ca.log
verbosity: 1
ocsp_url: http://ocsp.example.com/ocsp
ca_key_algo: ecdsa
ca_key_size: 384
leaf_key_algo: rsa
leaf_key_size: 3072
ca_subject_org: Example Org
ca_subject_ou: IT
ca_subject_country: US
ca_subject_locality: Springfield
ca_subject_province: IL
ca_path_length: 1
ca_validity_days: 3650
leaf_validity_days: 1825
`
	cfgFile := writeTempConfig(t, content)

	cfg, err := loadServerConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	checks := []struct {
		field string
		got   interface{}
		want  interface{}
	}{
		{"CADir", cfg.CADir, "/tmp/myca"},
		{"Host", cfg.Host, "127.0.0.1"},
		{"Port", cfg.Port, 9090},
		{"Hostname", cfg.Hostname, "myhost"},
		{"NoTLSRequired", cfg.NoTLSRequired, true},
		{"TLSCert", cfg.TLSCert, "/etc/ssl/cert.pem"},
		{"TLSKey", cfg.TLSKey, "/etc/ssl/key.pem"},
		{"PuppetServer", cfg.PuppetServer, "puppet-master"},
		{"PuppetServerFile", cfg.PuppetServerFile, "/etc/puppet-ca/servers.txt"},
		{"NoPpCliAuth", cfg.NoPpCliAuth, true},
		{"AutosignConfig", cfg.AutosignConfig, "true"},
		{"LogFile", cfg.LogFile, "/var/log/puppet-ca.log"},
		{"Verbosity", cfg.Verbosity, 1},
		{"OCSPUrl", cfg.OCSPUrl, "http://ocsp.example.com/ocsp"},
		{"CAKeyAlgo", cfg.CAKeyAlgo, "ecdsa"},
		{"CAKeySize", cfg.CAKeySize, 384},
		{"LeafKeyAlgo", cfg.LeafKeyAlgo, "rsa"},
		{"LeafKeySize", cfg.LeafKeySize, 3072},
		{"CASubjectOrg", cfg.CASubjectOrg, "Example Org"},
		{"CASubjectOU", cfg.CASubjectOU, "IT"},
		{"CASubjectCountry", cfg.CASubjectCountry, "US"},
		{"CASubjectLocality", cfg.CASubjectLocality, "Springfield"},
		{"CASubjectProvince", cfg.CASubjectProvince, "IL"},
		{"CAPathLength", cfg.CAPathLength, 1},
		{"CAValidityDays", cfg.CAValidityDays, 3650},
		{"LeafValidityDays", cfg.LeafValidityDays, 1825},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.field, c.got, c.want)
		}
	}
}

// TestLoadServerConfigYAMLPartial verifies that unset YAML keys keep built-in defaults.
func TestLoadServerConfigYAMLPartial(t *testing.T) {
	clearServerEnv(t)

	cfgFile := writeTempConfig(t, "cadir: /tmp/partial\n")
	cfg, err := loadServerConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host = %q; want default 0.0.0.0", cfg.Host)
	}
	if cfg.Port != 8140 {
		t.Errorf("Port = %d; want default 8140", cfg.Port)
	}
	if cfg.CADir != "/tmp/partial" {
		t.Errorf("CADir = %q; want /tmp/partial", cfg.CADir)
	}
}

// --- loadServerConfig: env vars override YAML ---

func TestLoadServerConfigEnvOverridesYAML(t *testing.T) {
	clearServerEnv(t)

	cfgFile := writeTempConfig(t, "host: 10.0.0.1\nport: 9090\n")
	t.Setenv("PUPPET_CA_HOST", "192.168.1.1")
	t.Setenv("PUPPET_CA_PORT", "7777")

	cfg, err := loadServerConfig(cfgFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "192.168.1.1" {
		t.Errorf("Host = %q; want env value 192.168.1.1", cfg.Host)
	}
	if cfg.Port != 7777 {
		t.Errorf("Port = %d; want env value 7777", cfg.Port)
	}
}

// --- loadServerConfig: error cases ---

func TestLoadServerConfigMissingFile(t *testing.T) {
	_, err := loadServerConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing config file, got nil")
	}
}

func TestLoadServerConfigInvalidYAML(t *testing.T) {
	cfgFile := writeTempConfig(t, "host: [unclosed\n")
	_, err := loadServerConfig(cfgFile)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// --- applyServerEnv: each variable ---

func TestApplyServerEnvEachVar(t *testing.T) {
	tests := []struct {
		name   string
		envKey string
		envVal string
		check  func(*serverConfig) bool
		desc   string
	}{
		{
			name: "CADIR", envKey: "PUPPET_CA_CADIR", envVal: "/some/dir",
			check: func(c *serverConfig) bool { return c.CADir == "/some/dir" },
			desc:  "CADir",
		},
		{
			name: "AUTOSIGN_CONFIG", envKey: "PUPPET_CA_AUTOSIGN_CONFIG", envVal: "true",
			check: func(c *serverConfig) bool { return c.AutosignConfig == "true" },
			desc:  "AutosignConfig",
		},
		{
			name: "HOST", envKey: "PUPPET_CA_HOST", envVal: "1.2.3.4",
			check: func(c *serverConfig) bool { return c.Host == "1.2.3.4" },
			desc:  "Host",
		},
		{
			name: "PORT", envKey: "PUPPET_CA_PORT", envVal: "9999",
			check: func(c *serverConfig) bool { return c.Port == 9999 },
			desc:  "Port",
		},
		{
			name: "HOSTNAME", envKey: "PUPPET_CA_HOSTNAME", envVal: "puppet.test",
			check: func(c *serverConfig) bool { return c.Hostname == "puppet.test" },
			desc:  "Hostname",
		},
		{
			name: "VERBOSITY", envKey: "PUPPET_CA_VERBOSITY", envVal: "2",
			check: func(c *serverConfig) bool { return c.Verbosity == 2 },
			desc:  "Verbosity",
		},
		{
			name: "LOGFILE", envKey: "PUPPET_CA_LOGFILE", envVal: "/var/log/puppet.log",
			check: func(c *serverConfig) bool { return c.LogFile == "/var/log/puppet.log" },
			desc:  "LogFile",
		},
		{
			name: "TLS_CERT", envKey: "PUPPET_CA_TLS_CERT", envVal: "/etc/tls/cert.pem",
			check: func(c *serverConfig) bool { return c.TLSCert == "/etc/tls/cert.pem" },
			desc:  "TLSCert",
		},
		{
			name: "TLS_KEY", envKey: "PUPPET_CA_TLS_KEY", envVal: "/etc/tls/key.pem",
			check: func(c *serverConfig) bool { return c.TLSKey == "/etc/tls/key.pem" },
			desc:  "TLSKey",
		},
		{
			name: "PUPPET_SERVER", envKey: "PUPPET_CA_PUPPET_SERVER", envVal: "puppet-master",
			check: func(c *serverConfig) bool { return c.PuppetServer == "puppet-master" },
			desc:  "PuppetServer",
		},
		{
			name: "PUPPET_SERVER_FILE", envKey: "PUPPET_CA_PUPPET_SERVER_FILE", envVal: "/etc/puppet-ca/servers.txt",
			check: func(c *serverConfig) bool { return c.PuppetServerFile == "/etc/puppet-ca/servers.txt" },
			desc:  "PuppetServerFile",
		},
		{
			name: "NO_PP_CLI_AUTH_true", envKey: "PUPPET_CA_NO_PP_CLI_AUTH", envVal: "true",
			check: func(c *serverConfig) bool { return c.NoPpCliAuth },
			desc:  "NoPpCliAuth=true",
		},
		{
			name: "NO_TLS_REQUIRED_true", envKey: "PUPPET_CA_NO_TLS_REQUIRED", envVal: "true",
			check: func(c *serverConfig) bool { return c.NoTLSRequired },
			desc:  "NoTLSRequired=true",
		},
		{
			name: "NO_TLS_REQUIRED_1", envKey: "PUPPET_CA_NO_TLS_REQUIRED", envVal: "1",
			check: func(c *serverConfig) bool { return c.NoTLSRequired },
			desc:  "NoTLSRequired=1",
		},
		{
			name: "OCSP_URL", envKey: "PUPPET_CA_OCSP_URL", envVal: "http://ocsp.example.com",
			check: func(c *serverConfig) bool { return c.OCSPUrl == "http://ocsp.example.com" },
			desc:  "OCSPUrl",
		},
		{
			name: "CA_KEY_ALGO", envKey: "PUPPET_CA_CA_KEY_ALGO", envVal: "ecdsa",
			check: func(c *serverConfig) bool { return c.CAKeyAlgo == "ecdsa" },
			desc:  "CAKeyAlgo",
		},
		{
			name: "CA_KEY_SIZE", envKey: "PUPPET_CA_CA_KEY_SIZE", envVal: "384",
			check: func(c *serverConfig) bool { return c.CAKeySize == 384 },
			desc:  "CAKeySize",
		},
		{
			name: "LEAF_KEY_ALGO", envKey: "PUPPET_CA_LEAF_KEY_ALGO", envVal: "rsa",
			check: func(c *serverConfig) bool { return c.LeafKeyAlgo == "rsa" },
			desc:  "LeafKeyAlgo",
		},
		{
			name: "LEAF_KEY_SIZE", envKey: "PUPPET_CA_LEAF_KEY_SIZE", envVal: "3072",
			check: func(c *serverConfig) bool { return c.LeafKeySize == 3072 },
			desc:  "LeafKeySize",
		},
		{
			name: "CA_SUBJECT_ORG", envKey: "PUPPET_CA_CA_SUBJECT_ORG", envVal: "Example Org",
			check: func(c *serverConfig) bool { return c.CASubjectOrg == "Example Org" },
			desc:  "CASubjectOrg",
		},
		{
			name: "CA_SUBJECT_OU", envKey: "PUPPET_CA_CA_SUBJECT_OU", envVal: "IT",
			check: func(c *serverConfig) bool { return c.CASubjectOU == "IT" },
			desc:  "CASubjectOU",
		},
		{
			name: "CA_SUBJECT_COUNTRY", envKey: "PUPPET_CA_CA_SUBJECT_COUNTRY", envVal: "US",
			check: func(c *serverConfig) bool { return c.CASubjectCountry == "US" },
			desc:  "CASubjectCountry",
		},
		{
			name: "CA_SUBJECT_LOCALITY", envKey: "PUPPET_CA_CA_SUBJECT_LOCALITY", envVal: "Springfield",
			check: func(c *serverConfig) bool { return c.CASubjectLocality == "Springfield" },
			desc:  "CASubjectLocality",
		},
		{
			name: "CA_SUBJECT_PROVINCE", envKey: "PUPPET_CA_CA_SUBJECT_PROVINCE", envVal: "IL",
			check: func(c *serverConfig) bool { return c.CASubjectProvince == "IL" },
			desc:  "CASubjectProvince",
		},
		{
			name: "CA_PATH_LENGTH_0", envKey: "PUPPET_CA_CA_PATH_LENGTH", envVal: "0",
			check: func(c *serverConfig) bool { return c.CAPathLength == 0 },
			desc:  "CAPathLength=0",
		},
		{
			name: "CA_PATH_LENGTH_1", envKey: "PUPPET_CA_CA_PATH_LENGTH", envVal: "1",
			check: func(c *serverConfig) bool { return c.CAPathLength == 1 },
			desc:  "CAPathLength=1",
		},
		{
			name: "CA_PATH_LENGTH_neg1", envKey: "PUPPET_CA_CA_PATH_LENGTH", envVal: "-1",
			check: func(c *serverConfig) bool { return c.CAPathLength == -1 },
			desc:  "CAPathLength=-1 (unconstrained)",
		},
		{
			name: "CA_VALIDITY_DAYS", envKey: "PUPPET_CA_CA_VALIDITY_DAYS", envVal: "3650",
			check: func(c *serverConfig) bool { return c.CAValidityDays == 3650 },
			desc:  "CAValidityDays",
		},
		{
			name: "LEAF_VALIDITY_DAYS", envKey: "PUPPET_CA_LEAF_VALIDITY_DAYS", envVal: "1825",
			check: func(c *serverConfig) bool { return c.LeafValidityDays == 1825 },
			desc:  "LeafValidityDays",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearServerEnv(t)
			t.Setenv(tc.envKey, tc.envVal)
			cfg := &serverConfig{}
			applyServerEnv(cfg)
			if !tc.check(cfg) {
				t.Errorf("%s not applied from %s=%s", tc.desc, tc.envKey, tc.envVal)
			}
		})
	}
}

// TestApplyServerEnvInvalidValues verifies that malformed values are silently ignored.
func TestApplyServerEnvInvalidValues(t *testing.T) {
	clearServerEnv(t)
	t.Setenv("PUPPET_CA_PORT", "not-a-number")
	t.Setenv("PUPPET_CA_VERBOSITY", "bad")
	t.Setenv("PUPPET_CA_NO_TLS_REQUIRED", "maybe")
	t.Setenv("PUPPET_CA_CA_VALIDITY_DAYS", "not-a-number")
	t.Setenv("PUPPET_CA_LEAF_VALIDITY_DAYS", "bad")
	t.Setenv("PUPPET_CA_CA_PATH_LENGTH", "not-a-number")

	cfg := &serverConfig{Port: 8140, Verbosity: 0, CAPathLength: -1}
	applyServerEnv(cfg)

	if cfg.Port != 8140 {
		t.Errorf("Port changed on bad input: got %d, want 8140", cfg.Port)
	}
	if cfg.Verbosity != 0 {
		t.Errorf("Verbosity changed on bad input: got %d, want 0", cfg.Verbosity)
	}
	if cfg.NoTLSRequired {
		t.Error("NoTLSRequired changed on bad input: want false")
	}
	if cfg.CAValidityDays != 0 {
		t.Errorf("CAValidityDays changed on bad input: got %d, want 0", cfg.CAValidityDays)
	}
	if cfg.LeafValidityDays != 0 {
		t.Errorf("LeafValidityDays changed on bad input: got %d, want 0", cfg.LeafValidityDays)
	}
	if cfg.CAPathLength != -1 {
		t.Errorf("CAPathLength changed on bad input: got %d, want -1", cfg.CAPathLength)
	}
}

// TestApplyServerEnvCAValidityDaysZeroIgnored verifies that a zero or negative
// value for PUPPET_CA_CA_VALIDITY_DAYS and PUPPET_CA_LEAF_VALIDITY_DAYS is
// silently ignored (only positive values are applied).
func TestApplyServerEnvValidityDaysZeroIgnored(t *testing.T) {
	clearServerEnv(t)
	t.Setenv("PUPPET_CA_CA_VALIDITY_DAYS", "0")
	t.Setenv("PUPPET_CA_LEAF_VALIDITY_DAYS", "-5")

	cfg := &serverConfig{}
	applyServerEnv(cfg)

	if cfg.CAValidityDays != 0 {
		t.Errorf("CAValidityDays should stay 0 when env is 0, got %d", cfg.CAValidityDays)
	}
	if cfg.LeafValidityDays != 0 {
		t.Errorf("LeafValidityDays should stay 0 when env is negative, got %d", cfg.LeafValidityDays)
	}
}

// --- loadPuppetServerFile ---

func TestLoadPuppetServerFileEmpty(t *testing.T) {
	cns, err := loadPuppetServerFile("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cns != nil {
		t.Errorf("expected nil slice for empty path, got %v", cns)
	}
}

func TestLoadPuppetServerFileMissing(t *testing.T) {
	_, err := loadPuppetServerFile("/nonexistent/path/servers.txt")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadPuppetServerFileParsing(t *testing.T) {
	content := `
# primary puppet server
puppet.example.com

# compile masters
compile-01.example.com
compile-02.example.com

`
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cns, err := loadPuppetServerFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"puppet.example.com", "compile-01.example.com", "compile-02.example.com"}
	if len(cns) != len(want) {
		t.Fatalf("got %d CNs, want %d: %v", len(cns), len(want), cns)
	}
	for i, cn := range cns {
		if cn != want[i] {
			t.Errorf("cns[%d] = %q; want %q", i, cn, want[i])
		}
	}
}

func TestLoadPuppetServerFileCommentsAndBlanks(t *testing.T) {
	content := "# comment\n\n  \n# another comment\npuppet.example.com\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cns, err := loadPuppetServerFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cns) != 1 || cns[0] != "puppet.example.com" {
		t.Errorf("got %v; want [puppet.example.com]", cns)
	}
}

func TestLoadPuppetServerFileInlineComments(t *testing.T) {
	content := "puppet.example.com # primary\ncompile-01.example.com # compile master\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "servers.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cns, err := loadPuppetServerFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"puppet.example.com", "compile-01.example.com"}
	if len(cns) != len(want) {
		t.Fatalf("got %v; want %v", cns, want)
	}
	for i, cn := range cns {
		if cn != want[i] {
			t.Errorf("cns[%d] = %q; want %q", i, cn, want[i])
		}
	}
}

func TestLoadPuppetServerFileEmpty_file(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("# just a comment\n\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cns, err := loadPuppetServerFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cns) != 0 {
		t.Errorf("expected empty slice for comment-only file, got %v", cns)
	}
}

// --- helper ---

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
