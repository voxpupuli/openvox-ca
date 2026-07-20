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

package openbao

// White-box unit tests for the pure mapping/decoding helpers. These map
// algorithm/size/hash inputs to Transit's exact wire strings and decode its
// responses, so a wrong string or off-by-one is a silent correctness bug that
// only surfaces against a live server; pinning them here keeps `go test ./...`
// honest without the openbao_integration tag.

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

func TestTransitKeyType(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ca.KeyConfig
		want    string
		wantErr bool
	}{
		// Zero Size must select the same defaults ca.generateKey applies
		// locally (RSA 4096, ECDSA P-256) so OpenBao- and file-provisioned CAs
		// bootstrap identically.
		{"rsa default size", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 0}, "rsa-4096", false},
		{"empty algo defaults to rsa-4096", ca.KeyConfig{Algo: "", Size: 0}, "rsa-4096", false},
		{"rsa 2048", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 2048}, "rsa-2048", false},
		{"rsa 3072", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 3072}, "rsa-3072", false},
		{"rsa 4096", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 4096}, "rsa-4096", false},
		{"ecdsa default size", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 0}, "ecdsa-p256", false},
		{"ecdsa 256", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}, "ecdsa-p256", false},
		{"ecdsa 384", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 384}, "ecdsa-p384", false},
		{"ecdsa 521", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 521}, "ecdsa-p521", false},
		{"unsupported rsa size", ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 1024}, "", true},
		{"unsupported ecdsa size", ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 512}, "", true},
		{"unsupported algo", ca.KeyConfig{Algo: "ed25519", Size: 0}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := transitKeyType(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("transitKeyType(%+v) = %q, nil; want an error", tc.cfg, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("transitKeyType(%+v) unexpected error: %v", tc.cfg, err)
			}
			if got != tc.want {
				t.Fatalf("transitKeyType(%+v) = %q; want %q", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestTransitHashAlgorithm(t *testing.T) {
	cases := []struct {
		h       crypto.Hash
		want    string
		wantErr bool
	}{
		{crypto.SHA256, "sha2-256", false},
		{crypto.SHA384, "sha2-384", false},
		{crypto.SHA512, "sha2-512", false},
		{crypto.SHA1, "", true},
		{crypto.MD5, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.h.String(), func(t *testing.T) {
			got, err := transitHashAlgorithm(tc.h)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("transitHashAlgorithm(%v) = %q, nil; want an error", tc.h, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("transitHashAlgorithm(%v) unexpected error: %v", tc.h, err)
			}
			if got != tc.want {
				t.Fatalf("transitHashAlgorithm(%v) = %q; want %q", tc.h, got, tc.want)
			}
		})
	}
}

func TestDecodeTransitSignature(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03, 0x04}
	b64 := base64.StdEncoding.EncodeToString(raw)

	t.Run("valid vault-prefixed signature decodes to raw bytes", func(t *testing.T) {
		got, err := decodeTransitSignature("vault:v1:" + b64)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(raw) {
			t.Fatalf("decoded = %x; want %x", got, raw)
		}
	})

	t.Run("higher key version is accepted", func(t *testing.T) {
		got, err := decodeTransitSignature("vault:v42:" + b64)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(raw) {
			t.Fatalf("decoded = %x; want %x", got, raw)
		}
	})

	errCases := []struct {
		name string
		sig  string
	}{
		{"missing vault prefix", "v1:" + b64},
		{"prefix but no version separator", "vault:v1" + b64},
		{"invalid base64 payload", "vault:v1:not!base64!"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeTransitSignature(tc.sig); err == nil {
				t.Fatalf("decodeTransitSignature(%q) = nil error; want an error", tc.sig)
			}
		})
	}
}

func TestLatestKeyVersion(t *testing.T) {
	// version builds a "keys" map whose named entries each carry a marker so a
	// test can confirm the right one was picked.
	version := func(names ...string) map[string]interface{} {
		keys := map[string]interface{}{}
		for _, n := range names {
			keys[n] = map[string]interface{}{"public_key": "pem-" + n}
		}
		return keys
	}

	t.Run("json.Number is the production decode path", func(t *testing.T) {
		// The SDK decodes response bodies with UseNumber(), so latest_version
		// always arrives as json.Number in production; this is the branch a
		// float64-only fake would never exercise.
		var n json.Number
		if err := json.Unmarshal([]byte(`2`), &n); err != nil {
			t.Fatalf("building json.Number: %v", err)
		}
		data := map[string]interface{}{
			"latest_version": n,
			"keys":           version("1", "2"),
		}
		got, err := latestKeyVersion(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["public_key"] != "pem-2" {
			t.Fatalf("picked %v; want the version-2 entry", got["public_key"])
		}
	})

	t.Run("string latest_version", func(t *testing.T) {
		data := map[string]interface{}{
			"latest_version": "3",
			"keys":           version("1", "3"),
		}
		got, err := latestKeyVersion(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["public_key"] != "pem-3" {
			t.Fatalf("picked %v; want the version-3 entry", got["public_key"])
		}
	})

	t.Run("float64 latest_version fallback", func(t *testing.T) {
		data := map[string]interface{}{
			"latest_version": float64(1),
			"keys":           version("1"),
		}
		got, err := latestKeyVersion(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["public_key"] != "pem-1" {
			t.Fatalf("picked %v; want the version-1 entry", got["public_key"])
		}
	})

	errCases := []struct {
		name string
		data map[string]interface{}
	}{
		{"no keys map", map[string]interface{}{"latest_version": json.Number("1")}},
		{"missing latest_version", map[string]interface{}{"keys": version("1")}},
		{"unusable latest_version type", map[string]interface{}{
			"latest_version": true, "keys": version("1"),
		}},
		{"latest_version has no matching keys entry", map[string]interface{}{
			"latest_version": json.Number("5"), "keys": version("1", "2"),
		}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := latestKeyVersion(tc.data); err == nil {
				t.Fatalf("latestKeyVersion(%v) = nil error; want an error", tc.data)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	// base is a minimal valid AppRole config; each negative case zeroes one
	// required field to prove that branch of Validate actually rejects.
	base := Config{
		Addr:                "https://bao:8200",
		KeyName:             "mykey",
		AuthMethod:          AuthAppRole,
		AppRoleRoleID:       "role",
		AppRoleSecretIDFile: "/creds/secret-id",
	}

	t.Run("valid approle config passes", func(t *testing.T) {
		if err := base.Validate(); err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
	})

	t.Run("valid token config passes", func(t *testing.T) {
		cfg := Config{Addr: "https://bao:8200", KeyName: "k", AuthMethod: AuthToken, TokenFile: "/creds/token"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
	})

	t.Run("valid kubernetes config passes", func(t *testing.T) {
		cfg := Config{Addr: "https://bao:8200", KeyName: "k", AuthMethod: AuthKubernetes, K8sRole: "role"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
	})

	// role_id may come from either a literal or a file, so setting the file is
	// an equally valid AppRole config.
	t.Run("approle with role_id from file passes", func(t *testing.T) {
		cfg := base
		cfg.AppRoleRoleID = ""
		cfg.AppRoleRoleIDFile = "/creds/role-id"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid config rejected: %v", err)
		}
	})

	negatives := []struct {
		name      string
		mutate    func(*Config)
		wantField string
	}{
		{"missing addr", func(c *Config) { c.Addr = "" }, "addr"},
		{"missing key_name", func(c *Config) { c.KeyName = "" }, "key_name"},
		{"approle without any role_id", func(c *Config) {
			c.AppRoleRoleID = ""
			c.AppRoleRoleIDFile = ""
		}, "approle_role_id"},
		{"approle without secret_id file", func(c *Config) { c.AppRoleSecretIDFile = "" }, "approle_secret_id_file"},
		{"token without token file", func(c *Config) {
			c.AuthMethod = AuthToken
			c.AppRoleRoleID = ""
			c.AppRoleSecretIDFile = ""
		}, "token_file"},
		{"kubernetes without role", func(c *Config) {
			c.AuthMethod = AuthKubernetes
			c.AppRoleRoleID = ""
			c.AppRoleSecretIDFile = ""
		}, "kubernetes_role"},
		{"empty auth_method", func(c *Config) { c.AuthMethod = "" }, "auth_method"},
		{"unknown auth_method", func(c *Config) { c.AuthMethod = "nonsense" }, "nonsense"},
	}
	for _, tc := range negatives {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil; want an error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantField) {
				t.Fatalf("Validate() error %q does not name %q", err.Error(), tc.wantField)
			}
		})
	}
}
