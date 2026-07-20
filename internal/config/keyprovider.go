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

package config

import (
	"fmt"

	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

// CAKeyProviderConfig is the CA-key-custody portion of a openvox-ca
// configuration. It lives in the shared config package (alongside
// StorageConfig) so a future operator-CLI command can embed it and interpret
// the same YAML keys/flags as the server; today it is consumed only by the
// server (cmd/openvox-ca).
//
// CAKeyProvider selects where the CA's own private key lives: "file"
// (default) keeps today's behaviour (a local PEM blob, via the configured
// storage backend); "openbao" delegates custody and every signing operation
// to an OpenBao Transit secrets engine key (see internal/signer/openbao). A
// future "pkcs11" value is anticipated to slot into the same flag.
type CAKeyProviderConfig struct {
	CAKeyProvider string `yaml:"ca_key_provider"`

	// OpenBao holds every OpenBao-specific setting under its own top-level
	// YAML key ("openbao.addr", "openbao.key_name", ...) rather than a flat
	// "openbao_*" prefix, since there's a lot of them and they only ever
	// matter together. Only consulted when CAKeyProvider is "openbao".
	OpenBao OpenBaoConfig `yaml:"openbao"`
}

// OpenBaoConfig is the OpenBao portion of CAKeyProviderConfig.
type OpenBaoConfig struct {
	Addr         string `yaml:"addr"`
	TransitMount string `yaml:"transit_mount"`
	KeyName      string `yaml:"key_name"`
	TLSCAFile    string `yaml:"tls_ca_file"`
	TLSCertFile  string `yaml:"tls_cert_file"`
	TLSKeyFile   string `yaml:"tls_key_file"`

	// AuthMethod selects how openvox-ca authenticates to OpenBao:
	// "approle", "token", or "kubernetes".
	AuthMethod string `yaml:"auth_method"`

	AppRoleMount        string `yaml:"approle_mount"`
	AppRoleRoleID       string `yaml:"approle_role_id"`
	AppRoleRoleIDFile   string `yaml:"approle_role_id_file"`
	AppRoleSecretIDFile string `yaml:"approle_secret_id_file"`

	TokenFile string `yaml:"token_file"`

	KubernetesMount   string `yaml:"kubernetes_mount"`
	KubernetesRole    string `yaml:"kubernetes_role"`
	KubernetesJWTFile string `yaml:"kubernetes_jwt_file"`
}

// UsesOpenBao reports whether CAKeyProvider selects the OpenBao Transit
// backend.
func (c CAKeyProviderConfig) UsesOpenBao() bool {
	return c.CAKeyProvider == "openbao"
}

// Validate rejects an unrecognised ca_key_provider before any storage or
// backend I/O is attempted. An unknown value (e.g. a typo like "openba", or
// the anticipated-but-unimplemented "pkcs11") must be a hard error rather than
// silently falling through to local-file key custody: that would write the CA
// private key to disk when the operator explicitly asked for it to live
// elsewhere. Empty is accepted as the "file" default.
func (c CAKeyProviderConfig) Validate() error {
	switch c.CAKeyProvider {
	case "", "file", "openbao":
		return nil
	default:
		return fmt.Errorf("unknown ca_key_provider %q (must be %q or %q)", c.CAKeyProvider, "file", "openbao")
	}
}

// ToOpenBaoConfig derives an openbao.Config from the configured fields. Only
// meaningful when UsesOpenBao() is true. cfg.Validate() is the sole authority
// on auth-method validity (including the empty and unknown cases), so this
// method maps the fields verbatim and lets Validate reject a bad auth_method
// with its more specific messages.
func (c CAKeyProviderConfig) ToOpenBaoConfig() (openbao.Config, error) {
	b := c.OpenBao
	cfg := openbao.Config{
		Addr:         b.Addr,
		TransitMount: b.TransitMount,
		KeyName:      b.KeyName,
		TLSCAFile:    b.TLSCAFile,
		TLSCertFile:  b.TLSCertFile,
		TLSKeyFile:   b.TLSKeyFile,
		AuthMethod:   openbao.AuthMethodKind(b.AuthMethod),

		AppRoleMount:        b.AppRoleMount,
		AppRoleRoleID:       b.AppRoleRoleID,
		AppRoleRoleIDFile:   b.AppRoleRoleIDFile,
		AppRoleSecretIDFile: b.AppRoleSecretIDFile,

		TokenFile: b.TokenFile,

		K8sMount:   b.KubernetesMount,
		K8sRole:    b.KubernetesRole,
		K8sJWTFile: b.KubernetesJWTFile,
	}
	if err := cfg.Validate(); err != nil {
		return openbao.Config{}, err
	}
	return cfg, nil
}
