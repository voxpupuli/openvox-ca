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

// Package openbao implements a crypto.Signer backed by an OpenBao Transit
// secrets engine key, so the CA private key never has to exist inside any
// openvox-ca process. It authenticates to OpenBao itself (AppRole, a static
// token file, or Kubernetes auth) and maintains its own token lifecycle —
// proactively renewing before expiry and re-authenticating from source
// credentials when renewal fails — so no external agent/sidecar is needed to
// keep it working.
package openbao

import (
	"fmt"
	"time"
)

// AuthMethodKind selects which OpenBao auth method Config uses to obtain its
// initial (and any subsequent) client token.
type AuthMethodKind string

const (
	AuthAppRole    AuthMethodKind = "approle"
	AuthToken      AuthMethodKind = "token"
	AuthKubernetes AuthMethodKind = "kubernetes"
)

// Config describes how to connect and authenticate to OpenBao, and which
// Transit key to use as the CA's private key. It is the config-file-friendly
// form consumed by NewSigner/NewKeyProvider; field names mirror the
// storage-backend Spec types (EtcdSpec, RedisSpec) in internal/storage/spec.go.
// The server's own configuration (cmd/openvox-ca, internal/config) nests the
// fields below under a top-level "openbao" YAML key / --openbao-* flags; see
// docs/openbao-transit.md.
type Config struct {
	// Addr is the OpenBao server address: a full URI including scheme and
	// port, e.g. "https://openbao.example.com:8200". "http://" is also
	// accepted (e.g. for a plain-HTTP listener in development).
	Addr string
	// TransitMount is the Transit secrets engine mount path. Empty selects
	// "transit".
	TransitMount string
	// KeyName is the name of the Transit key backing the CA's private key.
	KeyName string

	// TLSCAFile, TLSCertFile, and TLSKeyFile configure the client's TLS
	// connection to OpenBao (server CA verification and optional mTLS).
	// All may be empty to use the platform's default trust store.
	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string

	// AuthMethod selects how to authenticate. Empty is invalid; the caller
	// must pick one of AuthAppRole, AuthToken, or AuthKubernetes.
	AuthMethod AuthMethodKind

	// AppRoleMount is the AppRole auth method's mount path. Empty selects
	// "approle".
	AppRoleMount string
	// AppRoleRoleID is the AppRole role_id. May be a literal value or, if
	// AppRoleRoleIDFile is set, is ignored in favour of the file's contents.
	AppRoleRoleID string
	// AppRoleRoleIDFile, if set, is read fresh on every login (first line,
	// trimmed) instead of using AppRoleRoleID directly.
	AppRoleRoleIDFile string
	// AppRoleSecretIDFile is the path to the AppRole secret_id, read fresh
	// on every login attempt so a rotated secret_id is always picked up.
	AppRoleSecretIDFile string

	// TokenFile is the path to a file containing a pre-issued OpenBao token
	// (first line, trimmed) for AuthToken. Re-read whenever the token
	// currently in use is rejected or fails to renew.
	TokenFile string

	// K8sMount is the Kubernetes auth method's mount path. Empty selects
	// "kubernetes".
	K8sMount string
	// K8sRole is the OpenBao Kubernetes auth role name.
	K8sRole string
	// K8sJWTFile is the path to the projected ServiceAccount token. Empty
	// selects the standard in-cluster path
	// (/var/run/secrets/kubernetes.io/serviceaccount/token). Always read
	// fresh at login time: bound ServiceAccount tokens are short-lived and
	// kubelet rewrites this file in place well before expiry.
	K8sJWTFile string

	// LoginTimeout bounds a single login/renew HTTP round trip. Zero uses a
	// built-in default.
	LoginTimeout time.Duration
}

// defaultLoginTimeout mirrors the dial-timeout defaulting convention used by
// the etcd/redis storage backends (internal/storage/etcd.go).
const defaultLoginTimeout = 10 * time.Second

func (c Config) loginTimeout() time.Duration {
	if c.LoginTimeout > 0 {
		return c.LoginTimeout
	}
	return defaultLoginTimeout
}

// EffectiveTransitMount returns the configured Transit mount path, or the
// default ("transit") when unset. Callers constructing a Signer/KeyProvider
// should use this rather than the raw TransitMount field.
func (c Config) EffectiveTransitMount() string {
	if c.TransitMount != "" {
		return c.TransitMount
	}
	return "transit"
}

// Validate reports a config error before any network I/O is attempted.
func (c Config) Validate() error {
	if c.Addr == "" {
		return fmt.Errorf("openbao.addr is required")
	}
	if c.KeyName == "" {
		return fmt.Errorf("openbao.key_name is required")
	}
	switch c.AuthMethod {
	case AuthAppRole:
		if c.AppRoleRoleID == "" && c.AppRoleRoleIDFile == "" {
			return fmt.Errorf("openbao auth method %q requires openbao.approle_role_id or openbao.approle_role_id_file", c.AuthMethod)
		}
		if c.AppRoleSecretIDFile == "" {
			return fmt.Errorf("openbao auth method %q requires openbao.approle_secret_id_file", c.AuthMethod)
		}
	case AuthToken:
		if c.TokenFile == "" {
			return fmt.Errorf("openbao auth method %q requires openbao.token_file", c.AuthMethod)
		}
	case AuthKubernetes:
		if c.K8sRole == "" {
			return fmt.Errorf("openbao auth method %q requires openbao.kubernetes_role", c.AuthMethod)
		}
	case "":
		return fmt.Errorf("openbao.auth_method is required (must be %q, %q, or %q)", AuthAppRole, AuthToken, AuthKubernetes)
	default:
		return fmt.Errorf("unknown openbao.auth_method %q (must be %q, %q, or %q)", c.AuthMethod, AuthAppRole, AuthToken, AuthKubernetes)
	}
	return nil
}
