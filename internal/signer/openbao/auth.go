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

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/openbao/openbao/api/auth/approle/v2"
	"github.com/openbao/openbao/api/auth/kubernetes/v2"
	"github.com/openbao/openbao/api/v2"
)

// authMethodFactory builds a fresh api.AuthMethod for every login attempt.
//
// This indirection exists because of a load-bearing detail in the official
// SDK: api/auth/kubernetes's KubernetesAuth reads the ServiceAccount JWT
// exactly once, inside NewKubernetesAuth, and caches it in the struct —
// Login() itself never touches the filesystem again. Bound ServiceAccount
// tokens are short-lived (default 1h) and kubelet rewrites the token file in
// place well before expiry, so reusing a single KubernetesAuth value across
// repeated logins would eventually authenticate with a stale, expired JWT
// even though a valid one is sitting on disk — precisely the "read the
// credential once at startup and never refresh it" failure this package
// exists to avoid. Constructing a new AuthMethod on every login call (via
// this factory) re-reads credentials from their source every time,
// regardless of which underlying auth method is in play.
//
// api/auth/approle's AppRoleAuth does re-read a secret_id file on every
// Login() call already, so a factory isn't strictly required for AppRole —
// but using the same factory shape for all three methods keeps TokenManager
// uniform and avoids relying on an SDK implementation detail that could
// change.
type authMethodFactory func() (api.AuthMethod, error)

// newAuthMethodFactory builds the factory for cfg.AuthMethod. tokenFile
// authentication is handled separately by TokenManager (it is not a /login
// exchange — the token is used directly via Client.SetToken), so it is not
// represented here.
func newAuthMethodFactory(cfg Config) (authMethodFactory, error) {
	switch cfg.AuthMethod {
	case AuthAppRole:
		return appRoleAuthFactory(cfg), nil
	case AuthKubernetes:
		return kubernetesAuthFactory(cfg), nil
	default:
		return nil, fmt.Errorf("auth method %q does not use a login exchange", cfg.AuthMethod)
	}
}

func appRoleAuthFactory(cfg Config) authMethodFactory {
	mount := cfg.AppRoleMount
	return func() (api.AuthMethod, error) {
		roleID := cfg.AppRoleRoleID
		if cfg.AppRoleRoleIDFile != "" {
			v, err := readFirstLine(cfg.AppRoleRoleIDFile)
			if err != nil {
				return nil, fmt.Errorf("reading openbao.approle_role_id_file: %w", err)
			}
			roleID = v
		}
		opts := []approle.LoginOption{}
		if mount != "" {
			opts = append(opts, approle.WithMountPath(mount))
		}
		return approle.NewAppRoleAuth(roleID, &approle.SecretID{FromFile: cfg.AppRoleSecretIDFile}, opts...)
	}
}

func kubernetesAuthFactory(cfg Config) authMethodFactory {
	mount := cfg.K8sMount
	jwtPath := cfg.K8sJWTFile
	return func() (api.AuthMethod, error) {
		opts := []kubernetes.LoginOption{}
		if mount != "" {
			opts = append(opts, kubernetes.WithMountPath(mount))
		}
		if jwtPath != "" {
			opts = append(opts, kubernetes.WithServiceAccountTokenPath(jwtPath))
		}
		// A zero-value NewKubernetesAuth call (no WithServiceAccountToken*
		// option) reads the default in-cluster path itself, matching
		// jwtPath == "" selecting that default too.
		return kubernetes.NewKubernetesAuth(cfg.K8sRole, opts...)
	}
}

// readFirstLine reads path and returns its first line with surrounding
// whitespace trimmed, mirroring the CA key passphrase file convention in
// internal/ca/keyenc.go.
func readFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("%s is empty", path)
	}
	line := strings.TrimSpace(sc.Text())
	if line == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return line, nil
}
