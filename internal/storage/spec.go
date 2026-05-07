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

package storage

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BackendKind identifies which backend implementation to construct.
type BackendKind string

const (
	BackendFilesystem BackendKind = "filesystem"
	BackendEtcd       BackendKind = "etcd"
)

// BackendSpec describes how to construct a StorageService from configuration.
// It lets the main application defer backend selection to a single place.
type BackendSpec struct {
	// Kind selects the backend implementation. Empty means BackendFilesystem.
	Kind BackendKind

	// LocalDir is the operational directory on the local filesystem. For the
	// filesystem backend it is the backend root; for remote backends it is
	// still used for per-subject generated private keys (always local) and
	// for ancillary local state such as the auto-generated CA key passphrase.
	LocalDir string

	// Etcd configures the etcd backend. Only consulted when Kind == BackendEtcd.
	Etcd EtcdSpec

	// CACertFile, when non-empty, keeps the CA certificate on local disk at
	// this path regardless of the selected backend. Useful when operators
	// want to supply the cert as a file or mount it from a secret volume.
	CACertFile string

	// CAKeyFile, when non-empty, keeps the CA private key on local disk at
	// this path regardless of the selected backend. Combine with a remote
	// backend to keep the key out of shared storage.
	CAKeyFile string
}

// EtcdSpec is the config-friendly form of EtcdConfig with TLS expressed as
// file paths rather than a preloaded tls.Config.
type EtcdSpec struct {
	Endpoints      []string
	KeyPrefix      string
	Username       string
	Password       string
	DialTimeoutSec int
	RequestTimeoutSec int
	TLSCAFile      string
	TLSCertFile    string
	TLSKeyFile     string
}

// NewServiceFromSpec constructs a StorageService according to spec. Returns
// an error when the backend cannot be initialised (e.g. etcd unreachable).
// The caller is responsible for calling s.Backend().Close() at shutdown.
func NewServiceFromSpec(spec BackendSpec) (*StorageService, error) {
	kind := spec.Kind
	if kind == "" {
		kind = BackendFilesystem
	}

	var (
		backend          Backend
		localPrivKeyDir  string
	)

	switch kind {
	case BackendFilesystem:
		if spec.LocalDir == "" {
			return nil, fmt.Errorf("filesystem backend requires LocalDir")
		}
		backend = NewFilesystemBackend(spec.LocalDir)
		localPrivKeyDir = filepath.Join(spec.LocalDir, "private")

	case BackendEtcd:
		if len(spec.Etcd.Endpoints) == 0 {
			return nil, fmt.Errorf("etcd backend requires at least one endpoint")
		}
		if spec.LocalDir == "" {
			return nil, fmt.Errorf("etcd backend still needs LocalDir for local private keys")
		}
		tlsCfg, err := loadEtcdTLS(spec.Etcd)
		if err != nil {
			return nil, err
		}
		cfg := EtcdConfig{
			Endpoints: spec.Etcd.Endpoints,
			KeyPrefix: spec.Etcd.KeyPrefix,
			Username:  spec.Etcd.Username,
			Password:  spec.Etcd.Password,
			TLS:       tlsCfg,
		}
		if spec.Etcd.DialTimeoutSec > 0 {
			cfg.DialTimeout = time.Duration(spec.Etcd.DialTimeoutSec) * time.Second
		}
		if spec.Etcd.RequestTimeoutSec > 0 {
			cfg.RequestTimeout = time.Duration(spec.Etcd.RequestTimeoutSec) * time.Second
		}
		b, err := NewEtcdBackend(cfg)
		if err != nil {
			return nil, err
		}
		backend = b
		localPrivKeyDir = filepath.Join(spec.LocalDir, "private")

	default:
		return nil, fmt.Errorf("unknown storage backend kind %q", spec.Kind)
	}

	if overrides := collectOverrides(spec); len(overrides) > 0 {
		ov, err := NewOverlayBackend(backend, overrides)
		if err != nil {
			_ = backend.Close()
			return nil, err
		}
		backend = ov
	}

	return NewWithBackend(backend, localPrivKeyDir), nil
}

// collectOverrides builds the logical-key → local-path map from the spec's
// optional override fields. Empty paths are dropped.
func collectOverrides(spec BackendSpec) map[string]string {
	out := map[string]string{}
	if spec.CACertFile != "" {
		out[KeyCACert] = spec.CACertFile
	}
	if spec.CAKeyFile != "" {
		out[KeyCAKey] = spec.CAKeyFile
	}
	return out
}

func loadEtcdTLS(spec EtcdSpec) (*tls.Config, error) {
	if spec.TLSCAFile == "" && spec.TLSCertFile == "" && spec.TLSKeyFile == "" {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if spec.TLSCAFile != "" {
		caPEM, err := os.ReadFile(spec.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading etcd TLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("etcd TLS CA file %s contains no usable certificates", spec.TLSCAFile)
		}
		cfg.RootCAs = pool
	}
	if spec.TLSCertFile != "" || spec.TLSKeyFile != "" {
		if spec.TLSCertFile == "" || spec.TLSKeyFile == "" {
			return nil, fmt.Errorf("etcd TLS client cert and key must both be set")
		}
		cert, err := tls.LoadX509KeyPair(spec.TLSCertFile, spec.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading etcd client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// ParseBackendKind parses a kind string from configuration, accepting common
// aliases and rejecting unknown values.
func ParseBackendKind(s string) (BackendKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "filesystem", "file", "fs", "disk", "local":
		return BackendFilesystem, nil
	case "etcd":
		return BackendEtcd, nil
	default:
		return "", fmt.Errorf("unknown storage backend %q (supported: filesystem, etcd)", s)
	}
}
