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
	BackendRedis      BackendKind = "redis"
	BackendSQLite     BackendKind = "sqlite"
	BackendPostgres   BackendKind = "postgres"
	BackendMySQL      BackendKind = "mysql"
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

	// Redis configures the Redis/Valkey backend. Only consulted when
	// Kind == BackendRedis.
	Redis RedisSpec

	// SQL configures a SQL backend (SQLite, and in later changes PostgreSQL and
	// MySQL/MariaDB). Only consulted when Kind is one of the SQL backends.
	SQL SQLSpec

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
	Endpoints         []string
	KeyPrefix         string
	Username          string
	Password          string
	DialTimeoutSec    int
	RequestTimeoutSec int
	TLSCAFile         string
	TLSCertFile       string
	TLSKeyFile        string
}

// RedisSpec is the config-friendly form of RedisConfig with TLS expressed
// as file paths rather than a preloaded tls.Config.
type RedisSpec struct {
	Addrs []string

	SentinelMasterName string
	SentinelAddrs      []string
	SentinelUsername   string
	SentinelPassword   string

	DB       int
	Username string
	Password string

	DialTimeoutSec    int
	RequestTimeoutSec int
	LockTTLSec        int

	KeyPrefix string

	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string
}

// SQLSpec is the config-friendly form of SQLConfig with TLS expressed as file
// paths rather than a preloaded tls.Config. The same spec serves every SQL
// dialect; the dialect is chosen by BackendSpec.Kind.
type SQLSpec struct {
	// DSN is the driver-specific data source name (a file path/URI for SQLite,
	// a connection string for PostgreSQL/MySQL).
	DSN string

	RequestTimeoutSec int
	MaxOpenConns      int
	MaxIdleConns      int

	// TLS file paths apply to the networked dialects (PostgreSQL, MySQL); they
	// are ignored by SQLite.
	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string
}

// sqlDialectForKind maps a BackendKind to the SQLBackend dialect, reporting
// whether the kind is a SQL backend at all.
func sqlDialectForKind(kind BackendKind) (SQLDialect, bool) {
	switch kind {
	case BackendSQLite:
		return SQLitePure, true
	case BackendPostgres:
		return SQLPostgres, true
	case BackendMySQL:
		return SQLMySQL, true
	default:
		return "", false
	}
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
		backend         Backend
		localPrivKeyDir string
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

	case BackendRedis:
		if spec.LocalDir == "" {
			return nil, fmt.Errorf("redis backend still needs LocalDir for local private keys")
		}
		if spec.Redis.SentinelMasterName == "" && len(spec.Redis.Addrs) == 0 {
			return nil, fmt.Errorf("redis backend requires redis_addrs or redis_sentinel_master_name+redis_sentinel_addrs")
		}
		if spec.Redis.SentinelMasterName != "" && len(spec.Redis.SentinelAddrs) == 0 {
			return nil, fmt.Errorf("redis backend: redis_sentinel_master_name requires redis_sentinel_addrs")
		}
		tlsCfg, err := loadRedisTLS(spec.Redis)
		if err != nil {
			return nil, err
		}
		cfg := RedisConfig{
			Addrs:              spec.Redis.Addrs,
			SentinelMasterName: spec.Redis.SentinelMasterName,
			SentinelAddrs:      spec.Redis.SentinelAddrs,
			SentinelUsername:   spec.Redis.SentinelUsername,
			SentinelPassword:   spec.Redis.SentinelPassword,
			DB:                 spec.Redis.DB,
			Username:           spec.Redis.Username,
			Password:           spec.Redis.Password,
			TLS:                tlsCfg,
			KeyPrefix:          spec.Redis.KeyPrefix,
		}
		if spec.Redis.DialTimeoutSec > 0 {
			cfg.DialTimeout = time.Duration(spec.Redis.DialTimeoutSec) * time.Second
		}
		if spec.Redis.RequestTimeoutSec > 0 {
			cfg.RequestTimeout = time.Duration(spec.Redis.RequestTimeoutSec) * time.Second
		}
		if spec.Redis.LockTTLSec > 0 {
			cfg.LockTTL = time.Duration(spec.Redis.LockTTLSec) * time.Second
		}
		rb, err := NewRedisBackend(cfg)
		if err != nil {
			return nil, err
		}
		backend = rb
		localPrivKeyDir = filepath.Join(spec.LocalDir, "private")

	case BackendSQLite, BackendPostgres, BackendMySQL:
		if spec.LocalDir == "" {
			return nil, fmt.Errorf("sql backend still needs LocalDir for local private keys")
		}
		if spec.SQL.DSN == "" {
			return nil, fmt.Errorf("sql backend requires sql_dsn")
		}
		dialect, ok := sqlDialectForKind(kind)
		if !ok {
			return nil, fmt.Errorf("backend kind %q is not a SQL dialect", kind)
		}
		cfg := SQLConfig{
			Dialect:      dialect,
			DSN:          spec.SQL.DSN,
			MaxOpenConns: spec.SQL.MaxOpenConns,
			MaxIdleConns: spec.SQL.MaxIdleConns,
		}
		if spec.SQL.RequestTimeoutSec > 0 {
			cfg.RequestTimeout = time.Duration(spec.SQL.RequestTimeoutSec) * time.Second
		}
		// SQLite is a local file with no transport security; TLS applies only
		// to the networked dialects.
		if dialect != SQLitePure {
			tlsCfg, err := loadSQLTLS(spec.SQL)
			if err != nil {
				return nil, err
			}
			cfg.TLS = tlsCfg
		}
		sb, err := NewSQLBackend(cfg)
		if err != nil {
			return nil, err
		}
		backend = sb
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
	return loadBackendTLS(spec.TLSCAFile, spec.TLSCertFile, spec.TLSKeyFile, "etcd")
}

func loadRedisTLS(spec RedisSpec) (*tls.Config, error) {
	return loadBackendTLS(spec.TLSCAFile, spec.TLSCertFile, spec.TLSKeyFile, "redis")
}

func loadSQLTLS(spec SQLSpec) (*tls.Config, error) {
	return loadBackendTLS(spec.TLSCAFile, spec.TLSCertFile, spec.TLSKeyFile, "sql")
}

// loadBackendTLS reads CA/cert/key PEMs into a tls.Config shared by backends.
// label appears in error messages to disambiguate which backend's config is
// malformed. Returns (nil, nil) when all three fields are empty.
func loadBackendTLS(caFile, certFile, keyFile, label string) (*tls.Config, error) {
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading %s TLS CA: %w", label, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("%s TLS CA file %s contains no usable certificates", label, caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("%s TLS client cert and key must both be set", label)
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading %s client cert/key: %w", label, err)
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
	case "redis", "valkey":
		return BackendRedis, nil
	case "sqlite", "sqlite3":
		return BackendSQLite, nil
	case "postgres", "postgresql", "pg":
		return BackendPostgres, nil
	case "mysql", "mariadb":
		return BackendMySQL, nil
	default:
		return "", fmt.Errorf("unknown storage backend %q (supported: filesystem, etcd, redis, sqlite, postgres, mysql)", s)
	}
}
