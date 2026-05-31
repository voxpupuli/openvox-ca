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

package config

import (
	"path/filepath"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

// StorageConfig is the storage-backend portion of a puppet-ca configuration,
// shared by the server (cmd/puppet-ca) and the operator CLI (cmd/puppet-ca-ctl)
// so that both interpret the same YAML keys identically. The server embeds it
// inline into its larger config; the migrate command parses two of them, one
// per backend.
type StorageConfig struct {
	// Storage backend selection. "filesystem" (default) stores all CA data
	// under cadir; "etcd" keeps CA cert, key, CRL, inventory, serial, CSRs
	// and signed certs in an etcd cluster; "redis" (alias "valkey") keeps
	// the same state in a Redis/Valkey instance or Sentinel-managed primary;
	// "sqlite", "postgres" and "mysql"/"mariadb" use a SQL database
	// (per-subject generated private keys always remain on local disk under
	// cadir, regardless of backend).
	StorageBackend        string   `yaml:"storage_backend"`
	EtcdEndpoints         []string `yaml:"etcd_endpoints"`
	EtcdKeyPrefix         string   `yaml:"etcd_key_prefix"`
	EtcdUsername          string   `yaml:"etcd_username"`
	EtcdPassword          string   `yaml:"etcd_password"`
	EtcdDialTimeoutSec    int      `yaml:"etcd_dial_timeout_sec"`
	EtcdRequestTimeoutSec int      `yaml:"etcd_request_timeout_sec"`
	EtcdTLSCAFile         string   `yaml:"etcd_tls_ca_file"`
	EtcdTLSCertFile       string   `yaml:"etcd_tls_cert_file"`
	EtcdTLSKeyFile        string   `yaml:"etcd_tls_key_file"`

	// Redis/Valkey backend. RedisAddrs is used in direct mode; when
	// RedisSentinelMasterName is set, the client resolves the primary via
	// RedisSentinelAddrs and follows failovers automatically.
	RedisAddrs              []string `yaml:"redis_addrs"`
	RedisSentinelMasterName string   `yaml:"redis_sentinel_master_name"`
	RedisSentinelAddrs      []string `yaml:"redis_sentinel_addrs"`
	RedisSentinelUsername   string   `yaml:"redis_sentinel_username"`
	RedisSentinelPassword   string   `yaml:"redis_sentinel_password"`
	RedisDB                 int      `yaml:"redis_db"`
	RedisUsername           string   `yaml:"redis_username"`
	RedisPassword           string   `yaml:"redis_password"`
	RedisKeyPrefix          string   `yaml:"redis_key_prefix"`
	RedisDialTimeoutSec     int      `yaml:"redis_dial_timeout_sec"`
	RedisRequestTimeoutSec  int      `yaml:"redis_request_timeout_sec"`
	RedisLockTTLSec         int      `yaml:"redis_lock_ttl_sec"`
	RedisTLSCAFile          string   `yaml:"redis_tls_ca_file"`
	RedisTLSCertFile        string   `yaml:"redis_tls_cert_file"`
	RedisTLSKeyFile         string   `yaml:"redis_tls_key_file"`

	// SQL backend (sqlite, postgres, mysql/mariadb). SQLDSN is the
	// driver-specific data source name: a file path/URI for SQLite
	// ("file:/var/lib/puppet-ca/ca.db"), or a connection string for the
	// networked engines. SQLTLS* apply only to the networked dialects.
	SQLDSN               string `yaml:"sql_dsn"`
	SQLRequestTimeoutSec int    `yaml:"sql_request_timeout_sec"`
	SQLMaxOpenConns      int    `yaml:"sql_max_open_conns"`
	SQLMaxIdleConns      int    `yaml:"sql_max_idle_conns"`
	SQLTLSCAFile         string `yaml:"sql_tls_ca_file"`
	SQLTLSCertFile       string `yaml:"sql_tls_cert_file"`
	SQLTLSKeyFile        string `yaml:"sql_tls_key_file"`

	// Local-file overrides. When set, the named asset is read/written via
	// this filesystem path regardless of the selected backend. Typical use:
	// keep the CA cert and/or key on local disk (or a mounted secret volume)
	// while storing CSRs, signed certs, CRL and inventory in a remote backend.
	CACertFile string `yaml:"ca_cert_file"`
	CAKeyFile  string `yaml:"ca_key_file"`
}

// ToBackendSpec derives a storage.BackendSpec from the configured backend
// fields. localDir is the operational directory on local disk: the backend
// root for the filesystem backend, and the location of per-subject generated
// private keys for every backend. It returns an error for an unknown backend
// name.
func (c StorageConfig) ToBackendSpec(localDir string) (storage.BackendSpec, error) {
	kind, err := storage.ParseBackendKind(c.StorageBackend)
	if err != nil {
		return storage.BackendSpec{}, err
	}
	spec := storage.BackendSpec{
		Kind:       kind,
		LocalDir:   localDir,
		CACertFile: absIfSet(c.CACertFile),
		CAKeyFile:  absIfSet(c.CAKeyFile),
	}
	switch kind {
	case storage.BackendEtcd:
		spec.Etcd = storage.EtcdSpec{
			Endpoints:         c.EtcdEndpoints,
			KeyPrefix:         c.EtcdKeyPrefix,
			Username:          c.EtcdUsername,
			Password:          c.EtcdPassword,
			DialTimeoutSec:    c.EtcdDialTimeoutSec,
			RequestTimeoutSec: c.EtcdRequestTimeoutSec,
			TLSCAFile:         c.EtcdTLSCAFile,
			TLSCertFile:       c.EtcdTLSCertFile,
			TLSKeyFile:        c.EtcdTLSKeyFile,
		}
	case storage.BackendRedis:
		spec.Redis = storage.RedisSpec{
			Addrs:              c.RedisAddrs,
			SentinelMasterName: c.RedisSentinelMasterName,
			SentinelAddrs:      c.RedisSentinelAddrs,
			SentinelUsername:   c.RedisSentinelUsername,
			SentinelPassword:   c.RedisSentinelPassword,
			DB:                 c.RedisDB,
			Username:           c.RedisUsername,
			Password:           c.RedisPassword,
			KeyPrefix:          c.RedisKeyPrefix,
			DialTimeoutSec:     c.RedisDialTimeoutSec,
			RequestTimeoutSec:  c.RedisRequestTimeoutSec,
			LockTTLSec:         c.RedisLockTTLSec,
			TLSCAFile:          c.RedisTLSCAFile,
			TLSCertFile:        c.RedisTLSCertFile,
			TLSKeyFile:         c.RedisTLSKeyFile,
		}
	case storage.BackendSQLite, storage.BackendPostgres, storage.BackendMySQL:
		spec.SQL = storage.SQLSpec{
			DSN:               c.SQLDSN,
			RequestTimeoutSec: c.SQLRequestTimeoutSec,
			MaxOpenConns:      c.SQLMaxOpenConns,
			MaxIdleConns:      c.SQLMaxIdleConns,
			TLSCAFile:         c.SQLTLSCAFile,
			TLSCertFile:       c.SQLTLSCertFile,
			TLSKeyFile:        c.SQLTLSKeyFile,
		}
	}
	return spec, nil
}

// absIfSet returns filepath.Abs(p) when p is non-empty, otherwise "".
// Resolving at config time lets error messages and logs show canonical paths.
func absIfSet(p string) string {
	if p == "" {
		return ""
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}
