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

package config_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("StorageConfig.ToBackendSpec", func() {
	// localDir is an absolute path so it is propagated verbatim into
	// BackendSpec.LocalDir (ToBackendSpec does not re-resolve it).
	const localDir = "/var/lib/puppet-ca"

	Describe("backend kind resolution", func() {
		// Every accepted alias must resolve to the canonical kind so that
		// operators can spell the backend the way their YAML does. The default
		// (empty string) must resolve to the filesystem backend.
		DescribeTable("maps the configured name onto the canonical BackendKind",
			func(configured string, expected storage.BackendKind) {
				spec, err := config.StorageConfig{StorageBackend: configured}.ToBackendSpec(localDir)
				Expect(err).NotTo(HaveOccurred())
				Expect(spec.Kind).To(Equal(expected))
				Expect(spec.LocalDir).To(Equal(localDir))
			},
			Entry("empty defaults to filesystem", "", storage.BackendFilesystem),
			Entry("filesystem", "filesystem", storage.BackendFilesystem),
			Entry("file alias", "file", storage.BackendFilesystem),
			Entry("fs alias", "fs", storage.BackendFilesystem),
			Entry("disk alias", "disk", storage.BackendFilesystem),
			Entry("local alias", "local", storage.BackendFilesystem),
			Entry("etcd", "etcd", storage.BackendEtcd),
			Entry("redis", "redis", storage.BackendRedis),
			Entry("valkey alias", "valkey", storage.BackendRedis),
			Entry("sqlite", "sqlite", storage.BackendSQLite),
			Entry("sqlite3 alias", "sqlite3", storage.BackendSQLite),
			Entry("postgres", "postgres", storage.BackendPostgres),
			Entry("postgresql alias", "postgresql", storage.BackendPostgres),
			Entry("pg alias", "pg", storage.BackendPostgres),
			Entry("mysql", "mysql", storage.BackendMySQL),
			Entry("mariadb alias", "mariadb", storage.BackendMySQL),
		)

		It("is case- and whitespace-insensitive", func() {
			spec, err := config.StorageConfig{StorageBackend: "  ETCD  "}.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.Kind).To(Equal(storage.BackendEtcd))
		})

		It("returns an error for an unknown backend and a zero spec", func() {
			spec, err := config.StorageConfig{StorageBackend: "cassandra"}.ToBackendSpec(localDir)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unknown storage backend"))
			Expect(err.Error()).To(ContainSubstring("cassandra"))
			Expect(spec).To(Equal(storage.BackendSpec{}))
		})
	})

	Describe("CA file overrides", func() {
		// CACertFile/CAKeyFile are populated for every backend kind and run
		// through absIfSet, so a relative path is resolved to an absolute one.
		It("resolves the CA cert and key override paths to absolute form", func() {
			spec, err := config.StorageConfig{
				StorageBackend: "filesystem",
				CACertFile:     "certs/ca.pem",
				CAKeyFile:      "certs/ca.key",
			}.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.CACertFile).To(Equal(absViaRoot("certs/ca.pem")))
			Expect(spec.CAKeyFile).To(Equal(absViaRoot("certs/ca.key")))
		})

		It("leaves unset override paths empty", func() {
			spec, err := config.StorageConfig{StorageBackend: "filesystem"}.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.CACertFile).To(BeEmpty())
			Expect(spec.CAKeyFile).To(BeEmpty())
		})
	})

	Describe("filesystem backend", func() {
		// The switch has no filesystem case, so none of the backend sub-specs
		// are populated. Guard against a future edit that accidentally leaks
		// another backend's fields into a filesystem spec.
		It("leaves every backend-specific sub-spec at its zero value", func() {
			spec, err := config.StorageConfig{StorageBackend: "filesystem"}.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.Etcd).To(Equal(storage.EtcdSpec{}))
			Expect(spec.Redis).To(Equal(storage.RedisSpec{}))
			Expect(spec.SQL).To(Equal(storage.SQLSpec{}))
		})
	})

	Describe("etcd backend", func() {
		// Asserts every etcd field — including the EtcdPassword secret, the
		// TLS CA/cert/key paths, and the key prefix — is carried into the spec.
		It("propagates every etcd field including the password and TLS paths", func() {
			cfg := config.StorageConfig{
				StorageBackend:        "etcd",
				EtcdEndpoints:         []string{"https://etcd-1:2379", "https://etcd-2:2379"},
				EtcdKeyPrefix:         "/puppet-ca/",
				EtcdUsername:          "ca-writer",
				EtcdPassword:          "etcd-s3cr3t",
				EtcdDialTimeoutSec:    7,
				EtcdRequestTimeoutSec: 11,
				EtcdTLSCAFile:         "/tls/etcd-ca.pem",
				EtcdTLSCertFile:       "/tls/etcd-client.pem",
				EtcdTLSKeyFile:        "/tls/etcd-client.key",
			}
			spec, err := cfg.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.Kind).To(Equal(storage.BackendEtcd))
			Expect(spec.Etcd).To(Equal(storage.EtcdSpec{
				Endpoints:         []string{"https://etcd-1:2379", "https://etcd-2:2379"},
				KeyPrefix:         "/puppet-ca/",
				Username:          "ca-writer",
				Password:          "etcd-s3cr3t",
				DialTimeoutSec:    7,
				RequestTimeoutSec: 11,
				TLSCAFile:         "/tls/etcd-ca.pem",
				TLSCertFile:       "/tls/etcd-client.pem",
				TLSKeyFile:        "/tls/etcd-client.key",
			}))
			// Other backends' sub-specs stay zero.
			Expect(spec.Redis).To(Equal(storage.RedisSpec{}))
			Expect(spec.SQL).To(Equal(storage.SQLSpec{}))
		})

		It("preserves the etcd password even when no TLS is configured", func() {
			spec, err := config.StorageConfig{
				StorageBackend: "etcd",
				EtcdEndpoints:  []string{"http://etcd:2379"},
				EtcdPassword:   "only-a-password",
			}.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.Etcd.Password).To(Equal("only-a-password"))
		})
	})

	Describe("redis backend", func() {
		// Asserts every redis field, including both secrets (RedisPassword and
		// the Sentinel credentials) and the TLS paths, reaches the spec.
		It("propagates every redis field including direct and sentinel credentials", func() {
			cfg := config.StorageConfig{
				StorageBackend:          "redis",
				RedisAddrs:              []string{"redis-a:6379", "redis-b:6379"},
				RedisSentinelMasterName: "mymaster",
				RedisSentinelAddrs:      []string{"sentinel-a:26379", "sentinel-b:26379"},
				RedisSentinelUsername:   "sentinel-user",
				RedisSentinelPassword:   "sentinel-s3cr3t",
				RedisDB:                 3,
				RedisUsername:           "ca-redis",
				RedisPassword:           "redis-s3cr3t",
				RedisKeyPrefix:          "puppet-ca:",
				RedisDialTimeoutSec:     4,
				RedisRequestTimeoutSec:  8,
				RedisLockTTLSec:         30,
				RedisTLSCAFile:          "/tls/redis-ca.pem",
				RedisTLSCertFile:        "/tls/redis-client.pem",
				RedisTLSKeyFile:         "/tls/redis-client.key",
			}
			spec, err := cfg.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.Kind).To(Equal(storage.BackendRedis))
			Expect(spec.Redis).To(Equal(storage.RedisSpec{
				Addrs:              []string{"redis-a:6379", "redis-b:6379"},
				SentinelMasterName: "mymaster",
				SentinelAddrs:      []string{"sentinel-a:26379", "sentinel-b:26379"},
				SentinelUsername:   "sentinel-user",
				SentinelPassword:   "sentinel-s3cr3t",
				DB:                 3,
				Username:           "ca-redis",
				Password:           "redis-s3cr3t",
				DialTimeoutSec:     4,
				RequestTimeoutSec:  8,
				LockTTLSec:         30,
				KeyPrefix:          "puppet-ca:",
				TLSCAFile:          "/tls/redis-ca.pem",
				TLSCertFile:        "/tls/redis-client.pem",
				TLSKeyFile:         "/tls/redis-client.key",
			}))
			Expect(spec.Etcd).To(Equal(storage.EtcdSpec{}))
			Expect(spec.SQL).To(Equal(storage.SQLSpec{}))
		})

		It("carries both redis secrets through when set in isolation", func() {
			spec, err := config.StorageConfig{
				StorageBackend:        "valkey",
				RedisAddrs:            []string{"valkey:6379"},
				RedisPassword:         "direct-secret",
				RedisSentinelPassword: "sentinel-secret",
			}.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.Redis.Password).To(Equal("direct-secret"))
			Expect(spec.Redis.SentinelPassword).To(Equal("sentinel-secret"))
		})
	})

	Describe("SQL backends", func() {
		// Every SQL dialect shares one SQLSpec; the DSN (which itself may embed
		// a password) and the TLS paths must propagate for each dialect.
		DescribeTable("propagate the DSN and TLS paths for each SQL dialect",
			func(configured string, expectedKind storage.BackendKind) {
				cfg := config.StorageConfig{
					StorageBackend:       configured,
					SQLDSN:               "user:dsn-s3cr3t@tcp(db:3306)/puppetca",
					SQLRequestTimeoutSec: 9,
					SQLMaxOpenConns:      20,
					SQLMaxIdleConns:      5,
					SQLTLSCAFile:         "/tls/sql-ca.pem",
					SQLTLSCertFile:       "/tls/sql-client.pem",
					SQLTLSKeyFile:        "/tls/sql-client.key",
				}
				spec, err := cfg.ToBackendSpec(localDir)
				Expect(err).NotTo(HaveOccurred())
				Expect(spec.Kind).To(Equal(expectedKind))
				Expect(spec.SQL).To(Equal(storage.SQLSpec{
					DSN:               "user:dsn-s3cr3t@tcp(db:3306)/puppetca",
					RequestTimeoutSec: 9,
					MaxOpenConns:      20,
					MaxIdleConns:      5,
					TLSCAFile:         "/tls/sql-ca.pem",
					TLSCertFile:       "/tls/sql-client.pem",
					TLSKeyFile:        "/tls/sql-client.key",
				}))
				Expect(spec.Etcd).To(Equal(storage.EtcdSpec{}))
				Expect(spec.Redis).To(Equal(storage.RedisSpec{}))
			},
			Entry("sqlite", "sqlite", storage.BackendSQLite),
			Entry("postgres", "postgres", storage.BackendPostgres),
			Entry("mysql", "mysql", storage.BackendMySQL),
		)

		It("preserves a DSN-embedded password verbatim", func() {
			spec, err := config.StorageConfig{
				StorageBackend: "postgres",
				SQLDSN:         "postgres://ca:p%40ss@db:5432/puppetca?sslmode=require",
			}.ToBackendSpec(localDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(spec.SQL.DSN).To(Equal("postgres://ca:p%40ss@db:5432/puppetca?sslmode=require"))
		})
	})
})
