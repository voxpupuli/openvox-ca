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

package main

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("applyServerEnv SQL settings", func() {
	It("applies all SQL-related env vars", func() {
		setEnv("PUPPET_CA_STORAGE_BACKEND", "sqlite")
		setEnv("PUPPET_CA_SQL_DSN", "file:/var/lib/puppet-ca/ca.db")
		setEnv("PUPPET_CA_SQL_REQUEST_TIMEOUT_SEC", "15")
		setEnv("PUPPET_CA_SQL_MAX_OPEN_CONNS", "8")
		setEnv("PUPPET_CA_SQL_MAX_IDLE_CONNS", "4")

		cfg := &serverConfig{}
		applyServerEnv(cfg)

		Expect(cfg.StorageBackend).To(Equal("sqlite"), "StorageBackend = %q, want sqlite", cfg.StorageBackend)
		Expect(cfg.SQLDSN).To(Equal("file:/var/lib/puppet-ca/ca.db"), "SQLDSN = %q", cfg.SQLDSN)
		Expect(cfg.SQLRequestTimeoutSec).To(Equal(15), "SQLRequestTimeoutSec = %d, want 15", cfg.SQLRequestTimeoutSec)
		Expect(cfg.SQLMaxOpenConns).To(Equal(8), "SQLMaxOpenConns = %d, want 8", cfg.SQLMaxOpenConns)
		Expect(cfg.SQLMaxIdleConns).To(Equal(4), "SQLMaxIdleConns = %d, want 4", cfg.SQLMaxIdleConns)
	})
})

var _ = Describe("buildBackendSpec", func() {
	DescribeTable("SQLite aliases",
		func(alias string) {
			cfg := &serverConfig{
				StorageConfig: config.StorageConfig{
					StorageBackend:       alias,
					SQLDSN:               "file:/tmp/ca.db",
					SQLRequestTimeoutSec: 12,
				},
			}
			spec, err := buildBackendSpec(cfg, "/abs/cadir")
			Expect(err).NotTo(HaveOccurred(), "buildBackendSpec")
			Expect(spec.Kind).To(Equal(storage.BackendSQLite), "Kind = %q, want %q", spec.Kind, storage.BackendSQLite)
			Expect(spec.SQL.DSN).To(Equal("file:/tmp/ca.db"), "SQL.DSN = %q", spec.SQL.DSN)
			Expect(spec.SQL.RequestTimeoutSec).To(Equal(12), "SQL.RequestTimeoutSec = %d, want 12", spec.SQL.RequestTimeoutSec)
			Expect(spec.LocalDir).To(Equal("/abs/cadir"), "LocalDir = %q, want /abs/cadir", spec.LocalDir)
		},
		Entry("sqlite", "sqlite"),
		Entry("sqlite3", "sqlite3"),
	)

	DescribeTable("Postgres aliases",
		func(alias string) {
			cfg := &serverConfig{
				StorageConfig: config.StorageConfig{
					StorageBackend: alias,
					SQLDSN:         "postgres://u:p@host:5432/db?sslmode=require",
					SQLTLSCAFile:   "/etc/pg-ca.pem",
				},
			}
			spec, err := buildBackendSpec(cfg, "/abs/cadir")
			Expect(err).NotTo(HaveOccurred(), "buildBackendSpec")
			Expect(spec.Kind).To(Equal(storage.BackendPostgres), "Kind = %q, want %q", spec.Kind, storage.BackendPostgres)
			Expect(spec.SQL.DSN).To(Equal(cfg.SQLDSN), "SQL.DSN = %q", spec.SQL.DSN)
			Expect(spec.SQL.TLSCAFile).To(Equal("/etc/pg-ca.pem"), "SQL.TLSCAFile = %q", spec.SQL.TLSCAFile)
		},
		Entry("postgres", "postgres"),
		Entry("postgresql", "postgresql"),
		Entry("pg", "pg"),
	)

	DescribeTable("MySQL aliases",
		func(alias string) {
			cfg := &serverConfig{
				StorageConfig: config.StorageConfig{
					StorageBackend: alias,
					SQLDSN:         "puppetca:secret@tcp(db:3306)/puppetca",
				},
			}
			spec, err := buildBackendSpec(cfg, "/abs/cadir")
			Expect(err).NotTo(HaveOccurred(), "buildBackendSpec")
			Expect(spec.Kind).To(Equal(storage.BackendMySQL), "Kind = %q, want %q", spec.Kind, storage.BackendMySQL)
			Expect(spec.SQL.DSN).To(Equal(cfg.SQLDSN), "SQL.DSN = %q", spec.SQL.DSN)
		},
		Entry("mysql", "mysql"),
		Entry("mariadb", "mariadb"),
	)
})

var _ = Describe("NewServiceFromSpec", func() {
	It("returns an error when the SQLite DSN is empty", func() {
		_, err := storage.NewServiceFromSpec(storage.BackendSpec{
			Kind:     storage.BackendSQLite,
			LocalDir: GinkgoT().TempDir(),
		})
		Expect(err).To(HaveOccurred(), "expected error when sql_dsn is empty, got nil")
	})
})
