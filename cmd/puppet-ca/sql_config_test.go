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

package main

import (
	"testing"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

func TestApplyServerEnvSQL(t *testing.T) {
	t.Setenv("PUPPET_CA_STORAGE_BACKEND", "sqlite")
	t.Setenv("PUPPET_CA_SQL_DSN", "file:/var/lib/puppet-ca/ca.db")
	t.Setenv("PUPPET_CA_SQL_REQUEST_TIMEOUT_SEC", "15")
	t.Setenv("PUPPET_CA_SQL_MAX_OPEN_CONNS", "8")
	t.Setenv("PUPPET_CA_SQL_MAX_IDLE_CONNS", "4")

	cfg := &serverConfig{}
	applyServerEnv(cfg)

	if cfg.StorageBackend != "sqlite" {
		t.Errorf("StorageBackend = %q, want sqlite", cfg.StorageBackend)
	}
	if cfg.SQLDSN != "file:/var/lib/puppet-ca/ca.db" {
		t.Errorf("SQLDSN = %q", cfg.SQLDSN)
	}
	if cfg.SQLRequestTimeoutSec != 15 {
		t.Errorf("SQLRequestTimeoutSec = %d, want 15", cfg.SQLRequestTimeoutSec)
	}
	if cfg.SQLMaxOpenConns != 8 || cfg.SQLMaxIdleConns != 4 {
		t.Errorf("SQLMaxOpenConns/IdleConns = %d/%d, want 8/4", cfg.SQLMaxOpenConns, cfg.SQLMaxIdleConns)
	}
}

func TestBuildBackendSpecSQLite(t *testing.T) {
	for _, alias := range []string{"sqlite", "sqlite3"} {
		t.Run(alias, func(t *testing.T) {
			cfg := &serverConfig{
				StorageBackend:       alias,
				SQLDSN:               "file:/tmp/ca.db",
				SQLRequestTimeoutSec: 12,
			}
			spec, err := buildBackendSpec(cfg, "/abs/cadir")
			if err != nil {
				t.Fatalf("buildBackendSpec: %v", err)
			}
			if spec.Kind != storage.BackendSQLite {
				t.Errorf("Kind = %q, want %q", spec.Kind, storage.BackendSQLite)
			}
			if spec.SQL.DSN != "file:/tmp/ca.db" {
				t.Errorf("SQL.DSN = %q", spec.SQL.DSN)
			}
			if spec.SQL.RequestTimeoutSec != 12 {
				t.Errorf("SQL.RequestTimeoutSec = %d, want 12", spec.SQL.RequestTimeoutSec)
			}
			if spec.LocalDir != "/abs/cadir" {
				t.Errorf("LocalDir = %q, want /abs/cadir", spec.LocalDir)
			}
		})
	}
}

func TestNewServiceFromSpecSQLiteRequiresDSN(t *testing.T) {
	_, err := storage.NewServiceFromSpec(storage.BackendSpec{
		Kind:     storage.BackendSQLite,
		LocalDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected error when sql_dsn is empty, got nil")
	}
}
