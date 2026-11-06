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
	"reflect"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// sharedStorageKeys are the StorageConfig keys every backend reads. Anything
// else in StorageConfig belongs to one backend that is not the filesystem one,
// and the filesystem backend ignores it.
var sharedStorageKeys = []string{"storage_backend", "ca_cert_file", "ca_key_file"}

// storageKeys returns every yaml key StorageConfig declares, in order.
func storageKeys() []string {
	t := reflect.TypeFor[config.StorageConfig]()
	keys := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		key, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		keys = append(keys, key)
	}
	return keys
}

// withSetting returns c with the field whose yaml key is key set to a non-zero
// value of its type.
func withSetting(c config.StorageConfig, key string) config.StorageConfig {
	v := reflect.ValueOf(&c).Elem()
	t := v.Type()
	for i := range t.NumField() {
		k, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if k != key {
			continue
		}
		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString("set")
		case reflect.Int:
			f.SetInt(1)
		case reflect.Slice:
			f.Set(reflect.ValueOf([]string{"set"}))
		default:
			Fail("withSetting does not know how to set " + key + " (" + f.Kind().String() + ")")
		}
		return c
	}
	Fail("StorageConfig has no key " + key)
	return c
}

// backendSettingEntries is one entry per StorageConfig key that is not shared,
// derived from the struct so that a setting added later gets an entry without
// anyone writing one.
func backendSettingEntries() []TableEntry {
	var entries []TableEntry
	for _, key := range storageKeys() {
		if isShared(key) {
			continue
		}
		entries = append(entries, Entry(key, key))
	}
	return entries
}

func isShared(key string) bool {
	for _, s := range sharedStorageKeys {
		if key == s {
			return true
		}
	}
	return false
}

// A server with backend settings but no storage_backend used to start on the
// filesystem backend and ignore every one of them (#484). On a deployment
// whose cadir is not persistent that is an empty store, which serves an empty
// CRL, so clients checking it accept revoked certificates.
var _ = Describe("StorageConfig.ToBackendSpec on the filesystem backend", func() {
	const localDir = "/var/lib/openvox-ca"

	// The entries below are derived from StorageConfig, and so is the code
	// under test, so this pins what the derivation has to find. A refusal
	// that found nothing would pass a table with no entries.
	It("classifies every storage key, and finds the settings of each backend", func() {
		var backend []string
		for _, key := range storageKeys() {
			if isShared(key) {
				continue
			}
			Expect(key).To(Or(HavePrefix("etcd_"), HavePrefix("redis_"), HavePrefix("sql_")),
				"%s is neither shared nor a known backend's setting: decide which it is, "+
					"and whether the filesystem backend reads it", key)
			backend = append(backend, key)
		}
		Expect(backend).To(ContainElements(
			"etcd_endpoints", "etcd_password",
			"redis_addrs", "redis_sentinel_master_name", "redis_db",
			"sql_dsn", "sql_dsn_file", "sql_tls_ca_file",
		))
		Expect(storageKeys()).To(ContainElements(sharedStorageKeys))
	})

	DescribeTable("refuses each setting only another backend reads when storage_backend is unset",
		func(key string) {
			spec, err := withSetting(config.StorageConfig{}, key).ToBackendSpec(localDir)
			Expect(err).To(MatchError(And(
				ContainSubstring("storage_backend is not set, so the filesystem backend is selected"),
				ContainSubstring("("+key+")"),
				ContainSubstring("set storage_backend to the backend they configure"),
			)))
			Expect(spec).To(Equal(storage.BackendSpec{}))
		},
		backendSettingEntries(),
	)

	// An explicit filesystem beside a DSN is as likely a leftover as a choice.
	DescribeTable("refuses them when storage_backend names the filesystem backend",
		func(configured string) {
			_, err := config.StorageConfig{
				StorageBackend: configured,
				SQLDSN:         "postgres://ca@db/ca",
			}.ToBackendSpec(localDir)
			Expect(err).To(MatchError(And(
				ContainSubstring(`storage_backend is "`+configured+`", the filesystem backend`),
				ContainSubstring("(sql_dsn)"),
			)))
		},
		Entry("filesystem", "filesystem"),
		Entry("an alias", "local"),
	)

	It("names every setting it found, in declaration order", func() {
		_, err := config.StorageConfig{
			SQLDSNFile:    "/run/secrets/dsn",
			EtcdEndpoints: []string{"https://etcd:2379"},
			RedisAddrs:    []string{"redis:6379"},
		}.ToBackendSpec(localDir)
		Expect(err).To(MatchError(ContainSubstring("(etcd_endpoints, redis_addrs, sql_dsn_file)")))
	})

	It("accepts the settings every backend reads", func() {
		spec, err := config.StorageConfig{
			CACertFile: "/etc/openvox-ca/ca.pem",
			CAKeyFile:  "/etc/openvox-ca/ca.key",
		}.ToBackendSpec(localDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(spec.Kind).To(Equal(storage.BackendFilesystem))
	})

	// An empty list decodes from `etcd_endpoints: []`, and says no more than
	// leaving the key out.
	It("treats an empty list as unset", func() {
		_, err := config.StorageConfig{EtcdEndpoints: []string{}}.ToBackendSpec(localDir)
		Expect(err).NotTo(HaveOccurred())
	})

	// Out of scope by decision: another backend's stray settings do not
	// change which store is opened, so they are not the fail-open #484 is.
	It("leaves another backend's settings alone when a non-filesystem backend is selected", func() {
		spec, err := config.StorageConfig{
			StorageBackend: "postgres",
			SQLDSN:         "postgres://ca@db/ca",
			EtcdEndpoints:  []string{"https://etcd:2379"},
		}.ToBackendSpec(localDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(spec.Kind).To(Equal(storage.BackendPostgres))
	})
})
