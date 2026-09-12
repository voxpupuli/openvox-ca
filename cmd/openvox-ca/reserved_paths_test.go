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
	"reflect"
	"sort"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/certstore"
	"github.com/voxpupuli/openvox-ca/internal/config"
)

// The sweep that makes caOwnedPaths authoritative.
//
// An enumeration nobody re-derives is how this guard goes quietly wrong: the
// first version of caOwnedPaths listed the path settings declared on
// serverConfig itself and so omitted ca_cert_file and ca_key_file, which are
// declared on the embedded StorageConfig and name the CA's own certificate and
// private key. The list looked complete, the documentation asserted it was, and
// the one path the whole check exists to protect was not on it.
//
// So this walks serverConfig by reflection, finds every field whose YAML key is
// path-shaped, and requires each to be either reserved by caOwnedPaths or
// listed below with a reason. The reason is the point: it is what lets the next
// reader check a judgement rather than inherit it.
//
// The same shape as internal/api/authseam_test.go's guardedPackages sweep, and
// for the same reason.
var _ = Describe("the CA's own paths, as the managed_certs check sees them", func() {
	// notReserved are the path-shaped settings deliberately absent from
	// caOwnedPaths. Each carries why, because a bare exemption list is
	// indistinguishable from an oversight.
	// Keys are the qualified names the sweep produces, so a setting inside the
	// `openbao:` block is `openbao.tls_cert_file` rather than a bare
	// `tls_cert_file` that could be mistaken for the serving pair.
	notReserved := map[string]string{
		// Client TLS material for reaching a storage backend or a key provider.
		// Overwriting one breaks this CA's connection to its own backend, which
		// is loud and recoverable -- the file is re-copyable from wherever it
		// was provisioned. That is a different class from the CA key, which is
		// not reconstructible from anything. Reserving them is defensible and
		// may happen later; the decision today is that the check stays a
		// backstop over material that cannot be replaced.
		"etcd_tls_ca_file":               "backend client credential, replaceable",
		"etcd_tls_cert_file":             "backend client credential, replaceable",
		"etcd_tls_key_file":              "backend client credential, replaceable",
		"redis_tls_ca_file":              "backend client credential, replaceable",
		"redis_tls_cert_file":            "backend client credential, replaceable",
		"redis_tls_key_file":             "backend client credential, replaceable",
		"sql_tls_ca_file":                "backend client credential, replaceable",
		"sql_tls_cert_file":              "backend client credential, replaceable",
		"sql_tls_key_file":               "backend client credential, replaceable",
		"openbao.tls_ca_file":            "key-provider client credential, replaceable",
		"openbao.tls_cert_file":          "key-provider client credential, replaceable",
		"openbao.tls_key_file":           "key-provider client credential, replaceable",
		"openbao.approle_role_id_file":   "key-provider credential, replaceable",
		"openbao.approle_secret_id_file": "key-provider credential, replaceable",
		"openbao.token_file":             "key-provider credential, replaceable",
		"openbao.kubernetes_jwt_file":    "projected by the kubelet, not ours to protect",
	}

	// pathShaped decides which YAML keys name a filesystem location. Deliberately
	// broad: a key this matches that is not a path costs one line in the map
	// above, whereas a path it misses is the defect this spec exists to catch.
	pathShaped := func(key string) bool {
		for _, suffix := range []string{"file", "dir", "path", "_config"} {
			if strings.HasSuffix(key, suffix) {
				return true
			}
		}
		return false
	}

	// sweep walks serverConfig the way the decoder reads it -- following inline
	// embeds transparently, and descending into a named block under its own
	// key -- and yields every string-typed setting as (qualified name, field).
	// Both directions of this spec use it, so neither can judge a set of keys
	// the other never saw.
	var sweep func(sv reflect.Value, prefix string, yield func(string, reflect.Value))
	sweep = func(sv reflect.Value, prefix string, yield func(string, reflect.Value)) {
		t := sv.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if f.Anonymous && strings.Contains(opts, "inline") {
				sweep(sv.Field(i), prefix, yield)
				continue
			}
			if name == "" || name == "-" {
				continue
			}
			switch f.Type.Kind() {
			case reflect.Struct:
				sweep(sv.Field(i), prefix+name+".", yield)
			case reflect.String:
				yield(prefix+name, sv.Field(i))
			}
		}
	}

	// pathKeys is every swept setting whose name is path-shaped, with its field.
	pathKeys := func(cfg *serverConfig) map[string]reflect.Value {
		out := map[string]reflect.Value{}
		sweep(reflect.ValueOf(cfg).Elem(), "", func(key string, fv reflect.Value) {
			if pathShaped(key) {
				out[key] = fv
			}
		})
		return out
	}

	It("reserves every path-shaped setting, or records why not", func() {
		// Every path-shaped setting given a value, so caOwnedPaths cannot skip
		// one as empty. The values are never read from disk: the check is
		// lexical, which is what lets it run against paths that do not exist.
		cfg := &serverConfig{}
		fields := pathKeys(cfg)
		for key, fv := range fields {
			fv.SetString("/spec/" + strings.ReplaceAll(key, ".", "/"))
		}

		// The sweep must have found something to judge, and specifically the
		// setting whose omission this spec exists for. A reflection walk that
		// silently returns nothing agrees with every list.
		Expect(fields).NotTo(BeEmpty(), "the sweep found no path-shaped settings at all")
		Expect(fields).To(HaveKey("ca_key_file"),
			"precondition: the setting whose omission this spec exists for must be swept")
		Expect(fields).To(HaveKey("cadir"))
		Expect(fields).To(HaveKey("openbao.token_file"),
			"precondition: the sweep must descend into named blocks, or every "+
				"exemption naming one is unchecked")

		reserved, err := caOwnedPaths(cfg, "/spec/cadir")
		Expect(err).NotTo(HaveOccurred())

		got := map[string]bool{}
		for _, r := range reserved {
			got[r.Setting] = true
		}

		var missing []string
		for key := range fields {
			if got[key] {
				continue
			}
			if _, exempt := notReserved[key]; exempt {
				continue
			}
			missing = append(missing, key)
		}
		sort.Strings(missing)
		Expect(missing).To(BeEmpty(),
			"path-shaped settings that are neither reserved by caOwnedPaths nor "+
				"listed in notReserved with a reason")
	})

	// The other direction. An exemption for a setting that no longer exists is a
	// reason nobody can check; one for a setting the sweep never reaches is
	// worse, because it reads as a decision about a key that was never in
	// question and hides the next omission behind a name that looks handled.
	It("exempts only settings that exist and are actually swept", func() {
		fields := pathKeys(&serverConfig{})
		for key := range notReserved {
			Expect(fields).To(HaveKey(key),
				"notReserved names %q, which the sweep does not yield as a "+
					"path-shaped setting", key)
		}
	})

	It("reserves the CA's own key and certificate wherever they are configured", func() {
		cfg := &serverConfig{}
		cfg.CAKeyFile = "/var/secrets/ca_key.pem"
		cfg.CACertFile = "/var/secrets/ca_crt.pem"

		reserved, err := caOwnedPaths(cfg, "/var/lib/openvox-ca")
		Expect(err).NotTo(HaveOccurred())

		cfgCerts := certstore.Config{{
			Certname:    "a.example.com",
			Names:       []string{"a"},
			RenewBefore: certstore.Duration(720 * time.Hour),
			Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
				Cert: "/var/secrets/a.pem", Key: "/var/secrets/ca_key.pem",
			}},
		}}
		Expect(cfgCerts.CheckReservedPaths(reserved)).
			To(MatchError(ContainSubstring("is ca_key_file")))
	})

	It("reserves each configured client_ca anchor and CRL bundle", func() {
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{{
			Name: "partner", File: "/etc/anchors/partner.pem",
			CRLFile: "/etc/anchors/partner-crl.pem",
		}}

		reserved, err := caOwnedPaths(cfg, "/var/lib/openvox-ca")
		Expect(err).NotTo(HaveOccurred())

		store := func(key string) certstore.Config {
			return certstore.Config{{
				Certname:    "a.example.com",
				Names:       []string{"a"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
					Cert: "/etc/a.pem", Key: key,
				}},
			}}
		}
		Expect(store("/etc/anchors/partner.pem").CheckReservedPaths(reserved)).
			To(MatchError(ContainSubstring("partner")))
		Expect(store("/etc/anchors/partner-crl.pem").CheckReservedPaths(reserved)).
			To(MatchError(ContainSubstring("crl_file")))
	})
})
