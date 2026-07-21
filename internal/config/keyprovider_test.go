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
	"github.com/voxpupuli/openvox-ca/internal/signer/openbao"
)

var _ = Describe("CAKeyProviderConfig.UsesOpenBao", func() {
	DescribeTable("reports true only for the openbao provider",
		func(provider string, want bool) {
			got := config.CAKeyProviderConfig{CAKeyProvider: provider}.UsesOpenBao()
			Expect(got).To(Equal(want))
		},
		Entry("openbao", "openbao", true),
		Entry("file", "file", false),
		Entry("empty (defaults to file)", "", false),
		Entry("unknown", "pkcs11", false),
	)
})

var _ = Describe("CAKeyProviderConfig.Validate", func() {
	DescribeTable("accepts the known providers",
		func(provider string) {
			err := config.CAKeyProviderConfig{CAKeyProvider: provider}.Validate()
			Expect(err).NotTo(HaveOccurred())
		},
		Entry("empty (defaults to file)", ""),
		Entry("file", "file"),
		Entry("openbao", "openbao"),
	)

	// An unrecognised provider must be a hard error: silently falling back to
	// local-file custody would write the CA private key to disk when the
	// operator asked for it to live in OpenBao.
	DescribeTable("rejects an unknown provider rather than falling back to file",
		func(provider string) {
			err := config.CAKeyProviderConfig{CAKeyProvider: provider}.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(provider))
		},
		Entry("a typo", "openba"),
		Entry("an anticipated-but-unimplemented backend", "pkcs11"),
		Entry("nonsense", "somewhere-else"),
	)
})

var _ = Describe("CAKeyProviderConfig.ToOpenBaoConfig", func() {
	// fullOpenBao populates every OpenBaoConfig field with a distinct sentinel
	// so a transposed mapping (e.g. tls_cert_file -> TLSKeyFile, or
	// role_id <-> secret_id) produces a mismatch a plain struct comparison
	// catches. auth_method is filled in per-entry.
	fullOpenBao := func(authMethod string) config.OpenBaoConfig {
		return config.OpenBaoConfig{
			Addr:                "https://bao.example.com:8200",
			TransitMount:        "transit-mount",
			KeyName:             "my-ca-key",
			TLSCAFile:           "/tls/ca.pem",
			TLSCertFile:         "/tls/client-cert.pem",
			TLSKeyFile:          "/tls/client-key.pem",
			AuthMethod:          authMethod,
			AppRoleMount:        "approle-mount",
			AppRoleRoleID:       "the-role-id",
			AppRoleRoleIDFile:   "/creds/role-id",
			AppRoleSecretIDFile: "/creds/secret-id",
			TokenFile:           "/creds/token",
			KubernetesMount:     "kubernetes-mount",
			KubernetesRole:      "the-k8s-role",
			KubernetesJWTFile:   "/creds/sa.jwt",
		}
	}

	// wantOpenBao is the openbao.Config every field of fullOpenBao must map to.
	// It asserts the Kubernetes* -> K8s* rename and that nothing is dropped or
	// swapped. LoginTimeout is intentionally not mapped from config, so it
	// stays at its zero value.
	wantOpenBao := func(authMethod openbao.AuthMethodKind) openbao.Config {
		return openbao.Config{
			Addr:                "https://bao.example.com:8200",
			TransitMount:        "transit-mount",
			KeyName:             "my-ca-key",
			TLSCAFile:           "/tls/ca.pem",
			TLSCertFile:         "/tls/client-cert.pem",
			TLSKeyFile:          "/tls/client-key.pem",
			AuthMethod:          authMethod,
			AppRoleMount:        "approle-mount",
			AppRoleRoleID:       "the-role-id",
			AppRoleRoleIDFile:   "/creds/role-id",
			AppRoleSecretIDFile: "/creds/secret-id",
			TokenFile:           "/creds/token",
			K8sMount:            "kubernetes-mount",
			K8sRole:             "the-k8s-role",
			K8sJWTFile:          "/creds/sa.jwt",
		}
	}

	DescribeTable("maps every field to the right openbao.Config field",
		func(authMethod string, want openbao.AuthMethodKind) {
			c := config.CAKeyProviderConfig{
				CAKeyProvider: "openbao",
				OpenBao:       fullOpenBao(authMethod),
			}
			got, err := c.ToOpenBaoConfig()
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(wantOpenBao(want)))
		},
		Entry("approle", "approle", openbao.AuthAppRole),
		Entry("token", "token", openbao.AuthToken),
		Entry("kubernetes", "kubernetes", openbao.AuthKubernetes),
	)

	// The mapping defers auth-method validity entirely to openbao.Config's own
	// Validate, so an unknown or empty auth_method surfaces its error naming
	// the offending value rather than parsing to a valid config.
	DescribeTable("returns an error naming the bad auth_method",
		func(authMethod, wantSubstring string) {
			c := config.CAKeyProviderConfig{
				CAKeyProvider: "openbao",
				OpenBao:       fullOpenBao(authMethod),
			}
			_, err := c.ToOpenBaoConfig()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(wantSubstring))
		},
		Entry("unknown method names the value", "nonsense", "nonsense"),
		Entry("empty method reports it is required", "", "auth_method"),
	)
})
