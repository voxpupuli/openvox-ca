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
	"github.com/spf13/cobra"
)

// parseOpenBaoFlags registers the OpenBao flags on a fresh command, parses
// args, applies the overrides onto a zero serverConfig, and returns it — the
// same register→parse→apply path newRootCmd's RunE runs, isolated for testing.
func parseOpenBaoFlags(args ...string) *serverConfig {
	GinkgoHelper()
	cmd := &cobra.Command{}
	var v openBaoFlagValues
	registerOpenBaoFlags(cmd.Flags(), &v)
	Expect(cmd.Flags().Parse(args)).To(Succeed())
	cfg := &serverConfig{}
	applyOpenBaoFlagOverrides(cmd, cfg, &v)
	return cfg
}

var _ = Describe("openbao flag → config mapping", func() {
	// Each entry sets exactly one flag to a distinct sentinel and asserts the
	// specific destination field, so a copy-paste transposition (e.g.
	// --openbao-tls-cert-file writing TLSKeyFile, or role-id ↔ secret-id — both
	// credential/trust bugs) fails rather than passing silently. Mirrors the
	// env DescribeTable's guard for the flag precedence source.
	DescribeTable("maps each explicitly-set flag to the right field",
		func(flag, value string, check func(*serverConfig) bool, desc string) {
			cfg := parseOpenBaoFlags(flag, value)
			Expect(check(cfg)).To(BeTrue(), "%s not applied from %s=%s", desc, flag, value)
		},
		Entry("ca-key-provider", "--ca-key-provider", "openbao",
			func(c *serverConfig) bool { return c.CAKeyProvider == "openbao" }, "CAKeyProvider"),
		Entry("openbao-addr", "--openbao-addr", "https://bao:8200",
			func(c *serverConfig) bool { return c.OpenBao.Addr == "https://bao:8200" }, "OpenBao.Addr"),
		Entry("openbao-transit-mount", "--openbao-transit-mount", "transit-x",
			func(c *serverConfig) bool { return c.OpenBao.TransitMount == "transit-x" }, "OpenBao.TransitMount"),
		Entry("openbao-key-name", "--openbao-key-name", "ca-key",
			func(c *serverConfig) bool { return c.OpenBao.KeyName == "ca-key" }, "OpenBao.KeyName"),
		Entry("openbao-tls-ca-file", "--openbao-tls-ca-file", "/tls/ca.pem",
			func(c *serverConfig) bool { return c.OpenBao.TLSCAFile == "/tls/ca.pem" }, "OpenBao.TLSCAFile"),
		Entry("openbao-tls-cert-file", "--openbao-tls-cert-file", "/tls/cert.pem",
			func(c *serverConfig) bool { return c.OpenBao.TLSCertFile == "/tls/cert.pem" }, "OpenBao.TLSCertFile"),
		Entry("openbao-tls-key-file", "--openbao-tls-key-file", "/tls/key.pem",
			func(c *serverConfig) bool { return c.OpenBao.TLSKeyFile == "/tls/key.pem" }, "OpenBao.TLSKeyFile"),
		Entry("openbao-auth-method", "--openbao-auth-method", "kubernetes",
			func(c *serverConfig) bool { return c.OpenBao.AuthMethod == "kubernetes" }, "OpenBao.AuthMethod"),
		Entry("openbao-approle-mount", "--openbao-approle-mount", "approle-x",
			func(c *serverConfig) bool { return c.OpenBao.AppRoleMount == "approle-x" }, "OpenBao.AppRoleMount"),
		Entry("openbao-approle-role-id", "--openbao-approle-role-id", "role-id-val",
			func(c *serverConfig) bool { return c.OpenBao.AppRoleRoleID == "role-id-val" }, "OpenBao.AppRoleRoleID"),
		Entry("openbao-approle-role-id-file", "--openbao-approle-role-id-file", "/creds/role-id",
			func(c *serverConfig) bool { return c.OpenBao.AppRoleRoleIDFile == "/creds/role-id" }, "OpenBao.AppRoleRoleIDFile"),
		Entry("openbao-approle-secret-id-file", "--openbao-approle-secret-id-file", "/creds/secret-id",
			func(c *serverConfig) bool { return c.OpenBao.AppRoleSecretIDFile == "/creds/secret-id" }, "OpenBao.AppRoleSecretIDFile"),
		Entry("openbao-token-file", "--openbao-token-file", "/creds/token",
			func(c *serverConfig) bool { return c.OpenBao.TokenFile == "/creds/token" }, "OpenBao.TokenFile"),
		Entry("openbao-kubernetes-mount", "--openbao-kubernetes-mount", "k8s-x",
			func(c *serverConfig) bool { return c.OpenBao.KubernetesMount == "k8s-x" }, "OpenBao.KubernetesMount"),
		Entry("openbao-kubernetes-role", "--openbao-kubernetes-role", "k8s-role",
			func(c *serverConfig) bool { return c.OpenBao.KubernetesRole == "k8s-role" }, "OpenBao.KubernetesRole"),
		Entry("openbao-kubernetes-jwt-file", "--openbao-kubernetes-jwt-file", "/creds/sa.jwt",
			func(c *serverConfig) bool { return c.OpenBao.KubernetesJWTFile == "/creds/sa.jwt" }, "OpenBao.KubernetesJWTFile"),
	)

	// An unset flag must not overwrite a value already resolved from the config
	// file or environment (the overlay only applies flags the operator changed).
	It("leaves unset flags alone so file/env values survive", func() {
		cmd := &cobra.Command{}
		var v openBaoFlagValues
		registerOpenBaoFlags(cmd.Flags(), &v)
		Expect(cmd.Flags().Parse([]string{"--openbao-addr", "https://flag:8200"})).To(Succeed())

		// cfg as if already populated from YAML/env.
		cfg := &serverConfig{}
		cfg.CAKeyProvider = "openbao"
		cfg.OpenBao.KeyName = "from-yaml"
		applyOpenBaoFlagOverrides(cmd, cfg, &v)

		Expect(cfg.OpenBao.Addr).To(Equal("https://flag:8200"), "changed flag should win")
		Expect(cfg.CAKeyProvider).To(Equal("openbao"), "unset --ca-key-provider must not clobber the YAML value")
		Expect(cfg.OpenBao.KeyName).To(Equal("from-yaml"), "unset --openbao-key-name must not clobber the YAML value")
	})
})
