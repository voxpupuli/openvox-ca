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
)

var _ = Describe("HTTPClientConfig", func() {
	decode := func(doc string) (config.HTTPClientConfig, error) {
		var out config.HTTPClientConfig
		err := config.DecodeStrict([]byte(doc), &out, "openvox-ca")
		return out, err
	}

	Describe("defaults", func() {
		It("follows redirects, allows HTTP/2 and takes the proxy from the environment", func() {
			c, err := decode("{}\n")
			Expect(err).NotTo(HaveOccurred())
			Expect(c.FollowsRedirects()).To(BeTrue())
			Expect(c.HTTP2Enabled()).To(BeTrue())
			// Prometheus defaults this to false; openvox-ca deliberately does
			// not, and that difference is documented.
			Expect(c.ProxiesFromEnvironment()).To(BeTrue())
			Expect(c.Validate("http_config")).To(Succeed())
		})

		It("stops taking the proxy from the environment once proxy_url names one", func() {
			c, err := decode("proxy_url: http://proxy.example:3128\n")
			Expect(err).NotTo(HaveOccurred())
			Expect(c.ProxiesFromEnvironment()).To(BeFalse())
			Expect(c.Validate("http_config")).To(Succeed())
		})

		It("honours explicit false", func() {
			c, err := decode("follow_redirects: false\nenable_http2: false\nproxy_from_environment: false\n")
			Expect(err).NotTo(HaveOccurred())
			Expect(c.FollowsRedirects()).To(BeFalse())
			Expect(c.HTTP2Enabled()).To(BeFalse())
			Expect(c.ProxiesFromEnvironment()).To(BeFalse())
		})
	})

	// File-only credentials are the point: the configuration is often a
	// ConfigMap. The strict decoder refusing the inline Prometheus spellings is
	// what keeps them file-only, so each is pinned.
	DescribeTable("refuses inline credentials as unknown keys",
		func(doc, key string) {
			_, err := decode(doc)
			Expect(err).To(MatchError(ContainSubstring(`unknown key "` + key + `"`)))
		},
		Entry("basic_auth.password", "basic_auth:\n  username: u\n  password: p\n", "basic_auth.password"),
		Entry("authorization.credentials", "authorization:\n  credentials: c\n", "authorization.credentials"),
		Entry("bearer_token", "bearer_token: t\n", "bearer_token"),
		Entry("oauth2", "oauth2: {}\n", "oauth2"),
	)

	DescribeTable("Validate refuses",
		func(doc, want string) {
			c, err := decode(doc)
			Expect(err).NotTo(HaveOccurred())
			Expect(c.Validate("crl_chain.http_config")).To(MatchError(ContainSubstring(want)))
		},
		Entry("both auth kinds",
			"basic_auth: {username: u, password_file: /p}\nauthorization: {credentials_file: /c}\n",
			"crl_chain.http_config.basic_auth and crl_chain.http_config.authorization are mutually exclusive"),
		Entry("basic_auth without a username",
			"basic_auth: {password_file: /p}\n", "crl_chain.http_config.basic_auth.username is required"),
		Entry("basic_auth without a password file",
			"basic_auth: {username: u}\n", "crl_chain.http_config.basic_auth.password_file is required"),
		Entry("authorization without a credentials file",
			"authorization: {type: Bearer}\n", "crl_chain.http_config.authorization.credentials_file is required"),
		Entry("authorization of type Basic",
			"authorization: {type: basic, credentials_file: /c}\n", "cannot be Basic"),
		Entry("an authorization type that would split the header",
			"authorization: {type: \"Bearer x\", credentials_file: /c}\n", "must be a single token"),
		Entry("a client certificate without its key",
			"tls_config: {cert_file: /c}\n", "must be set together"),
		Entry("a client key without its certificate",
			"tls_config: {key_file: /k}\n", "must be set together"),
		Entry("TLS below 1.2",
			"tls_config: {min_version: TLS11}\n", `min_version "TLS11" must be TLS12 or TLS13`),
		Entry("proxy_url with proxy_from_environment",
			"proxy_url: http://p:3128\nproxy_from_environment: true\n", "mutually exclusive"),
		Entry("a proxy_url of another scheme",
			"proxy_url: ftp://p\n", "must be an http, https or socks5 URL"),
		Entry("a proxy_url with no host",
			"proxy_url: http://\n", "has no host"),
		Entry("a proxy_url carrying credentials",
			"proxy_url: http://user:secret@p:3128\n", "must not carry credentials"),
		Entry("no_proxy without proxy_url",
			"no_proxy: 10.0.0.0/8\n", "no_proxy requires crl_chain.http_config.proxy_url"),
	)

	It("accepts a full block", func() {
		c, err := decode(`basic_auth:
  username: u
  password_file: /run/secrets/p
tls_config:
  ca_file: /ca.pem
  cert_file: /c.pem
  key_file: /k.pem
  server_name: crl.example
  min_version: TLS13
follow_redirects: true
enable_http2: false
proxy_url: socks5://proxy.example:1080
no_proxy: .svc,10.0.0.0/8
`)
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Validate("http_config")).To(Succeed())
	})
})
