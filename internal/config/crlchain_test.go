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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

var _ = Describe("CRLChainConfig", func() {
	It("decodes the whole block", func() {
		var c config.CRLChainConfig
		Expect(config.DecodeStrict([]byte(`urls:
  - https://openbao-active.openbao.svc:8200/v1/pki-root/issuer/x4/crl/pem
  - http://pki.example.com/root.crl
  - file:///run/secrets/upstream-crls/sub-ca.crl
refresh_interval_sec: 3600
fetch_timeout_sec: 30
http_config:
  tls_config:
    ca_file: /run/secrets/openbao-ca/ca.crt
`), &c, "openvox-ca")).To(Succeed())
		Expect(c.URLs).To(HaveLen(3))
		Expect(c.HTTPConfig.TLSConfig.CAFile).To(Equal("/run/secrets/openbao-ca/ca.crt"))
		Expect(c.Validate()).To(Succeed())
	})

	It("accepts an empty block, which leaves the feature off", func() {
		Expect(config.CRLChainConfig{}.Validate()).To(Succeed())
	})

	DescribeTable("Validate refuses",
		func(c config.CRLChainConfig, want string) {
			Expect(c.Validate()).To(MatchError(ContainSubstring(want)))
		},
		Entry("file and urls together",
			config.CRLChainConfig{File: "/f.pem", URLs: []string{"https://a/x.crl"}},
			"crl_chain.file and crl_chain.urls are mutually exclusive"),
		Entry("an entry listed twice",
			config.CRLChainConfig{URLs: []string{"https://a/x.crl", "https://a/x.crl"}},
			"listed twice"),
		Entry("credentials in an entry",
			config.CRLChainConfig{URLs: []string{"https://user:secret@a/x.crl"}},
			"carries credentials"),
		Entry("a token as an entry's username",
			config.CRLChainConfig{URLs: []string{"https://token@a/x.crl"}},
			"carries credentials"),
		Entry("credentials in a file entry, which names no host to carry them to",
			config.CRLChainConfig{URLs: []string{"file://user:secret@/etc/crl.pem"}},
			"carries credentials"),
		Entry("an http entry with no host",
			config.CRLChainConfig{URLs: []string{"http:///x.crl"}},
			"has no host"),
		Entry("a file entry naming a host, the missing-slash mistake",
			config.CRLChainConfig{URLs: []string{"file://etc/crl.pem"}},
			"names a host"),
		Entry("a file entry with a relative path",
			config.CRLChainConfig{URLs: []string{"file:crl.pem"}},
			"not an absolute path"),
		Entry("a file entry with a query",
			config.CRLChainConfig{URLs: []string{"file:///etc/crl.pem?x=1"}},
			"query or fragment"),
		Entry("another scheme",
			config.CRLChainConfig{URLs: []string{"ldap://dir.example/cn=CA"}},
			"must be an http://, https:// or file:/// URL"),
		Entry("a negative timeout",
			config.CRLChainConfig{FetchTimeoutSec: -1},
			"fetch_timeout_sec must be between 0"),
		Entry("a timeout over the ceiling",
			config.CRLChainConfig{FetchTimeoutSec: config.MaxCRLChainFetchTimeoutSec + 1},
			"fetch_timeout_sec must be between 0"),
		Entry("an entry that is not UTF-8, which would panic the metrics collector",
			config.CRLChainConfig{URLs: []string{"https://pki.example/\xffcrl"}},
			"not valid UTF-8"),
		Entry("an entry with whitespace",
			config.CRLChainConfig{URLs: []string{"https://a/x y.crl"}},
			"contains whitespace"),
		Entry("a file entry with a fragment",
			config.CRLChainConfig{URLs: []string{"file:///etc/crl.pem#f"}},
			"query or fragment"),
		Entry("an entry that does not parse",
			config.CRLChainConfig{URLs: []string{"http://[::1"}},
			"missing ']' in host"),
		Entry("a negative refresh interval",
			config.CRLChainConfig{RefreshIntervalSec: -1},
			"refresh_interval_sec must be between 0"),
		Entry("a refresh interval past the ceiling",
			config.CRLChainConfig{RefreshIntervalSec: config.MaxCRLChainRefreshIntervalSec + 1},
			"refresh_interval_sec must be between 0"),
		Entry("an invalid http_config, naming its path",
			config.CRLChainConfig{HTTPConfig: config.HTTPClientConfig{NoProxy: "x"}},
			"crl_chain.http_config.no_proxy requires crl_chain.http_config.proxy_url"),
	)

	It("accepts the refresh interval and fetch timeout at exactly their ceilings", func() {
		Expect(config.CRLChainConfig{
			RefreshIntervalSec: config.MaxCRLChainRefreshIntervalSec,
			FetchTimeoutSec:    config.MaxCRLChainFetchTimeoutSec,
		}.Validate()).To(Succeed())
	})

	Describe("credentials in http_config", func() {
		basic := config.HTTPClientConfig{BasicAuth: &config.BasicAuth{Username: "u", PasswordFile: "/p"}}
		bearer := config.HTTPClientConfig{Authorization: &config.Authorization{CredentialsFile: "/c"}}

		// One http_config serves every entry, so its credentials go to every
		// upstream: a plain http:// entry would carry them in clear text.
		DescribeTable("are refused beside a plain http:// entry, naming it",
			func(h config.HTTPClientConfig) {
				err := config.CRLChainConfig{
					URLs:       []string{"https://a/root.crl", "http://b/sub.crl"},
					HTTPConfig: h,
				}.Validate()
				Expect(err).To(MatchError(ContainSubstring("crl_chain.urls[1] is plain http://")))
			},
			Entry("basic_auth", basic),
			Entry("authorization", bearer),
		)

		DescribeTable("are accepted when every entry is https:// or file:///",
			func(h config.HTTPClientConfig) {
				Expect(config.CRLChainConfig{
					URLs:       []string{"https://a/root.crl", "file:///srv/crl/sub.crl"},
					HTTPConfig: h,
				}.Validate()).To(Succeed())
			},
			Entry("basic_auth", basic),
			Entry("authorization", bearer),
		)

		It("leave a plain http:// entry alone when there are none", func() {
			Expect(config.CRLChainConfig{URLs: []string{"http://b/sub.crl"}}.Validate()).To(Succeed())
		})
	})

	// A refusal reaches the terminal, the journal or the pod log, which are
	// read more widely than the configuration: it must not echo a password.
	DescribeTable("never quotes a password in a refusal",
		func(c config.CRLChainConfig) {
			err := c.Validate()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).NotTo(ContainSubstring("hunter2"))
		},
		Entry("an entry carrying credentials",
			config.CRLChainConfig{URLs: []string{"https://user:hunter2@a/x.crl"}}),
		Entry("such an entry listed twice",
			config.CRLChainConfig{URLs: []string{"https://user:hunter2@a/x.crl", "https://user:hunter2@a/x.crl"}}),
		Entry("such an entry that does not parse",
			config.CRLChainConfig{URLs: []string{"http://user:hunter2@[::1"}}),
		Entry("such an entry of another scheme",
			config.CRLChainConfig{URLs: []string{"ldap://user:hunter2@dir.example/cn=CA"}}),
		Entry("a proxy_url carrying credentials, of a scheme it refuses",
			config.CRLChainConfig{HTTPConfig: config.HTTPClientConfig{ProxyURL: "socks5h://user:hunter2@proxy:1080"}}),
		Entry("an entry carrying a token as its username",
			config.CRLChainConfig{URLs: []string{"https://hunter2@a/x.crl"}}),
		Entry("such an entry listed twice",
			config.CRLChainConfig{URLs: []string{"https://hunter2@a/x.crl", "https://hunter2@a/x.crl"}}),
		Entry("a file entry carrying credentials",
			config.CRLChainConfig{URLs: []string{"file://user:hunter2@/etc/crl.pem"}}),
		Entry("a proxy_url carrying credentials that does not parse",
			config.CRLChainConfig{HTTPConfig: config.HTTPClientConfig{ProxyURL: "http://user:hunter2@[::1"}}),
		// Without "//" url.Parse finds no user information: the credential is
		// left in Opaque or Path, where clearing User does not reach it.
		Entry("an entry missing both slashes",
			config.CRLChainConfig{URLs: []string{"https:user:hunter2@a/x.crl"}}),
		Entry("an entry missing one slash",
			config.CRLChainConfig{URLs: []string{"https:/user:hunter2@a/x.crl"}}),
		Entry("such an entry listed twice",
			config.CRLChainConfig{URLs: []string{"https:user:hunter2@a/x.crl", "https:user:hunter2@a/x.crl"}}),
		Entry("a file entry missing its slashes",
			config.CRLChainConfig{URLs: []string{"file:user:hunter2@/etc/crl.pem"}}),
		Entry("a proxy_url missing its slashes",
			config.CRLChainConfig{HTTPConfig: config.HTTPClientConfig{ProxyURL: "http:user:hunter2@p:3128"}}),
		Entry("a proxy_url of a refused scheme missing its slashes",
			config.CRLChainConfig{HTTPConfig: config.HTTPClientConfig{ProxyURL: "ftp:user:hunter2@p:21"}}),
		// A password holding '/', '?' or '#' ends the authority before its '@',
		// so the URL fails to parse and the parser's own reason names it.
		Entry("an entry whose password holds a '/'",
			config.CRLChainConfig{URLs: []string{"https://user:hunter2/x@a/x.crl"}}),
		Entry("an entry whose password holds a '#'",
			config.CRLChainConfig{URLs: []string{"https://user:hunter2#x@a/x.crl"}}),
		Entry("an entry whose password holds a '?'",
			config.CRLChainConfig{URLs: []string{"https://user:hunter2?x@a/x.crl"}}),
		Entry("a proxy_url whose password holds a '/'",
			config.CRLChainConfig{HTTPConfig: config.HTTPClientConfig{ProxyURL: "http://user:hunter2/x@p:3128"}}),
		Entry("an entry that does not parse, listed twice",
			config.CRLChainConfig{URLs: []string{"http://user:hunter2@[::1", "http://user:hunter2@[::1"}}),
	)

	// The other half of the contract: withholding is for what may carry a
	// credential, and an ordinary URL is still quoted, so the operator can see
	// which entry was refused.
	DescribeTable("still quotes an ordinary URL in a refusal",
		func(c config.CRLChainConfig, want string) {
			err := c.Validate()
			Expect(err).To(MatchError(ContainSubstring(want)))
			Expect(err.Error()).NotTo(ContainSubstring("withheld"))
		},
		Entry("an entry of another scheme",
			config.CRLChainConfig{URLs: []string{"ldap://dir.example/cn=CA"}}, `"ldap://dir.example/cn=CA"`),
		Entry("a proxy_url of a refused scheme",
			config.CRLChainConfig{HTTPConfig: config.HTTPClientConfig{ProxyURL: "ftp://p"}}, `proxy_url "ftp://p"`),
		Entry("a parse failure's reason, when the URL holds no '@'",
			config.CRLChainConfig{URLs: []string{"http://[::1"}}, "missing ']' in host"),
	)

	It("names an unparsable entry listed twice without quoting it", func() {
		err := config.CRLChainConfig{URLs: []string{"http://[::1", "http://[::1"}}.Validate()
		Expect(err).To(MatchError(ContainSubstring("crl_chain.urls[1] (not a URL) is listed twice")))
	})

	It("refuses more entries than the cap, and accepts exactly the cap", func() {
		urls := make([]string, config.MaxCRLChainURLs+1)
		for i := range urls {
			urls[i] = fmt.Sprintf("https://pki.example/%d.crl", i)
		}
		Expect(config.CRLChainConfig{URLs: urls[:config.MaxCRLChainURLs]}.Validate()).To(Succeed())
		Expect(config.CRLChainConfig{URLs: urls}.Validate()).To(MatchError(ContainSubstring("at most 64")))
	})
})
