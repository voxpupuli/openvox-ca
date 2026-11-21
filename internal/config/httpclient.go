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

package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// HTTPClientConfig is the http_config block: how openvox-ca makes outbound
// HTTP requests on behalf of a feature that needs them. A feature that fetches
// from URLs the operator configures takes this block and builds its client
// with internal/httpclient; AGENTS.md names the clients outside that rule,
// among them the OpenBao key provider, which keeps its own openbao.* TLS
// settings.
//
// It is modelled on Prometheus's <http_config>
// (github.com/prometheus/common/config.HTTPClientConfig) and uses its key
// names, so an operator who has written one recognises the other. It is a
// subset with deliberate differences rather than a copy, and docs/configuration.md
// lists them. When adding a field, consult the Prometheus type first and give
// the field the same name and shape wherever the two overlap in function;
// AGENTS.md carries the same rule.
//
// The differences that matter for security:
//
//   - Credentials come from files only (password_file, credentials_file). The
//     configuration file is often a Kubernetes ConfigMap, and a key that
//     cannot hold a secret inline is one the chart never has to refuse.
//   - A redirect is followed at most httpclient.MaxRedirects (5) times and
//     never from https to http, whatever follow_redirects says. An operator
//     who wrote https:// is relying on an authenticated origin.
//   - proxy_from_environment defaults to true, where Prometheus defaults it to
//     false: the conventional HTTP(S)_PROXY / NO_PROXY variables are how a
//     host's egress proxy is normally configured, and the OpenBao client
//     already honours them.
type HTTPClientConfig struct {
	// BasicAuth sends an Authorization: Basic header.
	BasicAuth *BasicAuth `yaml:"basic_auth"`

	// Authorization sends an Authorization header of the given type.
	Authorization *Authorization `yaml:"authorization"`

	// TLSConfig configures TLS for https:// requests.
	TLSConfig TLSConfig `yaml:"tls_config"`

	// FollowRedirects says whether 3xx responses are followed. Default true.
	FollowRedirects *bool `yaml:"follow_redirects"`

	// EnableHTTP2 says whether HTTP/2 may be negotiated. Default true.
	EnableHTTP2 *bool `yaml:"enable_http2"`

	// ProxyURL sends every request through this proxy. Mutually exclusive with
	// proxy_from_environment: true.
	ProxyURL string `yaml:"proxy_url"`

	// NoProxy is a comma-separated list of hosts, domains and CIDRs that
	// bypass ProxyURL, in the NO_PROXY syntax. Requires proxy_url.
	NoProxy string `yaml:"no_proxy"`

	// ProxyFromEnvironment takes the proxy from HTTP_PROXY, HTTPS_PROXY and
	// NO_PROXY (and their lower-case forms). Default true unless proxy_url is
	// set.
	ProxyFromEnvironment *bool `yaml:"proxy_from_environment"`
}

// BasicAuth is http_config.basic_auth.
type BasicAuth struct {
	Username string `yaml:"username"`
	// PasswordFile is re-read on every request, so a rotated password takes
	// effect without a restart.
	PasswordFile string `yaml:"password_file"`
}

// Authorization is http_config.authorization.
type Authorization struct {
	// Type is the scheme, e.g. Bearer (the default).
	Type string `yaml:"type"`
	// CredentialsFile is re-read on every request, so a rotated credential
	// takes effect without a restart.
	CredentialsFile string `yaml:"credentials_file"`
}

// TLSConfig is http_config.tls_config.
type TLSConfig struct {
	// CAFile is a PEM bundle of the CAs that may sign a server's certificate.
	// When set it replaces the system roots rather than adding to them.
	CAFile string `yaml:"ca_file"`
	// CertFile and KeyFile are a client certificate, presented to servers that
	// ask for one. Both or neither.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ServerName overrides the name the server's certificate is verified
	// against, and the SNI sent.
	ServerName string `yaml:"server_name"`
	// MinVersion is TLS12 (the default) or TLS13.
	MinVersion string `yaml:"min_version"`
}

// The TLS versions min_version accepts. Prometheus also accepts TLS10 and
// TLS11; openvox-ca's own listener refuses anything below 1.2, and an outbound
// client has no better reason to accept it.
const (
	TLSVersion12 = "TLS12"
	TLSVersion13 = "TLS13"
)

// FollowsRedirects resolves follow_redirects, defaulting to true.
func (c HTTPClientConfig) FollowsRedirects() bool {
	return c.FollowRedirects == nil || *c.FollowRedirects
}

// HTTP2Enabled resolves enable_http2, defaulting to true.
func (c HTTPClientConfig) HTTP2Enabled() bool {
	return c.EnableHTTP2 == nil || *c.EnableHTTP2
}

// ProxiesFromEnvironment resolves proxy_from_environment: true unless set
// false, or unless proxy_url is set, which names the proxy explicitly.
func (c HTTPClientConfig) ProxiesFromEnvironment() bool {
	if c.ProxyFromEnvironment != nil {
		return *c.ProxyFromEnvironment
	}
	return c.ProxyURL == ""
}

// Validate refuses a block that cannot be turned into a client. block is the
// key path the operator wrote it under (e.g. "crl_chain.http_config"), so a
// message names the setting to fix.
func (c HTTPClientConfig) Validate(block string) error {
	var errs []error
	add := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s.%s", block, fmt.Sprintf(format, args...)))
	}

	if c.BasicAuth != nil && c.Authorization != nil {
		add("basic_auth and %s.authorization are mutually exclusive", block)
	}
	if b := c.BasicAuth; b != nil {
		if b.Username == "" {
			add("basic_auth.username is required")
		}
		if b.PasswordFile == "" {
			add("basic_auth.password_file is required: credentials are read from files only")
		}
	}
	if a := c.Authorization; a != nil {
		if strings.EqualFold(a.Type, "basic") {
			add("authorization.type cannot be Basic; use %s.basic_auth", block)
		}
		if strings.ContainsAny(a.Type, " \t\r\n") {
			add("authorization.type %q must be a single token", a.Type)
		}
		if a.CredentialsFile == "" {
			add("authorization.credentials_file is required: credentials are read from files only")
		}
	}

	t := c.TLSConfig
	if (t.CertFile == "") != (t.KeyFile == "") {
		add("tls_config.cert_file and %s.tls_config.key_file must be set together", block)
	}
	switch t.MinVersion {
	case "", TLSVersion12, TLSVersion13:
	default:
		add("tls_config.min_version %q must be %s or %s", t.MinVersion, TLSVersion12, TLSVersion13)
	}

	if c.ProxyURL != "" {
		if c.ProxyFromEnvironment != nil && *c.ProxyFromEnvironment {
			add("proxy_url and %s.proxy_from_environment are mutually exclusive", block)
		}
		// Checked for credentials before anything that quotes it, and quoted
		// through quotedURL, so a refusal never echoes a password into a log --
		// including one url.Parse left outside User for want of "//".
		u, err := url.Parse(c.ProxyURL)
		switch {
		case err != nil:
			add("proxy_url is not a URL: %v", unwrapURLError(c.ProxyURL, err))
		case u.User != nil:
			// Inline proxy credentials would land in a ConfigMap like any
			// other inline secret.
			add("proxy_url must not carry credentials")
		case u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5":
			add("proxy_url %s must be an http, https or socks5 URL", quotedURL(u))
		case u.Host == "":
			add("proxy_url %s has no host", quotedURL(u))
		}
	}
	if c.NoProxy != "" && c.ProxyURL == "" {
		add("no_proxy requires %s.proxy_url; with proxies from the environment, set NO_PROXY instead", block)
	}
	return errors.Join(errs...)
}
