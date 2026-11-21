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

// Package httpclient builds the outbound HTTP client that features fetching
// from operator-configured URLs share, from a config.HTTPClientConfig (the
// http_config block). AGENTS.md names the clients outside it.
//
// One builder rather than one per feature, so that the rules below hold for
// every request a client built here sends, rather than for whichever feature
// remembered them.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/voxpupuli/openvox-ca/internal/boundedfile"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/version"
)

// MaxRedirects is how many redirects one request may follow. Enough for a
// moved endpoint behind a CDN; a chain longer than this is a loop or a
// misconfiguration, and following it costs the caller's timeout for nothing.
const MaxRedirects = 5

// maxSecretFileBytes bounds a credentials file. A credential is at most a few
// kilobytes; reading an arbitrary file into a header unbounded would let a
// mistaken path (a log, a disk image) exhaust memory on every request.
const maxSecretFileBytes = 64 << 10

// maxPEMFileBytes bounds tls_config's ca_file, cert_file and key_file. A CA
// bundle of a few hundred certificates is well under it.
const maxPEMFileBytes = 1 << 20

// tlsHandshakeTimeout bounds a TLS handshake, and with it the client
// certificate re-read that each handshake makes.
const tlsHandshakeTimeout = 10 * time.Second

// Client is an *http.Client built from an http_config block, together with the
// credentials it applies.
type Client struct {
	hc   *http.Client
	auth func(*http.Request) error
}

// New builds a Client. The block is validated first; block names the key path
// it was configured under, for the messages.
//
// tls_config.ca_file is read here, once, so a missing or empty bundle fails
// the build rather than the first request; a caller that builds a Client per
// use, as crl_chain.urls does per round, sees that as a failed use, not as a
// refusal to start. A caller that wants a rotated bundle picked up builds a new
// Client. The client certificate and the credentials files are re-read on use
// instead -- per handshake and per request -- so that rotating them needs no
// restart.
//
// Every file is read through boundedfile, so a hung mount fails the build or
// the request instead of wedging the caller. The build's reads are bounded by
// ctx, and the credentials files by the request's own context. The client
// certificate's per-handshake re-read is bounded by the TLS handshake timeout
// instead: it runs under the dial's context, which net/http detaches from the
// request and never cancels.
func New(ctx context.Context, cfg config.HTTPClientConfig, block string) (*Client, error) {
	if err := cfg.Validate(block); err != nil {
		return nil, err
	}
	tlsCfg, err := tlsConfig(ctx, cfg.TLSConfig, block)
	if err != nil {
		return nil, err
	}
	proxy, err := proxyFunc(cfg)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: proxy,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     cfg.HTTP2Enabled(),
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: time.Second,
	}
	if !cfg.HTTP2Enabled() {
		// A non-nil empty map is net/http's documented way to turn HTTP/2 off
		// on a Transport.
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	return &Client{
		hc: &http.Client{
			Transport:     tr,
			CheckRedirect: checkRedirect(cfg.FollowsRedirects()),
		},
		auth: authFunc(cfg, block),
	}, nil
}

// Do sends req, applying the configured credentials and User-Agent.
//
// Credentials go on this request only, not in the transport, so that net/http's
// redirect handling decides whether they follow a redirect: it drops the
// Authorization header when the target is not the original host or a
// subdomain of it. A transport-level header would be sent to wherever a
// redirect pointed.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "openvox-ca/"+version.Version)
	}
	if c.auth != nil {
		if err := c.auth(req); err != nil {
			return nil, err
		}
	}
	return c.hc.Do(req) //nolint:gosec // G704: callers pass operator-configured URLs; redirects are bounded by checkRedirect
}

// CloseIdleConnections closes any idle connections the client holds, for a
// caller about to drop it.
func (c *Client) CloseIdleConnections() { c.hc.CloseIdleConnections() }

// checkRedirect enforces the redirect rules. Comparing each hop with the one
// before it is enough for the https-to-http rule: every hop passes through
// here, so a chain that ever left https would have been stopped at that hop.
func checkRedirect(follow bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if !follow {
			return http.ErrUseLastResponse
		}
		if len(via) > MaxRedirects {
			return fmt.Errorf("stopped after %d redirects", MaxRedirects)
		}
		if req.URL.Scheme != "https" && via[len(via)-1].URL.Scheme == "https" {
			return fmt.Errorf("refusing to follow a redirect from https to %s", req.URL.Scheme)
		}
		return nil
	}
}

func tlsConfig(ctx context.Context, t config.TLSConfig, block string) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: t.ServerName,
	}
	if t.MinVersion == config.TLSVersion13 {
		tc.MinVersion = tls.VersionTLS13
	}
	if t.CAFile != "" {
		pemData, err := boundedfile.Read(ctx, t.CAFile, maxPEMFileBytes)
		if err != nil {
			return nil, fmt.Errorf("reading %s.tls_config.ca_file: %w", block, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("%s.tls_config.ca_file %s holds no PEM certificate", block, t.CAFile)
		}
		tc.RootCAs = pool
	}
	if t.CertFile != "" {
		// Loaded once now so a wrong path fails the build, then again on each
		// handshake so a renewed certificate is used without a restart.
		if _, err := loadKeyPair(ctx, t.CertFile, t.KeyFile); err != nil {
			return nil, fmt.Errorf("loading %s.tls_config client certificate: %w", block, err)
		}
		certFile, keyFile := t.CertFile, t.KeyFile
		tc.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// Bounded here, not by cri.Context() alone: that is the dial's
			// context, which net/http detaches from the request and does not
			// cancel when the handshake times out -- it closes the connection
			// instead. Unbounded, a read on a wedged mount would never be
			// counted as stranded, so every new connection would strand one
			// more goroutine and descriptor.
			ctx, cancel := context.WithTimeout(cri.Context(), tlsHandshakeTimeout)
			defer cancel()
			cert, err := loadKeyPair(ctx, certFile, keyFile)
			if err != nil {
				// Named as the build names it: crypto/tls and net/http pass
				// this up unchanged, and a key that no longer matches after a
				// rotation would otherwise read as the server's fault.
				return nil, fmt.Errorf("loading %s.tls_config client certificate: %w", block, err)
			}
			return &cert, nil
		}
	}
	return tc, nil
}

// loadKeyPair is tls.LoadX509KeyPair, reading both files through boundedfile.
func loadKeyPair(ctx context.Context, certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := boundedfile.Read(ctx, certFile, maxPEMFileBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := boundedfile.Read(ctx, keyFile, maxPEMFileBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// proxyFunc resolves the proxy settings to a Transport.Proxy function.
//
// The environment is read when the client is built, through httpproxy rather
// than http.ProxyFromEnvironment, which caches the variables for the life of
// the process. As with Prometheus, an explicit proxy_url with no no_proxy
// proxies every request, loopback included; httpproxy is used only when there
// is a no_proxy list to apply.
func proxyFunc(cfg config.HTTPClientConfig) (func(*http.Request) (*url.URL, error), error) {
	switch {
	case cfg.ProxyURL != "":
		u, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, err
		}
		if cfg.NoProxy == "" {
			return http.ProxyURL(u), nil
		}
		f := (&httpproxy.Config{
			HTTPProxy:  cfg.ProxyURL,
			HTTPSProxy: cfg.ProxyURL,
			NoProxy:    cfg.NoProxy,
		}).ProxyFunc()
		return func(r *http.Request) (*url.URL, error) { return f(r.URL) }, nil
	case cfg.ProxiesFromEnvironment():
		f := httpproxy.FromEnvironment().ProxyFunc()
		return func(r *http.Request) (*url.URL, error) { return f(r.URL) }, nil
	default:
		return nil, nil
	}
}

// authFunc returns what Do applies to each request, or nil for none.
func authFunc(cfg config.HTTPClientConfig, block string) func(*http.Request) error {
	switch {
	case cfg.BasicAuth != nil:
		b := *cfg.BasicAuth
		return func(req *http.Request) error {
			pw, err := readSecretFile(req.Context(), b.PasswordFile)
			if err != nil {
				return fmt.Errorf("reading %s.basic_auth.password_file: %w", block, err)
			}
			req.SetBasicAuth(b.Username, pw)
			return nil
		}
	case cfg.Authorization != nil:
		a := *cfg.Authorization
		typ := a.Type
		if typ == "" {
			typ = "Bearer"
		}
		return func(req *http.Request) error {
			cred, err := readSecretFile(req.Context(), a.CredentialsFile)
			if err != nil {
				return fmt.Errorf("reading %s.authorization.credentials_file: %w", block, err)
			}
			req.Header.Set("Authorization", typ+" "+cred)
			return nil
		}
	default:
		return nil
	}
}

// readSecretFile reads a credentials file through boundedfile -- bounded in
// size, and in time by the request's context, so a hung mount fails the
// request rather than wedging it before it is sent -- with surrounding
// whitespace trimmed as Prometheus does: a file written by `echo` ends in a
// newline that is not part of the credential.
func readSecretFile(ctx context.Context, path string) (string, error) {
	data, err := boundedfile.Read(ctx, path, maxSecretFileBytes)
	if err != nil {
		return "", err
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return "", errors.New(path + " is empty")
	}
	// A header value cannot carry a line break; refusing one here gives a
	// message naming the file rather than net/http's about an invalid header.
	if strings.ContainsAny(string(data), "\r\n") {
		return "", fmt.Errorf("%s holds more than one line", path)
	}
	return string(data), nil
}
