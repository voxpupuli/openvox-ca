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

package httpclient_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/httpclient"
)

// unresolvable is a host no resolver answers for (.test is reserved by RFC
// 6761), so a request for it can only succeed through a proxy.
const unresolvable = "crl.example.test"

func ptr[T any](v T) *T { return &v }

var _ = Describe("httpclient", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		// The environment's proxy settings must not leak into specs that do
		// not set them; Setenv restores whatever was there afterwards.
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
			GinkgoT().Setenv(k, "")
		}
	})

	writeFile := func(name, content string) string {
		p := filepath.Join(dir, name)
		Expect(os.WriteFile(p, []byte(content), 0o600)).To(Succeed())
		return p
	}

	serverCAFile := func(ts *httptest.Server) string {
		return writeFile("ca.pem", string(pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: ts.Certificate().Raw,
		})))
	}

	newClient := func(cfg config.HTTPClientConfig) *httpclient.Client {
		c, err := httpclient.New(context.Background(), cfg, "http_config")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(c.CloseIdleConnections)
		return c
	}

	get := func(c *httpclient.Client, url string) (*http.Response, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		DeferCleanup(cancel)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		Expect(err).NotTo(HaveOccurred())
		resp, err := c.Do(req)
		if resp != nil {
			DeferCleanup(resp.Body.Close)
		}
		return resp, err
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	Describe("tls_config.ca_file", func() {
		It("trusts a server the bundle signed", func() {
			ts := httptest.NewTLSServer(ok)
			DeferCleanup(ts.Close)
			c := newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: serverCAFile(ts)}})
			resp, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
		})

		It("is what makes that server trusted: without it the handshake fails", func() {
			ts := httptest.NewTLSServer(ok)
			DeferCleanup(ts.Close)
			c := newClient(config.HTTPClientConfig{})
			_, err := get(c, ts.URL)
			Expect(err).To(MatchError(ContainSubstring("certificate")))
		})

		It("trusts only what the bundle holds", func() {
			ts := httptest.NewTLSServer(ok)
			DeferCleanup(ts.Close)
			// A bundle naming an unrelated certificate. Not a second
			// httptest server's: every one of those shares the same built-in
			// certificate, which would make this pass for the wrong reason.
			unrelated, _ := clientCertificate(dir)
			c := newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: unrelated}})
			_, err := get(c, ts.URL)
			Expect(err).To(MatchError(ContainSubstring("certificate")))
		})

		It("refuses at build time a bundle holding no certificate", func() {
			_, err := httpclient.New(context.Background(), config.HTTPClientConfig{
				TLSConfig: config.TLSConfig{CAFile: writeFile("empty.pem", "not a certificate\n")},
			}, "crl_chain.http_config")
			Expect(err).To(MatchError(ContainSubstring("crl_chain.http_config.tls_config.ca_file")))
		})

		It("refuses at build time a bundle larger than its bound, rather than reading it all", func() {
			_, err := httpclient.New(context.Background(), config.HTTPClientConfig{
				TLSConfig: config.TLSConfig{CAFile: writeFile("big.pem", strings.Repeat("a", httpclient.MaxPEMFileBytes+1))},
			}, "http_config")
			Expect(err).To(MatchError(ContainSubstring("http_config.tls_config.ca_file")))
			Expect(err).To(MatchError(ContainSubstring("larger than %d bytes", httpclient.MaxPEMFileBytes)))
		})

		It("refuses at build time a bundle that is not there", func() {
			_, err := httpclient.New(context.Background(), config.HTTPClientConfig{
				TLSConfig: config.TLSConfig{CAFile: filepath.Join(dir, "absent.pem")},
			}, "http_config")
			Expect(err).To(MatchError(ContainSubstring("reading http_config.tls_config.ca_file")))
		})
	})

	Describe("tls_config.min_version", func() {
		var ts *httptest.Server

		BeforeEach(func() {
			ts = httptest.NewUnstartedServer(ok)
			ts.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
			ts.StartTLS()
			DeferCleanup(ts.Close)
		})

		It("refuses a server that tops out below it", func() {
			c := newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{
				CAFile: serverCAFile(ts), MinVersion: config.TLSVersion13,
			}})
			_, err := get(c, ts.URL)
			Expect(err).To(MatchError(ContainSubstring("protocol version")))
		})

		It("reaches the same server without it, so the refusal is the setting's", func() {
			c := newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: serverCAFile(ts)}})
			_, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("tls_config.server_name", func() {
		// httptest's certificate is valid for example.com and 127.0.0.1, and
		// the request goes to 127.0.0.1: server_name decides which name the
		// certificate is checked against.
		var ts *httptest.Server

		BeforeEach(func() {
			ts = httptest.NewTLSServer(ok)
			DeferCleanup(ts.Close)
		})

		It("verifies the certificate against it rather than the URL's host", func() {
			c := newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{
				CAFile: serverCAFile(ts), ServerName: "example.com",
			}})
			_, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
		})

		It("refuses a certificate not valid for it", func() {
			c := newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{
				CAFile: serverCAFile(ts), ServerName: "wrong.example",
			}})
			_, err := get(c, ts.URL)
			Expect(err).To(MatchError(ContainSubstring("wrong.example")))
		})
	})

	Describe("tls_config client certificate", func() {
		It("presents it to a server that asks", func() {
			certFile, keyFile := clientCertificate(dir)
			var presented atomic.Int32
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				presented.Store(int32(len(r.TLS.PeerCertificates)))
			}))
			ts.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			ts.StartTLS()
			DeferCleanup(ts.Close)
			c := newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{
				CAFile: serverCAFile(ts), CertFile: certFile, KeyFile: keyFile,
			}})
			_, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(presented.Load()).To(BeEquivalentTo(1))
		})

		It("re-reads a renewed certificate on the next connection", func() {
			certFile, keyFile := clientCertificate(dir)
			var presented atomic.Value
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				presented.Store(r.TLS.PeerCertificates[0].SerialNumber.String())
			}))
			ts.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			ts.StartTLS()
			DeferCleanup(ts.Close)
			c := newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{
				CAFile: serverCAFile(ts), CertFile: certFile, KeyFile: keyFile,
			}})
			_, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			first := presented.Load()

			// Renewed in place, as cert-manager or a config-management run does.
			renewed := filepath.Join(dir, "renewed")
			Expect(os.MkdirAll(renewed, 0o700)).To(Succeed())
			newCert, newKey := clientCertificateSerial(renewed, 2)
			Expect(os.Rename(newCert, certFile)).To(Succeed())
			Expect(os.Rename(newKey, keyFile)).To(Succeed())
			c.CloseIdleConnections()

			_, err = get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(presented.Load()).NotTo(Equal(first), "the renewed certificate must be presented")
			Expect(presented.Load()).To(Equal("2"))
		})

		It("refuses at build time a certificate that does not load", func() {
			_, err := httpclient.New(context.Background(), config.HTTPClientConfig{TLSConfig: config.TLSConfig{
				CertFile: writeFile("c.pem", "x"), KeyFile: writeFile("k.pem", "x"),
			}}, "http_config")
			Expect(err).To(MatchError(ContainSubstring("loading http_config.tls_config client certificate")))
		})
	})

	Describe("enable_http2", func() {
		h2Server := func() *httptest.Server {
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprint(w, r.ProtoMajor)
			}))
			ts.EnableHTTP2 = true
			ts.StartTLS()
			DeferCleanup(ts.Close)
			return ts
		}

		It("negotiates HTTP/2 by default", func() {
			ts := h2Server()
			resp, err := get(newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: serverCAFile(ts)}}), ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.ProtoMajor).To(Equal(2))
		})

		It("stays on HTTP/1.1 when false", func() {
			ts := h2Server()
			resp, err := get(newClient(config.HTTPClientConfig{
				EnableHTTP2: ptr(false),
				TLSConfig:   config.TLSConfig{CAFile: serverCAFile(ts)},
			}), ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.ProtoMajor).To(Equal(1))
		})
	})

	Describe("redirects", func() {
		// hops returns a server that redirects /n to /n-1 until /0, which
		// answers 200.
		hops := func() *httptest.Server {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var n int
				_, _ = fmt.Sscanf(r.URL.Path, "/%d", &n)
				if n == 0 {
					_, _ = w.Write([]byte("ok"))
					return
				}
				http.Redirect(w, r, fmt.Sprintf("/%d", n-1), http.StatusFound)
			}))
			DeferCleanup(ts.Close)
			return ts
		}

		It("follows up to MaxRedirects", func() {
			ts := hops()
			resp, err := get(newClient(config.HTTPClientConfig{}), fmt.Sprintf("%s/%d", ts.URL, httpclient.MaxRedirects))
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
		})

		It("stops at one more", func() {
			ts := hops()
			_, err := get(newClient(config.HTTPClientConfig{}), fmt.Sprintf("%s/%d", ts.URL, httpclient.MaxRedirects+1))
			Expect(err).To(MatchError(ContainSubstring(fmt.Sprintf("stopped after %d redirects", httpclient.MaxRedirects))))
		})

		It("never follows a redirect onto the filesystem", func() {
			// file:/// entries are read by crlfetch itself, never through this
			// client, so no upstream can redirect a fetch onto a local file.
			// That rests on the transport refusing the scheme; this pins it.
			secret := writeFile("secret.txt", "sentinel-file-contents")
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "file://"+secret, http.StatusFound)
			}))
			DeferCleanup(ts.Close)
			resp, err := get(newClient(config.HTTPClientConfig{}), ts.URL)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).NotTo(ContainSubstring("sentinel-file-contents"))
			if resp != nil {
				body, _ := io.ReadAll(resp.Body)
				Expect(string(body)).NotTo(ContainSubstring("sentinel-file-contents"))
			}
		})

		It("returns the redirect itself when follow_redirects is false", func() {
			ts := hops()
			resp, err := get(newClient(config.HTTPClientConfig{FollowRedirects: ptr(false)}), ts.URL+"/1")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusFound))
		})

		Context("from https to http", func() {
			var plainHits atomic.Int32
			var plain *httptest.Server

			BeforeEach(func() {
				plainHits.Store(0)
				plain = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					plainHits.Add(1)
				}))
				DeferCleanup(plain.Close)
			})

			It("is refused, and the plain-text server never sees the request", func() {
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, plain.URL, http.StatusFound)
				}))
				DeferCleanup(ts.Close)
				_, err := get(newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: serverCAFile(ts)}}), ts.URL)
				Expect(err).To(MatchError(ContainSubstring("refusing to follow a redirect from https to http")))
				Expect(plainHits.Load()).To(BeZero())
			})

			It("is refused after an https-to-https hop too", func() {
				ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/first" {
						http.Redirect(w, r, "/second", http.StatusFound)
						return
					}
					http.Redirect(w, r, plain.URL, http.StatusFound)
				}))
				DeferCleanup(ts.Close)
				_, err := get(newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: serverCAFile(ts)}}), ts.URL+"/first")
				Expect(err).To(MatchError(ContainSubstring("refusing to follow a redirect from https to http")))
				Expect(plainHits.Load()).To(BeZero())
			})
		})

		It("follows http to https", func() {
			ts := httptest.NewTLSServer(ok)
			DeferCleanup(ts.Close)
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, ts.URL, http.StatusFound)
			}))
			DeferCleanup(plain.Close)
			resp, err := get(newClient(config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: serverCAFile(ts)}}), plain.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
		})
	})

	Describe("credentials", func() {
		var seen atomic.Value
		var requests atomic.Int32
		var ts *httptest.Server

		BeforeEach(func() {
			seen.Store("")
			requests.Store(0)
			ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				seen.Store(r.Header.Get("Authorization"))
			}))
			DeferCleanup(ts.Close)
		})

		It("sends basic_auth, re-reading the password file on every request", func() {
			pw := writeFile("pw", "first\n")
			c := newClient(config.HTTPClientConfig{BasicAuth: &config.BasicAuth{Username: "u", PasswordFile: pw}})
			_, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(seen.Load()).To(Equal("Basic dTpmaXJzdA==")) // u:first

			writeFile("pw", "second")
			_, err = get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(seen.Load()).To(Equal("Basic dTpzZWNvbmQ=")) // u:second
		})

		It("sends authorization as Bearer by default", func() {
			c := newClient(config.HTTPClientConfig{Authorization: &config.Authorization{CredentialsFile: writeFile("t", "tok\n")}})
			_, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(seen.Load()).To(Equal("Bearer tok"))
		})

		It("sends authorization with the configured type", func() {
			c := newClient(config.HTTPClientConfig{Authorization: &config.Authorization{Type: "Token", CredentialsFile: writeFile("t", "tok")}})
			_, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(seen.Load()).To(Equal("Token tok"))
		})

		DescribeTable("refuses a credentials file that cannot be a header",
			func(content, want string) {
				c := newClient(config.HTTPClientConfig{Authorization: &config.Authorization{CredentialsFile: writeFile("t", content)}})
				_, err := get(c, ts.URL)
				Expect(err).To(MatchError(ContainSubstring(want)))
				Expect(requests.Load()).To(BeZero(), "the request must not be sent")
			},
			Entry("empty", "\n", "is empty"),
			Entry("two lines", "a\nb\n", "holds more than one line"),
			Entry("one byte past the bound", strings.Repeat("a", httpclient.MaxSecretFileBytes+1), "is larger than"),
		)

		It("accepts a credentials file of exactly the bound", func() {
			c := newClient(config.HTTPClientConfig{Authorization: &config.Authorization{
				CredentialsFile: writeFile("t", strings.Repeat("a", httpclient.MaxSecretFileBytes)),
			}})
			_, err := get(c, ts.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(seen.Load()).To(HavePrefix("Bearer aaa"))
		})

		It("refuses a basic_auth password file that is not there, naming the setting", func() {
			c := newClient(config.HTTPClientConfig{BasicAuth: &config.BasicAuth{
				Username: "u", PasswordFile: filepath.Join(dir, "absent"),
			}})
			_, err := get(c, ts.URL)
			Expect(err).To(MatchError(ContainSubstring("reading http_config.basic_auth.password_file")))
			Expect(err).To(MatchError(os.ErrNotExist))
			Expect(requests.Load()).To(BeZero(), "the request must not be sent")
		})

		It("does not carry credentials to another host on a redirect", func() {
			// 127.0.0.1 and localhost are the same listener but different
			// hosts as far as net/http's redirect rule is concerned.
			other := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, other, http.StatusFound)
			}))
			DeferCleanup(first.Close)
			c := newClient(config.HTTPClientConfig{Authorization: &config.Authorization{CredentialsFile: writeFile("t", "tok")}})
			resp, err := get(c, first.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(seen.Load()).To(BeEmpty())
		})
	})

	Describe("proxies", func() {
		var proxied atomic.Int32
		var proxy *httptest.Server

		BeforeEach(func() {
			proxied.Store(0)
			// A forward proxy answering every absolute-form request itself.
			proxy = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Host == unresolvable {
					proxied.Add(1)
				}
				_, _ = w.Write([]byte("via proxy"))
			}))
			DeferCleanup(proxy.Close)
		})

		It("sends requests through proxy_url", func() {
			resp, err := get(newClient(config.HTTPClientConfig{ProxyURL: proxy.URL}), "http://"+unresolvable+"/crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(proxied.Load()).To(BeEquivalentTo(1))
		})

		It("still proxies a host not in no_proxy", func() {
			resp, err := get(newClient(config.HTTPClientConfig{ProxyURL: proxy.URL, NoProxy: "other.test"}),
				"http://"+unresolvable+"/crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(proxied.Load()).To(BeEquivalentTo(1))
		})

		// An https:// request reaches a proxy as a CONNECT for the target's
		// host and port; https:// is what crl_chain.urls is meant to use, and
		// with a no_proxy list the proxy for it is a field of its own.
		DescribeTable("sends an https:// request through proxy_url as a CONNECT",
			func(noProxy string) {
				var connects atomic.Int32
				p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodConnect && r.Host == unresolvable+":443" {
						connects.Add(1)
					}
					w.WriteHeader(http.StatusBadGateway)
				}))
				DeferCleanup(p.Close)
				_, err := get(newClient(config.HTTPClientConfig{ProxyURL: p.URL, NoProxy: noProxy}),
					"https://"+unresolvable+"/crl")
				Expect(err).To(HaveOccurred(), "the proxy refuses the tunnel")
				Expect(connects.Load()).To(BeEquivalentTo(1), "the request went to the proxy, not direct")
			},
			Entry("with no no_proxy list", ""),
			Entry("with a no_proxy list that does not match", "other.test"),
		)

		It("bypasses proxy_url for a host in no_proxy", func() {
			_, err := get(newClient(config.HTTPClientConfig{ProxyURL: proxy.URL, NoProxy: unresolvable}), "http://"+unresolvable+"/crl")
			Expect(err).To(HaveOccurred(), "a direct request for an unresolvable host cannot succeed")
			Expect(proxied.Load()).To(BeZero())
		})

		It("takes the proxy from the environment by default", func() {
			GinkgoT().Setenv("HTTP_PROXY", proxy.URL)
			resp, err := get(newClient(config.HTTPClientConfig{}), "http://"+unresolvable+"/crl")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
			Expect(proxied.Load()).To(BeEquivalentTo(1))
		})

		It("sends even a loopback request through proxy_url when no_proxy is empty, as Prometheus does", func() {
			// httpproxy never proxies loopback, which is why it is used only
			// when there is a no_proxy list to apply.
			var viaProxy atomic.Int32
			target := httptest.NewServer(ok)
			DeferCleanup(target.Close)
			host := strings.TrimPrefix(target.URL, "http://")
			p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Host == host {
					viaProxy.Add(1)
				}
				_, _ = w.Write([]byte("via proxy"))
			}))
			DeferCleanup(p.Close)
			_, err := get(newClient(config.HTTPClientConfig{ProxyURL: p.URL}), target.URL)
			Expect(err).NotTo(HaveOccurred())
			Expect(viaProxy.Load()).To(BeEquivalentTo(1))
		})

		It("ignores the environment when proxy_from_environment is false", func() {
			GinkgoT().Setenv("HTTP_PROXY", proxy.URL)
			_, err := get(newClient(config.HTTPClientConfig{ProxyFromEnvironment: ptr(false)}), "http://"+unresolvable+"/crl")
			Expect(err).To(HaveOccurred())
			Expect(proxied.Load()).To(BeZero())
		})
	})

	It("names itself in the User-Agent", func() {
		var ua atomic.Value
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ua.Store(r.Header.Get("User-Agent"))
		}))
		DeferCleanup(ts.Close)
		_, err := get(newClient(config.HTTPClientConfig{}), ts.URL)
		Expect(err).NotTo(HaveOccurred())
		Expect(ua.Load()).To(HavePrefix("openvox-ca/"))
	})

	It("refuses to build from a block that does not validate", func() {
		_, err := httpclient.New(context.Background(), config.HTTPClientConfig{NoProxy: "x"}, "crl_chain.http_config")
		Expect(err).To(MatchError(ContainSubstring("crl_chain.http_config.no_proxy requires")))
	})
})

// clientCertificate writes a self-signed client certificate and its key.
func clientCertificate(dir string) (certFile, keyFile string) {
	return clientCertificateSerial(dir, 1)
}

// clientCertificateSerial is clientCertificate with a chosen serial number, so
// a spec can tell two certificates apart.
func clientCertificateSerial(dir string, serial int64) (certFile, keyFile string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())
	certFile = filepath.Join(dir, "client.pem")
	keyFile = filepath.Join(dir, "client.key")
	Expect(os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)).To(Succeed())
	Expect(os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)).To(Succeed())
	return certFile, keyFile
}
