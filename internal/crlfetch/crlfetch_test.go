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

package crlfetch_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/crlfetch"
)

// newCRLDER issues an empty CRL with the given number from a fresh CA.
func newCRLDER(number int64) []byte {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Upstream"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(certDER)
	Expect(err).NotTo(HaveOccurred())
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return der
}

// bigCRLDER issues a CRL listing entries revocations, to size one near the
// bound.
func bigCRLDER(entries int) []byte {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Upstream"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(certDER)
	Expect(err).NotTo(HaveOccurred())
	now := time.Now()
	revoked := make([]x509.RevocationListEntry, entries)
	for i := range revoked {
		revoked[i] = x509.RevocationListEntry{SerialNumber: big.NewInt(int64(1_000_000_000 + i)), RevocationTime: now}
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                now,
		NextUpdate:                now.Add(24 * time.Hour),
		RevokedCertificateEntries: revoked,
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return der
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

var _ = Describe("Decode", func() {
	It("accepts DER, as a distribution point serves it", func() {
		crl, err := crlfetch.Decode(newCRLDER(4))
		Expect(err).NotTo(HaveOccurred())
		Expect(crl.Number.Int64()).To(BeEquivalentTo(4))
	})

	It("accepts PEM, with text before the block", func() {
		crl, err := crlfetch.Decode(append([]byte("Certificate Revocation List (CRL):\n  ...\n"), pemOf(newCRLDER(5))...))
		Expect(err).NotTo(HaveOccurred())
		Expect(crl.Number.Int64()).To(BeEquivalentTo(5))
	})

	It("accepts PEM with a block of another type beside the CRL, as crl_chain.file does", func() {
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
		crl, err := crlfetch.Decode(append(cert, pemOf(newCRLDER(6))...))
		Expect(err).NotTo(HaveOccurred())
		Expect(crl.Number.Int64()).To(BeEquivalentTo(6))
	})

	// The bound is on the PEM form, the one the CRL is published in: a DER CRL
	// within the response cap can still be too large to publish, and must fail
	// as its own entry rather than at the merge's bound on the whole chain.
	It("refuses a DER CRL whose PEM form is over the bound, and accepts one just under it", func() {
		over := bigCRLDER(160_000)
		Expect(len(over)).To(BeNumerically("<=", crlfetch.MaxBytes), "precondition: within the response cap as DER")
		Expect(len(pemOf(over))).To(BeNumerically(">", crlfetch.MaxBytes), "precondition: over it as PEM")
		_, err := crlfetch.Decode(over)
		Expect(err).To(MatchError(ContainSubstring("as PEM, over the %d-byte bound", crlfetch.MaxBytes)))

		under := bigCRLDER(130_000)
		Expect(len(pemOf(under))).To(And(BeNumerically("<=", crlfetch.MaxBytes),
			BeNumerically(">", crlfetch.MaxBytes*9/10)), "precondition: just under the bound as PEM")
		_, err = crlfetch.Decode(under)
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("refuses what is not exactly one CRL",
		func(data func() []byte, want string) {
			_, err := crlfetch.Decode(data())
			Expect(err).To(MatchError(ContainSubstring(want)))
		},
		Entry("an empty body", func() []byte { return []byte(" \n") }, "empty"),
		Entry("two CRLs", func() []byte { return append(pemOf(newCRLDER(1)), pemOf(newCRLDER(2))...) },
			"more than one CRL"),
		Entry("PEM of another type", func() []byte {
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})
		}, "no X509 CRL block"),
		Entry("a truncated PEM", func() []byte {
			p := pemOf(newCRLDER(1))
			return append(p, []byte("-----BEGIN X509 CRL-----\nMIIB")...)
		}, "content after its last PEM block"),
		Entry("a complete block followed by text", func() []byte {
			return append(pemOf(newCRLDER(1)), []byte("-- end of list --\n")...)
		}, "content after its last PEM block"),
		Entry("an HTML error page served with a 200", func() []byte {
			return []byte("<html><body>Service Unavailable</body></html>")
		}, "neither a DER nor a PEM CRL"),
		Entry("DER with trailing bytes", func() []byte { return append(newCRLDER(1), 0, 0) },
			"neither a DER nor a PEM CRL"),
		Entry("an X509 CRL block that is not a CRL", func() []byte {
			return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: []byte{1, 2, 3}})
		}, "parsing the CRL"),
	)
})

var _ = Describe("Fetcher", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
			GinkgoT().Setenv(k, "")
		}
	})

	fetch := func(urls ...string) []crlfetch.Result {
		GinkgoHelper()
		f, err := crlfetch.New(ctx, urls, config.HTTPClientConfig{}, 5*time.Second)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		return f.Fetch(ctx)
	}

	serve := func(h http.HandlerFunc) string {
		ts := httptest.NewServer(h)
		DeferCleanup(ts.Close)
		return ts.URL
	}

	It("returns one result per entry, in configured order", func() {
		der := newCRLDER(3)
		good := serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(der) })
		missing := serve(func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
		file := filepath.Join(GinkgoT().TempDir(), "sub.crl")
		Expect(os.WriteFile(file, pemOf(newCRLDER(9)), 0o600)).To(Succeed())

		res := fetch(good, missing, "file://"+file)
		Expect(res).To(HaveLen(3))
		Expect(res[0].URL).To(Equal(good))
		Expect(res[0].Err).NotTo(HaveOccurred())
		Expect(res[0].CRL.Number.Int64()).To(BeEquivalentTo(3))
		Expect(res[1].Err).To(MatchError("HTTP status 404"))
		Expect(res[2].Err).NotTo(HaveOccurred())
		Expect(res[2].CRL.Number.Int64()).To(BeEquivalentTo(9))
	})

	It("never quotes a response body in its error", func() {
		secret := "internal-service-response-do-not-log"
		u := serve(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(secret))
		})
		html := serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(secret)) })
		for _, r := range fetch(u, html) {
			Expect(r.Err).To(HaveOccurred())
			Expect(r.Err.Error()).NotTo(ContainSubstring(secret))
		}
	})

	It("refuses a response over the size cap rather than truncating it", func() {
		big := bytes.Repeat([]byte("A"), crlfetch.MaxBytes+1)
		u := serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(big) })
		Expect(fetch(u)[0].Err).To(MatchError(ContainSubstring("larger than")))
	})

	It("reads a response of exactly the size cap", func() {
		// Not a CRL, so it fails to decode; what matters is that it is not
		// refused for its size.
		exact := bytes.Repeat([]byte("A"), crlfetch.MaxBytes)
		u := serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(exact) })
		err := fetch(u)[0].Err
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("larger than"))
	})

	It("holds a file:/// entry to the same size cap", func() {
		file := filepath.Join(GinkgoT().TempDir(), "big.crl")
		Expect(os.WriteFile(file, bytes.Repeat([]byte("A"), crlfetch.MaxBytes+1), 0o600)).To(Succeed())
		Expect(fetch("file://" + file)[0].Err).To(MatchError(ContainSubstring("larger than")))
	})

	It("gives up on an entry that does not answer within the timeout", func() {
		release := make(chan struct{})
		DeferCleanup(func() { close(release) })
		u := serve(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
		f, err := crlfetch.New(ctx, []string{u}, config.HTTPClientConfig{}, 200*time.Millisecond)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		start := time.Now()
		Expect(f.Fetch(ctx)[0].Err).To(MatchError(ContainSubstring("deadline exceeded")))
		Expect(time.Since(start)).To(BeNumerically("<", 3*time.Second))
	})

	It("fetches at most Concurrency entries at once", func() {
		// A long list must not open a burst of connections: the entries past
		// the bound wait for a slot rather than start.
		var inflight, peak atomic.Int32
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		DeferCleanup(unblock)
		der := newCRLDER(1)
		base := serve(func(w http.ResponseWriter, r *http.Request) {
			n := inflight.Add(1)
			defer inflight.Add(-1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			select {
			case <-release:
				_, _ = w.Write(der)
			case <-r.Context().Done():
			}
		})
		urls := make([]string, crlfetch.Concurrency+2)
		for i := range urls {
			urls[i] = fmt.Sprintf("%s/%d.crl", base, i)
		}
		f, err := crlfetch.New(ctx, urls, config.HTTPClientConfig{}, 10*time.Second)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		results := make(chan []crlfetch.Result, 1)
		go func() { results <- f.Fetch(ctx) }()

		Eventually(inflight.Load).WithTimeout(5 * time.Second).Should(BeEquivalentTo(crlfetch.Concurrency))
		Consistently(inflight.Load).WithTimeout(300*time.Millisecond).
			Should(BeEquivalentTo(crlfetch.Concurrency), "no entry past the bound may start while the others are held")
		unblock()
		var res []crlfetch.Result
		Eventually(results).WithTimeout(5 * time.Second).Should(Receive(&res))
		for _, r := range res {
			Expect(r.Err).NotTo(HaveOccurred())
		}
		Expect(peak.Load()).To(BeEquivalentTo(crlfetch.Concurrency))
	})

	It("reports a file entry that is not there", func() {
		res := fetch("file://" + filepath.Join(GinkgoT().TempDir(), "absent.crl"))
		Expect(res[0].Err).To(MatchError(os.ErrNotExist))
	})

	It("fails every http(s) entry, naming the setting, when the client cannot be built, but still reads file:/// entries", func() {
		file := filepath.Join(GinkgoT().TempDir(), "sub.crl")
		Expect(os.WriteFile(file, newCRLDER(2), 0o600)).To(Succeed())
		f, err := crlfetch.New(ctx, []string{"https://pki.example/root.crl", "file://" + file, "http://pki.example/other.crl"},
			config.HTTPClientConfig{
				TLSConfig: config.TLSConfig{CAFile: filepath.Join(GinkgoT().TempDir(), "absent.pem")},
			}, time.Second)
		Expect(err).NotTo(HaveOccurred(), "a broken http_config fails entries, not the round")
		DeferCleanup(f.Close)
		res := f.Fetch(ctx)
		Expect(res[0].Err).To(MatchError(ContainSubstring("crl_chain.http_config.tls_config.ca_file")))
		Expect(res[1].Err).NotTo(HaveOccurred(), "a file:/// entry never depends on http_config")
		Expect(res[2].Err).To(MatchError(ContainSubstring("crl_chain.http_config.tls_config.ca_file")))
	})

	It("does not need http_config at all for a list of file:/// entries", func() {
		file := filepath.Join(GinkgoT().TempDir(), "root.crl")
		Expect(os.WriteFile(file, newCRLDER(2), 0o600)).To(Succeed())
		// A broken http_config that would refuse an http(s) list.
		f, err := crlfetch.New(ctx, []string{"file://" + file}, config.HTTPClientConfig{
			TLSConfig: config.TLSConfig{CAFile: filepath.Join(GinkgoT().TempDir(), "absent.pem")},
		}, time.Second)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		res := f.Fetch(ctx)
		Expect(res[0].Err).NotTo(HaveOccurred())
	})

	It("follows the shared client's redirect rules", func() {
		// The fetcher must use httpclient rather than a client of its own;
		// a plain http.Client would follow this downgrade.
		plain := serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newCRLDER(1)) })
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain, http.StatusFound)
		}))
		DeferCleanup(ts.Close)
		caFile := filepath.Join(GinkgoT().TempDir(), "ca.pem")
		Expect(os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600)).To(Succeed())
		f, err := crlfetch.New(ctx, []string{ts.URL}, config.HTTPClientConfig{TLSConfig: config.TLSConfig{CAFile: caFile}}, 5*time.Second)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		Expect(f.Fetch(ctx)[0].Err).To(MatchError(ContainSubstring("from https to http")))
		Expect(strings.HasPrefix(ts.URL, "https://")).To(BeTrue())
	})
})
