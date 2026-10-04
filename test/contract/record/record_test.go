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
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The recorder needs Docker to run, so CI never does; these specs pin the
// refusals that keep a hand-run recording from damaging anything, and the
// rules that shape every fixture, none of which need a container.

// contractFixtures is the committed contract, relative to this package.
const contractFixtures = "../../../internal/api/testdata/contract/fixtures"

// generatedBodies are the cases whose request body run fills in, a CSR made
// fresh for each recording.
var generatedBodies = map[string]bool{"certificate-request-put": true, "certificate-request-put-existing-cert": true}

// fixtureDrift reports every way the fixtures in dir differ from cases():
// a fixture no case records, a case with no fixture, and a fixture whose
// request or compare mode is not its case's. A difference means the contract
// was edited by hand or not re-recorded after cases() changed.
func fixtureDrift(dir string) []string {
	var drift []string
	want := map[string]fixture{}
	for _, c := range cases() {
		want[c.Name] = c
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	Expect(err).NotTo(HaveOccurred())
	seen := map[string]bool{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		Expect(err).NotTo(HaveOccurred())
		var got fixture
		Expect(json.Unmarshal(b, &got)).To(Succeed(), p)
		seen[got.Name] = true
		c, ok := want[got.Name]
		if !ok {
			drift = append(drift, got.Name+": no case records it")
			continue
		}
		if got.Compare != c.Compare {
			drift = append(drift, fmt.Sprintf("%s: compare %q, case %q", got.Name, got.Compare, c.Compare))
		}
		if got.Description != c.Description || !reflect.DeepEqual(got.Sources, c.Sources) {
			drift = append(drift, got.Name+": description or sources differ from the case")
		}
		gr, cr := got.Request, c.Request
		if generatedBodies[c.Name] {
			gr.Body, cr.Body = "", ""
		}
		if gr != cr {
			drift = append(drift, fmt.Sprintf("%s: request %+v, case %+v", got.Name, gr, cr))
		}
	}
	for name := range want {
		if !seen[name] {
			drift = append(drift, name+": not recorded")
		}
	}
	sort.Strings(drift)
	return drift
}

var _ = Describe("the committed contract", func() {
	It("is what cases() records, untouched by hand", func() {
		Expect(fixtureDrift(contractFixtures)).To(BeEmpty(), "re-record: go run ./test/contract/record")
	})

	It("is reported when a fixture's compare mode is edited", func() {
		dir := GinkgoT().TempDir()
		paths, err := filepath.Glob(filepath.Join(contractFixtures, "*.json"))
		Expect(err).NotTo(HaveOccurred())
		for _, p := range paths {
			b, err := os.ReadFile(p)
			Expect(err).NotTo(HaveOccurred())
			if filepath.Base(p) == "status-signed-dns.json" {
				var f map[string]any
				Expect(json.Unmarshal(b, &f)).To(Succeed())
				f["compare"] = "none"
				b, err = json.Marshal(f)
				Expect(err).NotTo(HaveOccurred())
			}
			Expect(os.WriteFile(filepath.Join(dir, filepath.Base(p)), b, 0o600)).To(Succeed())
		}
		Expect(os.Remove(filepath.Join(dir, "crl-get.json"))).To(Succeed())
		Expect(fixtureDrift(dir)).To(ConsistOf(
			`status-signed-dns: compare "none", case "exact"`,
			"crl-get: not recorded",
		))
	})
})

var _ = Describe("loadCA", func() {
	var dir string

	// writeCA writes a self-signed CA and its key, as keyPEM renders it.
	writeCA := func(keyPEM func(*rsa.PrivateKey) []byte) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(dir, "ca_crt.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)).To(Succeed())
		if keyPEM != nil {
			Expect(os.WriteFile(filepath.Join(dir, "ca_key.pem"), keyPEM(key), 0o600)).To(Succeed())
		}
	}
	pkcs1 := func(k *rsa.PrivateKey) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	}

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	It("loads an RSA CA whose key is PKCS#1, as OpenVox Server writes it", func() {
		writeCA(pkcs1)
		a, err := loadCA(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(a.chain).To(HaveLen(1))
		Expect(a.chain[0].Subject.CommonName).To(Equal("Test CA"))
	})

	It("refuses a key that is a symlink, which could name a host file", func() {
		writeCA(nil)
		host := filepath.Join(GinkgoT().TempDir(), "key.pem")
		Expect(os.WriteFile(host, []byte("key"), 0o600)).To(Succeed())
		Expect(os.Symlink(host, filepath.Join(dir, "ca_key.pem"))).To(Succeed())
		_, err := loadCA(dir)
		Expect(err).To(MatchError(ContainSubstring("not a regular file")))
	})

	It("refuses a bundle with no certificate", func() {
		writeCA(pkcs1)
		Expect(os.WriteFile(filepath.Join(dir, "ca_crt.pem"), nil, 0o600)).To(Succeed())
		_, err := loadCA(dir)
		Expect(err).To(MatchError(ContainSubstring("holds no certificate")))
	})

	It("refuses a key that cannot sign, rather than panicking", func() {
		writeCA(func(*rsa.PrivateKey) []byte {
			k, err := ecdh.X25519().GenerateKey(rand.Reader)
			Expect(err).NotTo(HaveOccurred())
			der, err := x509.MarshalPKCS8PrivateKey(k)
			Expect(err).NotTo(HaveOccurred())
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		})
		_, err := loadCA(dir)
		Expect(err).To(MatchError(ContainSubstring("cannot sign")))
	})
})

var _ = Describe("copyCadir", func() {
	var src, out *os.Root
	var srcDir, outDir string

	BeforeEach(func() {
		srcDir, outDir = GinkgoT().TempDir(), GinkgoT().TempDir()
		for _, name := range []string{"ca_crt.pem", "ca_key.pem", "ca_crl.pem", "signed/a.pem", "requests/b.pem"} {
			Expect(os.MkdirAll(filepath.Dir(filepath.Join(srcDir, name)), 0o750)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(srcDir, name), []byte(name), 0o600)).To(Succeed())
		}
		var err error
		src, err = os.OpenRoot(srcDir)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(src.Close)
		out, err = os.OpenRoot(outDir)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(out.Close)
	})

	It("copies the store's files into cadir/", func() {
		Expect(copyCadir(src, out)).To(Succeed())
		Expect(os.ReadFile(filepath.Join(outDir, "cadir", "signed", "a.pem"))).To(Equal([]byte("signed/a.pem")))
		Expect(os.ReadFile(filepath.Join(outDir, "cadir", "requests", "b.pem"))).To(Equal([]byte("requests/b.pem")))
	})

	It("refuses a certificate that is a symlink, rather than copying its target into the contract", func() {
		host := filepath.Join(GinkgoT().TempDir(), "host.pem")
		Expect(os.WriteFile(host, []byte("host"), 0o600)).To(Succeed())
		Expect(os.Symlink(host, filepath.Join(srcDir, "signed", "c.pem"))).To(Succeed())
		Expect(copyCadir(src, out)).To(MatchError(ContainSubstring("not a regular file")))
		Expect(filepath.Join(outDir, "cadir", "signed", "c.pem")).NotTo(BeAnExistingFile())
	})
})

var _ = Describe("do", func() {
	var client *http.Client

	BeforeEach(func() {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/json":
				w.Header().Set("Content-Type", "application/json;charset=utf-8")
				_, _ = w.Write([]byte(`{"a":1}`))
			case "/broken-json":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("Resource not found."))
			default:
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("PEM\n"))
			}
		}))
		DeferCleanup(srv.Close)
		// do addresses the server by serverName, as the recorder's client
		// does: dial the test server whatever the name, and verify its
		// certificate under the name it was issued for.
		t := srv.Client().Transport.(*http.Transport).Clone()
		t.TLSClientConfig.ServerName = "example.com"
		t.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}
		client = &http.Client{Transport: t}
	})

	It("records a JSON body as JSON, and every header but Date", func() {
		resp, err := do(context.Background(), client, request{Method: "GET", Path: "/json"})
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.JSON).To(MatchJSON(`{"a":1}`))
		Expect(resp.Text).To(BeNil())
		Expect(resp.Headers).To(HaveKey("Content-Type"))
		Expect(resp.Headers).NotTo(HaveKey("Date"))
	})

	It("records a body labelled JSON that is not JSON as text, as it came", func() {
		resp, err := do(context.Background(), client, request{Method: "GET", Path: "/broken-json"})
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.JSON).To(BeNil())
		Expect(resp.Text).To(HaveValue(Equal("Resource not found.")))
	})

	It("records any other body as text", func() {
		resp, err := do(context.Background(), client, request{Method: "GET", Path: "/text"})
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.JSON).To(BeNil())
		Expect(resp.Text).To(HaveValue(Equal("PEM\n")))
	})
})

var _ = Describe("checkReplaceable", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	It("accepts an out that does not exist yet", func() {
		Expect(checkReplaceable(filepath.Join(dir, "contract"))).To(Succeed())
	})

	It("accepts a contract this recorder wrote", func() {
		Expect(os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o600)).To(Succeed())
		Expect(checkReplaceable(dir)).To(Succeed())
	})

	DescribeTable("refuses anything else, since a run replaces out wholesale",
		func(setup func(out string) string) {
			Expect(checkReplaceable(setup(dir))).To(MatchError(ContainSubstring("is not a recorded contract")))
		},
		Entry("an empty directory", func(out string) string { return out }),
		Entry("a directory whose README is someone else's", func(out string) string {
			Expect(os.WriteFile(filepath.Join(out, "README.md"), []byte("# My project\n"), 0o600)).To(Succeed())
			return out
		}),
		Entry("a plain file", func(out string) string {
			f := filepath.Join(out, "file")
			Expect(os.WriteFile(f, []byte(contractHeader), 0o600)).To(Succeed())
			return f
		}),
	)
})

var _ = Describe("readRegular", func() {
	var src *os.Root

	BeforeEach(func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "ca_crt.pem"), []byte("PEM"), 0o600)).To(Succeed())
		Expect(os.Mkdir(filepath.Join(dir, "signed"), 0o750)).To(Succeed())
		host := filepath.Join(GinkgoT().TempDir(), "secret")
		Expect(os.WriteFile(host, []byte("host"), 0o600)).To(Succeed())
		Expect(os.Symlink(host, filepath.Join(dir, "ca_key.pem"))).To(Succeed())
		var err error
		src, err = os.OpenRoot(dir)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(src.Close)
	})

	It("reads a regular file", func() {
		Expect(readRegular(src, "ca_crt.pem")).To(Equal([]byte("PEM")))
	})

	It("refuses a symlink, which docker cp carries over and which could name a host file", func() {
		_, err := readRegular(src, "ca_key.pem")
		Expect(err).To(MatchError(ContainSubstring("not a regular file")))
	})

	It("refuses a directory", func() {
		_, err := readRegular(src, "signed")
		Expect(err).To(MatchError(ContainSubstring("not a regular file")))
	})
})

var _ = Describe("pinnedImage", func() {
	var compose string

	BeforeEach(func() {
		compose = filepath.Join(GinkgoT().TempDir(), "compose.yml")
	})

	It("reads the OpenVox Server image, skipping a commented-out one and other images", func() {
		Expect(os.WriteFile(compose, []byte(`services:
  old-puppet:
    # image: ghcr.io/openvoxproject/openvoxserver:8.0.0-main
    image: ghcr.io/openvoxproject/openvoxserver:8.14.1-main@sha256:abc
  test-runner:
    image: openvox-ca-integ:latest
`), 0o600)).To(Succeed())
		Expect(pinnedImage(compose)).To(Equal("ghcr.io/openvoxproject/openvoxserver:8.14.1-main@sha256:abc"))
	})

	It("fails when no OpenVox Server image is pinned", func() {
		Expect(os.WriteFile(compose, []byte("services:\n  x:\n    image: openvox-ca-integ:latest\n"), 0o600)).To(Succeed())
		_, err := pinnedImage(compose)
		Expect(err).To(MatchError(ContainSubstring("pins no")))
	})
})

var _ = Describe("the cited release", func() {
	DescribeTable("releaseTag takes the image tag up to its first dash",
		func(image, want string) {
			Expect(releaseTag(image)).To(Equal(want))
		},
		Entry("a variant tag with a digest", imagePrefix+"8.14.1-main@sha256:abc", "8.14.1"),
		Entry("a plain tag with a digest", imagePrefix+"8.14.1@sha256:abc", "8.14.1"),
		Entry("a plain tag", imagePrefix+"8.15.0", "8.15.0"),
	)

	It("accepts an image built from the release the citations were checked against", func() {
		Expect(checkCitedRelease(imagePrefix + citedTag + "-main@sha256:abc")).To(Succeed())
	})

	It("refuses an image built from any other release", func() {
		Expect(checkCitedRelease(imagePrefix + "99.0.0-main@sha256:abc")).To(MatchError(ContainSubstring("move citedTag")))
	})
})

var _ = Describe("swapIn", func() {
	var dir, staging, out string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		staging = filepath.Join(dir, "contract.recording-1")
		out = filepath.Join(dir, "contract")
		Expect(os.Mkdir(staging, 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(staging, "new"), nil, 0o600)).To(Succeed())
	})

	It("replaces the previous contract, leaving nothing beside it", func() {
		Expect(os.Mkdir(out, 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(out, "old"), nil, 0o600)).To(Succeed())
		Expect(swapIn(staging, out)).To(Succeed())
		Expect(filepath.Join(out, "new")).To(BeAnExistingFile())
		Expect(filepath.Join(out, "old")).NotTo(BeAnExistingFile())
		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
	})

	It("puts a first contract in place", func() {
		Expect(swapIn(staging, out)).To(Succeed())
		Expect(filepath.Join(out, "new")).To(BeAnExistingFile())
	})

	It("puts the previous contract back when the new one cannot be moved in", func() {
		Expect(os.Mkdir(out, 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(out, "old"), nil, 0o600)).To(Succeed())
		Expect(swapIn(filepath.Join(dir, "missing"), out)).NotTo(Succeed())
		Expect(filepath.Join(out, "old")).To(BeAnExistingFile())
	})
})
