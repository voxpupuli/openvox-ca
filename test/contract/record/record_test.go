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
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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

// recordedCases is cases(), in order, each with the response the committed
// contract recorded for it.
func recordedCases() []fixture {
	fs := cases()
	for i, c := range fs {
		var got fixture
		Expect(json.Unmarshal(mustRead(filepath.Join(contractFixtures, c.Name+".json")), &got)).To(Succeed(), c.Name)
		fs[i].Response = got.Response
	}
	return fs
}

// clientSubjects names the subject a client's own certificate is for, which
// is what auto-renewal changes.
var clientSubjects = map[string]string{"renewer": "renew-me"}

// changedSubjects lists the subjects a request changes, if upstream accepts
// it, or reports false when it cannot tell.
func changedSubjects(r request) ([]string, bool) {
	const v1 = "/puppet-ca/v1"
	switch {
	case strings.HasPrefix(r.Path, v1+"/certificate_status/"), strings.HasPrefix(r.Path, v1+"/certificate_request/"):
		return []string{path.Base(r.Path)}, true
	case r.Path == v1+"/sign", r.Path == v1+"/clean":
		var body struct {
			Certnames []string `json:"certnames"`
		}
		// A body whose certnames is not a list names no subject.
		_ = json.Unmarshal([]byte(r.Body), &body)
		return body.Certnames, true
	case r.Path == v1+"/certificate_renewal":
		s, ok := clientSubjects[r.Client]
		return []string{s}, ok
	}
	return nil, false
}

// snapshotViolations reports every way fs, cases with their recorded
// responses, breaks the rule cases() states: no read after a mutation
// upstream accepts, no subject changed by two of them, and /sign/all last.
// A non-GET answered 2xx counts as accepted. That over-counts (POST /sign
// answers 200 while refusing every name in it), so the rule is held tighter
// than it needs to be, never looser.
func snapshotViolations(fs []fixture) []string {
	var out []string
	changedBy := map[string]string{}
	firstChange := ""
	for i, f := range fs {
		if strings.HasSuffix(f.Request.Path, "/sign/all") {
			if i != len(fs)-1 {
				out = append(out, f.Name+": acts on every pending CSR, so it must be last")
			}
			continue
		}
		if f.Request.Method == http.MethodGet {
			if firstChange != "" {
				out = append(out, fmt.Sprintf("%s: reads after %s changed the store", f.Name, firstChange))
			}
			continue
		}
		if f.Response.Status < 200 || f.Response.Status > 299 {
			continue
		}
		if firstChange == "" {
			firstChange = f.Name
		}
		subjects, ok := changedSubjects(f.Request)
		if !ok {
			out = append(out, f.Name+": cannot tell which subjects it changes; teach changedSubjects")
			continue
		}
		for _, s := range subjects {
			if prev, dup := changedBy[s]; dup {
				out = append(out, fmt.Sprintf("%s: changes %s, which %s already changed", f.Name, s, prev))
			}
			changedBy[s] = f.Name
		}
	}
	return out
}

var _ = Describe("the committed contract", func() {
	// It binds the fixtures' names, compare modes, descriptions, sources and
	// requests; a hand-edited response is beyond it, and only a re-record
	// shows one up.
	It("records every case in cases(), with its request and compare mode", func() {
		Expect(fixtureDrift(contractFixtures)).To(BeEmpty(), "re-record: go run ./test/contract/record")
	})

	// Each entry edits one fixture in a copy of the contract and expects the
	// one drift line that edit causes.
	DescribeTable("reports a contract that has drifted from cases()",
		func(edit func(dir string), want string) {
			dir := GinkgoT().TempDir()
			paths, err := filepath.Glob(filepath.Join(contractFixtures, "*.json"))
			Expect(err).NotTo(HaveOccurred())
			for _, p := range paths {
				b, err := os.ReadFile(p)
				Expect(err).NotTo(HaveOccurred())
				Expect(os.WriteFile(filepath.Join(dir, filepath.Base(p)), b, 0o600)).To(Succeed())
			}
			edit(dir)
			Expect(fixtureDrift(dir)).To(ConsistOf(HavePrefix(want)))
		},
		Entry("an edited compare mode", editFixture("status-signed-dns", func(f map[string]any) { f["compare"] = "none" }),
			`status-signed-dns: compare "none", case "exact"`),
		Entry("an edited request", editFixture("crl-get", func(f map[string]any) {
			f["request"].(map[string]any)["path"] = "/puppet-ca/v1/certificate_revocation_list/other"
		}), "crl-get: request "),
		Entry("an edited description", editFixture("sign", func(f map[string]any) { f["description"] = "something else" }),
			"sign: description or sources differ from the case"),
		Entry("edited sources", editFixture("clean", func(f map[string]any) { f["sources"] = []string{"elsewhere.clj:1-2"} }),
			"clean: description or sources differ from the case"),
		Entry("a fixture no case records", func(dir string) {
			editFixture("crl-get", func(f map[string]any) { f["name"] = "orphan" })(dir)
			b, err := os.ReadFile(filepath.Join(dir, "crl-get.json"))
			Expect(err).NotTo(HaveOccurred())
			Expect(os.WriteFile(filepath.Join(dir, "orphan.json"), b, 0o600)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "crl-get.json"), mustRead(filepath.Join(contractFixtures, "crl-get.json")), 0o600)).To(Succeed())
		}, "orphan: no case records it"),
		Entry("a case never recorded", func(dir string) {
			Expect(os.Remove(filepath.Join(dir, "crl-get.json"))).To(Succeed())
		}, "crl-get: not recorded"),
	)

	// Every response is replayed against the snapshot taken before the first
	// case, so each must have been an answer to that state.
	It("orders cases() so that every recorded response answers the snapshot", func() {
		Expect(snapshotViolations(recordedCases())).To(BeEmpty())
	})

	// Each entry edits the recorded cases and expects the one violation that
	// edit causes.
	DescribeTable("reports a case order that would record a later state than the snapshot",
		func(edit func([]fixture) []fixture, want string) {
			Expect(snapshotViolations(edit(recordedCases()))).To(Equal([]string{want}))
		},
		Entry("/sign/all before another case", func(fs []fixture) []fixture {
			n := len(fs)
			fs[n-2], fs[n-1] = fs[n-1], fs[n-2]
			return fs
		}, "sign-all: acts on every pending CSR, so it must be last"),
		Entry("a read after an accepted mutation", func(fs []fixture) []fixture {
			read := fs[0]
			read.Name = "late-read"
			return insertBefore(fs, "status-delete", read)
		}, "late-read: reads after status-put-sign changed the store"),
		Entry("a second accepted mutation on one subject", func(fs []fixture) []fixture {
			again := fixtureNamed(fs, "status-put-revoke")
			again.Name = "revoke-again"
			return insertBefore(fs, "sign-all", again)
		}, "revoke-again: changes revoke-me, which status-put-revoke already changed"),
		Entry("an accepted mutation whose subjects it cannot tell", func(fs []fixture) []fixture {
			mystery := fixtureNamed(fs, "clean")
			mystery.Name, mystery.Request.Path = "mystery", "/puppet-ca/v1/mystery"
			return insertBefore(fs, "sign-all", mystery)
		}, "mystery: cannot tell which subjects it changes; teach changedSubjects"),
	)

	It("lets a refused mutation share a subject, since it changes nothing", func() {
		fs := recordedCases()
		refused := fixtureNamed(fs, "status-put-revoke")
		refused.Name, refused.Response.Status = "refused-revoke", http.StatusConflict
		Expect(snapshotViolations(insertBefore(fs, "sign-all", refused))).To(BeEmpty())
	})
})

func fixtureNamed(fs []fixture, name string) fixture {
	for _, f := range fs {
		if f.Name == name {
			return f
		}
	}
	Fail("no case named " + name)
	return fixture{}
}

// insertBefore returns fs with f inserted before the case named name.
func insertBefore(fs []fixture, name string, f fixture) []fixture {
	for i, c := range fs {
		if c.Name == name {
			return append(fs[:i:i], append([]fixture{f}, fs[i:]...)...)
		}
	}
	Fail("no case named " + name)
	return nil
}

// editFixture rewrites one fixture in dir through edit.
func editFixture(name string, edit func(map[string]any)) func(dir string) {
	return func(dir string) {
		p := filepath.Join(dir, name+".json")
		var f map[string]any
		Expect(json.Unmarshal(mustRead(p), &f)).To(Succeed())
		edit(f)
		b, err := json.Marshal(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(p, b, 0o600)).To(Succeed())
	}
}

func mustRead(p string) []byte {
	b, err := os.ReadFile(p)
	Expect(err).NotTo(HaveOccurred())
	return b
}

var _ = Describe("waitReady", func() {
	It("reports a cancelled wait as not ready, not as a container that stopped", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// Nothing listens on port 1, so the probe fails, and the cancelled
		// context is seen before docker would be asked anything.
		err := waitReady(ctx, "no-such-container", "127.0.0.1:1")
		Expect(err).To(MatchError(context.Canceled))
		Expect(err).To(MatchError(ContainSubstring("did not become ready")))
		Expect(err.Error()).NotTo(ContainSubstring("stopped"))
	})

	It("returns once the server reports itself running", func() {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/status/v1/simple" {
				_, _ = w.Write([]byte("running\n"))
			}
		}))
		DeferCleanup(srv.Close)
		// docker is unreachable, so asking after the container would fail.
		GinkgoT().Setenv("PATH", GinkgoT().TempDir())
		Expect(waitReady(context.Background(), "no-such-container", srv.Listener.Addr().String())).To(Succeed())
	})

	It("reports a container that stopped before the server was ready", func() {
		// The stub docker is the whole PATH, so this is the only docker the
		// spec can reach, and it runs nothing but shell builtins.
		bin := GinkgoT().TempDir()
		seen := filepath.Join(GinkgoT().TempDir(), "args")
		Expect(os.WriteFile(filepath.Join(bin, "docker"),
			[]byte("#!/bin/sh\necho \"$@\" > '"+seen+"'\necho false\n"), 0o700)).To(Succeed())
		GinkgoT().Setenv("PATH", bin)
		// Nothing listens on port 1, so the probe fails and docker is asked.
		err := waitReady(context.Background(), "openvox-recording", "127.0.0.1:1")
		Expect(err).To(MatchError(ContainSubstring("container stopped before it was ready")))
		Expect(err).To(MatchError(ContainSubstring("docker logs openvox-recording")))
		Expect(os.ReadFile(seen)).To(Equal([]byte("inspect -f {{.State.Running}} openvox-recording\n")))
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

	It("loads a key that is PKCS#8", func() {
		writeCA(func(k *rsa.PrivateKey) []byte {
			der, err := x509.MarshalPKCS8PrivateKey(k)
			Expect(err).NotTo(HaveOccurred())
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		})
		a, err := loadCA(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(a.key.Public()).To(Equal(a.chain[0].PublicKey))
	})

	It("refuses a key file that holds no PEM block", func() {
		writeCA(func(*rsa.PrivateKey) []byte { return []byte("not a key\n") })
		_, err := loadCA(dir)
		Expect(err).To(MatchError(ContainSubstring("holds no key")))
	})

	It("keeps an intermediate's bundle in order, and trusts the CA that issues the server's leaf", func() {
		// OpenVox Server's own layout: ca_crt.pem is the intermediate that
		// signs, then the root that issued it.
		newCA := func(cn string, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(int64(len(cn))), Subject: pkix.Name{CommonName: cn},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			}
			if parent == nil {
				parent, parentKey = tmpl, key
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
			Expect(err).NotTo(HaveOccurred())
			c, err := x509.ParseCertificate(der)
			Expect(err).NotTo(HaveOccurred())
			return c, key
		}
		root, rootKey := newCA("Test Root", nil, nil)
		inter, interKey := newCA("Test Intermediate", root, rootKey)
		bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
		Expect(os.WriteFile(filepath.Join(dir, "ca_crt.pem"), bundle, 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "ca_key.pem"), pkcs1(interKey), 0o600)).To(Succeed())

		a, err := loadCA(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(a.chain).To(HaveLen(2))
		Expect(a.chain[0].Subject.CommonName).To(Equal("Test Intermediate"), "issue signs with chain[0]")
		Expect(a.chain[1].Subject.CommonName).To(Equal("Test Root"))

		// The server presents its leaf alone, so a pool holding only the
		// root could not verify it.
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "server"}, DNSNames: []string{"server"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, inter, &leafKey.PublicKey, interKey)
		Expect(err).NotTo(HaveOccurred())
		leaf, err := x509.ParseCertificate(leafDER)
		Expect(err).NotTo(HaveOccurred())
		_, err = leaf.Verify(x509.VerifyOptions{Roots: a.roots, DNSName: "server"})
		Expect(err).NotTo(HaveOccurred())
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

	It("refuses a signed/ that is a symlink, rather than listing a host directory", func() {
		// readRegular does not see this one: the directory is listed through
		// the Root, which refuses a symlink that leaves it.
		host := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(host, "host.pem"), []byte("host"), 0o600)).To(Succeed())
		Expect(os.RemoveAll(filepath.Join(srcDir, "signed"))).To(Succeed())
		Expect(os.Symlink(host, filepath.Join(srcDir, "signed"))).To(Succeed())
		Expect(copyCadir(src, out)).NotTo(Succeed())
		Expect(filepath.Join(outDir, "cadir", "signed", "host.pem")).NotTo(BeAnExistingFile())
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
			case "/echo":
				// Hands back what do sent, as headers do records.
				w.Header().Set("X-Seen-Method", r.Method)
				w.Header().Set("X-Seen-Accept", r.Header.Get("Accept"))
				w.Header().Set("X-Seen-Content-Type", r.Header.Get("Content-Type"))
				w.Header().Set("X-Seen-If-Modified-Since", r.Header.Get("If-Modified-Since"))
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("X-Seen-Body", string(body))
				w.WriteHeader(http.StatusConflict)
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

	It("sends the request as the case describes it, and records the status", func() {
		resp, err := do(context.Background(), client, request{Method: "PUT", Path: "/echo",
			ContentType: "text/plain", Body: "not a CSR", IfModifiedSince: farFuture, Accept: "text/pson"})
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Status).To(Equal(http.StatusConflict))
		Expect(resp.Headers).To(HaveKeyWithValue("X-Seen-Method", "PUT"))
		Expect(resp.Headers).To(HaveKeyWithValue("X-Seen-Content-Type", "text/plain"))
		Expect(resp.Headers).To(HaveKeyWithValue("X-Seen-Body", "not a CSR"))
		Expect(resp.Headers).To(HaveKeyWithValue("X-Seen-If-Modified-Since", farFuture))
		Expect(resp.Headers).To(HaveKeyWithValue("X-Seen-Accept", "text/pson"))
	})

	It("asks for JSON or text when the case names no Accept", func() {
		resp, err := do(context.Background(), client, request{Method: "GET", Path: "/echo"})
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.Headers).To(HaveKeyWithValue("X-Seen-Accept", "application/json, text/plain"))
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
