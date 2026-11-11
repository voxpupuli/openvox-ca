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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// These drive renew against a real CA behind the real routes, so what they
// assert is what an operator gets: the certificate on stdout, the key on disk,
// and the two belonging together.
var _ = Describe("renew subcommand", func() {
	var (
		ctx      = context.Background()
		myCA     *ca.CA
		store    *storage.StorageService
		srv      *httptest.Server
		requests atomic.Int32
		cfg      string
		outDir   string
	)

	parseCert := func(certPEM []byte) *x509.Certificate {
		GinkgoHelper()
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil(), "expected a PEM certificate, got %q", certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	// issueWith signs a certificate for subject over key, through the ordinary
	// request-and-sign flow.
	issueWith := func(subject string, key crypto.Signer) *x509.Certificate {
		GinkgoHelper()
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, key)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCert(certPEM)
	}

	issue := func(subject string) *x509.Certificate {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		return issueWith(subject, key)
	}

	stored := func(subject string) *x509.Certificate {
		GinkgoHelper()
		data, err := store.GetCert(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCert(data)
	}

	run := func(args ...string) (string, error) {
		return captureStdout(append([]string{"renew", "--config", cfg, "--server-url", srv.URL}, args...))
	}

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		cfg = writeTempCtlConfig("")
		outDir = GinkgoT().TempDir()

		keyPEM, crtPEM, crlPEM, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(GinkgoT().TempDir())
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, keyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, crtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, crlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())

		requests.Store(0)
		routes := api.New(myCA).Routes()
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			routes.ServeHTTP(w, r)
		}))
		DeferCleanup(srv.Close)
	})

	Describe("re-keying with a key it generates (the default)", func() {
		It("prints a certificate for the key it saved, of the current key's algorithm", func() {
			original := issue("node1.example.com")

			out, err := run("--certname", "node1.example.com", "--out-dir", outDir)
			Expect(err).NotTo(HaveOccurred())

			renewed := parseCert([]byte(out))
			Expect(renewed.SerialNumber).To(Equal(stored("node1.example.com").SerialNumber))
			Expect(renewed.PublicKey).NotTo(Equal(original.PublicKey))

			keyPath := filepath.Join(outDir, "node1.example.com_key.pem")
			fi, err := os.Stat(keyPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o600)))
			keyPEM, err := os.ReadFile(keyPath)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(keyPEM)
			Expect(block).NotTo(BeNil())
			key, err := x509.ParseECPrivateKey(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(key.Curve).To(Equal(elliptic.P384()), "the new key must follow the current one's curve")
			Expect(renewed.PublicKey).To(Equal(key.Public()), "the certificate must be for the key saved")
		})

		It("says so when it replaces a key already at the path", func() {
			issue("replaced.example.com")
			keyPath := filepath.Join(outDir, "replaced.example.com_key.pem")
			Expect(os.WriteFile(keyPath, []byte("OLD KEY"), 0o600)).To(Succeed())

			errR, errW, err := os.Pipe()
			Expect(err).NotTo(HaveOccurred())
			origErr := os.Stderr
			os.Stderr = errW
			DeferCleanup(func() { os.Stderr = origErr })
			out, runErr := run("--certname", "replaced.example.com", "--out-dir", outDir)
			os.Stderr = origErr
			Expect(errW.Close()).To(Succeed())
			stderr, err := io.ReadAll(errR)
			Expect(err).NotTo(HaveOccurred())
			Expect(runErr).NotTo(HaveOccurred())

			Expect(string(stderr)).To(ContainSubstring("replacing the key that was there"))
			keyPEM, err := os.ReadFile(keyPath)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(keyPEM)
			Expect(block).NotTo(BeNil(), "the old contents must have been replaced by a PEM key")
			key, err := x509.ParseECPrivateKey(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(parseCert([]byte(out)).PublicKey).To(Equal(key.Public()))
		})

		It("reports a renewal whose key it could not save, so the operator knows to run it again", func() {
			if os.Geteuid() == 0 {
				Skip("root ignores directory permissions")
			}
			original := issue("unsaved.example.com")
			// checkKeyPath only looks at the directory, so a read-only one
			// passes it and fails the write after the server has renewed.
			Expect(os.Chmod(outDir, 0o555)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(outDir, 0o755) })

			_, err := run("--certname", "unsaved.example.com", "--out-dir", outDir)
			Expect(err).To(MatchError(ContainSubstring("the certificate was renewed")))
			Expect(err).To(MatchError(ContainSubstring("run renew --certname unsaved.example.com again")))
			Expect(stored("unsaved.example.com").SerialNumber).NotTo(Equal(original.SerialNumber),
				"the fixture must fail the write after the server has renewed, not before")
		})

		It("writes no key when the server refuses the renewal", func() {
			issue("revoked.example.com")
			Expect(myCA.Revoke(ctx, "revoked.example.com")).To(Succeed())

			_, err := run("--certname", "revoked.example.com", "--out-dir", outDir)
			Expect(err).To(MatchError(ContainSubstring("HTTP 409")))
			Expect(filepath.Join(outDir, "revoked.example.com_key.pem")).NotTo(BeAnExistingFile())
		})

		It("refuses a name with no certificate before generating anything", func() {
			_, err := run("--certname", "nobody.example.com", "--out-dir", outDir)
			Expect(err).To(MatchError(ContainSubstring("HTTP 404")))
			Expect(filepath.Join(outDir, "nobody.example.com_key.pem")).NotTo(BeAnExistingFile())
		})

		It("refuses the certname \"ca\" without contacting the server", func() {
			_, err := run("--certname", "ca", "--out-dir", outDir)
			Expect(err).To(MatchError(ca.ErrReservedSubject))
			Expect(requests.Load()).To(BeZero())
		})

		It("refuses a symbolic link at the key path without contacting the server", func() {
			issue("linked.example.com")
			Expect(os.Symlink(filepath.Join(outDir, "elsewhere"),
				filepath.Join(outDir, "linked.example.com_key.pem"))).To(Succeed())

			_, err := run("--certname", "linked.example.com", "--out-dir", outDir)
			Expect(err).To(MatchError(ContainSubstring("symbolic link")))
			Expect(requests.Load()).To(BeZero())
		})
	})

	It("reissues over the current key with --keep-key, writing no key", func() {
		original := issue("keep.example.com")

		out, err := run("--certname", "keep.example.com", "--keep-key")
		Expect(err).NotTo(HaveOccurred())

		renewed := parseCert([]byte(out))
		Expect(renewed.PublicKey).To(Equal(original.PublicKey))
		Expect(renewed.SerialNumber).NotTo(Equal(original.SerialNumber))
		Expect(os.ReadDir(outDir)).To(BeEmpty())
	})

	It("re-keys onto the key in --csr", func() {
		issue("csr.example.com")
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr.example.com"}}, key)
		Expect(err).NotTo(HaveOccurred())
		csrPath := filepath.Join(GinkgoT().TempDir(), "req.pem")
		Expect(os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o600)).To(Succeed())

		out, err := run("--certname", "csr.example.com", "--csr", csrPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(parseCert([]byte(out)).PublicKey).To(Equal(key.Public()))
	})

	It("refuses an unreadable --csr without contacting the server", func() {
		_, err := run("--certname", "node1.example.com", "--csr", filepath.Join(outDir, "missing.pem"))
		Expect(err).To(MatchError(ContainSubstring("nothing was sent to the server")))
		Expect(requests.Load()).To(BeZero())
	})

	DescribeTable("refuses conflicting flags without contacting the server",
		func(want string, args ...string) {
			_, err := run(append([]string{"--certname", "node1.example.com"}, args...)...)
			Expect(err).To(MatchError(ContainSubstring(want)))
			Expect(requests.Load()).To(BeZero())
		},
		Entry("--keep-key with --csr", "none of the others can be", "--keep-key", "--csr", "req.pem"),
		Entry("--out-dir with --keep-key", "--out-dir applies only", "--keep-key", "--out-dir", "."),
		Entry("--out-dir with --csr", "--out-dir applies only", "--csr", "req.pem", "--out-dir", "."),
	)
})
