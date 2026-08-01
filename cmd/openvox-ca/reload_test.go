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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
)

// writeTestKeypair writes a self-signed server certificate and its key into
// dir, named after cn so successive keypairs can be told apart, and returns
// the two paths.
func writeTestKeypair(dir, cn string) (certPath, keyPath string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())

	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())

	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	Expect(os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)).To(Succeed())
	Expect(os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)).To(Succeed())
	return certPath, keyPath
}

// servedCN returns the common name of the certificate the reloader currently
// hands to new handshakes.
func servedCN(c *certReloader) string {
	cert, err := c.GetCertificate(nil)
	Expect(err).NotTo(HaveOccurred())
	Expect(cert.Leaf).NotTo(BeNil())
	return cert.Leaf.Subject.CommonName
}

var _ = Describe("Admin allow list construction", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	It("merges the configured CNs with the allow-list file", func() {
		path := filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(path, []byte("compile-1.example.com\n# a comment\n\ncompile-2.example.com\n"), 0600)).To(Succeed())

		allowList, err := buildAdminAllowList("puppet.example.com, primary.example.com", path)
		Expect(err).NotTo(HaveOccurred())
		Expect(allowList).To(Equal(map[string]bool{
			"puppet.example.com":    true,
			"primary.example.com":   true,
			"compile-1.example.com": true,
			"compile-2.example.com": true,
		}))
	})

	It("copes with neither source being configured", func() {
		allowList, err := buildAdminAllowList("", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowList).To(BeEmpty())
	})

	It("ignores blank entries in the configured list", func() {
		allowList, err := buildAdminAllowList(" , puppet.example.com ,", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowList).To(Equal(map[string]bool{"puppet.example.com": true}))
	})

	It("reports an unreadable allow-list file", func() {
		_, err := buildAdminAllowList("", filepath.Join(dir, "missing.txt"))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("TLS certificate reloading", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	It("refuses to start with an unreadable keypair", func() {
		_, err := newCertReloader(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"))
		Expect(err).To(HaveOccurred())
	})

	It("serves the keypair it loaded", func() {
		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(servedCN(reloader)).To(Equal("first.example.com"))
	})

	It("picks up a renewed certificate", func() {
		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		writeTestKeypair(dir, "renewed.example.com")
		Expect(reloader.reload()).To(Succeed())
		Expect(servedCN(reloader)).To(Equal("renewed.example.com"))
	})

	It("keeps serving the previous certificate when the new one is unusable", func() {
		// This is the half-written-file case: a reload that lands while the
		// certificate is being replaced must not leave the server with no
		// certificate at all.
		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		Expect(os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\ntruncated"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(HaveOccurred())
		Expect(servedCN(reloader)).To(Equal("first.example.com"))
	})

	It("rejects a certificate that does not match the key", func() {
		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		otherDir := GinkgoT().TempDir()
		_, otherKey := writeTestKeypair(otherDir, "other.example.com")
		keyPEM, err := os.ReadFile(otherKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(keyPath, keyPEM, 0600)).To(Succeed())

		Expect(reloader.reload()).To(HaveOccurred())
		Expect(servedCN(reloader)).To(Equal("first.example.com"))
	})
})

var _ = Describe("Configuration reloading", func() {
	var (
		dir      string
		cnFile   string
		auth     *api.AuthConfig
		reloader *configReloader
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		cnFile = filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\n"), 0600)).To(Succeed())

		allowList, err := buildAdminAllowList("puppet.example.com", cnFile)
		Expect(err).NotTo(HaveOccurred())
		auth = &api.AuthConfig{AllowList: allowList}

		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		certs, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		reloader = &configReloader{
			certs:     certs,
			auth:      auth,
			staticCNs: "puppet.example.com",
			cnFile:    cnFile,
		}
	})

	It("grants admin access to a newly listed compile server", func() {
		Expect(auth.IsAdminCN("compile-2.example.com")).To(BeFalse())

		Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\ncompile-2.example.com\n"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(Succeed())

		Expect(auth.IsAdminCN("compile-2.example.com")).To(BeTrue())
		Expect(auth.IsAdminCN("compile-1.example.com")).To(BeTrue())
		Expect(auth.IsAdminCN("puppet.example.com")).To(BeTrue(), "the configured CNs survive a reload")
	})

	It("withdraws admin access from a removed compile server", func() {
		// The security-relevant direction: a decommissioned compile server
		// must stop being an admin without waiting for a restart.
		Expect(auth.IsAdminCN("compile-1.example.com")).To(BeTrue())

		Expect(os.WriteFile(cnFile, []byte("# decommissioned\n"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(Succeed())

		Expect(auth.IsAdminCN("compile-1.example.com")).To(BeFalse())
	})

	It("rotates the TLS certificate", func() {
		writeTestKeypair(dir, "renewed.example.com")
		Expect(reloader.reload()).To(Succeed())
		Expect(servedCN(reloader.certs)).To(Equal("renewed.example.com"))
	})

	It("still applies the allow list when the certificate cannot be reloaded", func() {
		// One broken input must not block the other: the two are independent
		// and an operator fixing one should not have to fix both.
		Expect(os.WriteFile(filepath.Join(dir, "server.crt"), []byte("garbage"), 0600)).To(Succeed())
		Expect(os.WriteFile(cnFile, []byte("compile-9.example.com\n"), 0600)).To(Succeed())

		err := reloader.reload()
		Expect(err).To(HaveOccurred())
		Expect(auth.IsAdminCN("compile-9.example.com")).To(BeTrue())
	})

	It("reports every failure together", func() {
		Expect(os.WriteFile(filepath.Join(dir, "server.crt"), []byte("garbage"), 0600)).To(Succeed())
		Expect(os.Remove(cnFile)).To(Succeed())

		err := reloader.reload()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("TLS cert/key"))
		Expect(err.Error()).To(ContainSubstring("puppet-server file"))
	})

	It("keeps a failure visible in the status until a reload succeeds", func() {
		// Otherwise the next heartbeat overwrites the notice and the operator
		// is left believing the reload took effect.
		Expect(reloader.statusSuffix()).To(BeEmpty())

		Expect(os.Remove(cnFile)).To(Succeed())
		Expect(reloader.reload()).To(HaveOccurred())
		Expect(reloader.statusSuffix()).To(ContainSubstring("FAILED"))

		Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\n"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(Succeed())
		Expect(reloader.statusSuffix()).To(BeEmpty())
	})

	It("does nothing when there is nothing reloadable", func() {
		// Plain HTTP mode: no TLS keypair, no auth config.
		Expect((&configReloader{}).reload()).To(Succeed())
	})
})

var _ = Describe("Reload watcher", func() {
	var (
		dir      string
		cnFile   string
		auth     *api.AuthConfig
		reloader *configReloader
		rec      *notifyRecorder
		notifier *sdnotify.Notifier
	)

	BeforeEach(func() {
		// Claim SIGHUP before anything can send one: the default action for an
		// unhandled SIGHUP is to terminate, which would take the test binary
		// with it if the watcher had not registered yet.
		guard := make(chan os.Signal, 1)
		signal.Notify(guard, syscall.SIGHUP)
		DeferCleanup(func() { signal.Stop(guard) })

		dir = GinkgoT().TempDir()
		cnFile = filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\n"), 0600)).To(Succeed())

		allowList, err := buildAdminAllowList("", cnFile)
		Expect(err).NotTo(HaveOccurred())
		auth = &api.AuthConfig{AllowList: allowList}
		reloader = &configReloader{auth: auth, cnFile: cnFile}

		rec = startNotifyRecorder(nil)
		notifier = sdnotify.New()
		DeferCleanup(func() { Expect(notifier.Close()).To(Succeed()) })
	})

	// startWatcher runs the watcher for the duration of the spec.
	startWatcher := func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runReloadWatcher(ctx, notifier, reloader, func() string { return "serving" + reloader.statusSuffix() })
		}()
		DeferCleanup(func() {
			cancel()
			Eventually(done).Should(BeClosed())
		})
	}

	It("reloads on SIGHUP and reports the reload to the service manager", func() {
		startWatcher()

		Expect(os.WriteFile(cnFile, []byte("compile-2.example.com\n"), 0600)).To(Succeed())
		Expect(syscall.Kill(os.Getpid(), syscall.SIGHUP)).To(Succeed())

		Eventually(rec.msgs).Should(Receive(HavePrefix("RELOADING=1")))
		Eventually(rec.msgs).Should(Receive(Equal("READY=1\nSTATUS=serving\n")))
		Expect(auth.IsAdminCN("compile-2.example.com")).To(BeTrue())
		Expect(auth.IsAdminCN("compile-1.example.com")).To(BeFalse())
	})

	It("keeps serving and says so when the reload fails", func() {
		startWatcher()

		Expect(os.Remove(cnFile)).To(Succeed())
		Expect(syscall.Kill(os.Getpid(), syscall.SIGHUP)).To(Succeed())

		// READY=1 still closes out the reload -- withholding it would only
		// hang `systemctl reload` -- but the status says the reload failed.
		Eventually(rec.msgs).Should(Receive(HavePrefix("RELOADING=1")))
		Eventually(rec.msgs).Should(Receive(Equal("READY=1\nSTATUS=serving | last reload FAILED, see the logs\n")))
		Expect(auth.IsAdminCN("compile-1.example.com")).To(BeTrue(), "the previous allow list is still in force")
	})

	It("handles repeated reloads", func() {
		startWatcher()

		for _, cn := range []string{"a.example.com", "b.example.com"} {
			Expect(os.WriteFile(cnFile, []byte(cn+"\n"), 0600)).To(Succeed())
			Expect(syscall.Kill(os.Getpid(), syscall.SIGHUP)).To(Succeed())
			Eventually(func() bool { return auth.IsAdminCN(cn) }).Should(BeTrue())
		}
	})
})
