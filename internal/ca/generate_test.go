// Copyright (C) 2026 Trevor Vaughan
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

package ca_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// recordingLockBackend wraps a Backend and implements storage.Locker, recording
// every lock name acquired. The locks themselves are real (a process-local
// mutex per name) so behaviour is unchanged; only the observation is added.
type recordingLockBackend struct {
	storage.Backend

	mu       sync.Mutex
	locks    map[string]*sync.Mutex
	acquired []string
}

func (b *recordingLockBackend) AcquireLock(_ context.Context, name string) (storage.Unlocker, error) {
	b.mu.Lock()
	if b.locks == nil {
		b.locks = map[string]*sync.Mutex{}
	}
	m, ok := b.locks[name]
	if !ok {
		m = &sync.Mutex{}
		b.locks[name] = m
	}
	b.acquired = append(b.acquired, name)
	b.mu.Unlock()

	m.Lock()
	return unlockFunc(m.Unlock), nil
}

func (b *recordingLockBackend) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.acquired = nil
}

func (b *recordingLockBackend) names() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.acquired...)
}

type unlockFunc func()

func (f unlockFunc) Unlock() error { f(); return nil }

var _ = Describe("CA Generate", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-generate-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(context.Background(), cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(context.Background(), "0001")).To(Succeed())
		Expect(store.TouchInventory(context.Background())).To(Succeed())
		Expect(myCA.Init(context.Background())).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("creates a valid cert and key for a new subject", func() {
		result, err := myCA.Generate(context.Background(), "gen-node", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).NotTo(BeNil())

		// Key PEM must be parseable.
		keyBlock, _ := pem.Decode(result.PrivateKeyPEM)
		Expect(keyBlock).NotTo(BeNil())
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(key.N.BitLen()).To(Equal(2048))

		// Cert PEM must be parseable and signed by the CA.
		certBlock, _ := pem.Decode(result.CertificatePEM)
		Expect(certBlock).NotTo(BeNil())
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(cert.Subject.CommonName).To(Equal("gen-node"))

		caCertBlock, _ := pem.Decode(cachedCrtPEM)
		caCert, _ := x509.ParseCertificate(caCertBlock.Bytes)
		Expect(cert.CheckSignatureFrom(caCert)).To(Succeed())

		// Private key must be on disk.
		_, err = os.Stat(store.PrivateKeyPath("gen-node"))
		Expect(err).NotTo(HaveOccurred())

		// Cert must be in the signed dir.
		Expect(store.HasCert(context.Background(), "gen-node")).To(BeTrue())
		// No pending CSR should remain after signing.
		Expect(store.HasCSR(context.Background(), "gen-node")).To(BeFalse())
	})

	It("includes DNS alt names when requested", func() {
		result, err := myCA.Generate(context.Background(), "gen-san-node", []string{"alt1.example.com", "alt2.example.com"})
		Expect(err).NotTo(HaveOccurred())

		certBlock, _ := pem.Decode(result.CertificatePEM)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(cert.DNSNames).To(ConsistOf("alt1.example.com", "alt2.example.com"))
	})

	It("returns ErrCertExists when cert already exists for subject", func() {
		_, err := myCA.Generate(context.Background(), "gen-dup", nil)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Generate(context.Background(), "gen-dup", nil)
		Expect(err).To(HaveOccurred())
		Expect(errors.Is(err, ca.ErrCertExists)).To(BeTrue())
	})

	It("returns error for invalid subject name", func() {
		_, err := myCA.Generate(context.Background(), "INVALID/Name", nil)
		Expect(err).To(HaveOccurred())
	})

	It("generated private key matches the certificate's public key", func() {
		result, err := myCA.Generate(context.Background(), "gen-key-match", nil)
		Expect(err).NotTo(HaveOccurred())

		keyBlock, _ := pem.Decode(result.PrivateKeyPEM)
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		certBlock, _ := pem.Decode(result.CertificatePEM)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		certPub, ok := cert.PublicKey.(*rsa.PublicKey)
		Expect(ok).To(BeTrue(), "cert public key should be RSA")
		Expect(key.PublicKey.N.Cmp(certPub.N)).To(Equal(0))
		Expect(key.PublicKey.E).To(Equal(certPub.E))
	})

	It("cleans up cert when private key save fails", func() {
		// Make the private key directory read-only to force SavePrivateKey failure.
		privDir := filepath.Join(tmpDir, "private")
		Expect(os.Chmod(privDir, 0555)).To(Succeed())
		defer os.Chmod(privDir, 0755) // restore for cleanup

		_, err := myCA.Generate(context.Background(), "gen-key-fail", nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to save private key"))

		// The signed cert should NOT remain on disk.
		Expect(store.HasCert(context.Background(), "gen-key-fail")).To(BeFalse(),
			"cert should be cleaned up when private key save fails")

		// No pending CSR should remain either.
		Expect(store.HasCSR(context.Background(), "gen-key-fail")).To(BeFalse())
	})

	It("private key file exists on disk at expected path", func() {
		_, err := myCA.Generate(context.Background(), "gen-disk-key", nil)
		Expect(err).NotTo(HaveOccurred())

		keyPath := filepath.Join(tmpDir, "private", "gen-disk-key_key.pem")
		data, err := os.ReadFile(keyPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(data).To(ContainSubstring("RSA PRIVATE KEY"))
	})

	Context("serialisation on the per-subject lock", func() {
		// Asserting on the lock being taken, rather than on the outcome of a
		// live race. Racing two Generate calls is not a usable regression test
		// here: on the filesystem backend WithLock degrades to a process-local
		// mutex, and even without any lock at all the two goroutines serialise
		// by luck often enough that the spec passes with the fix reverted --
		// verified, not assumed. A spec that passes either way pins nothing, so
		// pin the mechanism instead: Generate must route through the named
		// cluster lock for its subject, which is what makes it correct on the
		// backends where that lock is real.
		It("acquires the subject lock before issuing", func() {
			ctx := context.Background()

			rec := &recordingLockBackend{Backend: storage.NewFilesystemBackend(tmpDir)}
			recStore := storage.NewWithBackend(rec, filepath.Join(tmpDir, "private"))
			recCA := ca.New(recStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(recCA.Init(ctx)).To(Succeed())

			rec.reset()
			_, err := recCA.Generate(ctx, "locked-node", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(rec.names()).To(ContainElement("subject:locked-node"),
				"Generate must serialise on the same per-subject lock Sign and Clean use")
		})
	})

	Context("CRL cache freshness", func() {
		It("re-issues when the subject was revoked after this process started", func() {
			ctx := context.Background()

			// Issue, then revoke through a second CA value sharing the store --
			// standing in for another replica. This process's cachedCRL was
			// snapshotted at Init and knows nothing about it.
			_, err := myCA.Generate(ctx, "stale-crl-node", nil)
			Expect(err).NotTo(HaveOccurred())

			other := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(other.Init(ctx)).To(Succeed())
			Expect(other.Revoke(ctx, "stale-crl-node")).To(Succeed())

			// Without the re-read under the lock, evictRevokedLocked consults a
			// CRL that predates the revocation and refuses with ErrCertExists.
			_, err = myCA.Generate(ctx, "stale-crl-node", nil)
			Expect(err).NotTo(HaveOccurred(),
				"a subject revoked elsewhere must be evictable, not reported as still valid")
		})
	})
})
