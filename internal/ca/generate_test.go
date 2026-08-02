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
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
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

var _ = Describe("CA GenerateWithOptions", func() {
	var (
		ctx    context.Context
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		ctx = context.Background()
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-genopts-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	AfterEach(func() { os.RemoveAll(tmpDir) })

	certFrom := func(r *ca.GenerateResult) *x509.Certificate {
		block, _ := pem.Decode(r.CertificatePEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	Describe("authorisation grants", func() {
		It("stamps no authorisation OID when none is requested", func() {
			result, err := myCA.GenerateWithOptions(ctx, "plain-node", ca.GenerateOptions{})
			Expect(err).NotTo(HaveOccurred())

			for _, ext := range certFrom(result).Extensions {
				Expect(ca.IsAuthOID(ext.Id)).To(BeFalse(),
					"the default path must never produce an authorisation extension")
			}
		})

		It("stamps pp_cli_auth as a non-critical UTF8String \"true\"", func() {
			result, err := myCA.GenerateWithOptions(ctx, "admin-node", ca.GenerateOptions{
				AuthGrants: []ca.AuthGrant{ca.PpCliAuth()},
			})
			Expect(err).NotTo(HaveOccurred())

			var found *pkix.Extension
			for i, ext := range certFrom(result).Extensions {
				if ext.Id.Equal(ca.OIDPpCliAuth) {
					found = &certFrom(result).Extensions[i]
					break
				}
			}
			Expect(found).NotTo(BeNil(), "pp_cli_auth must be present when granted")

			// Pin the DER, not the decoded string. encoding/asn1 will happily
			// unmarshal a PrintableString into a Go string, so a regression to
			// plain asn1.Marshal would still read back as "true" here while
			// producing a certificate that differs on the wire from Puppet's
			// and from the openssl recipe this replaces.
			Expect(found.Value).To(Equal([]byte{0x0c, 0x04, 't', 'r', 'u', 'e'}))
			Expect(found.Critical).To(BeFalse())
		})

		It("rejects a zero-value AuthGrant", func() {
			// ca.AuthGrant is exported, so a zero value is constructible from
			// another package even though its fields are not. It must be inert.
			_, err := myCA.GenerateWithOptions(ctx, "zero-grant-node", ca.GenerateOptions{
				AuthGrants: []ca.AuthGrant{{}},
			})
			Expect(err).To(MatchError(ca.ErrInvalidAuthGrant))
			Expect(store.HasCert(ctx, "zero-grant-node")).To(BeFalse())
		})

		It("rejects the same grant twice", func() {
			_, err := myCA.GenerateWithOptions(ctx, "dup-grant-node", ca.GenerateOptions{
				AuthGrants: []ca.AuthGrant{ca.PpCliAuth(), ca.PpCliAuth()},
			})
			Expect(err).To(MatchError(ca.ErrInvalidAuthGrant))
			Expect(store.HasCert(ctx, "dup-grant-node")).To(BeFalse())
		})
	})

	Describe("private key handling", func() {
		It("does not retain the key in storage by default", func() {
			_, err := myCA.GenerateWithOptions(ctx, "no-retain-node", ca.GenerateOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, statErr := os.Stat(store.PrivateKeyPath("no-retain-node"))
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"the CA has no use for this key; leaving it is a liability")
		})

		It("retains the key when asked, which is what the API path does", func() {
			_, err := myCA.GenerateWithOptions(ctx, "retain-node", ca.GenerateOptions{
				RetainPrivateKeyInStorage: true,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(store.PrivateKeyPath("retain-node")).To(BeAnExistingFile())
		})

		It("emits the key before issuing anything", func() {
			var emitted []byte
			_, err := myCA.GenerateWithOptions(ctx, "emit-node", ca.GenerateOptions{
				EmitKey: func(keyPEM []byte) error {
					// Nothing may exist yet: the whole point is that a caller
					// can put the key somewhere durable before this CA commits.
					Expect(store.HasCert(ctx, "emit-node")).To(BeFalse())
					emitted = keyPEM
					return nil
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(emitted).To(ContainSubstring("PRIVATE KEY"))
		})

		It("issues nothing when EmitKey fails", func() {
			_, err := myCA.GenerateWithOptions(ctx, "emit-fail-node", ca.GenerateOptions{
				EmitKey: func([]byte) error { return errors.New("disk full") },
			})
			Expect(err).To(MatchError(ContainSubstring("disk full")))
			Expect(store.HasCert(ctx, "emit-fail-node")).To(BeFalse(),
				"a key the caller could not keep must not leave a certificate behind")
		})
	})

	Describe("consequences of not round-tripping through a CSR", func() {
		It("leaves no pending CSR behind", func() {
			_, err := myCA.GenerateWithOptions(ctx, "no-csr-node", ca.GenerateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Expect(store.HasCSR(ctx, "no-csr-node")).To(BeFalse())
			csrs, err := store.ListCSRs(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(csrs).To(BeEmpty(), "a CSR left in storage is signable into a second certificate")
		})

		It("removes an agent's pending CSR for the same subject", func() {
			// The old implementation destroyed it as a side effect of
			// overwriting the CSR slot. Without deliberate deletion it would
			// now survive, and a later sign --all would mint a second
			// certificate for a name that already has one.
			Expect(store.SaveCSR(ctx, "pending-node", []byte("-----BEGIN CERTIFICATE REQUEST-----\nstale\n-----END CERTIFICATE REQUEST-----\n"))).To(Succeed())
			Expect(store.HasCSR(ctx, "pending-node")).To(BeTrue())

			_, err := myCA.GenerateWithOptions(ctx, "pending-node", ca.GenerateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(store.HasCSR(ctx, "pending-node")).To(BeFalse())
		})

		It("promotes the subject to a DNS SAN when no alt names are given", func() {
			result, err := myCA.GenerateWithOptions(ctx, "promoted-node", ca.GenerateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(certFrom(result).DNSNames).To(ConsistOf("promoted-node"))
		})

		It("does not promote the subject when alt names are given", func() {
			result, err := myCA.GenerateWithOptions(ctx, "san-node", ca.GenerateOptions{
				DNSAltNames: []string{"alt.example.com"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(certFrom(result).DNSNames).To(ConsistOf("alt.example.com"))
		})

		It("records the certificate in the inventory and the serial index", func() {
			// The issue this feature exists for is that the openssl workaround
			// produced a certificate the CA could not see or revoke. Prove this
			// one is tracked on both counts.
			result, err := myCA.GenerateWithOptions(ctx, "tracked-node", ca.GenerateOptions{})
			Expect(err).NotTo(HaveOccurred())
			cert := certFrom(result)

			inv, err := store.ReadInventory(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(inv)).To(ContainSubstring("/tracked-node"))

			// serialIndex is not directly observable; OCSP is where it shows.
			req, err := testutil.BuildOCSPRequest(cert, myCA.CACert)
			Expect(err).NotTo(HaveOccurred())
			respDER, err := myCA.OCSPResponse(ctx, req)
			Expect(err).NotTo(HaveOccurred())
			resp, err := ocsp.ParseResponse(respDER, myCA.CACert)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Status).To(Equal(ocsp.Good),
				"a serial missing from the index answers Unknown, not Good")

			Expect(myCA.Revoke(ctx, "tracked-node")).To(Succeed())
		})

		It("honours an explicit TTL", func() {
			// Kept well under the test CA's own hour of remaining life:
			// issueLeafLocked caps a leaf at the issuer's expiry, so a longer
			// TTL here would be measuring the cap rather than the option.
			result, err := myCA.GenerateWithOptions(ctx, "ttl-node", ca.GenerateOptions{
				TTL: 10 * time.Minute,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(certFrom(result).NotAfter).To(BeTemporally("~", time.Now().Add(10*time.Minute), time.Minute))
		})

		It("returns ErrNotInitialized when Init was not called", func() {
			bare := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
			_, err := bare.GenerateWithOptions(ctx, "uninit-node", ca.GenerateOptions{})
			Expect(err).To(MatchError(ca.ErrNotInitialized))
		})
	})
})
