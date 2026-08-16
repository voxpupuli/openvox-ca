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
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

// replicaID identifies which replica a call came from, threaded through the
// context so the barrier below can tell two callers apart from one caller
// arriving twice.
type replicaIDKey struct{}

// twoReplicaBackend stands in for a backend that coordinates across processes,
// so two StorageService values can be raced the way two replicas would be.
//
// It embeds recordingLockBackend for the per-name mutex map -- held on the
// backend rather than on either service, which is what a distributed lock looks
// like to WithLock. The filesystem backend has no Locker at all, so two services
// over one directory fall back to a mutex each and coordinate nothing; #195's
// suggested shape founders on exactly that.
//
// On top of it, Exists rendezvouses on the subject's certificate key and
// releases on whichever of two events happens: a second *distinct* replica
// reaching the same check, or a second caller blocking in AcquireLock. Those are
// the two shapes the spec has to tell apart, and making the release event-driven
// rather than timed is what makes it deterministic in both directions.
//
// The naive alternatives do not work, measured over 20 runs each. Two
// StorageServices over one filesystem directory double-issued 6 times with the
// subject lock in place and 4 times with it bypassed -- it cannot tell correct
// code from broken, and it is red on correct code. An unsynchronised race over a
// shared Locker was right 20/20 with the lock but caught its absence only 4
// times in 20, because the winner is whichever goroutine writes first.
//
// limit is a deadlock guard, not part of the mechanism: reaching it means
// neither event happened, which is a broken fixture rather than a result, so the
// spec asserts it was never hit.
type twoReplicaBackend struct {
	*recordingLockBackend

	barrierKey string
	lockName   string

	barrierMu sync.Mutex
	seen      map[int]bool
	waiting   int
	released  bool
	release   chan struct{}
	timedOut  bool
	limit     time.Duration
}

func newTwoReplicaBackend(base storage.Backend, subject string) *twoReplicaBackend {
	return &twoReplicaBackend{
		recordingLockBackend: &recordingLockBackend{Backend: base},
		barrierKey:           storage.CertKey(subject),
		lockName:             "subject:" + subject,
		seen:                 map[int]bool{},
		release:              make(chan struct{}),
		limit:                30 * time.Second,
	}
}

// signalLocked releases the barrier once either event has happened. Callers hold
// barrierMu.
//
// Both arms require somebody to be *at* the barrier already. Releasing on
// b.waiting alone would fire on the first, uncontended acquisition -- which
// happens before either replica reaches the existence check -- so the barrier
// would already be open when they got there and would never engage at all. The
// spec would still catch a missing lock, because that path takes no lock and so
// releases on the two-arrival arm, but the green path would silently decay to
// the unsynchronised race this fixture exists to replace, and degraded() could
// never fail.
func (b *twoReplicaBackend) signalLocked() {
	if b.released {
		return
	}
	if len(b.seen) >= 2 || (len(b.seen) >= 1 && b.waiting > 0) {
		b.released = true
		close(b.release)
	}
}

func (b *twoReplicaBackend) AcquireLock(ctx context.Context, name string) (storage.Unlocker, error) {
	// Only the subject lock counts. A replacement path also takes the CRL lock,
	// and letting that satisfy the barrier would release it for a reason that
	// has nothing to do with two replicas contending for one subject.
	if name != b.lockName {
		return b.recordingLockBackend.AcquireLock(ctx, name)
	}

	b.barrierMu.Lock()
	b.waiting++
	b.signalLocked()
	b.barrierMu.Unlock()

	u, err := b.recordingLockBackend.AcquireLock(ctx, name)

	b.barrierMu.Lock()
	b.waiting--
	b.barrierMu.Unlock()
	return u, err
}

func (b *twoReplicaBackend) Exists(ctx context.Context, key string) (bool, error) {
	if key != b.barrierKey {
		return b.recordingLockBackend.Exists(ctx, key)
	}

	// Ids are 1-based so the zero value means "no identity threaded", which must
	// never be mistaken for a replica: an unthreaded caller counting as replica
	// zero would let one arrival plus one stranger satisfy the two-arrival arm
	// and release a rendezvous that never happened.
	id, ok := ctx.Value(replicaIDKey{}).(int)
	Expect(ok && id > 0).To(BeTrue(),
		"a barrier-key existence check arrived without a replica identity")

	b.barrierMu.Lock()
	b.seen[id] = true
	b.signalLocked()
	wait := b.release
	b.barrierMu.Unlock()

	select {
	case <-wait:
	case <-time.After(b.limit):
		b.barrierMu.Lock()
		b.timedOut = true
		b.barrierMu.Unlock()
	}
	return b.recordingLockBackend.Exists(ctx, key)
}

func (b *twoReplicaBackend) degraded() bool {
	b.barrierMu.Lock()
	defer b.barrierMu.Unlock()
	return b.timedOut
}

// crlWriteFailBackend fails only the CRL write, so a spec can drive the revoke
// phase of a replacement into failure while everything else keeps working.
// Chmod cannot do this job: the CRL is rewritten by a temp file plus rename in
// the cadir, so making it unwritable means making the whole directory
// unwritable, which fails the certificate write too and would satisfy the
// assertions for the wrong reason.
type crlWriteFailBackend struct {
	storage.Backend
	err error
}

func (b *crlWriteFailBackend) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if key == storage.KeyCRL {
		return b.err
	}
	return b.Backend.Put(ctx, key, data, kind)
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

		It("lets only one of two replicas issue for the same subject", func() {
			// The outcome #195 asks for, rather than the mechanism the spec
			// above pins: two independent CA values over one coordinating
			// backend, racing the same subject, and exactly one certificate
			// comes out of it.
			//
			// #195 names a technique -- two StorageService values over one
			// filesystem directory -- which does not work; twoReplicaBackend's
			// doc comment records what was measured and why a shared Locker
			// plus an event-driven rendezvous replaces it.
			ctx := context.Background()

			two := newTwoReplicaBackend(storage.NewFilesystemBackend(tmpDir), "replica-node")
			priv := filepath.Join(tmpDir, "private")
			replica := func() *ca.CA {
				c := ca.New(storage.NewWithBackend(two, priv), ca.AutosignConfig{Mode: "off"}, "puppet.test")
				Expect(c.Init(ctx)).To(Succeed())
				return c
			}
			first, second := replica(), replica()

			var wg sync.WaitGroup
			errs := make([]error, 2)
			wg.Add(2)
			for i, c := range []*ca.CA{first, second} {
				go func(i int, c *ca.CA) {
					defer GinkgoRecover()
					defer wg.Done()
					// The replica id is what lets the barrier tell two callers
					// apart from one caller reaching the check twice --
					// evictRevokedLocked consults it again after Generate does.
					own := context.WithValue(ctx, replicaIDKey{}, i+1)
					_, errs[i] = c.GenerateWithOptions(own, "replica-node", ca.GenerateOptions{})
				}(i, c)
			}
			wg.Wait()

			Expect(two.degraded()).To(BeFalse(),
				"the barrier timed out, so neither replica met the other and this run proved nothing")

			var issued int
			for _, err := range errs {
				if err == nil {
					issued++
					continue
				}
				Expect(err).To(MatchError(ca.ErrCertExists),
					"the replica that loses the lock must see the winner's certificate, not some other failure")
			}
			Expect(issued).To(Equal(1),
				"two replicas issuing for one subject is the whole defect: %v", errs)

			// The error count is a proxy. The inventory is the durable record,
			// and a second row is what "issued twice" would actually mean to an
			// operator -- a serial consumed and a certificate the CA lists.
			inv, err := storage.NewWithBackend(two, priv).ReadInventory(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Count(string(inv), "/replica-node")).To(Equal(1),
				"exactly one inventory row for the subject:\n%s", inv)

			Expect(two.names()).To(ContainElement("subject:replica-node"),
				"and it was the per-subject lock that did it")
		})

		It("takes the subject lock before the CRL lock when replacing", func() {
			// The documented ordering is subject-lock -> CRL-lock -> c.mu, and
			// every lockNameCRL acquisition in this package follows it. Taking
			// them the other way round would deadlock against RefreshCRLIfDue.
			// The concurrent smoke test alongside this cannot pin the ordering
			// -- it has no barrier forcing the hazardous interleaving -- so pin
			// the sequence directly.
			ctx := context.Background()

			rec := &recordingLockBackend{Backend: storage.NewFilesystemBackend(tmpDir)}
			recStore := storage.NewWithBackend(rec, filepath.Join(tmpDir, "private"))
			recCA := ca.New(recStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(recCA.Init(ctx)).To(Succeed())

			_, err := recCA.GenerateWithOptions(ctx, "order-node", ca.GenerateOptions{})
			Expect(err).NotTo(HaveOccurred())

			rec.reset()
			_, err = recCA.GenerateWithOptions(ctx, "order-node", ca.GenerateOptions{
				ReplaceExisting: true,
			})
			Expect(err).NotTo(HaveOccurred())

			names := rec.names()
			subjectAt := -1
			crlAt := -1
			for i, n := range names {
				if n == "subject:order-node" && subjectAt < 0 {
					subjectAt = i
				}
				if n == "crl" && crlAt < 0 {
					crlAt = i
				}
			}
			Expect(subjectAt).To(BeNumerically(">=", 0), "the subject lock must be taken: %v", names)
			Expect(crlAt).To(BeNumerically(">=", 0), "the CRL lock must be taken to revoke: %v", names)
			Expect(subjectAt).To(BeNumerically("<", crlAt),
				"subject lock must precede the CRL lock, not follow it: %v", names)
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

	Describe("DNS alt-name validation", func() {
		// Reached by POST /generate/{subject}?dns=..., so these are the bounds
		// on attacker-influenced input. Only the accepting paths were covered.
		DescribeTable("rejects malformed or oversized alt names, issuing nothing",
			func(names []string, wants string) {
				_, err := myCA.GenerateWithOptions(ctx, "dns-node", ca.GenerateOptions{
					DNSAltNames: names,
				})
				Expect(err).To(MatchError(ContainSubstring(wants)))
				Expect(store.HasCert(ctx, "dns-node")).To(BeFalse())
			},
			Entry("not a hostname", []string{"not a hostname"}, "invalid DNS alt name"),
			Entry("trailing hyphen", []string{"bad-.example.com"}, "invalid DNS alt name"),
			Entry("over the length limit", []string{strings.Repeat("a", 254)}, "exceeds maximum length"),
			Entry("too many", make([]string, 101), "too many DNS alt names"),
		)
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

var _ = Describe("CA GenerateWithOptions replacement", func() {
	var (
		ctx    context.Context
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		ctx = context.Background()
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-replace-test")
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

	// Compared as hex strings: big.Int has unexported fields, so gomega's
	// structural matchers cannot compare them.
	serialOf := func(r *ca.GenerateResult) string {
		block, _ := pem.Decode(r.CertificatePEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return fmt.Sprintf("%X", cert.SerialNumber)
	}

	revokedSerials := func() []string {
		crlPEM, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(crlPEM)
		Expect(block).NotTo(BeNil())
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		out := make([]string, 0, len(crl.RevokedCertificateEntries))
		for _, e := range crl.RevokedCertificateEntries {
			out = append(out, fmt.Sprintf("%X", e.SerialNumber))
		}
		return out
	}

	It("revokes the old certificate and issues a new one", func() {
		first, err := myCA.GenerateWithOptions(ctx, "replace-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())
		oldSerial := serialOf(first)

		second, err := myCA.GenerateWithOptions(ctx, "replace-node", ca.GenerateOptions{
			ReplaceExisting: true,
		})
		Expect(err).NotTo(HaveOccurred())
		newSerial := serialOf(second)

		Expect(newSerial).NotTo(Equal(oldSerial))
		Expect(revokedSerials()).To(ContainElement(oldSerial))
		Expect(revokedSerials()).NotTo(ContainElement(newSerial))
		Expect(store.HasCert(ctx, "replace-node")).To(BeTrue())

		// Replaced is what the command keys its "revoked the previous
		// certificate" advisory off, and nothing else observes it. Without this
		// the field could report anything and every other spec would pass.
		Expect(second.Replaced).To(BeTrue())
		Expect(first.Replaced).To(BeFalse(), "an ordinary issuance retired nothing")
	})

	It("records the forced revocation in the log", func() {
		// SECURITY: docs/operator-cli.md publishes this message and its
		// attributes as a line to alert on, and revokeSerialLocked itself
		// records only at Debug -- so without this line the only trace of an
		// operator-forced revocation at default level is the CRL. Captured at
		// Info rather than Warn: the sibling grant spec installs a Warn handler
		// and would not see this one at all. NIST 800-53: AU-2.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		defer slog.SetDefault(orig)

		first, err := myCA.GenerateWithOptions(ctx, "logged-replace-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())
		oldSerial := serialOf(first)
		buf.Reset()

		_, err = myCA.GenerateWithOptions(ctx, "logged-replace-node", ca.GenerateOptions{
			ReplaceExisting: true,
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(buf.String()).To(ContainSubstring("Revoked a certificate to make room for its replacement"))
		Expect(buf.String()).To(ContainSubstring("subject=logged-replace-node"))
		Expect(buf.String()).To(ContainSubstring("serial="+oldSerial),
			"the retired serial is what an operator needs to correlate with the CRL")
	})

	It("is not an error when there is nothing to replace", func() {
		// Unlike Clean, which reports ErrNotFound. This command's job is to end
		// with a certificate, so being asked to replace one that does not exist
		// is a no-op, not a failure -- which keeps --force usable in scripts.
		result, err := myCA.GenerateWithOptions(ctx, "fresh-node", ca.GenerateOptions{
			ReplaceExisting: true,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(store.HasCert(ctx, "fresh-node")).To(BeTrue())

		// Replaced reports what was retired, not what was asked for. Deriving
		// it from opts.ReplaceExisting would make the command tell the operator
		// it revoked a certificate that never existed.
		Expect(result.Replaced).To(BeFalse())
	})

	It("revokes the stored certificate's serial, not the inventory's latest", func() {
		// The inventory's newest row for a subject and the certificate actually
		// in storage can diverge. revokeLocked resolves the former, which is
		// why this path uses the stored certificate instead: putting the wrong
		// serial on the CRL cannot be undone.
		first, err := myCA.GenerateWithOptions(ctx, "diverged-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())
		storedSerial := serialOf(first)

		// Append a newer inventory row for the same subject without touching
		// the stored certificate.
		decoyInt := new(big.Int)
		_, ok := decoyInt.SetString(storedSerial, 16)
		Expect(ok).To(BeTrue())
		decoy := fmt.Sprintf("%X", decoyInt.Add(decoyInt, big.NewInt(1)))
		line := storage.FormatInventoryLine(decoy,
			time.Now().Add(-time.Hour), time.Now().Add(time.Hour), "diverged-node")
		Expect(store.AppendInventory(ctx, line)).To(Succeed())

		_, err = myCA.GenerateWithOptions(ctx, "diverged-node", ca.GenerateOptions{
			ReplaceExisting: true,
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(revokedSerials()).To(ContainElement(storedSerial),
			"the certificate actually in storage is what was retired")
		Expect(revokedSerials()).NotTo(ContainElement(decoy),
			"the inventory's newest row is not the credential being replaced")
	})

	It("aborts without revoking when the stored certificate cannot be parsed", func() {
		_, err := myCA.GenerateWithOptions(ctx, "corrupt-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())
		before := len(revokedSerials())

		Expect(store.SaveCert(ctx, "corrupt-node", []byte("not a certificate"))).To(Succeed())

		_, err = myCA.GenerateWithOptions(ctx, "corrupt-node", ca.GenerateOptions{
			ReplaceExisting: true,
		})
		Expect(err).To(HaveOccurred())
		// Not ErrCertExists: that error tells the operator to pass --force,
		// which is exactly what they did. A dead-end loop is worse than a
		// blunt message.
		Expect(err).NotTo(MatchError(ca.ErrCertExists))
		Expect(err.Error()).To(ContainSubstring("openvox-ca-ctl clean"))
		Expect(revokedSerials()).To(HaveLen(before), "nothing may be revoked when the read fails")
	})

	It("issues nothing when the revoke fails, rather than leaving two live certificates", func() {
		// The fail-closed half of the replacement path, and the one the two
		// neighbouring specs bracket without entering: one fails in the read
		// phase and one in the issue phase, so nothing makes revokeSerialLocked
		// itself fail. Clean logs and proceeds here, deliberately, because the
		// certificate is going away either way -- on a replacement the same
		// choice would leave the subject with two live certificates. Downgrade
		// this return to a slog.Warn and only this spec notices.
		failStore := storage.NewWithBackend(
			&crlWriteFailBackend{
				Backend: storage.NewFilesystemBackend(tmpDir),
				err:     errors.New("crl storage is offline"),
			},
			filepath.Join(tmpDir, "private"))
		failCA := ca.New(failStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(failCA.Init(ctx)).To(Succeed())

		first, err := failCA.GenerateWithOptions(ctx, "revoke-fail-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())
		firstSerial := serialOf(first)

		_, err = failCA.GenerateWithOptions(ctx, "revoke-fail-node", ca.GenerateOptions{
			ReplaceExisting: true,
		})
		Expect(err).To(MatchError(ContainSubstring("could not revoke the existing certificate")))
		Expect(err).To(MatchError(ContainSubstring("no replacement was issued")))

		// The original must still be the one in storage: a second certificate
		// for the subject is exactly what failing open would produce.
		stored, err := failStore.GetCert(ctx, "revoke-fail-node")
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(stored)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(fmt.Sprintf("%X", cert.SerialNumber)).To(Equal(firstSerial))
	})

	It("aborts without revoking when the stored certificate cannot be read", func() {
		// The sibling above covers an unreadable *value*; this covers an
		// unreadable *file*, which is the branch the whole function is
		// justified by: answering "no certificate here" to a transient read
		// error would skip the revoke and issue a second live certificate for
		// the subject, the one outcome --force must never produce. The two
		// branches also report differently, so the sibling's assertion on
		// "openvox-ca-ctl clean" would not hold here.
		if os.Geteuid() == 0 {
			Skip("root ignores file permissions")
		}
		first, err := myCA.GenerateWithOptions(ctx, "unreadable-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())
		storedSerial := serialOf(first)
		before := len(revokedSerials())

		certFile := filepath.Join(tmpDir, "signed", "unreadable-node.pem")
		Expect(certFile).To(BeAnExistingFile())
		Expect(os.Chmod(certFile, 0o000)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(certFile, 0o644) })

		_, err = myCA.GenerateWithOptions(ctx, "unreadable-node", ca.GenerateOptions{
			ReplaceExisting: true,
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("reading the stored certificate"))
		Expect(revokedSerials()).To(HaveLen(before),
			"a read failure must not put a serial on the CRL")
		Expect(revokedSerials()).NotTo(ContainElement(storedSerial))
	})

	It("records an authorisation grant in the log, and nothing without one", func() {
		// SECURITY: the inventory line carries no record of the grant, so this
		// message is the only durable trace distinguishing an administrator
		// credential from a node one. NIST 800-53: AU-2.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		_, err := myCA.GenerateWithOptions(ctx, "audited-node", ca.GenerateOptions{
			AuthGrants: []ca.AuthGrant{ca.PpCliAuth()},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(buf.String()).To(ContainSubstring("audited-node"))
		Expect(buf.String()).To(ContainSubstring("pp_cli_auth=true"))

		buf.Reset()
		_, err = myCA.GenerateWithOptions(ctx, "unaudited-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(buf.String()).NotTo(ContainSubstring("authorisation extension"),
			"an ordinary node certificate must not look like a grant in the log")
	})

	It("records the grant even when a later step fails and rolls the certificate back", func() {
		// SECURITY: the audit line must not be contingent on the rest of the
		// call succeeding. By the time issueLeafLocked returns, the grant is
		// signed into a certificate and has consumed a serial and an inventory
		// row; the SavePrivateKey rollback below deletes the certificate blob
		// but neither of those, so a grant logged at the end of the closure
		// would leave a privileged issuance with no trace outside the DER.
		// Move the AuthGrants loop back below SavePrivateKey and this is the
		// only spec that notices. NIST 800-53: AU-2.
		privDir := filepath.Join(tmpDir, "private")
		Expect(os.Chmod(privDir, 0o555)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(privDir, 0o755) })
		if os.Geteuid() == 0 {
			Skip("root ignores directory permissions")
		}

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		_, err := myCA.GenerateWithOptions(ctx, "rolled-back-node", ca.GenerateOptions{
			AuthGrants:                []ca.AuthGrant{ca.PpCliAuth()},
			RetainPrivateKeyInStorage: true,
		})
		Expect(err).To(HaveOccurred())
		Expect(store.HasCert(ctx, "rolled-back-node")).To(BeFalse(),
			"the rollback is what makes this the awkward case worth pinning")

		Expect(buf.String()).To(ContainSubstring("rolled-back-node"))
		Expect(buf.String()).To(ContainSubstring("pp_cli_auth=true"))
	})

	It("emits the key before the revoke, not after it", func() {
		// This ordering is the whole reason --force requires --key-out. Move
		// the EmitKey call inside the lock -- anywhere after the revoke phase
		// -- and every other spec still passes, while the outcome the design
		// exists to prevent becomes reachable: the old certificate on the CRL,
		// no replacement, and no key. Only a replacement with a failing EmitKey
		// can tell the two orderings apart.
		first, err := myCA.GenerateWithOptions(ctx, "emit-order-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())
		oldSerial := serialOf(first)

		_, err = myCA.GenerateWithOptions(ctx, "emit-order-node", ca.GenerateOptions{
			ReplaceExisting: true,
			EmitKey:         func([]byte) error { return errors.New("no room on device") },
		})
		Expect(err).To(MatchError(ContainSubstring("no room on device")))

		Expect(revokedSerials()).NotTo(ContainElement(oldSerial),
			"a key the caller could not keep must not cost them the certificate they still have")
		Expect(store.HasCert(ctx, "emit-order-node")).To(BeTrue(),
			"the existing certificate must survive a failure that happened before the revoke")
	})

	It("reports the revoked-but-not-replaced state when issuance fails after the revoke", func() {
		// The one irreversible outcome this design cannot rule out: the old
		// certificate is on the CRL, which cannot be undone, and no replacement
		// exists. Surfacing the bare error would be actively misleading here --
		// evictRevokedLocked answers ErrCertExists, whose remedy text tells the
		// operator to pass --force, which is what they just did.
		_, err := myCA.GenerateWithOptions(ctx, "post-revoke-fail", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Fail the issue phase after the revoke phase has committed: the
		// private directory is unwritable, so SavePrivateKey fails.
		privDir := filepath.Join(tmpDir, "private")
		Expect(os.Chmod(privDir, 0o555)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(privDir, 0o755) })
		if os.Geteuid() == 0 {
			Skip("root ignores directory permissions")
		}

		_, err = myCA.GenerateWithOptions(ctx, "post-revoke-fail", ca.GenerateOptions{
			ReplaceExisting:           true,
			RetainPrivateKeyInStorage: true,
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("was revoked, but no replacement was issued"))
		Expect(err.Error()).To(ContainSubstring("cannot be undone"))
		Expect(err).NotTo(MatchError(ca.ErrCertExists),
			"a bare ErrCertExists here sends the operator round the --force loop again")
	})

	It("does not deadlock against a concurrent CRL refresh", func() {
		// The replacement path nests the CRL lock inside the subject lock.
		// c.mu is non-reentrant and every other lockNameCRL acquisition takes
		// the distributed lock first, so holding c.mu across the nested
		// WithLock would invert the ordering against RefreshCRLIfDue and wedge
		// the process.
		_, err := myCA.GenerateWithOptions(ctx, "deadlock-node", ca.GenerateOptions{})
		Expect(err).NotTo(HaveOccurred())

		done := make(chan error, 2)
		go func() {
			defer GinkgoRecover()
			_, err := myCA.RefreshCRLIfDue(ctx, 100*365*24*time.Hour) // always due
			done <- err
		}()
		go func() {
			defer GinkgoRecover()
			_, err := myCA.GenerateWithOptions(ctx, "deadlock-node", ca.GenerateOptions{
				ReplaceExisting: true,
			})
			done <- err
		}()

		for range 2 {
			select {
			case err := <-done:
				Expect(err).NotTo(HaveOccurred())
			case <-time.After(30 * time.Second):
				Fail("deadlock: the replacement path and a CRL refresh blocked each other")
			}
		}
	})
})
