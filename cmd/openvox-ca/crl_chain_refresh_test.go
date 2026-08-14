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
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The pass this job runs, exercised directly. Whether it is *scheduled*, and
// under which gate, is background_jobs_test.go's half — separating the two is
// what makes "the job exists but nothing starts it" a spec failure rather than
// something both halves assume the other covers.
var _ = Describe("refreshCRLChainOnce", func() {
	var (
		ctx      context.Context
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		upstream, upsCRL = chainUpstreamCA("Upstream Root CA")

		// Trust the upstream so its CRL verifies against the stored bundle.
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...), upstreamPEM...))).To(Succeed())
	})

	It("publishes the file's CRLs when the pass runs", func() {
		path := filepath.Join(GinkgoT().TempDir(), "upstream.pem")
		Expect(os.WriteFile(path, upsCRL, 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		refreshCRLChainOnce(ctx, myCA, path)

		blob, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(countCRLPEMBlocks(blob)).To(Equal(2),
			"the published blob must carry the upstream CRL beside our own")
	})

	It("swallows a failing pass so the caller can keep ticking", func() {
		// The pass returns nothing, so the only contract it has with its caller
		// is that a bad file neither panics nor propagates. The loop's own
		// survival is pinned separately, below, against the ticker.
		path := filepath.Join(GinkgoT().TempDir(), "corrupt.pem")
		Expect(os.WriteFile(path, []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n"), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		Expect(func() { refreshCRLChainOnce(ctx, myCA, path) }).NotTo(Panic())
		Expect(myCA.CRLChainFailures()).To(BeNumerically("==", 1),
			"a refusal that is not counted is a refusal nothing can alert on")
	})
})

// The loop, as distinct from the pass. Each of the three sibling jobs has this
// spec; without it the immediate pass, the ticker re-arm and the return on
// cancellation are all unexercised, and main.go starts these as bare
// `go job.run(ctx)`, so a loop that never returns leaks a goroutine at shutdown.
var _ = Describe("runCRLChainRefresher", func() {
	var (
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsCRL   []byte
		path     string
	)

	BeforeEach(func() {
		ctx := context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		upstream, upsCRL = chainUpstreamCA("Loop Upstream CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})...))).To(Succeed())

		path = filepath.Join(GinkgoT().TempDir(), "upstream.pem")
		myCA.CRLChainFile = path
	})

	It("publishes before its first tick, and returns on cancellation", func() {
		// The immediate pass is load-bearing rather than a nicety: nothing else
		// publishes the file's contents, so without it a Secret that arrives
		// late is not picked up for a whole interval. The hour-long interval
		// here means only the immediate pass can satisfy the assertion.
		Expect(os.WriteFile(path, upsCRL, 0o644)).To(Succeed())
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan struct{})
		go func() {
			runCRLChainRefresher(ctx, myCA, path, time.Hour)
			close(done)
		}()

		Eventually(func() int {
			blob, err := store.GetCRL(context.Background())
			if err != nil {
				return 0
			}
			return countCRLPEMBlocks(blob)
		}).WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			Should(Equal(2), "the immediate pass did not publish the upstream CRL within 2s")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runCRLChainRefresher did not return after context cancellation")
	})

	It("keeps ticking after a pass that failed", func() {
		// The ticker must re-arm across a failure: a chain file that is
		// unreadable for one pass -- mid-rewrite, or a mount that has not landed
		// -- must not stop the job for the process lifetime, which is exactly
		// what an unrecovered pass would do.
		Expect(os.WriteFile(path,
			[]byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n"), 0o644)).To(Succeed())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		done := make(chan struct{})
		go func() {
			runCRLChainRefresher(ctx, myCA, path, 10*time.Millisecond)
			close(done)
		}()

		Eventually(myCA.CRLChainFailures).WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			Should(BeNumerically(">=", 3), "the ticker stopped after the first failing pass")

		// And it recovers: a good file published on a later tick, by the same
		// loop that has been failing.
		Expect(os.WriteFile(path, upsCRL, 0o644)).To(Succeed())
		Eventually(func() int {
			blob, err := store.GetCRL(context.Background())
			if err != nil {
				return 0
			}
			return countCRLPEMBlocks(blob)
		}).WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			Should(Equal(2), "the loop never recovered once the file became readable")

		cancel()
		Eventually(done).WithTimeout(2 * time.Second).Should(BeClosed())
	})
})

// chainUpstreamCA mints a self-signed CA and an empty CRL from it.
func chainUpstreamCA(cn string) (*x509.Certificate, []byte) {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	skid := sha1.Sum(pubDER)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skid[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())

	now := time.Now().UTC()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(7), ThisUpdate: now, NextUpdate: now.Add(30 * 24 * time.Hour),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return cert, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
}

// countCRLPEMBlocks counts X509 CRL blocks in a PEM blob.
func countCRLPEMBlocks(blob []byte) int {
	n, rest := 0, blob
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return n
		}
		if b.Type == "X509 CRL" {
			n++
		}
	}
}
