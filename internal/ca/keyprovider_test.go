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

package ca_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// fakeKeyProvider is a minimal in-memory ca.KeyProvider stand-in, exercising
// the same Load/Generate contract internal/signer/openbao's Transit-backed
// KeyProvider satisfies, without needing a real OpenBao server. It tracks
// call counts so tests can assert Generate is never called when a key
// already exists (i.e. bootstrapCA doesn't clobber an existing OpenBao key) and
// Load is what a steady-state restart goes through.
type fakeKeyProvider struct {
	mu            sync.Mutex
	key           crypto.Signer
	loadErr       error // if non-nil (and not ErrKeyProviderKeyNotFound-wrapped), returned verbatim by Load
	generateCalls int
	loadCalls     int
}

func (f *fakeKeyProvider) Load(_ context.Context) (crypto.Signer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadCalls++
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	if f.key == nil {
		return nil, fmt.Errorf("fakeKeyProvider: %w", ca.ErrKeyProviderKeyNotFound)
	}
	return f.key, nil
}

func (f *fakeKeyProvider) Generate(_ context.Context, cfg ca.KeyConfig) (crypto.Signer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generateCalls++
	if f.key != nil {
		return nil, fmt.Errorf("fakeKeyProvider: key already exists")
	}
	algo := cfg.Algo
	if algo == "" {
		algo = ca.KeyAlgoRSA
	}
	switch algo {
	case ca.KeyAlgoECDSA:
		var curve elliptic.Curve
		switch cfg.Size {
		case 0, 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported ECDSA size %d", cfg.Size)
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		f.key = key
	default:
		size := cfg.Size
		if size == 0 {
			size = 2048 // small size keeps the test fast; algo choice is what's under test
		}
		key, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return nil, err
		}
		f.key = key
	}
	return f.key, nil
}

var _ = Describe("KeyProvider integration", func() {
	var (
		tmpDir string
		store  *storage.StorageService
		asCfg  ca.AutosignConfig
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-keyprovider-test")
		Expect(err).NotTo(HaveOccurred())
		store = storage.New(tmpDir)
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		asCfg = ca.AutosignConfig{Mode: "off"}
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("bootstraps a fresh CA through the key provider without writing a local key blob", func() {
		provider := &fakeKeyProvider{}
		myCA := ca.New(store, asCfg, "puppet.test")
		myCA.KeyProvider = provider

		Expect(myCA.Init(context.Background())).To(Succeed())
		Expect(provider.generateCalls).To(Equal(1))

		hasKey, err := store.HasCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(hasKey).To(BeFalse(), "no local key blob should be written when a KeyProvider is set")

		hasCert, err := store.HasCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(hasCert).To(BeTrue())

		certPEM, err := store.GetCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		keyPubDER, err := x509.MarshalPKIXPublicKey(myCA.CAKey.Public())
		Expect(err).NotTo(HaveOccurred())
		Expect(certPubDER).To(Equal(keyPubDER))
	})

	It("loads an existing key through the provider on a subsequent Init without regenerating", func() {
		provider := &fakeKeyProvider{}

		firstCA := ca.New(store, asCfg, "puppet.test")
		firstCA.KeyProvider = provider
		Expect(firstCA.Init(context.Background())).To(Succeed())
		Expect(provider.generateCalls).To(Equal(1))

		// A fresh CA instance against the same store and the same
		// (already-keyed) provider simulates a process restart.
		secondCA := ca.New(store, asCfg, "puppet.test")
		secondCA.KeyProvider = provider
		Expect(secondCA.Init(context.Background())).To(Succeed())

		Expect(provider.generateCalls).To(Equal(1), "restart must not generate a second key")
		Expect(provider.loadCalls).To(BeNumerically(">=", 1))

		certPubDER, err := x509.MarshalPKIXPublicKey(secondCA.CACert.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		keyPubDER, err := x509.MarshalPKIXPublicKey(secondCA.CAKey.Public())
		Expect(err).NotTo(HaveOccurred())
		Expect(certPubDER).To(Equal(keyPubDER))
	})

	It("surfaces a real key-provider error rather than silently re-bootstrapping", func() {
		provider := &fakeKeyProvider{loadErr: errors.New("openbao: connection refused")}
		myCA := ca.New(store, asCfg, "puppet.test")
		myCA.KeyProvider = provider

		err := myCA.Init(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("connection refused"))
		Expect(provider.generateCalls).To(Equal(0), "a real provider error must never be treated as \"no key yet\"")

		hasCert, hcErr := store.HasCACert(context.Background())
		Expect(hcErr).NotTo(HaveOccurred())
		Expect(hasCert).To(BeFalse(), "nothing should have been bootstrapped")
	})

	It("bootstraps an ECDSA CA through the key provider when configured", func() {
		provider := &fakeKeyProvider{}
		myCA := ca.New(store, asCfg, "puppet.test")
		myCA.KeyProvider = provider
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 384}

		Expect(myCA.Init(context.Background())).To(Succeed())

		pub, ok := myCA.CAKey.Public().(*ecdsa.PublicKey)
		Expect(ok).To(BeTrue(), "expected an ECDSA public key, got %T", myCA.CAKey.Public())
		Expect(pub.Curve).To(Equal(elliptic.P384()))
	})
})
