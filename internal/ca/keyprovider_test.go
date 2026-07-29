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
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

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

	// DR scenario: the CA certificate (and the rest of the storage backend) is
	// lost and restored empty, but the Transit key persists in OpenBao. Init
	// then finds no cert but a keyed provider, reaches bootstrapCA, and calls
	// Generate on an already-keyed provider. This pins that a provider which
	// refuses Generate-on-existing-key surfaces a controlled error rather than
	// the CA silently rotating/overwriting the live CA key.
	It("does not silently rotate the provider key when the cert is absent but the key exists", func() {
		provider := &fakeKeyProvider{}

		firstCA := ca.New(store, asCfg, "puppet.test")
		firstCA.KeyProvider = provider
		Expect(firstCA.Init(context.Background())).To(Succeed())
		Expect(provider.generateCalls).To(Equal(1))
		originalKey := provider.key
		Expect(originalKey).NotTo(BeNil())

		// A fresh, empty store (storage wiped/restored) against the same,
		// still-keyed provider.
		wipedDir, err := os.MkdirTemp("", "openvox-ca-keyprovider-wiped")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(wipedDir)
		wipedStore := storage.New(wipedDir)
		Expect(wipedStore.EnsureDirs(context.Background())).To(Succeed())

		secondCA := ca.New(wipedStore, asCfg, "puppet.test")
		secondCA.KeyProvider = provider

		err = secondCA.Init(context.Background())
		Expect(err).To(HaveOccurred(), "Init must not silently overwrite an existing provider key")
		Expect(err.Error()).To(ContainSubstring("refusing to bootstrap"),
			"Init should fail closed with guidance, not attempt to regenerate")
		// The CA core must fail closed at the call site: Generate is never
		// reached (generateCalls stays at its post-bootstrap value of 1), so the
		// safety no longer rests solely on the provider refusing.
		Expect(provider.generateCalls).To(Equal(1), "Generate must not be called on the already-keyed provider")
		Expect(provider.key).To(BeIdenticalTo(originalKey), "the provider key must not have been rotated")

		hasCert, hcErr := wipedStore.HasCACert(context.Background())
		Expect(hcErr).NotTo(HaveOccurred())
		Expect(hasCert).To(BeFalse(), "no CA certificate should have been bootstrapped over the existing key")
	})

	// The same guarantee for the default configuration, where the key is a
	// local PEM blob and no provider is involved at all. This is the state
	// "openvox-ca csr --create-key" leaves behind while the parent CA signs:
	// bootstrapping over it destroys the key the outstanding request is bound
	// to, and the signed chain that comes back can then never be imported.
	It("does not bootstrap over a local key left by an outstanding signing request", func() {
		ctx := context.Background()
		localStore := storage.New(GinkgoT().TempDir())

		pending := ca.New(localStore, asCfg, "puppet.test")
		pending.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		csrPEM, err := pending.BuildCSR(ctx, "puppet.test", true)
		Expect(err).NotTo(HaveOccurred())
		Expect(csrPEM).NotTo(BeEmpty())

		before, err := localStore.GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())

		// A server start in the window before the signed chain comes back.
		restarted := ca.New(localStore, asCfg, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		err = restarted.Init(ctx)
		Expect(err).To(HaveOccurred(), "Init must not bootstrap over a key with no certificate")
		Expect(err).To(MatchError(ContainSubstring("import-ca-cert")),
			"the error should name the command that resolves the state")

		after, err := localStore.GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "the key bound to the outstanding request must be untouched")

		hasCert, err := localStore.HasCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(hasCert).To(BeFalse())
	})

	It("rejects a CA configured with both ExternalSigner and KeyProvider", func() {
		externalKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		myCA := ca.New(store, asCfg, "puppet.test")
		myCA.KeyProvider = &fakeKeyProvider{}
		myCA.ExternalSigner = externalKey

		err = myCA.Init(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("mutually exclusive"))

		hasCert, hcErr := store.HasCACert(context.Background())
		Expect(hcErr).NotTo(HaveOccurred())
		Expect(hasCert).To(BeFalse(), "nothing should have been bootstrapped for a misconfigured CA")
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

	It("detects a key-provider key that no longer matches the stored CA certificate (RSA)", func() {
		provider := &fakeKeyProvider{}
		firstCA := ca.New(store, asCfg, "puppet.test")
		firstCA.KeyProvider = provider
		Expect(firstCA.Init(context.Background())).To(Succeed())

		// Simulate the provider's key having been rotated out-of-band (e.g.
		// `bao write -f transit/keys/<name>/rotate` run directly against
		// OpenBao): a fresh key is now what Load returns, but the CA
		// certificate on record was issued against the old one.
		rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		rotatedProvider := &fakeKeyProvider{key: rotatedKey}

		secondCA := ca.New(store, asCfg, "puppet.test")
		secondCA.KeyProvider = rotatedProvider

		err = secondCA.Init(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not match"))
	})

	It("detects a key-provider key that no longer matches the stored CA certificate (ECDSA)", func() {
		provider := &fakeKeyProvider{}
		firstCA := ca.New(store, asCfg, "puppet.test")
		firstCA.KeyProvider = provider
		firstCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(firstCA.Init(context.Background())).To(Succeed())

		rotatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		rotatedProvider := &fakeKeyProvider{key: rotatedKey}

		secondCA := ca.New(store, asCfg, "puppet.test")
		secondCA.KeyProvider = rotatedProvider

		err = secondCA.Init(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not match"))
	})
})

// The provider-backed path is what this whole feature exists for: docs
// document the sub-CA round trip under an OpenBao Transit key, and every other
// spec in the suite runs with KeyProvider nil, so none of it was exercised.
var _ = Describe("BuildCSR and LoadOrCreateCAKey against a key provider", func() {
	var (
		ctx      context.Context
		store    *storage.StorageService
		asCfg    ca.AutosignConfig
		provider *fakeKeyProvider
		subject  *ca.CA
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		asCfg = ca.AutosignConfig{Mode: "off"}
		provider = &fakeKeyProvider{}
		subject = ca.New(store, asCfg, "puppet.test")
		subject.KeyProvider = provider
		subject.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	})

	// noLocalKey asserts the provider path never writes a key blob to storage.
	// That is the property the whole custody model rests on: if the CSR path
	// spilled a local copy, the key would exist in two places and "the key
	// never leaves the vault" would be false.
	noLocalKey := func() {
		GinkgoHelper()
		hasKey, err := store.HasCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(hasKey).To(BeFalse(), "a provider-held key must never be written to storage")
	}

	It("refuses to invent a key when the provider slot is empty and --create-key was not passed", func() {
		_, err := subject.BuildCSR(ctx, "puppet.test", false)
		Expect(err).To(MatchError(ca.ErrKeyProviderKeyNotFound))
		Expect(provider.generateCalls).To(Equal(0), "no key may be created without --create-key")
		noLocalKey()
	})

	It("creates the key at the provider when --create-key is passed", func() {
		csrPEM, err := subject.BuildCSR(ctx, "puppet.test", true)
		Expect(err).NotTo(HaveOccurred())
		Expect(provider.generateCalls).To(Equal(1))

		block, _ := pem.Decode(csrPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("CERTIFICATE REQUEST"))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(csr.CheckSignature()).To(Succeed())

		// The request must be bound to the provider's key, not to some other
		// key generated alongside it — otherwise the parent signs a
		// certificate this CA cannot use.
		wantDER, err := x509.MarshalPKIXPublicKey(provider.key.Public())
		Expect(err).NotTo(HaveOccurred())
		gotDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(gotDER).To(Equal(wantDER))
		noLocalKey()
	})

	It("does not rotate a key the provider already holds, even with --create-key", func() {
		existing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		provider.key = existing

		csrPEM, err := subject.BuildCSR(ctx, "puppet.test", true)
		Expect(err).NotTo(HaveOccurred())
		Expect(provider.generateCalls).To(Equal(0), "an established CA key must never be replaced")

		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		wantDER, err := x509.MarshalPKIXPublicKey(existing.Public())
		Expect(err).NotTo(HaveOccurred())
		gotDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(gotDER).To(Equal(wantDER))
	})

	// The distinction that matters most: "the vault says there is no key" and
	// "the vault could not be reached" must not be conflated. Treating the
	// second as the first would mint a brand new CA key on a network blip,
	// while the real one sits in the vault with certificates issued under it.
	It("propagates a provider failure instead of treating it as an empty slot", func() {
		provider.loadErr = errors.New("openbao: connection refused")

		_, err := subject.BuildCSR(ctx, "puppet.test", true)
		Expect(err).To(MatchError(ContainSubstring("connection refused")))
		Expect(err).NotTo(MatchError(ca.ErrKeyProviderKeyNotFound))
		Expect(provider.generateCalls).To(Equal(0),
			"an unreachable provider must never cause a second CA key to be created")
		noLocalKey()
	})

	It("proves an imported chain binds the provider-held key", func() {
		// The round trip import-ca-cert performs: build the request, have a
		// parent sign it, import the chain. AssertSignerMatchesCert is reached
		// through LoadOrCreateCAKey(ctx, false), so this is the provider path.
		csrPEM, err := subject.BuildCSR(ctx, "puppet.test", true)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		chain := signAsSubCA(csr)
		key, err := subject.LoadOrCreateCAKey(ctx, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(provider.generateCalls).To(Equal(1), "loading must not generate a second key")

		Expect(ca.ImportCAMaterial(ctx, store, chain, nil, nil, key, ca.CRLValidity)).To(Succeed())
		noLocalKey()

		stored, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored).NotTo(BeEmpty())
	})
})

// signAsSubCA has a self-signed root sign csr as an intermediate, returning the
// bundle in the order openvox-ca stores it: this CA first, root last.
func signAsSubCA(csr *x509.CertificateRequest) []byte {
	GinkgoHelper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	serial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		Expect(err).NotTo(HaveOccurred())
		return n
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	Expect(err).NotTo(HaveOccurred())
	root, err := x509.ParseCertificate(rootDER)
	Expect(err).NotTo(HaveOccurred())

	interTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, csr.PublicKey, rootKey)
	Expect(err).NotTo(HaveOccurred())

	return append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})...,
	)
}

var _ = Describe("LoadOrCreateCAKey under concurrent creation", func() {
	// The lock and the in-lock re-check exist for a failure the code calls
	// unrecoverable: two `csr --create-key` runs against a shared backend, where
	// the loser would overwrite a key the winner has already sent to a parent
	// for signing. The signed chain that came back could then never be imported.
	// Sequential specs take the fast path and never reach the branch that runs
	// when the race is lost.
	It("creates exactly one key however many callers race", func() {
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())
		asCfg := ca.AutosignConfig{Mode: "off"}

		const racers = 8
		keys := make([][]byte, racers)
		errs := make([]error, racers)
		var wg sync.WaitGroup
		for i := range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Separate CA values sharing one backend, which is what two
				// processes against a shared storage backend look like.
				subject := ca.New(store, asCfg, "puppet.test")
				subject.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
				key, err := subject.LoadOrCreateCAKey(ctx, true)
				if err != nil {
					errs[i] = err
					return
				}
				der, err := x509.MarshalPKIXPublicKey(key.Public())
				if err != nil {
					errs[i] = err
					return
				}
				keys[i] = der
			}()
		}
		wg.Wait()

		for i, err := range errs {
			Expect(err).NotTo(HaveOccurred(), "racer %d", i)
		}
		for i := 1; i < racers; i++ {
			Expect(keys[i]).To(Equal(keys[0]),
				"every caller must end up with the same key, not its own")
		}

		stored, err := store.GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(countPEMBlocks(stored, "EC PRIVATE KEY")+countPEMBlocks(stored, "PRIVATE KEY")).
			To(Equal(1), "storage must hold exactly one key blob")
	})
})
