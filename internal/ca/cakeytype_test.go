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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// ca_key_algo cannot create an Ed25519 CA key, but each of these is a way to
// arrive with one anyway. Every one of them used to succeed, leaving a CA that
// signs under --single-process and fails every signature through the isolated
// signer, which refuses the crypto.Hash(0) Ed25519 signs with.
var _ = Describe("CA key type", func() {
	var (
		ctx     context.Context
		tmpDir  string
		store   *storage.StorageService
		key     ed25519.PrivateKey
		certPEM []byte
		keyPEM  []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-cakeytype")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(os.RemoveAll, tmpDir)
		store = storage.New(tmpDir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())

		// A self-signed CA certificate that passes every bundle check, so the
		// key type is the only thing wrong with it.
		_, key, err = ed25519.GenerateKey(rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Puppet CA: ed25519.test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		Expect(err).NotTo(HaveOccurred())
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).NotTo(HaveOccurred())
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	})

	It("refuses to start a CA whose key in storage is Ed25519", func() {
		Expect(store.SaveCAKey(ctx, keyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, certPEM)).To(Succeed())

		err := ca.New(store, ca.AutosignConfig{Mode: "off"}, "ed25519.test").Init(ctx)

		Expect(err).To(MatchError(ca.ErrCAKeyType))
		Expect(err.Error()).To(ContainSubstring("the CA key is ed25519.PublicKey"))
	})

	It("refuses to start a frontend whose CA certificate binds an Ed25519 key", func() {
		Expect(store.SaveCACert(ctx, certPEM)).To(Succeed())
		frontend := ca.New(store, ca.AutosignConfig{Mode: "off"}, "ed25519.test")
		frontend.ExternalSigner = key

		Expect(frontend.Init(ctx)).To(MatchError(ca.ErrCAKeyType))
	})

	It("refuses to import an Ed25519 CA key and certificate, and writes neither", func() {
		err := ca.ImportCA(ctx, store, certPEM, keyPEM, nil)

		Expect(err).To(MatchError(ca.ErrCAKeyType))
		Expect(store.HasCACert(ctx)).To(BeFalse())
		Expect(store.HasCAKey(ctx)).To(BeFalse())
	})

	It("refuses to import a certificate for an Ed25519 key held elsewhere, and writes nothing", func() {
		_, err := ca.ImportCACertificate(ctx, store, certPEM, key, ca.CRLValidity, false)

		Expect(err).To(MatchError(ca.ErrCAKeyType))
		Expect(store.HasCACert(ctx)).To(BeFalse())
	})
})
