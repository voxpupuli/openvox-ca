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
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// rotatedKey simulates a CA key that has been rotated at its provider (e.g.
// an OpenBao Transit key changed with `bao write -f transit/keys/<name>/rotate`)
// out from under a running CA: it still advertises the original public key —
// so it passes CA load's cert/key match check and x509.CreateCertificate's
// key-matches-parent check exactly as the real key would — but every signature
// is produced by a *different* private key. x509.CreateCertificate re-verifies
// the signature it gets back against the advertised public key, so the
// mismatch is caught and issuance is refused rather than emitting a
// certificate no verifier could validate.
type rotatedKey struct {
	pub      crypto.PublicKey // the original CA public key (matches the CA cert)
	signWith crypto.Signer    // a different key that actually produces signatures
}

func (k *rotatedKey) Public() crypto.PublicKey { return k.pub }

func (k *rotatedKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.signWith.Sign(r, digest, opts)
}

var _ = Describe("issuance rejects a provider-side key rotation", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-keyrotation-test")
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

	// The rotation scenario: the CA key still advertises the public key the CA
	// certificate was issued against (so nothing upstream notices), but it now
	// signs with a different private key. Issuance must be refused and nothing
	// persisted, so the CA never hands out a certificate that fails to verify
	// against its own certificate.
	It("refuses to issue and persists nothing", func() {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		myCA.CAKey = &rotatedKey{pub: myCA.CAKey.Public(), signWith: other}

		ctx := context.Background()
		csrPEM, err := testutil.GenerateCSR("rotated.example.com")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, "rotated.example.com", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Sign(ctx, "rotated.example.com")
		Expect(err).To(HaveOccurred())
		Expect(store.HasCert(ctx, "rotated.example.com")).To(BeFalse())
	})

	It("issues normally when the signing key still matches the CA certificate", func() {
		ctx := context.Background()
		csrPEM, err := testutil.GenerateCSR("healthy.example.com")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, "healthy.example.com", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Sign(ctx, "healthy.example.com")
		Expect(err).NotTo(HaveOccurred())
		Expect(store.HasCert(ctx, "healthy.example.com")).To(BeTrue())
	})
})
