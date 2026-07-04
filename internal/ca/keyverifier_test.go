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
	"errors"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// fakeVerifiableKey wraps a real crypto.Signer with a controllable
// KeyVerifier implementation (see internal/ca/keyprovider.go), so tests can
// drive the "CA key no longer matches its source of truth" path without a
// real OpenBao server. Signing still delegates to the embedded real key, so
// a successful issuance produces a genuinely valid certificate.
type fakeVerifiableKey struct {
	crypto.Signer
	verifyErr   error
	verifyCalls int
}

func (k *fakeVerifiableKey) VerifyCurrentKey(_ context.Context) error {
	k.verifyCalls++
	return k.verifyErr
}

var _ = Describe("KeyVerifier", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-keyverifier-test")
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

	It("refuses to issue a certificate when the CA key reports it no longer matches its source", func() {
		fake := &fakeVerifiableKey{Signer: myCA.CAKey, verifyErr: errors.New("transit key rotated at provider")}
		myCA.CAKey = fake

		ctx := context.Background()
		csrPEM, err := testutil.GenerateCSR("rotated.example.com")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, "rotated.example.com", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Sign(ctx, "rotated.example.com")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("transit key rotated at provider"))
		Expect(fake.verifyCalls).To(BeNumerically(">=", 1))

		// Nothing should have been issued.
		Expect(store.HasCert(ctx, "rotated.example.com")).To(BeFalse())
	})

	It("issues normally when the CA key's live verification succeeds", func() {
		fake := &fakeVerifiableKey{Signer: myCA.CAKey}
		myCA.CAKey = fake

		ctx := context.Background()
		csrPEM, err := testutil.GenerateCSR("healthy.example.com")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, "healthy.example.com", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Sign(ctx, "healthy.example.com")
		Expect(err).NotTo(HaveOccurred())
		Expect(fake.verifyCalls).To(BeNumerically(">=", 1))
	})
})
