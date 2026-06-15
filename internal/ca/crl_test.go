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
	"crypto/x509"
	"encoding/pem"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// parseStoredCRL is a test helper that loads and parses the CRL currently in
// storage so assertions can inspect its number, validity, and entries.
func parseStoredCRL(store *storage.StorageService) *x509.RevocationList {
	crlPEM, err := store.GetCRL(context.Background())
	Expect(err).NotTo(HaveOccurred())
	block, _ := pem.Decode(crlPEM)
	Expect(block).NotTo(BeNil())
	crl, err := x509.ParseRevocationList(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

var _ = Describe("CA CRL reissuance", func() {
	var (
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-crl-test")
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

	Describe("ReissueCRL", func() {
		It("bumps the CRL number and refreshes the validity window", func() {
			before := parseStoredCRL(store)

			Expect(myCA.ReissueCRL(context.Background())).To(Succeed())

			after := parseStoredCRL(store)
			Expect(after.Number.Cmp(before.Number)).To(Equal(1), "CRL number must increase")
			// A freshly reissued CRL should carry the full default validity
			// window (30 days) from now, allowing slack for execution time and
			// the whole-second truncation x509 applies to CRL timestamps.
			Expect(after.NextUpdate).To(BeTemporally("~", time.Now().Add(30*24*time.Hour), time.Minute))
		})

		It("preserves existing revocation entries", func() {
			// Sign and revoke a node so the CRL has an entry to preserve.
			csrPEM, err := testutil.GenerateCSR("crl-preserve-node")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "crl-preserve-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(context.Background(), "crl-preserve-node")
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(context.Background(), "crl-preserve-node")).To(Succeed())

			before := parseStoredCRL(store)
			Expect(before.RevokedCertificateEntries).To(HaveLen(1))
			revokedSerial := before.RevokedCertificateEntries[0].SerialNumber

			Expect(myCA.ReissueCRL(context.Background())).To(Succeed())

			after := parseStoredCRL(store)
			Expect(after.RevokedCertificateEntries).To(HaveLen(1))
			Expect(after.RevokedCertificateEntries[0].SerialNumber.Cmp(revokedSerial)).To(Equal(0))
			Expect(after.Number.Cmp(before.Number)).To(Equal(1))
		})

		It("keeps the revoked serial recognised after reissuance", func() {
			csrPEM, err := testutil.GenerateCSR("crl-recheck-node")
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(context.Background(), "crl-recheck-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(context.Background(), "crl-recheck-node")
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(context.Background(), "crl-recheck-node")).To(Succeed())

			block, _ := pem.Decode(certPEM)
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			Expect(myCA.ReissueCRL(context.Background())).To(Succeed())

			revoked, err := myCA.IsRevokedSerial(context.Background(), cert.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		})
	})

	Describe("RefreshCRLIfDue", func() {
		It("does nothing when the CRL is still well within its validity", func() {
			// Establish a known-fresh CRL (NextUpdate ~ now + crlValidity).
			Expect(myCA.ReissueCRL(context.Background())).To(Succeed())
			before := parseStoredCRL(store)

			// A one-hour refresh window against a multi-day-valid CRL: not due.
			reissued, err := myCA.RefreshCRLIfDue(context.Background(), time.Hour)
			Expect(err).NotTo(HaveOccurred())
			Expect(reissued).To(BeFalse())

			after := parseStoredCRL(store)
			Expect(after.Number.Cmp(before.Number)).To(Equal(0), "CRL must be untouched")
		})

		It("re-signs when remaining validity is within the refresh window", func() {
			Expect(myCA.ReissueCRL(context.Background())).To(Succeed())
			before := parseStoredCRL(store)

			// A refresh window far larger than the CRL's remaining validity
			// forces the refresh to fire.
			reissued, err := myCA.RefreshCRLIfDue(context.Background(), 3650*24*time.Hour)
			Expect(err).NotTo(HaveOccurred())
			Expect(reissued).To(BeTrue())

			after := parseStoredCRL(store)
			Expect(after.Number.Cmp(before.Number)).To(Equal(1))
			Expect(after.NextUpdate).To(BeTemporally("~", time.Now().Add(30*24*time.Hour), time.Minute))
		})

		It("is idempotent across replicas: a second due-check finds it fresh", func() {
			// First replica refreshes...
			reissued, err := myCA.RefreshCRLIfDue(context.Background(), 3650*24*time.Hour)
			Expect(err).NotTo(HaveOccurred())
			Expect(reissued).To(BeTrue())
			afterFirst := parseStoredCRL(store)

			// ...a second replica running the same check with a normal window
			// sees a fresh CRL and does not re-sign again.
			reissued, err = myCA.RefreshCRLIfDue(context.Background(), time.Hour)
			Expect(err).NotTo(HaveOccurred())
			Expect(reissued).To(BeFalse())

			afterSecond := parseStoredCRL(store)
			Expect(afterSecond.Number.Cmp(afterFirst.Number)).To(Equal(0))
		})
	})

	Describe("DefaultCRLRefreshBefore", func() {
		It("defaults to a third of the CRL validity window", func() {
			// Default validity is 30 days; a third is 10 days.
			Expect(myCA.DefaultCRLRefreshBefore()).To(Equal(30 * 24 * time.Hour / 3))
		})

		It("tracks a custom CRL validity", func() {
			myCA.CRLValidityDays = 9
			Expect(myCA.DefaultCRLRefreshBefore()).To(Equal(3 * 24 * time.Hour))
		})
	})
})

// Guard against an empty-storage edge case so a missing CRL surfaces an error
// rather than a panic.
var _ = Describe("CA CRL reissuance without stored CRL", func() {
	It("returns an error when no CRL is present", func() {
		tmpDir, err := os.MkdirTemp("", "openvox-ca-crl-missing-test")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir)

		store := storage.New(tmpDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SaveCAKey(context.Background(), cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(context.Background(), cachedCrtPEM)).To(Succeed())

		// Load the CA key/cert without going through Init (which would seed a CRL).
		_, err = myCA.LoadKey(context.Background())
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.RefreshCRLIfDue(context.Background(), time.Hour)
		Expect(err).To(HaveOccurred())
	})
})
