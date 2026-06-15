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
	"crypto/x509"
	"encoding/pem"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// newRefresherTestCA builds an initialised CA backed by a temp filesystem store,
// seeded with a freshly generated test CA and CRL.
func newRefresherTestCA() (*ca.CA, *storage.StorageService) {
	GinkgoHelper()
	keyPEM, crtPEM, crlPEM, err := testutil.GenerateTestCA()
	Expect(err).NotTo(HaveOccurred(), "GenerateTestCA")

	store := storage.New(GinkgoT().TempDir())
	c := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
	ctx := context.Background()
	Expect(store.EnsureDirs(ctx)).To(Succeed(), "EnsureDirs")
	Expect(store.SaveCAKey(ctx, keyPEM)).To(Succeed(), "SaveCAKey")
	Expect(store.SaveCACert(ctx, crtPEM)).To(Succeed(), "SaveCACert")
	Expect(store.UpdateCRL(ctx, crlPEM)).To(Succeed(), "UpdateCRL")
	Expect(store.WriteSerial(ctx, "0001")).To(Succeed(), "WriteSerial")
	Expect(store.TouchInventory(ctx)).To(Succeed(), "TouchInventory")
	Expect(c.Init(ctx)).To(Succeed(), "Init")
	return c, store
}

func storedCRLNumber(store *storage.StorageService) int64 {
	GinkgoHelper()
	crlPEM, err := store.GetCRL(context.Background())
	Expect(err).NotTo(HaveOccurred(), "GetCRL")
	block, _ := pem.Decode(crlPEM)
	Expect(block).NotTo(BeNil(), "CRL is not PEM")
	crl, err := x509.ParseRevocationList(block.Bytes)
	Expect(err).NotTo(HaveOccurred(), "ParseRevocationList")
	return crl.Number.Int64()
}

// refreshCRLOnce should re-sign when the refresh window exceeds the CRL's
// remaining validity, and leave it alone otherwise.
var _ = Describe("refreshCRLOnce", func() {
	It("re-signs when due and leaves a fresh CRL alone", func() {
		c, store := newRefresherTestCA()
		ctx := context.Background()

		start := storedCRLNumber(store)

		// Window far larger than remaining validity: must re-sign.
		refreshCRLOnce(ctx, c, 3650*24*time.Hour)
		afterDue := storedCRLNumber(store)
		Expect(afterDue).To(Equal(start+1), "expected CRL number to increment from %d, got %d", start, afterDue)

		// Tiny window against a freshly reissued CRL: must not re-sign.
		refreshCRLOnce(ctx, c, time.Hour)
		afterFresh := storedCRLNumber(store)
		Expect(afterFresh).To(Equal(afterDue), "expected CRL number to stay at %d, got %d", afterDue, afterFresh)
	})
})

// runCRLRefresher must perform an immediate check at startup and then return
// promptly once its context is cancelled.
var _ = Describe("runCRLRefresher", func() {
	It("re-signs at startup and returns after context cancellation", func() {
		c, store := newRefresherTestCA()
		start := storedCRLNumber(store)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			// A large refresh window guarantees the startup check re-signs.
			runCRLRefresher(ctx, c, time.Hour, 3650*24*time.Hour)
			close(done)
		}()

		// The startup check should re-sign before we cancel; poll briefly.
		Eventually(func() int64 {
			return storedCRLNumber(store)
		}).WithTimeout(2*time.Second).WithPolling(10*time.Millisecond).
			ShouldNot(Equal(start), "startup refresh did not run within 2s")

		cancel()
		Eventually(done).WithTimeout(2*time.Second).Should(BeClosed(),
			"runCRLRefresher did not return after context cancellation")
	})
})
