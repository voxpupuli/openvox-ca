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
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("CA CRL update notifications", func() {
	var (
		tmpDir string
		myCA   *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-crl-notify-test")
		Expect(err).NotTo(HaveOccurred())

		store := storage.New(tmpDir)
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

	It("signals on ReissueCRL", func() {
		Expect(myCA.ReissueCRL(context.Background())).To(Succeed())
		Eventually(myCA.CRLUpdated()).Should(Receive())
	})

	It("signals on revoke", func() {
		csrPEM, err := testutil.GenerateCSR("crl-notify-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(context.Background(), "crl-notify-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(context.Background(), "crl-notify-node")
		Expect(err).NotTo(HaveOccurred())

		// Drain any pending signal so we observe the one from the revoke.
		select {
		case <-myCA.CRLUpdated():
		default:
		}

		Expect(myCA.Revoke(context.Background(), "crl-notify-node")).To(Succeed())
		Eventually(myCA.CRLUpdated()).Should(Receive())
	})

	It("coalesces multiple updates and never blocks signing", func() {
		// Several CRL updates with no consumer must not block (the buffered,
		// non-blocking send drops extras), and exactly one signal remains pending.
		for range 5 {
			Expect(myCA.ReissueCRL(context.Background())).To(Succeed())
		}
		Eventually(myCA.CRLUpdated()).Should(Receive())
		// Only one was buffered; the channel is now empty.
		Consistently(myCA.CRLUpdated()).ShouldNot(Receive())
	})
})
