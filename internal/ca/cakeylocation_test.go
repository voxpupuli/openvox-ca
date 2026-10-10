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
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("Init and where the cadir keeps the CA key", func() {
	var (
		ctx   = context.Background()
		dir   string
		store *storage.StorageService
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		store = storage.New(dir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
	})

	It("refuses to start when the two keys differ", func() {
		// One is the key OpenVox Server signs with, the other the one this CA
		// signed with before it moved; nothing here can tell which the
		// operator means, so starting at all would be a guess.
		Expect(os.WriteFile(filepath.Join(dir, "ca_key.pem"), cachedKeyPEM, 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "private", "ca_key.pem"), []byte("some other key"), 0o600)).To(Succeed())

		err := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test").Init(ctx)
		Expect(err).To(MatchError(storage.ErrCAKeyConflict))
	})

	It("starts, signs and revokes on a cadir with the key only in private/, and leaves it there", func() {
		// A cadir an earlier openvox-ca created. It keeps working where it
		// is: nothing moves the key to the top of the cadir.
		Expect(os.WriteFile(filepath.Join(dir, "private", "ca_key.pem"), cachedKeyPEM, 0o600)).To(Succeed())
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())

		csrPEM, _ := buildCSR("legacy-node")
		_, err := myCA.SaveRequest(ctx, "legacy-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(ctx, "legacy-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "legacy-node")).To(Succeed())

		Expect(filepath.Join(dir, "ca_key.pem")).NotTo(BeAnExistingFile())
		Expect(os.ReadFile(filepath.Join(dir, "private", "ca_key.pem"))).To(Equal(cachedKeyPEM))
	})

	It("starts when both hold the same key", func() {
		Expect(os.WriteFile(filepath.Join(dir, "ca_key.pem"), cachedKeyPEM, 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "private", "ca_key.pem"), cachedKeyPEM, 0o600)).To(Succeed())

		Expect(ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test").Init(ctx)).To(Succeed())

		// Starting rearranges nothing: both copies are still there, unchanged.
		Expect(os.ReadFile(filepath.Join(dir, "ca_key.pem"))).To(Equal(cachedKeyPEM))
		Expect(os.ReadFile(filepath.Join(dir, "private", "ca_key.pem"))).To(Equal(cachedKeyPEM))
	})
})
