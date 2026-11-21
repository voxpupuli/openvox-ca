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

	It("refuses to start on a cadir with the key only in private/, and changes nothing", func() {
		// private/ca_key.pem is not where the CA key lives, so this is a CA
		// certificate without its key. Bootstrapping would replace the
		// certificate every issued certificate chains to, so Init refuses, and
		// neither file moves.
		stray := filepath.Join(dir, "private", "ca_key.pem")
		Expect(os.WriteFile(stray, cachedKeyPEM, 0o600)).To(Succeed())

		err := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test").Init(ctx)
		Expect(err).To(MatchError(ContainSubstring("a CA certificate exists but its key is missing")))

		Expect(filepath.Join(dir, "ca_key.pem")).NotTo(BeAnExistingFile())
		Expect(os.ReadFile(stray)).To(Equal(cachedKeyPEM))
		Expect(store.GetCACert(ctx)).To(Equal(cachedCrtPEM))
	})

	It("starts on ca_key.pem and leaves a private/ca_key.pem beside it alone", func() {
		Expect(os.WriteFile(filepath.Join(dir, "ca_key.pem"), cachedKeyPEM, 0o600)).To(Succeed())
		stray := filepath.Join(dir, "private", "ca_key.pem")
		Expect(os.WriteFile(stray, []byte("some other key"), 0o600)).To(Succeed())

		Expect(ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test").Init(ctx)).To(Succeed())

		Expect(os.ReadFile(filepath.Join(dir, "ca_key.pem"))).To(Equal(cachedKeyPEM))
		Expect(os.ReadFile(stray)).To(Equal([]byte("some other key")))
	})
})
