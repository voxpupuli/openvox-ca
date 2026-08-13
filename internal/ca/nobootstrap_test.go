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
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("CA Init with NoBootstrap", func() {
	var ctx context.Context

	BeforeEach(func() { ctx = context.Background() })

	It("refuses to create a CA when none exists", func() {
		dir := GinkgoT().TempDir()
		store := storage.New(dir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.NoBootstrap = true

		err := myCA.Init(ctx)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("will not create one"))

		// The point of the flag: a mistyped cadir must not leave a brand-new CA
		// behind, under which certificates would be issued that nothing in the
		// fleet trusts, with no obvious sign of why.
		hasCert, err := store.HasCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(hasCert).To(BeFalse())

		// And the limit of the flag, which is load-bearing for callers: Init
		// reaches EnsureDirs and InitHMAC before it decides, so NoBootstrap is
		// not a read-only mode. cmd/openvox-ca's generate therefore runs its own
		// guard *before* Init rather than relying on this one, and the spec
		// asserting the cadir is byte-identical after that refusal is only
		// meaningful because this side effect is real. If Init ever does become
		// read-only here, that guard can be simplified -- but do not delete this
		// assertion to make an unrelated change pass.
		Expect(filepath.Dir(store.PrivateKeyPath("anything"))).To(BeADirectory())
	})

	It("still loads a CA that already exists", func() {
		dir := GinkgoT().TempDir()
		store := storage.New(dir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.NoBootstrap = true
		Expect(myCA.Init(ctx)).To(Succeed())
		Expect(myCA.CACert).NotTo(BeNil())
	})
})
