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

// White-box, to reuse lockOrderObserver and goID from lockorder_test.go.
package ca

import (
	"context"
	"slices"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// caKeyReadObserver records which locks the reading goroutine held each time
// the CA key was read.
type caKeyReadObserver struct {
	*lockOrderObserver
	keyReadsUnder [][]string
}

func (o *caKeyReadObserver) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeyCAKey {
		o.mu.Lock()
		o.keyReadsUnder = append(o.keyReadsUnder, slices.Clone(o.held[goID()]))
		o.mu.Unlock()
	}
	return o.lockOrderObserver.Get(ctx, key)
}

// ImportCA's refusal of a plaintext key over an encrypted one (#516) is a
// check-then-write: the check reads the stored key and the write replaces it.
// AGENTS.md requires the check to run inside the lock the write runs under,
// and the one for a CA key is bootstrap, as for ImportCACertificate and
// LoadOrCreateCAKey.
var _ = Describe("ImportCA's stored-key check", func() {
	It("reads the stored key under bootstrap, then nests crl inside it", func() {
		ctx := context.Background()
		keyPEM, crtPEM, _, err := testutil.GenerateTestCA()
		Expect(err).NotTo(HaveOccurred())

		dir := GinkgoT().TempDir()
		obs := &caKeyReadObserver{lockOrderObserver: newLockOrderObserver(dir)}
		store := storage.NewWithBackend(obs, dir+"/private")

		Expect(ImportCA(ctx, store, crtPEM, keyPEM, nil)).To(Succeed())

		Expect(obs.keyReadsUnder).NotTo(BeEmpty(), "the check read the stored key")
		for _, held := range obs.keyReadsUnder {
			Expect(held).To(ContainElement(lockNameBootstrap),
				"every read of the stored key was made holding bootstrap")
		}
		Expect(obs.edgeCount(lockNameBootstrap, lockNameCRL)).To(BeNumerically(">", 0),
			"the CRL rewrite runs inside bootstrap")
		Expect(obs.violations()).To(BeEmpty(), "and that nesting is one locking.md permits")
	})
})
