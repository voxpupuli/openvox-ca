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
	"os"
	"path/filepath"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The CA signing bound follows the CSR rate limit's three-state contract
// exactly: -1 ("unset") takes the built-in default, an explicit 0 disables the
// bound, and positive values pass through. Getting the 0 case wrong in either
// direction is the expensive mistake — rewriting it to the default takes away
// an operator's explicit opt-out, and rewriting the sentinel to 0 would ship
// unbounded signing to everyone who never set the key, which is the exposure
// this bound exists to close.
var _ = Describe("CA signing-concurrency resolution", func() {
	Describe("resolveSigningConcurrency", func() {
		It("uses the built-in default when unset (sentinel -1)", func() {
			Expect(resolveSigningConcurrency(-1)).
				To(Equal(max(minSigningConcurrency, runtime.GOMAXPROCS(0))))
		})

		It("never returns a default below the floor", func() {
			// A single-CPU container would otherwise get a bound of 1, which
			// serialises issuance behind the OCSP responder.
			Expect(resolveSigningConcurrency(-1)).
				To(BeNumerically(">=", minSigningConcurrency))
		})

		It("treats an explicit 0 as unbounded, not as the default", func() {
			Expect(resolveSigningConcurrency(0)).To(Equal(0))
		})

		It("passes an explicit positive value through unchanged", func() {
			Expect(resolveSigningConcurrency(2)).To(Equal(2))
		})

		// A remote signer's capacity is routinely below the CPU count, so a
		// value under the floor has to survive: the floor guards the default,
		// not an operator's deliberate choice.
		It("does not raise an explicit value to the floor", func() {
			Expect(resolveSigningConcurrency(1)).To(Equal(1))
		})
	})

	Describe("config-file layer", func() {
		writeConfig := func(body string) string {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "openvox-ca.yaml")
			Expect(os.WriteFile(path, []byte(body), 0o600)).To(Succeed())
			return path
		}

		It("leaves the field at the unset sentinel when the key is absent", func() {
			cfg, err := loadServerConfig(writeConfig("host: 127.0.0.1\n"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.CASigningConcurrency).To(Equal(-1),
				"an absent ca_signing_concurrency must remain unset, not become 0")
		})

		It("reads an explicit 0 without confusing it with unset", func() {
			cfg, err := loadServerConfig(writeConfig("ca_signing_concurrency: 0\n"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.CASigningConcurrency).To(Equal(0))
			Expect(resolveSigningConcurrency(cfg.CASigningConcurrency)).To(Equal(0))
		})

		It("reads an explicit positive value", func() {
			cfg, err := loadServerConfig(writeConfig("ca_signing_concurrency: 6\n"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.CASigningConcurrency).To(Equal(6))
		})
	})

	Describe("environment layer", func() {
		It("overlays PUPPET_CA_SIGNING_CONCURRENCY over the file", func() {
			dir := GinkgoT().TempDir()
			path := filepath.Join(dir, "openvox-ca.yaml")
			Expect(os.WriteFile(path, []byte("ca_signing_concurrency: 6\n"), 0o600)).To(Succeed())

			GinkgoT().Setenv("PUPPET_CA_SIGNING_CONCURRENCY", "3")
			cfg, err := loadServerConfig(path)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.CASigningConcurrency).To(Equal(3))
		})
	})
})
