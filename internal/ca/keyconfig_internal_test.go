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

// White-box: resolveKeyConfig and the two accessors over it are unexported.
// They are what turns an operator's ca_key_* and leaf_key_* settings into the
// key the CA generates, and each half of a setting falls back on its own, so
// every combination of set and unset is a case here (#681).

package ca

import (
	"crypto/rsa"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Resolving the CA's own key settings", func() {
	var c *CA

	BeforeEach(func() {
		c = &CA{}
	})

	DescribeTable("the CA key, whose built-in is RSA 4096",
		func(set, want KeyConfig) {
			c.CAKeyConfig = set
			Expect(c.caKeyConfig()).To(Equal(want))
		},
		Entry("nothing set is the built-in", KeyConfig{}, KeyConfig{Algo: KeyAlgoRSA, Size: 4096}),
		Entry("a size alone is that size of RSA, not the built-in",
			KeyConfig{Size: 2048}, KeyConfig{Algo: KeyAlgoRSA, Size: 2048}),
		Entry("RSA alone is the built-in's size", KeyConfig{Algo: KeyAlgoRSA}, KeyConfig{Algo: KeyAlgoRSA, Size: 4096}),
		Entry("ECDSA alone is P-256", KeyConfig{Algo: KeyAlgoECDSA}, KeyConfig{Algo: KeyAlgoECDSA, Size: 256}),
		Entry("both set are kept", KeyConfig{Algo: KeyAlgoECDSA, Size: 384}, KeyConfig{Algo: KeyAlgoECDSA, Size: 384}),
		Entry("an unknown algorithm is left for validation to refuse",
			KeyConfig{Algo: "dsa"}, KeyConfig{Algo: "dsa"}),
	)

	DescribeTable("the leaf key, whose built-in is RSA 2048",
		func(set, want KeyConfig) {
			c.LeafKeyConfig = set
			Expect(c.leafKeyConfig()).To(Equal(want))
		},
		Entry("nothing set is the built-in", KeyConfig{}, KeyConfig{Algo: KeyAlgoRSA, Size: 2048}),
		Entry("a size alone is that size of RSA", KeyConfig{Size: 4096}, KeyConfig{Algo: KeyAlgoRSA, Size: 4096}),
		Entry("RSA alone is the leaf built-in's 2048, not generateKey's 4096",
			KeyConfig{Algo: KeyAlgoRSA}, KeyConfig{Algo: KeyAlgoRSA, Size: 2048}),
		Entry("ECDSA alone is P-256", KeyConfig{Algo: KeyAlgoECDSA}, KeyConfig{Algo: KeyAlgoECDSA, Size: 256}),
		Entry("both set are kept", KeyConfig{Algo: KeyAlgoRSA, Size: 3072}, KeyConfig{Algo: KeyAlgoRSA, Size: 3072}),
	)

	// generateKey passes rsa.GenerateKey a literal per allowed size, so a
	// mapping slip between them would otherwise go unseen.
	DescribeTable("generates an RSA key of the size each setting names",
		func(size, wantBits int) {
			key, err := generateKey(KeyConfig{Algo: KeyAlgoRSA, Size: size})
			Expect(err).NotTo(HaveOccurred())
			rsaKey, ok := key.(*rsa.PrivateKey)
			Expect(ok).To(BeTrue())
			Expect(rsaKey.N.BitLen()).To(Equal(wantBits))
		},
		Entry("2048", 2048, 2048),
		Entry("3072", 3072, 3072),
		Entry("4096", 4096, 4096),
		Entry("no size, generateKey's own default", 0, 4096),
	)

	It("refuses an RSA size it does not generate", func() {
		_, err := generateKey(KeyConfig{Algo: KeyAlgoRSA, Size: 1024})
		Expect(err).To(MatchError(ContainSubstring("below the minimum of 2048 bits")))
	})

	It("resolves each key from its own settings, not the other's", func() {
		c.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 384}
		c.LeafKeyConfig = KeyConfig{Algo: KeyAlgoRSA}
		Expect(c.caKeyConfig()).To(Equal(KeyConfig{Algo: KeyAlgoECDSA, Size: 384}))
		Expect(c.leafKeyConfig()).To(Equal(KeyConfig{Algo: KeyAlgoRSA, Size: 2048}))
	})
})
