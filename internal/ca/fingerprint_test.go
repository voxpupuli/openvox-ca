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

package ca

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseFingerprintAlgorithms", func() {
	DescribeTable("returns the digests to report besides SHA-256, in a fixed order",
		func(names []string, want []FingerprintAlgorithm) {
			got, err := ParseFingerprintAlgorithms(names)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))
		},
		Entry("nothing configured", nil, nil),
		Entry("SHA256 alone, which is always reported", []string{"SHA256"}, nil),
		Entry("all three", []string{"SHA512", "SHA256", "SHA1"},
			[]FingerprintAlgorithm{FingerprintSHA1, FingerprintSHA512}),
		Entry("any case, with repeats and spaces", []string{" sha512", "Sha1", "SHA512 "},
			[]FingerprintAlgorithm{FingerprintSHA1, FingerprintSHA512}),
	)

	DescribeTable("refuses a name it does not know, naming it",
		func(name string) {
			_, err := ParseFingerprintAlgorithms([]string{"SHA1", name})
			Expect(err).To(MatchError(ContainSubstring("%q", name)))
		},
		Entry("another digest", "MD5"),
		Entry("the hyphenated spelling", "SHA-512"),
		Entry("an empty entry", ""),
	)

	Context("when crypto/sha1 refuses to hash, as under GODEBUG=fips140=only", func() {
		BeforeEach(func() {
			saved := sha1Usable
			sha1Usable = func() bool { return false }
			DeferCleanup(func() { sha1Usable = saved })
		})

		It("refuses SHA1 and says why", func() {
			_, err := ParseFingerprintAlgorithms([]string{"SHA1"})
			Expect(err).To(MatchError(ContainSubstring("fips140=only")))
		})

		It("still accepts the others", func() {
			Expect(ParseFingerprintAlgorithms([]string{"SHA256", "SHA512"})).
				To(Equal([]FingerprintAlgorithm{FingerprintSHA512}))
		})
	})

	It("reads a panicking hash as unusable", func() {
		// The branch sha1Usable takes under fips140=only, which a test binary
		// cannot enter: crypto/sha1 panics there rather than returning.
		Expect(hashes(func() { panic("crypto/sha1: use of SHA-1 is not allowed in FIPS 140-only mode") })).
			To(BeFalse())
		Expect(hashes(func() {})).To(BeTrue())
	})

	It("finds crypto/sha1 usable in this process", func() {
		// The probe itself, unreplaced: a test binary does not run under
		// fips140=only, so it must report true here, or the refusal above would
		// fire for everyone.
		Expect(sha1Usable()).To(BeTrue())
	})
})

var _ = Describe("ColonFingerprint", func() {
	der := []byte("not really a certificate")

	// Known answers from openssl, not from a second copy of the formatter:
	// printf 'not really a certificate' | openssl dgst -sha1 -c (and -sha256,
	// -sha512).
	DescribeTable("renders each digest as colon-separated lower-case hex pairs",
		func(alg FingerprintAlgorithm, want string) {
			Expect(ColonFingerprint(alg, der)).To(Equal(want))
		},
		Entry("SHA1", FingerprintSHA1,
			"83:90:f3:b4:59:64:0f:62:68:38:44:84:a2:b9:68:09:17:08:af:de"),
		Entry("SHA256", FingerprintSHA256,
			"d6:18:22:55:e5:73:9d:55:fc:97:81:75:9c:7a:82:3d:4d:ff:3d:2b:7d:17:94:9e:70:85:ee:7c:0c:c2:2a:cf"),
		Entry("SHA512", FingerprintSHA512,
			"15:54:65:ef:04:94:6f:80:92:30:a8:00:5f:43:90:65:9a:11:64:39:bb:db:96:95:ee:37:3f:7b:5f:05:42:0d:"+
				"cb:8e:6f:ce:42:48:dd:23:9f:d1:6f:2c:7e:eb:ab:81:6d:4e:86:55:87:69:8c:16:19:1e:a2:53:2c:be:91:7e"),
	)

	It("renders nothing for an algorithm it does not know", func() {
		Expect(ColonFingerprint("MD5", der)).To(BeEmpty())
	})

	It("agrees with SHA256ColonFingerprint", func() {
		Expect(ColonFingerprint(FingerprintSHA256, der)).To(Equal(SHA256ColonFingerprint(der)))
	})

	It("keys OtherFingerprints by algorithm, and gives nil for none", func() {
		Expect(OtherFingerprints(nil, der)).To(BeNil())
		Expect(OtherFingerprints([]FingerprintAlgorithm{FingerprintSHA512}, der)).
			To(Equal(map[string]string{"SHA512": ColonFingerprint(FingerprintSHA512, der)}))
	})
})
