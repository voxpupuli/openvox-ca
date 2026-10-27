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

package k8sexport

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("needsDefaultNamespace", func() {
	It("is false when every target sets its own namespace", func() {
		cfg := Config{Targets: []Target{
			{Metadata: Metadata{Name: "a", Namespace: "ns1"}},
			{Metadata: Metadata{Name: "b", Namespace: "ns2"}},
		}}
		Expect(needsDefaultNamespace(&cfg)).To(BeFalse())
	})

	It("is true when any target omits its namespace", func() {
		cfg := Config{Targets: []Target{
			{Metadata: Metadata{Name: "a", Namespace: "ns1"}},
			{Metadata: Metadata{Name: "b"}},
		}}
		Expect(needsDefaultNamespace(&cfg)).To(BeTrue())
	})
})

// pemBlocks filters by block type, and it decides what a *narrowed* target
// publishes: scoped() returns the blob untouched under the default chain scope,
// so this is reached only for self and root. On those, dropping the filter would
// make "block 0" mean whatever came first in the blob rather than the first
// certificate. Nothing drove the mismatch branch: every fixture elsewhere holds
// one block type.
var _ = Describe("pemBlocks", func() {
	const mixed = "-----BEGIN CERTIFICATE-----\nQ0VSVA==\n-----END CERTIFICATE-----\n" +
		"-----BEGIN X509 CRL-----\nQ1JM\n-----END X509 CRL-----\n" +
		"-----BEGIN RSA PRIVATE KEY-----\nS0VZ\n-----END RSA PRIVATE KEY-----\n"

	It("keeps only the blocks of the type asked for", func() {
		certs := pemBlocks([]byte(mixed), "CERTIFICATE")
		Expect(certs).To(HaveLen(1))
		Expect(string(certs[0])).To(ContainSubstring("Q0VSVA=="))

		crls := pemBlocks([]byte(mixed), "X509 CRL")
		Expect(crls).To(HaveLen(1))
		Expect(string(crls[0])).To(ContainSubstring("Q1JM"))
	})

	It("drops a private key rather than passing it through", func() {
		// What this returns is written into a Secret or ConfigMap by a narrowed
		// target, so a key surviving the filter would be published there.
		for _, t := range []string{"CERTIFICATE", "X509 CRL"} {
			blocks := pemBlocks([]byte(mixed), t)
			Expect(blocks).NotTo(BeEmpty(), "an empty result would pass the loop below vacuously")
			for _, b := range blocks {
				Expect(string(b)).NotTo(ContainSubstring("PRIVATE KEY"))
			}
		}
	})

	It("returns nothing when no block matches", func() {
		Expect(pemBlocks([]byte(mixed), "CERTIFICATE REQUEST")).To(BeEmpty())
	})
})

// scoped()'s zero-block fallback. It is the one branch that decides what a
// target publishes when the *material* is not what the scope assumed -- a CRL
// blob asked for a certificate scope, or a blob that decodes to nothing at all.
//
// Returning the blob untouched is the safe answer: narrowing to "block 0" of an
// empty list would publish nothing, and a target that silently publishes an
// empty Secret is worse than one that publishes more than it meant to. But
// nothing drove it. Every fixture elsewhere holds blocks of the type the scope
// asks for, so the branch was reachable only through material this suite never
// built, and inverting it -- returning nil, or blocks[0] on an empty slice --
// would have gone unnoticed or panicked in production rather than in a spec.
var _ = Describe("scoped's fallback when nothing matches the block type", func() {
	const crlOnly = "-----BEGIN X509 CRL-----\nQ1JM\n-----END X509 CRL-----\n"

	It("publishes the blob untouched rather than narrowing to nothing", func() {
		for _, scope := range []string{ScopeSelf, ScopeRoot} {
			out := scoped([]byte(crlOnly), "CERTIFICATE", scope)
			Expect(string(out)).To(Equal(crlOnly),
				"scope %q must fall back to the whole blob when no CERTIFICATE block matches", scope)
		}
	})

	It("does the same for material that decodes to no PEM at all", func() {
		// The other way to reach it: a blob that is not PEM. Narrowing here
		// must not be an index into an empty slice.
		garbage := []byte("not pem at all\n")
		for _, scope := range []string{ScopeSelf, ScopeRoot} {
			Expect(string(scoped(garbage, "CERTIFICATE", scope))).To(Equal(string(garbage)))
		}
	})
})
