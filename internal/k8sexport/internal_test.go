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

var _ = Describe("Config.needsDefaultNamespace", func() {
	It("is false when every target sets its own namespace", func() {
		cfg := Config{Targets: []Target{
			{Metadata: Metadata{Name: "a", Namespace: "ns1"}},
			{Metadata: Metadata{Name: "b", Namespace: "ns2"}},
		}}
		Expect(cfg.needsDefaultNamespace()).To(BeFalse())
	})

	It("is true when any target omits its namespace", func() {
		cfg := Config{Targets: []Target{
			{Metadata: Metadata{Name: "a", Namespace: "ns1"}},
			{Metadata: Metadata{Name: "b"}},
		}}
		Expect(cfg.needsDefaultNamespace()).To(BeTrue())
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
