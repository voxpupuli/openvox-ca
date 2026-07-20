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
