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

package k8sclient_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/k8sclient"
)

func TestK8sClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "k8sclient Suite")
}

// The label both features apply, which docs/kubernetes-export.md tells
// operators is one selector over everything this CA owns. It used to be two
// copies -- one in internal/k8sexport, one in internal/certstore -- each
// asserting in a comment that it matched the other, and nothing checking.
var _ = Describe("WithManagedByLabel", func() {
	It("is the value the documented selector uses", func() {
		// Written out rather than referenced, so a change to the constant has
		// to be a deliberate edit here too: this string appears in operator
		// documentation and in the chart, and changing it orphans every object
		// already carrying the old one.
		Expect(k8sclient.ManagedByLabelKey).To(Equal("app.kubernetes.io/managed-by"))
		Expect(k8sclient.ManagedByLabelValue).To(Equal("openvox-ca"))
	})

	It("adds the label to configured labels", func() {
		Expect(k8sclient.WithManagedByLabel(map[string]string{"app": "puppetserver"})).
			To(Equal(map[string]string{
				"app":                          "puppetserver",
				"app.kubernetes.io/managed-by": "openvox-ca",
			}))
	})

	It("wins over a configured value for the same key", func() {
		// Ownership must not be maskable by configuration: a selector that
		// skipped an object this CA is overwriting is worse than none.
		Expect(k8sclient.WithManagedByLabel(map[string]string{
			"app.kubernetes.io/managed-by": "flux",
		})).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
	})

	It("does not modify what it was given", func() {
		// Callers hold configuration that is read again on the next pass, so a
		// helper that wrote into it would accumulate across reconciles.
		configured := map[string]string{"app": "puppetserver"}
		k8sclient.WithManagedByLabel(configured)
		Expect(configured).To(Equal(map[string]string{"app": "puppetserver"}))
	})

	It("works on a nil map, which is what an unconfigured entry has", func() {
		Expect(k8sclient.WithManagedByLabel(nil)).
			To(Equal(map[string]string{"app.kubernetes.io/managed-by": "openvox-ca"}))
	})
})
