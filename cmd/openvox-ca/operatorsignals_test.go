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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
)

var _ = Describe("openvoxca_destructive_operations_total", func() {
	values := func(reg *prometheus.Registry) map[string]float64 {
		GinkgoHelper()
		mfs, err := reg.Gather()
		Expect(err).NotTo(HaveOccurred())
		Expect(mfs).To(HaveLen(1))
		Expect(mfs[0].GetName()).To(Equal("openvoxca_destructive_operations_total"))
		out := map[string]float64{}
		for _, m := range mfs[0].GetMetric() {
			Expect(m.GetLabel()).To(HaveLen(1))
			Expect(m.GetLabel()[0].GetName()).To(Equal("operation"))
			out[m.GetLabel()[0].GetValue()] = m.GetCounter().GetValue()
		}
		return out
	}

	It("publishes every operation at zero before the first one happens", func() {
		// The mixin's alert is an increase() over this series, and increase()
		// over a series that does not exist yet never fires: the first burst
		// after a restart would go unseen.
		reg := prometheus.NewRegistry()
		newDestructiveOperationsCounter(reg)
		Expect(values(reg)).To(Equal(map[string]float64{"revoke": 0, "clean": 0, "bulk-clean": 0}))
	})

	It("adds each report's subjects to its operation", func() {
		reg := prometheus.NewRegistry()
		report := newDestructiveOperationsCounter(reg)
		report("bulk-clean", 3)
		report("revoke", 1)
		report("bulk-clean", 2)
		Expect(values(reg)).To(Equal(map[string]float64{"revoke": 1, "clean": 0, "bulk-clean": 5}))
	})
})
