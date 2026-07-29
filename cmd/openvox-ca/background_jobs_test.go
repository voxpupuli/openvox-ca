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
)

// jobNames reduces the job list to the names it contains, which is what these
// specs are about: which jobs a configuration starts, not what they do.
func jobNames(cfg *serverConfig) []string {
	GinkgoHelper()
	c, _ := newRefresherTestCA()
	names := make([]string, 0, 3)
	for _, job := range backgroundJobs(cfg, c) {
		Expect(job.run).NotTo(BeNil(), "job %q has no runner", job.name)
		names = append(names, job.name)
	}
	return names
}

var _ = Describe("backgroundJobs", func() {
	It("runs CRL refresh and CRL sync by default, and cleanup only on request", func() {
		Expect(jobNames(&serverConfig{})).To(ConsistOf(jobCRLRefresh, jobCRLSync))
		Expect(jobNames(&serverConfig{EnableExpiredCertCleanup: true})).
			To(ConsistOf(jobCRLRefresh, jobCRLSync, jobCertCleanup))
	})

	// The promise this whole change rests on. disable_crl_refresh governs
	// whether this deployment re-signs the CRL — an operator may drive that
	// externally — and must not also decide whether revocations performed on
	// another replica reach this one. Before backgroundJobs existed the two
	// goroutine starts were adjacent statements in the serve command told apart
	// only by which side of a brace they sat on, and nothing could observe it.
	It("keeps CRL sync running when disable_crl_refresh turns off re-signing", func() {
		names := jobNames(&serverConfig{DisableCRLRefresh: true})
		Expect(names).To(ContainElement(jobCRLSync),
			"disabling CRL refresh must not disable revocation propagation")
		Expect(names).NotTo(ContainElement(jobCRLRefresh))
	})

	It("still runs CRL sync when every other job is switched off", func() {
		Expect(jobNames(&serverConfig{DisableCRLRefresh: true, EnableExpiredCertCleanup: false})).
			To(ConsistOf(jobCRLSync))
	})

	// crl_chain_file gates the chain refresh on its own, and nothing else gates
	// it. The failure this pins is not "the job is missing" but "the job is
	// there and never runs": the ancestor CRLs would be read once at startup
	// and never again, and under Puppet's default certificate_revocation =
	// chain an ancestor CRL that lapses afterwards is a fleet-wide verification
	// failure that clears only on restart. Gating it on any other feature --
	// re-signing, cleanup, a serving certificate -- puts that outcome behind a
	// switch that has nothing to do with it.
	It("runs the chain refresh when crl_chain_file is set, and only then", func() {
		Expect(jobNames(&serverConfig{})).NotTo(ContainElement(jobCRLChainRefresh))
		Expect(jobNames(&serverConfig{CRLChainFile: "/etc/openvox-ca/upstream-crls.pem"})).
			To(ContainElement(jobCRLChainRefresh))

		// Every other switch off, chain file set: it still runs.
		Expect(jobNames(&serverConfig{
			DisableCRLRefresh:        true,
			EnableExpiredCertCleanup: false,
			CRLChainFile:             "/etc/openvox-ca/upstream-crls.pem",
		})).To(ConsistOf(jobCRLSync, jobCRLChainRefresh))
	})
})
