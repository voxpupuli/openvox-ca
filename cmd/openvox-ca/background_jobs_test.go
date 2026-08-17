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
	names := make([]string, 0, 4)
	for _, job := range backgroundJobs(cfg, c) {
		Expect(job.run).NotTo(BeNil(), "job %q has no runner", job.name)
		names = append(names, job.name)
	}
	return names
}

var _ = Describe("backgroundJobs", func() {
	It("runs CRL refresh and both sync jobs by default, and cleanup only on request", func() {
		Expect(jobNames(&serverConfig{})).To(ConsistOf(jobCRLRefresh, jobCRLSync, jobOCSPIndexSync))
		Expect(jobNames(&serverConfig{EnableExpiredCertCleanup: true})).
			To(ConsistOf(jobCRLRefresh, jobCRLSync, jobOCSPIndexSync, jobCertCleanup))
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

	It("still runs both sync jobs when every other job is switched off", func() {
		Expect(jobNames(&serverConfig{DisableCRLRefresh: true, EnableExpiredCertCleanup: false})).
			To(ConsistOf(jobCRLSync, jobOCSPIndexSync))
	})

	// The OCSP index sync has no switch of its own, and specifically is not
	// gated on ocsp_url. That setting decides whether issued certificates carry
	// an AIA extension pointing here; the /ocsp endpoint answers either way, so
	// gating on it would leave the responder saying "unknown" about valid
	// certificates for any operator who distributes the responder URL by another
	// route. There is no configuration in which the endpoint answers and the
	// index behind it is left to go stale.
	It("runs the OCSP index sync whatever ocsp_url says", func() {
		Expect(jobNames(&serverConfig{})).To(ContainElement(jobOCSPIndexSync))
		Expect(jobNames(&serverConfig{OCSPUrl: "http://ca.example.com:8140/ocsp"})).
			To(ContainElement(jobOCSPIndexSync))
	})
})
