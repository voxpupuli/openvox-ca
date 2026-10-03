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

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// jobNames reduces the job list to the names it contains, which is what these
// specs are about: which jobs a configuration starts, not what they do.
//
// The CA is a fresh one, so this answers for configuration alone. A job gated
// on the CA's own state -- the managed-certificate reconciler is -- needs
// jobNamesForCA, which takes the CA the caller has arranged.
func jobNames(cfg *serverConfig) []string {
	GinkgoHelper()
	c, _ := newRefresherTestCA()
	return jobNamesForCA(cfg, c)
}

var _ = Describe("backgroundJobs", func() {
	// The default backend is filesystem, so the default job set deliberately
	// does not include the OCSP index sync; the table below owns that decision.
	It("runs CRL refresh, CRL sync and the superseded sweep by default, and cleanup only on request", func() {
		Expect(jobNames(&serverConfig{})).To(ConsistOf(jobCRLRefresh, jobCRLSync, jobSupersededSweep))
		Expect(jobNames(&serverConfig{EnableExpiredCertCleanup: true})).
			To(ConsistOf(jobCRLRefresh, jobCRLSync, jobSupersededSweep, jobCertCleanup))
	})

	// The same promise as the CRL-sync one below, for the other list a
	// configuration change can strand. superseded_cert_revoke_after_sec decides
	// whether a renewal *records* a delayed revocation; it must not also decide
	// whether revocations already recorded are ever carried out. An operator who
	// grants a window, accrues entries and then sets the delay back to zero
	// still has those entries, each with its own recorded due time — and gating
	// the sweep on the delay would leave every one of them a live credential,
	// with the job that would retire them switched off by the change meant to
	// tighten things up.
	It("runs the superseded sweep even with no delay configured", func() {
		Expect(jobNames(&serverConfig{SupersededCertRevokeAfterSec: 0})).
			To(ContainElement(jobSupersededSweep),
				"a zero delay must still drain a list an earlier configuration filled")
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

	It("still runs both sync jobs and the superseded sweep when every other job is switched off", func() {
		Expect(jobNames(&serverConfig{
			StorageConfig:            config.StorageConfig{StorageBackend: "etcd"},
			DisableCRLRefresh:        true,
			EnableExpiredCertCleanup: false,
		})).To(ConsistOf(jobCRLSync, jobOCSPIndexSync, jobSupersededSweep))
	})

	// The OCSP index goes stale when a *second* process issues certificates
	// this one will not hear about, which is a property of the backend and of
	// nothing else. filesystem and SQLite are a local file with no
	// cross-process coordination, so there is no supported way to have that
	// second writer; every other backend is reachable by several replicas by
	// design.
	//
	// A table rather than two examples, because the cost of getting one entry
	// wrong is asymmetric and invisible: a backend wrongly called single-node
	// answers `unknown` for its peers' certificates until someone restarts it,
	// and nothing in the logs says why.
	DescribeTable("starts the OCSP index sync only where a second writer is possible",
		func(backend string, want bool) {
			names := jobNames(&serverConfig{StorageConfig: config.StorageConfig{StorageBackend: backend}})
			if want {
				Expect(names).To(ContainElement(jobOCSPIndexSync))
			} else {
				Expect(names).NotTo(ContainElement(jobOCSPIndexSync))
			}
		},
		Entry("filesystem", "filesystem", false),
		Entry("the empty default, which is filesystem", "", false),
		Entry("sqlite", "sqlite", false),
		Entry("etcd", "etcd", true),
		Entry("redis", "redis", true),
		Entry("postgres", "postgres", true),
		Entry("mysql", "mysql", true),
		// Unparseable: run it. A needless read is the cheaper mistake.
		Entry("a name that does not parse", "no-such-backend", true),
	)

	// Not gated on ocsp_url, which is a different question: that setting
	// decides whether issued certificates carry an AIA extension pointing here,
	// while /ocsp answers either way. On a shared backend the job runs whatever
	// it says, so an operator distributing the responder URL by another route
	// still gets correct answers.
	It("runs the OCSP index sync on a shared backend whatever ocsp_url says", func() {
		Expect(jobNames(&serverConfig{StorageConfig: config.StorageConfig{StorageBackend: "etcd"}})).To(ContainElement(jobOCSPIndexSync))
		Expect(jobNames(&serverConfig{StorageConfig: config.StorageConfig{StorageBackend: "etcd"}, OCSPUrl: "http://ca.example.com:8140/ocsp"})).
			To(ContainElement(jobOCSPIndexSync))
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

		// Every other switch off, chain file set: it still runs. ConsistOf
		// rather than ContainElement deliberately -- the claim is that nothing
		// else is required for the chain refresh to be scheduled, and only an
		// exhaustive assertion can carry it. jobSupersededSweep is in the set
		// because it registers unconditionally, delay or no delay, so that it
		// can drain a list an earlier configuration may have filled.
		Expect(jobNames(&serverConfig{
			DisableCRLRefresh:        true,
			EnableExpiredCertCleanup: false,
			CRLChainFile:             "/etc/openvox-ca/upstream-crls.pem",
		})).To(ConsistOf(jobCRLSync, jobSupersededSweep, jobCRLChainRefresh))
	})
})
