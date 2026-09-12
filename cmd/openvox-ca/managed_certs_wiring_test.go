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

// managed_certs_config_test.go covers buildManagedCerts in isolation, and
// managed_certs_test.go covers the reconcile pass against a CA whose
// ManagedCerts the spec sets by hand. Neither notices if the line that carries
// the built entries into the CA is dropped: ca.CA.ManagedCerts stays nil, the
// reconcile job is never registered, the configured gauge is never emitted,
// PuppetCAManagedCertificateNeverIssued has nothing to match, and CI stays
// green while no certificate is ever issued.
//
// The sibling of signing_concurrency_wiring_test.go, and the same class of gap.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// jobNamesForCA is jobNames against a CA the caller supplies, which is what
// these specs need: the reconcile job is gated on that CA's ManagedCerts, so a
// helper that builds its own cannot observe the gate at all. jobNames, whose
// specs care only about configuration, delegates here.
func jobNamesForCA(cfg *serverConfig, myCA *ca.CA) []string {
	GinkgoHelper()
	names := make([]string, 0, 4)
	for _, job := range backgroundJobs(cfg, myCA) {
		Expect(job.run).NotTo(BeNil(), "job %q has no runner", job.name)
		names = append(names, job.name)
	}
	return names
}

var _ = Describe("managed_certs wiring", func() {
	newCA := func() *ca.CA {
		return ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
	}

	loadCfg := func(body string) *serverConfig {
		GinkgoHelper()
		path := filepath.Join(GinkgoT().TempDir(), "openvox-ca.yaml")
		Expect(os.WriteFile(path, []byte(body), 0o600)).To(Succeed())
		cfg, err := loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred())
		return cfg
	}

	const twoEntries = `
managed_certs:
  - certname: puppetserver.openvox.svc.cluster.local
    names: [puppetserver]
    renew_before: 720h
    store: {files: {cert: /srv/components/ps.pem, key: /srv/components/ps-key.pem}}
  - certname: puppetdb.openvox.svc.cluster.local
    names: [puppetdb]
    renew_before: 720h
    store: {files: {cert: /srv/components/pdb.pem, key: /srv/components/pdb-key.pem}}
`

	It("reaches the CA", func() {
		myCA := newCA()
		Expect(attachManagedCerts(myCA, loadCfg(twoEntries), specCADir, specConfigPath, stubCACerts{})).To(Succeed())

		Expect(myCA.ManagedCerts).To(HaveLen(2))
		Expect(myCA.ManagedCerts[0].Spec.Subject).To(Equal("puppetserver.openvox.svc.cluster.local"))
		Expect(myCA.ManagedCerts[1].Spec.Subject).To(Equal("puppetdb.openvox.svc.cluster.local"))
		// The store closures, because entries that reached the CA without them
		// would be walked by the reconcile pass and could neither load nor save.
		Expect(myCA.ManagedCerts[0].Load).NotTo(BeNil())
		Expect(myCA.ManagedCerts[0].Save).NotTo(BeNil())
	})

	// What the assignment being present is worth: it is what decides whether the
	// reconcile job runs at all. Asserting the field alone would leave the job
	// gate free to stop reading it.
	It("is what registers the reconcile job", func() {
		cfg := loadCfg(twoEntries)
		myCA := newCA()
		Expect(myCA.ManagedCerts).To(BeEmpty(), "precondition: a bare CA manages nothing")
		Expect(jobNamesForCA(cfg, myCA)).NotTo(ContainElement(jobManagedCerts))

		Expect(attachManagedCerts(myCA, cfg, specCADir, specConfigPath, stubCACerts{})).To(Succeed())
		Expect(jobNamesForCA(cfg, myCA)).To(ContainElement(jobManagedCerts))
	})

	// The dormant case, which is what almost every deployment gets: no
	// managed_certs block must leave the CA managing nothing and the job
	// unregistered, rather than registering a loop with an empty list.
	It("leaves the CA alone when nothing is configured", func() {
		myCA := newCA()
		Expect(attachManagedCerts(myCA, loadCfg("hostname: ca.example.com\n"),
			specCADir, specConfigPath, stubCACerts{})).To(Succeed())

		Expect(myCA.ManagedCerts).To(BeEmpty())
		Expect(jobNamesForCA(loadCfg("hostname: ca.example.com\n"), myCA)).
			NotTo(ContainElement(jobManagedCerts))
	})

	// The call site, which the specs above do not reach.
	//
	// They drive attachManagedCerts directly, so all of them stay green if the
	// serve command simply stops calling it -- which was demonstrated by
	// mutation, not assumed: dropping the call from main.go left every spec in
	// this file passing. A behavioural spec would have to start the server,
	// bind its listeners and reach a running reconcile pass, which is what the
	// compose integration suite does and a unit spec should not.
	//
	// So this reads the source instead. It is a weaker guarantee than
	// behaviour -- it pins that the call is written, not that it runs -- but it
	// closes the hole the mutation found, and it fails for the one edit that
	// silently disables the whole feature. The same technique as
	// internal/api/authseam_test.go, which parses the tree to decide what
	// imports what.
	It("is called by the serve command", func() {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "main.go", nil, 0)
		Expect(err).NotTo(HaveOccurred())

		var called bool
		var funcsSeen int
		ast.Inspect(file, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				funcsSeen++
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "attachManagedCerts" {
				called = true
			}
			return true
		})

		// The parse must have found something to judge. A file that failed to
		// yield any function literal would agree with every claim below.
		Expect(funcsSeen).To(BeNumerically(">", 0),
			"precondition: main.go parsed but contains no function literals")
		Expect(called).To(BeTrue(),
			"main.go does not call attachManagedCerts, so no configured managed "+
				"certificate would ever be issued, and every other spec in this "+
				"file would still pass")
	})

	It("refuses to start when the configuration could never issue", func() {
		myCA := newCA()
		err := attachManagedCerts(myCA, loadCfg(`
managed_certs:
  - certname: a.example.com
    names: [a]
    store: {files: {cert: /srv/a.pem, key: /srv/a-key.pem}}
`), specCADir, specConfigPath, stubCACerts{})

		Expect(err).To(MatchError(ContainSubstring("renew_before must be positive")))
		Expect(myCA.ManagedCerts).To(BeEmpty(),
			"a refused configuration must not leave half a list on the CA")
	})
})
