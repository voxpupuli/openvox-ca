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
	"context"
	"crypto/x509"
	"log/slog"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// specCADir is the cadir these specs run the server under. It is not a real
// directory: caOwnedPaths only compares it, and the path check is lexical on
// purpose so that it works on a configuration whose files do not exist yet.
const specCADir = "/var/lib/openvox-ca-spec"

// stubCACerts stands in for the storage service, which is the only thing a
// store needs from the CA at build time.
type stubCACerts struct{}

func (stubCACerts) GetCACert(context.Context) ([]byte, error) { return []byte("CA"), nil }

// writeServerConfig writes a config file and loads it the way the server does,
// so these specs exercise the YAML an operator writes rather than a struct
// literal. A `managed_certs` key that was misspelled in the struct tag would
// decode into nothing and every spec below would pass vacuously.
func writeServerConfig(doc string) *serverConfig {
	GinkgoHelper()
	path := filepath.Join(GinkgoT().TempDir(), "config.yaml")
	Expect(os.WriteFile(path, []byte(doc), 0o600)).To(Succeed())
	cfg, err := loadServerConfig(path)
	Expect(err).NotTo(HaveOccurred())
	return cfg
}

var _ = Describe("managed_certs, as the server reads it", func() {
	It("is dormant when nothing is configured", func() {
		cfg := writeServerConfig("hostname: ca.example.com\n")

		managed, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
		Expect(managed).To(BeEmpty())
	})

	It("reads an entry out of the config file", func() {
		cfg := writeServerConfig(`
managed_certs:
  - certname: puppetserver.openvox.svc.cluster.local
    names: [puppetserver, puppetserver.openvox.svc]
    ttl: 2160h
    renew_before: 720h
    revoke_after: 24h
    store:
      files:
        cert: /tmp/openvox-ca-spec/cert.pem
        key: /tmp/openvox-ca-spec/key.pem
`)
		Expect(cfg.ManagedCerts).To(HaveLen(1))

		managed, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
		Expect(managed).To(HaveLen(1))
		Expect(managed[0].Spec.Subject).To(Equal("puppetserver.openvox.svc.cluster.local"))
		Expect(managed[0].Spec.DNSNames).To(HaveLen(2))
		Expect(managed[0].Load).NotTo(BeNil())
		Expect(managed[0].Save).NotTo(BeNil())
	})

	// Fail-fast, like the storage and kubernetes_export blocks. Every failure
	// reachable here is a configuration failure rather than a transient one,
	// and a CA that came up serving while quietly issuing none of the
	// certificates an operator configured would be discovered by whichever
	// component failed to start.
	It("refuses a configuration that could never issue", func() {
		cfg := writeServerConfig(`
managed_certs:
  - certname: a.example.com
    names: [a]
    store: {files: {cert: /c.pem, key: /k.pem}}
`)
		_, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		Expect(err).To(MatchError(ContainSubstring("invalid managed_certs config")))
		Expect(err).To(MatchError(ContainSubstring("renew_before must be positive")))
	})

	It("refuses a Secret that is also a kubernetes_export target", func() {
		cfg := writeServerConfig(`
kubernetes_export:
  targets:
    - kind: Secret
      metadata: {name: puppetserver-tls, namespace: openvox}
      cert: true
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: puppetserver-tls, namespace: openvox}}
`)
		_, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		Expect(err).To(MatchError(ContainSubstring("kubernetes_export target")))
	})

	// The file-store sibling of the export-overlap refusal above: the entry
	// names a path the CA itself owns, and issuance would overwrite it.
	It("refuses a file store inside the cadir", func() {
		cfg := writeServerConfig(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store:
      files:
        cert: /var/lib/openvox-ca-spec/ca/ca_crt.pem
        key: /var/lib/openvox-ca-spec/ca/ca_key.pem
`)
		_, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		Expect(err).To(MatchError(ContainSubstring("invalid managed_certs config")))
		Expect(err).To(MatchError(ContainSubstring("is inside cadir")))
		// The cert is checked before the key, so the first path reported is
		// the certificate -- which pins that the whole entry is scanned rather
		// than only its key.
		Expect(err).To(MatchError(ContainSubstring("/var/lib/openvox-ca-spec/ca/ca_crt.pem")))
	})

	It("refuses a file store that is the CA's own serving key", func() {
		cfg := writeServerConfig(`
tls_key: /etc/openvox-ca/serving-key.pem
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store:
      files:
        cert: /etc/openvox-ca/a.pem
        key: /etc/openvox-ca/serving-key.pem
`)
		_, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		Expect(err).To(MatchError(ContainSubstring("is tls_key")))
	})

	// The cadir prefix is a directory boundary, not a string one. Without the
	// separator this path would read as being inside specCADir and the spec
	// above would pass for a reason that also refuses this legitimate one.
	It("allows a sibling directory sharing the cadir's prefix", func() {
		cfg := writeServerConfig(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store:
      files:
        cert: /var/lib/openvox-ca-spec-components/a.pem
        key: /var/lib/openvox-ca-spec-components/a-key.pem
`)
		managed, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
		Expect(managed).To(HaveLen(1))
	})

	// A file-only configuration is the systemd shape, and must not need a
	// cluster. This suite does not run in one, so the spec is the assertion:
	// if the gate were wrong, building the client would fail here.
	It("needs no cluster for a file-only configuration", func() {
		cfg := writeServerConfig(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`)
		managed, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
		Expect(managed).To(HaveLen(1))
	})

	It("says which setting is at fault when a Secret store is configured outside a cluster", func() {
		cfg := writeServerConfig(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: a-tls, namespace: openvox}}
`)
		_, err := buildManagedCerts(cfg, specCADir, stubCACerts{})
		// Anchored to a string only k8sclient.InClusterClientset produces.
		// "inside a pod" and "Secret store" both appear in certstore.Build's
		// own refusal too, so asserting those alone would pass even if the
		// whole client-construction branch were removed.
		Expect(err).To(MatchError(ContainSubstring("loading in-cluster Kubernetes config")))
		Expect(err).To(MatchError(ContainSubstring("Secret store")))
	})
})

var _ = Describe("the export targets a managed certificate is checked against", func() {
	It("lists Secret targets, whatever case the kind was written in", func() {
		cfg := k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "secret", Metadata: k8sexport.Metadata{Name: "a", Namespace: "ns"}},
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "b"}},
		}}
		Expect(exportSecretTargets(cfg)).To(Equal([][2]string{{"ns", "a"}, {"", "b"}}))
	})

	// A ConfigMap cannot be a managed certificate's store, so an overlap with
	// one is impossible and reporting it would be a false refusal.
	It("ignores ConfigMap targets", func() {
		cfg := k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "a", Namespace: "ns"}},
		}}
		Expect(exportSecretTargets(cfg)).To(BeEmpty())
	})
})

var _ = Describe("saying when a managed certificate is an admin credential", func() {
	// SECURITY: a certname listed in puppet_server is an administrator, and
	// clientAuth is what lets the certificate be presented. The two together
	// are an admin credential, so the store holding that key is one -- which is
	// the intended configuration for OpenVox Server, and exactly why it is
	// said out loud rather than left to be inferred.
	It("warns when the certname is listed in puppet_server", func() {
		cfg := &serverConfig{PuppetServer: "puppetserver.example.com, other.example.com"}
		managed := []ca.ManagedCert{{Spec: ca.CertSpec{Subject: "puppetserver.example.com"}}}

		out := captureLogs(slog.LevelWarn, func() { warnIfManagedCertIsAdmin(cfg, managed) })
		Expect(out).To(ContainSubstring("CA admin credential"))
		Expect(out).To(ContainSubstring("puppetserver.example.com"))
		// The two warnings are alternatives, not a pair. Without this the
		// `continue` separating them can be deleted and both fire for one
		// entry, telling an operator in consecutive lines that a certificate
		// both is and is not an admin credential.
		Expect(out).NotTo(ContainSubstring("does not carry clientAuth"))
	})

	It("says nothing about a certname nobody listed", func() {
		cfg := &serverConfig{PuppetServer: "other.example.com"}
		managed := []ca.ManagedCert{{Spec: ca.CertSpec{Subject: "puppetserver.example.com"}}}

		out := captureLogs(slog.LevelWarn, func() { warnIfManagedCertIsAdmin(cfg, managed) })
		Expect(out).To(BeEmpty(), "an unlisted certname warrants no warning at all")
	})

	// The listing grants authority the certificate cannot use, which is
	// usually a mistake in one setting or the other.
	It("says so when a listed certname cannot be presented as a client", func() {
		cfg := &serverConfig{PuppetServer: "puppetserver.example.com"}
		managed := []ca.ManagedCert{{Spec: ca.CertSpec{
			Subject:     "puppetserver.example.com",
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}}}

		out := captureLogs(slog.LevelWarn, func() { warnIfManagedCertIsAdmin(cfg, managed) })
		Expect(out).To(ContainSubstring("does not carry clientAuth"))
		Expect(out).NotTo(ContainSubstring("CA admin credential"))
	})

	// An unset usage list means the serverAuth+clientAuth pair every other
	// issuance path uses, so it is an admin credential too -- and this is the
	// arm an operator actually configures, since nothing in the example sets
	// usages at all.
	It("counts an entry that never mentioned usages", func() {
		Expect(carriesClientAuth(ca.CertSpec{})).To(BeTrue())
	})

	It("does not count one narrowed away from clientAuth", func() {
		Expect(carriesClientAuth(ca.CertSpec{
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})).To(BeFalse())
	})

	// Through buildManagedCerts rather than by calling the function directly,
	// which is what pins the call site, its ordering after Build, and the
	// subject actually reaching the warning. Delete the call from
	// buildManagedCerts and every spec above stays green.
	//
	// The certname is listed in puppet_server_file rather than puppet_server,
	// so this also pins that the allow list comes from buildAdminAllowList: a
	// hand-rolled comma split of puppet_server would lose every administrator
	// named in the file, silently.
	It("warns from startup, for a certname listed only in puppet_server_file", func() {
		dir := GinkgoT().TempDir()
		cnFile := filepath.Join(dir, "puppet-server")
		Expect(os.WriteFile(cnFile, []byte("puppetserver.example.com\n"), 0o600)).To(Succeed())

		cfg := writeServerConfig(`
puppet_server_file: ` + cnFile + `
managed_certs:
  - certname: puppetserver.example.com
    names: [puppetserver.example.com]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`)
		var managed []ca.ManagedCert
		out := captureLogs(slog.LevelWarn, func() {
			var err error
			managed, err = buildManagedCerts(cfg, specCADir, stubCACerts{})
			Expect(err).NotTo(HaveOccurred())
		})
		Expect(managed).To(HaveLen(1))
		Expect(out).To(ContainSubstring("CA admin credential"))
		Expect(out).To(ContainSubstring("puppetserver.example.com"))
	})
})
