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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// mintCA issues a CA certificate, self-signed when parent is nil.
func mintCA(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return cert, key
}

// writeCertFile writes certs to a PEM bundle and returns its path.
func writeCertFile(certs ...*x509.Certificate) string {
	GinkgoHelper()
	path := filepath.Join(GinkgoT().TempDir(), "anchors.pem")
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	Expect(os.WriteFile(path, out, 0o644)).To(Succeed())
	return path
}

var _ = Describe("client_ca configuration", func() {
	Describe("Validate", func() {
		It("accepts an empty block, which is the default", func() {
			cfg := &config.ClientCAConfig{}
			Expect(cfg.Validate()).To(Succeed())
			Expect(cfg.Enabled()).To(BeFalse())
			Expect(cfg.Policy()).To(Equal("require"))
		})

		It("defaults the policy to require", func() {
			// Not check or skip: an unset policy must not default into a hole.
			cfg := &config.ClientCAConfig{ClientCA: []config.ClientCA{
				{Name: "server", File: "/x.pem", CRLFile: "/x-crl.pem"},
			}}
			Expect(cfg.Validate()).To(Succeed())
			Expect(cfg.Policy()).To(Equal("require"))
		})

		It("rejects an unknown policy", func() {
			cfg := &config.ClientCAConfig{ClientRevocationPolicy: "maybe"}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("invalid client_revocation_policy")))
		})

		It("requires a name", func() {
			cfg := &config.ClientCAConfig{ClientCA: []config.ClientCA{{File: "/x.pem", CRLFile: "/c.pem"}}}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("name is required")))
		})

		It("rejects duplicate names, which would make logs and metrics ambiguous", func() {
			cfg := &config.ClientCAConfig{ClientCA: []config.ClientCA{
				{Name: "dup", File: "/a.pem", CRLFile: "/a-crl.pem"},
				{Name: "dup", File: "/b.pem", CRLFile: "/b-crl.pem"},
			}}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("duplicate name")))
		})

		It("requires a file", func() {
			cfg := &config.ClientCAConfig{ClientCA: []config.ClientCA{{Name: "server"}}}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("file is required")))
		})

		It("requires a crl_file under the require policy", func() {
			// Under require an issuer with no CRL rejects every one of its
			// clients, so the alternative is a fleet-wide 403 whose cause is
			// three layers from where an operator would look.
			cfg := &config.ClientCAConfig{ClientCA: []config.ClientCA{{Name: "server", File: "/x.pem"}}}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("crl_file is required")))
		})

		It("allows a missing crl_file under check", func() {
			cfg := &config.ClientCAConfig{
				ClientRevocationPolicy: "check",
				ClientCA:               []config.ClientCA{{Name: "server", File: "/x.pem"}},
			}
			Expect(cfg.Validate()).To(Succeed())
		})
	})

	Describe("buildTrustDomains", func() {
		var (
			ownCA    *x509.Certificate
			root     *x509.Certificate
			serverCA *x509.Certificate
		)

		BeforeEach(func() {
			ownCA, _ = mintCA("Own CA", nil, nil)
			var rootKey *ecdsa.PrivateKey
			root, rootKey = mintCA("Shared Root", nil, nil)
			serverCA, _ = mintCA("Server CA", root, rootKey)
		})

		It("puts our own CA first, always", func() {
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{{Name: "server", File: writeCertFile(serverCA)}}

			domains, err := buildTrustDomains(cfg, ownCA, map[string]bool{"admin": true})
			Expect(err).NotTo(HaveOccurred())
			Expect(domains).To(HaveLen(2))
			Expect(domains[0].IsOwn()).To(BeTrue())
			Expect(domains[0].AdminCNs).To(HaveKey("admin"))
			Expect(domains[1].Name).To(Equal("server"))
		})

		It("keeps configuration order, which the middleware relies on", func() {
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{
				{Name: "first", File: writeCertFile(serverCA)},
				{Name: "second", File: writeCertFile(root)},
			}
			domains, err := buildTrustDomains(cfg, ownCA, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(domains[1].Name).To(Equal("first"))
			Expect(domains[2].Name).To(Equal("second"))
		})

		It("grants no admin authority by default", func() {
			// Adding an entry authenticates an issuer without giving it
			// anything; both foreign grants are opt-in per entry.
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{{Name: "server", File: writeCertFile(serverCA)}}

			domains, err := buildTrustDomains(cfg, ownCA, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(domains[1].AdminCNs).To(BeEmpty())
			Expect(domains[1].PpCliAuth).To(BeFalse())
		})

		It("carries per-entry admin grants", func() {
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{{
				Name: "server", File: writeCertFile(serverCA),
				AdminCNs: []string{"openvox-server.example.com"}, AllowPpCliAuth: true,
			}}
			domains, err := buildTrustDomains(cfg, ownCA, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(domains[1].AdminCNs).To(HaveKey("openvox-server.example.com"))
			Expect(domains[1].PpCliAuth).To(BeTrue())
		})

		It("keeps our own pp_cli_auth default untouched", func() {
			cfg := &serverConfig{}
			domains, err := buildTrustDomains(cfg, ownCA, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(domains[0].PpCliAuth).To(BeTrue(), "on by default, as it has always been")

			cfg.NoPpCliAuth = true
			domains, err = buildTrustDomains(cfg, ownCA, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(domains[0].PpCliAuth).To(BeFalse())
		})

		It("refuses to start when an anchor file is missing", func() {
			// Not a warning: under require an empty anchor pool rejects every
			// client of that domain, so a path typo would be a silent
			// authentication outage for one issuer while the CA looked healthy.
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{{
				Name: "server", File: filepath.Join(GinkgoT().TempDir(), "absent.pem"),
			}}
			_, err := buildTrustDomains(cfg, ownCA, nil)
			Expect(err).To(MatchError(ContainSubstring("server")))
		})

		It("refuses a bundle that parses to no certificates", func() {
			path := filepath.Join(GinkgoT().TempDir(), "empty.pem")
			Expect(os.WriteFile(path, []byte("# nothing here\n"), 0o644)).To(Succeed())
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{{Name: "server", File: path}}

			_, err := buildTrustDomains(cfg, ownCA, nil)
			Expect(err).To(MatchError(ContainSubstring("no certificates")))
		})

		It("accepts a self-signed root as an anchor, having warned", func() {
			// Legitimate when the root really is the intended boundary, so it
			// warns rather than refuses — but it is the natural mistake,
			// because "the CA bundle" usually means the whole chain.
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{{Name: "wide", File: writeCertFile(root)}}

			domains, err := buildTrustDomains(cfg, ownCA, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(domains).To(HaveLen(2))
		})
	})
})
