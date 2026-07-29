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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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
			Expect(domains[0].IsAdminCN("admin")).To(BeTrue())
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
			Expect(domains[1].IsAdminCN("openvox-server.example.com")).To(BeFalse(),
				"an entry with no admin_cns grants admin to nobody")
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
			Expect(domains[1].IsAdminCN("openvox-server.example.com")).To(BeTrue())
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

// writeCRLFile writes CRLs to a PEM bundle and returns its path.
func writeCRLFile(crls ...*x509.RevocationList) string {
	GinkgoHelper()
	path := filepath.Join(GinkgoT().TempDir(), "crls.pem")
	var out []byte
	for _, c := range crls {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: c.Raw})...)
	}
	Expect(os.WriteFile(path, out, 0o644)).To(Succeed())
	return path
}

// mintCRL issues a CRL from cert, valid for an hour.
func mintCRL(cert *x509.Certificate, key *ecdsa.PrivateKey, revoked ...*big.Int) *x509.RevocationList {
	GinkgoHelper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, serial := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(time.Now().UnixNano()),
		RevokedCertificateEntries: entries,
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(time.Hour),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

var _ = Describe("client_ca CRL loading", func() {
	var (
		root      *x509.Certificate
		rootKey   *ecdsa.PrivateKey
		serverCA  *x509.Certificate
		serverKey *ecdsa.PrivateKey
		otherCA   *x509.Certificate
		otherKey  *ecdsa.PrivateKey
		ownCA     *x509.Certificate
	)

	BeforeEach(func() {
		ownCA, _ = mintCA("Own CA", nil, nil)
		root, rootKey = mintCA("Shared Root", nil, nil)
		serverCA, serverKey = mintCA("Server CA", root, rootKey)
		otherCA, otherKey = mintCA("Unrelated CA", nil, nil)
	})

	build := func(entry config.ClientCA) ([]byte, error) {
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{entry}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		if err != nil {
			return nil, err
		}
		Expect(domains).To(HaveLen(2))
		return nil, nil
	}

	It("refuses to start when crl_file cannot be read", func() {
		// The anchor bundle beside it already fails closed. A server that starts
		// here rejects every client of the domain under require, and the
		// readiness probe does not notice — so an orchestrator routes traffic to
		// it.
		_, err := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: filepath.Join(GinkgoT().TempDir(), "absent.pem"),
		})
		Expect(err).To(MatchError(ContainSubstring("reading crl_file")))
	})

	It("refuses to start when crl_file holds an unparseable CRL", func() {
		path := filepath.Join(GinkgoT().TempDir(), "bad.pem")
		Expect(os.WriteFile(path, []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n"), 0o644)).To(Succeed())

		_, err := build(config.ClientCA{Name: "server", File: writeCertFile(serverCA), CRLFile: path})
		Expect(err).To(MatchError(ContainSubstring("parsing CRL 1")))
	})

	It("discards a CRL no anchor in this entry signed", func() {
		// SECURITY: without the check a writable crl_file is a way to *clear*
		// revocations — replace a CRL naming a revoked certificate with one
		// signed by anything else, and that certificate is valid again.
		_, err := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(mintCRL(otherCA, otherKey)),
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("discards a CRL with no Authority Key Identifier", func() {
		// Issuers are matched by AKI, never by DN: under a shared root two
		// siblings can carry the same DN, and a DN fallback would consult the
		// wrong CA's revocations.
		_, err := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(crlWithoutAKI(serverCA, serverKey)),
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("loads a CRL its own anchor signed", func() {
		_, err := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey)),
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("starts, having warned, when a root anchor leaves no usable CRLs", func() {
		// The configuration that locks everyone out: anchored on the shared
		// root, the Server CA's own CRL is signed by the Server CA and not by
		// the anchor, so it is discarded and every client is rejected under
		// require. Legitimate when the root really is the boundary, so a warning
		// rather than a refusal — but the warning has to name the consequence,
		// because the obvious fix is to switch to check and that silently stops
		// checking leaf revocation altogether.
		_, err := build(config.ClientCA{
			Name: "shared", File: writeCertFile(root),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey)),
		})
		Expect(err).NotTo(HaveOccurred())
	})
})

// crlWithoutAKI signs a CRL carrying no Authority Key Identifier.
//
// x509.CreateRevocationList always stamps one, so the DER is assembled directly.
// Without this fixture the "discards a CRL with no AKI" spec passes whether or
// not the guard exists: every CRL the standard library can produce has one.
func crlWithoutAKI(cert *x509.Certificate, key *ecdsa.PrivateKey) *x509.RevocationList {
	GinkgoHelper()
	algo := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	now := time.Now().UTC().Truncate(time.Second)

	type tbs struct {
		Version    int
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate time.Time
		NextUpdate time.Time `asn1:"optional"`
	}
	tbsDER, err := asn1.Marshal(tbs{
		Version:    1,
		Signature:  algo,
		Issuer:     asn1.RawValue{FullBytes: cert.RawSubject},
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(time.Hour),
	})
	Expect(err).NotTo(HaveOccurred())

	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	Expect(err).NotTo(HaveOccurred())

	type certList struct {
		TBS       asn1.RawValue
		Signature pkix.AlgorithmIdentifier
		Sig       asn1.BitString
	}
	der, err := asn1.Marshal(certList{
		TBS:       asn1.RawValue{FullBytes: tbsDER},
		Signature: algo,
		Sig:       asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	Expect(err).NotTo(HaveOccurred())

	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	Expect(crl.AuthorityKeyId).To(BeEmpty())
	return crl
}
