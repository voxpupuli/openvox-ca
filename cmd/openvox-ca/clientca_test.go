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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/voxpupuli/openvox-ca/internal/api"
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

	// buildAuthConfig is the only path from operator configuration to what the
	// middleware trusts, and until now nothing called it with a client_ca
	// present: the specs below it exercise buildTrustDomains directly, so the
	// assembly around it -- validation, the admin allow list, the revocation
	// policy -- was reachable only by starting a server.
	Describe("buildAuthConfig", func() {
		var (
			serverCA *x509.Certificate
			caKey    *ecdsa.PrivateKey
		)

		BeforeEach(func() {
			root, rootKey := mintCA("Shared Root", nil, nil)
			serverCA, caKey = mintCA("Server CA", root, rootKey)
		})

		newCA := func() *ca.CA {
			store := storage.New(GinkgoT().TempDir())
			c := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			c.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(c.Init(context.Background())).To(Succeed())
			return c
		}

		It("assembles every configured domain, with ours first", func() {
			myCA := newCA()
			cfg := &serverConfig{PuppetServer: "compile-1.example.com"}
			cfg.ClientCA = []config.ClientCA{{
				Name: "server", File: writeCertFile(serverCA),
				CRLFile:  writeCRLFile(mintCRL(serverCA, caKey)),
				AdminCNs: []string{"ops-admin"},
			}}

			authCfg, err := buildAuthConfig(cfg, myCA)
			Expect(err).NotTo(HaveOccurred())
			Expect(authCfg.Domains).To(HaveLen(2))

			// Domain zero takes the allow list from the flags, and only it.
			Expect(authCfg.Domains[0].IsOwn()).To(BeTrue())
			Expect(authCfg.Domains[0].IsAdminCN("compile-1.example.com")).To(BeTrue())
			Expect(authCfg.Domains[0].IsAdminCN("ops-admin")).To(BeFalse(),
				"a foreign entry's admin_cns must not grant admin in our own domain")

			// The foreign entry takes its own, and neither leaks the other way.
			Expect(authCfg.Domains[1].Name).To(Equal("server"))
			Expect(authCfg.Domains[1].IsAdminCN("ops-admin")).To(BeTrue())
			Expect(authCfg.Domains[1].IsAdminCN("compile-1.example.com")).To(BeFalse(),
				"our allow list must not grant admin in a foreign domain")
		})

		It("refuses to start on an invalid client_ca rather than trusting less than asked", func() {
			myCA := newCA()
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{{Name: "server"}} // no file

			_, err := buildAuthConfig(cfg, myCA)
			Expect(err).To(MatchError(ContainSubstring("client_ca")))
		})

		It("carries the resolved revocation policy through, defaulting to require", func() {
			myCA := newCA()
			cfg := &serverConfig{}
			cfg.ClientCA = []config.ClientCA{{
				Name: "server", File: writeCertFile(serverCA),
				CRLFile: writeCRLFile(mintCRL(serverCA, caKey)),
			}}

			authCfg, err := buildAuthConfig(cfg, myCA)
			Expect(err).NotTo(HaveOccurred())
			Expect(authCfg.ClientRevocationPolicy).To(Equal(config.RevocationRequire),
				"an unset policy must reach the middleware as require, not as empty")
		})

		It("builds one domain when no client_ca is configured", func() {
			myCA := newCA()
			authCfg, err := buildAuthConfig(&serverConfig{}, myCA)
			Expect(err).NotTo(HaveOccurred())
			Expect(authCfg.Domains).To(HaveLen(1))
			Expect(authCfg.Domains[0].IsOwn()).To(BeTrue())
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

// numberedCRLUntil is mintCRL with an explicit cRLNumber and NextUpdate, so a
// spec can order two CRLs from one issuer deliberately rather than relying on
// mintCRL's clock, and tell which of the two ended up installed.
func numberedCRLUntil(cert *x509.Certificate, key *ecdsa.PrivateKey, number int64, until time.Time, revoked ...*big.Int) *x509.RevocationList {
	GinkgoHelper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, serial := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		RevokedCertificateEntries: entries,
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                until,
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

// mintCRLUntil is mintCRL with an explicit NextUpdate, so a spec can
// distinguish which of two sets is installed using only the exported API:
// Usable at a time past the first CRL's expiry is true only for the second.
func mintCRLUntil(cert *x509.Certificate, key *ecdsa.PrivateKey, until time.Time) *x509.RevocationList {
	GinkgoHelper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(time.Now().UnixNano()),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: until,
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

	build := func(entry config.ClientCA) ([]api.TrustDomain, error) {
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{entry}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		if err != nil {
			return nil, err
		}
		Expect(domains).To(HaveLen(2))
		return domains, nil
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
		domains, err := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(mintCRL(otherCA, otherKey)),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(domains[1].RevocationSet().CoverageGaps(time.Now())).To(ConsistOf("Server CA"),
			"a spec named for a discard must be able to observe one")
	})

	It("keeps a CRL with no Authority Key Identifier, because matching is by signature", func() {
		// This spec used to be named "discards", for a guard that existed only to
		// serve AKI-based matching. Binding a CRL to the certificate that signed
		// it removed the need, and keeping the guard would only have lost
		// revocations: `openssl ca -gencrl` omits the extension under the stock
		// openssl.cnf, which is the generator this project's own migration guide
		// calls out.
		domains, err := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(crlWithoutAKI(serverCA, serverKey)),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(domains[1].RevocationSet().CoverageGaps(time.Now())).To(BeEmpty(),
			"the CRL must be loaded and attributed to its signer")
	})

	It("loads a CRL its own anchor signed", func() {
		domains, err := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey)),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(domains[1].RevocationSet().Usable(time.Now())).To(BeTrue())
		Expect(domains[1].RevocationSet().CoverageGaps(time.Now())).To(BeEmpty())
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
// The fixture survives the guard it was built for: it is now what shows that an
// AKI-less CRL is *used*, which no standard-library CRL could demonstrate.
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

var _ = Describe("refreshClientCRLs", func() {
	var (
		root      *x509.Certificate
		rootKey   *ecdsa.PrivateKey
		serverCA  *x509.Certificate
		serverKey *ecdsa.PrivateKey
		agentCA   *x509.Certificate
		agentKey  *ecdsa.PrivateKey
		ownCA     *x509.Certificate
		reg       *prometheus.Registry
		metrics   *clientCRLMetrics
	)

	BeforeEach(func() {
		ownCA, _ = mintCA("Own CA", nil, nil)
		root, rootKey = mintCA("Shared Root", nil, nil)
		serverCA, serverKey = mintCA("Server CA", root, rootKey)
		agentCA, agentKey = mintCA("Agent CA", root, rootKey)
		reg = prometheus.NewRegistry()
		metrics = newClientCRLMetrics(reg)
	})

	// gauge reads puppetca_client_crl_usable for one client_ca label.
	// gathered lists the metric family names currently registered, so a spec can
	// assert a series is absent -- which gauge() cannot, since it fails when the
	// family is missing.
	gathered := func() string {
		GinkgoHelper()
		families, err := reg.Gather()
		Expect(err).NotTo(HaveOccurred())
		var names []string
		for _, f := range families {
			names = append(names, f.GetName())
		}
		return strings.Join(names, " ")
	}

	lastReload := func(name string) float64 {
		GinkgoHelper()
		families, err := reg.Gather()
		Expect(err).NotTo(HaveOccurred())
		for _, f := range families {
			if f.GetName() != "puppetca_client_crl_last_reload_timestamp_seconds" {
				continue
			}
			for _, m := range f.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "client_ca" && l.GetValue() == name {
						return m.GetGauge().GetValue()
					}
				}
			}
		}
		Fail("no puppetca_client_crl_last_reload_timestamp_seconds for " + name)
		return 0
	}

	gauge := func(name string) float64 {
		GinkgoHelper()
		families, err := reg.Gather()
		Expect(err).NotTo(HaveOccurred())
		for _, f := range families {
			if f.GetName() != "puppetca_client_crl_usable" {
				continue
			}
			for _, m := range f.GetMetric() {
				for _, l := range m.GetLabel() {
					if l.GetName() == "client_ca" && l.GetValue() == name {
						return m.GetGauge().GetValue()
					}
				}
			}
		}
		Fail("no puppetca_client_crl_usable series for client_ca " + name)
		return 0
	}

	It("maps each entry to its own domain, not to a neighbour's", func() {
		// Domain zero is ours, so entry i is domain i+1. Get that offset wrong
		// by one and each entry's CRLs are installed on the wrong issuer —
		// which fails open or closed depending on the pairing, and looks
		// entirely healthy either way.
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{
			{Name: "server", File: writeCertFile(serverCA), CRLFile: writeCRLFile(mintCRL(serverCA, serverKey))},
			{Name: "agent", File: writeCertFile(agentCA), CRLFile: writeCRLFile(mintCRL(agentCA, agentKey))},
		}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(domains).To(HaveLen(3))

		refreshClientCRLs(cfg, domains, metrics)

		// Each domain must hold the CRL signed by its own anchor. A swapped
		// pairing leaves both sets non-empty, so the assertion is per-issuer.
		Expect(domains[1].RevocationSet().Usable(time.Now())).To(BeTrue())
		Expect(domains[2].RevocationSet().Usable(time.Now())).To(BeTrue())
		Expect(gauge("server")).To(Equal(1.0))
		Expect(gauge("agent")).To(Equal(1.0))

	})

	It("stamps the reload timestamp only when the file is actually applied", func() {
		// The staleness rule is the only thing covering the retain-previous
		// branches, and this gauge is its sole input. Stamping it on every pass
		// -- beside the zero-init, say -- would mean the series never goes stale
		// and the alert built for those branches could never fire.
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey)),
		}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		applied := lastReload("server")
		Expect(applied).To(BeNumerically(">", 0))

		// A reload that cannot read the file keeps the previous set and must not
		// advance the stamp -- that is exactly the state the alert reports.
		cfg.ClientCA[0].CRLFile = filepath.Join(GinkgoT().TempDir(), "gone.pem")
		refreshClientCRLs(cfg, domains, metrics)
		Expect(lastReload("server")).To(Equal(applied), "a failed reload is not an apply")
	})

	It("keeps the previous set and keeps publishing the gauge when a reload fails", func() {
		// The failure the review found five ways: skipping the metric left the
		// series uncreated, so an `== 0` alert could not fire on a domain whose
		// very first load failed.
		crlPath := writeCRLFile(mintCRL(serverCA, serverKey))
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{
			{Name: "server", File: writeCertFile(serverCA), CRLFile: crlPath},
		}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		Expect(gauge("server")).To(Equal(1.0))

		// Now make the file unreadable mid-flight.
		cfg.ClientCA[0].CRLFile = filepath.Join(GinkgoT().TempDir(), "vanished.pem")
		refreshClientCRLs(cfg, domains, metrics)

		Expect(domains[1].RevocationSet().Usable(time.Now())).To(BeTrue(),
			"a transient read error must not discard a working set")
		Expect(gauge("server")).To(Equal(1.0))
	})

	It("keeps the previous set when the file yields no usable CRLs", func() {
		// Readable, populated, and every CRL in it discarded as unverifiable.
		// Installing that empty set would reject every client of the domain on
		// a file the operator can see is not empty.
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{
			{Name: "server", File: writeCertFile(serverCA), CRLFile: writeCRLFile(mintCRL(serverCA, serverKey))},
		}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		Expect(gauge("server")).To(Equal(1.0))

		unrelated, unrelatedKey := mintCA("Unrelated CA", nil, nil)
		cfg.ClientCA[0].CRLFile = writeCRLFile(mintCRL(unrelated, unrelatedKey))
		refreshClientCRLs(cfg, domains, metrics)

		Expect(domains[1].RevocationSet().Usable(time.Now())).To(BeTrue())
		Expect(gauge("server")).To(Equal(1.0))
	})

	It("keeps the previous set when a reload covers fewer anchors than it did", func() {
		// The guard used to be "yielded nothing at all", which protected against
		// total failure and not against partial -- and partial is the likelier
		// of the two in the bundle-assembly topology that produces multi-anchor
		// entries. One upstream drops out, or one issuer rotates its key so its
		// new CRL no longer verifies, and the narrower set installed while the
		// good one was discarded, refusing every client of the anchor that went
		// missing. A wholly broken file, meanwhile, was safely retained.
		second, secondKey := mintCA("Second CA", nil, nil)
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{{
			Name: "pair",
			File: writeCertFile(serverCA, second),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey),
				mintCRL(second, secondKey)),
		}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		Expect(domains[1].RevocationSet().CoverageGaps(time.Now())).To(BeEmpty())

		// The refresh loses the second issuer's CRL but keeps the first's, so
		// the file is neither empty nor unreadable.
		cfg.ClientCA[0].CRLFile = writeCRLFile(mintCRL(serverCA, serverKey))
		refreshClientCRLs(cfg, domains, metrics)

		Expect(domains[1].RevocationSet().CoverageGaps(time.Now())).To(BeEmpty(),
			"the previous, fully covering set must be kept rather than narrowed")
	})

	It("keeps the previous set when two anchors share a common name", func() {
		// The guard compared anchors by common name, and a name is not an
		// identity here -- the same reason CRLs are not keyed by one. A CA that
		// renews *and* rekeys keeps its subject, so a bundle carrying both
		// certificates through the overlap has two independent coverage slots
		// under one name. Name-keyed, the gaps collapsed to one entry and a
		// strictly narrower reload passed the guard it exists to fail.
		twinA, twinAKey := mintCA("Twin CA", nil, nil)
		twinB, twinBKey := mintCA("Twin CA", nil, nil)
		Expect(twinA.RawSubject).To(Equal(twinB.RawSubject))
		Expect(twinA.RawSubjectPublicKeyInfo).NotTo(Equal(twinB.RawSubjectPublicKeyInfo))

		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{{
			Name:    "twins",
			File:    writeCertFile(twinA, twinB),
			CRLFile: writeCRLFile(mintCRL(twinA, twinAKey), mintCRL(twinB, twinBKey)),
		}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		present, current := domains[1].RevocationSet().Coverage(time.Now())
		Expect(present).To(HaveLen(2), "two distinct keys under one name")
		Expect(current).To(HaveLen(2))

		// The refresh loses twinA's CRL. Under a name-keyed comparison both the
		// before and after gap lists read the same, so the narrower set installs.
		cfg.ClientCA[0].CRLFile = writeCRLFile(mintCRL(twinB, twinBKey))
		refreshClientCRLs(cfg, domains, metrics)

		_, current = domains[1].RevocationSet().Coverage(time.Now())
		Expect(current).To(HaveLen(2),
			"the previous set, covering both keys, must be kept")
	})

	It("keeps an expired CRL that a reload would drop, because check still reads it", func() {
		// Coverage has two halves for a reason. Under check, an expired CRL is
		// still consulted for the serials it names -- discarding it does not make
		// the policy stricter, it silently re-admits everything it listed. A
		// guard watching only currency could not see that, and VerifyCRLAgainst's
		// own comment says clearing revocations is the threat, not just forging.
		cfg := &serverConfig{}
		cfg.ClientRevocationPolicy = config.RevocationCheck
		cfg.ClientCA = []config.ClientCA{{
			Name:    "server",
			File:    writeCertFile(serverCA),
			CRLFile: writeCRLFile(expiredCRL(serverCA, serverKey)),
		}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		present, current := domains[1].RevocationSet().Coverage(time.Now())
		Expect(present).To(HaveLen(1), "expired, but present and readable under check")
		Expect(current).To(BeEmpty())

		// A reload that yields nothing for that anchor would drop the serials it
		// names, so the previous set is kept.
		cfg.ClientCA[0].CRLFile = writeCRLFile()
		refreshClientCRLs(cfg, domains, metrics)

		present, _ = domains[1].RevocationSet().Coverage(time.Now())
		Expect(present).To(HaveLen(1),
			"dropping an expired CRL re-admits every serial it listed")
	})

	It("refuses a replayed CRL that would re-admit a revoked serial", func() {
		// The reload path's own guard, not ClientCRLSet.Regresses in isolation:
		// a replayed file verifies, covers exactly the anchors the current set
		// covers, and is older. Both arms above this one pass it, so without
		// this case a replay installs and every serial revoked since the older
		// CRL was signed becomes valid again.
		//
		// Which set is installed is read the way mintCRLUntil describes: the
		// replay expires sooner, so Usable past that point is true only while
		// the newer set is still in place.
		soon := time.Now().Add(30 * time.Minute)
		late := time.Now().Add(2 * time.Hour)
		replay := numberedCRLUntil(serverCA, serverKey, 7, soon)
		current := numberedCRLUntil(serverCA, serverKey, 8, late)

		cfg := &serverConfig{}
		cfg.ClientRevocationPolicy = config.RevocationRequire
		cfg.ClientCA = []config.ClientCA{{
			Name:    "server",
			File:    writeCertFile(serverCA),
			CRLFile: writeCRLFile(current),
		}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		applied := lastReload("server")

		// An attacker with write access to crl_file substitutes a genuine,
		// correctly signed, earlier CRL from the same issuer.
		cfg.ClientCA[0].CRLFile = writeCRLFile(replay)
		refreshClientCRLs(cfg, domains, metrics)

		Expect(lastReload("server")).To(Equal(applied),
			"a replayed CRL must not count as an applied reload")
		Expect(domains[1].RevocationSet().Usable(soon.Add(time.Minute))).To(BeTrue(),
			"the replay installed, discarding every revocation made since it was signed")
	})

	It("accepts a CRL that moves forward, so the guard is not refusing everything", func() {
		// The companion to the spec above. A guard that never lets anything
		// through would satisfy it while breaking every legitimate rotation,
		// which is the likelier way to take a fleet down.
		soon := time.Now().Add(30 * time.Minute)
		late := time.Now().Add(2 * time.Hour)

		cfg := &serverConfig{}
		cfg.ClientRevocationPolicy = config.RevocationRequire
		cfg.ClientCA = []config.ClientCA{{
			Name:    "server",
			File:    writeCertFile(serverCA),
			CRLFile: writeCRLFile(numberedCRLUntil(serverCA, serverKey, 7, soon)),
		}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		applied := lastReload("server")

		cfg.ClientCA[0].CRLFile = writeCRLFile(numberedCRLUntil(serverCA, serverKey, 8, late))
		refreshClientCRLs(cfg, domains, metrics)

		Expect(lastReload("server")).To(BeNumerically(">", applied),
			"a newer CRL must install, or no revocation ever takes effect")
		Expect(domains[1].RevocationSet().Usable(soon.Add(time.Minute))).To(BeTrue())
	})

	It("accepts a re-read of the same file, since that is the steady state", func() {
		// Equality is deliberately not a regression. Between refreshes the file
		// is usually byte-identical, and treating that as a replay would leave
		// every domain on its first load forever, logging an error each pass.
		crl := numberedCRLUntil(serverCA, serverKey, 7, time.Now().Add(time.Hour))
		cfg := &serverConfig{}
		cfg.ClientRevocationPolicy = config.RevocationRequire
		cfg.ClientCA = []config.ClientCA{{
			Name:    "server",
			File:    writeCertFile(serverCA),
			CRLFile: writeCRLFile(crl),
		}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		applied := lastReload("server")

		refreshClientCRLs(cfg, domains, metrics)

		Expect(lastReload("server")).To(BeNumerically(">", applied),
			"an unchanged file must not be refused as a replay")
	})

	It("publishes no gauge at all when the policy does not require CRLs", func() {
		// crl_file is optional under check and skip, so a domain with no CRLs is
		// a correct configuration there. Publishing 0 for it fired the mixin's
		// only critical authentication alert forever on a healthy server, and
		// the realistic response -- silencing the rule -- takes the require case
		// down with it. The counter is not gated: a refusal is a refusal.
		cfg := &serverConfig{}
		cfg.ClientRevocationPolicy = config.RevocationCheck
		cfg.ClientCA = []config.ClientCA{{Name: "server", File: writeCertFile(serverCA)}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)

		Expect(gathered()).NotTo(ContainSubstring("puppetca_client_crl_usable"))
		Expect(gathered()).To(ContainSubstring("puppetca_client_crl_refusals_total"),
			"the refusals series is zero-initialised regardless of policy")
	})

	It("installs the reloaded set, not just the one built at startup", func() {
		// Every other refresh spec here is a degradation designed to be rejected,
		// so all of them pass against a build-time set that was never replaced --
		// deleting the install from the accept arm left the suite green. The
		// steady state is the branch's whole point: a foreign issuer republishes
		// its CRL and the next pass has to apply it. Losing that is invisible on
		// all three signals: the retained CRLs stay current so the gauge reads 1,
		// clients are still served so no refusal is counted, and recordReload
		// still fires so the staleness gauge advances.
		//
		// The two sets are told apart by validity window, which the exported API
		// can see: only the reloaded CRL is still current in two hours.
		soon := time.Now().Add(time.Hour)
		later := time.Now().Add(48 * time.Hour)

		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(mintCRLUntil(serverCA, serverKey, soon)),
		}}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())
		refreshClientCRLs(cfg, domains, metrics)
		Expect(domains[1].RevocationSet().Usable(time.Now().Add(2*time.Hour))).To(BeFalse(),
			"the startup set expires within the hour")

		cfg.ClientCA[0].CRLFile = writeCRLFile(mintCRLUntil(serverCA, serverKey, later))
		refreshClientCRLs(cfg, domains, metrics)

		Expect(domains[1].RevocationSet().Usable(time.Now().Add(2*time.Hour))).To(BeTrue(),
			"a republished crl_file must actually be applied")
	})

	It("publishes the gauge as unusable when every CRL has expired", func() {
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{
			{Name: "server", File: writeCertFile(serverCA), CRLFile: writeCRLFile(expiredCRL(serverCA, serverKey))},
		}
		domains, err := buildTrustDomains(cfg, ownCA, nil)
		Expect(err).NotTo(HaveOccurred())

		refreshClientCRLs(cfg, domains, metrics)
		Expect(gauge("server")).To(Equal(0.0), "the alert fires on this")
	})
})

// expiredCRL issues a CRL from cert whose NextUpdate has already passed.
func expiredCRL(cert *x509.Certificate, key *ecdsa.PrivateKey) *x509.RevocationList {
	GinkgoHelper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	crl, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred())
	return crl
}

// captureWarnings runs fn with the default logger redirected, and returns what
// it wrote. The two warnings below are the only signal an operator gets for
// configurations that authenticate nobody, so they are asserted rather than
// assumed.
func captureWarnings(fn func()) string {
	GinkgoHelper()
	var buf bytes.Buffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(orig)
	fn()
	return buf.String()
}

var _ = Describe("client_ca startup warnings", func() {
	var (
		ownCA     *x509.Certificate
		root      *x509.Certificate
		rootKey   *ecdsa.PrivateKey
		serverCA  *x509.Certificate
		serverKey *ecdsa.PrivateKey
	)

	BeforeEach(func() {
		ownCA, _ = mintCA("Own CA", nil, nil)
		root, rootKey = mintCA("Shared Root", nil, nil)
		serverCA, serverKey = mintCA("Server CA", root, rootKey)
	})

	build := func(entry config.ClientCA, policy string) string {
		GinkgoHelper()
		cfg := &serverConfig{}
		cfg.ClientCA = []config.ClientCA{entry}
		cfg.ClientRevocationPolicy = policy
		return captureWarnings(func() {
			_, err := buildTrustDomains(cfg, ownCA, nil)
			Expect(err).NotTo(HaveOccurred())
		})
	}

	It("warns that a self-signed anchor widens the entry's authority", func() {
		// The natural mistake — "the CA bundle" usually means the whole chain —
		// and its consequence is invisible: the entry's admin_cns silently apply
		// to every intermediate beneath that root, including ones that do not
		// exist yet.
		out := build(config.ClientCA{
			Name: "shared", File: writeCertFile(root),
			CRLFile: writeCRLFile(mintCRL(root, rootKey)),
		}, config.RevocationRequire)

		Expect(out).To(ContainSubstring("self-signed root"))
		Expect(out).To(ContainSubstring("admin_cns apply to all of them"))
	})

	It("warns that honouring pp_cli_auth delegates admin admission", func() {
		// Every certificate that issuer chooses to stamp becomes an
		// administrator of this CA.
		out := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey)), AllowPpCliAuth: true,
		}, config.RevocationRequire)

		Expect(out).To(ContainSubstring("honours pp_cli_auth"))
		Expect(out).To(ContainSubstring("administrator of this CA"))
	})

	It("warns that a grant spans every anchor in a multi-anchor entry", func() {
		// admin_cns and allow_pp_cli_auth are properties of the *entry*, so a
		// file bundling two issuers honours a name from either -- while the
		// documentation says a name means something only within its issuer's
		// namespace. This warning is the only thing that says otherwise, and it
		// had no regression protection while both its siblings did.
		second, _ := mintCA("Second CA", nil, nil)
		out := build(config.ClientCA{
			Name: "pair", File: writeCertFile(serverCA, second),
			CRLFile:  writeCRLFile(mintCRL(serverCA, serverKey)),
			AdminCNs: []string{"ops-admin"},
		}, config.RevocationCheck)

		Expect(out).To(ContainSubstring("more than one anchor"))
		Expect(out).To(ContainSubstring("Server CA"))
		Expect(out).To(ContainSubstring("Second CA"))
	})

	It("says nothing about spanning anchors when the entry grants nothing", func() {
		// The guard is the half most likely to drift: a bundle with no grants
		// spans nothing, so the warning would be noise.
		second, _ := mintCA("Second CA", nil, nil)
		out := build(config.ClientCA{
			Name: "pair", File: writeCertFile(serverCA, second),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey)),
		}, config.RevocationCheck)

		Expect(out).NotTo(ContainSubstring("more than one anchor"))
	})

	It("names the uncovered anchor under require", func() {
		// The lockout: the Server CA's own CRL is signed by the Server CA, not
		// by the root anchor, so it is discarded and the root is left uncovered.
		// The warning must name which anchor, and the consequence of the obvious
		// workaround.
		out := build(config.ClientCA{
			Name: "shared", File: writeCertFile(root),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey)),
		}, config.RevocationRequire)

		Expect(out).To(ContainSubstring("no currently valid CRL"))
		Expect(out).To(ContainSubstring("uncovered_anchors"))
		Expect(out).To(ContainSubstring("anchor on the issuing CA instead"))
		Expect(out).To(ContainSubstring("disabling leaf revocation checking"))
	})

	It("does not warn when an uncovered anchor is one nobody chains to", func() {
		// A partner ships their issuing CA and the root above it, and a CRL for
		// the issuing CA only. Every client works -- no chain terminates at the
		// root -- so asserting that every client would be rejected was false,
		// and it pushed the operator towards client_revocation_policy: check.
		out := build(config.ClientCA{
			Name: "partner", File: writeCertFile(serverCA),
			CRLFile: writeCRLFile(mintCRL(serverCA, serverKey)),
		}, config.RevocationRequire)

		Expect(out).NotTo(ContainSubstring("no currently valid CRL"))
	})

	It("says nothing about CRLs when the policy does not require them", func() {
		out := build(config.ClientCA{
			Name: "server", File: writeCertFile(serverCA),
		}, config.RevocationCheck)

		Expect(out).NotTo(ContainSubstring("no currently valid CRL"))
	})
})

var _ = Describe("client_ca from a config file", func() {
	It("loads the whole block, including per-entry grants", func() {
		// Nothing else parses this YAML. The block is a list of structs with
		// per-entry grants, which is exactly the shape a typo in a struct tag
		// silently drops — and the failure mode is a trust domain that exists
		// with none of the authority the operator configured, or an admin_cns
		// list that never took effect.
		clearServerEnv()
		path := writeTempConfig(`
client_revocation_policy: check
client_ca:
  - name: server-ca
    file: /etc/openvox-ca/server-ca.pem
    crl_file: /etc/openvox-ca/server-ca-crls.pem
    admin_cns:
      - ops-admin
      - deploy
    allow_pp_cli_auth: true
  - name: partner-ca
    file: /etc/openvox-ca/partner.pem
`)
		cfg, err := loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred())

		Expect(cfg.ClientRevocationPolicy).To(Equal("check"))
		Expect(cfg.ClientCA).To(HaveLen(2))

		Expect(cfg.ClientCA[0].Name).To(Equal("server-ca"))
		Expect(cfg.ClientCA[0].File).To(Equal("/etc/openvox-ca/server-ca.pem"))
		Expect(cfg.ClientCA[0].CRLFile).To(Equal("/etc/openvox-ca/server-ca-crls.pem"))
		Expect(cfg.ClientCA[0].AdminCNs).To(Equal([]string{"ops-admin", "deploy"}))
		Expect(cfg.ClientCA[0].AllowPpCliAuth).To(BeTrue())

		// Order is the middleware's contract, so it is asserted rather than
		// assumed, and the defaults on a minimal entry are pinned too.
		Expect(cfg.ClientCA[1].Name).To(Equal("partner-ca"))
		Expect(cfg.ClientCA[1].AdminCNs).To(BeEmpty())
		Expect(cfg.ClientCA[1].AllowPpCliAuth).To(BeFalse())
		Expect(cfg.ClientCA[1].CRLFile).To(BeEmpty())
	})

	It("defaults to no client_ca at all", func() {
		clearServerEnv()
		cfg, err := loadServerConfig(writeTempConfig("cadir: /tmp/ca\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ClientCA).To(BeEmpty())
		Expect(cfg.ClientRevocationPolicy).To(BeEmpty(), "unset resolves to require at use, not here")
	})
})
