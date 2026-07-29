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

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// runCSR executes the csr subcommand with args, returning its stdout.
func runCSR(args ...string) (string, error) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"csr"}, args...))
	err := root.Execute()
	return out.String(), err
}

var _ = Describe("openvox-ca csr", func() {
	var caDir string

	BeforeEach(func() {
		caDir = GinkgoT().TempDir()
		// Pin to an empty config file so the host's /etc/puppet-ca/config.yaml,
		// if it exists, cannot influence the result.
		// ECDSA P-256, not the RSA-4096 default: these specs create a CA key
		// on nearly every It, and RSA generation at that size dominates the
		// suite's runtime for no assertion value. It also pins the
		// ca_key_algo/ca_key_size wiring from the config file through
		// applyCAConfig into LoadOrCreateCAKey, which nothing else asserts.
		pinnedCfg := "ca_key_algo: ecdsa\nca_key_size: 256\n"
		emptyCfg := filepath.Join(GinkgoT().TempDir(), "pinned.yaml")
		Expect(os.WriteFile(emptyCfg, []byte(pinnedCfg), 0o644)).To(Succeed())
		GinkgoT().Setenv("PUPPET_CA_CONFIG", emptyCfg)
		clearServerEnv()
	})

	It("refuses without a key rather than silently creating one", func() {
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).To(MatchError(ContainSubstring("--create-key")))
	})

	It("refuses without a hostname when no CA certificate exists", func() {
		// A request is handed to a third party and signed; a silently wrong CN
		// is expensive to discover afterwards.
		_, err := runCSR("--cadir", caDir, "--create-key")
		Expect(err).To(MatchError(ContainSubstring("hostname is required")))
	})

	It("creates a key and emits a request carrying the CA subject", func() {
		out, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode([]byte(out))
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("CERTIFICATE REQUEST"))

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(csr.CheckSignature()).To(Succeed())
		Expect(csr.Subject.CommonName).To(Equal("Puppet CA: puppet.example.com"))

		// No BasicConstraints: the parent sets those from its own policy, and a
		// sibling openvox-ca would reject a CSR asserting CA:TRUE outright.
		for _, ext := range csr.Extensions {
			Expect(ext.Id.String()).NotTo(Equal("2.5.29.19"))
		}
	})

	It("creates the key algorithm the configuration asks for", func() {
		// Pins ca_key_algo/ca_key_size from the config file through
		// applyCAConfig into LoadOrCreateCAKey. Nothing else asserts that
		// wiring, so csr --create-key ignoring the configured algorithm and
		// falling back to the RSA default would go unnoticed.
		out, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode([]byte(out))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		Expect(ok).To(BeTrue(), "expected an ECDSA key, got %T", csr.PublicKey)
		Expect(pub.Curve).To(Equal(elliptic.P256()))
	})

	It("persists the created key so a second run reuses it", func() {
		first, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		// Without --create-key the second run must find the key from the first.
		second, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).NotTo(HaveOccurred())

		firstBlock, _ := pem.Decode([]byte(first))
		secondBlock, _ := pem.Decode([]byte(second))
		firstCSR, err := x509.ParseCertificateRequest(firstBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		secondCSR, err := x509.ParseCertificateRequest(secondBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		firstPub, err := x509.MarshalPKIXPublicKey(firstCSR.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		secondPub, err := x509.MarshalPKIXPublicKey(secondCSR.PublicKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(secondPub).To(Equal(firstPub))
	})

	It("writes to --out with permissions matching public material", func() {
		outPath := filepath.Join(caDir, "request.pem")
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key", "--out", outPath)
		Expect(err).NotTo(HaveOccurred())

		info, err := os.Stat(outPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0644)))

		block, _ := pem.Decode(mustRead(outPath))
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("CERTIFICATE REQUEST"))
	})

	It("does not clobber an established key when --create-key is passed again", func() {
		// The no-clobber ordering inside LoadOrCreateCAKey is what stops a
		// second --create-key orphaning every certificate already issued. The
		// reuse spec above proves persistence, not this: transpose the checks
		// and it still passes.
		first, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		second, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		Expect(csrPublicKey(second)).To(Equal(csrPublicKey(first)))
	})

	It("reuses an established CA certificate's subject verbatim", func() {
		// The re-key case: the DN must be reproduced exactly, including fields
		// the flags cannot express, or the parent signs for a different name.
		bootstrapCAInDir(caDir, "original.example.com")

		out, err := runCSR("--cadir", caDir, "--hostname", "ignored.example.com")
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode([]byte(out))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(csr.Subject.CommonName).To(Equal("Puppet CA: original.example.com"))
	})

	It("reproduces the stored DER subject byte for byte", func() {
		// Re-encoding via pkix.Name would drop any attribute it does not model
		// and reorder the rest. Agents match the issuer against what they
		// already trust, so a reconstructed DN is a different name.
		//
		// The DN has to be one pkix.Name cannot round-trip, or the spec proves
		// nothing: for a CN-only subject, x509's fallback path
		// (asn1.Marshal(Subject.ToRDNSequence())) produces byte-identical DER,
		// so dropping RawSubject from the request template would still pass.
		// domainComponent is such an attribute — modelled only as ExtraNames on
		// the way out, and never reconstructed on the way back in.
		bootstrapCAWithSubject(caDir, pkix.Name{
			CommonName: "Puppet CA: original.example.com",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "example"},
				{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "test"},
			},
		})

		store := storage.New(caDir)
		stored, err := store.GetCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		certs, err := ca.ParseCABundle(stored)
		Expect(err).NotTo(HaveOccurred())

		out, err := runCSR("--cadir", caDir)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode([]byte(out))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(csr.RawSubject).To(Equal(certs[0].RawSubject))

		// Belt and braces: prove the fixture really is one a reconstruction
		// would mangle, so this spec cannot quietly decay into the CN-only case.
		rebuilt, err := asn1.Marshal(csr.Subject.ToRDNSequence())
		Expect(err).NotTo(HaveOccurred())
		Expect(rebuilt).NotTo(Equal(certs[0].RawSubject),
			"fixture DN must be one pkix.Name cannot reconstruct, or this spec proves nothing")
	})

	It("refuses rather than re-subjecting itself when the stored certificate is unreadable", func() {
		// Fail-closed, and the reason is specific: conflating "cannot read the
		// certificate" with "there is no certificate yet" would let a transient
		// backend fault make an established CA emit a request under a different
		// DN. A parent would sign it and import-ca-cert would accept it —
		// nothing downstream compares subjects.
		bootstrapCAInDir(caDir, "original.example.com")
		certPath := filepath.Join(caDir, "ca_crt.pem")
		Expect(os.WriteFile(certPath, []byte("not a certificate\n"), 0o644)).To(Succeed())

		out, err := runCSR("--cadir", caDir, "--hostname", "attacker.example.com")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("reuse its subject")))
		Expect(out).NotTo(ContainSubstring("CERTIFICATE REQUEST"),
			"no request may be emitted under a subject we could not confirm")
	})

	It("creates no key when the subject cannot be resolved", func() {
		// A run that cannot determine a subject must not leave a CA key behind:
		// at a provider it may not be removable with openvox-ca at all, and it
		// is the state Init now refuses to start over. The specific error
		// matters because the ordering is the claim: any other failure arriving
		// first would satisfy "no key was left behind" vacuously.
		_, err := runCSR("--cadir", caDir, "--create-key")
		Expect(err).To(MatchError(ContainSubstring("hostname is required")))

		has, err := storage.New(caDir).HasCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(has).To(BeFalse())
	})

	It("encrypts the created key at rest when configured", func() {
		// csr --create-key duplicates bootstrapCA's key handling; nothing else
		// pins the two together, and the failure mode is silent — a CA key
		// written in plaintext despite encrypt_ca_key.
		cfgPath := filepath.Join(GinkgoT().TempDir(), "enc.yaml")
		Expect(os.WriteFile(cfgPath,
			[]byte("ca_key_algo: ecdsa\nca_key_size: 256\nencrypt_ca_key: true\n"), 0o600)).To(Succeed())
		GinkgoT().Setenv("PUPPET_CA_CONFIG", cfgPath)

		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		keyPEM, err := storage.New(caDir).GetCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).To(Equal("ENCRYPTED PRIVATE KEY"))
	})

	It("leaves the created key unencrypted when encrypt_ca_key is not set", func() {
		// The counterpart the spec above needs in order to mean anything.
		// Without it, an ambient PUPPET_CA_ENCRYPT_CA_KEY=true makes that
		// assertion one that cannot fail: the key comes out encrypted either
		// way, and the config file it exists to prove has no bearing on the
		// result. This one fails in that environment, which is the point.
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		keyPEM, err := storage.New(caDir).GetCAKey(context.Background())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(keyPEM)
		Expect(block).NotTo(BeNil())
		Expect(block.Type).NotTo(Equal("ENCRYPTED PRIVATE KEY"))
	})
})

// csrPublicKey extracts the marshalled public key from a PEM-encoded request.
func csrPublicKey(csrPEM string) []byte {
	GinkgoHelper()
	block, _ := pem.Decode([]byte(csrPEM))
	Expect(block).NotTo(BeNil())
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	pub, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	return pub
}

func mustRead(path string) []byte {
	GinkgoHelper()
	data, err := os.ReadFile(path)
	Expect(err).NotTo(HaveOccurred())
	return data
}

// bootstrapCAInDir creates a fully bootstrapped CA in dir, so tests can
// exercise the paths that require an established certificate.
// bootstrapCAWithSubject writes a self-signed CA whose DN is exactly subject,
// including attributes pkix.Name models only as ExtraNames. Built directly
// rather than through Init, which composes the DN from a hostname.
func bootstrapCAWithSubject(dir string, subject pkix.Name) {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	Expect(err).NotTo(HaveOccurred())
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	Expect(err).NotTo(HaveOccurred())

	store := storage.New(dir)
	ctx := context.Background()
	Expect(store.EnsureDirs(ctx)).To(Succeed())
	Expect(store.SaveCACert(ctx, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))).To(Succeed())
	Expect(store.SaveCAKey(ctx, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))).To(Succeed())
}

func bootstrapCAInDir(dir, hostname string) {
	GinkgoHelper()
	store := storage.New(dir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
	myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	Expect(myCA.Init(context.Background())).To(Succeed())
}

// revokeInDir issues and then revokes a certificate, so the stored CRL carries
// an entry that later operations must preserve.
func revokeInDir(dir, subject string) {
	GinkgoHelper()
	store := storage.New(dir)
	myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
	myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	Expect(myCA.Init(context.Background())).To(Succeed())
	_, err := myCA.Generate(context.Background(), subject, nil)
	Expect(err).NotTo(HaveOccurred())
	Expect(myCA.Revoke(context.Background(), subject)).To(Succeed())
}
