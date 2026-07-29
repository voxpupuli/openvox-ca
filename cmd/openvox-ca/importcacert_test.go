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
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// runImport executes import-ca-cert with args, returning its stderr.
func runImport(args ...string) (string, error) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"import-ca-cert"}, args...))
	err := root.Execute()
	return errOut.String(), err
}

// signCSRAsParent plays the role of the external root: it signs csrPEM as a CA
// certificate and returns the resulting chain, nearest first.
func signCSRAsParent(csrPEM []byte, root *x509.Certificate, rootKey crypto.Signer, rootPEM []byte) []byte {
	GinkgoHelper()
	block, _ := pem.Decode(csrPEM)
	Expect(block).NotTo(BeNil())
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	Expect(csr.CheckSignature()).To(Succeed())

	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	skid := sha1.Sum(pubDER)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skid[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, rootKey)
	Expect(err).NotTo(HaveOccurred())

	interPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(append([]byte{}, interPEM...), rootPEM...)
}

var _ = Describe("openvox-ca import-ca-cert", func() {
	var (
		caDir   string
		chain   *testutil.TestChain
		bundle  string
		emptyCf string
	)

	BeforeEach(func() {
		caDir = GinkgoT().TempDir()
		// ECDSA P-256, not the RSA-4096 default: these specs create a CA key
		// on nearly every It, and RSA generation at that size dominates the
		// suite's runtime for no assertion value. It also pins the
		// ca_key_algo/ca_key_size wiring from the config file through
		// applyCAConfig into LoadOrCreateCAKey, which nothing else asserts.
		pinnedCfg := "ca_key_algo: ecdsa\nca_key_size: 256\n"
		emptyCf = filepath.Join(GinkgoT().TempDir(), "pinned.yaml")
		Expect(os.WriteFile(emptyCf, []byte(pinnedCfg), 0o644)).To(Succeed())
		setEnv("PUPPET_CA_CONFIG", emptyCf)

		clearServerEnv()

		var err error
		chain, err = testutil.GenerateTestChain("unused.example.com")
		Expect(err).NotTo(HaveOccurred())
		bundle = filepath.Join(caDir, "chain.pem")
	})

	It("completes the csr round trip against an external parent", func() {
		// The whole point of MR1: request out, parent signs, chain back in, and
		// the CA is a working intermediate.
		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)
		Expect(os.WriteFile(bundle, signed, 0o644)).To(Succeed())

		msg, err := runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg).To(ContainSubstring("2 certificates in chain"))

		// The CA now loads and can issue, which is the property that matters.
		store := storage.New(caDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
		Expect(myCA.Init(context.Background())).To(Succeed())
		Expect(myCA.CACert.Subject.CommonName).To(Equal("Puppet CA: puppet.example.com"))
		Expect(myCA.CACert.Issuer.CommonName).To(Equal("Test Root CA"))

		// Stored bundle keeps both certificates, root last.
		stored, err := store.GetCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		certs, err := ca.ParseCABundle(stored)
		Expect(err).NotTo(HaveOccurred())
		Expect(certs).To(HaveLen(2))
		Expect(certs[1].Subject.CommonName).To(Equal("Test Root CA"))
	})

	It("refuses a certificate that does not match the CA key", func() {
		// The single check that makes importing without a private key safe.
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		// chain.Bundle binds a different key entirely.
		Expect(os.WriteFile(bundle, chain.Bundle, 0o644)).To(Succeed())
		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ContainSubstring("does not match the certificate's public key")))
	})

	It("refuses a partial chain that stops at an intermediate", func() {
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).NotTo(HaveOccurred())
		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)

		// Drop the root, leaving only our own certificate.
		certs, err := ca.ParseCABundle(signed)
		Expect(err).NotTo(HaveOccurred())
		onlyOurs := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certs[0].Raw})
		Expect(os.WriteFile(bundle, onlyOurs, 0o644)).To(Succeed())

		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ContainSubstring("not self-signed")))
	})

	It("refuses to replace an existing certificate without --force", func() {
		bootstrapCAInDir(caDir, "puppet.example.com")
		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).NotTo(HaveOccurred())
		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)
		Expect(os.WriteFile(bundle, signed, 0o644)).To(Succeed())

		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ca.ErrCACertExists),
			"the sentinel is what callers discriminate on; a substring is not")
	})

	It("re-signs the CRL when --force replaces a certificate, keeping revocations", func() {
		// The stored CRL was signed by the subject being replaced; after the
		// import nothing could verify it unless it is re-signed. The entries
		// name serials this CA issued and must survive: dropping them would
		// silently un-revoke every node already revoked.
		bootstrapCAInDir(caDir, "puppet.example.com")
		store := storage.New(caDir)
		revokeInDir(caDir, "node1.example.com")
		before, err := store.GetCRL(context.Background())
		Expect(err).NotTo(HaveOccurred())

		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com")
		Expect(err).NotTo(HaveOccurred())
		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)
		Expect(os.WriteFile(bundle, signed, 0o644)).To(Succeed())

		msg, err := runImport("--cadir", caDir, "--cert-bundle", bundle, "--force")
		Expect(err).NotTo(HaveOccurred())
		Expect(msg).To(ContainSubstring("restart every replica"))

		after, err := store.GetCRL(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(after).NotTo(Equal(before))

		// It verifies under the newly imported certificate, and still revokes.
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
		Expect(myCA.Init(context.Background())).To(Succeed())
		block, _ := pem.Decode(after)
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(crl.CheckSignatureFrom(myCA.CACert)).To(Succeed())
		Expect(crl.RevokedCertificateEntries).To(HaveLen(1))
	})

	It("refuses a bundle that does not bind the CA key under --out", func() {
		// --out is the read-only-Secret path: without the key-binding proof
		// here, a wrong bundle is discovered only after it has rolled out to
		// every replica, with the previous certificate already overwritten.
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		Expect(os.WriteFile(bundle, chain.Bundle, 0o644)).To(Succeed())
		validated := filepath.Join(caDir, "validated.pem")
		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle, "--out", validated)
		Expect(err).To(MatchError(ContainSubstring("does not match the certificate's public key")))

		// And nothing was written: a file that exists reads as success.
		_, statErr := os.Stat(validated)
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("refuses a bundle carrying the CA private key", func() {
		// The stored certificate is world-readable and served unauthenticated,
		// so a pem_bundle export that includes the key must not get through.
		_, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())

		withKey := append(append([]byte{}, chain.InterKeyPEM...), chain.Bundle...)
		Expect(os.WriteFile(bundle, withKey, 0o600)).To(Succeed())
		_, err = runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ContainSubstring("PRIVATE KEY")))
	})

	It("reports a missing bundle file rather than panicking", func() {
		_, err := runImport("--cadir", caDir, "--cert-bundle", filepath.Join(caDir, "absent.pem"))
		Expect(err).To(MatchError(ContainSubstring("reading --cert-bundle")))
	})

	It("rejects --out together with --force", func() {
		Expect(os.WriteFile(bundle, chain.Bundle, 0o644)).To(Succeed())
		_, err := runImport("--cadir", caDir, "--cert-bundle", bundle, "--out",
			filepath.Join(caDir, "validated.pem"), "--force")
		Expect(err).To(MatchError(ContainSubstring("--out cannot be combined with --force")))
	})

	It("validates and writes the bundle without installing it under --out", func() {
		csrPEM, err := runCSR("--cadir", caDir, "--hostname", "puppet.example.com", "--create-key")
		Expect(err).NotTo(HaveOccurred())
		signed := signCSRAsParent([]byte(csrPEM), chain.RootCert, chain.RootKey, chain.RootPEM)
		Expect(os.WriteFile(bundle, signed, 0o644)).To(Succeed())

		validated := filepath.Join(caDir, "validated.pem")
		msg, err := runImport("--cadir", caDir, "--cert-bundle", bundle, "--out", validated)
		Expect(err).NotTo(HaveOccurred())
		Expect(msg).To(ContainSubstring("not installed"))
		Expect(mustRead(validated)).To(Equal(signed))

		// The written bundle is destined for a Kubernetes Secret and is served
		// to every agent, so the explicit chmod that makes the mode
		// umask-independent matters. The csr sibling asserts this; dropping the
		// chmod here would otherwise go unnoticed.
		info, err := os.Stat(validated)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0644)))

		// Storage is untouched: no certificate was installed.
		store := storage.New(caDir)
		has, err := store.HasCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(has).To(BeFalse())
	})

	It("refuses when no CA key exists to match against", func() {
		Expect(os.WriteFile(bundle, chain.Bundle, 0o644)).To(Succeed())
		_, err := runImport("--cadir", caDir, "--cert-bundle", bundle)
		Expect(err).To(MatchError(ContainSubstring("no CA key exists")))
	})
})

var _ = Describe("openvox-ca import-ca-cert: resolved configuration", func() {
	It("reports the configuration it resolved, before it opens anything", func() {
		// Same reasoning as the csr side, and the same call site that would
		// otherwise be deletable without a spec noticing. A real bundle is
		// needed to get past the --cert-bundle read, which happens first and
		// deliberately: that failure is about the operator's argument, not
		// about which configuration was resolved.
		caDir := GinkgoT().TempDir()
		cfgPath := filepath.Join(GinkgoT().TempDir(), "pinned.yaml")
		Expect(os.WriteFile(cfgPath, []byte("ca_key_algo: ecdsa\nca_key_size: 256\n"), 0o644)).To(Succeed())
		setEnv("PUPPET_CA_CONFIG", cfgPath)
		clearServerEnv()

		chain, err := testutil.GenerateTestChain("unused.example.com")
		Expect(err).NotTo(HaveOccurred())
		bundlePath := filepath.Join(caDir, "chain.pem")
		Expect(os.WriteFile(bundlePath, chain.Bundle, 0o644)).To(Succeed())

		// The import fails at the key-binding proof (this cadir holds no key),
		// which is well after the diagnostic.
		stderr, err := runImport("--cadir", caDir, "--cert-bundle", bundlePath)
		Expect(err).To(HaveOccurred())
		Expect(stderr).To(ContainSubstring("Using config file:"))
		Expect(stderr).To(ContainSubstring("CA key provider: file"))
		Expect(stderr).To(ContainSubstring(caDir))
	})
})

var _ = Describe("annotateOverlayWriteError", func() {
	// The whole value of this helper is what it declines to annotate. The
	// remedy it names — re-run with --out and load the result out of band — is
	// right only for a certificate blob that could not be written, and is
	// actively misleading for a key mismatch or a bad CRL. A later change that
	// keyed on any import failure would still look plausible.
	const overlay = "/etc/openvox-ca/ca_crt.pem"

	DescribeTable("appends the read-only overlay guidance only where it applies",
		func(err error, cacertFile string, wantGuidance bool) {
			cfg := &serverConfig{}
			cfg.CACertFile = cacertFile
			got := annotateOverlayWriteError(err, cfg)
			if err == nil {
				Expect(got).To(BeNil())
				return
			}
			if wantGuidance {
				Expect(got).To(MatchError(ContainSubstring("re-run with --out")))
				Expect(got).To(MatchError(ContainSubstring(overlay)))
				Expect(got).To(MatchError(err), "the original error must stay wrapped")
			} else {
				Expect(got).NotTo(MatchError(ContainSubstring("re-run with --out")))
			}
		},
		Entry("a certificate write failure onto an overlay",
			fmt.Errorf("%w: read-only file system", ca.ErrCACertWrite), overlay, true),
		Entry("a certificate write failure with no overlay configured",
			fmt.Errorf("%w: read-only file system", ca.ErrCACertWrite), "", false),
		Entry("an unrelated failure onto an overlay",
			errors.New("failed to write CRL: disk full"), overlay, false),
		Entry("the key-mismatch failure the guidance would mislead on",
			errors.New("certificate does not match the CA key"), overlay, false),
		Entry("no failure at all", nil, overlay, false),
	)
})
