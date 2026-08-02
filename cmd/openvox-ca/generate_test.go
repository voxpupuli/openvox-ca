// Copyright (C) 2026 Trevor Vaughan
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
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

func runGenerate(args ...string) (stdout, stderr string, err error) {
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"generate"}, args...))
	err = root.Execute()
	return out.String(), errOut.String(), err
}

// hashTree fingerprints every file under dir, so a spec can assert that a
// refusal changed nothing at all rather than only that one file survived.
func hashTree(dir string) map[string]string {
	GinkgoHelper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		sum := sha256.Sum256(data)
		out[rel] = string(sum[:])
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		Expect(err).NotTo(HaveOccurred())
	}
	return out
}

func certFromPEM(pemBytes string) *x509.Certificate {
	GinkgoHelper()
	block, _ := pem.Decode([]byte(pemBytes))
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert
}

var _ = Describe("openvox-ca generate", func() {
	var (
		caDir  string
		outDir string
	)

	BeforeEach(func() {
		caDir = GinkgoT().TempDir()
		outDir = GinkgoT().TempDir()

		// ECDSA P-256 rather than the RSA defaults: these specs mint a CA and a
		// leaf on nearly every It, and RSA at the default sizes dominates the
		// suite's runtime for no assertion value.
		pinnedCfg := "ca_key_algo: ecdsa\nca_key_size: 256\nleaf_key_algo: ecdsa\nleaf_key_size: 256\n"
		cfgPath := filepath.Join(GinkgoT().TempDir(), "pinned.yaml")
		Expect(os.WriteFile(cfgPath, []byte(pinnedCfg), 0o644)).To(Succeed())
		setEnv("PUPPET_CA_CONFIG", cfgPath)
		clearServerEnv()

		// The command calls setupLogger, which rebinds the process-wide default
		// logger. Restore it so it cannot leak into sibling specs.
		orig := slog.Default()
		DeferCleanup(func() { slog.SetDefault(orig) })
	})

	keyPath := func(name string) string { return filepath.Join(outDir, name+".key") }

	Describe("refusing to act on storage that holds no usable CA", func() {
		It("will not bootstrap a CA when none exists", func() {
			before := hashTree(caDir)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring("refusing to create one")))

			// Init writes -- EnsureDirs, InitHMAC, CRL seeding -- before it
			// reaches the bootstrap decision, so asserting only that ca_crt.pem
			// is absent would pass with the guard in the wrong place.
			Expect(hashTree(caDir)).To(Equal(before), "a refusal must leave the cadir untouched")
		})

		It("will not issue when the CA certificate is present but the key is gone", func() {
			// Init refuses this case too, so this passes with the command's own
			// guard removed -- it is defence in depth against a regression in
			// either layer, not a pin on this command alone. What it does pin
			// here is that the refusal happens before Init's side effects, so
			// the cadir is left byte-identical rather than merely un-bootstrapped.
			bootstrapCAInDir(caDir, "puppet.example.com")
			Expect(os.Remove(filepath.Join(caDir, "private", "ca_key.pem"))).To(Succeed())
			before := hashTree(caDir)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring("its key is missing")))
			Expect(hashTree(caDir)).To(Equal(before))
		})

		It("refuses on the frontend role, which cannot reach the CA key", func() {
			// The role is an environment variable the launcher sets into its
			// children, not a config key. roleMayReachCAKey is role !=
			// "frontend", so the predicate is easy to invert -- hence both
			// directions below.
			bootstrapCAInDir(caDir, "puppet.example.com")
			setEnv("PUPPET_CA_ROLE", "frontend")

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring("frontend")))
		})

		It("proceeds on the signer role, which does hold the key", func() {
			bootstrapCAInDir(caDir, "puppet.example.com")
			setEnv("PUPPET_CA_ROLE", "signer")

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("minting against an existing CA", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("requires a ttl rather than defaulting to five years", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--key-out", keyPath("web01"))
			Expect(err).To(MatchError(ContainSubstring(`"ttl" not set`)))
		})

		It("emits a certificate signed by the CA on stdout", func() {
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "web01.example.com",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			cert := certFromPEM(stdout)
			Expect(cert.Subject.CommonName).To(Equal("web01.example.com"))
			Expect(cert.DNSNames).To(ConsistOf("web01.example.com"), "the CN is promoted to a SAN")

			caPEM, err := os.ReadFile(filepath.Join(caDir, "ca_crt.pem"))
			Expect(err).NotTo(HaveOccurred())
			Expect(cert.CheckSignatureFrom(certFromPEM(string(caPEM)))).To(Succeed())
		})

		It("writes the private key at 0600 and leaves none in the cadir", func() {
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			info, err := os.Stat(keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

			// The key must match the certificate, or the operator has a
			// credential they cannot use.
			keyPEM, err := os.ReadFile(keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(keyPEM)
			Expect(block).NotTo(BeNil())
			key, err := x509.ParseECPrivateKey(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(key.PublicKey.Equal(certFromPEM(stdout).PublicKey)).To(BeTrue())

			_, statErr := os.Stat(storage.New(caDir).PrivateKeyPath("web01"))
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"nothing should be left in the cadir when --key-out was given")
		})

		It("falls back to the cadir and says what that costs", func() {
			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01", "--ttl", "8760h")
			Expect(err).NotTo(HaveOccurred())

			Expect(storage.New(caDir).PrivateKeyPath("web01")).To(BeAnExistingFile())
			Expect(stderr).To(ContainSubstring("persists there until"))
			Expect(stderr).To(ContainSubstring("ephemeral cadir"))
		})

		It("applies dns alt names and an explicit ttl", func() {
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "1h", "--dns", "a.example.com,b.example.com",
				"--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			cert := certFromPEM(stdout)
			Expect(cert.DNSNames).To(ConsistOf("a.example.com", "b.example.com"))
			Expect(cert.NotAfter.Sub(cert.NotBefore)).To(BeNumerically("<", 26*60*60*1e9),
				"a 1h ttl plus the 24h backdate, not the multi-year default")
		})

		It("writes the certificate to --cert-out at 0644, leaving stdout empty", func() {
			certOut := filepath.Join(outDir, "web01.crt")
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"), "--cert-out", certOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(stdout).To(BeEmpty())

			info, err := os.Stat(certOut)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)))
		})

		It("reports the configuration and backend capabilities before acting", func() {
			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			Expect(stderr).To(ContainSubstring("Storage backend: filesystem"))
			Expect(stderr).To(ContainSubstring("Issuance settings:"))
			// The filesystem backend provides neither capability, so the
			// stop-the-server warning is the correct output here.
			Expect(stderr).To(ContainSubstring("Stop the server before running this"))
		})

		It("bypasses autosign policy, which is not consulted at all", func() {
			// Deliberate: this is an operator action, not a request, and must
			// work when there is no policy and no server to evaluate one.
			denyAll := filepath.Join(GinkgoT().TempDir(), "autosign.conf")
			Expect(os.WriteFile(denyAll, []byte("# matches nothing\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_AUTOSIGN_CONFIG", denyAll)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("output pre-flight", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("refuses to overwrite an existing key, issuing nothing", func() {
			existing := keyPath("web01")
			Expect(os.WriteFile(existing, []byte("original"), 0o600)).To(Succeed())

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", existing)
			Expect(err).To(MatchError(ContainSubstring("refusing to overwrite")))

			data, readErr := os.ReadFile(existing)
			Expect(readErr).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal("original"))

			// The point of checking before issuing: the certificate would
			// otherwise have consumed a serial and be in the inventory.
			Expect(storage.New(caDir).HasCert(context.Background(), "web01")).To(BeFalse())
		})

		It("refuses when the key's directory does not exist", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", filepath.Join(outDir, "nope", "web01.key"))
			Expect(err).To(MatchError(ContainSubstring("does not exist")))
		})

		It("refuses to overwrite an existing certificate file", func() {
			certOut := filepath.Join(outDir, "web01.crt")
			Expect(os.WriteFile(certOut, []byte("original"), 0o644)).To(Succeed())

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"), "--cert-out", certOut)
			Expect(err).To(MatchError(ContainSubstring("refusing to overwrite")))
		})
	})

	Describe("administrator credentials", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("stamps pp_cli_auth only when asked", func() {
			stdout, _, err := runGenerate("--cadir", caDir, "--certname", "node",
				"--ttl", "8760h", "--key-out", keyPath("node"))
			Expect(err).NotTo(HaveOccurred())
			for _, ext := range certFromPEM(stdout).Extensions {
				Expect(ca.IsAuthOID(ext.Id)).To(BeFalse())
			}

			stdout, _, err = runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).NotTo(HaveOccurred())

			var found bool
			for _, ext := range certFromPEM(stdout).Extensions {
				if ext.Id.Equal(ca.OIDPpCliAuth) {
					found = true
					Expect(ext.Value).To(Equal([]byte{0x0c, 0x04, 't', 'r', 'u', 'e'}))
				}
			}
			Expect(found).To(BeTrue())
		})

		It("requires --key-out, so the key cannot land somewhere ephemeral", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth")
			Expect(err).To(MatchError(ContainSubstring("--key-out is required with --pp-cli-auth")))

			Expect(storage.New(caDir).HasCert(context.Background(), "admin")).To(BeFalse())
		})

		It("states what the credential grants and how to withdraw it", func() {
			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).NotTo(HaveOccurred())

			Expect(stderr).To(ContainSubstring("administrator credential"))
			// The withdrawal procedure is the part an operator cannot infer,
			// and all three steps matter: revoking alone does not take effect
			// on a running server, and a superseded serial may not be
			// revocable at all.
			Expect(stderr).To(ContainSubstring("openvox-ca-ctl revoke --certname admin"))
			Expect(stderr).To(ContainSubstring("restart every replica"))
			Expect(stderr).To(ContainSubstring("other live serials"))
		})

		It("refuses when the CA is configured to ignore pp_cli_auth", func() {
			cfgPath := filepath.Join(GinkgoT().TempDir(), "nopp.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nno_pp_cli_auth: true\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).To(MatchError(ContainSubstring("no_pp_cli_auth")))
		})
	})

	Describe("replacing an existing certificate", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("names both remedies when a certificate already exists", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())

			_, _, err = runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01-again"))
			Expect(err).To(MatchError(ca.ErrCertExists),
				"the sentinel is what callers discriminate on; a substring is not")
			Expect(err.Error()).To(ContainSubstring("--force"))
			Expect(err.Error()).To(ContainSubstring("openvox-ca-ctl clean"))
		})

		It("replaces with --force and reports the revocation", func() {
			first, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred())
			oldSerial := certFromPEM(first).SerialNumber

			second, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--force", "--key-out", keyPath("web01-new"))
			Expect(err).NotTo(HaveOccurred())

			Expect(certFromPEM(second).SerialNumber.Cmp(oldSerial)).NotTo(Equal(0))
			Expect(stderr).To(ContainSubstring("was revoked"))
			Expect(stderr).To(ContainSubstring("until it reloads the CRL"))
		})

		It("requires --key-out, because a failed key write after the revoke is unrecoverable", func() {
			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--force")
			Expect(err).To(MatchError(ContainSubstring("--key-out is required with --force")))
		})

		It("issues again once an existing certificate has been revoked", func() {
			revokeInDir(caDir, "web01")

			_, _, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred(), "a revoked certificate must be evictable without --force")
		})

		It("warns when replacing the CA's own serving name", func() {
			cfgPath := filepath.Join(GinkgoT().TempDir(), "host.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nhostname: puppet.example.com\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "puppet.example.com",
				"--ttl", "8760h", "--key-out", keyPath("serving"))
			Expect(err).NotTo(HaveOccurred())

			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "puppet.example.com",
				"--ttl", "8760h", "--force", "--key-out", keyPath("serving-new"))
			Expect(err).NotTo(HaveOccurred())
			Expect(stderr).To(ContainSubstring("this CA's own hostname"))
		})
	})

	Describe("audit logging", func() {
		BeforeEach(func() { bootstrapCAInDir(caDir, "puppet.example.com") })

		It("writes the grant to a configured logfile", func() {
			logPath := filepath.Join(outDir, "ca.log")
			Expect(os.WriteFile(logPath, nil, 0o600)).To(Succeed())

			cfgPath := filepath.Join(GinkgoT().TempDir(), "log.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nlogfile: "+logPath+"\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, _, err := runGenerate("--cadir", caDir, "--certname", "admin",
				"--ttl", "8760h", "--pp-cli-auth", "--key-out", keyPath("admin"))
			Expect(err).NotTo(HaveOccurred())

			logged, err := os.ReadFile(logPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(logged)).To(ContainSubstring("pp_cli_auth=true"))
			Expect(string(logged)).To(ContainSubstring("admin"))
		})

		It("does not create a missing logfile, and mints anyway", func() {
			// Creating it would be actively harmful: run as root before the
			// server has ever started, the file would end up owned by root and
			// the server -- running unprivileged -- would fail to open it and
			// exit at startup.
			logPath := filepath.Join(outDir, "absent.log")
			cfgPath := filepath.Join(GinkgoT().TempDir(), "log.yaml")
			Expect(os.WriteFile(cfgPath, []byte(
				"ca_key_algo: ecdsa\nca_key_size: 256\nlogfile: "+logPath+"\n"), 0o644)).To(Succeed())
			setEnv("PUPPET_CA_CONFIG", cfgPath)

			_, stderr, err := runGenerate("--cadir", caDir, "--certname", "web01",
				"--ttl", "8760h", "--key-out", keyPath("web01"))
			Expect(err).NotTo(HaveOccurred(), "a logging problem must not stop an operator issuing")
			Expect(stderr).To(ContainSubstring("will not be created"))
			Expect(logPath).NotTo(BeAnExistingFile())
		})
	})
})

// sortedKeys is a small helper for readable failure output when comparing
// directory fingerprints.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = Describe("generate helpers", func() {
	It("fingerprints a directory tree", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "a"), []byte("one"), 0o600)).To(Succeed())
		Expect(strings.Join(sortedKeys(hashTree(dir)), ",")).To(Equal("a"))
	})
})
