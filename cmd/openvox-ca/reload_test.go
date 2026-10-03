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
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// writeTestKeypair writes a self-signed server certificate and its key into
// dir as the fixed names server.crt and server.key, and returns the two paths.
// cn sets the certificate's common name, which is how specs tell one keypair
// from another; calling this twice with the same dir deliberately overwrites,
// which is how the rotation specs work. Two keypairs that must coexist need
// two directories.
func writeTestKeypair(dir, cn string) (certPath, keyPath string) {
	GinkgoHelper()
	return writeTestKeypairValid(dir, cn, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// writeTestKeypairValid is writeTestKeypair with an explicit validity window,
// so a spec can produce a certificate that is already expired or not yet
// valid — the cases a rotation is supposed to warn about.
func writeTestKeypairValid(dir, cn string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	GinkgoHelper()
	return writeTestKeypairFromTemplate(dir, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
	})
}

// writeTestKeypairFromTemplate self-signs tmpl with a fresh key and writes the
// pair into dir under the same fixed names the other helpers use. It exists so
// a spec can reload a certificate of a deliberately wrong shape -- a CA
// certificate, say -- without each such spec restating how a keypair is
// written.
func writeTestKeypairFromTemplate(dir string, tmpl *x509.Certificate) (certPath, keyPath string) {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())

	keyDER, err := x509.MarshalECPrivateKey(key)
	Expect(err).NotTo(HaveOccurred())

	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	Expect(os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)).To(Succeed())
	Expect(os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)).To(Succeed())
	return certPath, keyPath
}

// bootstrappedCATemplate is the certificate internal/ca mints for a new CA:
// IsCA, keyUsage certSign|cRLSign, no extendedKeyUsage and no SANs. It is
// reproduced here rather than imported because it is the *documented example*
// that is under test -- docs/configuration.md offered these paths as the
// tls_cert/tls_key pair, and the point of the specs below is that this shape
// of certificate cannot serve TLS.
func bootstrappedCATemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Puppet CA: " + cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

// servedCN returns the common name of the certificate the reloader currently
// hands to new handshakes.
func servedCN(c *certReloader) string {
	GinkgoHelper()
	cert, err := c.GetCertificate(nil)
	Expect(err).NotTo(HaveOccurred())
	Expect(cert.Leaf).NotTo(BeNil())
	return cert.Leaf.Subject.CommonName
}

var _ = Describe("Admin allow list construction", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	It("merges the configured CNs with the allow-list file", func() {
		path := filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(path, []byte("compile-1.example.com\n# a comment\n\ncompile-2.example.com\n"), 0600)).To(Succeed())

		allowList, err := buildAdminAllowList("puppet.example.com, primary.example.com", path)
		Expect(err).NotTo(HaveOccurred())
		Expect(allowList).To(Equal(map[string]bool{
			"puppet.example.com":    true,
			"primary.example.com":   true,
			"compile-1.example.com": true,
			"compile-2.example.com": true,
		}))
	})

	It("copes with neither source being configured", func() {
		allowList, err := buildAdminAllowList("", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowList).To(BeEmpty())
	})

	It("ignores blank entries in the configured list", func() {
		allowList, err := buildAdminAllowList(" , puppet.example.com ,", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(allowList).To(Equal(map[string]bool{"puppet.example.com": true}))
	})

	It("reports an unreadable allow-list file", func() {
		_, err := buildAdminAllowList("", filepath.Join(dir, "missing.txt"))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("diffAllowList", func() {
	It("names the CNs that gained and lost admin access", func() {
		// The audit record: a count alone cannot distinguish "unchanged" from
		// "one compile server swapped for another".
		added, removed := diffAllowList(
			map[string]bool{"stays.example.com": true, "goes.example.com": true},
			map[string]bool{"stays.example.com": true, "arrives.example.com": true},
		)
		Expect(added).To(Equal([]string{"arrives.example.com"}))
		Expect(removed).To(Equal([]string{"goes.example.com"}))
	})

	It("reports no change when the allow list is rewritten identically", func() {
		added, removed := diffAllowList(
			map[string]bool{"a.example.com": true},
			map[string]bool{"a.example.com": true},
		)
		Expect(added).To(BeEmpty())
		Expect(removed).To(BeEmpty())
	})
})

var _ = Describe("TLS certificate reloading", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	It("refuses to start with an unreadable keypair", func() {
		_, err := newCertReloader(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"))
		Expect(err).To(HaveOccurred())
	})

	It("serves the keypair it loaded", func() {
		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(servedCN(reloader)).To(Equal("first.example.com"))
	})

	It("picks up a renewed certificate", func() {
		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		writeTestKeypair(dir, "renewed.example.com")
		Expect(reloader.reload()).To(Succeed())
		Expect(servedCN(reloader)).To(Equal("renewed.example.com"))
	})

	It("keeps serving the previous certificate when the new one is unusable", func() {
		// This is the half-written-file case: a reload that lands while the
		// certificate is being replaced must not leave the server with no
		// certificate at all.
		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		Expect(os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\ntruncated"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(HaveOccurred())
		Expect(servedCN(reloader)).To(Equal("first.example.com"))
	})

	DescribeTable("warns about a keypair outside its validity window",
		func(notBefore, notAfter time.Time, want string) {
			// LoadX509KeyPair checks only that certificate and key
			// correspond, and a Go TLS server does not validate its own
			// leaf — so without this the reload reports success while every
			// new handshake fails at the agent.
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			dir := GinkgoT().TempDir()
			certPath, keyPath := writeTestKeypairValid(dir, "rotated.example.com", notBefore, notAfter)
			reloader, err := newCertReloader(certPath, keyPath)
			Expect(err).NotTo(HaveOccurred())

			Expect(servedCN(reloader)).To(Equal("rotated.example.com"),
				"an out-of-window certificate is still installed; refusing it would leave no certificate at all")
			Expect(buf.String()).To(ContainSubstring(want))
		},
		Entry("already expired",
			time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour),
			"has already expired"),
		Entry("not yet valid",
			time.Now().Add(time.Hour), time.Now().Add(48*time.Hour),
			"is not valid yet"),
	)

	It("says nothing about a keypair inside its window", func() {
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		certPath, keyPath := writeTestKeypair(GinkgoT().TempDir(), "current.example.com")
		_, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())
		Expect(buf.String()).To(BeEmpty())
	})

	It("rejects a certificate that does not match the key", func() {
		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		otherDir := GinkgoT().TempDir()
		_, otherKey := writeTestKeypair(otherDir, "other.example.com")
		keyPEM, err := os.ReadFile(otherKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(keyPath, keyPEM, 0600)).To(Succeed())

		Expect(reloader.reload()).To(HaveOccurred())
		Expect(servedCN(reloader)).To(Equal("first.example.com"))
	})
})

var _ = Describe("servingCertProblems", func() {
	// The reference case. docs/configuration.md offered the CA's own
	// ca_crt.pem/ca_key.pem as the tls_cert/tls_key example; a CA started that
	// way logs "TLS enabled", completes the handshake, and is rejected by
	// every client that verifies it. `openssl s_client -verify_hostname`
	// against such a server reports both "unsuitable certificate purpose" and
	// "hostname mismatch" — the two faults asserted here. Being a CA
	// certificate is not one of them: reload() warns about that separately,
	// as custody advice, because such a certificate can still serve TLS.
	It("names every fault in the CA certificate the config reference used to point tls_cert at", func() {
		Expect(servingCertProblems(bootstrappedCATemplate("ca.example.com"))).To(ConsistOf(
			ContainSubstring("no subjectAltName"),
			ContainSubstring("neither digitalSignature nor keyEncipherment"),
		))
	})

	It("stays silent about basicConstraints, which does not stop a client verifying a leaf", func() {
		// Empirically: a self-signed certificate with CA:TRUE, a SAN,
		// serverAuth and digitalSignature -- what `openssl req -x509`
		// produces by default -- verifies and serves. OpenSSL applies its CA
		// checks to a certificate in the issuer position, not the end-entity
		// one. Claiming such a certificate "cannot serve TLS" would be the
		// false positive this table exists to prevent; reload() warns about
		// a CA certificate separately, as custody advice.
		leaf := servingLeafTemplate()
		leaf.IsCA = true
		Expect(servingCertProblems(leaf)).To(BeEmpty())
	})

	It("agrees with what internal/ca actually mints, so the fixture cannot drift", func() {
		// bootstrappedCATemplate is hand-written. This anchors it to the real
		// bootstrap: if internal/ca ever gives the CA certificate a SAN or a
		// serving keyUsage, this fails while the fixture-based specs above
		// would carry on passing against a shape the product no longer makes.
		dir := GinkgoT().TempDir()
		bootstrapCAInDir(dir, "ca.example.com")
		caCert, err := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, "ca.example.com").
			Storage.GetCACert(context.Background())
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(caCert)
		Expect(block).NotTo(BeNil())
		real, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		Expect(real.IsCA).To(BeTrue(), "reload() warns about this separately")

		// Asserted against the matchers directly, not only against
		// servingCertProblems(fixture): comparing the function with itself
		// would be satisfied by any shared value, two empty slices included.
		Expect(servingCertProblems(real)).To(ConsistOf(
			ContainSubstring("no subjectAltName"),
			ContainSubstring("neither digitalSignature nor keyEncipherment"),
		))
		Expect(servingCertProblems(real)).
			To(Equal(servingCertProblems(bootstrappedCATemplate("ca.example.com"))))

		// servingCertProblems never reads the subject, but the wiring spec
		// matches on it and docs/configuration.md publishes it.
		Expect(real.Subject.CommonName).
			To(Equal(bootstrappedCATemplate("ca.example.com").Subject.CommonName))
	})

	It("says nothing about a leaf this CA actually issues", func() {
		// The mirror of the anchor above, for the fixture that carries far
		// more specs. If internal/ca ever narrows the extendedKeyUsage or the
		// keyUsage it issues, every "says nothing" entry would keep passing
		// against servingLeafTemplate while the CA's own serving certificates
		// started tripping the warning — the false positive those specs exist
		// to prevent. Mutation testing cannot reach it: the drifting party is
		// internal/ca, not the code under review.
		dir := GinkgoT().TempDir()
		myCA := ca.New(storage.New(dir), ca.AutosignConfig{Mode: "off"}, "ca.example.com")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(context.Background())).To(Succeed())

		result, err := myCA.Generate(context.Background(), "node.example.com", []string{"node.example.com"})
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(result.CertificatePEM)
		Expect(block).NotTo(BeNil())
		leaf, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		Expect(leaf.IsCA).To(BeFalse(), "and so draws no custody warning either")
		Expect(servingCertProblems(leaf)).To(BeEmpty())
	})

	DescribeTable("reports one fault at a time",
		func(mutate func(*x509.Certificate), want string) {
			leaf := servingLeafTemplate()
			mutate(leaf)
			Expect(servingCertProblems(leaf)).To(ConsistOf(ContainSubstring(want)))
		},
		Entry("no subjectAltName of either kind", func(c *x509.Certificate) {
			c.DNSNames, c.IPAddresses = nil, nil
		}, "no subjectAltName"),
		Entry("a keyUsage with neither signing nor encipherment bit", func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		}, "neither digitalSignature nor keyEncipherment"),
		Entry("an extendedKeyUsage that excludes serverAuth", func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}, "does not include serverAuth"),
		Entry("an extendedKeyUsage Go has no constant for", func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}}
		}, "does not include serverAuth"),
	)

	DescribeTable("says nothing about a certificate a client can accept",
		func(mutate func(*x509.Certificate)) {
			// Each of these is a shape that must NOT warn: warning about a
			// working configuration trains operators to ignore the line, and
			// the one case it exists for would go with it.
			leaf := servingLeafTemplate()
			mutate(leaf)
			Expect(servingCertProblems(leaf)).To(BeEmpty())
		},
		Entry("as generated by `openvox-ca-ctl generate`", func(*x509.Certificate) {}),
		Entry("with no extendedKeyUsage extension at all, which is unconstrained", func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
		}),
		Entry("with no keyUsage extension at all, which is likewise unconstrained", func(c *x509.Certificate) {
			c.KeyUsage = 0
		}),
		Entry("with anyExtendedKeyUsage rather than serverAuth", func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}),
		Entry("named by IP address rather than DNS name", func(c *x509.Certificate) {
			c.DNSNames = nil
			c.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
		}),
		Entry("with keyEncipherment but not digitalSignature", func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageKeyEncipherment
		}),
		Entry("with digitalSignature but not keyEncipherment, the usual ECDSA shape", func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageDigitalSignature
		}),
		Entry("with serverAuth somewhere other than first", func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}),
	)
})

// logLineContaining returns the single log record in logged that contains
// want, failing if none or more than one does. Specs assert against one record
// rather than the whole buffer because both serving-certificate warnings carry
// the same `cert` and `subject` attributes, and a buffer-wide match would hold
// even with an attribute dropped from the record under test.
func logLineContaining(logged, want string) string {
	GinkgoHelper()
	var found []string
	for _, line := range strings.Split(strings.TrimSpace(logged), "\n") {
		if strings.Contains(line, want) {
			found = append(found, line)
		}
	}
	Expect(found).To(HaveLen(1), "expected exactly one log record containing %q, got:\n%s", want, logged)
	return found[0]
}

// servingLeafTemplate is a certificate shaped like the one `openvox-ca-ctl
// generate` issues: end-entity, serverAuth + clientAuth, digitalSignature +
// keyEncipherment, one DNS SAN. Specs mutate one field of it at a time, so
// each asserts on the fault it introduced and nothing else.
func servingLeafTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ca.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"ca.example.com"},
	}
}

var _ = Describe("Loading a certificate that cannot serve TLS", func() {
	It("warns, naming the certificate and how to replace it", func() {
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		dir := GinkgoT().TempDir()
		certPath, keyPath := writeTestKeypairFromTemplate(dir, bootstrappedCATemplate("ca.example.com"))
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		// Installed regardless: refusing it here would take the CA down on an
		// upgrade, and a CA that is reachable over a certificate agents
		// distrust is still serving the CRL and the public endpoints.
		Expect(servedCN(reloader)).To(Equal("Puppet CA: ca.example.com"))

		// Asserted against the one line rather than the whole buffer: both
		// warnings carry `cert` and `subject`, so a buffer-wide match would
		// still pass with either attribute dropped from this one.
		// The attribute KEYS are asserted, not just their values:
		// docs/configuration.md publishes this record whole, and an operator's
		// realistic use of it is to grep their logs for it. Renaming `problems`
		// would leave every value-matching assertion green and the doc wrong.
		cannotServe := logLineContaining(buf.String(), "cannot serve TLS to a client that verifies it")
		Expect(cannotServe).To(ContainSubstring(
			"msg=\"The TLS certificate just loaded cannot serve TLS to a client that verifies it; " +
				"issue a serving certificate with `openvox-ca-ctl generate` and point tls_cert/tls_key at that\""))
		Expect(cannotServe).To(ContainSubstring("cert="+certPath), "the operator needs to know which path is wrong")
		Expect(cannotServe).To(ContainSubstring(`subject="Puppet CA: ca.example.com"`), "and which certificate it loaded")
		Expect(cannotServe).To(ContainSubstring("problems="))

		// Spans the "; " join, so logging only the first fault fails here.
		// An operator told one fault of two fixes it and still has no
		// working server. docs/configuration.md publishes this exact line.
		Expect(cannotServe).To(ContainSubstring(
			`problems="it has no subjectAltName, and clients match the hostname against SANs only; ` +
				`its keyUsage allows neither digitalSignature nor keyEncipherment"`))

		// The custody advice is a separate line: it is true of certificates
		// that serve TLS perfectly well, so it must not be folded into the
		// "cannot serve TLS" verdict.
		custody := logLineContaining(buf.String(), "is a CA certificate; serving from it puts a signing key on the network-facing listener")
		Expect(custody).To(ContainSubstring(
			"msg=\"The TLS certificate just loaded is a CA certificate; serving from it puts a signing key " +
				"on the network-facing listener. Issue an end-entity certificate with `openvox-ca-ctl generate` " +
				"and point tls_cert/tls_key at that\""))
		Expect(custody).To(ContainSubstring("cert=" + certPath))
		Expect(custody).To(ContainSubstring(`subject="Puppet CA: ca.example.com"`))
	})

	It("warns only about custody for a CA certificate that can otherwise serve", func() {
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		tmpl := servingLeafTemplate()
		tmpl.IsCA = true
		certPath, keyPath := writeTestKeypairFromTemplate(GinkgoT().TempDir(), tmpl)
		_, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		logged := buf.String()
		Expect(logged).To(ContainSubstring("puts a signing key on the network-facing listener"))
		Expect(logged).NotTo(ContainSubstring("cannot serve TLS"),
			"this certificate does serve TLS; saying otherwise is the false positive that trains operators to ignore the line")
	})

	It("warns again when a reload swaps a working certificate for one that cannot serve", func() {
		dir := GinkgoT().TempDir()
		certPath, keyPath := writeTestKeypair(dir, "working.example.com")
		reloader, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		writeTestKeypairFromTemplate(dir, bootstrappedCATemplate("ca.example.com"))
		Expect(reloader.reload()).To(Succeed())
		Expect(buf.String()).To(ContainSubstring("cannot serve TLS to a client that verifies it"),
			"a rotation onto an unusable certificate is exactly as silent as a bad one at startup")
		Expect(buf.String()).To(ContainSubstring("puts a signing key on the network-facing listener"))
	})
})

var _ = Describe("Configuration reloading", func() {
	var (
		dir      string
		cnFile   string
		auth     *api.AuthConfig
		reloader *configReloader
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		cnFile = filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\n"), 0600)).To(Succeed())

		allowList, err := buildAdminAllowList("puppet.example.com", cnFile)
		Expect(err).NotTo(HaveOccurred())
		auth = api.NewAuthConfig(nil, allowList)

		certPath, keyPath := writeTestKeypair(dir, "first.example.com")
		certs, err := newCertReloader(certPath, keyPath)
		Expect(err).NotTo(HaveOccurred())

		reloader = &configReloader{
			certs:     certs,
			auth:      auth,
			staticCNs: "puppet.example.com",
			cnFile:    cnFile,
		}
	})

	It("grants admin access to a newly listed compile server", func() {
		Expect(auth.IsOwnAdminCN("compile-2.example.com")).To(BeFalse())

		Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\ncompile-2.example.com\n"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(Succeed())

		Expect(auth.IsOwnAdminCN("compile-2.example.com")).To(BeTrue())
		Expect(auth.IsOwnAdminCN("compile-1.example.com")).To(BeTrue())
		Expect(auth.IsOwnAdminCN("puppet.example.com")).To(BeTrue(), "the configured CNs survive a reload")
	})

	It("withdraws admin access from a removed compile server", func() {
		// The security-relevant direction: a decommissioned compile server
		// must stop being an admin without waiting for a restart.
		Expect(auth.IsOwnAdminCN("compile-1.example.com")).To(BeTrue())

		Expect(os.WriteFile(cnFile, []byte("# decommissioned\n"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(Succeed())

		Expect(auth.IsOwnAdminCN("compile-1.example.com")).To(BeFalse())
	})

	It("rotates the TLS certificate", func() {
		writeTestKeypair(dir, "renewed.example.com")
		Expect(reloader.reload()).To(Succeed())
		Expect(servedCN(reloader.certs)).To(Equal("renewed.example.com"))
	})

	It("still applies the allow list when the certificate cannot be reloaded", func() {
		// One broken input must not block the other: the two are independent
		// and an operator fixing one should not have to fix both.
		Expect(os.WriteFile(filepath.Join(dir, "server.crt"), []byte("garbage"), 0600)).To(Succeed())
		Expect(os.WriteFile(cnFile, []byte("compile-9.example.com\n"), 0600)).To(Succeed())

		err := reloader.reload()
		Expect(err).To(HaveOccurred())
		Expect(auth.IsOwnAdminCN("compile-9.example.com")).To(BeTrue())
	})

	It("reports every failure together", func() {
		Expect(os.WriteFile(filepath.Join(dir, "server.crt"), []byte("garbage"), 0600)).To(Succeed())
		Expect(os.Remove(cnFile)).To(Succeed())

		err := reloader.reload()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("TLS cert/key"))
		Expect(err.Error()).To(ContainSubstring("puppet-server file"))
	})

	It("logs the CNs that a real reload granted and withdrew", func() {
		// Exercised through the live call site, not just diffAllowList's own
		// arguments: transposing the two would still leave the allow list
		// correct (so IsAdminCN specs stay green) while attributing every
		// grant as a withdrawal in the security audit log.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		defer slog.SetDefault(orig)

		Expect(os.WriteFile(cnFile, []byte("compile-2.example.com\n"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(Succeed())

		logged := buf.String()
		Expect(logged).To(ContainSubstring("added=[compile-2.example.com]"))
		Expect(logged).To(ContainSubstring("removed=[compile-1.example.com]"))
	})

	It("keeps a failure visible in the status until a reload succeeds", func() {
		// Otherwise the next heartbeat overwrites the notice and the operator
		// is left believing the reload took effect.
		Expect(reloader.statusSuffix()).To(BeEmpty())

		Expect(os.Remove(cnFile)).To(Succeed())
		Expect(reloader.reload()).To(HaveOccurred())
		Expect(reloader.statusSuffix()).To(ContainSubstring("FAILED"))

		Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\n"), 0600)).To(Succeed())
		Expect(reloader.reload()).To(Succeed())
		Expect(reloader.statusSuffix()).To(BeEmpty())
	})

	It("does nothing when there is nothing reloadable", func() {
		// Plain HTTP mode: no TLS keypair, no auth config.
		Expect((&configReloader{}).reload()).To(Succeed())
	})
})

var _ = Describe("Reload watcher", func() {
	var (
		dir      string
		cnFile   string
		auth     *api.AuthConfig
		reloader *configReloader
		rec      *notifyRecorder
		notifier *sdnotify.Notifier
		hupCh    chan os.Signal
	)

	BeforeEach(func() {
		// Claim SIGHUP before anything can send one, exactly as the server
		// does before its own startup work: the default action for an
		// unhandled SIGHUP is to terminate, which would take the test binary
		// with it.
		hupCh = make(chan os.Signal, 1)
		signal.Notify(hupCh, syscall.SIGHUP)
		DeferCleanup(func() { signal.Stop(hupCh) })

		dir = GinkgoT().TempDir()
		cnFile = filepath.Join(dir, "servers.txt")
		Expect(os.WriteFile(cnFile, []byte("compile-1.example.com\n"), 0600)).To(Succeed())

		allowList, err := buildAdminAllowList("", cnFile)
		Expect(err).NotTo(HaveOccurred())
		auth = api.NewAuthConfig(nil, allowList)
		reloader = &configReloader{auth: auth, cnFile: cnFile}

		rec = startNotifyRecorder(nil)
		notifier = sdnotify.New()
		DeferCleanup(func() { Expect(notifier.Close()).To(Succeed()) })
	})

	// startWatcher runs the watcher for the duration of the spec, fed by the
	// same pre-registered channel the server wires up in main.
	startWatcher := func() {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			runReloadWatcher(ctx, hupCh, notifier, reloader, func() string { return "serving" + reloader.statusSuffix() })
		}()
		DeferCleanup(func() {
			cancel()
			Eventually(done).Should(BeClosed())
		})
	}

	It("reloads on SIGHUP and reports the reload to the service manager", func() {
		startWatcher()

		Expect(os.WriteFile(cnFile, []byte("compile-2.example.com\n"), 0600)).To(Succeed())
		Expect(syscall.Kill(os.Getpid(), syscall.SIGHUP)).To(Succeed())

		// The STATUS payload, not just the RELOADING prefix. The watcher was
		// changed to send r.reloadingStatus() instead of a hardcoded string,
		// and the three outcomes of that function are covered directly in
		// servingcert_test.go -- but nothing asserted the call site, so
		// reverting it to any fixed string left every spec green while systemd
		// announced a TLS rotation that a self-provisioning CA never performs.
		//
		// This reloader has auth set and certs nil, which is the
		// self-provisioned shape, so the allow-list-only text is the correct
		// one here.
		Eventually(rec.msgs).Should(Receive(And(
			HavePrefix("RELOADING=1"),
			ContainSubstring("STATUS=Reloading the admin allow list"),
		)))
		Eventually(rec.msgs).Should(Receive(Equal("READY=1\nSTATUS=serving\n")))
		Expect(auth.IsOwnAdminCN("compile-2.example.com")).To(BeTrue())
		Expect(auth.IsOwnAdminCN("compile-1.example.com")).To(BeFalse())
	})

	It("keeps serving and says so when the reload fails", func() {
		startWatcher()

		Expect(os.Remove(cnFile)).To(Succeed())
		Expect(syscall.Kill(os.Getpid(), syscall.SIGHUP)).To(Succeed())

		// READY=1 still closes out the reload -- withholding it would only
		// hang `systemctl reload` -- but the status says the reload failed.
		Eventually(rec.msgs).Should(Receive(HavePrefix("RELOADING=1")))
		Eventually(rec.msgs).Should(Receive(Equal("READY=1\nSTATUS=serving | last reload FAILED, see the logs\n")))
		Expect(auth.IsOwnAdminCN("compile-1.example.com")).To(BeTrue(), "the previous allow list is still in force")
	})

	It("applies a reload that arrived before the watcher started", func() {
		// This is the guarantee that justifies registering SIGHUP at the top
		// of RunE, ahead of storage, the signer handshake and the listener:
		// a reload delivered during a slow start waits in the buffer instead
		// of killing the process, and is applied when the loop reaches it.
		Expect(os.WriteFile(cnFile, []byte("early.example.com\n"), 0600)).To(Succeed())
		Expect(syscall.Kill(os.Getpid(), syscall.SIGHUP)).To(Succeed())
		Eventually(hupCh).Should(HaveLen(1), "the signal must be queued, not dropped")

		startWatcher()

		Eventually(func() bool { return auth.IsOwnAdminCN("early.example.com") }).Should(BeTrue())
		Eventually(rec.msgs).Should(Receive(HavePrefix("RELOADING=1")))
	})

	It("handles repeated reloads", func() {
		startWatcher()

		for _, cn := range []string{"a.example.com", "b.example.com"} {
			Expect(os.WriteFile(cnFile, []byte(cn+"\n"), 0600)).To(Succeed())
			Expect(syscall.Kill(os.Getpid(), syscall.SIGHUP)).To(Succeed())
			Eventually(func() bool { return auth.IsOwnAdminCN(cn) }).Should(BeTrue())
		}
	})
})
