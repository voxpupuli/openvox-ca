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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/certstore"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The CA's own serving certificate.
//
// Two halves, and they fail differently. The configuration half is refusals: a
// serving certificate that cannot serve, a store aimed at the CA's own files,
// and the combination with tls_cert/tls_key. The runtime half is the part
// nothing else in the tree does -- issue before the listener binds, and reach
// the listener again on renewal without a rebuild.
var _ = Describe("The CA's own serving certificate", func() {
	// servingDir is a directory to keep the file store's pair in, distinct from
	// the CA's own so no spec is accidentally asserting the reserved-path check.
	var servingDir string

	BeforeEach(func() {
		servingDir = GinkgoT().TempDir()
	})

	filesEntry := func() *certstore.Entry {
		return &certstore.Entry{
			Certname:    "ca.test",
			Names:       []string{"ca.test"},
			RenewBefore: certstore.Duration(720 * time.Hour),
			// ECDSA throughout: every issuance in these specs generates a key,
			// and RSA 2048 under -race dominates the runtime. No assertion here
			// is about the algorithm.
			KeyAlgo: "ecdsa",
			KeySize: 256,
			Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
				Cert: filepath.Join(servingDir, "tls.crt"),
				Key:  filepath.Join(servingDir, "tls.key"),
			}},
		}
	}

	// cfgWith is a server configuration with self-provisioning on and nothing
	// else that would reach the network.
	cfgWith := func(e *certstore.Entry) *serverConfig {
		return &serverConfig{Hostname: "ca.test", ServingCert: e}
	}

	// build runs the configuration half against a temp cadir.
	build := func(cfg *serverConfig) (*servingCert, error) {
		return buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
	}

	Describe("configuration", func() {
		It("is off by default, and leaves TLS to tls_cert/tls_key", func() {
			cfg := &serverConfig{}
			Expect(cfg.tlsEnabled()).To(BeFalse())

			sc, err := build(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(sc).To(BeNil())
			// A nil serving certificate must answer the listener's question
			// without a nil check at the call site, or main.go grows one.
			Expect(sc.getCertificate()).To(BeNil())
		})

		It("enables TLS on its own, with neither tls_cert nor tls_key set", func() {
			// The predicate five sites read. A self-provisioned CA that
			// satisfied some of them would come up serving HTTPS with no client
			// authentication, or refuse to bind having enabled TLS.
			Expect(cfgWith(filesEntry()).tlsEnabled()).To(BeTrue())
		})

		DescribeTable("is refused alongside an operator-supplied keypair",
			func(mutate func(*serverConfig)) {
				cfg := cfgWith(filesEntry())
				mutate(cfg)

				_, err := build(cfg)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("mutually exclusive"))
				// Both names, because an operator who set one of them has to be
				// told which pair to remove.
				Expect(err.Error()).To(ContainSubstring("serving_cert"))
				Expect(err.Error()).To(ContainSubstring("tls_cert"))
			},
			// Either alone, not only the pair: tls_cert without tls_key does not
			// enable TLS on its own, but it still names a path this mechanism
			// must never be understood to write to.
			Entry("tls_cert alone", func(c *serverConfig) { c.TLSCert = "/etc/tls.crt" }),
			Entry("tls_key alone", func(c *serverConfig) { c.TLSKey = "/etc/tls.key" }),
			Entry("both", func(c *serverConfig) { c.TLSCert = "/etc/tls.crt"; c.TLSKey = "/etc/tls.key" }),
		)

		It("names its own configuration block in a refusal, without an index", func() {
			// The seam's label, consumed rather than worked around. An operator
			// with no managed_certs block at all must never be told to go and
			// fix managed_certs[0], and `serving_cert[0]` would misname a block
			// holding one certificate just as precisely.
			e := filesEntry()
			e.RenewBefore = 0

			_, err := build(cfgWith(e))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("serving_cert (ca.test):"))
			Expect(err.Error()).NotTo(ContainSubstring("managed_certs"))
			Expect(err.Error()).NotTo(ContainSubstring("serving_cert["))
		})

		It("refuses a store that names neither flavour, and says so as serving_cert", func() {
			e := filesEntry()
			e.Store = certstore.StoreConfig{}

			_, err := build(cfgWith(e))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("serving_cert (ca.test):"))
			Expect(err.Error()).To(ContainSubstring("store must name where the certificate lives"))
		})

		Describe("extended key usage", func() {
			It("defaults to serverAuth and clientAuth, the pair everything else gets", func() {
				sc, err := build(cfgWith(filesEntry()))
				Expect(err).NotTo(HaveOccurred())
				// Nil rather than an explicit pair: internal/ca reads a nil
				// ExtKeyUsage as both, and spelling it out here would be a
				// second answer to what the default is.
				Expect(sc.entry.Spec.ExtKeyUsage).To(BeNil())
			})

			It("allows narrowing to serverAuth", func() {
				e := filesEntry()
				e.Usages = []string{"serverAuth"}

				sc, err := build(cfgWith(e))
				Expect(err).NotTo(HaveOccurred())
				Expect(sc.entry.Spec.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
			})

			It("refuses narrowing away serverAuth, which the listener cannot survive", func() {
				// The failure this prevents is not local: the listener presents
				// the certificate quite happily and every client that verifies
				// it refuses, so the fault surfaces somewhere else entirely.
				e := filesEntry()
				e.Usages = []string{"clientAuth"}

				_, err := build(cfgWith(e))
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("does not include serverAuth"))
				Expect(err.Error()).To(ContainSubstring("[serverAuth] is supported"))
			})

			DescribeTable("accepts the spellings internal/certstore accepts",
				func(usages []string) {
					e := filesEntry()
					e.Usages = usages
					_, err := build(cfgWith(e))
					Expect(err).NotTo(HaveOccurred())
				},
				Entry("case-insensitive", []string{"SERVERAUTH"}),
				Entry("with surrounding space", []string{" serverAuth "}),
				Entry("both, narrowed explicitly", []string{"serverAuth", "clientAuth"}),
			)
		})

		Describe("against the CA's own files", func() {
			It("refuses a serving store aimed at the cadir", func() {
				cadir := GinkgoT().TempDir()
				e := filesEntry()
				e.Store.Files.Cert = filepath.Join(cadir, "ca_crt.pem")

				_, err := buildServingCert(cfgWith(e), cadir, "", stubCACerts{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(HavePrefix("serving_cert (ca.test)"))
				Expect(err.Error()).To(ContainSubstring("cadir"))
			})

			It("does not refuse the serving store for colliding with itself", func() {
				// caOwnedPaths reserves these three paths so that a
				// managed_certs entry cannot overwrite them. Checking the
				// serving entry against that same list without taking its own
				// entries out would refuse every valid configuration, and the
				// spec above would still pass.
				_, err := build(cfgWith(filesEntry()))
				Expect(err).NotTo(HaveOccurred())
			})

			It("reserves the serving pair against a managed_certs entry", func() {
				// The direction that protects the listener. Without it the
				// reconcile loop writes a component's certificate over the one
				// the CA is presenting, and then the two replace each other on
				// every pass for ever, because each reads its store back.
				e := filesEntry()
				cfg := cfgWith(e)
				cfg.ManagedCerts = certstore.Config{{
					Certname:    "component.test",
					Names:       []string{"component.test"},
					RenewBefore: certstore.Duration(720 * time.Hour),
					Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
						Cert: e.Store.Files.Cert,
						Key:  filepath.Join(servingDir, "other.key"),
					}},
				}}

				err := attachManagedCerts(&ca.CA{}, cfg, GinkgoT().TempDir(), "", stubCACerts{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("managed_certs[0] (component.test)"))
				Expect(err.Error()).To(ContainSubstring(servingCertPathSetting + "cert"))
			})
		})
	})

	Describe("at startup and on renewal", func() {
		var (
			ctx   context.Context
			myCA  *ca.CA
			store *storage.StorageService
		)

		BeforeEach(func() {
			ctx = context.Background()
			myCA, store = newRefresherTestCA()
			myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		})

		// provision builds the serving certificate from e and runs the startup
		// path, exactly as the serve command does.
		provision := func(e *certstore.Entry) (*servingCert, error) {
			GinkgoHelper()
			sc, err := buildServingCert(cfgWith(e), GinkgoT().TempDir(), "", store)
			Expect(err).NotTo(HaveOccurred())
			Expect(sc).NotTo(BeNil())
			myCA.ManagedCerts = append(myCA.ManagedCerts, sc.entry)
			return sc, provisionServingCert(ctx, myCA, sc)
		}

		It("issues on a first start, so a fresh deployment binds", func() {
			// The deadlock this feature exists to break: nothing has issued
			// this certificate, and nothing can until the CA is serving.
			sc, err := provision(filesEntry())
			Expect(err).NotTo(HaveOccurred())

			cert, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cert.Leaf.Subject.CommonName).To(Equal("ca.test"))
			Expect(cert.Leaf.DNSNames).To(ConsistOf("ca.test"))

			// And it is really in the store, not only in memory: a restart has
			// to find it, or every restart issues and supersedes.
			Expect(filepath.Join(servingDir, "tls.crt")).To(BeAnExistingFile())
			Expect(filepath.Join(servingDir, "tls.key")).To(BeAnExistingFile())
		})

		It("issues a certificate this CA signed, with a serving keyUsage", func() {
			sc, err := provision(filesEntry())
			Expect(err).NotTo(HaveOccurred())

			cert, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cert.Leaf.IsCA).To(BeFalse(), "the listener must not present a signing key")
			// The checks reload.go applies to an operator-supplied keypair. A
			// certificate this CA issued for itself must pass all of them, or
			// the holder's warning fires on every install.
			Expect(servingCertProblems(cert.Leaf)).To(BeEmpty())
		})

		It("really omits clientAuth when the operator narrows it", func() {
			// The setting must not be decorative. #242 treats a usage mismatch
			// as grounds to reissue, so this takes effect when an operator
			// narrows it rather than at natural expiry -- and what reaches the
			// certificate is what this asserts.
			e := filesEntry()
			e.Usages = []string{"serverAuth"}

			sc, err := provision(e)
			Expect(err).NotTo(HaveOccurred())

			cert, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cert.Leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth))
			Expect(cert.Leaf.ExtKeyUsage).NotTo(ContainElement(x509.ExtKeyUsageClientAuth))
		})

		It("carries clientAuth by default, which is what makes it an admin credential", func() {
			// The opposite of the least-privilege instinct, and deliberate: one
			// host running openvox-ca and OpenVox Server on a shared serving
			// certificate is a normal deployment. Asserted so that narrowing
			// the default becomes a decision somebody has to make here.
			sc, err := provision(filesEntry())
			Expect(err).NotTo(HaveOccurred())

			cert, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())
			Expect(cert.Leaf.ExtKeyUsage).To(ConsistOf(
				x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth))
		})

		It("presents a renewed certificate through a real handshake, with no rebuild", func() {
			// Through a handshake rather than through the holder's internals,
			// because what is being asserted is that the *listener* picks the
			// renewal up. A holder that stored the new certificate while
			// crypto/tls kept presenting the old one would satisfy every
			// assertion made against the holder alone.
			sc, err := provision(filesEntry())
			Expect(err).NotTo(HaveOccurred())

			// One listener, built once, never rebuilt for the rest of this
			// spec. Its TLSConfig is the one main.go builds.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = ln.Close() })
			tlsLn := tls.NewListener(ln, &tls.Config{
				GetCertificate: sc.holder.GetCertificate,
				MinVersion:     tls.VersionTLS12,
			})
			go func() {
				defer GinkgoRecover()
				for {
					conn, err := tlsLn.Accept()
					if err != nil {
						return
					}
					// Drive the handshake and drop the connection: the
					// certificate is chosen during it, which is all this needs.
					go func() {
						defer GinkgoRecover()
						defer func() { _ = conn.Close() }()
						_ = conn.(*tls.Conn).HandshakeContext(ctx)
					}()
				}
			}()

			before := handshakeSerial(ln.Addr().String())
			Expect(before).NotTo(BeEmpty())

			// A renewal the mechanism decides on for itself, rather than a
			// certificate pushed into the holder by hand. Revoking is the
			// realistic trigger that is also deterministic: the decision step
			// treats revoked material as grounds to reissue, and it re-keys
			// while doing so.
			Expect(myCA.Revoke(ctx, "ca.test")).To(Succeed())
			issued, err := myCA.ReconcileManaged(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(Equal(1), "the reconcile pass must have reissued")

			after := handshakeSerial(ln.Addr().String())
			Expect(after).NotTo(Equal(before),
				"the listener is still presenting the certificate it started with")
		})

		It("picks up a renewal another replica performed", func() {
			// Our own Save never runs in that case: the winner writes under the
			// subject lock, our next pass loads the winner's certificate and
			// the decision finds it current. Without Load installing, the
			// listener would keep presenting the predecessor until it was
			// revoked at the end of the supersession window.
			sc, err := provision(filesEntry())
			Expect(err).NotTo(HaveOccurred())
			before, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())

			// A peer's issuance, written straight into the shared store so that
			// nothing of this replica's own is involved.
			peerCert, peerKey := reissueInto(ctx, myCA, "ca.test")
			Expect(os.WriteFile(filepath.Join(servingDir, "tls.crt"), peerCert, 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(servingDir, "tls.key"), peerKey, 0o600)).To(Succeed())

			// A pass that issues nothing: the material is another replica's and
			// is current, so the decision leaves it alone.
			issued, err := myCA.ReconcileManaged(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(Equal(0), "precondition: the peer's certificate must be current")

			after, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())
			Expect(after.Leaf.SerialNumber.String()).NotTo(Equal(before.Leaf.SerialNumber.String()))
			Expect(after.Leaf.SerialNumber.String()).To(Equal(serialOf(peerCert)))
		})

		Describe("startup failure", func() {
			It("is fatal when the store's directory does not exist, and names it", func() {
				// A component store's absence is routine and self-heals on the
				// next pass. This one is not: the listener has nothing to
				// present, so the CA must refuse to come up rather than bind
				// and fail every handshake.
				e := filesEntry()
				missing := filepath.Join(servingDir, "absent")
				e.Store.Files.Cert = filepath.Join(missing, "tls.crt")
				e.Store.Files.Key = filepath.Join(missing, "tls.key")

				_, err := provision(e)
				Expect(err).To(HaveOccurred())
				// Not merely that nothing appeared -- the reconcile pass's own
				// failure, recorded by this entry's wrapper, because the pass
				// reports one error across every entry and cannot attribute it.
				Expect(err.Error()).To(ContainSubstring("does not exist"))
				Expect(err.Error()).To(ContainSubstring(missing))
			})

			It("is fatal when the store cannot be read, and names the store", func() {
				// Unreadable rather than absent, which is the other half of the
				// requirement and a different code path: Load fails outright
				// instead of reporting empty material.
				e := filesEntry()
				Expect(os.Mkdir(e.Store.Files.Cert, 0o755)).To(Succeed())

				_, err := provision(e)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("cannot be read"))
				Expect(err.Error()).To(ContainSubstring("the file pair at " + e.Store.Files.Cert))
			})

			It("says which store failed, not merely that a certificate is missing", func() {
				// "Startup failure looks different per store, and the message
				// must say which." A message that named neither the store nor
				// the reason would satisfy every other spec here.
				e := filesEntry()
				e.Store.Files.Cert = filepath.Join(servingDir, "absent", "tls.crt")
				e.Store.Files.Key = filepath.Join(servingDir, "absent", "tls.key")

				_, err := provision(e)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("the file pair at"))
				Expect(err.Error()).To(ContainSubstring("the listener has nothing to present"))
			})
		})

		It("does not refuse to start when the store holds usable material a failed pass left", func() {
			// The asymmetry that makes this fail-fast rather than brittle. A
			// renewal that did not happen is not an outage: the certificate in
			// the store is still one the CA can serve while the loop retries,
			// and refusing to bind would turn a recoverable failure into one.
			sc, err := provision(filesEntry())
			Expect(err).NotTo(HaveOccurred())
			before, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())

			// A second start against the same store, with writes now failing.
			// The material from the first start is still there and still good.
			Expect(os.Chmod(servingDir, 0o500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(servingDir, 0o700) })

			myCA.ManagedCerts = nil
			sc2, err := provision(filesEntry())
			Expect(err).NotTo(HaveOccurred(), "a readable store must not be fatal")

			after, err := sc2.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())
			Expect(after.Leaf.SerialNumber.String()).To(Equal(before.Leaf.SerialNumber.String()))
		})
	})

	Describe("the holder", func() {
		It("refuses material that is not a keypair, naming the store", func() {
			h := &servingCertHolder{describe: "the file pair at /tmp/tls.crt"}
			err := h.install([]byte("not a certificate"), []byte("not a key"))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("the file pair at /tmp/tls.crt"))
		})

		It("names the encrypted-key case, which crypto/tls reports as something else", func() {
			// crypto/tls accepts any PEM block whose type ends " PRIVATE KEY",
			// so an encrypted one passes the type check and then fails to parse
			// with a message that says nothing about encryption. Encrypting the
			// serving key is on #326's decided-against list because it stopped
			// the server booting; this is what makes the remaining route to it
			// legible.
			encrypted := pem.EncodeToMemory(&pem.Block{
				Type:  "ENCRYPTED PRIVATE KEY",
				Bytes: []byte("ciphertext"),
			})
			h := &servingCertHolder{describe: "Secret openvox/ca-tls"}
			err := h.install([]byte("irrelevant"), encrypted)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be unencrypted"))
		})

		It("reports no certificate before one has been issued", func() {
			h := &servingCertHolder{describe: "Secret openvox/ca-tls"}
			_, err := h.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).To(HaveOccurred())
		})
	})
})

// handshakeSerial dials addr, completes a TLS handshake without verifying, and
// returns the serial of the certificate the server presented.
//
// InsecureSkipVerify because the assertion is about *which* certificate the
// listener chose, not about whether a client would trust it -- and the CA that
// issued it is a per-spec temporary one.
func handshakeSerial(addr string) string {
	GinkgoHelper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		// Skipping verification is the point: the assertion is which
		// certificate the listener chose, and the CA that issued it is a
		// per-spec temporary one no root store knows about.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = conn.Close() }()

	certs := conn.ConnectionState().PeerCertificates
	Expect(certs).NotTo(BeEmpty())
	return certs[0].SerialNumber.String()
}

// reissueInto mints a fresh certificate for subject as another replica would,
// returning the PEM pair. It goes through the CA's own managed-certificate
// path, so the material is indistinguishable from a peer's.
func reissueInto(ctx context.Context, myCA *ca.CA, subject string) (certPEM, keyPEM []byte) {
	GinkgoHelper()
	var gotCert, gotKey []byte
	entry := ca.ManagedCert{
		Spec: ca.CertSpec{
			Subject:     subject,
			DNSNames:    []string{subject},
			RenewBefore: 720 * time.Hour,
			KeyConfig:   ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256},
		},
		// An empty store, so the decision always issues.
		Load: func(context.Context) ([]byte, []byte, error) { return nil, nil, nil },
		Save: func(_ context.Context, c, k []byte) error {
			gotCert, gotKey = c, k
			return nil
		},
	}
	// The same CA, briefly reconciling a different entry: a second *ca.CA
	// cannot be a copy of this one, because it holds a mutex.
	saved := myCA.ManagedCerts
	defer func() { myCA.ManagedCerts = saved }()
	myCA.ManagedCerts = []ca.ManagedCert{entry}
	issued, err := myCA.ReconcileManaged(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(issued).To(Equal(1))
	Expect(gotCert).NotTo(BeEmpty())
	return gotCert, gotKey
}

// serialOf returns the serial of the first certificate in a PEM bundle.
func serialOf(certPEM []byte) string {
	GinkgoHelper()
	block, _ := pem.Decode(certPEM)
	Expect(block).NotTo(BeNil())
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return cert.SerialNumber.String()
}
