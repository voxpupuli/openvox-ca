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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

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

		It("does not refuse to start when a failed pass left usable material behind", func() {
			// The asymmetry that makes this fail-fast rather than brittle. A
			// renewal that did not happen is not an outage: the certificate in
			// the store is still one the CA can serve while the loop retries,
			// and refusing to bind would turn a recoverable failure into one.
			//
			// The first version of this spec did not reach that arm at all. It
			// made the directory read-only and provisioned again, but the
			// certificate from the first start was still current, so the
			// decision never issued, Save was never called, and nothing failed
			// -- it asserted the ordinary restart case while claiming to assert
			// this one. Mutating provisionServingCert to return the pass error
			// instead of logging it left it green.
			//
			// So the pass is made to fail for a reason that does not depend on
			// who the test runs as: revoking forces a reissue, and the entry's
			// chain file is pointed at a directory that does not exist, which
			// FileStore.Save refuses before it writes anything. A read-only
			// directory would have been inert under a root-run container.
			sc, err := provision(filesEntry())
			Expect(err).NotTo(HaveOccurred())
			before, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
			Expect(err).NotTo(HaveOccurred())

			Expect(myCA.Revoke(ctx, "ca.test")).To(Succeed())

			doomed := filesEntry()
			doomed.Store.Files.CA = filepath.Join(servingDir, "absent", "ca.crt")
			myCA.ManagedCerts = nil
			sc2, err := provision(doomed)
			Expect(err).NotTo(HaveOccurred(), "a readable store must not be fatal")

			// The precondition, asserted rather than assumed: this entry's own
			// Save really did fail on this pass. Without this the spec silently
			// degrades back into a restart test the moment the fixture stops
			// forcing a reissue.
			Expect(sc2.ownError()).To(HaveOccurred(),
				"precondition: the reconcile pass must have failed against this store")
			Expect(sc2.ownError().Error()).To(ContainSubstring("does not exist"))

			// And the material the failed pass left behind is what the listener
			// still presents.
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

// The Secret store, which no spec above reaches: filesEntry is the only entry
// constructor there, so NeedsKubernetes is false throughout and the whole
// Kubernetes arm of servingCertDeps returns at its first branch.
//
// That is the deployment this feature was built for -- ci/serving-cert-values.yaml
// calls itself "the deployment serving_cert exists for" and uses a Secret -- and
// a defect in it is not a delayed certificate but a CA that cannot bind. The
// same seam managed_certs_config_test.go uses makes both arms reachable.
var _ = Describe("the CA's own serving certificate in a Kubernetes Secret", func() {
	const secretStore = `
serving_cert:
  certname: ca.example.com
  names: [ca.example.com]
  renew_before: 720h
  store: {secret: {name: openvox-ca-serving-tls}}
`

	// stubCluster points both lookups at fakes and restores them afterwards.
	stubCluster := func(client func(string) (kubernetes.Interface, error), ns func() (string, error)) {
		GinkgoHelper()
		restoreClient, restoreNS := inClusterClientset, podNamespace
		DeferCleanup(func() { inClusterClientset, podNamespace = restoreClient, restoreNS })
		inClusterClientset, podNamespace = client, ns
	}

	It("names the CA's own serving certificate when no cluster client can be built", func() {
		// The label matters: an operator reading this has both a managed_certs
		// block and a serving_cert block to check, and the message is what says
		// which one made in-cluster credentials a startup requirement.
		stubCluster(
			func(what string) (kubernetes.Interface, error) {
				return nil, errors.New("not in a pod (" + what + ")")
			},
			func() (string, error) { return "openvox", nil },
		)

		_, err := buildServingCert(writeServerConfig(secretStore), specCADir,
			specConfigPath, stubCACerts{})
		Expect(err).To(MatchError(ContainSubstring("the CA's own serving certificate")))
	})

	It("says which setting needs the namespace it could not resolve", func() {
		stubCluster(
			func(string) (kubernetes.Interface, error) { return fake.NewClientset(), nil },
			func() (string, error) {
				return "", errors.New("open /var/run/secrets/.../namespace: no such file")
			},
		)

		_, err := buildServingCert(writeServerConfig(secretStore), specCADir,
			specConfigPath, stubCACerts{})
		Expect(err).To(MatchError(ContainSubstring("resolving the namespace for the CA's own")))
		Expect(err).To(MatchError(ContainSubstring("no such file")))
	})

	It("does not resolve a namespace the store spells out", func() {
		// The mutation this catches is dropping the NeedsDefaultNamespace gate:
		// a configuration naming its own namespace must not be held up by an
		// unreadable ServiceAccount mount.
		stubCluster(
			func(string) (kubernetes.Interface, error) { return fake.NewClientset(), nil },
			func() (string, error) {
				Fail("podNamespace must not be called when the store names its namespace")
				return "", nil
			},
		)

		sc, err := buildServingCert(writeServerConfig(`
serving_cert:
  certname: ca.example.com
  names: [ca.example.com]
  renew_before: 720h
  store: {secret: {name: openvox-ca-serving-tls, namespace: openvox}}
`), specCADir, specConfigPath, stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
		// The store names itself for the fatal message, and the namespace it
		// names is the configured one.
		Expect(sc.store.String()).To(Equal("Secret openvox/openvox-ca-serving-tls"))
	})

	It("builds the store in the CA pod's namespace when the entry omits one", func() {
		stubCluster(
			func(string) (kubernetes.Interface, error) { return fake.NewClientset(), nil },
			func() (string, error) { return "ca-system", nil },
		)

		sc, err := buildServingCert(writeServerConfig(secretStore), specCADir,
			specConfigPath, stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sc.store.String()).To(Equal("Secret ca-system/openvox-ca-serving-tls"))
	})

	It("refuses a Secret the Kubernetes exporter also writes", func() {
		// Only reachable with a Secret store, so no spec above can cover it.
		// Both write ca.crt, so they would take the key from each other on
		// every pass.
		stubCluster(
			func(string) (kubernetes.Interface, error) { return fake.NewClientset(), nil },
			func() (string, error) { return "openvox", nil },
		)

		_, err := buildServingCert(writeServerConfig(`
kubernetes_export:
  targets:
    - kind: Secret
      metadata: {name: openvox-ca-serving-tls, namespace: openvox}
      cert_key: ca.crt
serving_cert:
  certname: ca.example.com
  names: [ca.example.com]
  renew_before: 720h
  store: {secret: {name: openvox-ca-serving-tls, namespace: openvox}}
`), specCADir, specConfigPath, stubCACerts{})
		Expect(err).To(MatchError(ContainSubstring("serving_cert")))
		Expect(err).To(MatchError(ContainSubstring("kubernetes_export")))
	})
})

// Collisions between the two blocks that feed one reconcile set.
//
// serving_cert and managed_certs are validated in separate calls, so
// internal/certstore's own duplicate-certname and duplicate-Secret checks never
// see the pair -- each is built per call, over one slice. main.go then appends
// the serving entry to the same ca.CA.ManagedCerts slice, and internal/ca
// de-duplicates nothing.
var _ = Describe("serving_cert colliding with managed_certs", func() {
	entry := func(certname, cert, key string) *certstore.Entry {
		return &certstore.Entry{
			Certname: certname, Names: []string{certname},
			RenewBefore: certstore.Duration(720 * time.Hour),
			Store:       certstore.StoreConfig{Files: &certstore.FilesConfig{Cert: cert, Key: key}},
		}
	}

	It("refuses a shared certname", func() {
		// One inventory slot per subject: each pass would find the other's
		// certificate failing its own spec and replace it, for ever, and the
		// certificate being replaced is the one the listener presents.
		cfg := &serverConfig{
			ServingCert:  entry("shared.test", "/srv/serving/tls.crt", "/srv/serving/tls.key"),
			ManagedCerts: certstore.Config{*entry("shared.test", "/srv/comp/tls.crt", "/srv/comp/tls.key")},
		}

		_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
		Expect(err).To(MatchError(ContainSubstring("serving_cert (shared.test)")))
		Expect(err).To(MatchError(ContainSubstring("managed_certs[0]")))
		Expect(err).To(MatchError(ContainSubstring("one inventory slot")))
	})

	It("allows two different certnames", func() {
		// The guard must not refuse the ordinary configuration, which is the
		// one an operator running components alongside a self-provisioning CA
		// actually writes.
		cfg := &serverConfig{
			ServingCert:  entry("ca.test", "/srv/serving/tls.crt", "/srv/serving/tls.key"),
			ManagedCerts: certstore.Config{*entry("component.test", "/srv/comp/tls.crt", "/srv/comp/tls.key")},
		}

		_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("refuses a shared Secret",
		func(servingNS, managedNS string, wantOmissionNote bool) {
			// One field manager across every managed certificate, so neither
			// apply ever raises a conflict and the two overwrite each other's
			// material on every pass.
			cfg := &serverConfig{
				ServingCert: &certstore.Entry{
					Certname: "ca.test", Names: []string{"ca.test"},
					RenewBefore: certstore.Duration(720 * time.Hour),
					Store: certstore.StoreConfig{Secret: &certstore.SecretConfig{
						Name: "shared-tls", Namespace: servingNS}},
				},
				ManagedCerts: certstore.Config{{
					Certname: "component.test", Names: []string{"component.test"},
					RenewBefore: certstore.Duration(720 * time.Hour),
					Store: certstore.StoreConfig{Secret: &certstore.SecretConfig{
						Name: "shared-tls", Namespace: managedNS}},
				}},
			}

			_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
			Expect(err).To(MatchError(ContainSubstring("shared-tls")))
			Expect(err).To(MatchError(ContainSubstring("serving_cert (ca.test)")))
			if wantOmissionNote {
				Expect(err).To(MatchError(ContainSubstring("omitted namespace")))
			} else {
				Expect(err).NotTo(MatchError(ContainSubstring("omitted namespace")))
			}
		},
		Entry("both spelled out and equal", "openvox", "openvox", false),
		// An omission on either side resolves to the CA pod's own namespace,
		// which is not known before a client exists -- so the pair is refused
		// rather than risked, and the message says why.
		Entry("the serving entry omits its namespace", "", "openvox", true),
		Entry("the managed entry omits its namespace", "openvox", "", true),
		Entry("both omit their namespace", "", "", true),
	)

	DescribeTable("refuses a chain file that is a component's material",
		func(componentField string) {
			// The one file pairing nothing else catches: caOwnedPaths reserves
			// the serving cert and key, but leaves the chain file unreserved so
			// two entries may share one. That exemption is about chain-to-chain
			// sharing; chain-over-material is a loop, and the serving issuance
			// would overwrite the component's material with the CA chain on
			// every pass.
			//
			// A table over both arms because the guard is a loop over both, and
			// a single spec pinning only `cert` let the `key` element be
			// deleted with the suite green -- which is the arm where the file
			// overwritten is a private key.
			comp := &certstore.FilesConfig{Cert: "/srv/comp/tls.crt", Key: "/srv/comp/tls.key"}
			chain := comp.Cert
			if componentField == "key" {
				chain = comp.Key
			}
			cfg := &serverConfig{
				ServingCert: &certstore.Entry{
					Certname: "ca.test", Names: []string{"ca.test"},
					RenewBefore: certstore.Duration(720 * time.Hour),
					Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
						Cert: "/srv/serving/tls.crt", Key: "/srv/serving/tls.key",
						CA: chain}},
				},
				ManagedCerts: certstore.Config{{
					Certname: "component.test", Names: []string{"component.test"},
					RenewBefore: certstore.Duration(720 * time.Hour),
					Store:       certstore.StoreConfig{Files: comp},
				}},
			}

			_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
			Expect(err).To(MatchError(ContainSubstring("writes its CA chain")))
			Expect(err).To(MatchError(ContainSubstring("managed_certs[0] (component.test)")))
			Expect(err).To(MatchError(ContainSubstring("store.files." + componentField)))
		},
		Entry("over the component's certificate", "cert"),
		// The worse of the two: the file overwritten is a private key.
		Entry("over the component's private key", "key"),
	)

	It("still allows two entries to share one chain file", func() {
		// The layout the exemption exists for, and the thing the check above
		// must not break: every entry writes the same chain from the same
		// source, and none reads it back.
		cfg := &serverConfig{
			ServingCert: &certstore.Entry{
				Certname: "ca.test", Names: []string{"ca.test"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
					Cert: "/srv/serving/tls.crt", Key: "/srv/serving/tls.key",
					CA: "/etc/openvox/ca.pem"}},
			},
			ManagedCerts: certstore.Config{{
				Certname: "component.test", Names: []string{"component.test"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
					Cert: "/srv/comp/tls.crt", Key: "/srv/comp/tls.key",
					CA: "/etc/openvox/ca.pem"}},
			}},
		}

		_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("allows two differently named Secrets in one namespace", func() {
		// The must-not-refuse twin for the name arm of the guard. The certname
		// and chain-file guards each have one; this one did not, so widening
		// the condition to ignore the Secret name -- refusing every deployment
		// whose serving and component Secrets differ, which is all of them --
		// left the whole suite green.
		restoreClient, restoreNS := inClusterClientset, podNamespace
		DeferCleanup(func() { inClusterClientset, podNamespace = restoreClient, restoreNS })
		inClusterClientset = func(string) (kubernetes.Interface, error) {
			return fake.NewClientset(), nil
		}
		podNamespace = func() (string, error) { return "openvox", nil }

		cfg := &serverConfig{
			ServingCert: &certstore.Entry{
				Certname: "ca.test", Names: []string{"ca.test"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Secret: &certstore.SecretConfig{
					Name: "openvox-ca-serving-tls", Namespace: "openvox"}},
			},
			ManagedCerts: certstore.Config{{
				Certname: "component.test", Names: []string{"component.test"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Secret: &certstore.SecretConfig{
					Name: "puppetserver-tls", Namespace: "openvox"}},
			}},
		}

		_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("allows one Secret name in two spelled-out namespaces", func() {
		// The case the conservative arm must not swallow: two namespaces that
		// genuinely differ, both written down, so nothing has to be guessed.
		//
		// The cluster is stubbed so this asserts unconditionally. Written the
		// other way -- asserting only that the error, if any, was not the
		// collision one -- it passed both when the check was reached and when
		// nothing reached it, which is no assertion at all.
		restoreClient, restoreNS := inClusterClientset, podNamespace
		DeferCleanup(func() { inClusterClientset, podNamespace = restoreClient, restoreNS })
		inClusterClientset = func(string) (kubernetes.Interface, error) {
			return fake.NewClientset(), nil
		}
		podNamespace = func() (string, error) { return "ca-system", nil }
		cfg := &serverConfig{
			ServingCert: &certstore.Entry{
				Certname: "ca.test", Names: []string{"ca.test"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Secret: &certstore.SecretConfig{
					Name: "tls", Namespace: "ca-system"}},
			},
			ManagedCerts: certstore.Config{{
				Certname: "component.test", Names: []string{"component.test"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Secret: &certstore.SecretConfig{
					Name: "tls", Namespace: "openvox"}},
			}},
		}

		_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
	})
})

// The admin-credential warning.
//
// This is the stated mitigation for a deliberate decision -- the serving
// certificate carries clientAuth by default, so the CA's own certname in
// puppet_server makes its store an admin credential -- and docs/configuration.md
// promises an operator that "The CA says so once at startup". Its managed_certs
// twin carries six specs including one that pins its call site; this had none,
// so deleting the call left the promise unkept with the suite green.
var _ = Describe("the serving certificate's admin-credential warning", func() {
	build := func(cfg *serverConfig) {
		GinkgoHelper()
		_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
		Expect(err).NotTo(HaveOccurred())
	}

	cfgFor := func(puppetServer string, usages []string) *serverConfig {
		return &serverConfig{
			PuppetServer: puppetServer,
			ServingCert: &certstore.Entry{
				Certname: "ca.test", Names: []string{"ca.test"}, Usages: usages,
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
					Cert: "/srv/serving/tls.crt", Key: "/srv/serving/tls.key"}},
			},
		}
	}

	It("warns when the CA's own certname is listed and the certificate can be presented", func() {
		// Reached through buildServingCert rather than by calling the function
		// directly, so the call site is pinned too: deleting it fails this.
		logs := captureLogs(slog.LevelWarn, func() { build(cfgFor("ca.test", nil)) })
		Expect(logs).To(ContainSubstring("admin credential"))
		Expect(logs).To(ContainSubstring("ca.test"))
	})

	It("stays silent for a certname nobody listed", func() {
		// clientAuth alone grants nothing: a certificate for a name no one has
		// listed authenticates as nobody in particular.
		logs := captureLogs(slog.LevelWarn, func() { build(cfgFor("someone.else", nil)) })
		Expect(logs).NotTo(ContainSubstring("admin credential"))
	})

	It("stays silent when the certificate is narrowed out of being a client", func() {
		// The listing still grants authority, but the certificate cannot be
		// presented as a client, so the pair is not a credential.
		logs := captureLogs(slog.LevelWarn, func() {
			build(cfgFor("ca.test", []string{"serverAuth"}))
		})
		Expect(logs).NotTo(ContainSubstring("admin credential"))
	})

	It("stays silent when nothing is listed at all", func() {
		logs := captureLogs(slog.LevelWarn, func() { build(cfgFor("", nil)) })
		Expect(logs).NotTo(ContainSubstring("admin credential"))
	})
})

// The YAML shape, which every other spec bypasses by building the entry as a Go
// struct. Nothing else verifies that the block documented in
// docs/configuration.md decodes at all: a renamed or mistyped tag would
// silently disable the feature with the whole suite green.
var _ = Describe("decoding a serving_cert block", func() {
	It("decodes the shape the documentation publishes", func() {
		cfg, err := loadServerConfig(writeTempConfig(`
hostname: ca.example.com
serving_cert:
  certname: ca.example.com
  names: [ca.example.com, puppet]
  ttl: 2160h
  renew_before: 720h
  revoke_after: 24h
  usages: [serverAuth]
  key_algo: ecdsa
  key_size: 256
  reuse_key: true
  store:
    files:
      cert: /var/lib/puppet-ca/serving/tls.crt
      key: /var/lib/puppet-ca/serving/tls.key
      ca: /var/lib/puppet-ca/serving/ca.crt
`))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ServingCert).NotTo(BeNil())
		Expect(cfg.ServingCert.Certname).To(Equal("ca.example.com"))
		Expect(cfg.ServingCert.Names).To(ConsistOf("ca.example.com", "puppet"))
		Expect(cfg.ServingCert.TTL.AsDuration()).To(Equal(2160 * time.Hour))
		Expect(cfg.ServingCert.RenewBefore.AsDuration()).To(Equal(720 * time.Hour))
		Expect(cfg.ServingCert.RevokeAfter).NotTo(BeNil())
		Expect(cfg.ServingCert.RevokeAfter.AsDuration()).To(Equal(24 * time.Hour))
		Expect(cfg.ServingCert.Usages).To(ConsistOf("serverAuth"))
		Expect(cfg.ServingCert.ReuseKey).To(BeTrue())
		Expect(cfg.ServingCert.Store.Files).NotTo(BeNil())
		Expect(cfg.ServingCert.Store.Files.Cert).To(Equal("/var/lib/puppet-ca/serving/tls.crt"))
	})

	It("decodes the Secret flavour", func() {
		cfg, err := loadServerConfig(writeTempConfig(`
serving_cert:
  certname: ca.example.com
  names: [ca.example.com]
  renew_before: 720h
  store:
    secret: {name: openvox-ca-serving-tls, namespace: openvox}
`))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ServingCert.Store.Secret).NotTo(BeNil())
		Expect(cfg.ServingCert.Store.Secret.Name).To(Equal("openvox-ca-serving-tls"))
		Expect(cfg.ServingCert.Store.Files).To(BeNil())
	})

	It("leaves the block nil when it is absent, so the feature is off", func() {
		cfg, err := loadServerConfig(writeTempConfig("hostname: ca.example.com\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ServingCert).To(BeNil())
		Expect(cfg.tlsEnabled()).To(BeFalse())
	})

	It("treats an empty block as a configuration error rather than a no-op", func() {
		// The reason the field is a pointer. `serving_cert: {}` decodes to a
		// non-nil entry naming no store, which buildServingCert then refuses --
		// a value type could not tell that from the block being absent, and the
		// operator would get a CA quietly serving no TLS.
		cfg, err := loadServerConfig(writeTempConfig("serving_cert: {}\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.ServingCert).NotTo(BeNil())
		Expect(cfg.tlsEnabled()).To(BeTrue())

		_, buildErr := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
		Expect(buildErr).To(MatchError(ContainSubstring("serving_cert")))
	})
})

// The holder's remaining branches: the second clause of encryptedKeyHint, the
// two validity warnings, and the Save-side install failure.
var _ = Describe("the serving certificate holder's diagnostics", func() {
	// selfSigned mints a keypair with the given validity window, for the arms
	// that need a certificate the CA would never issue.
	selfSigned := func(notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "ca.test"},
			DNSNames:     []string{"ca.test"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}

	It("names the encrypted-key case for a legacy DEK-Info block too", func() {
		// The older and still common shape: an "RSA PRIVATE KEY" block whose
		// headers carry the encryption. The type check alone does not see it,
		// which is why encryptedKeyHint tests the headers as well -- and that
		// clause could be deleted with only the newer spelling covered.
		legacy := pem.EncodeToMemory(&pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00"},
			Bytes:   []byte("ciphertext"),
		})
		h := &servingCertHolder{describe: "Secret openvox/ca-tls"}
		err := h.install([]byte("irrelevant"), legacy)
		Expect(err).To(MatchError(ContainSubstring("must be unencrypted")))
	})

	It("warns when the material it is given has already expired", func() {
		certPEM, keyPEM := selfSigned(time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
		h := &servingCertHolder{describe: "the file pair at /srv/tls.crt"}
		logs := captureLogs(slog.LevelWarn, func() {
			Expect(h.install(certPEM, keyPEM)).To(Succeed())
		})
		Expect(logs).To(ContainSubstring("already expired"))
	})

	It("warns when the material it is given is not valid yet", func() {
		certPEM, keyPEM := selfSigned(time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
		h := &servingCertHolder{describe: "the file pair at /srv/tls.crt"}
		logs := captureLogs(slog.LevelWarn, func() {
			Expect(h.install(certPEM, keyPEM)).To(Succeed())
		})
		Expect(logs).To(ContainSubstring("not valid yet"))
	})

	It("fails the reconcile pass when material it just wrote cannot be presented", func() {
		// The Save wrapper's own arm. Material this CA just issued that will
		// not form a keypair is a defect rather than a transient fault, so it
		// must not pass for a successful pass -- the store already holds it,
		// and the next pass would find it current and never mention it again.
		sc := newServingCert(acceptingStore{}, ca.CertSpec{Subject: "ca.test"})
		err := sc.entry.Save(context.Background(), []byte("not a certificate"), []byte("nor a key"))
		Expect(err).To(MatchError(ContainSubstring("cannot be presented by the listener")))
	})

	It("reports a store that cannot be read, and keeps what it has", func() {
		// The Load wrapper's error arm, which returns rather than installing.
		sc := newServingCert(refusingStore{}, ca.CertSpec{Subject: "ca.test"})
		_, _, err := sc.entry.Load(context.Background())
		Expect(err).To(MatchError(ContainSubstring("refusing")))
		Expect(sc.ownError()).To(HaveOccurred())
	})
})

// acceptingStore takes any write and holds nothing, for the Save-side arm.
type acceptingStore struct{}

func (acceptingStore) String() string { return "the accepting store" }
func (acceptingStore) Load(context.Context) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (acceptingStore) Save(context.Context, []byte, []byte) error { return nil }

// refusingStore fails every read, for the Load-side arm.
type refusingStore struct{}

func (refusingStore) String() string { return "the refusing store" }
func (refusingStore) Load(context.Context) ([]byte, []byte, error) {
	return nil, nil, errors.New("refusing to read")
}
func (refusingStore) Save(context.Context, []byte, []byte) error { return nil }

// The arms of the startup path that the specs above reach only incidentally:
// the swallowed install failure, the bound on the pass, the ephemeral-store
// line, and the no-op that keeps a real renewal legible.
var _ = Describe("the serving certificate's startup and renewal reporting", func() {
	It("keeps serving and says so when the store holds material it cannot present", func() {
		// The only place in this file where an error is deliberately not
		// propagated: returning it would stop the very pass that replaces the
		// material. It is the arm that carries another replica's renewal, so a
		// silent version of it leaves this replica presenting the previous
		// certificate until it expires with nothing in the log.
		sc := newServingCert(garbageStore{}, ca.CertSpec{Subject: "ca.test"})

		var certPEM, keyPEM []byte
		var err error
		logs := captureLogs(slog.LevelWarn, func() {
			certPEM, keyPEM, err = sc.entry.Load(context.Background())
		})

		Expect(err).NotTo(HaveOccurred(), "the repairing pass must not be stopped")
		Expect(certPEM).NotTo(BeEmpty(), "the material must still reach the decision")
		Expect(keyPEM).NotTo(BeEmpty())
		Expect(sc.ownError()).To(HaveOccurred())
		Expect(logs).To(ContainSubstring("cannot be presented by the listener"))
		Expect(logs).To(ContainSubstring("the garbage store"))
	})

	It("bounds the whole startup pass with one budget, not one per entry", func() {
		// internal/ca budgets each entry separately, so an unbounded pass costs
		// the sum of them before the listener binds -- inside a window the
		// chart budgets at 60s in total. Not through lock contention, which
		// cannot happen between entries because each locks on its own subject,
		// but through the stores: one unreachable API server costs every
		// Secret-store entry its own 30s API timeout, in sequence.
		//
		// The property that tells the two apart is not how long the pass takes
		// but whether the entries SHARE a deadline. Under one budget every
		// entry sees the same instant, because context.WithTimeout keeps the
		// earlier of the two; without it each entry's deadline is its own start
		// plus LockTimeout, so they drift apart by however long the previous
		// entries took. The first probe therefore delays deliberately: with the
		// bound the two deadlines stay identical, and without it they differ by
		// that delay.
		myCA, store := newRefresherTestCA()
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}

		const delay = 80 * time.Millisecond
		var deadlines []time.Time
		probe := func(subject string, wait time.Duration) ca.ManagedCert {
			return ca.ManagedCert{
				Spec: ca.CertSpec{
					Subject: subject, DNSNames: []string{subject},
					RenewBefore: 720 * time.Hour,
				},
				Load: func(ctx context.Context) ([]byte, []byte, error) {
					if d, ok := ctx.Deadline(); ok {
						deadlines = append(deadlines, d)
					}
					time.Sleep(wait)
					// Declining keeps the probe from issuing anything; the
					// deadline is all this spec wants from it.
					return nil, nil, errors.New("probe entry declines")
				},
				Save: func(context.Context, []byte, []byte) error { return nil },
			}
		}

		sc, err := buildServingCert(cfgWithServingFiles(GinkgoT().TempDir()),
			GinkgoT().TempDir(), "", store)
		Expect(err).NotTo(HaveOccurred())
		myCA.ManagedCerts = []ca.ManagedCert{sc.entry, probe("a.test", delay), probe("b.test", 0)}

		Expect(provisionServingCert(context.Background(), myCA, sc)).To(Succeed())

		Expect(deadlines).To(HaveLen(2),
			"precondition: both probe entries must have been reconciled and seen a deadline")
		Expect(deadlines[1]).To(BeTemporally("~", deadlines[0], delay/4),
			"the startup pass gives each entry its own budget instead of sharing one, so a "+
				"deployment with more component certificates gets a longer startup")
	})
})

// garbageStore returns material that reads cleanly and is not a keypair.
type garbageStore struct{}

func (garbageStore) String() string { return "the garbage store" }
func (garbageStore) Load(context.Context) ([]byte, []byte, error) {
	return []byte("not a certificate"), []byte("nor a key"), nil
}
func (garbageStore) Save(context.Context, []byte, []byte) error { return nil }

// cfgWithServingFiles is a self-provisioning configuration writing into dir.
func cfgWithServingFiles(dir string) *serverConfig {
	return &serverConfig{
		Hostname: "ca.test",
		ServingCert: &certstore.Entry{
			Certname: "ca.test", Names: []string{"ca.test"},
			RenewBefore: certstore.Duration(720 * time.Hour),
			KeyAlgo:     "ecdsa", KeySize: 256,
			Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
				Cert: filepath.Join(dir, "tls.crt"), Key: filepath.Join(dir, "tls.key")}},
		},
	}
}

// The two log lines that are promises rather than incidentals: the one
// docs/configuration.md says makes an ephemeral store visible, and the
// suppression that keeps a real renewal legible.
var _ = Describe("what the serving certificate reports at startup and on renewal", func() {
	It("says it issued into an empty store, which is what makes an ephemeral one visible", func() {
		// A store that loses its material every restart issues a fresh
		// certificate each time and supersedes the previous one, accumulating
		// CRL entries for certificates nothing presented. That is a legitimate
		// choice; this line is what stops it being an accident, and
		// docs/configuration.md publishes it as such.
		dir := GinkgoT().TempDir()
		myCA, store := newRefresherTestCA()
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}

		sc, err := buildServingCert(cfgWithServingFiles(dir), GinkgoT().TempDir(), "", store)
		Expect(err).NotTo(HaveOccurred())
		myCA.ManagedCerts = []ca.ManagedCert{sc.entry}

		logs := captureLogs(slog.LevelInfo, func() {
			Expect(provisionServingCert(context.Background(), myCA, sc)).To(Succeed())
		})
		Expect(logs).To(ContainSubstring("store held none"))

		// And it does not repeat on a restart against a store that kept its
		// material, or the line would say nothing about which case this is.
		sc2, err := buildServingCert(cfgWithServingFiles(dir), GinkgoT().TempDir(), "", store)
		Expect(err).NotTo(HaveOccurred())
		myCA.ManagedCerts = []ca.ManagedCert{sc2.entry}

		again := captureLogs(slog.LevelInfo, func() {
			Expect(provisionServingCert(context.Background(), myCA, sc2)).To(Succeed())
		})
		Expect(again).NotTo(ContainSubstring("store held none"))
	})

	It("reports a renewal once, not on every pass that reloads the same material", func() {
		// Load installs on every reconcile pass, so without the unchanged-material
		// check the listener would report an installation every interval and the
		// line announcing a real renewal would be worthless.
		myCA, store := newRefresherTestCA()
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		sc, err := buildServingCert(cfgWithServingFiles(GinkgoT().TempDir()),
			GinkgoT().TempDir(), "", store)
		Expect(err).NotTo(HaveOccurred())
		myCA.ManagedCerts = []ca.ManagedCert{sc.entry}
		Expect(provisionServingCert(context.Background(), myCA, sc)).To(Succeed())

		certPEM, keyPEM, err := sc.store.Load(context.Background())
		Expect(err).NotTo(HaveOccurred())

		first := captureLogs(slog.LevelInfo, func() {
			Expect(sc.holder.install(certPEM, keyPEM)).To(Succeed())
		})
		Expect(first).To(BeEmpty(), "the material is unchanged, so nothing should be reported")
	})
})

// The two fallback arms nothing else reaches.
var _ = Describe("the serving certificate's fallback reporting", func() {
	It("points at the reconcile warning when the store was never touched", func() {
		// whyNothingWasIssued's second arm, taken when the entry failed before
		// its store was consulted at all -- a subject lock timing out, or the
		// CA reporting itself uninitialised. The store is empty and this
		// entry's own wrappers recorded nothing, so the fatal message has no
		// cause of its own to give and must say where to look instead of
		// inventing one.
		sc := newServingCert(emptyStore{}, ca.CertSpec{Subject: "ca.test"})
		Expect(sc.ownError()).NotTo(HaveOccurred(), "precondition: nothing recorded")

		err := whyNothingWasIssued(sc)
		Expect(err).To(MatchError(ContainSubstring("Managed certificate not reconciled")))
		Expect(err).To(MatchError(ContainSubstring("neither wrote nor failed")))
	})

	It("stays silent about admin credentials when the allow list cannot be read", func() {
		// The arm that returns without warning. Its stated reason is that
		// buildAuthConfig reports the same failure fatally a moment later, and
		// that self-provisioning always means TLS is on -- a claim about
		// tlsEnabled that nothing else checks. Without this spec the whole
		// admin warning could vanish behind an unreadable file with nothing
		// failing.
		cfg := &serverConfig{
			PuppetServerFile: filepath.Join(GinkgoT().TempDir(), "absent"),
			ServingCert: &certstore.Entry{
				Certname: "ca.test", Names: []string{"ca.test"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				Store: certstore.StoreConfig{Files: &certstore.FilesConfig{
					Cert: "/srv/serving/tls.crt", Key: "/srv/serving/tls.key"}},
			},
		}
		Expect(cfg.tlsEnabled()).To(BeTrue(),
			"precondition: the silence is justified by TLS being on, so it must be")

		logs := captureLogs(slog.LevelWarn, func() {
			_, err := buildServingCert(cfg, GinkgoT().TempDir(), "", stubCACerts{})
			Expect(err).NotTo(HaveOccurred(),
				"an unreadable allow list is buildAuthConfig's to refuse, not this")
		})
		Expect(logs).NotTo(ContainSubstring("admin credential"))
	})
})

// emptyStore reads and writes nothing, for the arm where the store is never
// reached at all.
type emptyStore struct{}

func (emptyStore) String() string { return "the empty store" }
func (emptyStore) Load(context.Context) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (emptyStore) Save(context.Context, []byte, []byte) error { return nil }

// The Secret store driven all the way through, which no spec above does: the
// configuration half is covered with a fake client, and the fatal half with a
// file store, but their composition is not -- and the Secret store is the
// deployment the feature exists for.
var _ = Describe("provisioning the serving certificate into a Secret", func() {
	var (
		ctx    context.Context
		myCA   *ca.CA
		store  *storage.StorageService
		client *fake.Clientset
	)

	BeforeEach(func() {
		ctx = context.Background()
		myCA, store = newRefresherTestCA()
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		client = fake.NewClientset()

		restoreClient, restoreNS := inClusterClientset, podNamespace
		DeferCleanup(func() { inClusterClientset, podNamespace = restoreClient, restoreNS })
		inClusterClientset = func(string) (kubernetes.Interface, error) { return client, nil }
		podNamespace = func() (string, error) { return "openvox", nil }
	})

	secretCfg := func() *serverConfig {
		return &serverConfig{
			Hostname: "ca.test",
			ServingCert: &certstore.Entry{
				Certname: "ca.test", Names: []string{"ca.test"},
				RenewBefore: certstore.Duration(720 * time.Hour),
				KeyAlgo:     "ecdsa", KeySize: 256,
				Store: certstore.StoreConfig{Secret: &certstore.SecretConfig{
					Name: "openvox-ca-serving-tls"}},
			},
		}
	}

	It("issues into the Secret and presents what it wrote", func() {
		sc, err := buildServingCert(secretCfg(), GinkgoT().TempDir(), "", store)
		Expect(err).NotTo(HaveOccurred())
		myCA.ManagedCerts = []ca.ManagedCert{sc.entry}

		Expect(provisionServingCert(ctx, myCA, sc)).To(Succeed())

		// The listener has something, and it is what the Secret holds rather
		// than anything this spec placed there.
		held, err := sc.holder.GetCertificate(&tls.ClientHelloInfo{})
		Expect(err).NotTo(HaveOccurred())
		Expect(held.Leaf.Subject.CommonName).To(Equal("ca.test"))

		sec, err := client.CoreV1().Secrets("openvox").
			Get(ctx, "openvox-ca-serving-tls", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKey("tls.crt"))
		Expect(sec.Data).To(HaveKey("tls.key"))
		Expect(sec.Data).To(HaveKey("ca.crt"))
		Expect(serialOf(sec.Data["tls.crt"])).To(Equal(held.Leaf.SerialNumber.String()))
	})

	It("is fatal when RBAC refuses the Secret, and names it", func() {
		// The claim the chart's NOTES and the documentation both make about a
		// serving Secret: a refusal is fatal and the pod never starts. Nothing
		// pinned it, because every fatal spec used a file store.
		client.PrependReactor("get", "secrets",
			func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewForbidden(
					schema.GroupResource{Resource: "secrets"}, "openvox-ca-serving-tls",
					errors.New("no RBAC grant"))
			})

		sc, err := buildServingCert(secretCfg(), GinkgoT().TempDir(), "", store)
		Expect(err).NotTo(HaveOccurred())
		myCA.ManagedCerts = []ca.ManagedCert{sc.entry}

		err = provisionServingCert(ctx, myCA, sc)
		Expect(err).To(HaveOccurred())
		// Three things, and the first is the one this wrapper owns. The store
		// names itself in its own error, so asserting only the Secret name
		// passes whether or not the startup path says anything at all -- which
		// it did when this spec was first written, and the mutation that
		// stripped this clause survived it.
		Expect(err.Error()).To(ContainSubstring("the listener has nothing to present"))
		Expect(err.Error()).To(ContainSubstring("Secret openvox/openvox-ca-serving-tls"))
		Expect(err.Error()).To(ContainSubstring("no RBAC grant"))
	})
})

// The third fatal arm: material that reads cleanly and cannot be presented.
var _ = Describe("a serving store holding material the listener cannot use", func() {
	It("refuses to start rather than binding with an empty holder", func() {
		// Reachable when a store holds a corrupt or foreign keypair and the
		// reissue that would replace it also fails. The Load wrapper swallows
		// its own install failure by design, so this is the only thing left
		// that stops the listener binding with nothing to present.
		myCA, _ := newRefresherTestCA()
		sc := newServingCert(garbageStore{}, ca.CertSpec{
			Subject: "ca.test", DNSNames: []string{"ca.test"},
			RenewBefore: 720 * time.Hour,
		})
		// No entry in the set, so the pass writes nothing and the garbage
		// survives to be judged.
		myCA.ManagedCerts = nil

		err := provisionServingCert(context.Background(), myCA, sc)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cannot be presented by the listener"))
	})
})

// The last diagnostic in install() without a spec: the one that fires when the
// CA has issued itself a certificate its own clients would reject.
var _ = Describe("the serving holder's cannot-serve warning", func() {
	It("says so when the material cannot authenticate this server", func() {
		// buildServingCert refuses the one configuration that would produce
		// this -- a usages list without serverAuth -- so reaching it means
		// something upstream is wrong, which is exactly why the line exists and
		// why deleting it should not be silent.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "ca.test"},
			// No SAN at all, and an extendedKeyUsage that excludes serverAuth:
			// two of the three problems servingCertProblems reports.
			NotBefore:   time.Now().Add(-time.Hour),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).NotTo(HaveOccurred())
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

		h := &servingCertHolder{describe: "the file pair at /srv/tls.crt"}
		logs := captureLogs(slog.LevelWarn, func() {
			Expect(h.install(certPEM, keyPEM)).To(Succeed())
		})
		Expect(logs).To(ContainSubstring("cannot serve TLS"))
		Expect(logs).To(ContainSubstring("no subjectAltName"))
		Expect(logs).To(ContainSubstring("does not include serverAuth"))
	})
})

// The two diagnostics added so the serving path reports what certReloader does.
var _ = Describe("the serving holder's custody warning", func() {
	It("says so when the store holds a CA certificate", func() {
		// servingCertProblems deliberately does not report this -- a CA leaf
		// verifies and serves perfectly well, so the fault is custodial rather
		// than protocol -- which is why certReloader warns separately and why
		// this path has to as well, or the two listener sources disagree about
		// a signing key on the network-facing listener.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(3),
			Subject:               pkix.Name{CommonName: "ca.test"},
			DNSNames:              []string{"ca.test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		Expect(err).NotTo(HaveOccurred())
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		Expect(err).NotTo(HaveOccurred())

		h := &servingCertHolder{describe: "Secret openvox/ca-tls"}
		logs := captureLogs(slog.LevelWarn, func() {
			Expect(h.install(
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
				pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
			)).To(Succeed())
		})
		Expect(logs).To(ContainSubstring("is a CA certificate"))
		Expect(logs).To(ContainSubstring("Secret openvox/ca-tls"))
		// And not the cannot-serve warning: this certificate serves fine, which
		// is the whole reason the two checks are separate.
		Expect(logs).NotTo(ContainSubstring("cannot serve TLS"))
	})
})

// The reload status text, which must not announce work this path does not do.
var _ = Describe("the SIGHUP status text", func() {
	It("names only the allow list when the CA provisions its own certificate", func() {
		Expect((&configReloader{certs: nil}).reloadingStatus()).
			To(Equal("Reloading the admin allow list"))
	})

	It("names the TLS material when an operator supplied the keypair", func() {
		Expect((&configReloader{certs: &certReloader{}}).reloadingStatus()).
			To(ContainSubstring("TLS material"))
	})
})
