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

// White-box, for the reason renewrace_test.go and supersederace_test.go both
// give: these specs hold the very lock the code under test must acquire, and
// subjectLockName is the only thing that knows what it is called. Spelling the
// string a second time from outside would let a spec hold the wrong lock, block
// nothing, and still pass.
package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// memStore is a managed certificate's store, in memory. It is deliberately not
// an implementation of an interface: ManagedCert takes two functions, so a
// caller's store is whatever pair of closures it cares to supply, and this is
// one such pair.
type memStore struct {
	mu      sync.Mutex
	certPEM []byte
	keyPEM  []byte

	saves   int
	loadErr error
	saveErr error

	// saveHook, when set, runs before the write and may fail it. It exists for
	// the one failure the saveErr field cannot express: a store that consumes
	// the caller's deadline on its way to failing.
	saveHook func() error

	// delay is spent inside Load, before anything is returned. It exists for
	// the convergence specs: it widens the window in which four replicas are
	// all holding stale material, which is what makes the unlocked outcome a
	// certainty rather than a likelihood. Under a shared lock it costs one
	// delay per replica and changes no outcome.
	delay time.Duration
}

func (s *memStore) load(context.Context) ([]byte, []byte, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, nil, s.loadErr
	}
	return s.certPEM, s.keyPEM, nil
}

func (s *memStore) save(_ context.Context, certPEM, keyPEM []byte) error {
	s.mu.Lock()
	hook := s.saveHook
	s.mu.Unlock()
	// Outside the store's own mutex: the hook models what a real store does on
	// its way to failing, which for the deadline spec means cancelling the
	// caller's context.
	if hook != nil {
		if err := hook(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.certPEM, s.keyPEM = certPEM, keyPEM
	s.saves++
	return nil
}

// stored returns the certificate currently in the store, parsed.
func (s *memStore) stored() *x509.Certificate {
	GinkgoHelper()
	s.mu.Lock()
	defer s.mu.Unlock()
	block, _ := pem.Decode(s.certPEM)
	Expect(block).NotTo(BeNil(), "the store holds no certificate")
	crt, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return crt
}

func (s *memStore) saveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saves
}

var _ = Describe("Reconciling a managed certificate", func() {
	const subject = "managed.test"

	var (
		ctx      context.Context
		storeDir string
		store    *storage.StorageService
		myCA     *CA
		spec     CertSpec
		fake     *memStore
		entry    ManagedCert
	)

	BeforeEach(func() {
		ctx = context.Background()
		storeDir = GinkgoT().TempDir()
		store = storage.New(storeDir)
		myCA = New(store, AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		spec = CertSpec{
			Subject:     subject,
			DNSNames:    []string{subject, "managed"},
			TTL:         90 * 24 * time.Hour,
			RenewBefore: 30 * 24 * time.Hour,
		}
		fake = &memStore{}
		entry = ManagedCert{Spec: spec, Load: fake.load, Save: fake.save}
	})

	reconcile := func() (bool, error) {
		return myCA.reconcileManagedCert(ctx, entry, time.Now().UTC())
	}

	// reconcileAt runs a pass as though it were `ahead` from now. It is how the
	// specs below reach a *second* issuance, and the honest way to do it: the
	// obvious alternative -- widening RenewBefore until the certificate falls
	// inside it -- cannot work, because renewWindowFor clamps the window to
	// half the certificate's forward life precisely so that no setting can make
	// a fresh certificate due. Ageing the clock is what a real deployment does.
	reconcileAt := func(ahead time.Duration) (bool, error) {
		return myCA.reconcileManagedCert(ctx, entry, time.Now().UTC().Add(ahead))
	}

	// dueWindow is far enough ahead that a 90-day certificate is inside its
	// 30-day renew window, and short enough that it has not expired.
	const dueWindow = 80 * 24 * time.Hour

	Describe("the first pass", func() {
		It("issues, and writes the pair to the store", func() {
			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())

			crt := fake.stored()
			Expect(crt.Subject.CommonName).To(Equal(subject))
			Expect(crt.DNSNames).To(ConsistOf(subject, "managed"))
			Expect(fake.keyPEM).NotTo(BeEmpty(), "the certificate is useless without its key")
		})

		It("records the certificate the way every other issuance does", func() {
			// A managed certificate is an ordinary certificate in every respect
			// that matters to the CA: a blob at cert/<subject>, an inventory
			// row, a serial-index entry. That is what makes it visible to
			// `list`, to OCSP, to the CRL and to the expiry sweep without any
			// of them being taught about it -- and it is why #178 was closed
			// rather than generalised.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())

			Expect(store.HasCert(ctx, subject)).To(BeTrue())
			stored, err := store.GetCert(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(stored).To(Equal(fake.certPEM),
				"the CA's own copy must be the certificate the store was given")

			serial, err := store.LatestSerialForSubject(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(serial).To(Equal(serialHexStr(fake.stored().SerialNumber)),
				"the inventory row must name the certificate that was issued")
		})

		It("leaves no private key behind, in the backing store or the cadir", func() {
			// The invariant this mechanism exists to preserve. POST /generate
			// still writes leaf keys to <cadir>/private/ and is unchanged; a
			// managed certificate's key goes to its own store and nowhere else.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())

			_, statErr := os.Stat(store.PrivateKeyPath(subject))
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"a managed certificate's key must not be written to the cadir")

			entries, err := os.ReadDir(filepath.Join(storeDir, "private"))
			if err == nil {
				for _, e := range entries {
					Expect(e.Name()).NotTo(ContainSubstring(subject))
				}
			}
		})
	})

	It("does nothing on a second pass", func() {
		issued, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeTrue())
		first := fake.stored().SerialNumber

		issued, err = reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeFalse(), "a certificate that satisfies its spec must not be reissued")
		Expect(fake.saveCount()).To(Equal(1))
		Expect(fake.stored().SerialNumber).To(Equal(first))
	})

	Describe("per-certificate settings", func() {
		// Each entry can differ from the CA's defaults, and an unset field
		// inherits rather than resetting to a built-in. Both halves matter: the
		// first is the point, the second is what stops an entry that only sets
		// a ttl quietly losing the fleet's key algorithm.
		It("generates a key with the entry's own algorithm and size", func() {
			// The CA is ECDSA P-256 throughout this file, so RSA here can only
			// have come from the entry.
			entry.Spec.KeyConfig = KeyConfig{Algo: KeyAlgoRSA, Size: 2048}
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())

			Expect(fake.stored().PublicKeyAlgorithm).To(Equal(x509.RSA))
			rsaKey, ok := fake.stored().PublicKey.(*rsa.PublicKey)
			Expect(ok).To(BeTrue())
			Expect(rsaKey.N.BitLen()).To(Equal(2048))
		})

		It("inherits the CA's key configuration when the entry says nothing", func() {
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(fake.stored().PublicKeyAlgorithm).To(Equal(x509.ECDSA),
				"an unset entry must take the CA's setting, not a built-in default")
		})

		It("reissues against the stored key when ReuseKey is set", func() {
			// The case the setting exists for: a TLSA record or an SPKI pin
			// names the key, so re-keying breaks it.
			entry.Spec.ReuseKey = true
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			first := fake.stored()

			issued, err := reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())

			second := fake.stored()
			Expect(second.SerialNumber).NotTo(Equal(first.SerialNumber),
				"the fixture is only meaningful if a new certificate was issued")
			Expect(second.PublicKey).To(Equal(first.PublicKey),
				"the replacement must carry the same public key, or the pin is broken")
		})

		It("re-keys on every renewal by default", func() {
			// The zero value, and the better default: a key replaced regularly
			// is one a disclosure stops mattering about.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			first := fake.stored()

			_, err = reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())

			Expect(fake.stored().PublicKey).NotTo(Equal(first.PublicKey))
		})

		It("generates when there is no key to reuse", func() {
			// A first issuance has an empty store by definition, so an entry
			// with ReuseKey set still has to start somewhere.
			entry.Spec.ReuseKey = true
			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())
			Expect(fake.keyPEM).NotTo(BeEmpty())
		})

		It("generates, loudly, when the stored key cannot be parsed", func() {
			// Refusing would leave the certificate to expire over a key nobody
			// can use. Generating is right; doing it silently is not, because
			// the pin the operator asked for is about to stop holding.
			entry.Spec.ReuseKey = true
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			first := fake.stored()

			fake.mu.Lock()
			fake.keyPEM = []byte("-----BEGIN EC PRIVATE KEY-----\nnope\n-----END EC PRIVATE KEY-----\n")
			fake.mu.Unlock()

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})))
			defer slog.SetDefault(prev)

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue(), "an unusable key must not stall the certificate")
			Expect(fake.stored().PublicKey).NotTo(Equal(first.PublicKey))
			Expect(buf.String()).To(ContainSubstring("breaks any pin on the old key"))
		})

		It("refuses a reused key below the CA's key-strength policy", func() {
			// The contract is that such a key is REFUSED, not quietly replaced:
			// silently re-keying would defeat the pin the setting exists to
			// provide. Both halves are asserted, since a later
			// generate-on-failure fallback would satisfy only the first.
			entry.Spec.ReuseKey = true
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			good := fake.stored()

			weak, kerr := rsa.GenerateKey(rand.Reader, 1024)
			Expect(kerr).NotTo(HaveOccurred())
			fake.mu.Lock()
			fake.keyPEM = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(weak),
			})
			fake.mu.Unlock()

			_, err = reconcileAt(dueWindow)
			Expect(err).To(HaveOccurred(), "a weak reused key must fail the pass")
			Expect(fake.stored().SerialNumber).To(Equal(good.SerialNumber),
				"and must not be silently replaced with a fresh key")
		})

		It("does not reuse the key of a certificate that was revoked", func() {
			// SECURITY: reissuing over the same key would hand back, with a
			// fresh serial and a full lifetime, exactly the material an
			// operator revoking for key disclosure was retiring -- and no CRL
			// would list the replacement.
			entry.Spec.ReuseKey = true
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			first := fake.stored()

			Expect(myCA.Revoke(ctx, subject)).To(Succeed())

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})))
			defer slog.SetDefault(prev)

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())
			Expect(fake.stored().PublicKey).NotTo(Equal(first.PublicKey),
				"a revoked certificate must be replaced with a NEW key, whatever the pin says")
			Expect(buf.String()).To(ContainSubstring("its certificate was revoked"))
		})

		It("honours a per-certificate supersession window", func() {
			// The CA revokes inline; this entry wants an overlap.
			myCA.SupersedeAfter = 0
			window := 24 * time.Hour
			entry.Spec.SupersedeAfter = &window

			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			_, err = reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())

			revoked, rerr := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(), "the entry's window must delay the revocation")

			entries, _, serr := myCA.readSuperseded(ctx)
			Expect(serr).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Serial).To(Equal(serialHexStr(predecessor.SerialNumber)))
		})

		It("lets an entry ask for no overlap on a CA that grants one", func() {
			// Zero is a value, not an absence -- which is why the field is a
			// pointer. An entry setting it to zero on a CA whose default is 24h
			// must revoke inline.
			myCA.SupersedeAfter = 24 * time.Hour
			none := time.Duration(0)
			entry.Spec.SupersedeAfter = &none

			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			_, err = reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())

			revoked, rerr := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue(),
				"an explicit zero must revoke inline, not inherit the CA's window")
		})

		It("inherits the CA's window when the entry says nothing", func() {
			myCA.SupersedeAfter = 24 * time.Hour
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			_, err = reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())

			revoked, rerr := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(), "nil must inherit, not mean zero")
		})
	})

	It("uses the configured names verbatim, whatever the CSR-path settings say", func() {
		// Two settings that govern names on a submitted CSR must not reach a
		// managed certificate, and both are asserted here rather than left to
		// the call graph: AllowSubjectAltNames is what a *request* may ask for,
		// and PromoteCNToSAN adds the Common Name when a request carries no
		// names. A managed certificate's names come from a file an
		// administrator wrote, so neither applies -- and both are set to the
		// value that would change the outcome if they did.
		myCA.AllowSubjectAltNames = false
		myCA.PromoteCNToSAN = true
		entry.Spec.DNSNames = []string{"alias.example.com"}

		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())

		crt := fake.stored()
		Expect(crt.DNSNames).To(ConsistOf("alias.example.com"),
			"the configured names must be used exactly: no gate refusing a name that is "+
				"not the certname, and no Common Name promoted in beside them")
		Expect(crt.Subject.CommonName).To(Equal(subject))
	})

	It("carries every subject alternative name type, not only DNS", func() {
		// issueLeafLocked has supported all four since before managed
		// certificates existed, and AutoRenew carries all four forward. An IP
		// SAN is the case that makes it concrete: a component reached at a
		// fixed address has nothing else to be named by.
		entry.Spec.IPAddresses = []net.IP{net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::1")}
		entry.Spec.EmailAddresses = []string{"ca@example.com"}
		u, uerr := url.Parse("spiffe://example.com/ca")
		Expect(uerr).NotTo(HaveOccurred())
		entry.Spec.URIs = []*url.URL{u}

		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())

		crt := fake.stored()
		Expect(crt.IPAddresses).To(HaveLen(2))
		Expect(crt.IPAddresses[0].Equal(net.ParseIP("192.0.2.10"))).To(BeTrue())
		Expect(crt.IPAddresses[1].Equal(net.ParseIP("2001:db8::1"))).To(BeTrue())
		Expect(crt.EmailAddresses).To(ConsistOf("ca@example.com"))
		Expect(crt.URIs).To(HaveLen(1))
		Expect(crt.URIs[0].String()).To(Equal("spiffe://example.com/ca"))
	})

	It("does not reissue a certificate that already carries every name type", func() {
		// The other half, and the one that catches a comparison which cannot
		// recognise its own output. net.IP has a 4-byte and a 16-byte form for
		// the same address, and x509 does not promise which comes back -- a
		// bytewise comparison reissues on every pass, for ever, which is the
		// failure renewWindowFor exists to prevent arriving by another door.
		entry.Spec.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
		entry.Spec.EmailAddresses = []string{"ca@example.com"}
		u, uerr := url.Parse("spiffe://example.com/ca")
		Expect(uerr).NotTo(HaveOccurred())
		entry.Spec.URIs = []*url.URL{u}

		issued, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeTrue())

		issued, err = reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeFalse(),
			"a certificate carrying exactly the configured names must be current")

		// The fixture is only meaningful if the two representations really
		// differ: net.ParseIP yields the 16-byte IPv4-in-IPv6 form and x509
		// marshals an IPv4 SAN in 4 bytes. If they ever coincide, a bytewise
		// comparison would pass too and this spec would be testing nothing.
		Expect(entry.Spec.IPAddresses[0]).To(HaveLen(16))
		Expect(fake.stored().IPAddresses[0]).To(HaveLen(4))
	})

	It("reissues when a name type the spec wants is missing", func() {
		// An IP added to the configuration must take effect, or the setting is
		// decorative -- the same defect as a usage that never takes hold.
		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		first := fake.stored()
		Expect(first.IPAddresses).To(BeEmpty())

		entry.Spec.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
		issued, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeTrue(), "adding an IP SAN must trigger a reissue")
		Expect(fake.stored().IPAddresses).To(HaveLen(1))
	})

	It("reissues when an email SAN the spec wants is missing", func() {
		// One arm per type: with only the IP loop pinned, deleting the email
		// or URI loop from leafCarriesNames failed nothing.
		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())

		entry.Spec.EmailAddresses = []string{"ca@example.com"}
		issued, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeTrue(), "adding an email SAN must trigger a reissue")
		Expect(fake.stored().EmailAddresses).To(ConsistOf("ca@example.com"))
	})

	It("reissues when a URI SAN the spec wants is missing", func() {
		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())

		u, uerr := url.Parse("spiffe://example.com/ca")
		Expect(uerr).NotTo(HaveOccurred())
		entry.Spec.URIs = []*url.URL{u}
		issued, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(issued).To(BeTrue(), "adding a URI SAN must trigger a reissue")
		Expect(fake.stored().URIs).To(HaveLen(1))
	})

	It("issues a serverAuth-only certificate when the spec says so", func() {
		// SECURITY: when a spec asks for serverAuth alone, clientAuth must
		// really be absent, so this asserts the absence rather than only the
		// presence. Which certificates should ask is a configuration question
		// -- a certificate shared with an OpenVox Server needs clientAuth, one
		// that only answers handshakes does not. What must never happen is
		// getting the wider pair while having asked for the narrower.
		entry.Spec.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())

		Expect(fake.stored().ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
		Expect(fake.stored().ExtKeyUsage).NotTo(ContainElement(x509.ExtKeyUsageClientAuth),
			"a serverAuth-only spec that still emitted clientAuth would hand out an admin credential")
	})

	It("issues the default usages when the spec names none", func() {
		// The other half: an omitted EKU must not mean "unrestricted", which is
		// what an empty ExtKeyUsage means in X.509.
		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		Expect(fake.stored().ExtKeyUsage).To(ConsistOf(
			x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth))
	})

	It("refuses an entry whose spec would not validate, without touching the store", func() {
		entry.Spec.RenewBefore = 0
		issued, err := reconcile()
		Expect(err).To(MatchError(ContainSubstring("renew_before must be positive")))
		Expect(issued).To(BeFalse())
		Expect(fake.saveCount()).To(BeZero())
	})

	It("refuses an entry with no store configured, without panicking", func() {
		// A nil Load would be called inside the subject lock, and
		// reconcileManagedOnce has no recover -- so the panic would take the
		// process down rather than being logged and retried.
		bare := ManagedCert{Spec: spec}
		issued, err := myCA.reconcileManagedCert(ctx, bare, time.Now().UTC())
		Expect(err).To(MatchError(ContainSubstring("store is not configured")))
		Expect(issued).To(BeFalse())
		Expect(store.HasCert(ctx, subject)).To(BeFalse(), "nothing may be signed on this path")
	})

	It("refuses on an uninitialised CA rather than panicking", func() {
		// Every other entry point into this package has this spec; the
		// reconcile path is reached from a background job, where a panic is
		// the process rather than one request.
		blank := New(storage.New(GinkgoT().TempDir()), AutosignConfig{Mode: "off"}, "puppet.test")
		issued, err := blank.reconcileManagedCert(ctx, entry, time.Now().UTC())
		Expect(err).To(MatchError(ErrNotInitialized))
		Expect(issued).To(BeFalse())
	})

	It("stops on a store it cannot read rather than reissuing over it", func() {
		// Reconciling against material we could not read would reissue on every
		// pass for as long as the store is down -- and each pass would supersede
		// the last certificate it could not see.
		fake.loadErr = fmt.Errorf("backend unavailable")
		issued, err := reconcile()
		Expect(err).To(MatchError(ContainSubstring("backend unavailable")))
		Expect(issued).To(BeFalse())
		Expect(store.HasCert(ctx, subject)).To(BeFalse(), "nothing may be signed on this path")
	})

	Describe("when the store write fails after signing", func() {
		var predecessor *x509.Certificate

		BeforeEach(func() {
			// A first pass that succeeds, so there is a predecessor whose fate
			// the failure below is about.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor = fake.stored()

			// Make the store refuse the write. The passes below run ahead of
			// the clock so the predecessor is genuinely inside its window.
			fake.saveErr = fmt.Errorf("secret rejected")
		})

		It("revokes the certificate it just issued, immediately", func() {
			// Nothing ever saw this key: it was generated inside the lock and
			// the store refused it. A supersession window exists to let relying
			// parties pick up a replacement, and here there are none -- so this
			// is the one issuance retired without one, whatever SupersedeAfter
			// says.
			myCA.SupersedeAfter = 24 * time.Hour

			issued, err := reconcileAt(dueWindow)
			Expect(err).To(MatchError(ContainSubstring("secret rejected")))
			Expect(issued).To(BeFalse())

			// The orphan's serial comes from the inventory, not from
			// cert/<subject>: the failure path puts the CA's record back to the
			// predecessor, so the blob is no longer the certificate that was
			// just signed. The inventory row is what still names it.
			orphanSerial, err := store.LatestSerialForSubject(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(orphanSerial).NotTo(Equal(serialHexStr(predecessor.SerialNumber)),
				"the fixture is only meaningful if a new certificate was actually signed")

			orphanInt, ok := new(big.Int).SetString(orphanSerial, 16)
			Expect(ok).To(BeTrue())
			revoked, err := myCA.IsRevokedSerial(ctx, orphanInt)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue(),
				"a certificate nobody can use must not be left live for its full lifetime")

			// And the CA's own record names the certificate actually in
			// service, not the revoked orphan. Left pointing at the orphan, an
			// operator's `revoke --certname` would resolve to it, report
			// success, and retire nothing.
			restored, err := store.GetCert(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			rblock, _ := pem.Decode(restored)
			Expect(rblock).NotTo(BeNil())
			rcert, err := x509.ParseCertificate(rblock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(rcert.SerialNumber).To(Equal(predecessor.SerialNumber),
				"the CA's record must be put back to the predecessor still in service")

			// And not merely recorded for later: an immediate revocation is on
			// the CRL now, with nothing waiting on a sweep.
			entries, _, rerr := myCA.readSuperseded(ctx)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})

		It("still revokes it when the store write exhausted the pass's deadline", func() {
			// The realistic shape of this failure, and the one the plain spec
			// above cannot reach: the store did not refuse quickly, it HUNG, and
			// by the time it gave up the deadline the pass started with was
			// spent. A rollback sharing that deadline finds the context already
			// done, cannot take the CRL lock, and leaves precisely the orphan it
			// exists to prevent -- a live certificate whose key exists nowhere,
			// which nothing retires before it expires.
			//
			// Modelled by cancelling the context from inside Save, which is
			// stronger than waiting for a real deadline: a rollback that
			// inherits it is guaranteed to fail rather than merely likely to.
			var passCtx context.Context
			var cancelPass context.CancelFunc
			passCtx, cancelPass = context.WithCancel(ctx)
			defer cancelPass()

			fake.saveErr = nil
			fake.mu.Lock()
			fake.saveHook = func() error {
				cancelPass()
				return fmt.Errorf("secret store timed out")
			}
			fake.mu.Unlock()

			_, err := myCA.reconcileManagedCert(passCtx, entry,
				time.Now().UTC().Add(dueWindow))
			Expect(err).To(MatchError(ContainSubstring("secret store timed out")))

			orphanSerial, gerr := store.LatestSerialForSubject(ctx, subject)
			Expect(gerr).NotTo(HaveOccurred())
			Expect(orphanSerial).NotTo(Equal(serialHexStr(predecessor.SerialNumber)),
				"the fixture is only meaningful if a new certificate was actually signed")

			orphanInt, ok := new(big.Int).SetString(orphanSerial, 16)
			Expect(ok).To(BeTrue())
			revoked, rerr := myCA.IsRevokedSerial(ctx, orphanInt)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue(),
				"the rollback inherited the cancelled context and never ran, so a certificate "+
					"nobody can use is live until it expires")

			// The record put-back is the other half of the repair, and it is on
			// the same cancelled context. Asserted HERE rather than only on the
			// fast-failure arm, because this is the shape where a shared
			// deadline defeats it -- an assertion that only ever runs against a
			// live context cannot tell the two implementations apart.
			restored, gerr2 := store.GetCert(ctx, subject)
			Expect(gerr2).NotTo(HaveOccurred())
			rblock, _ := pem.Decode(restored)
			Expect(rblock).NotTo(BeNil())
			rcert, perr := x509.ParseCertificate(rblock.Bytes)
			Expect(perr).NotTo(HaveOccurred())
			Expect(rcert.SerialNumber).To(Equal(predecessor.SerialNumber),
				"the record still names the revoked orphan, so the put-back inherited the "+
					"cancelled context too")
		})

		It("does not put a foreign predecessor into the CA's own record", func() {
			// On the not-ours arm `current` is a certificate this CA did not
			// issue. Restoring THAT to cert/<subject> would leave the CA serving
			// material of unknown provenance with no inventory row, which
			// evictRevokedLocked then reads as ErrCertExists for ever, since a
			// foreign serial can never reach this CA's CRL.
			foreign, foreignKey := selfSignedIssuer("Some other CA")
			leaf := mintLeaf(foreign, foreignKey, subject, spec.DNSNames, nil,
				90*24*time.Hour, time.Now().UTC())
			fake.mu.Lock()
			fake.certPEM, fake.keyPEM = leaf.certPEM, leaf.keyPEM
			fake.mu.Unlock()

			_, err := reconcile()
			Expect(err).To(MatchError(ContainSubstring("secret rejected")))

			stored, gerr := store.GetCert(ctx, subject)
			Expect(gerr).NotTo(HaveOccurred())
			sblock, _ := pem.Decode(stored)
			Expect(sblock).NotTo(BeNil())
			scert, perr := x509.ParseCertificate(sblock.Bytes)
			Expect(perr).NotTo(HaveOccurred())
			Expect(scert.SerialNumber).NotTo(Equal(leaf.cert.SerialNumber),
				"the CA's record must not be overwritten with a certificate it did not issue")
		})

		It("leaves the predecessor valid and in the store", func() {
			_, err := reconcileAt(dueWindow)
			Expect(err).To(HaveOccurred())

			Expect(fake.stored().SerialNumber).To(Equal(predecessor.SerialNumber),
				"the store must still hold the working pair it had before")
			revoked, err := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(),
				"the predecessor is the only usable credential left; revoking it would strand the subject")
		})
	})

	Describe("retiring the predecessor", func() {
		It("records it for delayed revocation when a window is configured", func() {
			myCA.SupersedeAfter = 24 * time.Hour

			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			issued, err := reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())

			revoked, err := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(), "the window is the whole point: it must not be on the CRL yet")

			entries, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Serial).To(Equal(serialHexStr(predecessor.SerialNumber)))
			// The subject on the list is functional, not decorative:
			// retireSupersededForSubjectLocked matches it by exact string
			// equality, so a different spelling here silently loses this
			// predecessor from `revoke --certname`.
			Expect(entries[0].Subject).To(Equal(subject))
		})

		It("revokes it inline when no window is configured", func() {
			// SupersedeAfter's zero value. A CA constructed anywhere but
			// `openvox-ca serve` has it, so this is the behaviour a managed
			// certificate gets by default rather than an exotic setting.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			_, err = reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())

			revoked, err := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		})

		It("does not put a foreign certificate's serial on our CRL", func() {
			// The store held something this CA did not issue. Replacing it is
			// right; revoking it is not ours to do, and the serial identifies a
			// different certificate under a different issuer.
			foreign, foreignKey := selfSignedIssuer("Some other CA")
			leaf := mintLeaf(foreign, foreignKey, subject, spec.DNSNames, nil,
				90*24*time.Hour, time.Now().UTC())
			fake.certPEM, fake.keyPEM = leaf.certPEM, leaf.keyPEM

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())

			revoked, err := myCA.IsRevokedSerial(ctx, leaf.cert.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse())

			entries, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty())
		})
	})

	Describe("when the stored certificate has been revoked", func() {
		// The only wiring between the CRL and issueDecision's `revoked` input is
		// storedMaterialRevoked, and nothing exercised it: every other spec here
		// reaches it with an unrevoked certificate, so replacing its body with
		// `return false` failed nothing. An operator who revokes a managed
		// certificate expects it replaced now, not whenever its renew window
		// happens to open.
		It("reissues at once, without waiting for the renew window", func() {
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			Expect(myCA.Revoke(ctx, subject)).To(Succeed())

			// The SAME clock as the first pass. That is what makes this
			// falsifiable: a renew-window reissue would confound it, and at this
			// instant the certificate is 90 days from expiry with a 30-day
			// window, so the only thing that can make it due is the revocation.
			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue(), "a revoked certificate must be replaced immediately")
			Expect(fake.stored().SerialNumber).NotTo(Equal(predecessor.SerialNumber))
		})

		It("does not retire a predecessor that is already on the CRL", func() {
			// issueManagedUnderSubjectLock skips supersession on the revoked arm. Without
			// that guard the CA re-retires a serial the CRL already carries:
			// harmless on the immediate path, but on the delayed one it appends
			// a pending entry for a certificate that needs nothing further.
			myCA.SupersedeAfter = 24 * time.Hour
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			predecessor := fake.stored()

			Expect(myCA.Revoke(ctx, subject)).To(Succeed())
			// Confirm the revocation landed on the certificate this spec is
			// about. Revoke resolves the subject to its current certificate, so
			// if that were ever something other than the one in the store, the
			// assertions below would be about a certificate nobody revoked.
			wasRevoked, rerr := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(wasRevoked).To(BeTrue())

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue(),
				"the revoked certificate must have been replaced, or the empty list "+
					"below is satisfied by nothing having happened at all")

			entries, _, rerr := myCA.readSuperseded(ctx)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty(),
				"an already-revoked predecessor needs no supersession window")
		})
	})

	Describe("when another certificate already holds the name", func() {
		// issueLeafLocked ends in an unconditional SaveCert, and the predecessor
		// this path retires comes from the entry's own store -- which on the
		// absent arm is nothing. Without a guard, a managed entry configured for
		// a name that already has a certificate overwrites the CA's record of it
		// while leaving it valid, unrevoked, and no longer reachable by
		// `revoke --certname`: a live credential nothing can retire.
		It("issues anyway, and leaves the other certificate valid", func() {
			// The mechanism must not stall (#242's failure table requires the
			// next pass to reissue), and it must not revoke a credential it
			// cannot prove is its own. So it does neither: it issues, and it
			// leaves the incumbent exactly as it found it. The operator is told,
			// which is what warnIfDisplacingUnderSubjectLock is for.
			existing, err := myCA.GenerateWithOptions(ctx, subject, GenerateOptions{
				DNSAltNames: []string{subject},
			})
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(existing.CertificatePEM)
			Expect(block).NotTo(BeNil())
			incumbent, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue(), "the entry must not stall on a name already in use")

			// Not revoked. This is the assertion that matters: an ordinary agent
			// certificate for this name satisfies any spec the entry could
			// plausibly carry, so a mechanism that inferred ownership from the
			// spec would retire a node's live credential here.
			revoked, rerr := myCA.IsRevokedSerial(ctx, incumbent.SerialNumber)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(),
				"the CA must not revoke a certificate it cannot prove is the entry's")

			entries, _, serr := myCA.readSuperseded(ctx)
			Expect(serr).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty(),
				"nor schedule it for revocation, which is the same act with a delay")
		})

		It("logs the displacement, naming the serial and a remedy", func() {
			// After the refusal design was abandoned this warning is the ONLY
			// record that a live credential stopped being reachable by certname.
			// Deleting the call, or dropping the serial from it, would otherwise
			// fail nothing.
			existing, err := myCA.GenerateWithOptions(ctx, subject, GenerateOptions{
				DNSAltNames: []string{subject},
			})
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(existing.CertificatePEM)
			Expect(block).NotTo(BeNil())
			incumbent, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})))
			defer slog.SetDefault(prev)

			_, err = reconcile()
			Expect(err).NotTo(HaveOccurred())

			Expect(buf.String()).To(ContainSubstring("no longer reachable by certname"))
			Expect(buf.String()).To(ContainSubstring(serialHexStr(incumbent.SerialNumber)),
				"the warning must name the displaced serial; it is the only way to address it")
			Expect(buf.String()).To(ContainSubstring("revoke --serial"))
		})

		It("says nothing on the steady-state pass", func() {
			// The complement: an inverted same-serial check would warn on every
			// ordinary renewal, which is how a real warning becomes noise
			// nobody reads.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())

			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})))
			defer slog.SetDefault(prev)

			_, err = reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())
			Expect(buf.String()).NotTo(ContainSubstring("no longer reachable by certname"))
		})

		It("leaves a certificate with different usages alone too", func() {
			// Deliberately NOT claiming this is the complement of the spec
			// above. Both reach warnIfDisplacingUnderSubjectLock with an empty
			// entry store, so `current` is nil and neither leafCarriesNames nor
			// leafCarriesUsages is consulted on the incumbent -- the reconcile
			// path makes no resemblance judgement at all, which is the point.
			// The fixture varies anyway, so that a future change which DID start
			// judging resemblance here has a second shape to fail on. The
			// falsifiable resemblance case is "reissues when its own store was
			// emptied", whose incumbent satisfies the spec by construction.
			existing, err := myCA.GenerateWithOptions(ctx, subject, GenerateOptions{
				DNSAltNames: []string{subject, "managed"},
			})
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(existing.CertificatePEM)
			Expect(block).NotTo(BeNil())
			incumbent, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(incumbent.ExtKeyUsage).To(ContainElement(x509.ExtKeyUsageClientAuth))

			entry.Spec.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())

			revoked, rerr := myCA.IsRevokedSerial(ctx, incumbent.SerialNumber)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse())
		})

		It("reissues when its own store was emptied", func() {
			// #242's failure table: "Store contents deleted externally | The
			// load in step 1 catches it; next pass reissues." The CA still
			// holds the certificate this entry issued last pass, so a guard
			// that merely refused an unrecognised incumbent would stall the
			// entry for ever and let the real certificate expire -- which is
			// what the first version of this guard did.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			previous := fake.stored()

			// The store is emptied out from under the CA.
			fake.mu.Lock()
			fake.certPEM, fake.keyPEM = nil, nil
			fake.mu.Unlock()

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue(), "the entry must self-heal, not stall")
			Expect(fake.stored().SerialNumber).NotTo(Equal(previous.SerialNumber))

			// THIS is the fixture that makes the whole displacement decision
			// falsifiable, and it is the only one that can be.
			//
			// `previous` was issued by this entry from this very spec, so it
			// satisfies leafCarriesNames and leafCarriesUsages by construction.
			// The abandoned retire-on-resemblance design would therefore have
			// retired it here -- and no fixture whose incumbent FAILS the spec
			// can tell that design apart from this one, because that design
			// would not have retired those either.
			//
			// So: not revoked, and not scheduled for revocation. The CA revokes
			// nothing it cannot prove is the entry's, and it cannot prove this.
			revoked, rerr := myCA.IsRevokedSerial(ctx, previous.SerialNumber)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(),
				"a certificate that satisfies the entry's own spec must STILL not be revoked; "+
					"resemblance is not ownership, and an ordinary agent certificate for this "+
					"name resembles it just as closely")

			entries, _, serr2 := myCA.readSuperseded(ctx)
			Expect(serr2).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty(),
				"nor scheduled for revocation, which is the same act with a delay")

			// And it keeps its inventory row, so it stays addressable by serial
			// even though the CA's record for the name now points elsewhere.
			sub, serr := store.SubjectForSerial(ctx, serialHexStr(previous.SerialNumber))
			Expect(serr).NotTo(HaveOccurred())
			Expect(sub).To(Equal(subject),
				"the displaced certificate must remain addressable by serial")
		})

		It("reissues when its own store holds bytes that will not parse", func() {
			// The other self-heal arm, and the reason the guard treats
			// undecodable stored bytes as a repair rather than a collision.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())

			fake.mu.Lock()
			fake.certPEM = []byte("this is not a certificate")
			fake.mu.Unlock()

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())
		})

		It("reissues over an undecodable certificate in the CA's own record", func() {
			// Nothing anybody can present, so there is nothing to protect and
			// overwriting is the repair. Without this arm a corrupt blob would
			// wedge the entry permanently.
			Expect(store.SaveCert(ctx, subject, []byte("not a certificate"))).To(Succeed())

			issued, err := reconcile()
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue())
		})

		It("proceeds on the steady-state pass, where the stored certificate is its own", func() {
			// The guard must not fire on the certificate this entry itself
			// wrote, or the second renewal of every managed certificate fails.
			_, err := reconcile()
			Expect(err).NotTo(HaveOccurred())

			issued, err := reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())
			Expect(issued).To(BeTrue(), "a managed certificate must be able to replace itself")
		})
	})

	It("blocks on the subject lock, and takes crl inside it, not before", func() {
		// The deterministic half of the convergence claim, in the shape
		// renewrace_test.go uses for the four other callers of this nesting --
		// because lockorder_test.go's allowedLockNesting now names
		// ReconcileManaged as the fifth and credits this spec with pinning it.
		//
		// Three assertions, and the second is the one that makes it an
		// *ordering* spec rather than merely a locking one:
		//
		//  1. the reconcile waits on a held subject lock (it takes the lock);
		//  2. `crl` stays grantable while it waits (it did NOT take crl first,
		//     which is the inversion the documented order exists to forbid, and
		//     which would otherwise deadlock two replicas against each other);
		//  3. the CRL-locked work demonstrably ran, so 2 is not vacuous.
		//
		// Without 2 and 3 an inverted acquisition leaves this spec green.
		//
		// Seeded with a predecessor so there is something to retire: with
		// SupersedeAfter at its zero value the retirement revokes inline, which
		// is the CRL-locked work assertion 3 observes.
		_, err := reconcile()
		Expect(err).NotTo(HaveOccurred())
		predecessor := fake.stored()

		release := make(chan struct{})
		held := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			Expect(store.WithLock(ctx, subjectLockName(subject), func() error {
				close(held)
				<-release
				return nil
			})).To(Succeed())
		}()
		Eventually(held).Should(BeClosed())

		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			_, err := reconcileAt(dueWindow)
			Expect(err).NotTo(HaveOccurred())
			close(done)
		}()

		Consistently(done, 200*time.Millisecond, 20*time.Millisecond).ShouldNot(BeClosed(),
			"the reconcile issued while another holder had the subject lock")

		// While it is parked, `crl` must still be free. A path that took crl
		// before the subject lock would be holding it now.
		crlFree := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			crlCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			Expect(store.WithLock(crlCtx, lockNameCRL, func() error { return nil })).To(Succeed())
			close(crlFree)
		}()
		Eventually(crlFree).Should(BeClosed(),
			"the CRL lock was not grantable while the reconcile waited on the subject lock, "+
				"so this path takes crl outside the subject lock -- the inversion "+
				"docs/development/locking.md forbids")

		close(release)
		Eventually(done).Should(BeClosed())

		// And the CRL-locked work really happened, so the grant above was not
		// merely a lock nobody wanted.
		revoked, err := myCA.IsRevokedSerial(ctx, predecessor.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(),
			"the predecessor was not retired, so this spec observed no CRL-locked work at all")
	})
})

// Four replicas racing to reconcile the same managed certificate.
//
// The pair of specs is the assertion. Convergence on its own would pass with
// the lock deleted whenever the scheduler happened to be kind, and a green run
// would prove nothing; the second spec establishes that this harness really can
// observe the failure, by removing the only thing that prevents it. Both drive
// the same store, the same barrier and the same delay, so the shared lock table
// is the single difference between them.
var _ = Describe("Four replicas reconciling one managed certificate", func() {
	const subject = "managed.test"

	var (
		ctx      context.Context
		storeDir string
		spec     CertSpec
		fake     *memStore
	)

	// replicaOn builds a CA over svc. Four of them over one StorageService
	// share its lock table, which is what a distributed backend gives replicas
	// on different hosts; four over separate services share nothing.
	replicaOn := func(svc *storage.StorageService) *CA {
		GinkgoHelper()
		c := New(svc, AutosignConfig{Mode: "off"}, "puppet.test")
		c.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		c.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(c.Init(ctx)).To(Succeed())
		return c
	}

	// serviceOverStore builds a StorageService whose backend declines same-host
	// locking, for the reason renewrace_test.go's noSameHostLocks gives: the
	// filesystem flock added by #187 would otherwise couple two services over
	// one directory, and these specs need to control that coupling rather than
	// inherit it.
	serviceOverStore := func() *storage.StorageService {
		backend := &noSameHostLocks{FilesystemBackend: storage.NewFilesystemBackend(storeDir)}
		return storage.NewWithBackend(backend, filepath.Join(storeDir, "private"))
	}

	// raceFourWays runs one reconcile pass on each replica, all released at
	// once, and returns how many issuances reached the store.
	raceFourWays := func(replicas []*CA) int {
		entry := ManagedCert{Spec: spec, Load: fake.load, Save: fake.save}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, c := range replicas {
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				<-start
				// Errors are not asserted on: a replica that loses the race and
				// then finds the winner's certificate current returns no error,
				// but one whose lock acquisition times out legitimately does.
				// What this spec is about is how many certificates exist.
				_, _ = c.reconcileManagedCert(ctx, entry, time.Now().UTC())
			}()
		}
		close(start)
		wg.Wait()
		return fake.saveCount()
	}

	BeforeEach(func() {
		ctx = context.Background()
		storeDir = GinkgoT().TempDir()
		spec = CertSpec{
			Subject:     subject,
			DNSNames:    []string{subject},
			TTL:         90 * 24 * time.Hour,
			RenewBefore: 30 * 24 * time.Hour,
		}
		// Long enough that every replica is certainly inside Load before any of
		// them writes. It widens the window rather than deciding the outcome:
		// under a shared lock the losers simply wait their turn.
		fake = &memStore{delay: 10 * time.Millisecond}
	})

	It("converges on one certificate and one issuance", func() {
		svc := serviceOverStore()
		replicas := []*CA{replicaOn(svc), replicaOn(svc), replicaOn(svc), replicaOn(svc)}

		Expect(raceFourWays(replicas)).To(Equal(1),
			"the subject lock must serialise the four, so the three that follow the winner "+
				"load its certificate and find it current")

		serials, err := inventorySerialsFor(ctx, svc, subject)
		Expect(err).NotTo(HaveOccurred())
		Expect(serials).To(HaveLen(1), "one issuance means one inventory row")
		Expect(serials[0]).To(Equal(serialHexStr(fake.stored().SerialNumber)))
	})

	It("issues four times when the replicas share no lock", func() {
		// Not a property anybody wants -- it is what establishes that the spec
		// above is asserting something. Remove the lock from
		// reconcileManagedCert and the first spec becomes this one.
		replicas := []*CA{
			replicaOn(serviceOverStore()), replicaOn(serviceOverStore()),
			replicaOn(serviceOverStore()), replicaOn(serviceOverStore()),
		}

		Expect(raceFourWays(replicas)).To(BeNumerically(">", 1),
			"with nothing serialising them the four replicas must each issue; if this passes "+
				"with one issuance the harness cannot observe the failure the spec above rules out")
	})
})

// inventorySerialsFor returns the inventory serials recorded for subject, in
// the order they were written.
func inventorySerialsFor(ctx context.Context, svc *storage.StorageService, subject string) ([]string, error) {
	records, err := svc.InventoryEntries(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range records {
		if r.Subject == subject {
			out = append(out, r.Serial)
		}
	}
	return out, nil
}
