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

// White-box: issueDecision is unexported, and deliberately so. It is the one
// place the "does this certificate still do its job" question is answered, and
// exporting it to test it would invite a second caller to answer half of it
// somewhere else -- which is the exact failure the extraction exists to
// prevent.
package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// mintedLeaf is a certificate and its key, as a store would hold them.
type mintedLeaf struct {
	certPEM []byte
	keyPEM  []byte
	cert    *x509.Certificate
	key     crypto.Signer
}

// fixtureBackdate is the NotBefore backdate every fixture here is minted with.
// Chosen well above the 5-minute default so that subtracting it is observable:
// with a 24-hour backdate a one-hour certificate spans 25 hours, which is the
// case that distinguishes a clamp over forward life from one over the span.
const fixtureBackdate = 24 * time.Hour

// selfSignedIssuer builds a throwaway CA to sign fixtures with. ECDSA P-256
// because these specs mint dozens of certificates and RSA would make the suite
// slow for nothing -- no assertion here is about the key algorithm.
func selfSignedIssuer(cn string) (*x509.Certificate, crypto.Signer) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return cert, key
}

// mintLeaf signs a leaf with exactly the properties a spec asks for, including
// its NotBefore and NotAfter.
//
// It backdates NotBefore by fixtureBackdate, as issueLeafLocked backdates by
// the CA's setting, because the renew-window clamp reads that backdate out of
// the certificate again. A fixture that did not carry it would exercise
// arithmetic the real path never performs -- and would make the clamp look
// correct at short lifetimes when it is not.
//
// The fixture deliberately uses a LARGE backdate rather than the 5-minute
// default. The clamp's short-ttl arm is only interesting when the backdate is a
// significant fraction of the certificate's life, so a fixture pinned to the
// default would leave the arithmetic that matters untested on every spec here
// -- and would pass just as well if the subtraction were deleted.
func mintLeaf(issuer *x509.Certificate, issuerKey crypto.Signer, cn string,
	dnsNames []string, eku []x509.ExtKeyUsage, forwardLife time.Duration, now time.Time) mintedLeaf {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	if len(eku) == 0 {
		eku = defaultLeafExtKeyUsage()
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              dnsNames,
		ExtKeyUsage:           eku,
		NotBefore:             now.Add(-fixtureBackdate),
		NotAfter:              now.Add(forwardLife),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), issuerKey)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	keyPEM, err := marshalPrivateKeyPEM(key)
	Expect(err).NotTo(HaveOccurred())
	return mintedLeaf{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  keyPEM,
		cert:    cert,
		key:     key,
	}
}

var _ = Describe("The managed-certificate issue decision", func() {
	const subject = "managed.example.com"

	var (
		issuer    *x509.Certificate
		issuerKey crypto.Signer
		now       time.Time
		spec      CertSpec
	)

	BeforeEach(func() {
		issuer, issuerKey = selfSignedIssuer("Puppet CA: test")
		now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
		spec = CertSpec{
			Subject:     subject,
			DNSNames:    []string{subject, "managed"},
			TTL:         90 * 24 * time.Hour,
			RenewBefore: 30 * 24 * time.Hour,
		}
	})

	// The steady state first, so every arm below is a departure from something
	// that is known to answer "no".
	It("leaves a certificate that satisfies the spec alone", func() {
		leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
		issue, reason, current := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer, fixtureBackdate, now, false)
		Expect(issue).To(BeFalse(), "a fresh certificate matching the spec must not be reissued")
		Expect(reason).To(Equal(reasonCurrent))
		Expect(current).NotTo(BeNil(), "the parsed certificate is returned so the caller need not decode it again")
		Expect(current.SerialNumber).To(Equal(leaf.cert.SerialNumber))
	})

	DescribeTable("reissues, and says why",
		func(material func() (certPEM, keyPEM []byte), revoked bool, want issueReason) {
			certPEM, keyPEM := material()
			issue, reason, _ := issueDecision(certPEM, keyPEM, spec, issuer, fixtureBackdate, now, revoked)
			Expect(issue).To(BeTrue(), "expected an issuance for reason %s", want)
			Expect(reason).To(Equal(want), "reason = %s; want %s", reason, want)
		},

		Entry("nothing in the store", func() ([]byte, []byte) {
			return nil, nil
		}, false, reasonAbsent),

		Entry("a certificate that is not PEM at all", func() ([]byte, []byte) {
			return []byte("this is not a certificate"), nil
		}, false, reasonUnparseable),

		// A well-formed PEM wrapper around bytes that are not a certificate:
		// the PEM decode succeeds and the X.509 parse is what fails, which is a
		// different line of the function from the arm above.
		Entry("a PEM block whose contents are not a certificate", func() ([]byte, []byte) {
			return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02}}), nil
		}, false, reasonUnparseable),

		Entry("a certificate with no key beside it", func() ([]byte, []byte) {
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
			return leaf.certPEM, nil
		}, false, reasonKeyUnusable),

		Entry("a key that will not parse", func() ([]byte, []byte) {
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
			return leaf.certPEM, []byte("-----BEGIN EC PRIVATE KEY-----\nnope\n-----END EC PRIVATE KEY-----\n")
		}, false, reasonKeyUnusable),

		Entry("a key belonging to a different certificate", func() ([]byte, []byte) {
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
			other := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
			return leaf.certPEM, other.keyPEM
		}, false, reasonKeyMismatch),

		Entry("a certificate issued by another CA", func() ([]byte, []byte) {
			foreign, foreignKey := selfSignedIssuer("Some other CA")
			leaf := mintLeaf(foreign, foreignKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
			return leaf.certPEM, leaf.keyPEM
		}, false, reasonNotOurs),

		Entry("a certificate missing one of the spec's DNS names", func() ([]byte, []byte) {
			leaf := mintLeaf(issuer, issuerKey, subject, []string{subject}, nil, 90*24*time.Hour, now)
			return leaf.certPEM, leaf.keyPEM
		}, false, reasonNamesMissing),

		// The Common Name is a required name too. A store repointed at another
		// subject's material would otherwise satisfy a spec it has nothing to
		// do with, as long as the DNS names happened to overlap.
		Entry("a certificate carrying a different Common Name", func() ([]byte, []byte) {
			leaf := mintLeaf(issuer, issuerKey, "someone.else.example.com", spec.DNSNames, nil, 90*24*time.Hour, now)
			return leaf.certPEM, leaf.keyPEM
		}, false, reasonNamesMissing),

		Entry("a revoked certificate", func() ([]byte, []byte) {
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
			return leaf.certPEM, leaf.keyPEM
		}, true, reasonRevoked),

		// Issued 70 days ago for 90, so 20 days of a 30-day window remain. The
		// certificate has to have *aged* into the window rather than have been
		// issued short: a 30-day certificate is clamped to a 15-day window and
		// would not be due at all, which is the whole point of renewWindowFor
		// and is pinned separately below.
		Entry("a certificate inside its renew window", func() ([]byte, []byte) {
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil,
				90*24*time.Hour, now.Add(-70*24*time.Hour))
			return leaf.certPEM, leaf.keyPEM
		}, false, reasonRenewWindow),

		Entry("a certificate that has already expired", func() ([]byte, []byte) {
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, -time.Hour, now)
			return leaf.certPEM, leaf.keyPEM
		}, false, reasonRenewWindow),
	)

	It("reissues a certificate whose extended key usages are not the spec's", func() {
		// The certificate carries the default pair; the spec wants serverAuth
		// alone. Waiting for natural expiry is the wrong answer here: what is
		// in the store is a clientAuth certificate for a name in puppet_server,
		// which is a usable admin credential. Narrowing has to take effect when
		// the operator narrows it -- widening is not urgent in the same way,
		// but the comparison is exact in both directions so that neither drifts.
		leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
		spec.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

		issue, reason, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer, fixtureBackdate, now, false)
		Expect(issue).To(BeTrue())
		Expect(reason).To(Equal(reasonUsageMismatch))
	})

	It("accepts a serverAuth-only certificate against a serverAuth-only spec", func() {
		spec.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, spec.ExtKeyUsage, 90*24*time.Hour, now)

		issue, reason, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer, fixtureBackdate, now, false)
		Expect(issue).To(BeFalse(), "reason %s", reason)
	})

	It("accepts a certificate whose spec names the same usage twice", func() {
		// crypto/x509 de-duplicates extended key usages neither on write nor on
		// parse, so a spec naming one twice produces a certificate carrying it
		// twice. Comparing that against a compacted want never matches, and the
		// certificate then fails the very spec that produced it -- on every
		// pass, for ever. That is the unbounded reissue loop renewWindowFor
		// exists to close, reached through a door the clamp cannot see, so it
		// is pinned here rather than left to the clamp.
		spec.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageServerAuth}
		leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, spec.ExtKeyUsage,
			90*24*time.Hour, now)
		Expect(leaf.cert.ExtKeyUsage).To(HaveLen(2),
			"the fixture is only meaningful if the duplicate really survives the round trip; "+
				"if crypto/x509 ever starts de-duplicating, this spec is testing nothing")

		issue, reason, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer,
			fixtureBackdate, now, false)
		Expect(issue).To(BeFalse(),
			"a certificate issued from this very spec must satisfy it (reason %s)", reason)
	})

	It("accepts a certificate carrying names beyond the spec's", func() {
		// Narrowing a certificate would drop a name something may still be
		// dialling, and the certificate has done nothing wrong. Widening is
		// what the spec asks for; narrowing waits for natural renewal.
		leaf := mintLeaf(issuer, issuerKey, subject,
			append(append([]string{}, spec.DNSNames...), "extra.example.com"),
			nil, 90*24*time.Hour, now)

		issue, _, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer, fixtureBackdate, now, false)
		Expect(issue).To(BeFalse())
	})

	It("treats a certificate as foreign when it has no issuer to check against", func() {
		// An uninitialised CA cannot establish ownership, and "ours" would be
		// the unsafe answer.
		leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
		issue, reason, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, nil, fixtureBackdate, now, false)
		Expect(issue).To(BeTrue())
		Expect(reason).To(Equal(reasonNotOurs))
	})

	It("reports a foreign certificate as foreign even when it is also revoked", func() {
		// The order matters to the caller, not just to the log line: on this
		// arm the certificate's serial belongs to another issuer and must never
		// reach our CRL, and reasonNotOurs is how issueManagedUnderSubjectLock knows.
		foreign, foreignKey := selfSignedIssuer("Some other CA")
		leaf := mintLeaf(foreign, foreignKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)

		_, reason, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer, fixtureBackdate, now, true)
		Expect(reason).To(Equal(reasonNotOurs))
	})

	// The bug the extraction exists for. issueLeafLocked caps a leaf at the CA
	// certificate's remaining life, so as the CA certificate ages the
	// configured window stops being a window and becomes the whole lifetime --
	// and every fresh certificate reads as immediately due. Startup validation
	// cannot see this: the configuration never changes.
	Describe("the runtime clamp on the renew window", func() {
		It("does not reissue a certificate the CA's own remaining life cut short", func() {
			// 90-day ttl, 30-day window, but the CA certificate had 20 days
			// left, so this is what was actually signed. Unclamped, the
			// certificate is inside a 30-day window the moment it exists.
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 20*24*time.Hour, now)

			issue, reason, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer, fixtureBackdate, now, false)
			Expect(issue).To(BeFalse(),
				"a certificate issued for 20 days against a 30-day window must not be due at once "+
					"(reason %s); without the clamp this reissues on every pass, for ever", reason)
		})

		It("still renews the shortened certificate, at half its forward life", func() {
			// The clamp must not become "never renew". Progress is the other
			// half of the property: a 20-day certificate is due after 10.
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 20*24*time.Hour, now)

			issue, _, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer,
				fixtureBackdate, now.Add(10*24*time.Hour).Add(time.Minute), false)
			Expect(issue).To(BeTrue(), "the clamped window must still open")
		})

		It("does not reissue a short-lived certificate at once", func() {
			// leafBackdate is 24h, so a one-hour certificate spans 25 hours.
			// Clamping against the span rather than the forward life would give
			// a 12.5-hour window on a certificate that lasts one hour, and
			// reintroduce the loop at the other end of the scale.
			spec.TTL = time.Hour
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, time.Hour, now)

			issue, reason, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer, fixtureBackdate, now, false)
			Expect(issue).To(BeFalse(),
				"a one-hour certificate must not be due the moment it is signed (reason %s)", reason)
		})

		It("gives no window at all to a certificate the backdate outlives", func() {
			// Raising leaf_backdate_sec above a certificate's own span makes the
			// forward life negative. Without the guard the window goes negative
			// too, and `NotAfter.Add(-negative)` pushes the renewal PAST expiry
			// -- so the subject sits with an expired certificate for the
			// difference. The guard returns zero, which renews exactly at
			// expiry: late, but not later than it has to be.
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, time.Hour, now)
			Expect(renewWindowFor(leaf.cert, spec, 2*fixtureBackdate)).To(BeZero())

			// And the decision that reads it does not call the certificate due
			// while it is still valid, nor leave it undue once it is not.
			issue, _, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer,
				2*fixtureBackdate, now.Add(30*time.Minute), false)
			Expect(issue).To(BeFalse(), "still valid, so not yet due")

			issue, reason, _ := issueDecision(leaf.certPEM, leaf.keyPEM, spec, issuer,
				2*fixtureBackdate, now.Add(time.Hour+time.Minute), false)
			Expect(issue).To(BeTrue())
			Expect(reason).To(Equal(reasonRenewWindow))
		})

		It("leaves an ordinary window untouched", func() {
			// The clamp is a floor, not a policy. On a healthy CA the operator's
			// 30 days is nowhere near half of 90, and must be exactly what is
			// applied -- a clamp that quietly shortened every window would be a
			// change to what the setting means.
			leaf := mintLeaf(issuer, issuerKey, subject, spec.DNSNames, nil, 90*24*time.Hour, now)
			Expect(renewWindowFor(leaf.cert, spec, fixtureBackdate)).To(Equal(30 * 24 * time.Hour))
		})
	})
})

var _ = Describe("A managed-certificate spec", func() {
	var spec CertSpec

	BeforeEach(func() {
		spec = CertSpec{
			Subject:     "managed.example.com",
			DNSNames:    []string{"managed.example.com"},
			TTL:         90 * 24 * time.Hour,
			RenewBefore: 30 * 24 * time.Hour,
		}
	})

	It("accepts a well-formed spec", func() {
		Expect(spec.Validate()).To(Succeed())
	})

	It("refuses a certname the CA's own grammar would refuse", func() {
		spec.Subject = "../escape"
		Expect(spec.Validate()).NotTo(Succeed())
	})

	It("refuses a DNS name that is not a hostname", func() {
		spec.DNSNames = []string{"not a hostname"}
		Expect(spec.Validate()).NotTo(Succeed())
	})

	It("refuses a renew window of zero", func() {
		// Zero is not "renew at expiry" -- it is a renewal loop that only ever
		// acts on a certificate that has already stopped working.
		spec.RenewBefore = 0
		Expect(spec.Validate()).To(MatchError(ContainSubstring("renew_before must be positive")))
	})

	It("accepts a spec named only by IP", func() {
		// The requirement is a name of some kind, not a DNS name. A component
		// reached at a fixed address has nothing else to be named by.
		spec.DNSNames = nil
		spec.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
		Expect(spec.Validate()).To(Succeed())
	})

	It("refuses an IP entry that did not parse", func() {
		// net.ParseIP returns nil for a malformed address, and a nil net.IP
		// marshals into an empty SAN entry rather than failing -- so the
		// certificate would carry a name matching nothing.
		spec.IPAddresses = []net.IP{net.ParseIP("not-an-address")}
		Expect(spec.Validate()).To(MatchError(ContainSubstring("IP address entry is empty")))
	})

	It("refuses a spec with no names of any kind", func() {
		// With no CN promotion on this path, an empty list yields a certificate
		// carrying no subjectAltName extension at all -- refused by every RFC
		// 2818 client for every name, including its own certname, while looking
		// perfectly well-formed. Refused as configuration instead.
		spec.DNSNames = nil
		Expect(spec.Validate()).To(MatchError(
			ContainSubstring("at least one subject alternative name is required")))
	})

	It("refuses a nil URI entry", func() {
		// A nil *url.URL would be dereferenced in leafCarriesNames and in
		// marshalling. The reconcile loop has no recover, so that is the
		// process rather than one pass.
		spec.URIs = []*url.URL{nil}
		Expect(spec.Validate()).To(MatchError(ContainSubstring("a URI entry is nil")))
	})

	It("refuses an empty URI or email entry", func() {
		// Both satisfy the at-least-one-name requirement while reaching the
		// certificate as a name matching nothing, which is what that
		// requirement exists to stop.
		spec.URIs = []*url.URL{{}}
		Expect(spec.Validate()).To(MatchError(ContainSubstring("a URI entry is empty")))

		spec.URIs = nil
		spec.EmailAddresses = []string{""}
		Expect(spec.Validate()).To(MatchError(ContainSubstring("email address entry is empty")))
	})

	It("refuses a key configuration the CA's policy would reject", func() {
		// issueLeafLocked enforces the policy structurally, but only after a
		// pass has taken the subject lock and generated a key -- once per
		// interval, for ever. A spec that can never succeed fails here instead.
		spec.KeyConfig = KeyConfig{Algo: KeyAlgoRSA, Size: 1024}
		Expect(spec.Validate()).To(MatchError(ContainSubstring("below the minimum")))
	})

	It("refuses a negative supersession window", func() {
		// Zero is meaningful (revoke inline); negative is not.
		neg := -time.Hour
		spec.SupersedeAfter = &neg
		Expect(spec.Validate()).To(MatchError(ContainSubstring("must not be negative")))
	})

	It("refuses a negative ttl", func() {
		// Not merely nonsense: issueLeafLocked's `if ttl > 0` would silently
		// discard it and substitute the CA default, so without this arm a
		// mistyped lifetime becomes a five-year certificate with no complaint.
		spec.TTL = -time.Hour
		Expect(spec.Validate()).To(MatchError(ContainSubstring("ttl must not be negative")))
	})

	It("allows a ttl of zero, which inherits the CA's configured leaf lifetime", func() {
		spec.TTL = 0
		Expect(spec.Validate()).To(Succeed())
	})
})

var _ = Describe("The leaf NotBefore backdate", func() {
	// The setting reaches issued certificates through CA.leafBackdate(), and
	// nothing else in the suite looks at an issued certificate's NotBefore.
	// Without these, deleting the wiring in `openvox-ca serve` -- or making the
	// accessor ignore the field -- leaves every spec green while an operator's
	// leaf_backdate_sec does nothing.
	var (
		ctx  context.Context
		myCA *CA
	)

	// after is set by issueAndParse to the instant the call returned. The upper
	// bounds below must be anchored on that, not on a timestamp taken BEFORE
	// the call: issueLeafLocked reads its own clock, so the true NotBefore is
	// at or after (before - backdate), and an assertion against `before` only
	// passes because ASN.1 truncates to whole seconds -- which makes it a race
	// against however long the call took, and it is a keygen and a signature.
	var after time.Time

	issueAndParse := func(subject string) *x509.Certificate {
		GinkgoHelper()
		res, err := myCA.Generate(ctx, subject, []string{subject})
		Expect(err).NotTo(HaveOccurred())
		after = time.Now().UTC()
		block, _ := pem.Decode(res.CertificatePEM)
		Expect(block).NotTo(BeNil())
		crt, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return crt
	}

	BeforeEach(func() {
		ctx = context.Background()
		myCA = New(storage.New(GinkgoT().TempDir()), AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	It("backdates by five minutes when nothing is configured", func() {
		before := time.Now().UTC()
		crt := issueAndParse("default.test")
		// Bracketed by the two instants that surround the signature, so neither
		// bound depends on how long the call took.
		Expect(crt.NotBefore).To(BeTemporally("<=", after.Add(-defaultLeafBackdate)))
		Expect(crt.NotBefore).To(BeTemporally(">", before.Add(-defaultLeafBackdate-time.Minute)),
			"a much earlier NotBefore means the default is not 5 minutes")
	})

	It("honours a configured backdate", func() {
		myCA.LeafBackdate = 3 * time.Hour
		before := time.Now().UTC()
		crt := issueAndParse("configured.test")
		Expect(crt.NotBefore).To(BeTemporally("<=", after.Add(-3*time.Hour)))
		Expect(crt.NotBefore).To(BeTemporally(">", before.Add(-3*time.Hour-time.Minute)),
			"the configured backdate was ignored in favour of some other value")
	})

	It("does not let the backdate move NotAfter", func() {
		// The backdate lengthens the span but must not extend the life the
		// certificate was asked for, or raising it for a skewed fleet would
		// silently hand out longer-lived credentials.
		myCA.LeafBackdate = 3 * time.Hour
		before := time.Now().UTC()
		crt := issueAndParse("notafter.test")
		Expect(crt.NotAfter).To(BeTemporally(">", before),
			"a certificate that expires before it was issued is not a certificate")
		Expect(crt.NotAfter.Sub(before)).To(BeNumerically("<", certValidity+time.Minute))
		// The span exceeds the forward life by exactly the backdate, which is the
		// quantity renewWindowFor subtracts. Asserted as a difference rather
		// than as `span > 3h`: the default lifetime is five years, so that bound
		// holds with the backdate deleted altogether and tests nothing.
		Expect(crt.NotAfter.Sub(crt.NotBefore) - crt.NotAfter.Sub(after)).
			To(BeNumerically("~", 3*time.Hour, time.Minute))
	})

	It("does not reach the CA's own certificate", func() {
		// The changeset splits one backdate into two: leaves take the setting,
		// and bootstrapCA keeps a fixed 24 hours. That exclusion is asserted as
		// a contract in three doc comments and in docs/configuration.md, and
		// nothing was pinning it -- so the obvious tidy-up now that an accessor
		// exists (routing init.go through c.leafBackdate() too) would shrink the
		// CA certificate's backdate to five minutes with every spec still green.
		fresh := New(storage.New(GinkgoT().TempDir()), AutosignConfig{Mode: "off"}, "puppet.test")
		fresh.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		fresh.LeafBackdate = 3 * time.Hour
		before := time.Now().UTC()
		Expect(fresh.Init(ctx)).To(Succeed())
		then := time.Now().UTC()

		Expect(fresh.CACert.NotBefore).To(BeTemporally("<=", then.Add(-24*time.Hour)))
		Expect(fresh.CACert.NotBefore).To(BeTemporally(">", before.Add(-25*time.Hour)),
			"the CA certificate must keep its fixed 24-hour bootstrap backdate, "+
				"whatever leaf_backdate_sec says")
	})

	It("falls back to the default for a non-positive setting", func() {
		// Refused at startup by configuration, so a CA that reaches here with
		// one was built in code. The default is the safe answer: a zero or
		// negative backdate would issue certificates that are not yet valid.
		myCA.LeafBackdate = -time.Hour
		before := time.Now().UTC()
		crt := issueAndParse("negative.test")
		Expect(crt.NotBefore).To(BeTemporally("<=", after.Add(-defaultLeafBackdate)))
		Expect(crt.NotBefore).To(BeTemporally(">", before.Add(-defaultLeafBackdate-time.Minute)),
			"a negative setting must fall back to the default, not be applied")
	})
})
