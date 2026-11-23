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

package ca_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// existsProbeBackend intercepts Exists on the two keys SaveRequest's duplicate
// check reads: one subject's certificate and its pending CSR.
//
// With rendezvous set, each caller waits at the CSR key until a second has
// arrived, or until the timeout. Two submissions whose checks both precede
// either save meet and are released together, so both see an empty slot; two
// whose checks are serialised by the subject lock never meet, because the
// second cannot reach the check until the first has saved. The timeout is what
// lets the serialised case finish rather than hang, and it cuts both ways: with
// the lock removed, a second submission scheduled more than the timeout after
// the first would also miss the rendezvous and the spec would pass. So it is
// generous, at the cost of that much wall-clock in the serialised case.
//
// With fail set, Exists on failKey answers with that error instead, standing
// in for a backend that is reachable but cannot answer.
type existsProbeBackend struct {
	storage.Backend
	csrKey     string
	rendezvous bool
	failKey    string
	fail       error

	mu      sync.Mutex
	arrived int
	met     chan struct{}
}

func (b *existsProbeBackend) Exists(ctx context.Context, key string) (bool, error) {
	if b.fail != nil && key == b.failKey {
		return false, b.fail
	}
	if b.rendezvous && key == b.csrKey {
		b.mu.Lock()
		b.arrived++
		if b.arrived == 2 {
			close(b.met)
		}
		b.mu.Unlock()
		select {
		case <-b.met:
		case <-time.After(2 * time.Second):
		}
	}
	return b.Backend.Exists(ctx, key)
}

// OpenVox Server refuses a CSR for a subject that already has a pending CSR, a
// signed certificate or a revoked one, unless allow-duplicate-certs is set
// (validate-duplicate-cert-policy!). These specs pin the same policy here, and
// that it runs inside the subject lock, ahead of the save and of autosigning.
var _ = Describe("SaveRequest duplicate-certificate policy", func() {
	var (
		ctx    context.Context
		tmpDir string
		store  *storage.StorageService
		probe  *existsProbeBackend
	)

	const subject = "dup-node"

	// newCA returns a CA over the shared store. Calling it twice gives two
	// replicas of one cluster: each has its own c.mu, so only the store's
	// subject lock can serialise them.
	newCA := func(mode string) *ca.CA {
		GinkgoHelper()
		myCA := ca.New(store, ca.AutosignConfig{Mode: mode}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())
		return myCA
	}

	csr := func() []byte {
		GinkgoHelper()
		pemBytes, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		return pemBytes
	}

	stored := func(get func(context.Context, string) ([]byte, error)) []byte {
		GinkgoHelper()
		b, err := get(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return b
	}

	serialOf := func(certPEM []byte) *x509.Certificate {
		GinkgoHelper()
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	// acceptanceLine returns the log record allow_duplicate_certs writes when
	// it accepts a duplicate, failing the spec if there is none. Matched on
	// its full message because the docs tell operators to search for it.
	acceptanceLine := func(log string) string {
		GinkgoHelper()
		for _, l := range strings.Split(log, "\n") {
			if strings.Contains(l, `msg="Accepting a duplicate certificate request (allow_duplicate_certs)"`) {
				return l
			}
		}
		Fail("no acceptance line logged; log:\n" + log)
		return ""
	}

	// expectRefused asserts the refusal and the state word it reports.
	expectRefused := func(err error, state string) {
		GinkgoHelper()
		var dup *ca.DuplicateCertError
		Expect(errors.As(err, &dup)).To(BeTrue(), "want a *DuplicateCertError, got %T: %v", err, err)
		Expect(dup.State).To(Equal(state))
		Expect(dup.Error()).To(Equal(
			subject + " already has a " + state + " certificate; ignoring certificate request"))
	}

	// refusals builds what DuplicateRefusals should report, so that each
	// spec states every state's count and a refusal counted under the wrong
	// one fails as surely as one not counted at all.
	refusals := func(requested, signed, revoked uint64) map[string]uint64 {
		return map[string]uint64{
			ca.DuplicateRequested: requested,
			ca.DuplicateSigned:    signed,
			ca.DuplicateRevoked:   revoked,
		}
	}

	BeforeEach(func() {
		ctx = context.Background()
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-dupcsr-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(os.RemoveAll, tmpDir)

		probe = &existsProbeBackend{
			Backend: storage.NewFilesystemBackend(tmpDir),
			csrKey:  storage.CSRKey(subject),
			met:     make(chan struct{}),
		}
		store = storage.NewWithBackend(probe, tmpDir+"/private")
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
	})

	Context("with allow_duplicate_certs off (the default)", func() {
		var myCA *ca.CA

		BeforeEach(func() {
			myCA = newCA("off")
			Expect(myCA.AllowDuplicateCerts).To(BeFalse(), "the default must refuse")
		})

		It("refuses a subject with a pending CSR and keeps the first one", func() {
			first := csr()
			_, err := myCA.SaveRequest(ctx, subject, first)
			Expect(err).NotTo(HaveOccurred())

			_, err = myCA.SaveRequest(ctx, subject, csr())
			expectRefused(err, ca.DuplicateRequested)
			Expect(stored(store.GetCSR)).To(Equal(first))
			Expect(myCA.DuplicateRefusals()).To(Equal(refusals(1, 0, 0)),
				"openvoxca_csr_duplicate_refusals_total{state=\"requested\"} must count the refusal")
		})

		It("refuses a resubmission of the very same CSR, as OpenVox Server does", func() {
			first := csr()
			_, err := myCA.SaveRequest(ctx, subject, first)
			Expect(err).NotTo(HaveOccurred())

			_, err = myCA.SaveRequest(ctx, subject, first)
			expectRefused(err, ca.DuplicateRequested)
		})

		It("refuses a subject with a signed certificate and writes no CSR", func() {
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())

			_, err = myCA.SaveRequest(ctx, subject, csr())
			expectRefused(err, ca.DuplicateSigned)
			Expect(store.HasCSR(ctx, subject)).To(BeFalse())
			Expect(stored(store.GetCert)).To(Equal(certPEM))
			Expect(myCA.DuplicateRefusals()).To(Equal(refusals(0, 1, 0)),
				"openvoxca_csr_duplicate_refusals_total{state=\"signed\"} must count the refusal")
		})

		It("refuses a subject with a revoked certificate and keeps the certificate", func() {
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(ctx, subject)).To(Succeed())

			_, err = myCA.SaveRequest(ctx, subject, csr())
			expectRefused(err, ca.DuplicateRevoked)
			Expect(store.HasCSR(ctx, subject)).To(BeFalse())
			Expect(stored(store.GetCert)).To(Equal(certPEM),
				"a refused CSR must not evict the revoked certificate")
			Expect(myCA.DuplicateRefusals()).To(Equal(refusals(0, 0, 1)),
				"openvoxca_csr_duplicate_refusals_total{state=\"revoked\"} must count the refusal")
		})

		DescribeTable("accepts a CSR again once a pending one is removed",
			// The remedies docs/api.md gives for a subject held by a pending
			// request: reject the request, or clean the subject.
			func(remove func(*ca.CA) error) {
				_, err := myCA.SaveRequest(ctx, subject, csr())
				Expect(err).NotTo(HaveOccurred())
				_, err = myCA.SaveRequest(ctx, subject, csr())
				expectRefused(err, ca.DuplicateRequested)

				Expect(remove(myCA)).To(Succeed())

				next := csr()
				_, err = myCA.SaveRequest(ctx, subject, next)
				Expect(err).NotTo(HaveOccurred())
				Expect(stored(store.GetCSR)).To(Equal(next))
			},
			Entry("by rejecting it", func(c *ca.CA) error { return c.DeleteRequest(ctx, subject) }),
			Entry("by cleaning the subject", func(c *ca.CA) error { return c.Clean(ctx, subject) }),
		)

		It("refuses as signed when the stored certificate has expired", func() {
			// Expiry is not checked, as upstream does not: an expired node is
			// cleaned (or swept by enable_expired_cert_cleanup) like any other.
			csrPEM := csr()
			block, _ := pem.Decode(csrPEM)
			parsed, err := x509.ParseCertificateRequest(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			expired := &x509.Certificate{
				SerialNumber: big.NewInt(0xE0E0),
				Subject:      parsed.Subject,
				NotBefore:    time.Now().Add(-2 * 365 * 24 * time.Hour),
				NotAfter:     time.Now().Add(-24 * time.Hour),
			}
			der, err := x509.CreateCertificate(rand.Reader, expired, myCA.CACert, parsed.PublicKey, myCA.CAKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveCert(ctx, subject, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))).To(Succeed())

			_, err = myCA.SaveRequest(ctx, subject, csr())
			expectRefused(err, ca.DuplicateSigned)
			Expect(store.HasCSR(ctx, subject)).To(BeFalse())
		})

		It("refuses as signed when the stored certificate cannot be parsed", func() {
			// Unreadable is not absent: the subject still holds something, and
			// only the revoked/signed word depends on parsing it.
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveCert(ctx, subject, []byte("not a certificate"))).To(Succeed())

			_, err = myCA.SaveRequest(ctx, subject, csr())
			expectRefused(err, ca.DuplicateSigned)
			Expect(store.HasCSR(ctx, subject)).To(BeFalse())
		})

		It("accepts a CSR again once the subject has been cleaned", func() {
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(ctx, subject)).To(Succeed())
			_, err = myCA.SaveRequest(ctx, subject, csr())
			expectRefused(err, ca.DuplicateRevoked)

			Expect(myCA.Clean(ctx, subject)).To(Succeed())

			next := csr()
			_, err = myCA.SaveRequest(ctx, subject, next)
			Expect(err).NotTo(HaveOccurred())
			Expect(stored(store.GetCSR)).To(Equal(next))
		})

		// expectFault asserts that a storage fault came back as that fault: not
		// as a refusal, which would tell the agent to keep waiting for a
		// certificate nobody decided about, and not as success.
		expectFault := func(err error) {
			GinkgoHelper()
			Expect(err).To(MatchError(ContainSubstring("backend unavailable")))
			var dup *ca.DuplicateCertError
			Expect(errors.As(err, &dup)).To(BeFalse(),
				"a fault is not a refusal, and must not be answered as one")
		}

		It("refuses before the save when storage cannot say whether a CSR is pending", func() {
			first := csr()
			_, err := myCA.SaveRequest(ctx, subject, first)
			Expect(err).NotTo(HaveOccurred())

			probe.failKey, probe.fail = storage.CSRKey(subject), errors.New("backend unavailable")
			_, err = myCA.SaveRequest(ctx, subject, csr())
			probe.fail = nil

			expectFault(err)
			Expect(stored(store.GetCSR)).To(Equal(first),
				"an unanswered check must not fall through to the save")
		})

		It("refuses before the save when storage cannot say whether a certificate is held", func() {
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())

			probe.failKey, probe.fail = storage.CertKey(subject), errors.New("backend unavailable")
			_, err = myCA.SaveRequest(ctx, subject, csr())
			probe.fail = nil

			expectFault(err)
			Expect(store.HasCSR(ctx, subject)).To(BeFalse(),
				"an unanswered check must not fall through to the save")
			Expect(stored(store.GetCert)).To(Equal(certPEM))
			Expect(myCA.DuplicateRefusals()).To(Equal(refusals(0, 0, 0)),
				"a check storage could not answer is a fault, not a duplicate")
		})

		It("lets exactly one of two racing submissions through", func() {
			// Two replicas, so c.mu cannot serialise them and the subject lock
			// is the only thing that can.
			replica := newCA("off")
			probe.rendezvous = true

			csrs := [][]byte{csr(), csr()}
			errs := make([]error, 2)
			var wg sync.WaitGroup
			for i, c := range []*ca.CA{myCA, replica} {
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					_, errs[i] = c.SaveRequest(ctx, subject, csrs[i])
				}()
			}
			wg.Wait()

			var winners []int
			for i, err := range errs {
				if err == nil {
					winners = append(winners, i)
				}
			}
			Expect(winners).To(HaveLen(1), "want exactly one submission accepted; errors: %v", errs)
			expectRefused(errs[1-winners[0]], ca.DuplicateRequested)
			Expect(string(stored(store.GetCSR))).To(Equal(string(csrs[winners[0]])),
				"the stored CSR must be the winner's")
		})
	})

	Context("with autosigning on", func() {
		It("refuses before autosigning, so no second certificate is issued", func() {
			myCA := newCA("true")
			signed, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeTrue())
			certPEM := stored(store.GetCert)

			signed, err = myCA.SaveRequest(ctx, subject, csr())
			expectRefused(err, ca.DuplicateSigned)
			Expect(signed).To(BeFalse())
			Expect(stored(store.GetCert)).To(Equal(certPEM))
		})

		It("issues nothing when storage cannot say whether a certificate is held", func() {
			// The outcome the fail-closed certificate lookup exists for: read as
			// "nothing held", the fault would autosign a second certificate.
			myCA := newCA("true")
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			certPEM := stored(store.GetCert)

			probe.failKey, probe.fail = storage.CertKey(subject), errors.New("backend unavailable")
			signed, err := myCA.SaveRequest(ctx, subject, csr())
			probe.fail = nil

			Expect(err).To(MatchError(ContainSubstring("backend unavailable")))
			Expect(signed).To(BeFalse())
			Expect(stored(store.GetCert)).To(Equal(certPEM), "no second certificate may be issued")
		})
	})

	// allow-duplicate-certs in OpenVox Server only logs and carries on: the new
	// CSR is written over the old one, and a certificate is left where it is
	// until a signing writes over it. Nothing is revoked or deleted.
	Context("with allow_duplicate_certs on", func() {
		It("replaces a pending CSR", func() {
			myCA := newCA("off")
			myCA.AllowDuplicateCerts = true
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())

			next := csr()
			_, err = myCA.SaveRequest(ctx, subject, next)
			Expect(err).NotTo(HaveOccurred())
			Expect(stored(store.GetCSR)).To(Equal(next))
		})

		It("queues a CSR alongside a signed certificate, leaving the certificate in place", func() {
			myCA := newCA("off")
			myCA.AllowDuplicateCerts = true
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())

			next := csr()
			_, err = myCA.SaveRequest(ctx, subject, next)
			Expect(err).NotTo(HaveOccurred())
			Expect(stored(store.GetCSR)).To(Equal(next))
			Expect(stored(store.GetCert)).To(Equal(certPEM))
			Expect(myCA.DuplicateRefusals()).To(Equal(refusals(0, 0, 0)),
				"an accepted duplicate is not a refusal")
		})

		It("queues a CSR alongside a revoked certificate, leaving the certificate in place", func() {
			myCA := newCA("off")
			myCA.AllowDuplicateCerts = true
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			certPEM, err := myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.Revoke(ctx, subject)).To(Succeed())

			next := csr()
			_, err = myCA.SaveRequest(ctx, subject, next)
			Expect(err).NotTo(HaveOccurred())
			Expect(stored(store.GetCSR)).To(Equal(next))
			Expect(stored(store.GetCert)).To(Equal(certPEM))
		})

		It("names the certificate rather than a CSR queued beside it, once switched off", func() {
			// Upstream reports a certificate in preference to a pending CSR when
			// a subject has both, which only this setting can bring about.
			myCA := newCA("off")
			myCA.AllowDuplicateCerts = true
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())

			myCA.AllowDuplicateCerts = false
			_, err = myCA.SaveRequest(ctx, subject, csr())
			expectRefused(err, ca.DuplicateSigned)
		})

		It("logs the serial of the certificate it leaves in place", func() {
			// Nothing revokes that certificate and no metric counts it, so this
			// line is where an operator finds the serial to revoke.
			myCA := newCA("off")
			myCA.AllowDuplicateCerts = true
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			cert := serialOf(stored(store.GetCert))

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
			defer slog.SetDefault(orig)

			_, err = myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			// The docs quote this message as the line to search for.
			line := acceptanceLine(buf.String())
			Expect(line).To(ContainSubstring("state=signed"))
			Expect(line).To(ContainSubstring(fmt.Sprintf("serial=%X", cert.SerialNumber)))
		})

		It("accepts the CSR and logs no serial when the stored certificate cannot be parsed", func() {
			myCA := newCA("off")
			myCA.AllowDuplicateCerts = true
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.Sign(ctx, subject)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveCert(ctx, subject, []byte("not a certificate"))).To(Succeed())

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
			defer slog.SetDefault(orig)

			next := csr()
			_, err = myCA.SaveRequest(ctx, subject, next)
			Expect(err).NotTo(HaveOccurred())
			Expect(stored(store.GetCSR)).To(Equal(next))
			line := acceptanceLine(buf.String())
			Expect(line).To(ContainSubstring("state=signed"))
			Expect(line).NotTo(ContainSubstring("serial="))
		})

		It("autosigns over a signed certificate without revoking it", func() {
			myCA := newCA("true")
			myCA.AllowDuplicateCerts = true
			_, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			old := serialOf(stored(store.GetCert))

			signed, err := myCA.SaveRequest(ctx, subject, csr())
			Expect(err).NotTo(HaveOccurred())
			Expect(signed).To(BeTrue())
			replacement := serialOf(stored(store.GetCert))
			Expect(replacement.SerialNumber).NotTo(Equal(old.SerialNumber))

			revoked, err := myCA.IsRevokedSerial(ctx, old.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(),
				"OpenVox Server leaves the replaced certificate to be cleaned by the operator")
		})
	})
})
