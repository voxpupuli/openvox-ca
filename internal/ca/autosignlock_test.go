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

//go:build unix

package ca_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// What SaveRequest holds while an autosign policy decides (#664). The policy
// runs holding the subject lock and nothing else: the CA-wide c.mu stays free,
// so nothing that reads the CA's caches waits for an executable that may take
// its whole timeout, while everything that touches the same subject still
// does. Unix-only because the policy is a shell script, which these specs
// hold open until they release it.
//
// The readers alone would not tell c.mu released from c.mu read-held across
// the policy, since they take it for reading themselves; a writer queued
// behind a read-held c.mu would then stall them as before. The table therefore
// includes an issuance for another subject, which needs c.mu for writing.
var _ = Describe("SaveRequest while an autosign executable runs", func() {
	type submission struct {
		signed bool
		err    error
	}

	var (
		ctx      context.Context
		myCA     *ca.CA
		issued   *x509.Certificate
		ocspReq  []byte
		started  string
		released string
	)

	BeforeEach(func() {
		ctx = context.Background()
		myCA = setupOCSPCA(GinkgoT().TempDir())

		// A certificate for the readers below to be asked about, issued
		// before the policy is in place.
		csrPEM, err := testutil.GenerateCSR("issued-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, "issued-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, "issued-node")
		Expect(err).NotTo(HaveOccurred())
		issued = decodeCert(certPEM)
		ocspReq, err = testutil.BuildOCSPRequest(issued, myCA.CACert)
		Expect(err).NotTo(HaveOccurred())

		// A request for another subject, pending for an operator to sign.
		otherCSR, err := testutil.GenerateCSR("other-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, "other-node", otherCSR)
		Expect(err).NotTo(HaveOccurred())

		// The policy announces that it is running, then approves once the
		// spec releases it. Its own bound is well past every wait below, so
		// a spec that fails without releasing it still ends.
		scriptDir := GinkgoT().TempDir()
		started = filepath.Join(scriptDir, "started")
		released = filepath.Join(scriptDir, "released")
		script := filepath.Join(scriptDir, "autosign.sh")
		Expect(os.WriteFile(script, []byte("#!/bin/sh\n"+
			"touch '"+started+"'\n"+
			"i=0\n"+
			"while [ ! -e '"+released+"' ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done\n"+
			"exit 0\n"), 0o755)).To(Succeed())
		myCA.AutosignConfig = ca.AutosignConfig{Mode: "executable", FileOrPath: script}
	})

	release := func() {
		Expect(os.WriteFile(released, nil, 0o600)).To(Succeed())
	}

	// submitHeld submits a CSR for subject and returns once the policy is
	// running and has not yet decided. The submission's result arrives on the
	// returned channel after release.
	submitHeld := func(subject string) <-chan submission {
		GinkgoHelper()
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())

		done := make(chan submission, 1)
		finished := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(finished)
			signed, err := myCA.SaveRequest(ctx, subject, csrPEM)
			done <- submission{signed, err}
		}()
		// A spec that fails before releasing the policy still lets the
		// submission finish, so it does not outlive the spec. finished
		// rather than done, because the spec may already have taken the
		// result.
		DeferCleanup(func() {
			if _, err := os.Stat(released); errors.Is(err, os.ErrNotExist) {
				release()
			}
			Eventually(finished, 30*time.Second).Should(BeClosed())
		})

		Eventually(started, 10*time.Second).Should(BeAnExistingFile(),
			"the autosign executable never started")
		return done
	}

	DescribeTable("leaves the CA's cached state readable",
		func(read func() error) {
			submitted := submitHeld("held-node")

			answered := make(chan error, 1)
			go func() {
				defer GinkgoRecover()
				answered <- read()
			}()
			// Two seconds, against a policy that has not decided and will
			// not until released: before #664 the read waited for it.
			Eventually(answered, 2*time.Second).Should(Receive(BeNil()),
				"a read of the CA's cached state waited for the autosign executable")
			Expect(submitted).NotTo(Receive(),
				"the policy had decided before the read was made, so this proves nothing")

			release()
			var got submission
			Eventually(submitted, 30*time.Second).Should(Receive(&got))
			Expect(got.err).NotTo(HaveOccurred())
			Expect(got.signed).To(BeTrue())
		},
		Entry("the readiness probe (IsReady)", func() error {
			if !myCA.IsReady() {
				return errors.New("not ready")
			}
			return nil
		}),
		Entry("the revocation check on every authenticated request (IsRevokedSerial)", func() error {
			revoked, err := myCA.IsRevokedSerial(ctx, issued.SerialNumber)
			if err == nil && revoked {
				return errors.New("an unrevoked certificate read as revoked")
			}
			return err
		}),
		Entry("certificate_statuses (RevokedSerials)", func() error {
			_ = myCA.RevokedSerials()
			return nil
		}),
		Entry("the metrics scrape (CachedCRLNumber)", func() error {
			if _, ok := myCA.CachedCRLNumber(); !ok {
				return errors.New("no CRL number cached")
			}
			return nil
		}),
		Entry("the metrics scrape with OCSP on (SerialIndexSize)", func() error {
			_ = myCA.SerialIndexSize()
			return nil
		}),
		Entry("the OCSP responder (AnswerOCSP)", func() error {
			_, err := myCA.AnswerOCSP(ctx, ocspReq)
			return err
		}),
		Entry("an operator signing another subject (Sign), which needs c.mu for writing", func() error {
			_, err := myCA.Sign(ctx, "other-node")
			return err
		}),
	)

	It("keeps the subject's own operations waiting until the policy has decided", func() {
		// The subject lock is still held across the policy, which is what
		// keeps the decision and the signature about the same request: a
		// rejection landing in between would otherwise be signed anyway.
		submitted := submitHeld("held-node")

		deleted := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			deleted <- myCA.DeleteRequest(ctx, "held-node")
		}()
		Consistently(deleted, time.Second).ShouldNot(Receive(),
			"a rejection of the request completed while its autosign policy was deciding")

		release()
		var got submission
		Eventually(submitted, 30*time.Second).Should(Receive(&got))
		Expect(got.err).NotTo(HaveOccurred())
		Expect(got.signed).To(BeTrue())
		// Signing removes the pending CSR, so the rejection that waited
		// finds nothing left to reject.
		Eventually(deleted, 30*time.Second).Should(Receive(MatchError(ca.ErrNoCSR)))
	})

	It("refuses to sign when the pending CSR is not the one the policy approved", func() {
		// Nothing that takes the subject lock can replace the CSR while the
		// policy runs, so the spec writes past the lock, as a replica that
		// won a lapsed lease would.
		var logBuf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(slog.SetDefault, orig)

		submitted := submitHeld("held-node")
		replacement, err := testutil.GenerateCSR("held-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Storage.SaveCSR(ctx, "held-node", replacement)).To(Succeed())

		release()
		var got submission
		Eventually(submitted, 30*time.Second).Should(Receive(&got))
		Expect(got.err).To(MatchError(ContainSubstring("not the one the autosign policy approved")))
		Expect(got.signed).To(BeFalse())

		hasCert, err := myCA.Storage.CertExists(ctx, "held-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(hasCert).To(BeFalse(), "a certificate was issued for a request nobody approved")
		pending, err := myCA.Storage.GetCSR(ctx, "held-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(pending).To(Equal(replacement), "the replacement was not left pending for an operator")
		// The HTTP layer can only call this an internal failure, so the CA's
		// own record is what tells the operator what happened and what to do.
		Expect(logBuf.String()).To(ContainSubstring("changed while the autosign policy ran"))
		Expect(logBuf.String()).To(ContainSubstring("remedy="))
	})
})
