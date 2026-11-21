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

// White-box, so the specs can name autosignConcurrency rather than repeat its
// value, and fill the slots directly where a spec needs them full.
package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// How many autosign executables a CA runs at once. Holding c.mu across the
// policy used to make that one, as a side effect; running the policy outside
// c.mu (#664) would have made it unbounded, on an endpoint that needs no
// authentication, so it is capped on purpose instead.
var _ = Describe("Autosign executable concurrency", func() {
	type submission struct {
		signed bool
		err    error
	}

	var (
		ctx      context.Context
		myCA     *CA
		dir      string
		released string
		denied   string
	)

	// started counts the runs that have begun: each one leaves a marker named
	// after the certname it was given.
	started := func() int {
		matches, err := filepath.Glob(filepath.Join(dir, "started-*"))
		Expect(err).NotTo(HaveOccurred())
		return len(matches)
	}

	csrFor := func(subject string) []byte {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, key)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}

	// fillSlots takes every slot, as runs that have not finished would, until
	// the spec ends or it calls the function returned. A slot an earlier run
	// in the spec failed to give back fails it here, rather than hanging.
	fillSlots := func() func() {
		GinkgoHelper()
		for i := range autosignConcurrency {
			select {
			case myCA.autosignSlots <- struct{}{}:
			case <-time.After(5 * time.Second):
				Fail(fmt.Sprintf("only %d of %d autosign slots were free", i, autosignConcurrency))
			}
		}
		var once sync.Once
		drain := func() {
			once.Do(func() {
				for range autosignConcurrency {
					<-myCA.autosignSlots
				}
			})
		}
		DeferCleanup(drain)
		return drain
	}

	BeforeEach(func() {
		ctx = context.Background()
		myCA = New(storage.New(GinkgoT().TempDir()), AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		// Each run announces itself, then decides once the spec releases it:
		// it approves unless the spec has asked for denials. Its own bound is
		// well past every wait below.
		dir = GinkgoT().TempDir()
		released = filepath.Join(dir, "released")
		denied = filepath.Join(dir, "denied")
		script := filepath.Join(dir, "autosign.sh")
		Expect(os.WriteFile(script, []byte("#!/bin/sh\n"+
			"touch '"+dir+"/started-'\"$1\"\n"+
			"i=0\n"+
			"while [ ! -e '"+released+"' ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done\n"+
			"[ -e '"+denied+"' ] && exit 1\n"+
			"exit 0\n"), 0o755)).To(Succeed())
		myCA.AutosignConfig = AutosignConfig{Mode: "executable", FileOrPath: script}
		DeferCleanup(func() { _ = os.WriteFile(released, nil, 0o600) })
	})

	release := func() {
		Expect(os.WriteFile(released, nil, 0o600)).To(Succeed())
	}

	// captureWarnings routes WARN and above into a buffer for the rest of the
	// spec.
	captureWarnings := func() *bytes.Buffer {
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		DeferCleanup(slog.SetDefault, orig)
		return &buf
	}

	It("runs at most autosignConcurrency executables at once", func() {
		total := autosignConcurrency + 1
		csrs := make([][]byte, total)
		for i := range csrs {
			csrs[i] = csrFor(fmt.Sprintf("node%d.test", i))
		}
		done := make(chan submission, total)
		var running sync.WaitGroup
		for i := range total {
			running.Go(func() {
				defer GinkgoRecover()
				signed, err := myCA.SaveRequest(ctx, fmt.Sprintf("node%d.test", i), csrs[i])
				done <- submission{signed, err}
			})
		}
		// A spec that fails before releasing the runs still lets them finish
		// before the stores they use are removed.
		DeferCleanup(func() {
			_ = os.WriteFile(released, nil, 0o600)
			running.Wait()
		})

		Eventually(started, 10*time.Second).Should(Equal(autosignConcurrency))
		// Consistently, because the property is the one that has not started.
		Consistently(started, time.Second).Should(Equal(autosignConcurrency),
			"more autosign executables ran at once than autosignConcurrency")

		release()
		for range total {
			var got submission
			Eventually(done, 30*time.Second).Should(Receive(&got))
			Expect(got.err).NotTo(HaveOccurred())
			Expect(got.signed).To(BeTrue())
		}
		Expect(started()).To(Equal(total), "the request that waited for a slot never ran")
	})

	It("gives every slot back after runs that deny", func() {
		// The cap spec above only ever approves. A slot kept by a denial would
		// leave autosign stopped for good once autosignConcurrency of them had
		// happened, so this denies one more time than that, one after another,
		// and each must still get a slot.
		release()
		Expect(os.WriteFile(denied, nil, 0o600)).To(Succeed())
		for i := range autosignConcurrency + 1 {
			subject := fmt.Sprintf("denied%d.test", i)
			runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			signed, err := myCA.SaveRequest(runCtx, subject, csrFor(subject))
			cancel()
			Expect(err).NotTo(HaveOccurred(), "denial %d could not get an autosign slot", i+1)
			Expect(signed).To(BeFalse())
		}
		Expect(started()).To(Equal(autosignConcurrency + 1))
	})

	It("saves nothing when no slot comes free before the request's deadline", func() {
		// The wait comes before the save, so a request that times out in the
		// queue leaves no CSR behind to make the agent's next submission a
		// duplicate. That submission goes through the policy instead.
		drain := fillSlots()
		logBuf := captureWarnings()
		csrPEM := csrFor("queued.test")
		waitCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		DeferCleanup(cancel)
		answered := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, err := myCA.SaveRequest(waitCtx, "queued.test", csrPEM)
			answered <- err
		}()

		Eventually(answered, 5*time.Second).Should(Receive(MatchError(context.DeadlineExceeded)),
			"a request waiting for an autosign slot outlived its context")
		Expect(started()).To(BeZero(), "a run started without a slot")
		pending, err := myCA.Storage.CSRExists(ctx, "queued.test")
		Expect(err).NotTo(HaveOccurred())
		Expect(pending).To(BeFalse(), "a request that never reached the policy was left pending")
		// The agent sees an internal failure; this is what tells the operator
		// that the cap was the cause.
		Expect(logBuf.String()).To(ContainSubstring("No autosign slot came free"))
		Expect(logBuf.String()).To(ContainSubstring("remedy="))

		drain()
		release()
		signed, err := myCA.SaveRequest(ctx, "queued.test", csrPEM)
		Expect(err).NotTo(HaveOccurred(), "the agent's next submission was refused")
		Expect(signed).To(BeTrue())
	})

	It("gives up in the queue when too little time would be left to run and sign", func() {
		// The wait, the run and the signature share one deadline. A request
		// let in with less left than a run can take would be approved and
		// then fail to sign, so it must stop waiting while the run's whole
		// timeout is still in hand -- here at once, since ten seconds is
		// less than the default run plus its margins.
		fillSlots()
		csrPEM := csrFor("late.test")
		answered := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_, err := myCA.SaveRequest(waitCtx, "late.test", csrPEM)
			answered <- err
		}()
		Eventually(answered, 2*time.Second).Should(Receive(MatchError(context.DeadlineExceeded)),
			"a request waited for a slot it would have had no time to use")
		pending, err := myCA.Storage.CSRExists(ctx, "late.test")
		Expect(err).NotTo(HaveOccurred())
		Expect(pending).To(BeFalse())
	})

	It("takes a free slot whatever is left of the deadline", func() {
		// The time kept back is for a request that has to queue. One that
		// finds a slot free runs, as it did before there was a queue. Several
		// in turn, because a wait whose deadline has already passed races a
		// free slot in a select, and one request alone could win by chance.
		release()
		for i := range autosignConcurrency {
			subject := fmt.Sprintf("prompt%d.test", i)
			runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			signed, err := myCA.SaveRequest(runCtx, subject, csrFor(subject))
			cancel()
			Expect(err).NotTo(HaveOccurred(), "request %d found a slot free and was still refused", i+1)
			Expect(signed).To(BeTrue())
		}
	})

	It("keeps back the configured executable timeout, not the default", func() {
		// With a one-second timeout the reserve is a few seconds, so a
		// request with twelve in hand can queue for a while; reserving the
		// default thirty would have turned it away at once.
		myCA.AutosignConfig.ExecutableTimeout = time.Second
		drain := fillSlots()
		csrPEM := csrFor("configured.test")
		answered := make(chan submission, 1)
		go func() {
			defer GinkgoRecover()
			waitCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			signed, err := myCA.SaveRequest(waitCtx, "configured.test", csrPEM)
			answered <- submission{signed, err}
		}()
		Consistently(answered, 2*time.Second).ShouldNot(Receive(),
			"the request gave up as if the default timeout had to be kept back")

		release()
		drain()
		var got submission
		Eventually(answered, 5*time.Second).Should(Receive(&got))
		Expect(got.err).NotTo(HaveOccurred())
		Expect(got.signed).To(BeTrue())
	})

	It("keeps c.mu free while a request waits for a slot", func() {
		// A full set of slots is a queue, and a queue under c.mu would stall
		// every reader of the CA's caches as before #664. A reader, and an
		// operator's Sign, which needs c.mu for writing, must answer while a
		// request is queued.
		Expect(myCA.Storage.SaveCSR(ctx, "other.test", csrFor("other.test"))).To(Succeed())
		fillSlots()
		csrPEM := csrFor("queued.test")
		waitCtx, cancel := context.WithCancel(ctx)
		queued := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, err := myCA.SaveRequest(waitCtx, "queued.test", csrPEM)
			queued <- err
		}()
		DeferCleanup(func() {
			cancel()
			Eventually(queued, 10*time.Second).Should(Receive())
		})
		Consistently(queued, 300*time.Millisecond).ShouldNot(Receive(), "the request did not queue")

		ready := make(chan bool, 1)
		go func() {
			defer GinkgoRecover()
			ready <- myCA.IsReady()
		}()
		Eventually(ready, time.Second).Should(Receive(BeTrue()),
			"the readiness probe waited for a request queued for an autosign slot")
		signed := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, err := myCA.Sign(ctx, "other.test")
			signed <- err
		}()
		Eventually(signed, 5*time.Second).Should(Receive(BeNil()),
			"an operator's Sign waited for a request queued for an autosign slot")
		Expect(queued).NotTo(Receive(), "the request stopped queueing before the reads were made")
	})

	It("refuses a duplicate without waiting for a slot", func() {
		// An agent waiting for its certificate resubmits on every poll. Its
		// refusal must not queue behind the runs that hold the slots.
		release()
		Expect(os.WriteFile(denied, nil, 0o600)).To(Succeed())
		csrPEM := csrFor("waiting.test")
		signed, err := myCA.SaveRequest(ctx, "waiting.test", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeFalse(), "the request should be pending for an operator")

		fillSlots()
		answered := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_, err := myCA.SaveRequest(waitCtx, "waiting.test", csrPEM)
			answered <- err
		}()
		var dup *DuplicateCertError
		var got error
		Eventually(answered, 2*time.Second).Should(Receive(&got),
			"a duplicate waited for an autosign slot before being refused")
		Expect(errors.As(got, &dup)).To(BeTrue(), "expected a duplicate refusal, got %v", got)
		Expect(dup.State).To(Equal(DuplicateRequested))
	})

	It("takes no slot for a policy that starts no process", func() {
		fillSlots()
		myCA.AutosignConfig = AutosignConfig{Mode: "true"}
		answered := make(chan submission, 1)
		csrPEM := csrFor("always.test")
		go func() {
			defer GinkgoRecover()
			waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			signed, err := myCA.SaveRequest(waitCtx, "always.test", csrPEM)
			answered <- submission{signed, err}
		}()
		var got submission
		Eventually(answered, 2*time.Second).Should(Receive(&got),
			"autosign: true waited for a slot it does not need")
		Expect(got.err).NotTo(HaveOccurred())
		Expect(got.signed).To(BeTrue())
	})
})
