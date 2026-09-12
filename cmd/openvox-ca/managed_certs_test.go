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
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

var _ = Describe("The managed-certificate reconcile job", func() {
	// A store that records what the loop asked of it. Nothing here is about
	// what a real store does -- these specs are about the loop.
	var (
		mu    sync.Mutex
		loads int
	)

	managed := func(subject string) ca.ManagedCert {
		return ca.ManagedCert{
			Spec: ca.CertSpec{
				Subject:     subject,
				DNSNames:    []string{subject},
				TTL:         90 * 24 * time.Hour,
				RenewBefore: 30 * 24 * time.Hour,
			},
			Load: func(context.Context) ([]byte, []byte, error) {
				mu.Lock()
				defer mu.Unlock()
				loads++
				return nil, nil, nil
			},
			// Refuse the write, so a spec that only means to count passes does
			// not accumulate certificates it never asserts on.
			Save: func(context.Context, []byte, []byte) error {
				return context.Canceled
			},
		}
	}

	// fastCA is newRefresherTestCA with a leaf key algorithm that does not
	// dominate the spec's runtime. newRefresherTestCA leaves LeafKeyConfig
	// unset, which resolves to RSA 2048, and every pass of the loop generates a
	// fresh leaf key -- so the timing specs below would be waiting on keygen
	// inside Gomega's one-second default, and would be slowest under -race,
	// which is how this repo runs them. No assertion here is about the key
	// algorithm.
	fastCA := func() *ca.CA {
		GinkgoHelper()
		c, _ := newRefresherTestCA()
		c.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		return c
	}

	BeforeEach(func() {
		mu.Lock()
		loads = 0
		mu.Unlock()
	})

	It("is not started when no managed certificates are configured", func() {
		// The mechanism is dormant by default: a CA that configures none runs
		// exactly as it did before, with no extra goroutine.
		Expect(jobNames(&serverConfig{})).NotTo(ContainElement(jobManagedCerts))
	})

	It("is started when there is something to keep alive", func() {
		c := fastCA()
		c.ManagedCerts = []ca.ManagedCert{managed("managed.test")}

		var names []string
		for _, job := range backgroundJobs(&serverConfig{}, c) {
			names = append(names, job.name)
		}
		Expect(names).To(ContainElement(jobManagedCerts))
	})

	It("reconciles once at startup, before the first tick", func() {
		// On a fresh deployment nothing is in the store yet, and waiting a full
		// interval to issue would mean waiting an interval for whatever depends
		// on that certificate.
		c := fastCA()
		c.ManagedCerts = []ca.ManagedCert{managed("managed.test")}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			// An interval far longer than this spec lives, so a pass can only
			// be the startup one.
			runManagedCertReconciler(ctx, c, time.Hour)
		}()

		Eventually(func() int {
			mu.Lock()
			defer mu.Unlock()
			return loads
		}, 5*time.Second, 10*time.Millisecond).Should(Equal(1))

		cancel()
		Eventually(done, 5*time.Second).Should(BeClosed())
	})

	It("keeps reconciling on the timer", func() {
		c := fastCA()
		c.ManagedCerts = []ca.ManagedCert{managed("managed.test")}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(done)
			runManagedCertReconciler(ctx, c, 10*time.Millisecond)
		}()

		// More than one pass is the whole claim: renewal is time-driven, so
		// this loop must not be a one-shot at startup.
		Eventually(func() int {
			mu.Lock()
			defer mu.Unlock()
			return loads
		}, 5*time.Second, 10*time.Millisecond).Should(BeNumerically(">", 2))

		cancel()
		Eventually(done, 5*time.Second).Should(BeClosed())
	})

	It("keeps going when an entry fails, and reports what it managed", func() {
		// Entries are independent: one unreachable store must not stop every
		// other managed certificate from renewing, and must not stop the loop.
		//
		// The surviving entry's store SUCCEEDS here, deliberately. With both
		// entries rigged to fail the pass cannot issue anything, so an assertion
		// that `issued` is zero holds under every mutation of the loop -- it
		// cannot tell "stopped after the first failure" from "continued, and the
		// second also failed". Letting the second succeed is what makes the
		// count falsifiable, and it is the only spec that constructs the
		// mixed outcome ReconcileManaged documents: a non-zero issued count
		// returned alongside an error.
		c := fastCA()
		failing := managed("broken.test")
		failing.Load = func(context.Context) ([]byte, []byte, error) {
			return nil, nil, context.DeadlineExceeded
		}
		working := managed("managed.test")
		working.Save = func(context.Context, []byte, []byte) error { return nil }
		c.ManagedCerts = []ca.ManagedCert{failing, working}

		issued, err := c.ReconcileManaged(context.Background())
		Expect(err).To(HaveOccurred(), "the failure must be reported, not swallowed")
		Expect(issued).To(Equal(1),
			"the entry after the failing one must still have been issued, and counted")

		mu.Lock()
		defer mu.Unlock()
		Expect(loads).To(Equal(1),
			"the entry after the failing one must still have been attempted")
	})
})

var _ = Describe("The leaf backdate and reconcile interval settings", func() {
	BeforeEach(clearServerEnv)
	AfterEach(clearServerEnv)

	It("defaults the backdate to five minutes", func() {
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.leafBackdate()).To(Equal(defaultLeafBackdate))
		Expect(cfg.leafBackdate()).To(Equal(5*time.Minute),
			"the shipped default is a clock-skew tolerance, not a margin for a broken fleet")
	})

	It("takes a configured backdate", func() {
		setEnv("PUPPET_CA_LEAF_BACKDATE_SEC", "3600")
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.leafBackdate()).To(Equal(time.Hour))
	})

	It("refuses a negative backdate rather than clamping it", func() {
		// Clamping would hand back the default and leave the operator with a
		// typo they never hear about. A negative backdate issues certificates
		// that are not yet valid, fleet-wide, with nothing in the CA's logs
		// saying why -- so it has to fail at startup.
		setEnv("PUPPET_CA_LEAF_BACKDATE_SEC", "-60")
		_, err := loadServerConfig("")
		Expect(err).To(MatchError(ContainSubstring("leaf_backdate_sec must not be negative")))
	})

	It("reaches the CA, which is the step whose absence is silent", func() {
		// applyCAConfig is where a setting stops being configuration and starts
		// being behaviour. Deleting that one line leaves every other spec here
		// green while an operator's leaf_backdate_sec does nothing at all.
		setEnv("PUPPET_CA_LEAF_BACKDATE_SEC", "7200")
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())

		myCA := &ca.CA{}
		Expect(applyCAConfig(myCA, cfg)).To(Succeed())
		Expect(myCA.LeafBackdate).To(Equal(2 * time.Hour))
	})

	It("is read from the config file, not only the environment", func() {
		// Both keys are published as config-file keys in docs/configuration.md,
		// and a typo in either struct tag would leave the documented key inert
		// with every environment-driven spec still green.
		cfg, err := loadServerConfig(writeTempConfig(
			"leaf_backdate_sec: 3600\nmanaged_cert_interval_sec: 60\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.leafBackdate()).To(Equal(time.Hour))
		Expect(cfg.managedCertInterval()).To(Equal(time.Minute))
	})

	It("lets the environment outrank the config file", func() {
		setEnv("PUPPET_CA_LEAF_BACKDATE_SEC", "900")
		cfg, err := loadServerConfig(writeTempConfig("leaf_backdate_sec: 3600\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.leafBackdate()).To(Equal(15*time.Minute),
			"the documented precedence is environment over file")
	})

	It("refuses a backdate beyond the ceiling", func() {
		// The ceiling is not only about absurd values. time.Duration(n) *
		// time.Second multiplies by a billion in int64 nanoseconds, so a
		// mistyped extra few zeroes wraps, and a wrapped product that lands
		// positive passes every `> 0` guard downstream and reaches issuance.
		setEnv("PUPPET_CA_LEAF_BACKDATE_SEC", "31536000")
		_, err := loadServerConfig("")
		Expect(err).To(MatchError(ContainSubstring("leaf_backdate_sec must not exceed")))

		clearServerEnv()
		setEnv("PUPPET_CA_LEAF_BACKDATE_SEC", "99999999999")
		_, err = loadServerConfig("")
		Expect(err).To(MatchError(ContainSubstring("leaf_backdate_sec must not exceed")),
			"a value large enough to wrap the nanosecond multiply must be refused before it can")
	})

	It("defaults the reconcile interval, and takes a configured one", func() {
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.managedCertInterval()).To(Equal(defaultManagedCertInterval))
		// time.NewTicker panics on a non-positive duration and this job runs for
		// the life of the process, so the default has to be positive on its own
		// terms rather than merely equal to a constant that could become zero.
		Expect(cfg.managedCertInterval()).To(BeNumerically(">", 0))

		clearServerEnv()
		setEnv("PUPPET_CA_MANAGED_CERT_INTERVAL_SEC", "60")
		cfg, err = loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.managedCertInterval()).To(Equal(time.Minute))
	})
})
