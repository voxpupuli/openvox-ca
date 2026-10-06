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
	"log/slog"
	"strconv"
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
		// Deferred, not called at the end: a failing Eventually below would
		// otherwise return without cancelling, leaking a goroutine that keeps
		// incrementing the shared counter into whichever spec runs next. The
		// counter is reset per spec, which does not help against a writer that
		// outlives the spec that started it.
		DeferCleanup(cancel)
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
		// Deferred, not called at the end: a failing Eventually below would
		// otherwise return without cancelling, leaking a goroutine that keeps
		// incrementing the shared counter into whichever spec runs next. The
		// counter is reset per spec, which does not help against a writer that
		// outlives the spec that started it.
		DeferCleanup(cancel)
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

	// reconcileManagedOnce's three arms. This is the cmd layer's own behaviour --
	// how a pass's outcome is reported -- and the only part of the loop that is
	// not already pinned in internal/ca.
	//
	// The spec that used to sit here drove c.ReconcileManaged directly and
	// asserted the issued count and the keep-going contract. Those are
	// internal/ca's, and "ReconcileManaged over several entries" in
	// managedcert_reconcile_test.go now pins them against the real decision
	// path, including the mixed outcome of a non-zero count alongside an error.
	// Re-testing them from here asserted the same thing one layer further from
	// the code, which is how a package ends up with coverage that moves when an
	// unrelated layer is refactored.
	DescribeTable("reports a pass at the level its outcome deserves",
		func(rig func(*ca.CA), wantLevel, wantText string) {
			c := fastCA()
			rig(c)

			buf := &bytes.Buffer{}
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			})))
			DeferCleanup(func() { slog.SetDefault(prev) })

			reconcileManagedOnce(context.Background(), c)

			Expect(buf.String()).To(ContainSubstring("level=" + wantLevel))
			Expect(buf.String()).To(ContainSubstring(wantText))
		},
		Entry("a failing entry is a warning, carrying what still got issued",
			func(c *ca.CA) {
				failing := managed("broken.test")
				failing.Load = func(context.Context) ([]byte, []byte, error) {
					return nil, nil, context.DeadlineExceeded
				}
				working := managed("managed.test")
				working.Save = func(context.Context, []byte, []byte) error { return nil }
				c.ManagedCerts = []ca.ManagedCert{failing, working}
			},
			"WARN", "Managed-certificate reconcile pass had failures"),
		Entry("an issuance is info",
			func(c *ca.CA) {
				working := managed("managed.test")
				working.Save = func(context.Context, []byte, []byte) error { return nil }
				c.ManagedCerts = []ca.ManagedCert{working}
			},
			"INFO", "Managed certificates issued"),
		Entry("nothing due is debug, not silence",
			func(c *ca.CA) { c.ManagedCerts = nil },
			"DEBUG", "nothing due"),
	)
})

var _ = Describe("The leaf backdate and reconcile interval settings", func() {
	BeforeEach(clearServerEnv)
	AfterEach(clearServerEnv)

	It("defaults the backdate to five minutes", func() {
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.leafBackdate()).To(Equal(ca.DefaultLeafBackdate))
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

	It("refuses a reconcile interval beyond the ceiling", func() {
		// Worse than the backdate's overflow, which is why it is bounded too: a
		// wrapped product that lands non-positive reaches time.NewTicker, which
		// panics inside the reconcile goroutine with nothing to recover it --
		// a config typo taking the whole server down.
		setEnv("PUPPET_CA_MANAGED_CERT_INTERVAL_SEC", "31536000")
		_, err := loadServerConfig("")
		Expect(err).To(MatchError(ContainSubstring("managed_cert_interval_sec must not exceed")))

		clearServerEnv()
		setEnv("PUPPET_CA_MANAGED_CERT_INTERVAL_SEC", "99999999999")
		_, err = loadServerConfig("")
		Expect(err).To(MatchError(ContainSubstring("managed_cert_interval_sec must not exceed")),
			"a value large enough to wrap the nanosecond multiply must be refused before it can")
	})

	It("refuses a negative reconcile interval rather than ignoring it", func() {
		// Without the refusal a negative value fell through
		// managedCertInterval's own `> 0` to the default, which is safe but
		// silent: the operator's typo produced a working server on a value it
		// had discarded. The environment path is covered by its own spec below,
		// since a setting refused from YAML and defaulted from the environment
		// would be its own trap.
		_, err := loadServerConfig(writeTempConfig("managed_cert_interval_sec: -1\n"))
		Expect(err).To(MatchError(ContainSubstring("managed_cert_interval_sec must not be negative")))
	})

	It("refuses a negative reconcile interval from the environment too", func() {
		// The half the file-path spec cannot reach: applyServerEnv must not gate
		// this variable on n > 0, or a negative value is discarded there and the
		// server starts on the default -- the asymmetry the refusal exists to
		// end, in the one path the refusal cannot see.
		setEnv("PUPPET_CA_MANAGED_CERT_INTERVAL_SEC", "-1")
		_, err := loadServerConfig("")
		Expect(err).To(MatchError(ContainSubstring("managed_cert_interval_sec must not be negative")))
	})

	It("still defaults the reconcile interval when it is absent or zero", func() {
		// The other half, so the refusal above cannot be satisfied by refusing
		// zero as well: zero means unset and must keep taking the default.
		cfg, err := loadServerConfig(writeTempConfig("managed_cert_interval_sec: 0\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.managedCertInterval()).To(Equal(defaultManagedCertInterval))
	})

	It("accepts exactly the backdate ceiling, and refuses one second more", func() {
		// The boundary itself, which the specs above leave free: they use
		// 31536000 and 99999999999 against a 2592000 ceiling, so both a strict
		// `>` and an accidental `>=` reject them identically. Only the exact
		// value separates the two, and a `>=` would refuse the documented
		// 30-day maximum -- a limit an operator can read and set.
		setEnv("PUPPET_CA_LEAF_BACKDATE_SEC", strconv.Itoa(maxLeafBackdateSec))
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "the ceiling is a permitted value, not the first refused one")
		Expect(cfg.leafBackdate()).To(Equal(30 * 24 * time.Hour))

		clearServerEnv()
		setEnv("PUPPET_CA_LEAF_BACKDATE_SEC", strconv.Itoa(maxLeafBackdateSec+1))
		_, err = loadServerConfig("")
		Expect(err).To(MatchError(ContainSubstring("leaf_backdate_sec must not exceed")),
			"one past the ceiling must be the first value refused")
	})

	It("accepts exactly the reconcile-interval ceiling, and refuses one second more", func() {
		setEnv("PUPPET_CA_MANAGED_CERT_INTERVAL_SEC", strconv.Itoa(maxManagedCertIntervalSec))
		cfg, err := loadServerConfig("")
		Expect(err).NotTo(HaveOccurred(), "the ceiling is a permitted value, not the first refused one")
		Expect(cfg.managedCertInterval()).To(Equal(30 * 24 * time.Hour))

		clearServerEnv()
		setEnv("PUPPET_CA_MANAGED_CERT_INTERVAL_SEC", strconv.Itoa(maxManagedCertIntervalSec+1))
		_, err = loadServerConfig("")
		Expect(err).To(MatchError(ContainSubstring("managed_cert_interval_sec must not exceed")),
			"one past the ceiling must be the first value refused")
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
