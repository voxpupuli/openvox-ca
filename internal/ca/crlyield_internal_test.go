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

// White-box because a sweep step lasts sweepStepBudget, fifteen seconds, and a
// spec that has to watch one end cannot wait that long: c.sweep is the seam.
// The structural spec at the bottom also needs lockNameCRL, for the reason
// lockorder_test.go gives.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// sweepStore is a SQLite store that records every acquisition of the CRL lock
// and can stall the next prune or the next CRL write until its caller's
// deadline, modelling a backend that is slow but not broken: the case #347 is
// about, where a sweep holds the CRL lock for its whole budget.
//
// SQLite takes the same-host tier, so the in-process half of every acquisition
// is the mutex no deadline ends, as it is on every single-node deployment.
type sweepStore struct {
	*storage.SQLBackend

	mu sync.Mutex
	// events is the acquisition log: "begin" when an acquisition of the CRL
	// lock starts, "acquired" when it is granted, "released" when it is let go,
	// and whatever markers a spec appends from inside a critical section.
	events []string
	// stallPrune makes the next PruneEntries prune normally and then hold on
	// until its context ends, returning what it removed with ctx's error: a
	// batched prune (etcd) that ran out of time part-way.
	stallPrune bool
	// stalled is closed when that prune starts holding on.
	stalled chan struct{}
	// pruneBudget is how long the stalled prune's context had left when it
	// started holding on: the share of the step the prune was given.
	pruneBudget time.Duration
	// replayKeep makes every PruneEntries call first run keep over the whole
	// inventory and remove nothing, as an attempt that lost a race with an
	// append does before the backend retries it.
	replayKeep bool
	// stallCRLPut makes the next write of the CRL hold on until its context
	// ends and then fail.
	stallCRLPut bool
	// putStalled is closed when that write starts holding on, and putBudget
	// is how long its context had left when it did.
	putStalled chan struct{}
	putBudget  time.Duration
	// failCRLPut makes every write of the CRL fail at once.
	failCRLPut bool
	// failSupersededPut makes every write of the pending-supersession list
	// fail at once.
	failSupersededPut bool
	// pruneOutlivesShare makes the next PruneEntries hold on until its context
	// ends and then remove nothing: an inventory too large to prune within the
	// step's share.
	pruneOutlivesShare bool
	// pruneOwnDeadline makes the next PruneEntries fail at once with a
	// deadline of the backend's own, such as a SQL per-call timeout, while the
	// step's share still has time left.
	pruneOwnDeadline bool
	// stallSupersededPut makes the next write of the pending-supersession
	// list hold on until its context ends and then fail; supersededStalled
	// is closed when it starts holding on.
	stallSupersededPut bool
	supersededStalled  chan struct{}
	// stallSupersededGet makes the next read of the pending-supersession list
	// hold on until its context ends.
	stallSupersededGet bool
	// pruneKeepsAll makes every PruneEntries run keep over the inventory and
	// remove nothing, as a prune does when its selection finds nothing it may
	// take after all.
	pruneKeepsAll bool
}

func (s *sweepStore) log(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func (s *sweepStore) logged() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

func (s *sweepStore) count(event string) int {
	n := 0
	for _, e := range s.logged() {
		if e == event {
			n++
		}
	}
	return n
}

func (s *sweepStore) AcquireSameHostLock(ctx context.Context, name string) (storage.Unlocker, error) {
	if name != lockNameCRL {
		return s.SQLBackend.AcquireSameHostLock(ctx, name)
	}
	s.log("begin")
	ul, err := s.SQLBackend.AcquireSameHostLock(ctx, name)
	if err != nil {
		return nil, err
	}
	s.log("acquired")
	return loggedUnlocker{Unlocker: ul, s: s}, nil
}

// loggedUnlocker logs the release of the CRL lock in its store's event log.
type loggedUnlocker struct {
	storage.Unlocker
	s *sweepStore
}

func (u loggedUnlocker) Unlock() error {
	err := u.Unlocker.Unlock()
	u.s.log("released")
	return err
}

func (s *sweepStore) PruneEntries(ctx context.Context, keep func(storage.InventoryEntry) bool,
	advanceHead func(prev []byte, e storage.InventoryEntry) []byte) ([]storage.InventoryEntry, error) {
	s.mu.Lock()
	replay, outlive, ownDeadline, keepAll := s.replayKeep, s.pruneOutlivesShare, s.pruneOwnDeadline, s.pruneKeepsAll
	s.pruneOutlivesShare, s.pruneOwnDeadline = false, false
	s.mu.Unlock()
	switch {
	case outlive:
		<-ctx.Done()
		return nil, ctx.Err()
	case ownDeadline:
		return nil, fmt.Errorf("simulated per-call timeout: %w", context.DeadlineExceeded)
	case keepAll:
		_, err := s.SQLBackend.PruneEntries(ctx, func(e storage.InventoryEntry) bool {
			keep(e)
			return true
		}, advanceHead)
		return nil, err
	}
	if replay {
		if _, err := s.SQLBackend.PruneEntries(ctx, func(e storage.InventoryEntry) bool {
			keep(e)
			return true
		}, advanceHead); err != nil {
			return nil, err
		}
	}
	removed, err := s.SQLBackend.PruneEntries(ctx, keep, advanceHead)
	s.mu.Lock()
	stall := s.stallPrune
	s.stallPrune = false
	s.mu.Unlock()
	if !stall || err != nil {
		return removed, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		s.mu.Lock()
		s.pruneBudget = time.Until(deadline)
		s.mu.Unlock()
	}
	close(s.stalled)
	<-ctx.Done()
	return removed, ctx.Err()
}

func (s *sweepStore) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeySuperseded {
		s.mu.Lock()
		stall := s.stallSupersededGet
		s.stallSupersededGet = false
		s.mu.Unlock()
		if stall {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	return s.SQLBackend.Get(ctx, key)
}

func (s *sweepStore) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if key == storage.KeySuperseded {
		s.mu.Lock()
		fail, stall := s.failSupersededPut, s.stallSupersededPut
		s.stallSupersededPut = false
		s.mu.Unlock()
		if fail {
			return errors.New("simulated pending-list write failure")
		}
		if stall {
			close(s.supersededStalled)
			<-ctx.Done()
			return ctx.Err()
		}
	}
	if key == storage.KeyCRL {
		s.mu.Lock()
		stall, fail := s.stallCRLPut, s.failCRLPut
		s.stallCRLPut = false
		s.mu.Unlock()
		if fail {
			return errors.New("simulated CRL write failure")
		}
		if stall {
			if deadline, ok := ctx.Deadline(); ok {
				s.mu.Lock()
				s.putBudget = time.Until(deadline)
				s.mu.Unlock()
			}
			if s.putStalled != nil {
				close(s.putStalled)
			}
			<-ctx.Done()
			return ctx.Err()
		}
	}
	return s.SQLBackend.Put(ctx, key, data, kind)
}

var _ = Describe("Background sweeps on the CRL lock (#347)", func() {
	var (
		ctx    context.Context
		dir    string
		backed *sweepStore
		store  *storage.StorageService
		myCA   *CA
	)

	BeforeEach(func() {
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		inner, err := storage.NewSQLBackend(storage.SQLConfig{
			Dialect: storage.SQLitePure,
			DSN:     "file:" + filepath.Join(dir, "ca.db"),
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = inner.Close() })
		Expect(inner.EnsureReady(ctx)).To(Succeed())
		backed = &sweepStore{SQLBackend: inner, stalled: make(chan struct{})}
		store = storage.NewWithBackend(backed, filepath.Join(dir, "private"))
		Expect(store.EnsureDirs(ctx)).To(Succeed())

		myCA = New(store, AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	// issue signs a live certificate for subject and returns its serial.
	issue := func(subject string) *big.Int {
		GinkgoHelper()
		res, err := myCA.Generate(ctx, subject, nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		crt, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return crt.SerialNumber
	}

	// seedExpired stores a certificate for subject that expired a year ago,
	// with its inventory entry, and revokes it so its serial is on the CRL.
	// The signing path cannot produce one, so it is signed here directly.
	seedExpired := func(subject string, serial int64) *big.Int {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		notAfter := time.Now().Add(-365 * 24 * time.Hour).UTC().Truncate(time.Second)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: subject},
			NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
			NotAfter:     notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, myCA.CACert, &key.PublicKey, myCA.CAKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCert(ctx, subject,
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))).To(Succeed())
		Expect(store.AppendInventory(ctx, fmt.Sprintf("%s %s %s /%s", tmpl.SerialNumber.Text(16),
			tmpl.NotBefore.Format(storage.InventoryTimeFormat), notAfter.Format(storage.InventoryTimeFormat),
			subject))).To(Succeed())
		Expect(myCA.Revoke(ctx, subject)).To(Succeed())
		return tmpl.SerialNumber
	}

	revoked := func(serial *big.Int) bool {
		GinkgoHelper()
		r, err := myCA.IsRevokedSerial(ctx, serial)
		Expect(err).NotTo(HaveOccurred())
		return r
	}

	inInventory := func(subject string) bool {
		GinkgoHelper()
		_, err := store.LatestSerialForSubject(ctx, subject)
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		Expect(err).NotTo(HaveOccurred())
		return true
	}

	// The property itself. The step stalls first in its prune and then in its
	// CRL write, so it holds the lock for every moment of its budget, and the
	// revocation arrives once it holds it. The revocation has to commit as
	// soon as the step's budget runs out. Before #347 the cleanup's CRL write
	// ran on a detached LockTimeout/2 of its own, so a revocation queued here
	// waited a further thirty seconds for it, and on the process-local mutex,
	// which its own deadline does not end.
	It("commits a revocation that arrives during a slow step once that step's budget runs out", func() {
		const step = 2 * time.Second
		myCA.sweep = sweepTuning{stepBudget: step, stepPause: 10 * time.Millisecond}
		seedExpired("old.test", 0xEE01)
		victim := issue("victim.test")
		backed.mu.Lock()
		backed.stallPrune, backed.stallCRLPut = true, true
		backed.mu.Unlock()

		sweepDone := make(chan error, 1)
		go func() {
			_, err := myCA.CleanupExpiredCerts(ctx, 0)
			sweepDone <- err
		}()
		Eventually(backed.stalled).Should(BeClosed(), "the sweep never reached its prune")

		revokeDone := make(chan error, 1)
		go func() { revokeDone <- myCA.Revoke(ctx, "victim.test") }()
		Eventually(revokeDone, step+step/2).Should(Receive(BeNil()),
			"the revocation waited behind the sweep for longer than one step's budget")
		Expect(revoked(victim)).To(BeTrue())

		Eventually(sweepDone, step).Should(Receive(MatchError(context.DeadlineExceeded)),
			"the stalled step must end in its deadline")
	})

	// What each step owes the inventory and the CRL, and that the split of its
	// budget is what pays for it: the prune runs out of its share, and the CRL
	// and blob cleanup for what it durably removed still runs, on the rest.
	It("cleans up after what a prune removed even when the prune used up its share of the step", func() {
		myCA.sweep = sweepTuning{stepBudget: time.Second, stepPause: 10 * time.Millisecond}
		serial := seedExpired("old.test", 0xEE02)
		Expect(revoked(serial)).To(BeTrue(), "precondition")
		backed.mu.Lock()
		backed.stallPrune = true
		backed.mu.Unlock()

		removed, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).To(MatchError(context.DeadlineExceeded), "the prune's deadline error must surface")
		Expect(err.Error()).NotTo(ContainSubstring("share of a sweep step"),
			"a prune that removed something did fit, in part")
		Expect(removed).To(Equal(1))
		Expect(inInventory("old.test")).To(BeFalse())
		stored, err := myCA.readStoredCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored.own.RevokedCertificateEntries).To(BeEmpty(),
			"the CRL entry must be dropped in what is left of the step")
		Expect(store.HasCert(ctx, "old.test")).To(BeFalse(),
			"the stored certificate must be deleted in what is left of the step")
	})

	// A prune reads the whole inventory however few entries the step takes,
	// so one that runs out of its share and removes nothing will do so on
	// every pass. The error has to say that, not just "deadline exceeded".
	It("names the step's share when a prune that removed nothing runs out of it", func() {
		myCA.sweep = sweepTuning{stepBudget: 400 * time.Millisecond, stepPause: 10 * time.Millisecond}
		seedExpired("old.test", 0xEE05)
		backed.mu.Lock()
		backed.pruneOutlivesShare = true
		backed.mu.Unlock()

		removed, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(err).To(MatchError(ContainSubstring("the inventory prune ran out of its share of a sweep step")))
		Expect(removed).To(BeZero())
		Expect(inInventory("old.test")).To(BeTrue())
	})

	// The same error from the backend itself is not the step's ceiling, and
	// must not be blamed on it.
	It("leaves a deadline the backend raised itself unexplained by the step's share", func() {
		myCA.sweep = sweepTuning{stepBudget: 10 * time.Second, stepPause: 10 * time.Millisecond}
		seedExpired("old.test", 0xEE06)
		backed.mu.Lock()
		backed.pruneOwnDeadline = true
		backed.mu.Unlock()

		_, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(err.Error()).NotTo(ContainSubstring("share of a sweep step"))
	})

	It("cleans up a backlog in steps of at most sweepStepEntries, one CRL lock acquisition each", func() {
		myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Millisecond}
		for i := range 5 {
			seedExpired(fmt.Sprintf("old%d.test", i), int64(0xEE10+i))
		}
		before := backed.count("acquired")

		removed, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(5))
		for i := range 5 {
			Expect(inInventory(fmt.Sprintf("old%d.test", i))).To(BeFalse())
		}
		stored, err := myCA.readStoredCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored.own.RevokedCertificateEntries).To(BeEmpty())
		Expect(backed.count("acquired")-before).To(Equal(3),
			"five entries two at a time is three steps, each its own acquisition")
	})

	// A step knows more remain only by meeting one past its cap, so a backlog
	// that fills its last step exactly ends there rather than taking an empty
	// step that would read the whole inventory for nothing.
	It("cleans up an exact multiple of sweepStepEntries without an empty extra step", func() {
		myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Millisecond}
		for i := range 4 {
			seedExpired(fmt.Sprintf("old%d.test", i), int64(0xEE18+i))
		}
		before := backed.count("acquired")

		removed, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(4))
		Expect(backed.count("acquired")-before).To(Equal(2), "four entries two at a time is two steps")
	})

	// A step that saw more but removed nothing would see the same again: the
	// pass has to end rather than repeat it until its context runs out.
	It("ends the pass when a step removes nothing although more remain", func() {
		myCA.sweep = sweepTuning{stepEntries: 1, stepPause: time.Millisecond}
		for i := range 3 {
			seedExpired(fmt.Sprintf("old%d.test", i), int64(0xEE1C+i))
		}
		backed.mu.Lock()
		backed.pruneKeepsAll = true
		backed.mu.Unlock()
		before := backed.count("acquired")
		passCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		removed, err := myCA.CleanupExpiredCerts(passCtx, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(BeZero())
		Expect(backed.count("acquired") - before).To(Equal(1))
	})

	// Every step's prune reads the whole inventory, so an entry the cleanup
	// cannot parse is met once a step. It is worth one warning a pass, and the
	// pass reports its progress as it goes.
	It("warns about an unparseable entry once a pass, and logs each step", func() {
		myCA.sweep = sweepTuning{stepEntries: 1, stepPause: time.Millisecond}
		for i := range 3 {
			seedExpired(fmt.Sprintf("old%d.test", i), int64(0xEE60+i))
		}
		Expect(store.AppendInventory(ctx, "EE6F not-a-time not-a-time /bad.test")).To(Succeed())
		logs := captureLogs()

		removed, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(3))
		Expect(strings.Count(logs.String(), "unparseable NotAfter")).To(Equal(1),
			"one warning for the pass, not one a step")
		Expect(logs.String()).To(ContainSubstring("Expired-certificate cleanup: step done, more remain"))
	})

	// Every structured backend calls the prune predicate again when it retries
	// an attempt that lost a race with an append. A predicate that counted its
	// way to the step's cap would stand at the cap on the retry, keep every
	// entry, and end the pass with nothing removed and no error.
	It("still prunes a full step when the backend retries the prune", func() {
		myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Millisecond}
		for i := range 5 {
			seedExpired(fmt.Sprintf("old%d.test", i), int64(0xEE30+i))
		}
		backed.mu.Lock()
		backed.replayKeep = true
		backed.mu.Unlock()

		removed, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(5), "a retried prune must select the same entries again, not none")
		for i := range 5 {
			Expect(inInventory(fmt.Sprintf("old%d.test", i))).To(BeFalse())
		}
	})

	// A step's hold is what a waiting revocation counts on, and it is what the
	// post-prune cleanup needs time inside. A step that spent most of its
	// budget waiting for the lock must still get the whole budget once it
	// holds it, or the cleanup after a slow prune runs on a sliver.
	It("gives a step that waited for the lock its whole budget once it holds it", func() {
		const step = 2 * time.Second
		myCA.sweep = sweepTuning{stepBudget: step, stepPause: 10 * time.Millisecond}
		seedExpired("old.test", 0xEE40)
		backed.mu.Lock()
		backed.stallPrune = true
		backed.mu.Unlock()

		release := make(chan struct{})
		held := make(chan struct{})
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
				close(held)
				<-release
				return nil
			})
		}()
		Eventually(held).Should(BeClosed())

		sweepDone := make(chan error, 1)
		go func() {
			_, err := myCA.CleanupExpiredCerts(ctx, 0)
			sweepDone <- err
		}()
		// Most of the step's budget, spent waiting.
		time.Sleep(step * 3 / 4)
		close(release)
		Eventually(holderDone).Should(Receive(BeNil()))
		Eventually(backed.stalled, step).Should(BeClosed())
		Eventually(sweepDone, 2*step).Should(Receive(MatchError(context.DeadlineExceeded)))

		backed.mu.Lock()
		got := backed.pruneBudget
		backed.mu.Unlock()
		Expect(got).To(BeNumerically(">", step/2*8/10),
			"the prune's share was cut by the time the step spent waiting for the lock")
		Expect(got).To(BeNumerically("<=", step/2),
			"the prune's share is half the hold, so a larger one means the hold outgrew sweepStepBudget")
		Expect(inInventory("old.test")).To(BeFalse())
		stored, err := myCA.readStoredCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored.own.RevokedCertificateEntries).To(BeEmpty())
		Expect(store.HasCert(ctx, "old.test")).To(BeFalse())
	})

	// The refresh is one step, and the same split applies to it: a refresh
	// that waited most of its budget for the lock must still have the whole
	// budget for its re-sign once it holds it, or it fails in the lock in a way
	// that reads as a storage fault rather than as having stood aside.
	It("gives a CRL refresh that waited for the lock its whole budget once it holds it", func() {
		const step = 2 * time.Second
		myCA.sweep = sweepTuning{stepBudget: step}
		backed.mu.Lock()
		backed.stallCRLPut = true
		backed.putStalled = make(chan struct{})
		backed.mu.Unlock()

		release := make(chan struct{})
		held := make(chan struct{})
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
				close(held)
				<-release
				return nil
			})
		}()
		Eventually(held).Should(BeClosed())

		refreshDone := make(chan error, 1)
		go func() {
			// A refresh window longer than any CRL's life, so it re-signs.
			_, err := myCA.RefreshCRLIfDue(ctx, 1000*time.Hour)
			refreshDone <- err
		}()
		time.Sleep(step * 3 / 4)
		close(release)
		Eventually(holderDone).Should(Receive(BeNil()))
		Eventually(backed.putStalled, step).Should(BeClosed())
		Eventually(refreshDone, 2*step).Should(Receive(MatchError(context.DeadlineExceeded)))

		backed.mu.Lock()
		got := backed.putBudget
		backed.mu.Unlock()
		Expect(got).To(BeNumerically(">", step*8/10),
			"the re-sign's budget was cut by the time the refresh spent waiting for the lock")
		Expect(got).To(BeNumerically("<=", step),
			"the hold outgrew sweepStepBudget")
	})

	// The wait for the lock protects no write, so a shutdown must end it. A
	// step whose wait ran on a detached context kept the serve command's
	// shutdown waiting for a whole step budget behind a lock it never got.
	It("gives up waiting for the lock when the pass's context ends", func() {
		myCA.sweep = sweepTuning{stepBudget: 10 * time.Second, stepPause: 10 * time.Millisecond}
		seedExpired("old.test", 0xEE41)

		release := make(chan struct{})
		held := make(chan struct{})
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
				close(held)
				<-release
				return nil
			})
		}()
		Eventually(held).Should(BeClosed())
		DeferCleanup(func() {
			close(release)
			Eventually(holderDone).Should(Receive(BeNil()))
		})

		failuresBefore := myCA.CRLUpdateFailures()
		passCtx, cancel := context.WithCancel(ctx)
		sweepDone := make(chan error, 1)
		go func() {
			_, err := myCA.CleanupExpiredCerts(passCtx, 0)
			sweepDone <- err
		}()
		Consistently(sweepDone, 100*time.Millisecond).ShouldNot(Receive())
		cancel()
		Eventually(sweepDone, 2*time.Second).Should(Receive(MatchError(context.Canceled)),
			"a step waiting for the lock must stop when the pass's context ends")
		Expect(inInventory("old.test")).To(BeTrue(), "nothing was pruned, so nothing was lost")
		Expect(myCA.CRLUpdateFailures()).To(Equal(failuresBefore),
			"a pass that a shutdown ends is not a failed pass")
	})

	// The chain refresh takes the lock through a closure of its own rather
	// than withCRLLockYielding, so it needs the same exemption pinned apart.
	It("does not count a crl_chain.file refresh whose wait a shutdown ended", func() {
		myCA.sweep = sweepTuning{stepBudget: 10 * time.Second, stepPause: 10 * time.Millisecond}
		path := filepath.Join(dir, "chain.pem")
		Expect(os.WriteFile(path, nil, 0o600)).To(Succeed())
		myCA.CRLChainFile = path

		release := make(chan struct{})
		held := make(chan struct{})
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
				close(held)
				<-release
				return nil
			})
		}()
		Eventually(held).Should(BeClosed())
		DeferCleanup(func() {
			close(release)
			Eventually(holderDone).Should(Receive(BeNil()))
		})

		failuresBefore := myCA.CRLUpdateFailures()
		passCtx, cancel := context.WithCancel(ctx)
		refreshDone := make(chan error, 1)
		go func() {
			_, err := myCA.RefreshCRLChainFile(passCtx)
			refreshDone <- err
		}()
		Consistently(refreshDone, 100*time.Millisecond).ShouldNot(Receive())
		cancel()
		Eventually(refreshDone, 2*time.Second).Should(Receive(MatchError(context.Canceled)))
		Expect(myCA.CRLUpdateFailures()).To(Equal(failuresBefore),
			"a pass that a shutdown ends is not a failed pass")
	})

	// A caller's deadline is not a shutdown either: a cleanup step whose wait
	// it ended is counted.
	It("counts a cleanup step whose pass's own deadline ran out while it waited", func() {
		myCA.sweep = sweepTuning{stepBudget: 10 * time.Second, stepPause: 10 * time.Millisecond}
		seedExpired("old.test", 0xEE43)

		release := make(chan struct{})
		held := make(chan struct{})
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
				close(held)
				<-release
				return nil
			})
		}()
		Eventually(held).Should(BeClosed())
		DeferCleanup(func() {
			close(release)
			Eventually(holderDone).Should(Receive(BeNil()))
		})

		failuresBefore := myCA.CRLUpdateFailures()
		passCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		_, err := myCA.CleanupExpiredCerts(passCtx, 0)
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(myCA.CRLUpdateFailures() - failuresBefore).To(Equal(uint64(1)))
	})

	// Its counterpart: a step that ran out of its own wait budget with the
	// pass still live is a re-sign that did not happen, and is counted.
	It("counts a cleanup step that could not take the lock within its budget", func() {
		myCA.sweep = sweepTuning{stepBudget: 300 * time.Millisecond, stepPause: 10 * time.Millisecond}
		seedExpired("old.test", 0xEE42)

		release := make(chan struct{})
		held := make(chan struct{})
		holderDone := make(chan error, 1)
		go func() {
			holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
				close(held)
				<-release
				return nil
			})
		}()
		Eventually(held).Should(BeClosed())
		DeferCleanup(func() {
			close(release)
			Eventually(holderDone).Should(Receive(BeNil()))
		})

		failuresBefore := myCA.CRLUpdateFailures()
		_, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).To(MatchError(context.DeadlineExceeded))
		Expect(myCA.CRLUpdateFailures() - failuresBefore).To(Equal(uint64(1)))
	})

	// The other half: once a step holds the lock, a shutdown must not cut it
	// off between the prune and the cleanup that has to follow it, or the
	// pruned serials' CRL entries and certificates are orphaned for good.
	It("finishes a step it holds when the pass's context ends mid-prune", func() {
		myCA.sweep = sweepTuning{stepBudget: 2 * time.Second, stepPause: 10 * time.Millisecond}
		serial := seedExpired("old.test", 0xEE42)
		Expect(revoked(serial)).To(BeTrue(), "precondition")
		backed.mu.Lock()
		backed.stallPrune = true
		backed.mu.Unlock()

		passCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		sweepDone := make(chan error, 1)
		go func() {
			_, err := myCA.CleanupExpiredCerts(passCtx, 0)
			sweepDone <- err
		}()
		Eventually(backed.stalled).Should(BeClosed())
		cancel()
		Eventually(sweepDone, 5*time.Second).Should(Receive(MatchError(context.DeadlineExceeded)),
			"the step ends on its own prune deadline, not on the pass's cancellation")

		Expect(inInventory("old.test")).To(BeFalse())
		stored, err := myCA.readStoredCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored.own.RevokedCertificateEntries).To(BeEmpty(),
			"the CRL entry must be dropped although the pass was cancelled")
		Expect(store.HasCert(ctx, "old.test")).To(BeFalse(),
			"the stored certificate must be deleted although the pass was cancelled")
	})

	It("stops between steps when the pass's context ends, keeping what earlier steps did", func() {
		myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Minute}
		for i := range 5 {
			seedExpired(fmt.Sprintf("old%d.test", i), int64(0xEE50+i))
		}
		released := backed.count("released")

		passCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		done := make(chan struct {
			n   int
			err error
		}, 1)
		go func() {
			n, err := myCA.CleanupExpiredCerts(passCtx, 0)
			done <- struct {
				n   int
				err error
			}{n, err}
		}()
		Eventually(func() int { return backed.count("released") }).Should(BeNumerically(">", released))
		cancel()
		var got struct {
			n   int
			err error
		}
		Eventually(done, 5*time.Second).Should(Receive(&got))
		Expect(got.err).To(MatchError(context.Canceled))
		Expect(got.n).To(Equal(2), "the first step's removals are reported")
		left := 0
		for i := range 5 {
			if inInventory(fmt.Sprintf("old%d.test", i)) {
				left++
			}
		}
		Expect(left).To(Equal(3), "the rest waits for the next pass")
	})

	Describe("ReconcileSuperseded", func() {
		// due records subject's serial as superseded with a window that has
		// already elapsed.
		due := func(subjects ...string) ([]*big.Int, []supersededEntry) {
			GinkgoHelper()
			var serials []*big.Int
			var entries []supersededEntry
			for i, s := range subjects {
				serial := issue(s)
				serials = append(serials, serial)
				entries = append(entries, supersededEntry{Serial: serialHexStr(serial), Subject: s,
					RevokeAt: time.Now().UTC().Add(-time.Duration(len(subjects)-i) * time.Minute)})
			}
			Expect(myCA.writeSuperseded(ctx, entries)).To(Succeed())
			return serials, entries
		}
		subjects := []string{"p0.test", "p1.test", "p2.test", "p3.test", "p4.test"}

		// The write-back is the step's own bookkeeping, and it needs both
		// halves of the step's budget design: a share the drain cannot spend,
		// and a context a shutdown cannot cancel. Here the drain's CRL write
		// stalls through its share and the pass is cancelled while it does.
		It("writes the list back after a stalled drain although the pass's context ended", func() {
			myCA.sweep = sweepTuning{stepBudget: 2 * time.Second, stepPause: 10 * time.Millisecond}
			_, entries := due(subjects[:2]...)
			backed.mu.Lock()
			backed.stallCRLPut = true
			backed.putStalled = make(chan struct{})
			backed.mu.Unlock()
			failuresBefore := myCA.SupersedeFailures()

			passCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := myCA.ReconcileSuperseded(passCtx)
				done <- err
			}()
			Eventually(backed.putStalled).Should(BeClosed())
			cancel()
			Eventually(done, 5*time.Second).Should(Receive(BeNil()),
				"the write-back must land on what is left of the step, whatever the pass's context says")
			Expect(myCA.SupersedeFailures()-failuresBefore).To(Equal(uint64(1)),
				"one count for the entries the stalled drain left behind, none for the write-back")
			left, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(left).To(ConsistOf(entries))
		})

		// The property for this sweep too, at its last phase: the write-back
		// stalls for the rest of the step, and a revocation that arrives then
		// commits once the step's budget runs out. A context detached inside
		// writeSuperseded or beneath it would escape the structural gate,
		// which reads only the closure; this is what catches it.
		It("commits a revocation that arrives while a step writes the list back, once the step's budget runs out", func() {
			const step = 2 * time.Second
			myCA.sweep = sweepTuning{stepBudget: step, stepPause: 10 * time.Millisecond}
			due(subjects[:1]...)
			victim := issue("victim.test")
			backed.mu.Lock()
			backed.stallSupersededPut = true
			backed.supersededStalled = make(chan struct{})
			backed.mu.Unlock()

			sweepDone := make(chan error, 1)
			go func() {
				_, err := myCA.ReconcileSuperseded(ctx)
				sweepDone <- err
			}()
			Eventually(backed.supersededStalled).Should(BeClosed(), "the sweep never reached its write-back")

			revokeDone := make(chan error, 1)
			go func() { revokeDone <- myCA.Revoke(ctx, "victim.test") }()
			Eventually(revokeDone, step+step/2).Should(Receive(BeNil()),
				"the revocation waited behind the sweep for longer than one step's budget")
			Expect(revoked(victim)).To(BeTrue())
			Eventually(sweepDone, step).Should(Receive(HaveOccurred()),
				"the stalled write-back must end with the step")
		})

		// A shutdown between steps fails at nothing: what the pass did not
		// reach is still listed. Counting it would make every restart during a
		// backlog look like the storage fault the counter's alert is for.
		It("stops between steps when the pass's context ends, without counting a failure", func() {
			myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Minute}
			serials, _ := due(subjects...)
			failuresBefore := myCA.SupersedeFailures()
			released := backed.count("released")

			passCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan struct {
				n   int
				err error
			}, 1)
			go func() {
				n, err := myCA.ReconcileSuperseded(passCtx)
				done <- struct {
					n   int
					err error
				}{n, err}
			}()
			Eventually(func() int { return backed.count("released") }).Should(BeNumerically(">", released))
			cancel()
			var got struct {
				n   int
				err error
			}
			Eventually(done, 5*time.Second).Should(Receive(&got))
			Expect(got.err).To(MatchError(context.Canceled))
			Expect(got.n).To(Equal(2))
			Expect(revoked(serials[0])).To(BeTrue(), "the oldest two went in the first step")
			Expect(revoked(serials[1])).To(BeTrue())
			left, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(left).To(HaveLen(3), "the rest waits for the next pass")
			Expect(myCA.SupersedeFailures()).To(Equal(failuresBefore),
				"a pass a shutdown ended is not a failed pass")
		})

		It("does not count a pass whose context ended while its step waited for the lock", func() {
			myCA.sweep = sweepTuning{stepBudget: 10 * time.Second, stepPause: 10 * time.Millisecond}
			due(subjects[:1]...)
			failuresBefore := myCA.SupersedeFailures()

			release := make(chan struct{})
			held := make(chan struct{})
			holderDone := make(chan error, 1)
			go func() {
				holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
					close(held)
					<-release
					return nil
				})
			}()
			Eventually(held).Should(BeClosed())
			DeferCleanup(func() {
				close(release)
				Eventually(holderDone).Should(Receive(BeNil()))
			})

			passCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() {
				_, err := myCA.ReconcileSuperseded(passCtx)
				done <- err
			}()
			Consistently(done, 100*time.Millisecond).ShouldNot(Receive())
			cancel()
			Eventually(done, 2*time.Second).Should(Receive(MatchError(context.Canceled)))
			Expect(myCA.SupersedeFailures()).To(Equal(failuresBefore),
				"a pass a shutdown ended while it waited is not a failed pass")
		})

		// The other direction: a step that failed for a reason of its own is a
		// failure even when the pass's context has also ended by the time it
		// returns. Here the drain stalls, the pass is cancelled, and then the
		// write-back fails outright.
		It("counts a real failure that lands after the pass's context ended", func() {
			myCA.sweep = sweepTuning{stepBudget: 2 * time.Second, stepPause: 10 * time.Millisecond}
			due(subjects[:1]...)
			backed.mu.Lock()
			backed.stallCRLPut = true
			backed.putStalled = make(chan struct{})
			backed.mu.Unlock()
			failuresBefore := myCA.SupersedeFailures()

			passCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := myCA.ReconcileSuperseded(passCtx)
				done <- err
			}()
			Eventually(backed.putStalled).Should(BeClosed())
			backed.mu.Lock()
			backed.failSupersededPut = true
			backed.mu.Unlock()
			cancel()
			Eventually(done, 5*time.Second).Should(Receive(MatchError(ContainSubstring("saving pending certificate revocations"))))
			Expect(myCA.SupersedeFailures()-failuresBefore).To(Equal(uint64(2)),
				"one count for the entry left behind and one for the write-back that failed")
		})

		// And a timeout of the step's own, with the pass's context alive, is a
		// failure too, though it is a context error: here the step's wait for
		// the lock runs out its budget behind a holder that never lets go.
		// A caller's deadline that runs out while a step waits is a pass that
		// did not finish, not a shutdown: only cancellation is exempt, as for
		// the other background jobs.
		It("counts a pass whose own deadline ran out while its step waited for the lock", func() {
			myCA.sweep = sweepTuning{stepBudget: 10 * time.Second, stepPause: 10 * time.Millisecond}
			due(subjects[:1]...)
			failuresBefore := myCA.SupersedeFailures()

			release := make(chan struct{})
			held := make(chan struct{})
			holderDone := make(chan error, 1)
			go func() {
				holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
					close(held)
					<-release
					return nil
				})
			}()
			Eventually(held).Should(BeClosed())
			DeferCleanup(func() {
				close(release)
				Eventually(holderDone).Should(Receive(BeNil()))
			})

			passCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
			defer cancel()
			_, err := myCA.ReconcileSuperseded(passCtx)
			Expect(err).To(MatchError(context.DeadlineExceeded))
			Expect(myCA.SupersedeFailures() - failuresBefore).To(Equal(uint64(1)))
		})

		// The read that rules the work out happens before any lock and so
		// outside any step: it has a budget of its own, or a hung store would
		// wedge the sweep until shutdown with nothing counted.
		It("bounds the read before the lock by a step's budget", func() {
			myCA.sweep = sweepTuning{stepBudget: 300 * time.Millisecond, stepPause: 10 * time.Millisecond}
			due(subjects[:1]...)
			backed.mu.Lock()
			backed.stallSupersededGet = true
			backed.mu.Unlock()

			done := make(chan int, 1)
			go func() {
				n, _ := myCA.ReconcileSuperseded(context.Background())
				done <- n
			}()
			Eventually(done, 2*time.Second).Should(Receive(Equal(1)),
				"the pass waited on the first read past its budget instead of going on to the locked path")
		})

		It("counts a step that could not take the lock within its budget while the pass's context is alive", func() {
			myCA.sweep = sweepTuning{stepBudget: 300 * time.Millisecond, stepPause: 10 * time.Millisecond}
			due(subjects[:1]...)
			failuresBefore := myCA.SupersedeFailures()
			crlBefore := myCA.CRLUpdateFailures()

			release := make(chan struct{})
			held := make(chan struct{})
			holderDone := make(chan error, 1)
			go func() {
				holderDone <- store.WithLock(ctx, lockNameCRL, func() error {
					close(held)
					<-release
					return nil
				})
			}()
			Eventually(held).Should(BeClosed())
			DeferCleanup(func() {
				close(release)
				Eventually(holderDone).Should(Receive(BeNil()))
			})

			done := make(chan error, 1)
			go func() {
				_, err := myCA.ReconcileSuperseded(ctx)
				done <- err
			}()
			Eventually(done, 2*time.Second).Should(Receive(MatchError(context.DeadlineExceeded)))
			Expect(myCA.SupersedeFailures()-failuresBefore).To(Equal(uint64(1)),
				"a pass that could not take the lock under a live context is a failed pass")
			Expect(myCA.CRLUpdateFailures()).To(Equal(crlBefore),
				"the sweep's lock failure is counted by supersedeFailures alone")
		})

		It("revokes a backlog in steps of at most sweepStepEntries, one CRL lock acquisition each", func() {
			myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Millisecond}
			serials, _ := due(subjects...)
			before := backed.count("acquired")
			logs := captureLogs()

			n, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(5))
			for _, s := range serials {
				Expect(revoked(s)).To(BeTrue())
			}
			left, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(left).To(BeEmpty())
			Expect(backed.count("acquired")-before).To(Equal(3),
				"five entries two at a time is three steps, each its own acquisition")
			Expect(logs.String()).To(ContainSubstring("Superseded-certificate revocation sweep: step done, more remain"))
		})

		// A step takes the oldest due entries, whatever order the list is
		// stored in, and puts everything else back: the due entries it left
		// for the next step and the ones not due yet alike. The list is stored
		// out of RevokeAt order, as it is in production once an operator has
		// changed the window, with a not-yet-due entry among the due ones.
		It("takes the oldest due entries first and keeps the rest, due or not", func() {
			myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Minute}
			a, n, b, c := issue("a.test"), issue("n.test"), issue("b.test"), issue("c.test")
			now := time.Now().UTC()
			notDue := supersededEntry{Serial: serialHexStr(n), Subject: "n.test", RevokeAt: now.Add(time.Hour)}
			lastDue := supersededEntry{Serial: serialHexStr(a), Subject: "a.test", RevokeAt: now.Add(-time.Minute)}
			Expect(myCA.writeSuperseded(ctx, []supersededEntry{
				lastDue,
				notDue,
				{Serial: serialHexStr(b), Subject: "b.test", RevokeAt: now.Add(-5 * time.Minute)},
				{Serial: serialHexStr(c), Subject: "c.test", RevokeAt: now.Add(-3 * time.Minute)},
			})).To(Succeed())
			released := backed.count("released")

			passCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := myCA.ReconcileSuperseded(passCtx)
				done <- err
			}()
			// Stop the pass in the pause after its first step.
			Eventually(func() int { return backed.count("released") }).Should(BeNumerically(">", released))
			cancel()
			Eventually(done, 5*time.Second).Should(Receive(MatchError(context.Canceled)))

			Expect(revoked(b)).To(BeTrue(), "the oldest due entry goes in the first step")
			Expect(revoked(c)).To(BeTrue(), "so does the next oldest")
			Expect(revoked(a)).To(BeFalse(), "the newest due entry waits for the next step")
			left, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(left).To(ConsistOf(lastDue, notDue),
				"the step must put back both the due entry it did not take and the one not due yet")

			_, err = myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked(a)).To(BeTrue())
			Expect(revoked(n)).To(BeFalse(), "an entry not yet due is never revoked early")
			left, _, err = myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(left).To(ConsistOf(notDue))
		})

		// The counter moves once a pass, however many steps left something
		// behind, and a step that left something behind does not stop being
		// counted because a later one was clean. Two discards in different
		// steps, then a clean last step.
		It("counts a pass that discarded entries in more than one step exactly once", func() {
			myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Millisecond}
			serials, recorded := due("p0.test", "p1.test", "p2.test", "p3.test")
			now := time.Now().UTC()
			entries := []supersededEntry{
				{Serial: "not-hex", Subject: "bad0.test", RevokeAt: now.Add(-time.Hour)},
				{Serial: recorded[0].Serial, Subject: recorded[0].Subject, RevokeAt: now.Add(-50 * time.Minute)},
				{Serial: "also-not-hex", Subject: "bad1.test", RevokeAt: now.Add(-40 * time.Minute)},
				{Serial: recorded[1].Serial, Subject: recorded[1].Subject, RevokeAt: now.Add(-30 * time.Minute)},
				{Serial: recorded[2].Serial, Subject: recorded[2].Subject, RevokeAt: now.Add(-20 * time.Minute)},
				{Serial: recorded[3].Serial, Subject: recorded[3].Subject, RevokeAt: now.Add(-10 * time.Minute)},
			}
			Expect(myCA.writeSuperseded(ctx, entries)).To(Succeed())
			failuresBefore := myCA.SupersedeFailures()
			before := backed.count("acquired")

			n, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(4))
			Expect(backed.count("acquired")-before).To(Equal(3), "three steps of two")
			for _, s := range serials {
				Expect(revoked(s)).To(BeTrue())
			}
			left, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(left).To(BeEmpty())
			Expect(myCA.SupersedeFailures()-failuresBefore).To(Equal(uint64(1)),
				"once for the pass, not once a step and not forgotten by a clean last step")
		})

		// A step whose batch cannot be written puts its entries back on the
		// list still due. The pass has to stop there: the next step would
		// pick the same entries up again, for as long as the CRL stays
		// unwritable, and each try would count another CRL update failure.
		It("ends the pass at the first step that cannot amend the CRL", func() {
			myCA.sweep = sweepTuning{stepEntries: 2, stepPause: time.Millisecond}
			_, entries := due(subjects...)
			backed.mu.Lock()
			backed.failCRLPut = true
			backed.mu.Unlock()
			supersedeBefore := myCA.SupersedeFailures()
			crlBefore := myCA.CRLUpdateFailures()
			before := backed.count("acquired")

			passCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := myCA.ReconcileSuperseded(passCtx)
				done <- err
			}()
			Eventually(done, 5*time.Second).Should(Receive(BeNil()),
				"the pass must end at the failed step, not retry it until its context ends")
			Expect(backed.count("acquired")-before).To(Equal(1), "one step, then stop")
			Expect(myCA.SupersedeFailures() - supersedeBefore).To(Equal(uint64(1)))
			Expect(myCA.CRLUpdateFailures()-crlBefore).To(Equal(uint64(1)),
				"a failing pass counts one CRL update failure however large the backlog")
			left, _, err := myCA.readSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(left).To(ConsistOf(entries), "every entry is still owed a revocation")
		})
	})

	// Each background job against a revocation that is already waiting when
	// the job queues. The job must not take the lock ahead of it. Order is the
	// assertion, read from the acquisition log: the job's acquisition has to
	// come after the revocation's critical section.
	//
	// The job queues first, so a lock that served waiters in arrival order —
	// the in-process mutex every backend puts in front of its own — would give
	// it the lock first.
	DescribeTable("lets a revocation that is already waiting go first",
		func(prepare func(), job func() error, effect func()) {
			myCA.sweep = sweepTuning{stepBudget: 5 * time.Second, stepPause: time.Millisecond}
			prepare()

			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseHolder := func() { releaseOnce.Do(func() { close(release) }) }
			// Registered before the holder exists, so a failed assertion below
			// cannot leave it holding the CRL lock past the spec.
			DeferCleanup(releaseHolder)
			held := make(chan struct{})
			firstDone := make(chan error, 1)
			go func() {
				firstDone <- store.WithLock(ctx, lockNameCRL, func() error {
					close(held)
					<-release
					return nil
				})
			}()
			Eventually(held).Should(BeClosed())

			jobDone := make(chan error, 1)
			go func() { jobDone <- job() }()
			// Long enough for the job to reach whatever it waits on: the gate,
			// or, without one, the mutex behind the holder above.
			Consistently(jobDone, 200*time.Millisecond).ShouldNot(Receive())

			begun := backed.count("begin")
			revokeDone := make(chan error, 1)
			go func() {
				revokeDone <- store.WithLock(ctx, lockNameCRL, func() error {
					backed.log("revocation")
					return nil
				})
			}()
			Eventually(func() int { return backed.count("begin") }).Should(BeNumerically(">", begun),
				"the revocation never started waiting for the lock")

			releaseHolder()
			Eventually(firstDone).Should(Receive(BeNil()))
			Eventually(revokeDone).Should(Receive(BeNil()))
			Eventually(jobDone, 5*time.Second).Should(Receive(BeNil()),
				"a job that stood aside must still go on to do its work")

			events := backed.logged()
			at := -1
			for i, e := range events {
				if e == "revocation" {
					at = i
				}
			}
			Expect(at).NotTo(Equal(-1))
			Expect(events[at+1:]).To(ContainElement("acquired"),
				"the job took the CRL lock ahead of a revocation already waiting for it: %v", events)
			effect()
		},
		// The two sweeps' effects are asserted; the two refresh jobs and the
		// merge have none to show here, since nothing is due or fetched, so
		// their nil error is it.
		Entry("CleanupExpiredCerts", func() { seedExpired("old.test", 0xEE20) },
			func() error { _, err := myCA.CleanupExpiredCerts(ctx, 0); return err },
			func() { Expect(inInventory("old.test")).To(BeFalse(), "the job never pruned") }),
		Entry("ReconcileSuperseded", func() {
			serial := issue("pending.test")
			Expect(myCA.writeSuperseded(ctx, []supersededEntry{{Serial: serialHexStr(serial),
				Subject: "pending.test", RevokeAt: time.Now().UTC().Add(-time.Minute)}})).To(Succeed())
		}, func() error { _, err := myCA.ReconcileSuperseded(ctx); return err },
			func() {
				left, _, err := myCA.readSuperseded(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(left).To(BeEmpty(), "the job never revoked the pending entry")
			}),
		Entry("RefreshCRLIfDue", func() {},
			func() error { _, err := myCA.RefreshCRLIfDue(ctx, 0); return err }, func() {}),
		Entry("RefreshCRLChainFile", func() {
			path := filepath.Join(dir, "chain.pem")
			Expect(os.WriteFile(path, nil, 0o600)).To(Succeed())
			myCA.CRLChainFile = path
		}, func() error { _, err := myCA.RefreshCRLChainFile(ctx); return err }, func() {}),
		// The crl_chain.urls merge: a round with no entries still reads the
		// stored chain and judges it under the lock, which is all this asks.
		Entry("MergeFetchedUpstreamCRLs", func() {},
			func() error { _, err := myCA.MergeFetchedUpstreamCRLs(ctx, nil); return err }, func() {}),
	)

	// A long pass reports at info level so it can be told from a wedged one,
	// and no more than once a sweepProgressEvery so a large backlog does not
	// flood the log with it.
	It("reports a pass's progress at info level at most once a sweepProgressEvery", func() {
		logs := captureLogs()
		p := newSweepProgress("Test sweep", "done")
		p.last = time.Now().Add(-2 * sweepProgressEvery)
		p.step(5)
		p.step(7)

		out := logs.String()
		Expect(strings.Count(out, `level=INFO msg="Test sweep in progress"`)).To(Equal(1),
			"one info line for two steps inside a minute")
		Expect(out).To(ContainSubstring(`msg="Test sweep in progress" done=5`))
		Expect(strings.Count(out, "Test sweep: step done, more remain")).To(Equal(2),
			"a debug line every step")
	})

	// The budgets the guarantee rests on, pinned as relations so a change to
	// one of them has to be argued against the others.

	// Both sides of the relation are pinned. managedcert.go writes three
	// detached budgets inline: the rollback's revocation, the retirement of
	// the replaced certificate, and the restore write between them, which
	// takes no named lock and so is not bound by this relation but shares its
	// expression. The spec reads all three from there rather than restating
	// them: changing one fails here, and so does halving the step's budget's
	// margin.
	It("leaves the smallest revocation budget at least half of itself after one step", func() {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "managedcert.go", nil, parser.SkipObjectResolution)
		Expect(err).NotTo(HaveOccurred())
		var budgets []string
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 || !isContextCall(call.Fun, "WithTimeout") {
				return true
			}
			inner, ok := call.Args[0].(*ast.CallExpr)
			if !ok || !isContextCall(inner.Fun, "WithoutCancel") {
				return true
			}
			budgets = append(budgets, types.ExprString(call.Args[1]))
			return true
		})
		Expect(budgets).To(HaveLen(3),
			"managedcert.go's detached budgets (two revocations and the restore write) changed in number; re-derive the smallest revocation budget")
		for _, b := range budgets {
			Expect(b).To(Equal("LockTimeout / 2"),
				"a managed detached budget changed; if it is a revocation's, re-check it against sweepStepBudget")
		}
		Expect(sweepStepBudget).To(BeNumerically("<=", LockTimeout/2/2))
	})

	// The runbooks and the operator docs quote the step's budget and size,
	// and a responder reads them mid-incident. Each phrase is rendered from
	// the constant, so retuning one fails here until the text follows.
	DescribeTable("quotes the step's figures as the constants have them",
		func(path, pattern string, want func() int) {
			data, err := os.ReadFile(filepath.Join("..", "..", path))
			Expect(err).NotTo(HaveOccurred())
			// Joined across line breaks, and blockquote markers, so that
			// rewrapping a paragraph cannot fail this.
			text := regexp.MustCompile(`\s*\n[\s>]*`).ReplaceAllString(string(data), " ")
			found := regexp.MustCompile(pattern).FindAllStringSubmatch(text, -1)
			Expect(found).NotTo(BeEmpty(), "the phrase is gone; update this table with the text")
			for _, m := range found {
				Expect(m[1]).To(Equal(strconv.Itoa(want())), "a stale figure in %q", m[0])
			}
		},
		Entry("alert runbooks, budget", "mixin/alerts.libsonnet", `whole (\d+)s budget`, func() int { return int(sweepStepBudget / time.Second) }),
		Entry("alert runbooks, step size", "mixin/alerts.libsonnet", `up to (\d+) due entries`, func() int { return sweepStepEntries }),
		Entry("cleanup cost note and supersession bullet, hold", "docs/configuration.md", `at most (\d+) seconds plus any CA signature`, func() int { return int(sweepStepBudget / time.Second) }),
		Entry("prune ceiling", "docs/configuration.md", `half of the step's (\d+) seconds`, func() int { return int(sweepStepBudget / time.Second) }),
		Entry("cleanup and supersession step size", "docs/configuration.md", `steps of up to (\d+)`, func() int { return sweepStepEntries }),
		Entry("cleanup passes", "docs/configuration.md", `about N/(\d+) full passes`, func() int { return sweepStepEntries }),
		Entry("supersession re-signs", "docs/configuration.md", `per (\d+) due certificates`, func() int { return sweepStepEntries }),
		Entry("pending-list rewrites", "docs/configuration.md", `about D/(\d+) list rewrites`, func() int { return sweepStepEntries }),
		Entry("crl_update_failures note, budget", "docs/metrics.md", `after (\d+) seconds rather than \d+`, func() int { return int(sweepStepBudget / time.Second) }),
		Entry("crl_update_failures note, lock timeout", "docs/metrics.md", `after \d+ seconds rather than (\d+)`, func() int { return int(LockTimeout / time.Second) }),
		Entry("a whole step's wait", "docs/metrics.md", `a whole (\d+) seconds`, func() int { return int(sweepStepBudget / time.Second) }),
		Entry("supersede cost note", "docs/metrics.md", `each step of up to (\d+) due certificates`, func() int { return sweepStepEntries }),
		Entry("storage backends, step size", "docs/storage-backends.md", `steps of at most (\d+) entries`, func() int { return sweepStepEntries }),
		Entry("storage backends, reads", "docs/storage-backends.md", `N/(\d+) times`, func() int { return sweepStepEntries }),
		Entry("inventory records comment", "internal/storage/inventory_records.go", `sweepStepEntries \(internal/ca, (\d+)\)`, func() int { return sweepStepEntries }),
		Entry("etcd prune comment", "internal/storage/etcd_inventory.go", `sweepStepEntries \(internal/ca, (\d+)\)`, func() int { return sweepStepEntries }),
		Entry("Redis prune comment", "internal/storage/redis_inventory.go", `sweepStepEntries \(internal/ca, (\d+)\)`, func() int { return sweepStepEntries }),
	)

	// A cleanup step holds c.mu for up to its budget by design, and the
	// readiness probe must not wait behind it: with the chart's one-second
	// probe, back-to-back steps would take every sweeping replica out of its
	// Service at once.
	It("answers readiness while the CA's lock is held", func() {
		Expect(myCA.IsReady()).To(BeTrue(), "precondition")
		myCA.mu.Lock()
		DeferCleanup(myCA.mu.Unlock)
		ready := make(chan bool, 1)
		go func() { ready <- myCA.IsReady() }()
		Eventually(ready, time.Second).Should(Receive(BeTrue()),
			"IsReady waited for the CA's lock")
	})

	// The cost note's worked example is arithmetic on the step size, which the
	// table above cannot express.
	It("works its cleanup example out with the step size the code has", func() {
		data, err := os.ReadFile(filepath.Join("..", "..", "docs/configuration.md"))
		Expect(err).NotTo(HaveOccurred())
		text := regexp.MustCompile(`\s*\n[\s>]*`).ReplaceAllString(string(data), " ")
		m := regexp.MustCompile(`([\d,]+) of them for ([\d,]+) expired certificates`).FindStringSubmatch(text)
		Expect(m).NotTo(BeNil(), "the example is gone; update this spec with the text")
		passes, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", ""))
		Expect(err).NotTo(HaveOccurred())
		backlog, err := strconv.Atoi(strings.ReplaceAll(m[2], ",", ""))
		Expect(err).NotTo(HaveOccurred())
		Expect(passes).To(Equal(backlog / sweepStepEntries))
	})

	It("pauses between steps for longer than a Redis waiter's longest backoff", func() {
		Expect(sweepStepPause).To(BeNumerically(">", storage.RedisLockPollMaxBackoff))
	})

	It("lets the crl_chain.file read time out inside the refresh job's step", func() {
		Expect(crlChainReadTimeout).To(BeNumerically("<", sweepStepBudget))
	})
})

// detachedInCRLLock reports every context.WithoutCancel, context.Background or
// context.TODO call inside a closure that runs under the CRL lock, and how many
// such closures it found.
//
// A closure runs under the CRL lock when it is an argument to a WithLock or
// WithLockYielding call naming lockNameCRL, or to withCRLLockCounted,
// withCRLLockYielding or sweepStep. A detached context derived inside one is a
// hold that outlives the budget its acquisition was given, which is the shape
// #347 removed.
//
// It is syntactic, and two shapes get past it. A helper called from inside the
// closure that detaches a context of its own is not seen. Nor is a closure that
// captures a context detached before the lock and re-times it inside, starting
// a fresh budget: sweepStep does exactly that, once, at acquisition, and it is
// the only thing that may. Those are the limits of a check like this one, and
// the reason a closure has no business doing either.
func detachedInCRLLock(fset *token.FileSet, file *ast.File) (found []token.Position, closures int) {
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		underCRL := false
		switch sel.Sel.Name {
		case "withCRLLockCounted", "withCRLLockYielding", "sweepStep":
			underCRL = true
		case "WithLock", "WithLockYielding", "WithLockNeutral":
			for _, arg := range call.Args {
				if id, ok := arg.(*ast.Ident); ok && id.Name == "lockNameCRL" {
					underCRL = true
				}
			}
		}
		if !underCRL {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.FuncLit)
			if !ok {
				continue
			}
			closures++
			ast.Inspect(lit.Body, func(m ast.Node) bool {
				inner, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				// Every way to a context that does not end with the
				// acquisition's: detaching from it, or starting afresh.
				if isContextCall(inner.Fun, "WithoutCancel") || isContextCall(inner.Fun, "Background") ||
					isContextCall(inner.Fun, "TODO") {
					found = append(found, fset.Position(inner.Pos()))
				}
				return true
			})
		}
		return true
	})
	return found, closures
}

// yieldingCRLSites returns the name of every function in file that takes the
// CRL lock by yielding: one that names WithLockYielding, withCRLLockYielding or
// sweepStep, whether it calls it or passes it on. Methods are recorded by name.
func yieldingCRLSites(file *ast.File) map[string]bool {
	sites := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "WithLockYielding", "withCRLLockYielding", "sweepStep":
				sites[fn.Name.Name] = true
			}
			return true
		})
	}
	return sites
}

// neutralCRLSites returns the name of every function in file that names
// WithLockNeutral, whether it calls it or passes it on.
func neutralCRLSites(file *ast.File) map[string]bool {
	sites := make(map[string]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithLockNeutral" {
				sites[fn.Name.Name] = true
			}
			return true
		})
	}
	return sites
}

// isContextCall reports whether fun is context.<name>.
func isContextCall(fun ast.Expr, name string) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "context" && sel.Sel.Name == name
}

var _ = Describe("No CRL-lock holder extends its own hold (#347)", func() {
	It("finds no detached context derived inside a CRL-lock closure in this package", func() {
		paths, err := filepath.Glob("*.go")
		Expect(err).NotTo(HaveOccurred())
		fset := token.NewFileSet()
		var found []string
		closures := 0
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			Expect(err).NotTo(HaveOccurred())
			hits, n := detachedInCRLLock(fset, file)
			closures += n
			for _, h := range hits {
				found = append(found, h.String())
			}
		}
		// The floor: the package has more than a dozen CRL-lock closures, so a
		// count near zero means the matcher stopped seeing them and this spec
		// has gone vacuous, not that the package is clean.
		Expect(closures).To(BeNumerically(">=", 12),
			"the matcher no longer recognises the package's CRL-lock closures")
		Expect(found).To(BeEmpty(),
			"a CRL-lock closure derives a detached context, so its hold can outlast its budget and a "+
				"revocation waiting on it can lose; detach before taking the lock, or work in steps "+
				"(see crlyield.go)")
	})

	// Which side of the gate a caller is on is the guarantee itself: a
	// revocation that took the CRL lock by yielding would stand aside for the
	// very work #347 says it must beat, and nothing else would notice. So the
	// yielding sites are enumerated here, and adding one is an edit to this
	// list that a reviewer sees. Read locking.md rule 13 before adding one.
	It("lets only the background jobs take the CRL lock by yielding", func() {
		paths, err := filepath.Glob("*.go")
		Expect(err).NotTo(HaveOccurred())
		fset := token.NewFileSet()
		got := make(map[string]bool)
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			Expect(err).NotTo(HaveOccurred())
			for name := range yieldingCRLSites(file) {
				got[name] = true
			}
		}
		Expect(got).To(Equal(map[string]bool{
			"withCRLLockYielding":      true,
			"cleanupExpiredStep":       true,
			"reconcileSupersededStep":  true,
			"RefreshCRLIfDue":          true,
			"RefreshCRLChainFile":      true,
			"MergeFetchedUpstreamCRLs": true,
		}), "a function took the CRL lock by yielding that is not one of the background jobs, or one of them stopped")
	})

	// The third way to the CRL lock: neutral, neither going first nor standing
	// aside. Only work that revokes nothing may take it, or a revocation would
	// queue behind a sweep again; see locking.md rule 13.
	It("lets only the recording of a supersession take the CRL lock neutrally", func() {
		paths, err := filepath.Glob("*.go")
		Expect(err).NotTo(HaveOccurred())
		fset := token.NewFileSet()
		got := make(map[string]bool)
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			Expect(err).NotTo(HaveOccurred())
			for name := range neutralCRLSites(file) {
				got[name] = true
			}
		}
		Expect(got).To(Equal(map[string]bool{"recordSuperseded": true}),
			"a function took the CRL lock neutrally that is not recordSuperseded, or it stopped")
	})

	It("the enumeration sees a revocation that takes the lock neutrally", func() {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "x.go", `package ca
func (c *CA) Revoke(ctx context.Context, subject string) error {
	return c.Storage.WithLockNeutral(ctx, lockNameCRL, func() error { return nil })
}`, parser.SkipObjectResolution)
		Expect(err).NotTo(HaveOccurred())
		Expect(neutralCRLSites(file)).To(HaveKey("Revoke"))
	})

	It("the enumeration sees a revocation that yields", func() {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "x.go", `package ca
func (c *CA) Revoke(ctx context.Context, subject string) error {
	return c.withCRLLockYielding(ctx, func() error { return nil })
}`, parser.SkipObjectResolution)
		Expect(err).NotTo(HaveOccurred())
		Expect(yieldingCRLSites(file)).To(HaveKey("Revoke"))
	})

	// The must-fail twin of "finds no detached context derived inside a
	// CRL-lock closure in this package". Without it a matcher that recognised
	// nothing would pass that spec as surely as a clean package does.
	DescribeTable("the matcher",
		func(src string, want int) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "x.go", "package ca\n"+src, parser.SkipObjectResolution)
			Expect(err).NotTo(HaveOccurred())
			found, closures := detachedInCRLLock(fset, file)
			Expect(closures).To(Equal(1))
			Expect(found).To(HaveLen(want))
		},
		Entry("flags a detached context inside WithLock on lockNameCRL", `
func f(c *CA, ctx context.Context) {
	_ = c.Storage.WithLock(ctx, lockNameCRL, func() error {
		x, cancel := context.WithTimeout(context.WithoutCancel(ctx), LockTimeout/2)
		defer cancel()
		return use(x)
	})
}`, 1),
		Entry("flags a detached context inside WithLockNeutral on lockNameCRL", `
func f(c *CA, ctx context.Context) {
	_ = c.Storage.WithLockNeutral(ctx, lockNameCRL, func() error {
		_ = context.Background()
		return nil
	})
}`, 1),
		Entry("flags one nested deeper inside withCRLLockCounted", `
func f(c *CA, ctx context.Context) {
	_ = c.withCRLLockCounted(ctx, func() error {
		return func() error { _ = context.WithoutCancel(ctx); return nil }()
	})
}`, 1),
		Entry("flags one inside WithLockYielding", `
func f(c *CA, ctx context.Context) {
	_ = c.Storage.WithLockYielding(ctx, lockNameCRL, func() error {
		_ = context.WithoutCancel(ctx)
		return nil
	})
}`, 1),
		Entry("flags one inside a sweep step's body", `
func f(c *CA, ctx context.Context) {
	_ = c.sweepStep(ctx, c.withCRLLockYielding, func(ctx context.Context) error {
		_ = context.WithoutCancel(ctx)
		return nil
	})
}`, 1),
		Entry("flags a fresh context.Background inside a CRL-lock closure", `
func f(c *CA, ctx context.Context) {
	_ = c.withCRLLockYielding(ctx, func() error {
		x, cancel := context.WithTimeout(context.Background(), LockTimeout/2)
		defer cancel()
		return use(x)
	})
}`, 1),
		Entry("flags a context.TODO inside a CRL-lock closure", `
func f(c *CA, ctx context.Context) {
	_ = c.Storage.WithLock(ctx, lockNameCRL, func() error {
		return use(context.TODO())
	})
}`, 1),
		Entry("accepts one derived before the lock is taken", `
func f(c *CA, ctx context.Context) {
	x, cancel := context.WithTimeout(context.WithoutCancel(ctx), LockTimeout/2)
	defer cancel()
	_ = c.Storage.WithLock(x, lockNameCRL, func() error { return nil })
}`, 0),
	)
})

// StoppedByShutdown is the one place the background jobs and their drivers
// tell a shutdown from a failure, so both directions are pinned: a real failure must still read as
// one when the context has also ended, and a timeout of the CA's own must not
// read as a shutdown while the context is alive.
var _ = DescribeTable("StoppedByShutdown",
	func(cancelled bool, err error, want bool) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if cancelled {
			cancel()
		}
		Expect(StoppedByShutdown(ctx, err)).To(Equal(want))
	},
	Entry("no error", true, nil, false),
	Entry("the context's own error", true, context.Canceled, true),
	Entry("the context's error, wrapped", true, fmt.Errorf("waiting for the lock: %w", context.Canceled), true),
	Entry("a real failure after the context ended", true, errors.New("storage down"), false),
	Entry("a cancellation the context did not cause", false, context.Canceled, false),
	Entry("a step's own deadline while the context is alive", false, context.DeadlineExceeded, false),
)

// A caller's deadline is not a shutdown: a pass whose own deadline ran out did
// not finish, and the CA counts it, so the driver must not log it as stopped.
var _ = It("does not take a caller's deadline for a shutdown", func() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	Expect(StoppedByShutdown(ctx, ctx.Err())).To(BeFalse())
})
