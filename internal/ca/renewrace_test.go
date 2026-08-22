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

// White-box, unlike its sibling renewgate_test.go: these specs have to take the
// very locks the renewal and revocation paths take, and subjectLockName and
// lockNameCRL are the only things that know what they are called. Naming them
// from outside would spell the strings a second time, and a spec that holds the
// wrong lock blocks nothing while still passing.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// refuseIfRevoked answers the revocation question before Storage.WithLock takes
// the per-subject lock, and acquiring that lock can take a while. These specs
// cover what happens to an answer given there when a revocation lands before it
// is acted on — the certificate would otherwise be minted for an identity that
// was withdrawn before the minting.
//
// The cross-replica half of that staleness is not covered here: refuseIfRevoked
// calls SyncCRLCache first, so a revocation another replica performed is already
// visible to it, and crlsync_test.go owns that property. What is left, and what
// these pin, is the window between the gate's answer and the issuance it guards.
//
// The other three blocks cover the far side of the same lock, where Revoke
// takes it too. One pins that a revocation waits for an issuance already under
// way rather than stepping past it, and takes the subject lock without holding
// the CRL lock. A table then makes that ordering an assertion for every caller
// that holds both locks — Clean, Renew, AutoRenew — which is the block
// docs/development/locking.md points at as the automation of the nested
// invariant; an inversion of it deadlocks rather than failing, so the check is
// that the CRL lock stays grantable while each one waits. The last pins what
// happens when the renewal wins that race instead: the revocation behind it
// must retire the serial the renewal issued. Between them the two orderings Revoke's godoc
// rests on are both answers rather than races, which is the claim that makes the
// re-check worth its lock.
var _ = Describe("A revocation racing a renewal", func() {
	var (
		ctx      context.Context
		storeDir string
		store    *storage.StorageService
		myCA     *CA
		ownCrt   *x509.Certificate
		csrPEM   []byte
	)

	// replicaOn returns a second CA over the given storage, as another process
	// serving the same cluster would see it. Its Init loads the CA already
	// bootstrapped there rather than minting a new one, so a revocation it
	// performs is this CA's own certificate being revoked.
	replicaOn := func(s *storage.StorageService) *CA {
		GinkgoHelper()
		r := New(s, AutosignConfig{Mode: "off"}, "puppet.test")
		r.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		r.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(r.Init(ctx)).To(Succeed())
		return r
	}

	// unlockedReplica is a second CA over a second StorageService on the same
	// directory, sharing the CA's state but none of its named locks.
	//
	// The lock-wait spec needs that. Revoke takes the per-subject lock now, so a
	// revocation issued through `store` would queue behind the lock that spec
	// holds instead of committing during the wait. What survives on a real HA
	// backend, where the lock genuinely is shared, is the ordering it stands in
	// for: a revocation that reached storage before the renewal acquired the
	// lock, which the re-check must still refuse.
	//
	// The separation has to be asked for. A plain second StorageService over the
	// same directory used to provide it by accident — the filesystem backend
	// offered no lock at all, so WithLock fell back to a mutex map held per
	// StorageService — and #187 removed that accident by giving the backend a
	// same-host flock the two would now share. noSameHostLocks declines the
	// capability so the fallback is reached deliberately, which is also the more
	// honest model of the two replicas this spec is about: on a real HA backend
	// they are on different hosts.
	unlockedReplica := func() *CA {
		GinkgoHelper()
		backend := &noSameHostLocks{FilesystemBackend: storage.NewFilesystemBackend(storeDir)}
		return replicaOn(storage.NewWithBackend(backend, filepath.Join(storeDir, "private")))
	}

	// servedSerial is the serial of the certificate storage currently serves for
	// node1.test. A refused renewal must leave it as it was: the refusal is
	// worth little if the replacement was already written by the time it was
	// decided.
	servedSerial := func() *big.Int {
		GinkgoHelper()
		stored, err := store.GetCert(ctx, "node1.test")
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(stored)
		Expect(block).NotTo(BeNil())
		crt, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return crt.SerialNumber
	}

	// expectRefusedWithoutTrace asserts the other half of a refusal: that it was
	// decided before the renewal wrote anything. The served certificate covers
	// the issuance; the pending CSR covers the re-key path specifically, where
	// the re-check sits ahead of SaveCSR. Move it below and a refused renewal
	// leaves a CSR queued for a subject whose certificate has just been revoked,
	// signable later through the admin path — with the served serial, and every
	// other assertion here, unchanged.
	expectRefusedWithoutTrace := func() {
		GinkgoHelper()
		Expect(servedSerial()).To(Equal(ownCrt.SerialNumber))
		Expect(store.HasCSR(ctx, "node1.test")).To(BeFalse())
	}

	BeforeEach(func() {
		ctx = context.Background()
		storeDir = GinkgoT().TempDir()
		store = storage.New(storeDir)
		myCA = replicaOn(store)

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		ownCrt, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Built here rather than in the renewal closure below so that closure
		// carries no assertions: it runs on a goroutine of its own in the
		// lock-ordering specs, where a failed Expect is a panic to be recovered
		// rather than a spec failure to be read.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "node1.test"}}, key)
		Expect(err).NotTo(HaveOccurred())
		csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	})

	// The two renewal paths keep separate copies of the re-check and reach the
	// lock through separate code, so every spec here runs against both: one
	// added to a single path would otherwise look like one added to renewal.
	autoRenew := func() error { _, err := myCA.AutoRenew(ctx, ownCrt); return err }
	csrRenew := func() error { _, err := myCA.Renew(ctx, "node1.test", csrPEM, ownCrt); return err }

	DescribeTable("refuses a revocation that lands while it waits for the subject lock",
		func(renew func() error) {
			// Hold the lock the renewal needs, so the renewal is parked in
			// exactly the wait the issue describes rather than racing it.
			locked, release := make(chan struct{}), make(chan struct{})
			held := make(chan error, 1)
			// Registered before the goroutine exists, so the holder unblocks on
			// every exit path. Without it a failed assertion below aborts the
			// spec before the explicit close, leaving the holder parked and the
			// renewal blocked indefinitely: store is filesystem-backed, so that
			// wait is on a process-local mutex, which no deadline ends (see
			// StorageService.WithLock's godoc). That leaks a goroutine into
			// TempDir cleanup at exactly the moment the failure output matters.
			var releaseOnce sync.Once
			DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
			go func() {
				defer GinkgoRecover()
				held <- store.WithLock(ctx, subjectLockName("node1.test"), func() error {
					close(locked)
					<-release
					return nil
				})
			}()
			Eventually(locked).Should(BeClosed())

			renewed := make(chan error, 1)
			finished := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(finished)
				renewed <- renew()
			}()
			// Releasing the lock is not enough on a failure path: it only
			// unparks the renewal, which then runs on into signing and storage
			// writes while TempDir's cleanup — registered earlier, so it runs
			// later — deletes the directory underneath it. Wait for it here.
			DeferCleanup(func() {
				releaseOnce.Do(func() { close(release) })
				Eventually(finished).Should(BeClosed())
			})

			// The revocation lands mid-wait, through a replica with its own lock
			// namespace: Revoke takes the per-subject lock now, so one sharing
			// this store would queue behind the lock held above rather than
			// commit here.
			Expect(unlockedReplica().Revoke(ctx, "node1.test")).To(Succeed())

			// Nothing decided yet — and this is the half a re-check hoisted back
			// above the lock fails. Such a check answers before blocking: either
			// it has already seen the revocation and refuses here, or it has not
			// and the renewal succeeds once the lock is free.
			//
			// This does assume the renewal reached its pre-lock gate before the
			// revocation above committed, which nothing enforces — the main
			// goroutine does far more work first (a second CA's Init, then a CRL
			// read-modify-write and re-sign) than the renewal's signature check,
			// so it holds comfortably, but say so in the message rather than let
			// a scheduling upset read as the defect.
			Consistently(renewed, 100*time.Millisecond).ShouldNot(Receive(),
				"the renewal must still be parked on the subject lock: receiving here means "+
					"either the re-check was hoisted back above the lock, or the revocation "+
					"beat the renewal to its pre-lock gate")

			releaseOnce.Do(func() { close(release) })
			Expect(<-held).To(Succeed())

			Eventually(renewed).Should(Receive(MatchError(ErrCertRevoked)))
			expectRefusedWithoutTrace()
		},
		Entry("on the empty-body path", func() error { return autoRenew() }),
		Entry("on the CSR path", func() error { return csrRenew() }),
	)

	// The re-check is only worth its lock if nothing can revoke between it and
	// the issuance it guards. Revoke takes the same per-subject lock to make
	// that so; drop it and the defect this closes comes back over a shorter
	// window, with every other spec here still passing.
	It("makes a revocation wait for an issuance already under way", func() {
		locked, release := make(chan struct{}), make(chan struct{})
		held := make(chan error, 1)
		var releaseOnce sync.Once
		DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
		go func() {
			defer GinkgoRecover()
			held <- store.WithLock(ctx, subjectLockName("node1.test"), func() error {
				close(locked)
				<-release
				return nil
			})
		}()
		Eventually(locked).Should(BeClosed())

		revoked := make(chan error, 1)
		finished := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(finished)
			revoked <- myCA.Revoke(ctx, "node1.test")
		}()
		DeferCleanup(func() {
			releaseOnce.Do(func() { close(release) })
			Eventually(finished).Should(BeClosed())
		})

		// A Revoke that took only the CRL lock would be done by now, having
		// stepped straight past an issuance holding the subject lock.
		Consistently(revoked, 100*time.Millisecond).ShouldNot(Receive())

		// And it must be waiting on the subject lock specifically, not holding
		// the CRL lock while it waits. Taking them in the other order deadlocks
		// against Clean and both renewal paths, all of which take the subject
		// lock first and the CRL lock inside it — and that deadlock does not
		// time out, because every backend serialises same-process callers on a
		// mutex that ignores the context deadline. Without this the inversion
		// passes every spec in the file.
		crlFree := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			Expect(store.WithLock(ctx, lockNameCRL, func() error {
				close(crlFree)
				return nil
			})).To(Succeed())
		}()
		Eventually(crlFree).Should(BeClosed(),
			"Revoke must not be holding the CRL lock while it waits for the subject lock")

		releaseOnce.Do(func() { close(release) })
		Expect(<-held).To(Succeed())

		Eventually(revoked).Should(Receive(BeNil()))
		isRevoked, err := myCA.IsRevokedSerial(ctx, ownCrt.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(isRevoked).To(BeTrue(), "waiting for the lock must not lose the revocation")
	})

	// Revoke is not the only caller that nests the two locks, and the ordering
	// is a property of all of them: one inversion deadlocks against the rest.
	// The spec above pins Revoke because that is the acquisition this change
	// adds; this table pins the other three, so an inversion introduced in any
	// of them fails here instead of hanging the suite to its timeout.
	DescribeTable("takes the subject lock before the CRL lock",
		func(op func() error) {
			locked, release := make(chan struct{}), make(chan struct{})
			held := make(chan error, 1)
			var releaseOnce sync.Once
			DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
			go func() {
				defer GinkgoRecover()
				held <- store.WithLock(ctx, subjectLockName("node1.test"), func() error {
					close(locked)
					<-release
					return nil
				})
			}()
			Eventually(locked).Should(BeClosed())

			done := make(chan error, 1)
			finished := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(finished)
				done <- op()
			}()
			DeferCleanup(func() {
				releaseOnce.Do(func() { close(release) })
				Eventually(finished).Should(BeClosed())
			})

			Consistently(done, 100*time.Millisecond).ShouldNot(Receive())
			crlFree := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				Expect(store.WithLock(ctx, lockNameCRL, func() error {
					close(crlFree)
					return nil
				})).To(Succeed())
			}()
			Eventually(crlFree).Should(BeClosed(),
				"the operation must not hold the CRL lock while it waits for the subject lock")

			releaseOnce.Do(func() { close(release) })
			Expect(<-held).To(Succeed())
			Eventually(done).Should(Receive(BeNil()))

			// The crlFree check above is one-sided: it proves the operation was
			// not *holding* the CRL lock, which is equally true of one that
			// never takes it. All three swallow a failed revoke step and still
			// return nil, so without this the entry would go on passing if that
			// step were dropped — and locking.md advertises this table as the
			// automation of the ordering invariant. Assert the CRL-locked work
			// actually ran: each of the three retires ownCrt's serial, Clean as
			// the subject's latest and the two renewals as the one they replace.
			isRevoked, err := myCA.IsRevokedSerial(ctx, ownCrt.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(isRevoked).To(BeTrue(),
				"the operation must have reached the CRL lock it is being checked for")
		},
		Entry("Clean", func() error { return myCA.Clean(ctx, "node1.test") }),
		Entry("Renew", func() error { _, err := myCA.Renew(ctx, "node1.test", csrPEM, ownCrt); return err }),
		Entry("AutoRenew", func() error { _, err := myCA.AutoRenew(ctx, ownCrt); return err }),
	)

	// The other half of the disjunction Revoke's godoc rests on: when the
	// renewal wins the lock instead, the revocation that follows must retire the
	// serial that renewal just issued, not the one it replaced. That holds
	// because issueLeafLocked appends the new inventory row before the subject
	// lock is released, so findSerialForSubject resolves to it.
	//
	// Exercised sequentially, deliberately: with both waiters on one mutex,
	// which is granted first is not deterministic, so a concurrent form would be
	// a flaky spec. Be clear about what that costs. What this pins is that a
	// revocation following a renewal retires the *newest* serial — it would
	// catch one that retired the replaced serial instead. What it does not
	// discriminate is the position of Revoke's own serial capture: with no
	// renewal in flight, findSerialForSubject resolves to the renewed serial
	// whether it is called inside the subject lock or ahead of it. The in-lock
	// append that makes the concurrent case work is relied upon here, not
	// guarded.
	It("retires the certificate a renewal issued when the revocation follows it", func() {
		_, err := myCA.AutoRenew(ctx, ownCrt)
		Expect(err).NotTo(HaveOccurred())

		renewed := servedSerial()
		Expect(renewed.Cmp(ownCrt.SerialNumber)).NotTo(Equal(0), "the renewal must have issued a fresh serial")

		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		isRevoked, err := myCA.IsRevokedSerial(ctx, renewed)
		Expect(err).NotTo(HaveOccurred())
		Expect(isRevoked).To(BeTrue(), "the revocation must retire the serial the renewal issued")

		// The predecessor stays revoked too — the renewal retired it on the way
		// past — so neither certificate is left usable.
		wasRevoked, err := myCA.IsRevokedSerial(ctx, ownCrt.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(wasRevoked).To(BeTrue())
	})
})

// noSameHostLocks is a filesystem backend that declines the same-host locking
// capability, so StorageService.WithLock falls back to the per-service mutex
// map. It models a replica on another host — which is what the specs using it
// are about — without needing a distributed backend to model it with.
//
// The concrete backend is embedded rather than the Backend interface so that
// Path, BaseDir and the rest stay promoted: StorageService probes for several
// of them, and a wrapper that hid them would change more than the lock.
type noSameHostLocks struct {
	*storage.FilesystemBackend
}

func (*noSameHostLocks) AcquireSameHostLock(context.Context, string) (storage.Unlocker, error) {
	return nil, storage.ErrSameHostLockingUnsupported
}
