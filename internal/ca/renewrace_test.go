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

// White-box, unlike its sibling renewgate_test.go: the lock-ordering spec below
// has to take the very lock the renewal paths take, and subjectLockName is the
// only thing that knows what it is called. Naming it from outside would spell
// the string a second time, and a spec that holds the wrong lock blocks nothing
// while still passing.
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
	"log/slog"
	"math/big"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The renewal gate asks "has this certificate been revoked?" before the
// per-subject lock, and waiting for that lock can take up to lockTimeout. These
// specs cover the two ways an answer given there goes stale before it is acted
// on: another replica revoked and this one's CRL cache has not caught up, and a
// revocation that landed while this renewal was queued behind the lock.
//
// Both are the same defect from the issuing side — a certificate is minted for
// an identity that was withdrawn before the minting — and both are closed by
// re-asking the question from storage under the lock.
//
// Two more cover the other side of that lock, where Revoke now takes it too.
// One pins that a revocation waits for an issuance already under way rather
// than stepping past it, and that it waits on the subject lock without holding
// the CRL lock — the ordering every other nested acquisition in the package
// uses, and an inversion of it deadlocks. The other pins what happens when the
// renewal wins that race instead: the revocation behind it must retire the
// serial the renewal issued. Between them the two orderings Revoke's godoc
// rests on are both answers rather than races, which is the claim that makes
// the re-check above worth its lock.
//
// The corrupt-CRL spec pins reassertNotRevoked's fallback to the cached CRL,
// and does it by calling the method rather than a renewal. No route through Renew or
// AutoRenew can reach that branch's interesting case: it needs the cache to say
// "revoked" while the pre-lock gate, which reads that same cache, has already
// passed, and nothing a caller can do changes the cache between the two. The
// direct call poses the two sources independently instead.
//
// renew_test.go's corrupt-CRL specs are not a substitute. They run with a cache
// that says "not revoked", so returning the cached answer and returning nothing
// are the same answer there; they pin that an unreadable CRL is not a renewal
// outage, and nothing about what the cache is still allowed to refuse.
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
	// performs is this CA's own certificate being revoked — reaching storage,
	// and myCA's in-memory CRL cache not at all.
	replicaOn := func(s *storage.StorageService) *CA {
		GinkgoHelper()
		r := New(s, AutosignConfig{Mode: "off"}, "puppet.test")
		r.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		r.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(r.Init(ctx)).To(Succeed())
		return r
	}

	replica := func() *CA {
		GinkgoHelper()
		return replicaOn(store)
	}

	// unlockedReplica is replica() over a second StorageService on the same
	// directory, so it shares the CA's state but none of its named locks: the
	// filesystem backend has no distributed locker, and WithLock falls back to
	// a mutex map held per StorageService.
	//
	// The lock-wait spec needs that. Revoke takes the per-subject lock now, so a
	// revocation issued through `store` would queue behind the lock that spec
	// holds instead of committing during the wait. What survives on a real HA
	// backend, where the lock genuinely is shared, is the ordering this stands
	// in for: a revocation that reached storage before the renewal acquired the
	// lock, which the re-check must still refuse.
	unlockedReplica := func() *CA {
		GinkgoHelper()
		return replicaOn(storage.New(storeDir))
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
		myCA = replica()

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		ownCrt, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		// Built here rather than in the renewal closure below so that closure
		// carries no assertions: it runs on a goroutine of its own in the
		// lock-ordering spec, where a failed Expect is a panic to be recovered
		// rather than a spec failure to be read.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: "node1.test"}}, key)
		Expect(err).NotTo(HaveOccurred())
		csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	})

	// The two renewal paths keep separate copies of the gate and reach the lock
	// through separate code, so every spec here runs against both: a re-check
	// added to one only would otherwise look like a re-check added to renewal.
	autoRenew := func() error { _, err := myCA.AutoRenew(ctx, ownCrt); return err }
	csrRenew := func() error { _, err := myCA.Renew(ctx, "node1.test", csrPEM, ownCrt); return err }

	DescribeTable("refuses a certificate another replica has revoked",
		func(renew func() error) {
			// Positive control first, on a cert nobody has revoked: without it a
			// renewal broken for any other reason would read as the gate working.
			Expect(renew()).To(Succeed())

			// Re-read: the successful renewal above replaced the certificate and
			// revoked the old serial, so what the other replica revokes next —
			// and what the presented certificate must now be — is the new one.
			stored, err := store.GetCert(ctx, "node1.test")
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(stored)
			ownCrt, err = x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())

			Expect(replica().Revoke(ctx, "node1.test")).To(Succeed())

			// myCA never signed that CRL, so its cache still says the
			// certificate is live and the pre-lock gate still passes it. Only a
			// check that reads storage refuses here — which is what makes a
			// revocation on one replica bind on the others.
			revoked, err := myCA.IsRevokedSerial(ctx, ownCrt.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse(), "the cache must still be stale, or this spec proves nothing")

			Expect(renew()).To(MatchError(ErrForeignCertificate))
			expectRefusedWithoutTrace()
		},
		Entry("on the empty-body path", func() error { return autoRenew() }),
		Entry("on the CSR path", func() error { return csrRenew() }),
	)

	DescribeTable("refuses a revocation that lands while it waits for the subject lock",
		func(renew func() error) {
			// Hold the lock the renewal needs, so the renewal is parked in
			// exactly the wait the issue describes rather than racing it.
			locked, release := make(chan struct{}), make(chan struct{})
			held := make(chan error, 1)
			// Registered before the goroutine exists, so the holder unblocks on
			// every exit path. Without it a failed assertion below aborts the
			// spec before the explicit close, leaving the holder parked and the
			// renewal blocked for the full 60s lockTimeout — 60s of noise at
			// exactly the moment the failure output matters.
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
			// Cheap on the happy path, where finished is closed already.
			DeferCleanup(func() {
				releaseOnce.Do(func() { close(release) })
				Eventually(finished).Should(BeClosed())
			})

			// The revocation lands mid-wait. Performed on another replica so
			// that whether the renewal reached its pre-lock gate before or after
			// this line cannot decide the outcome: that gate reads myCA's cache,
			// which this leaves untouched either way. It must be the replica
			// with its own lock namespace — Revoke takes the per-subject lock,
			// so one sharing this store would queue behind the lock held above
			// rather than commit here.
			Expect(unlockedReplica().Revoke(ctx, "node1.test")).To(Succeed())

			// Nothing decided yet — and this is the half that a re-check hoisted
			// back above the lock fails. Such a re-check answers before blocking:
			// either it has already seen the revocation and refuses here, or it
			// has not and the renewal succeeds once the lock is free.
			Consistently(renewed, 100*time.Millisecond).ShouldNot(Receive())

			releaseOnce.Do(func() { close(release) })
			Expect(<-held).To(Succeed())

			Eventually(renewed).Should(Receive(MatchError(ErrForeignCertificate)))
			expectRefusedWithoutTrace()
		},
		Entry("on the empty-body path", func() error { return autoRenew() }),
		Entry("on the CSR path", func() error { return csrRenew() }),
	)

	// The re-check is only worth its lock if nothing can revoke between it and
	// the issuance it guards. Revoke takes the same per-subject lock to make
	// that so; drop it and the defect this branch closes comes back over a
	// shorter window, with every other spec here still passing.
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
		// lock first and the CRL lock inside it — and on the filesystem backend
		// that deadlock is unbounded, because the process-local fallback is a
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

	// The other half of the disjunction Revoke's godoc rests on: when the
	// renewal wins the lock instead, the revocation that follows must retire
	// the serial that renewal just issued, not the one it replaced. That holds
	// because issueLeafLocked appends the new inventory row before the subject
	// lock is released, so findSerialForSubject resolves to it — the same
	// latest-wins resolution revokeSerialLocked's godoc warns about, relied on
	// here rather than worked around. Move the serial capture ahead of the lock
	// and PUT /certificate_status answers 204 while the fresh certificate stays
	// live, which is this branch's own failure mode reached from the other side.
	//
	// Exercised sequentially, deliberately: with both waiters on one mutex,
	// which is granted first is not deterministic, so a concurrent form would be
	// a flaky spec. The observable claim is pinned; the in-lock append that
	// produces it is relied upon rather than guarded.
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

	It("still refuses from the cache when the stored CRL cannot be read", func() {
		// The fallback, posed directly because no renewal can pose it: the two
		// sources have to disagree, and every route in leaves them agreeing.
		//
		// Revoking on myCA moves both — signCRLLocked writes storage and then
		// refreshes the cache — so corrupting the stored CRL afterwards leaves
		// the cache as the only source that can still answer, which is the
		// backend-blip shape this branch exists for.
		//
		// Without it the method returns nil here and the renewal it guards goes
		// through on a revoked certificate. Nothing else in the suite notices:
		// renew_test.go's corrupt-CRL specs run with a cache that says "not
		// revoked", where returning that answer and returning none are the same.
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())
		revoked, err := myCA.IsRevokedSerial(ctx, ownCrt.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(), "the cache must know, or this spec proves nothing")

		Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())

		Expect(myCA.reassertNotRevoked(ctx, ownCrt)).To(MatchError(ErrForeignCertificate))
	})

	// Both degraded outcomes are reported by a log line and nothing else — the
	// decision not to give them a metric is recorded in reassertNotRevoked — and
	// docs/api.md publishes both messages verbatim as things to alert on. That
	// makes the message text an operator interface, so these pin it. Without
	// them a reword during future CRL-cache work breaks every such alert with
	// the whole suite still green.
	Describe("the warnings docs/api.md tells operators to alert on", func() {
		var logged *bytes.Buffer

		BeforeEach(func() {
			logged = &bytes.Buffer{}
			restore := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(restore) })
		})

		// The whole message, from its first word: the opening clause names the
		// condition, so it is what an operator keys on and what a reword is most
		// likely to touch. And the attribute pairs, not the bare values, because
		// docs/api.md publishes the keys as well — rename `serial` and a
		// JSON-mode alert written against the documented field stops matching
		// while a bare-value assertion goes on finding the hex anywhere in the
		// line, including inside the message itself.
		It("says so when it refuses on storage and its own cache disagrees", func() {
			Expect(replica().Revoke(ctx, "node1.test")).To(Succeed())

			Expect(myCA.reassertNotRevoked(ctx, ownCrt)).To(MatchError(ErrForeignCertificate))
			Expect(logged.String()).To(ContainSubstring(
				"Refusing a renewal on the stored CRL; this replica's cached CRL still calls the certificate live"))
			Expect(logged.String()).To(ContainSubstring("subject=node1.test"))
			Expect(logged.String()).To(ContainSubstring("serial=" + serialHexStr(ownCrt.SerialNumber)))
		})

		It("stays quiet when both sources agree the certificate is revoked", func() {
			// The guard on that warning, not just the warning. Report every
			// refusal as a stale cache and the alert fires on ordinary
			// revocations too, which is worse than not having it.
			Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

			Expect(myCA.reassertNotRevoked(ctx, ownCrt)).To(MatchError(ErrForeignCertificate))
			Expect(logged.String()).NotTo(ContainSubstring("Refusing a renewal on the stored CRL"))
		})

		It("says so when it cannot read the stored CRL at all", func() {
			Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())

			Expect(myCA.reassertNotRevoked(ctx, ownCrt)).To(Succeed())
			Expect(logged.String()).To(ContainSubstring(
				"Renewal could not read the stored CRL; falling back to this replica's cached copy"))
			Expect(logged.String()).To(ContainSubstring("subject=node1.test"))
			Expect(logged.String()).To(ContainSubstring("serial=" + serialHexStr(ownCrt.SerialNumber)))
		})
	})
})
