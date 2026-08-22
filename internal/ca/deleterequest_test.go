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

// White-box, for the same reason as renewrace_test.go: the claim under test is
// that DeleteRequest takes one specific named lock, and subjectLockName is the
// only thing that knows what it is called. Spelling the string again from a
// black-box spec would leave a rename passing while the two halves diverged.
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
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// deleteFailBackend fails Delete on one subject's CSR key with a fault that is
// not os.ErrNotExist, standing in for a network backend that is reachable but
// refusing writes. It exists to separate the two things DeleteRequest's caller
// has to tell apart: an empty queue and a backend that could not empty it.
type deleteFailBackend struct {
	storage.Backend
	key string
	err error
}

func (b *deleteFailBackend) Delete(ctx context.Context, key string) error {
	if key == b.key {
		return b.err
	}
	return b.Backend.Delete(ctx, key)
}

// lockRefusingBackend refuses to grant the subject lock once armed, standing in
// for a cross-node acquisition that reaches a spent deadline. WithLock wraps
// that error and returns without running its closure at all, so this is the one
// failure DeleteRequest can report having touched no storage.
type lockRefusingBackend struct {
	storage.Backend
	refuse atomic.Bool
	err    error
}

func (b *lockRefusingBackend) AcquireLock(_ context.Context, _ string) (storage.Unlocker, error) {
	if b.refuse.Load() {
		return nil, b.err
	}
	return grantedDeleteLock{}, nil
}

type grantedDeleteLock struct{}

func (grantedDeleteLock) Unlock() error { return nil }

// inventoryHookBackend runs a hook when the inventory line for a newly issued
// certificate is appended. That call sits inside the issuance's subject lock
// but under inventoryMu, not fileMu — so unlike a hook on the CSR write, it
// does not itself block a concurrent DeleteCSR. It is the one point in
// SaveRequest's critical section where a delete's exclusion can be observed
// rather than inferred.
type inventoryHookBackend struct {
	storage.Backend
	onAppend func()
}

func (b *inventoryHookBackend) AppendLine(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	err := b.Backend.AppendLine(ctx, key, data, kind)
	if key == storage.KeyInventory && err == nil && b.onAppend != nil {
		b.onAppend()
	}
	return err
}

// DeleteRequest is the operator rejecting a pending request. Before it took the
// per-subject lock it raced every path that signs one: each reads the CSR under
// that lock and writes the certificate later in the same critical section, so an
// unlocked delete landing in between issued a certificate for a request the
// operator had just been told was gone (#196). The lock turns that race into an
// ordering, and the first spec here is the one that fails without it.
var _ = Describe("DeleteRequest", func() {
	var (
		ctx      context.Context
		storeDir string
		store    *storage.StorageService
		myCA     *CA
	)

	// csrFor builds a valid CSR for subject. Built outside the specs' goroutines
	// so the assertions here never run on one — a failed Expect there is a panic
	// to be recovered rather than a failure to be read.
	csrFor := func(subject string) []byte {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, key)
		Expect(err).NotTo(HaveOccurred())
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	}

	caOn := func(s *storage.StorageService) *CA {
		GinkgoHelper()
		c := New(s, AutosignConfig{Mode: "off"}, "puppet.test")
		c.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		c.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(c.Init(ctx)).To(Succeed())
		return c
	}

	BeforeEach(func() {
		ctx = context.Background()
		storeDir = GinkgoT().TempDir()
		store = storage.New(storeDir)
		myCA = caOn(store)

		_, err := myCA.SaveRequest(ctx, "node1.test", csrFor("node1.test"))
		Expect(err).NotTo(HaveOccurred())
		Expect(store.HasCSR(ctx, "node1.test")).To(BeTrue())
	})

	// parkOnSubjectLock holds the per-subject lock on s and returns a release
	// func, so the operation under test is parked in exactly the wait the fix
	// introduces rather than racing it.
	parkOnSubjectLock := func(s *storage.StorageService, subject string) func() {
		GinkgoHelper()
		locked, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
		// Registered before the goroutine exists so the holder unblocks on every
		// exit path. Without it a failed assertion aborts the spec with the
		// holder still parked and the operation blocked indefinitely: these
		// stores are filesystem-backed, so that wait is on a process-local
		// mutex, which no deadline ends (see StorageService.WithLock's godoc).
		//
		// Joining the parked operation is the caller's job, not this helper's:
		// the holder's closure touches no storage, so it is the operation that
		// races TempDir teardown, and it has to be released before it can be
		// joined.
		DeferCleanup(releaseFn)
		go func() {
			defer GinkgoRecover()
			Expect(s.WithLock(ctx, subjectLockName(subject), func() error {
				close(locked)
				<-release
				return nil
			})).To(Succeed())
		}()
		Eventually(locked).Should(BeClosed())
		return releaseFn
	}

	It("waits for the subject lock rather than deleting underneath its holder", func() {
		release := parkOnSubjectLock(store, "node1.test")

		deleted := make(chan error, 1)
		finished := make(chan struct{})
		go func() {
			defer GinkgoRecover()
			defer close(finished)
			deleted <- myCA.DeleteRequest(ctx, "node1.test")
		}()
		// Release first, then wait for the delete to actually return: on a
		// failure path it is still parked, and unparking it only starts the
		// os.Remove that TempDir's cleanup — registered earlier, so it runs
		// later — is about to race.
		DeferCleanup(func() {
			release()
			Eventually(finished).Should(BeClosed())
		})

		// The claim, and the whole fix: while a signing path holds the lock the
		// CSR it is about to read is still there. Without the lock the delete
		// returns here and the CSR is already gone — which is the interleaving
		// that issues a certificate for a rejected request.
		Consistently(deleted, 200*time.Millisecond, 20*time.Millisecond).ShouldNot(Receive(),
			"DeleteRequest returned while the subject lock was held: it is deleting the CSR "+
				"outside the lock, so a sign already inside can still read and sign it")
		Expect(store.HasCSR(ctx, "node1.test")).To(BeTrue())

		release()
		Eventually(deleted).Should(Receive(BeNil()))
		Expect(store.HasCSR(ctx, "node1.test")).To(BeFalse())
	})

	It("cannot delete inside SaveRequest's evict/save/autosign section", func() {
		// The other half of #196, and the one an agent sees: SaveRequest holds
		// the subject lock across evict/save/autosign, and an unlocked delete
		// landing between SaveCSR and the sign made that sign fail with "CSR
		// not found" — turning a submission into a 5xx rather than a clean save
		// or a clean rejection.
		//
		// Driven from the inventory append inside the autosign's issuance,
		// which is the observable point in that critical section: a hook on the
		// CSR write would sit inside SaveCSR's own fileMu and block the delete
		// on that mutex whether or not the subject lock existed, proving the
		// wrong thing.
		dir := GinkgoT().TempDir()
		hooked := &inventoryHookBackend{Backend: storage.NewFilesystemBackend(dir)}
		st := storage.NewWithBackend(hooked, filepath.Join(dir, "private"))
		autoCA := New(st, AutosignConfig{Mode: "true"}, "puppet.test")
		autoCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		autoCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(autoCA.Init(ctx)).To(Succeed())

		deleted := make(chan error, 1)
		deleteDone := make(chan struct{})
		// reached is closed by the hook immediately before it launches the
		// delete, so it doubles as "was a goroutine started at all".
		reached := make(chan struct{})
		DeferCleanup(func() {
			select {
			case <-reached:
				// SaveRequest has returned by now, so the delete is unparked;
				// wait for its os.Remove to finish before TempDir's cleanup
				// removes the directory under it.
				Eventually(deleteDone).Should(BeClosed())
			default: // the hook never fired; nothing to join
			}
		})
		// Runs on the SaveRequest goroutine, which is this spec's own, so the
		// assertion inside it is a spec failure rather than a recovered panic.
		hooked.onAppend = func() {
			select {
			case <-reached:
				// Defensive: this spec issues exactly once, so the hook fires
				// once. Init does not append — it reaches the inventory only
				// through TouchInventory, which Puts an empty blob — and
				// onAppend is assigned after Init returns in any case.
				return
			default:
			}
			close(reached)
			go func() {
				defer GinkgoRecover()
				defer close(deleteDone)
				deleted <- autoCA.DeleteRequest(ctx, "node2.test")
			}()
			Consistently(deleted, 200*time.Millisecond, 20*time.Millisecond).ShouldNot(Receive(),
				"a DeleteRequest completed inside SaveRequest's locked section; "+
					"the autosign it is racing can still fail with \"CSR not found\"")
		}

		signed, err := autoCA.SaveRequest(ctx, "node2.test", csrFor("node2.test"))
		Expect(err).NotTo(HaveOccurred())
		Expect(signed).To(BeTrue())
		Expect(st.HasCert(ctx, "node2.test")).To(BeTrue())

		// Once SaveRequest releases the lock the delete runs. Signing has
		// already consumed the CSR, so it finds an empty queue: the rejection
		// lands after an issuance it could not overtake, rather than corrupting
		// it.
		Eventually(deleted).Should(Receive(MatchError(ErrNoCSR)))
	})

	It("returns ErrNoCSR when there is no pending CSR", func() {
		Expect(myCA.DeleteRequest(ctx, "ghost.test")).To(MatchError(ErrNoCSR))
	})

	It("rejects an invalid subject as invalid, not as a storage error", func() {
		// Asserted on the message rather than on bare failure. Remove
		// ValidateSubject and the traversal subject still fails — the backend's
		// own validateKey refuses the "csr/a..b" key — so NotTo(Succeed())
		// would pass either way and prove nothing about which layer refused.
		// The message is what distinguishes the CA's guard from the backend's
		// backstop, and only the CA's runs before the lock is taken.
		err := myCA.DeleteRequest(ctx, "a..b")
		Expect(err).To(MatchError(ContainSubstring("invalid subject name")))
		Expect(err).NotTo(MatchError(ContainSubstring("invalid key")))
		Expect(store.HasCSR(ctx, "node1.test")).To(BeTrue())
	})

	It("reports a refused lock as a failure, leaving the CSR queued", func() {
		// The failure the handler's comment actually names, and the one no
		// other spec reaches: WithLock rejects the acquisition and returns
		// before its closure runs, so DeleteCSR is never called and the
		// fs.ErrNotExist classification inside it never gets a say. Without
		// this, the branch that answers 503 rather than 404 is covered only by
		// inference from the injected-backend spec.
		dir := GinkgoT().TempDir()
		injected := errors.New("lock acquisition refused")
		backend := &lockRefusingBackend{Backend: storage.NewFilesystemBackend(dir), err: injected}
		refusing := storage.NewWithBackend(backend, filepath.Join(dir, "private"))
		refusingCA := caOn(refusing)
		_, err := refusingCA.SaveRequest(ctx, "node1.test", csrFor("node1.test"))
		Expect(err).NotTo(HaveOccurred())

		backend.refuse.Store(true)
		err = refusingCA.DeleteRequest(ctx, "node1.test")
		Expect(err).To(MatchError(injected))
		Expect(err).NotTo(MatchError(ErrNoCSR))

		// The rejection the operator was told about must not have happened.
		backend.refuse.Store(false)
		Expect(refusing.HasCSR(ctx, "node1.test")).To(BeTrue())
	})

	It("reports a backend failure as a failure, not as an absent CSR", func() {
		// The distinction the HTTP layer turns into 503 rather than 404. Collapse
		// the two and a delete that could not run answers "CSR not found" while
		// the request is still queued and still signable.
		dir := GinkgoT().TempDir()
		injected := errors.New("backend unavailable")
		faulty := storage.NewWithBackend(
			&deleteFailBackend{
				Backend: storage.NewFilesystemBackend(dir),
				key:     storage.CSRKey("node1.test"),
				err:     injected,
			},
			filepath.Join(dir, "private"),
		)
		faultyCA := caOn(faulty)
		_, err := faultyCA.SaveRequest(ctx, "node1.test", csrFor("node1.test"))
		Expect(err).NotTo(HaveOccurred())

		err = faultyCA.DeleteRequest(ctx, "node1.test")
		Expect(err).To(MatchError(injected))
		Expect(err).NotTo(MatchError(ErrNoCSR))
		Expect(faulty.HasCSR(ctx, "node1.test")).To(BeTrue())
	})
})
