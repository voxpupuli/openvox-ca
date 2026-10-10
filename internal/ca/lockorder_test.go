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

// White-box for the same reason renewrace_test.go is: lockNameBootstrap,
// lockNameCRL and lockSubjectPrefix are the only things that know what the
// locks are called, and c.mu is unexported. Spelling any of them a second time
// from outside the package would let the constants drift from the invariant
// these specs pin.
package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// This file automates docs/development/locking.md's **Lock ordering** section
// as a graph rather than as a list of callers.
//
// renewrace_test.go already pins `subject:<name>` → `crl` for the four callers
// that nest them, by parking each on a held subject lock and requiring the CRL
// lock to stay grantable — three of them as Entries in one DescribeTable, and
// Revoke as a standalone It beside it. That is the stronger check for those
// four, and this file does not replace it. What it adds is the half that check
// cannot give: it is a hand-maintained list of callers, so a *further* caller
// that nests two lock names — or a first caller that nests two *different*
// names — is protected by nothing until somebody remembers to extend it. #261 is the
// worked example: it adds a `bootstrap` → `hmac-key` nesting that no existing
// Entry would have noticed, and two of its review rounds were spent correcting
// prose claims about which nestings exist.
//
// So instead of enumerating pairs, the observer below watches every acquisition
// the driven CA paths make through StorageService.WithLock and reports the set
// of (outer, inner) pairs actually taken. "Instead of enumerating pairs" is the
// precise claim — the set of *callers* driven is still finite and listed under
// the limits below; what stops being hand-maintained is the set of lock pairs
// each of them is checked against. The specs then assert that
// set against allowedLockNesting. An inversion fails because the reversed pair
// is not in the table; a brand-new nesting fails because the new pair is not in
// the table either, which is the point — a new edge is protocol, and it should
// cost a deliberate line here and a matching line in the documentation.
//
// What this deliberately does *not* reach, stated because an allow-list that
// never sees a class of acquisition reports a clean graph for the same reason
// an empty grep reports no matches:
//
//   - **Tier 1 only.** c.mu and the StorageService mutexes are not named locks
//     and no backend wrapper can see them, so the tail of the documented order
//     (`… → c.mu → internal mutexes`) is covered by the narrower assertion in
//     "never holds c.mu across a lock acquisition" below rather than by the
//     edge table.
//   - **The paths these specs drive, and no others.** This is the sharpest
//     limit and the one that most qualifies "covers the graph". The observer is
//     passive: it records what the operations a spec calls actually do, so a
//     `WithLock` site no spec reaches contributes no edge and could be inverted
//     without failing anything here. The driven set is Init, Generate,
//     SaveRequest, Sign, Renew, AutoRenew, Revoke and Clean; it is a minority of
//     the call sites, and the counting rule is `c.Storage.WithLock` in non-test
//     `internal/ca` plus the sites in caImport.go that lock through a passed-in
//     store. Derive the totals from the tree rather than trusting a number
//     written here: which operations take which locks is under active change on
//     more than one branch, and a literal count in a comment goes stale in a
//     merge that conflicts with nothing and fails no spec. Untouched, among
//     others:
//     `SignWithTTL` and `DeleteRequest` (signing.go), `ImportCertificate`
//     (importcert.go), `ImportCACertificate` and the CRL import (caImport.go),
//     `RevokeSerial` (revoke.go), `CleanupExpiredCerts` (cleanup.go),
//     `seedSupportingState` (init.go), and the CRL refresh paths (crl.go). Extending the coverage
//     means driving the caller, not editing the table — which is the same kind
//     of manual step renewrace_test.go needs, moved from "add an Entry" to "add
//     an operation". The gain over the per-caller table is that ONE new
//     operation exercises every edge that operation takes, rather than one
//     assertion per pair somebody thought of.
//   - **This backend's acquisitions only.** The observer intercepts
//     AcquireSameHostLock on a filesystem backend, which is every lock
//     StorageService.WithLock takes here. It is *not* every lock the codebase
//     takes: backend-internal names are acquired through Backend.AcquireLock
//     directly, bypassing WithLock entirely — `sql-schema-migrate` from
//     SQLBackend.EnsureReady (internal/storage/sql.go), `inventory-decompose`
//     from EtcdBackend (internal/storage/etcd_inventory.go). Neither backend is
//     in play here, so neither name can appear; a harness over one of those
//     backends would see them and would need its own allow-list entries.
//   - **MigrateService.** It nests the *same* name over two different stores —
//     `bootstrap` (source) → `bootstrap` (destination), internal/storage/migrate.go
//     — and on a SQL destination reaches `sql-schema-migrate` at a third level
//     through EnsureReady. Because pairs here are keyed by lock *name* and not
//     by (store, name), driving it would record `("bootstrap", "bootstrap")`,
//     which reads as self-nesting and is not one: two stores, two locks. Keying
//     by name is the right choice for a single-store harness and the wrong one
//     for that path, so the path is out of scope rather than misrepresented.
//     locking.md covers it in prose, and the rule-9 spec below pins the part of
//     it that has operator-visible consequences.
//   - It asserts nothing about *which* operation took an edge. The per-caller
//     question is renewrace_test.go's, and answering it twice in two shapes
//     would mean two places to update for one change.
//
// The boundary above is why the first spec is a control on the instrumentation
// itself rather than on the CA.

// goID returns the calling goroutine's ID by parsing runtime.Stack's header.
//
// Test-only, and load-bearing rather than decorative: nesting is a property of
// one goroutine's acquisitions, and WithLock runs fn on the goroutine that
// acquired the lock. Without goroutine identity, two operations running
// concurrently would append to one shared stack and manufacture edges between
// locks that were never held together — the observer would report violations
// that did not happen, which is worse than reporting none.
//
// Go offers no supported accessor for this, and the parse is the standard
// workaround. The format ("goroutine 123 [running]:") has been stable since
// Go 1 and is exercised by every spec in this file, so a change to it fails
// here loudly rather than silently returning a constant.
func goID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	field := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	sp := strings.IndexByte(field, ' ')
	if sp < 0 {
		// Checked rather than sliced blind: IndexByte returns -1 when the
		// header is not the expected shape, and field[:-1] panics on a slice
		// bound -- which says nothing about runtime.Stack having changed, the
		// one thing a reader here needs to know.
		panic(fmt.Sprintf("unexpected runtime.Stack header %q", field))
	}
	field = field[:sp]
	id, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		// Panicking beats returning a sentinel: a shared fake ID would silently
		// collapse every goroutine onto one stack, which is the exact failure
		// this function exists to prevent.
		panic(fmt.Sprintf("cannot parse goroutine ID from %q: %v", field, err))
	}
	return id
}

// lockClass collapses `subject:<some.node>` to a single class. Two different
// subjects are two different locks, but they are one *edge* for ordering
// purposes, and keeping the node name would make the observed set depend on
// which fixtures a spec happens to use.
func lockClass(name string) string {
	if strings.HasPrefix(name, lockSubjectPrefix) {
		return lockSubjectPrefix + "<name>"
	}
	return name
}

// subjectClass is lockClass's answer for any per-subject lock, named once so
// the table below and the failure messages agree.
var subjectClass = lockSubjectPrefix + "<name>"

// allowedLockNesting is the set of (outer, inner) tier-1 acquisitions the CA
// layer is permitted to make, keyed by lock class. It is the machine-readable
// form of docs/development/locking.md's **Lock ordering** section, and the
// value is where that section says so.
//
// Adding an entry here is a protocol change. It means a new pair of named
// locks may now be held at once, which is a new way for two replicas to
// deadlock if any other path ever takes the pair the other way round. Add the
// entry and the documentation line together, or neither.
//
// Empty pairs are not listed: a lock taken with nothing else held is always
// fine and is not an edge. Pairs are keyed by lock *name*, not by (store,
// name) — see the MigrateService note at the top of this file for the one path
// where that distinction matters and why it is out of scope here.
//
// The table is a list of *permitted* pairs checked against *observed* ones, so
// an entry no spec exercises is harmless — `bootstrap` → `crl` is one, listed
// because it is real and documented rather than because anything here drives
// it. Do not read the table as an inventory of what is tested; the limits above
// say what is observed.
//
// One legitimate edge is knowingly absent, and this is where a future reader
// should look before concluding something broke.
//
// PR #261 adds a `bootstrap` → `hmac-key` nesting: MigrateService holds
// `bootstrap` across RebuildInventoryHMAC, which calls EnsureHMACKey. It is
// unlisted because `hmac-key` does not exist on this branch's base, and listing
// a name that no constant defines would be worse than omitting it.
//
// It does not fire here today, and the reason is narrower than "nothing in this
// package migrates" — internal/ca DOES drive MigrateService, in
// certindex_test.go. Two things keep the edge out of this observer:
//
//  1. The observer wraps only the backend built in this file's BeforeEach.
//     Other specs' stores are not instrumented, so their acquisitions are
//     invisible whatever they do.
//  2. Even instrumented, EnsureHMACKey returns on a fast path before taking any
//     lock when the stored key is well-formed, and every migration fixture in
//     internal/ca is built through a CA.Init that writes a valid 32-byte key.
//
// The second condition is one fixture away from flipping: seedCA in
// internal/storage/migrate_test.go deliberately seeds a 14-byte `hmac_key`, and
// a spec here copying that shape would reach the nesting. If that happens, or
// when #261 lands, the fix is to add the pair below together with the matching
// line in locking.md's Lock ordering section — it is a legitimate edge, not a
// regression, and the failure message will not know the difference.
var allowedLockNesting = map[[2]string]string{
	{subjectClass, lockNameCRL}: "locking.md, Lock ordering: `subject:<name>` → `crl` → `c.mu`. " +
		"Taken by Revoke, Clean, Renew, AutoRenew, ReconcileManaged and GenerateWithOptions " +
		"(the last on its ReplaceExisting path only, which no spec here drives); " +
		"renewrace_test.go pins the first four per-caller, " +
		"managedcert_reconcile_test.go the fifth, generate_test.go the sixth.",
	{lockNameBootstrap, lockNameCRL}: "locking.md, Lock ordering: `bootstrap` → `crl`. " +
		"ImportCACertificate holds bootstrap across importCAMaterial's CRL rewrite " +
		"(caImport.go). One-way: nothing takes crl and then bootstrap. Listed but not " +
		"exercised — no spec here drives ImportCACertificate.",
}

// lockOrderObserver wraps a filesystem backend and records every same-host lock
// acquisition, which on this backend is every acquisition StorageService.WithLock
// makes: FilesystemBackend implements SameHostLocker and not Locker, so WithLock
// finds no Locker and falls through to the same-host tier, which lands here.
// (Both are still locking.md's Tier 1 — "tier" means the top-level taxonomy
// everywhere in this file, and the Locker/SameHostLocker/mutex split is that
// document's *sub*-tiers.)
//
// The concrete backend is embedded rather than the Backend interface for the
// reason noSameHostLocks gives in renewrace_test.go: StorageService probes for
// several promoted methods and a wrapper that hid them would change more than
// the locking.
type lockOrderObserver struct {
	*storage.FilesystemBackend

	mu    sync.Mutex
	held  map[int64][]string // goroutine ID -> classes currently held, outermost first
	edges map[[2]string]int  // (outer, inner) class pair -> times observed
	names map[string]int     // raw lock name -> times acquired

	// probeCMu, when non-nil, is checked for being free at each acquisition.
	// See "never holds c.mu across a lock acquisition"; nil disables the probe.
	probeCMu   *sync.RWMutex
	cmuHeldFor []string
}

func newLockOrderObserver(dir string) *lockOrderObserver {
	return &lockOrderObserver{
		FilesystemBackend: storage.NewFilesystemBackend(dir),
		held:              map[int64][]string{},
		edges:             map[[2]string]int{},
		names:             map[string]int{},
	}
}

func (o *lockOrderObserver) AcquireSameHostLock(ctx context.Context, name string) (storage.Unlocker, error) {
	// Record the edge *before* acquiring, not after. An inverted order
	// deadlocks inside the acquisition — WithLock's godoc says so, because the
	// per-name gate ignores the context — so an observer that recorded after a
	// successful acquire would hang instead of reporting, and the spec would
	// fail as a timeout with nothing to read.
	o.observe(name)

	ul, err := o.FilesystemBackend.AcquireSameHostLock(ctx, name)
	if err != nil {
		o.release(name)
		return nil, err
	}
	return &observedUnlocker{o: o, name: name, Unlocker: ul}, nil
}

func (o *lockOrderObserver) observe(name string) {
	class := lockClass(name)
	gid := goID()

	o.mu.Lock()
	defer o.mu.Unlock()

	o.names[name]++
	for _, outer := range o.held[gid] {
		o.edges[[2]string{outer, class}]++
	}
	o.held[gid] = append(o.held[gid], class)

	if o.probeCMu != nil {
		// TryLock succeeds only when nothing holds c.mu, for read or for write.
		// The spec that enables this probe drives one operation at a time on one
		// goroutine, so a refusal means that goroutine holds it — which is the
		// violation. Under concurrency a peer's read lock would refuse too, so
		// the probe stays off there and the concurrent spec asserts completion
		// instead.
		//
		// **TryLock is load-bearing for deadlock-freedom, not only for the
		// meaning of the result. Do not change it to Lock.** o.mu is already
		// held here, so this path takes o.mu → c.mu; CA.Init takes them the
		// other way round, holding c.mu across WithLock and so reaching
		// observe() and o.mu beneath it. That is a genuine AB-BA pair, and the
		// only reason it cannot close is that TryLock never waits. A blocking
		// acquisition here would deadlock against Init — and would present as
		// exactly the hang this file exists to diagnose, which is the worst
		// possible disguise for it.
		if o.probeCMu.TryLock() {
			o.probeCMu.Unlock()
		} else {
			o.cmuHeldFor = append(o.cmuHeldFor, name)
		}
	}
}

func (o *lockOrderObserver) release(name string) {
	class := lockClass(name)
	gid := goID()

	o.mu.Lock()
	defer o.mu.Unlock()

	stack := o.held[gid]
	// Release the innermost matching entry rather than assuming the top: an
	// acquisition that failed unwinds out of order relative to one that
	// succeeded.
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == class {
			o.held[gid] = append(stack[:i], stack[i+1:]...)
			break
		}
	}
	if len(o.held[gid]) == 0 {
		delete(o.held, gid)
	}
}

// violations returns the observed edges that allowedLockNesting does not permit,
// formatted for a failure message. Sorted so a multi-edge failure reads the same
// way on every run.
func (o *lockOrderObserver) violations() []string {
	o.mu.Lock()
	defer o.mu.Unlock()

	var out []string
	for edge, count := range o.edges {
		if _, ok := allowedLockNesting[edge]; ok {
			continue
		}
		out = append(out, fmt.Sprintf("%q taken %d time(s) while holding %q", edge[1], count, edge[0]))
	}
	sort.Strings(out)
	return out
}

// edgeCount returns how many times one (outer, inner) pair has been observed.
//
// A count, for the reason acquisitions() is a count: membership is satisfied by
// whichever occurrence got there first, and that is routinely a setup step. This
// one is not hypothetical either — it is a trap set for a *future* merge. The
// BeforeEach calls Generate, which on this base takes no distributed lock; PR
// #189 gives it `subject:<name>` → `crl`, exactly the pair the DescribeTable
// below is checking its operation for. A HaveKey there would then be answered by
// the BeforeEach, in a branch that conflicts with nothing here and fails no
// spec. Comparing before and after the operation is immune to that.
func (o *lockOrderObserver) edgeCount(outer, inner string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.edges[[2]string{outer, inner}]
}

// acquisitions returns how many times name has been taken so far.
//
// A count rather than a set, and the difference is not cosmetic: an earlier
// step in the same spec routinely takes the very lock a later step is being
// checked for, so "was this name ever acquired" is satisfied by the wrong
// acquisition. The rule-9 spec below asserted exactly that at first and passed
// against a Sign that had had its lock removed altogether — the assertion was
// answered by the SaveRequest that set the spec up. Comparing a before/after
// count is what makes it discriminate.
func (o *lockOrderObserver) acquisitions(name string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.names[name]
}

// totalAcquisitions is the same question asked of the whole store, for specs
// that need to prove some lock was taken rather than a particular one.
func (o *lockOrderObserver) totalAcquisitions() int {
	o.mu.Lock()
	defer o.mu.Unlock()

	total := 0
	for _, n := range o.names {
		total += n
	}
	return total
}

func (o *lockOrderObserver) cmuViolations() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.cmuHeldFor...)
}

type observedUnlocker struct {
	storage.Unlocker
	o    *lockOrderObserver
	name string
}

func (u *observedUnlocker) Unlock() error {
	u.o.release(u.name)
	return u.Unlocker.Unlock()
}

var _ = Describe("The tier-1 lock ordering graph", func() {
	var (
		ctx      context.Context
		storeDir string
		obs      *lockOrderObserver
		store    *storage.StorageService
		myCA     *CA
		ownCrt   *x509.Certificate
		csrPEM   []byte
	)

	// csrFor builds a CSR without asserting, so it can be called from the
	// goroutines the concurrency spec runs: a failed Expect there is a panic to
	// recover rather than a spec failure to read.
	csrFor := func(subject string) ([]byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
	}

	BeforeEach(func() {
		ctx = context.Background()
		storeDir = GinkgoT().TempDir()
		obs = newLockOrderObserver(storeDir)
		store = storage.NewWithBackend(obs, storeDir+"/private")

		myCA = New(store, AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(res.CertificatePEM)
		Expect(block).NotTo(BeNil())
		ownCrt, err = x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		csrPEM, err = csrFor("node1.test")
		Expect(err).NotTo(HaveOccurred())
	})

	// Everything else in this file is an assertion about what the observer did
	// *not* see, and every one of them passes trivially if the observer sees
	// nothing at all. This is the control that rules that out.
	//
	// It is not hypothetical. StorageService.WithLock tries Locker first and
	// only falls through to SameHostLocker — where this observer sits — because
	// FilesystemBackend implements no AcquireLock. Give the filesystem backend a
	// Locker one day and every acquisition would route past this wrapper, the
	// edge table would stay empty, and every "no violations" assertion below
	// would keep passing while observing nothing whatsoever.
	//
	// So take a lock through the same public entry point the CA uses and require
	// it to have been recorded.
	It("observes locks taken through StorageService.WithLock", func() {
		const probe = "lockorder-probe"

		Expect(store.WithLock(ctx, probe, func() error { return nil })).To(Succeed())

		Expect(obs.acquisitions(probe)).To(Equal(1),
			"the observer did not see a lock taken through StorageService.WithLock, so "+
				"every ordering assertion in this file is vacuous. WithLock prefers the "+
				"Locker tier: if FilesystemBackend has gained an AcquireLock, acquisitions "+
				"now bypass AcquireSameHostLock and this wrapper must be moved to match.")
	})

	// The four callers that nest two named locks, one Ginkgo entry each. Each
	// entry gets a fresh observer and a fresh store from the BeforeEach, so the
	// entries are independent and order-insensitive under Ginkgo randomisation;
	// the c.mu probe is not armed here at all, only in its own spec below.
	//
	// Each entry re-establishes what it consumes, because Clean removes the
	// certificate the renewals need.
	DescribeTable("records only nestings the documentation permits",
		func(op func() error) {
			edgesBefore := obs.edgeCount(subjectClass, lockNameCRL)

			Expect(op()).To(Succeed())

			Expect(obs.violations()).To(BeEmpty(),
				"an acquisition was made while holding a lock that "+
					"docs/development/locking.md's Lock ordering section does not pair it with. "+
					"If the new nesting is intended, add it to allowedLockNesting *and* to that "+
					"section; if it is not, the order has been inverted.")

			// One-sided on its own: an operation that stopped taking the CRL
			// lock altogether would also report no violation. Require the edge
			// the caller is here for to have been taken *by this operation* —
			// a delta rather than membership, so a setup step that starts
			// producing the same edge cannot answer it. See edgeCount.
			Expect(obs.edgeCount(subjectClass, lockNameCRL)).To(BeNumerically(">", edgesBefore),
				"the operation must have nested the CRL lock inside the subject lock")
		},
		Entry("Revoke", func() error { return myCA.Revoke(context.Background(), "node1.test") }),
		Entry("Clean", func() error { return myCA.Clean(context.Background(), "node1.test") }),
		Entry("Renew", func() error {
			_, err := myCA.Renew(context.Background(), "node1.test", csrPEM, ownCrt)
			return err
		}),
		Entry("AutoRenew", func() error {
			_, err := myCA.AutoRenew(context.Background(), ownCrt)
			return err
		}),
	)

	// Rule 4: "release c.mu before entering another WithLock". c.mu is tier 3
	// and the bottom of the documented order, so holding it across a tier-1
	// acquisition inverts the order against every path that takes the lock
	// first and c.mu inside it — and inverts it in the direction that
	// deadlocks, since the acquisition's own gate ignores the context.
	//
	// No existing spec covers this. renewrace_test.go's table checks that the
	// *CRL* lock stays grantable, which says nothing about c.mu, and c.mu is
	// unexported so nothing outside this package can probe it at all.
	//
	// CA.Init is excluded deliberately rather than by accident: it holds c.mu
	// while acquiring `bootstrap`, which locking.md documents as a safe
	// inversion because Init completes before the server serves. The probe is
	// therefore armed after Init returns, in this spec's own body.
	It("never holds c.mu across a lock acquisition, outside CA.Init", func() {
		obs.mu.Lock()
		obs.probeCMu = &myCA.mu
		obs.mu.Unlock()
		armedAt := obs.totalAcquisitions()

		fresh, err := csrFor("node2.test")
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.SaveRequest(ctx, "node2.test", fresh)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(ctx, "node2.test")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.AutoRenew(ctx, ownCrt)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())
		Expect(myCA.Clean(ctx, "node2.test")).To(Succeed())

		Expect(obs.cmuViolations()).To(BeEmpty(),
			"c.mu was held while a distributed lock was acquired. locking.md rule 4 "+
				"requires it released first: it is the innermost tier, so holding it "+
				"across an acquisition inverts the order against every path that takes "+
				"the lock outside it, and that inversion deadlocks rather than timing out.")

		// The probe reports nothing if nothing was acquired, so prove the window
		// it inspects was actually entered — and prove it with a count taken
		// *after* arming. `> 0` was the first spelling and it was vacuous: the
		// BeforeEach's CA.Init takes `bootstrap` through this same observer, so
		// the total is already non-zero before probeCMu is set, and deleting the
		// WithLock from every operation below would have left this green.
		//
		// The floor is the exact number the five operations take, not one, for
		// the neighbouring reason: a bare delta is satisfied by any single
		// survivor while the other four have lost their locks. Measured rather
		// than assumed, and it is the sum of
		//
		//	SaveRequest  subject                 1
		//	Sign         subject                 1
		//	AutoRenew    subject + crl           2
		//	Revoke       subject + crl           2
		//	Clean        subject + crl           2
		//
		// so dropping any single WithLock below fails here.
		//
		// Two of the eight are conditional and this spec does not pin either
		// condition: AutoRenew's crl acquisition needs RevokeOnAutoRenew, which
		// defaults on, and Clean's needs a certificate to still be present.
		//
		// Equal, not >=, and for the reason a floor was written to address in
		// the first place. The count is deterministic — nothing in internal/ca
		// starts a background goroutine, and one goroutine drives everything
		// between arming and this read — so an exact match is safe, whereas a
		// floor silently stops discriminating the moment the real total rises
		// above it: at a true 9, dropping Sign's WithLock lands back on 8 and
		// passes. Equal fails in both directions and forces the deliberate
		// update rather than merely asking for one.
		const expectedAcquisitions = 8

		Expect(obs.totalAcquisitions()).To(Equal(armedAt+expectedAcquisitions),
			"the five operations below did not take exactly the locks this spec "+
				"expects while the probe was armed, so either one has stopped taking "+
				"a lock the probe inspects it through, or one has gained a lock and "+
				"expectedAcquisitions needs updating deliberately")
	})

	// The graph has documented *non*-edges as well, and rule 9 is the one with
	// operator-visible consequences: MigrateService holds `bootstrap` on both
	// stores, which excludes a booting server and deliberately does **not**
	// exclude per-subject signing — which is exactly why the documentation tells
	// operators to stop the server before migrating rather than relying on the
	// lock.
	//
	// Nothing tested that. It is the kind of contract a well-meaning change
	// quietly converts into a real edge — widening the migration lock, or
	// routing signing through `bootstrap` — and the result would look like a
	// safety improvement while turning a documented "stop the server" into a
	// silent stall bounded only by LockTimeout. Pinning it means such a change
	// has to be made deliberately, and the documentation updated with it.
	//
	// Requested by #259's author while reviewing this branch's lock graph.
	It("does not exclude per-subject signing while a migration holds bootstrap", func() {
		pending, err := csrFor("node3.test")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, "node3.test", pending)
		Expect(err).NotTo(HaveOccurred())

		// Hold `bootstrap` for the whole spec, as MigrateService does across a
		// migration. This is a real flock through the observer, not a stub: a
		// signing path that started taking the same name would genuinely block
		// on it rather than merely recording a second acquisition.
		locked, release := make(chan struct{}), make(chan struct{})
		held := make(chan error, 1)
		var releaseOnce sync.Once
		DeferCleanup(func() { releaseOnce.Do(func() { close(release) }) })
		go func() {
			defer GinkgoRecover()
			held <- store.WithLock(ctx, lockNameBootstrap, func() error {
				close(locked)
				<-release
				return nil
			})
		}()
		Eventually(locked).Should(BeClosed())

		// Bounded, but the bound is not what proves the point: a same-process
		// acquisition of a held name blocks on a mutex that ignores the
		// deadline, so a signing path that took `bootstrap` would hang here
		// rather than return a timeout. Eventually is what turns that hang into
		// a readable failure.
		// Snapshot before Sign runs: SaveRequest above already took this very
		// name, so only the delta can say whether Sign took it too.
		before := obs.acquisitions(subjectLockName("node3.test"))

		signed := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			_, err := myCA.Sign(ctx, "node3.test")
			signed <- err
		}()

		var signErr error
		Eventually(signed, 10*time.Second).Should(Receive(&signErr),
			"signing must not wait on the migration's bootstrap lock: locking.md rule 9 "+
				"says a migration and a concurrent Sign take different names and do not "+
				"exclude each other, which is why operators are told to stop the server")
		Expect(signErr).NotTo(HaveOccurred())

		releaseOnce.Do(func() { close(release) })
		Expect(<-held).To(Succeed())

		// The wait above is satisfied by a Sign that took no lock at all, so
		// confirm it really did take its own per-subject name while bootstrap
		// was held. That is the "different names" half of the contract, and it
		// has to be a delta: the first version of this assertion asked whether
		// the name had ever been seen, and passed against a Sign whose WithLock
		// had been deleted, because the SaveRequest above had already taken it.
		Expect(obs.acquisitions(subjectLockName("node3.test"))).To(BeNumerically(">", before),
			"Sign must still take its own subject lock; passing without one would mean "+
				"the exclusion was avoided by dropping the lock rather than by scoping it")
	})

	// The issue's own wording: drive the competing paths concurrently with a
	// bounded context and assert completion rather than timeout.
	//
	// Be exact about which assertion here is the detector, because the obvious
	// reading is wrong. **The edge assertion is what catches an inversion**, and
	// it catches it deterministically: inverting Revoke fails this spec in a
	// fraction of a second on `violations()`, not on the timeout. The timeout is
	// a *bound*, not a detector — it exists so that an interleaving which does
	// reach a genuine cycle presents as a readable failure instead of a suite
	// that never returns, since the per-name gate ignores the deadline.
	//
	// An earlier version of this spec gave every goroutine its own subject and
	// claimed the timeout as deadlock coverage. That claim was false: a cycle
	// needs two goroutines wanting *the same* subject in opposite orders, and
	// with disjoint subjects every inversion degrades to serialisation. The
	// contending pair below fixes the workload rather than the wording — two
	// different callers on one subject — so the cycle is at least reachable.
	// Reachable, not guaranteed: which of them wins the lock is not
	// deterministic, so the honest claim is that the edge table catches the
	// inversion and the bound keeps a cycle legible if one happens.
	It("completes concurrent work across subjects without deadlocking", func() {
		const subjects = 4

		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		// Set the contended subject up before anything is launched. It ran after
		// the workers at first, which put three unbounded, un-Eventually'd calls
		// on the main goroutine while five were already in flight: they take
		// c.mu, so the very regression this file's c.mu spec covers would park
		// the main goroutine here forever and the bound below — the thing that
		// exists to make a hang readable — would never be reached. A failing
		// Expect here would also unwind before wg.Wait(), leaving the workers
		// writing into a TempDir being torn down.
		const contended = "contend.test"
		contendCSR, err := csrFor(contended)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, contended, contendCSR)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(ctx, contended)
		Expect(err).NotTo(HaveOccurred())

		edgesBefore := obs.edgeCount(subjectClass, lockNameCRL)

		var wg sync.WaitGroup
		errs := make(chan error, subjects*3+4)

		// Every fallible setup step for this spec completes before any goroutine
		// starts, for the reason the contended pair below is hoisted: an Expect
		// that fails on iteration 2 unwinds the spec while iterations 0 and 1
		// are already running, leaving them racing the TempDir teardown. Ginkgo
		// does not wait for them, and the resulting failure names the cleanup
		// rather than the setup.
		type worker struct {
			subject string
			csr     []byte
		}
		workers := make([]worker, 0, subjects)
		for i := range subjects {
			subject := fmt.Sprintf("conc-%d.test", i)
			csr, err := csrFor(subject)
			Expect(err).NotTo(HaveOccurred())
			workers = append(workers, worker{subject: subject, csr: csr})
		}

		for _, w := range workers {
			subject, csr := w.subject, w.csr

			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				if _, err := myCA.SaveRequest(bounded, subject, csr); err != nil {
					errs <- fmt.Errorf("%s save: %w", subject, err)
					return
				}
				if _, err := myCA.Sign(bounded, subject); err != nil {
					errs <- fmt.Errorf("%s sign: %w", subject, err)
					return
				}
				if err := myCA.Clean(bounded, subject); err != nil {
					errs <- fmt.Errorf("%s clean: %w", subject, err)
				}
			}()
		}

		// A renew on the shared subject, contending with the four above for the
		// single `crl` lock while each of those holds its own per-subject lock.
		wg.Add(1)
		go func() {
			defer GinkgoRecover()
			defer wg.Done()
			if _, err := myCA.AutoRenew(bounded, ownCrt); err != nil {
				errs <- fmt.Errorf("autorenew: %w", err)
			}
		}()

		// The contending pair, and the only part of this workload where an
		// ordering cycle is reachable at all: two *different* callers racing for
		// *one* subject. Both take `subject:contend.test` then `crl`, so
		// inverting either one alone leaves the other holding what it wants —
		// which is the shape a deadlock needs and disjoint subjects can never
		// produce. Note a globally consistent reversal still cannot deadlock;
		// only a disagreement between two paths can, which is exactly what the
		// edge table forbids on the first acquisition either way.
		//
		// Both orderings return nil, so nothing needs tolerating and nothing is
		// tolerated. That is worth stating because the obvious guess is wrong
		// and an earlier version of this spec acted on it: `Clean` deletes only
		// the certificate blob, while `Revoke` resolves its serial from the
		// *inventory*, which survives — so Clean-then-Revoke still finds the
		// serial and re-revoking it is idempotent, and Revoke-then-Clean finds
		// the certificate still present. Neither races into a not-found.
		//
		// Tolerating one anyway would have been actively harmful rather than
		// merely dead: a wrapped fs.ErrNotExist reaches this point from a
		// *vanished CRL blob* too, via parseStoredCRL's "failed to load CRL",
		// so the suppression a race outcome seemed to justify would have hidden
		// exactly the storage-integrity failure a contended spec exists to
		// surface.
		report := func(label string, err error) {
			if err != nil {
				errs <- fmt.Errorf("%s: %w", label, err)
			}
		}

		wg.Add(2)
		go func() {
			defer GinkgoRecover()
			defer wg.Done()
			report("contended revoke", myCA.Revoke(bounded, contended))
		}()
		go func() {
			defer GinkgoRecover()
			defer wg.Done()
			report("contended clean", myCA.Clean(bounded, contended))
		}()

		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		Eventually(done, 40*time.Second).Should(BeClosed(),
			"concurrent CA operations did not all finish. This is the bound, not "+
				"the detector: an inverted lock order is normally caught by the edge "+
				"assertion below, and a hang here means an interleaving reached an "+
				"actual cycle, which never times out on its own because the per-name "+
				"gate ignores the deadline")

		close(errs)
		var failures []string
		for err := range errs {
			failures = append(failures, err.Error())
		}
		Expect(failures).To(BeEmpty())

		Expect(obs.violations()).To(BeEmpty(),
			"an acquisition under concurrency nested locks in a pair "+
				"docs/development/locking.md does not permit")
		Expect(obs.edgeCount(subjectClass, lockNameCRL)).To(BeNumerically(">", edgesBefore),
			"the concurrent run must have exercised the nesting it is checking")
	})
})
