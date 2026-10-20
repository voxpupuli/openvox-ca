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

// White-box: drainDueLocked and drainOutcome are unexported, and this spec
// exists to constrain them specifically rather than the sweep around them.
package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// drainDueLocked is the batched drain issue #176 produced: one CRL read, one
// signature and one write for all the due entries, where it used to be one of
// each per entry. These specs state the contract that batching had to keep, and
// they were written against the per-entry loop before it was replaced — so they
// check a property rather than the shape of either implementation.
//
// The property is drainOutcome's total: every entry handed in comes back in
// exactly one disposition. An entry that falls out of all four is a certificate
// left valid with nothing recording that it should not be — which is precisely
// the defect review round 2 found here, where deferred entries were named in
// the log line and then dropped from the write-back. A scenario spec caught
// that one after the fact; this one states the invariant it violated.
// recordSuperseded is what makes the stored form canonical. Its two callers
// disagree: AutoRenew passes serialHexStr of the presented certificate, already
// canonical, while Renew passes LatestSerialForSubject, which returns inventory
// text verbatim — and a migrated or older inventory carries zero-padded
// serials. Only a white-box call can feed it a genuinely non-canonical value:
// a spec driving Renew against a fresh store cannot, because that store's
// inventory is already canonical, which is precisely how a spec written that
// way passes whether or not the canonicalisation exists.
var _ = Describe("recordSuperseded", func() {
	var (
		ctx   context.Context
		store *storage.StorageService
		myCA  *CA
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = New(store, AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	stored := func() []supersededEntry {
		GinkgoHelper()
		entries, corrupt, err := myCA.readSuperseded(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(corrupt).To(BeFalse())
		return entries
	}

	DescribeTable("stores the canonical rendering, whatever form it is given",
		func(given, want string) {
			Expect(myCA.recordSuperseded(ctx, "node.test", given, time.Hour)).To(Succeed())
			entries := stored()
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Serial).To(Equal(want),
				"refuseIfSuperseded compares this against serialHexStr of a presented "+
					"certificate; a non-canonical stored form makes that comparison miss, and "+
					"that comparison is the only thing stopping a superseded credential "+
					"renewing itself")
		},
		Entry("zero-padded, as a migrated inventory carries", "000ABC", "ABC"),
		Entry("lowercase", "abc", "ABC"),
		Entry("lowercase and padded", "000abc", "ABC"),
		Entry("already canonical", "ABC", "ABC"),
		Entry("surrounding whitespace", " ABC ", "ABC"),
	)

	It("refuses a serial that is not hexadecimal at all", func() {
		before := myCA.SupersedeFailures()
		Expect(myCA.recordSuperseded(ctx, "node.test", "not-hex", time.Hour)).NotTo(Succeed())
		Expect(stored()).To(BeEmpty())
		Expect(myCA.SupersedeFailures()).To(Equal(before + 1))
	})
})

var _ = Describe("drainDueLocked", func() {
	var (
		ctx    context.Context
		store  *storage.StorageService
		myCA   *CA
		leaves []*x509.Certificate
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = New(store, AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = KeyConfig{Algo: KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		leaves = nil
		for i := range 3 {
			res, err := myCA.Generate(ctx, fmt.Sprintf("drain%d.test", i), nil)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(res.CertificatePEM)
			crt, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			leaves = append(leaves, crt)
		}
	})

	// entry builds a due entry for one of the generated leaves.
	entry := func(i int) supersededEntry {
		return supersededEntry{
			Serial:   serialHexStr(leaves[i].SerialNumber),
			Subject:  fmt.Sprintf("drain%d.test", i),
			RevokeAt: time.Now().UTC().Add(-time.Hour),
		}
	}

	// drain runs one pass under the locks drainDueLocked requires.
	drain := func(passCtx context.Context, due []supersededEntry) drainOutcome {
		GinkgoHelper()
		var out drainOutcome
		Expect(store.WithLock(passCtx, lockNameCRL, func() error {
			myCA.mu.Lock()
			defer myCA.mu.Unlock()
			out = myCA.drainDueLocked(passCtx, due)
			return nil
		})).To(Succeed())
		return out
	}

	// accounted is the invariant: the four dispositions partition the input.
	accounted := func(out drainOutcome) int {
		return out.revoked + len(out.failed) + len(out.deferred) + out.discarded
	}

	It("accounts for every entry when all of them can be revoked", func() {
		due := []supersededEntry{entry(0), entry(1), entry(2)}
		out := drain(ctx, due)

		Expect(accounted(out)).To(Equal(len(due)),
			"every due entry must land in exactly one disposition; one that lands in none is a "+
				"certificate left valid with nothing recording that it should not be")
		Expect(out.revoked).To(Equal(3))
		Expect(out.deferred).To(BeEmpty())
	})

	It("accounts for every entry when one can never be revoked", func() {
		due := []supersededEntry{entry(0), {Serial: "not-hex", Subject: "bad.test"}, entry(1)}
		out := drain(ctx, due)

		Expect(accounted(out)).To(Equal(len(due)))
		Expect(out.discarded).To(Equal(1))
		Expect(out.revoked).To(Equal(2),
			"a malformed serial must not stop the entries around it being revoked")
	})

	// The per-entry loop stopped part-way on a short deadline, because N
	// entries cost N re-signs and a large backlog could not fit in one lock
	// hold. One re-sign for all of them removes that, so the pass no longer
	// rations itself: the property still holds, but by attempting every entry
	// rather than by returning the ones it declined to attempt.
	It("attempts every due entry on a deadline that used to ration the pass", func() {
		due := []supersededEntry{entry(0), entry(1), entry(2)}
		// Below what the old reserve check (LockTimeout/2) would have allowed,
		// so the pre-batch loop revoked one entry here and deferred two.
		shortCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out := drain(shortCtx, due)

		Expect(accounted(out)).To(Equal(len(due)))
		Expect(out.revoked).To(Equal(3),
			"one re-sign covers the whole backlog, so a short deadline no longer rations it")
		Expect(out.deferred).To(BeEmpty(),
			"nothing defers since #176; the field is kept for a future implementation that "+
				"has to stop part-way, and the caller that carries it forward is unchanged")
	})

	// Batched, this is the shared failure the drain always had: a CRL this
	// replica cannot read, sign or write fails the pass however the entries are
	// grouped. What must not change is where the entries end up — failed keeps
	// them on the list, so the next pass retries them.
	It("accounts for every entry when the batch cannot be written", func() {
		// An unparseable stored CRL fails the batch's read without making any
		// of its entries unrevocable.
		Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())
		due := []supersededEntry{entry(0), entry(1)}
		before := myCA.CRLUpdateFailures()
		out := drain(ctx, due)

		Expect(accounted(out)).To(Equal(len(due)))
		Expect(out.failed).To(HaveLen(2), "a failed revocation must be retried, so it stays listed")
		Expect(out.revoked).To(BeZero())

		// The cardinality this PR told operators to expect. Two entries failed
		// together and the counter moved once, because one re-sign covers the
		// batch — mixin/alerts.libsonnet and docs/metrics.md both say a rising
		// openvoxca_crl_update_failures_total counts failed CRL amendments
		// rather than certificates left unrevoked, and nothing else pins that.
		// Equal, not BeNumerically(">"): counting once per entry here is
		// precisely the pre-batch behaviour, and it would satisfy a
		// greater-than.
		Expect(myCA.CRLUpdateFailures()).To(Equal(before+1),
			"a failed pass must move crl_update_failures once, not once per due entry")
	})

	It("returns an empty outcome for no entries", func() {
		out := drain(ctx, nil)
		Expect(accounted(out)).To(BeZero())
	})

	// The dispositions are not interchangeable: two of them keep the entry on
	// the list and one drops it, so a batched implementation that reported a
	// failure as a discard would silently lose the certificate.
	It("keeps a failed entry and drops only an unrevocable one", func() {
		bad := supersededEntry{Serial: "zz-not-hex", Subject: "bad.test"}
		Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())
		out := drain(ctx, []supersededEntry{entry(0), bad})

		Expect(out.discarded).To(Equal(1), "only the malformed serial may be discarded")
		Expect(out.failed).To(HaveLen(1))
		Expect(out.failed[0].Serial).To(Equal(serialHexStr(leaves[0].SerialNumber)),
			"the entry that merely failed must be the one carried forward")
		Expect(out.revoked).To(BeZero())
	})

	// Guards the one thing #176's godoc tells a batched implementation it must
	// not do: hand a malformed serial to the batch. Now that the re-sign is
	// batched this is no longer one lost entry — the whole batch shares a
	// single signature, so a serial that cannot be parsed fails every valid
	// entry beside it, and since a failed batch carries all of its entries
	// forward it does so again on every pass after this one. One unrevocable
	// entry would stall every pending revocation on the CA.
	It("never offers an unrevocable serial to the revocation step", func() {
		due := []supersededEntry{{Serial: "not-hex", Subject: "bad.test"}, entry(0)}
		out := drain(ctx, due)

		Expect(out.revoked).To(Equal(1),
			"the valid entry beside a malformed one must still be revoked; a batch that "+
				"accepted the malformed serial would have failed this one too")
		Expect(out.failed).To(BeEmpty(),
			"the malformed entry must be filtered out before revocation, not fail inside it")
		Expect(out.discarded).To(Equal(1),
			"and it must be discarded rather than carried forward: it can never be revoked, "+
				"so retrying it would stall the batch on every pass forever")
	})

	// countingCAKey wraps the CA's signing key and counts the signatures taken
	// through it.
	//
	// This is the only observer that can tell the batched drain apart from the
	// per-entry loop it replaced. From outside, both leave the same
	// certificates on the CRL, and every spec above passes under either — which
	// is exactly why the assertion this enables is the one most likely to be
	// omitted. One signature per pass rather than one per entry is the whole
	// point of #176: it is a CRL read, a signature and a write of the fleet's
	// entire revocation history, taken under the lock every revocation and
	// every OCSP lookup on every replica is waiting for, and under
	// ca_key_provider: openbao it is a remote Transit round trip.
	//
	// It is installed after Init and after the leaves are generated, so its
	// count starts at zero and every signature it sees belongs to the pass
	// under test. That also makes the assertion non-vacuous in both directions:
	// a wrapper that was never reached counts 0 and fails Equal(1) just as
	// loudly as a per-entry loop counting 3.
	countSignatures := func() *countingCAKey {
		GinkgoHelper()
		counter := &countingCAKey{Signer: myCA.CAKey}
		myCA.CAKey = counter
		return counter
	}

	// crlSerials returns the canonical serials currently on the stored CRL.
	crlSerials := func() []string {
		GinkgoHelper()
		stored, err := myCA.parseStoredCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		serials := make([]string, 0, len(stored.own.RevokedCertificateEntries))
		for _, e := range stored.own.RevokedCertificateEntries {
			serials = append(serials, serialHexStr(e.SerialNumber))
		}
		return serials
	}

	// captureLogs collects what fn logs, the same way revokeserial_test.go does.
	captureLogs := func(fn func()) string {
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		defer slog.SetDefault(orig)
		fn()
		return buf.String()
	}

	// crlEntryTimes maps each canonical serial on the stored CRL to the
	// revocation time recorded for it.
	crlEntryTimes := func() map[string]time.Time {
		GinkgoHelper()
		stored, err := myCA.parseStoredCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		times := make(map[string]time.Time, len(stored.own.RevokedCertificateEntries))
		for _, e := range stored.own.RevokedCertificateEntries {
			times[serialHexStr(e.SerialNumber)] = e.RevocationTime
		}
		return times
	}

	// crlNumber is the sequence number of the stored CRL. signCRLLocked bumps
	// it by exactly one per re-sign, so its delta counts CRL writes the way
	// countingCAKey counts signatures.
	crlNumber := func() int64 {
		GinkgoHelper()
		stored, err := myCA.parseStoredCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored.own.Number).NotTo(BeNil())
		return stored.own.Number.Int64()
	}

	// This is #176's actual claim, and nothing else in this file tests it: the
	// cost of a pass is one signature, not one per due entry.
	It("signs the CRL once for a batch of entries, not once per entry", func() {
		due := []supersededEntry{entry(0), entry(1), entry(2)}
		counter := countSignatures()
		before := crlNumber()

		out := drain(ctx, due)

		Expect(out.revoked).To(Equal(3))
		Expect(counter.count()).To(Equal(1),
			"three due entries must cost one CA-key signature; one per entry is the "+
				"stall #176 exists to remove, and under ca_key_provider: openbao it is one "+
				"remote Transit round trip per entry")
		Expect(crlNumber()).To(Equal(before+1),
			"and one CRL write: signCRLLocked bumps the number once per re-sign")
	})

	// The signature count says the batch signed once. It does not say the batch
	// carried every entry, and a batch that quietly dropped one would still
	// sign once — so this names each serial it expects to find. The fixture
	// cannot satisfy it: Generate does not revoke, so the CRL is empty until
	// this drain writes to it, and the three leaves carry distinct serials.
	It("puts every entry in the batch on the CRL", func() {
		due := []supersededEntry{entry(0), entry(1), entry(2)}
		Expect(crlSerials()).To(BeEmpty(),
			"the CRL must start empty, or a serial found afterwards proves nothing")

		out := drain(ctx, due)
		Expect(out.revoked).To(Equal(3))

		// Per serial before the count, deliberately: a length check fails first
		// and reports a number, leaving the reader to work out which entry went
		// missing. These name it.
		listed := crlSerials()
		for _, e := range due {
			Expect(listed).To(ContainElement(e.Serial),
				"the batch reported this entry revoked, so the CRL must list it: "+e.Serial+
					" ("+e.Subject+")")
		}
		Expect(listed).To(HaveLen(3),
			"and no more: an entry appended twice grows the CRL without bound")
	})

	// A pass over entries another replica has already revoked must cost
	// nothing. Without the no-op guard this is a signature and a CRL write on
	// every sweep interval, forever, on every replica that loses the race.
	It("does not re-sign when every entry is already revoked", func() {
		due := []supersededEntry{entry(0), entry(1)}
		Expect(drain(ctx, due).revoked).To(Equal(2))

		counter := countSignatures()
		before := crlNumber()
		out := drain(ctx, due)

		Expect(out.revoked).To(Equal(2),
			"a serial already on the CRL is revoked, so the entry may be pruned from the list")
		Expect(counter.count()).To(BeZero(), "nothing changed, so nothing may be signed")
		Expect(crlNumber()).To(Equal(before), "and nothing may be written")
		Expect(crlSerials()).To(HaveLen(2), "and no entry may be appended twice")
	})

	// The mixed batch: some serials already on the CRL, some not. Every other
	// spec here drives one extreme or the other — all new, or all already
	// listed — and the dedup loop's two arms only meet in one call in this
	// case. It is also the realistic recovery shape: a replica that wrote the
	// CRL and then failed to prune the pending list leaves an already-revoked
	// serial due again beside genuinely new ones on the next pass.
	It("appends only the new serials when the batch overlaps the CRL", func() {
		// Revoke leaf 0 on its own, so the second drain meets it already listed.
		Expect(drain(ctx, []supersededEntry{entry(0)}).revoked).To(Equal(1))
		wasRevokedAt := crlEntryTimes()[entry(0).Serial]
		Expect(wasRevokedAt).NotTo(BeZero(), "the setup must actually have revoked leaf 0")

		counter := countSignatures()
		beforeNumber := crlNumber()
		out := drain(ctx, []supersededEntry{entry(0), entry(1)})

		Expect(out.revoked).To(Equal(2),
			"both entries name a certificate that is on the CRL once this returns, so both "+
				"may be pruned from the pending list")
		Expect(out.failed).To(BeEmpty())

		// One signature, not zero and not two: the batch has something new to
		// add, so the appended==0 short-circuit must not fire, and the entry it
		// already had must not be appended again.
		Expect(counter.count()).To(Equal(1),
			"a batch with anything new in it re-signs exactly once")
		Expect(crlNumber()).To(Equal(beforeNumber + 1))

		listed := crlSerials()
		Expect(listed).To(ContainElement(entry(1).Serial),
			"the new entry must be appended: "+entry(1).Serial)
		Expect(listed).To(ContainElement(entry(0).Serial),
			"and the one already listed must survive the re-sign: "+entry(0).Serial)
		Expect(listed).To(HaveLen(2),
			"exactly one entry added; a second copy of the already-listed serial is the "+
				"unbounded-growth defect the dedup exists to prevent")

		// The re-sign must carry the entry it already had through unchanged
		// rather than rebuilding it at the current time.
		Expect(crlEntryTimes()[entry(0).Serial]).To(Equal(wasRevokedAt),
			"re-revoking a listed serial must not restamp it on the CRL")
	})

	// The revocation time appendCRLEntriesLocked reports back, which is what
	// drainDueLocked hands markCertRevokedIndex. Asserted on the returned map
	// rather than through a drain, deliberately: the index projection is where
	// a restamp would show, and this fixture's filesystem backend has no
	// certificate index, so MarkCertRevoked is a no-op and a spec driving the
	// drain would assert nothing. The CRL check above cannot stand in for it —
	// the CRL keeps the original entry either way.
	It("reports the original revocation time for a serial the CRL already listed", func() {
		Expect(drain(ctx, []supersededEntry{entry(0)}).revoked).To(Equal(1))
		wasRevokedAt := crlEntryTimes()[entry(0).Serial]
		Expect(wasRevokedAt).NotTo(BeZero())

		var got map[string]time.Time
		Expect(store.WithLock(ctx, lockNameCRL, func() error {
			myCA.mu.Lock()
			defer myCA.mu.Unlock()
			var err error
			got, err = myCA.appendCRLEntriesLocked(ctx,
				[]*big.Int{leaves[0].SerialNumber, leaves[1].SerialNumber})
			return err
		})).To(Succeed())

		Expect(got).To(HaveKey(entry(0).Serial))
		Expect(got[entry(0).Serial]).To(Equal(wasRevokedAt),
			"a serial already on the CRL must report when it was revoked, not when this "+
				"pass noticed it; the certificate index records what this returns")
		Expect(got[entry(1).Serial]).NotTo(Equal(wasRevokedAt),
			"and a serial this call appended must carry this call's timestamp")
	})

	// Batching collapsed N revocations into one re-sign, and it must not also
	// collapse N identities into a count. These certificates are still valid
	// credentials past the window their supersession granted them, and
	// OpenVoxCASupersedeFailing's runbook closes by telling an operator to
	// retire what the sweep will not with `openvox-ca-ctl revoke --serial
	// <hex>` — a serial the failure line has to carry for that instruction to
	// be followable. The per-entry loop named each one as it failed.
	It("names every certificate it could not revoke, not just how many", func() {
		Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())
		due := []supersededEntry{entry(0), entry(1)}

		var out drainOutcome
		logs := captureLogs(func() { out = drain(ctx, due) })
		Expect(out.failed).To(HaveLen(2), "the batch must actually have failed")

		for _, e := range due {
			Expect(logs).To(ContainSubstring(e.Serial),
				"the operator's remedy takes this serial as its argument, so the failure "+
					"line must carry it: "+e.Serial+" ("+e.Subject+")")
			Expect(logs).To(ContainSubstring(e.Subject),
				"and the subject is what an operator recognises: "+e.Subject)
		}
	})

	// Inventory serials are not canonical — a store migrated from Puppet
	// carries zero-padded ones — so the same certificate can reach the batch
	// under two spellings. Compared raw they look like two revocations, and the
	// batch appends both in one go, where the per-entry loop could not: its
	// second call re-read a CRL its first had already amended. Growing the CRL
	// without bound is what revokeSerialLocked's duplicate check exists to
	// prevent, and this is the batch's version of it.
	It("appends one CRL entry for two spellings of the same serial", func() {
		canonical := entry(0)
		padded := canonical
		padded.Serial = "000" + strings.ToLower(canonical.Serial)
		padded.Subject = "padded.test"

		counter := countSignatures()
		out := drain(ctx, []supersededEntry{canonical, padded})

		Expect(out.revoked).To(Equal(2),
			"both entries name a certificate that is now revoked, so both may be pruned")
		Expect(out.discarded).To(BeZero(), "a zero-padded serial is revocable, not malformed")
		Expect(counter.count()).To(Equal(1))
		Expect(crlSerials()).To(ConsistOf(canonical.Serial),
			"one certificate, one CRL entry, whatever spelling it arrived as")
	})

	// storage.NormaliseSerial is the validator recordSuperseded writes the list
	// through, and using it here rather than a bare big.Int parse is what keeps
	// the two in step. It is stricter in one direction and looser in the other,
	// and both differences are the pending list and the CRL agreeing.
	DescribeTable("classifies a serial the way the list's own validator does",
		func(serial string, wantRevoked, wantDiscarded int) {
			out := drain(ctx, []supersededEntry{{Serial: serial, Subject: "odd.test"}})
			Expect(out.revoked).To(Equal(wantRevoked))
			Expect(out.discarded).To(Equal(wantDiscarded))
			Expect(out.failed).To(BeEmpty(),
				"neither classification may reach the batch and fail inside it")
		},
		// A negative serial parses as a big.Int and no certificate can carry
		// one, so the bare parse this replaced handed it on as revocable.
		Entry("negative", "-1", 0, 1),
		Entry("empty", "", 0, 1),
		Entry("not hexadecimal", "not-hex", 0, 1),
	)

	It("revokes a serial that is merely spelled untidily", func() {
		// Surrounding whitespace: NormaliseSerial trims it, the bare parse this
		// replaced discarded the entry outright, and recordSuperseded would
		// have stored it canonically in the first place.
		untidy := entry(0)
		untidy.Serial = " " + strings.ToLower(untidy.Serial) + " "

		out := drain(ctx, []supersededEntry{untidy})

		Expect(out.discarded).To(BeZero())
		Expect(out.revoked).To(Equal(1))
		Expect(crlSerials()).To(ConsistOf(entry(0).Serial))
	})
})

// countingCAKey is a crypto.Signer that counts the signatures taken through it
// and otherwise defers to the key it wraps. Substituted for a CA's own key, it
// makes "one signature per pass, not one per entry" — the claim #176 is
// entirely about, and the one that is invisible from the CRL it produces — an
// assertion rather than an inspection.
type countingCAKey struct {
	crypto.Signer
	mu sync.Mutex
	n  int
}

func (k *countingCAKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	k.n++
	k.mu.Unlock()
	return k.Signer.Sign(rand, digest, opts)
}

func (k *countingCAKey) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.n
}
