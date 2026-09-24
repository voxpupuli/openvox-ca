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

package ca_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// pendingEntry mirrors the JSON the CA writes to storage.KeySuperseded. It is
// deliberately a separate declaration from the unexported one in package ca:
// the on-disk shape is shared between replicas and survives restarts, so a
// field rename that broke it would go unnoticed if this spec simply reused the
// type doing the writing.
type pendingEntry struct {
	Serial   string    `json:"serial"`
	Subject  string    `json:"subject"`
	RevokeAt time.Time `json:"revoke_at"`
}

var _ = Describe("Delayed supersession", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	parseCert := func(certPEM []byte) *x509.Certificate {
		GinkgoHelper()
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	// issue puts subject through the ordinary SaveRequest+Sign flow.
	issue := func(subject string) *x509.Certificate {
		GinkgoHelper()
		csrPEM, _ := buildCSR(subject)
		_, err := myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCert(certPEM)
	}

	// pending reads the stored pending-revocation list. An absent list is no
	// entries, which is what a CA that has recorded nothing must show.
	pending := func() []pendingEntry {
		GinkgoHelper()
		data, err := store.GetSuperseded(ctx)
		if err != nil {
			Expect(os.IsNotExist(err)).To(BeTrue(), "unexpected error reading the pending list: %v", err)
			return nil
		}
		var entries []pendingEntry
		// Annotated rather than bare: a spec that expected the sweep to
		// overwrite unparseable bytes and finds them still there fails here,
		// and "invalid character" alone would not say which promise broke.
		// Returning nil instead would let that spec pass.
		Expect(json.Unmarshal(data, &entries)).To(Succeed(),
			"the stored pending list must be parseable JSON; got %q", string(data))
		return entries
	}

	// revoked answers from the stored CRL rather than the in-memory copy, so a
	// spec cannot pass on a cache that was never written through.
	revoked := func(serial *big.Int) bool {
		GinkgoHelper()
		crlPEM, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(crlPEM)
		Expect(block).NotTo(BeNil())
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(serial) == 0 {
				return true
			}
		}
		return false
	}

	// writePending installs a pending list directly, so a spec can place an
	// entry's due time in the past without sleeping through a real delay.
	writePending := func(entries []pendingEntry) {
		GinkgoHelper()
		data, err := json.Marshal(entries)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveSuperseded(ctx, data)).To(Succeed())
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-supersede-test")
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")

		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	Describe("with no delay configured (the default)", func() {
		// The compatibility guarantee. Every deployment that does not set
		// superseded_cert_revoke_after_sec must behave exactly as it did before
		// the pending list existed: the predecessor is revoked inside the
		// renewal call, and nothing is written to the list at all.
		It("revokes the replaced certificate inside Renew, recording nothing", func() {
			original := issue("node-a")

			csrPEM, _ := buildCSR("node-a")
			_, err := myCA.Renew(ctx, "node-a", csrPEM, original)
			Expect(err).NotTo(HaveOccurred())

			Expect(revoked(original.SerialNumber)).To(BeTrue(),
				"with no delay the predecessor must be revoked by the time Renew returns")
			Expect(pending()).To(BeEmpty(),
				"an immediate revocation must not leave anything on the pending list")
		})

		It("revokes the replaced certificate inside AutoRenew, recording nothing", func() {
			original := issue("node-b")

			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())

			Expect(revoked(original.SerialNumber)).To(BeTrue())
			Expect(pending()).To(BeEmpty())
		})
	})

	Describe("with a delay configured", func() {
		BeforeEach(func() {
			myCA.SupersedeAfter = time.Hour
		})

		// The point of the whole feature: the predecessor keeps working while
		// relying parties pick up the replacement.
		It("leaves the certificate Renew replaced valid and records it as due later", func() {
			original := issue("node-c")

			csrPEM, _ := buildCSR("node-c")
			renewedPEM, err := myCA.Renew(ctx, "node-c", csrPEM, original)
			Expect(err).NotTo(HaveOccurred())
			renewed := parseCert(renewedPEM)

			Expect(revoked(original.SerialNumber)).To(BeFalse(),
				"the replaced certificate must stay valid for the length of the window")
			Expect(revoked(renewed.SerialNumber)).To(BeFalse(),
				"the replacement must never be the one revoked")

			entries := pending()
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Subject).To(Equal("node-c"))
			Expect(entries[0].Serial).To(Equal(hexSerial(original.SerialNumber)),
				"the recorded serial must be the predecessor's, not the replacement's")
			Expect(entries[0].RevokeAt).To(BeTemporally("~", time.Now().UTC().Add(time.Hour), time.Minute))
		})

		It("leaves the certificate AutoRenew replaced valid and records it as due later", func() {
			original := issue("node-d")

			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())

			Expect(revoked(original.SerialNumber)).To(BeFalse())
			entries := pending()
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Serial).To(Equal(hexSerial(original.SerialNumber)))
		})

		// revoke_on_auto_renew is a whether, not a when. With it off, the
		// predecessor is kept deliberately — so the delay must not smuggle it
		// onto a list that would revoke it an hour later.
		It("records nothing on the auto-renewal path when revoke_on_auto_renew is off", func() {
			myCA.RevokeOnAutoRenew = false
			original := issue("node-e")

			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())

			Expect(revoked(original.SerialNumber)).To(BeFalse())
			Expect(pending()).To(BeEmpty(),
				"revoke_on_auto_renew=false must keep the predecessor, not defer its revocation")
		})

		// One list, many subjects. This is the property the issue asks for and
		// the reason it was cut from main rather than stacked behind the
		// single-subject serving implementation.
		It("accumulates entries across different subjects on one list", func() {
			first := issue("node-f")
			second := issue("node-g")

			_, err := myCA.AutoRenew(ctx, first)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.AutoRenew(ctx, second)
			Expect(err).NotTo(HaveOccurred())

			entries := pending()
			Expect(entries).To(HaveLen(2), "a second subject's supersession must not overwrite the first")
			subjects := []string{entries[0].Subject, entries[1].Subject}
			Expect(subjects).To(ConsistOf("node-f", "node-g"))
		})
	})

	Describe("ReconcileSuperseded", func() {
		It("revokes what is due, leaves what is not, and reports the count", func() {
			due := issue("node-h")
			notYet := issue("node-i")
			writePending([]pendingEntry{
				{Serial: hexSerial(due.SerialNumber), Subject: "node-h", RevokeAt: time.Now().UTC().Add(-time.Minute)},
				{Serial: hexSerial(notYet.SerialNumber), Subject: "node-i", RevokeAt: time.Now().UTC().Add(time.Hour)},
			})

			count, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(1))

			Expect(revoked(due.SerialNumber)).To(BeTrue())
			Expect(revoked(notYet.SerialNumber)).To(BeFalse(),
				"an entry inside its window must not be revoked early")

			entries := pending()
			Expect(entries).To(HaveLen(1), "the revoked entry must be dropped from the list")
			Expect(entries[0].Subject).To(Equal("node-i"))
		})

		// Each entry's window was fixed when the supersession was recorded.
		// Turning the delay off afterwards changes what future renewals record;
		// it must not retroactively expire a window a fleet may be mid-way
		// through relying on.
		It("honours a recorded due time even after the delay is set back to zero", func() {
			cert := issue("node-j")
			writePending([]pendingEntry{
				{Serial: hexSerial(cert.SerialNumber), Subject: "node-j", RevokeAt: time.Now().UTC().Add(time.Hour)},
			})
			myCA.SupersedeAfter = 0

			count, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(BeZero())
			Expect(revoked(cert.SerialNumber)).To(BeFalse())
			Expect(pending()).To(HaveLen(1), "the entry must still be there, waiting for its own due time")
		})

		// Idempotence is what lets every replica run the sweep with no leader:
		// the second pass finds the list already drained and the serial already
		// on the CRL, and must do nothing rather than append a duplicate entry.
		It("is a no-op on a second pass", func() {
			cert := issue("node-k")
			writePending([]pendingEntry{
				{Serial: hexSerial(cert.SerialNumber), Subject: "node-k", RevokeAt: time.Now().UTC().Add(-time.Minute)},
			})

			_, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			before, err := store.GetCRL(ctx)
			Expect(err).NotTo(HaveOccurred())

			count, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(BeZero())
			after, err := store.GetCRL(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(after).To(Equal(before), "a drained list must not cause a CRL re-sign")
		})

		// A serial that is not parseable hex can never be revoked. Carrying it
		// forward would retry it on every pass forever, latching the failure
		// counter with nothing an operator could do to clear it.
		It("discards an entry whose serial can never be revoked, and counts it", func() {
			writePending([]pendingEntry{
				{Serial: "not-hex", Subject: "node-l", RevokeAt: time.Now().UTC().Add(-time.Minute)},
			})
			before := myCA.SupersedeFailures()

			count, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(BeZero())
			Expect(pending()).To(BeEmpty(), "an unrevocable entry must not be retried forever")
			Expect(myCA.SupersedeFailures()).To(BeNumerically(">", before),
				"discarding an entry loses a revocation and must be counted")
		})

		// The recovery arm, which a syntax error cannot reach: encoding/json
		// validates the whole input before decoding any of it, so truncation and
		// bad syntax recover nothing. A well-formed list with one badly-typed
		// field is the shape that does partially decode, and it is what makes
		// "entries keeps whatever decoded before the failure" a real branch
		// rather than an unfalsifiable claim.
		It("still sweeps the entries it could recover from a partly-decodable list", func() {
			cert := issue("node-t")
			raw := `[{"serial":"` + hexSerial(cert.SerialNumber) + `","subject":"node-t",` +
				`"revoke_at":"` + time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano) + `"},` +
				`{"serial":12345,"subject":"node-u","revoke_at":"2026-01-01T00:00:00Z"}]`
			Expect(store.SaveSuperseded(ctx, []byte(raw))).To(Succeed())

			count, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(1),
				"the entry that decoded must still be revoked, not thrown away with the one that did not")
			Expect(revoked(cert.SerialNumber)).To(BeTrue())
			Expect(pending()).To(BeEmpty(), "the write-back must leave clean, parseable bytes")
		})

		// Unparseable bytes are not self-clearing. Left alone they would warn,
		// count and be re-read on every pass forever.
		It("overwrites an unparseable list instead of re-reading it forever", func() {
			Expect(store.SaveSuperseded(ctx, []byte("{not json"))).To(Succeed())
			before := myCA.SupersedeFailures()

			_, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.SupersedeFailures()).To(BeNumerically(">", before))
			Expect(pending()).To(BeEmpty())

			// The second pass must find clean bytes, so the warning and the
			// counter stop rather than latching.
			steady := myCA.SupersedeFailures()
			_, err = myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(myCA.SupersedeFailures()).To(Equal(steady))
		})
	})

	// The window must bound the exposure it grants, not end it. A certificate
	// inside its window is deliberately absent from the CRL, so nothing else on
	// the renewal path turns it away — and a renewal mints a fresh full-lifetime
	// certificate. Without a gate, the credential the window was keeping alive
	// for relying parties could mint a successor that outlives the window
	// entirely, which on the re-key path is the previous private key doing it.
	Describe("a certificate inside its window", func() {
		BeforeEach(func() {
			myCA.SupersedeAfter = time.Hour
		})

		It("cannot auto-renew itself into a fresh certificate", func() {
			original := issue("node-n")
			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred(), "precondition: the first renewal succeeds")
			Expect(pending()).To(HaveLen(1), "precondition: the predecessor is inside its window")

			_, err = myCA.AutoRenew(ctx, original)
			Expect(err).To(MatchError(ca.ErrCertSuperseded),
				"a superseded certificate must not be able to renew itself")
			// Wrapping ErrCertRevoked is what makes every existing caller — the
			// HTTP layer included — answer 403 without being taught about a new
			// sentinel. If that stops holding, the API starts returning 500 for
			// a refusal.
			Expect(err).To(MatchError(ca.ErrCertRevoked),
				"ErrCertSuperseded must keep wrapping ErrCertRevoked so callers refuse it unchanged")
			Expect(pending()).To(HaveLen(1), "a refused renewal must not record anything")
		})

		It("cannot re-key itself, which would also retire the live replacement", func() {
			original := issue("node-o")
			csrPEM, _ := buildCSR("node-o")
			replacementPEM, err := myCA.Renew(ctx, "node-o", csrPEM, original)
			Expect(err).NotTo(HaveOccurred(), "precondition: the first renewal succeeds")
			replacement := parseCert(replacementPEM)

			// Presenting the superseded certificate again. Renew retires the
			// subject's *latest* serial, so an admitted call here would schedule
			// the live replacement for revocation as well as minting a successor
			// for the displaced key.
			csrPEM2, _ := buildCSR("node-o")
			_, err = myCA.Renew(ctx, "node-o", csrPEM2, original)
			Expect(err).To(MatchError(ca.ErrCertSuperseded),
				"a superseded certificate must not be able to re-key")

			entries := pending()
			Expect(entries).To(HaveLen(1), "a refused renewal must not record anything")
			Expect(entries[0].Serial).To(Equal(hexSerial(original.SerialNumber)),
				"the live replacement must not have been scheduled for revocation")
			Expect(revoked(replacement.SerialNumber)).To(BeFalse())
		})

		// The gate compares the presented certificate's serial against the
		// stored one. The presented side is always canonical (serialHexStr of a
		// *big.Int); the stored side used to be whatever the caller passed, and
		// on the CSR re-key path that is LatestSerialForSubject, which returns
		// inventory text verbatim. An inventory written by an older version, or
		// migrated from Puppet Server, carries zero-padded sequential serials —
		// so the gate compared "A" against "000A", missed, and let the
		// superseded credential renew itself. Exactly the escalation it exists
		// to prevent, on the worse path, and silent: the sweep parses before
		// comparing so it still revoked correctly.
		It("refuses a certificate recorded with a zero-padded serial", func() {
			original := issue("node-pad")
			padded := "000" + hexSerial(original.SerialNumber)
			writePending([]pendingEntry{
				{Serial: padded, Subject: "node-pad", RevokeAt: time.Now().UTC().Add(time.Hour)},
			})

			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).To(MatchError(ca.ErrCertSuperseded),
				"a zero-padded stored serial must still match the presented certificate; "+
					"inventory serials are not canonical and this is an authorisation decision")
		})

		It("does not obstruct the replacement renewing normally", func() {
			original := issue("node-p")
			replacementPEM, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			replacement := parseCert(replacementPEM)

			// The legitimate agent holds the replacement and renews with it.
			// Refusing this would break every fleet that turned the window on.
			_, err = myCA.AutoRenew(ctx, replacement)
			Expect(err).NotTo(HaveOccurred(),
				"the current certificate must still renew while its predecessor waits out the window")
		})
	})

	// The fail-closed arms of the renewal gate. Its godoc argues at length that
	// refusing renewals is the right trade when the list is unreadable; flipping
	// either arm to fail open moved no assertion before these.
	Describe("when the renewal gate cannot read the pending list", func() {
		It("refuses the renewal rather than admitting it, and counts the read failure", func() {
			original := issue("node-aa")
			base := storage.NewFilesystemBackend(tmpDir)
			failStore := storage.NewWithBackend(
				&supersededFailBackend{Backend: base, failGet: storage.KeySuperseded}, tmpDir)
			failing := ca.New(failStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(failing.Init(ctx)).To(Succeed())
			before := failing.SupersedeFailures()

			_, err := failing.AutoRenew(ctx, original)
			Expect(err).To(HaveOccurred(),
				"a list that cannot be read must refuse the renewal, not admit it")
			Expect(failing.SupersedeFailures()).To(Equal(before + 1))
		})

		It("refuses on an unparseable list, which may have named this very serial", func() {
			original := issue("node-ab")
			Expect(store.SaveSuperseded(ctx, []byte("{not json"))).To(Succeed())

			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).To(MatchError(ca.ErrCertSuperseded),
				"an unparseable list must refuse the renewal")
		})
	})

	Describe("when the pending list cannot be written", func() {
		// The delayed path's best-effort contract, in both directions. The
		// immediate path has the same pair of specs in renew_test.go against
		// CRLUpdateFailures; the delayed path's consequence is documented as
		// strictly worse — a supersession that was never recorded is gone for
		// good, because nothing else records that the certificate was replaced.
		var failing *ca.CA

		BeforeEach(func() {
			base := storage.NewFilesystemBackend(tmpDir)
			failStore := storage.NewWithBackend(
				&supersededFailBackend{Backend: base, failPut: storage.KeySuperseded}, tmpDir)
			failing = ca.New(failStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			failing.SupersedeAfter = time.Hour
			Expect(failing.Init(ctx)).To(Succeed())
		})

		It("still completes the renewal, and counts the lost supersession", func() {
			original := issue("node-q")
			before := failing.SupersedeFailures()

			renewedPEM, err := failing.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred(),
				"a supersession that could not be recorded must not fail the renewal the agent is waiting on")
			renewed := parseCert(renewedPEM)
			Expect(renewed.SerialNumber.Cmp(original.SerialNumber)).NotTo(Equal(0))

			Expect(failing.SupersedeFailures()).To(BeNumerically(">", before),
				"a supersession that was never recorded must be counted; it is the only trace that "+
					"the replaced certificate is still a valid credential")
		})
	})

	Describe("ReconcileSuperseded when a revocation fails", func() {
		// The retry half of the sweep's failure handling. The alert text tells
		// operators to distinguish "Could not revoke superseded certificates"
		// (recorded, will retry) from "Discarding" (gone for good), and only the
		// second was pinned. A change that dropped failed entries instead of
		// carrying them forward would turn a retryable failure into a
		// permanently valid credential and move no assertion.
		//
		// This is also the carry-forward case #176 had to preserve when it
		// batched the re-sign. Batched, the failure is all-or-nothing rather
		// than per entry — but where the entries end up is unchanged, which is
		// the part that decides whether a certificate stays tracked.
		It("carries the entry forward rather than dropping it, and counts the pass once", func() {
			first := issue("node-r")
			second := issue("node-s")
			writePending([]pendingEntry{
				{Serial: hexSerial(first.SerialNumber), Subject: "node-r", RevokeAt: time.Now().UTC().Add(-time.Minute)},
				{Serial: hexSerial(second.SerialNumber), Subject: "node-s", RevokeAt: time.Now().UTC().Add(-time.Minute)},
			})
			// An unparseable CRL fails the batch's own read without making any
			// of its entries unrevocable — the distinction the two arms turn
			// on.
			Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())
			before := myCA.SupersedeFailures()

			count, err := myCA.ReconcileSuperseded(ctx)
			Expect(err).NotTo(HaveOccurred(), "a failed revocation must not fail the whole pass")
			Expect(count).To(BeZero())

			Expect(pending()).To(HaveLen(2),
				"entries whose revocation failed must stay on the list for the next pass")
			Expect(myCA.SupersedeFailures()).To(Equal(before+1),
				"one pass counts once, however many entries it failed on")
		})
	})

	// Containment. `revoke --certname` retires the subject's latest serial and
	// no other, so during an overlap window it would retire the replacement and
	// leave the certificate that replacement displaced valid — on the re-key
	// path with a private key of its own. An operator responding to a
	// compromised node would be told it was revoked while a second working
	// credential for it stayed in circulation.
	Describe("revoking a subject that has a predecessor inside its window", func() {
		BeforeEach(func() {
			myCA.SupersedeAfter = time.Hour
		})

		It("retires the predecessor as well as the current certificate", func() {
			original := issue("node-v")
			replacementPEM, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			replacement := parseCert(replacementPEM)
			Expect(pending()).To(HaveLen(1), "precondition: the predecessor is inside its window")

			Expect(myCA.Revoke(ctx, "node-v")).To(Succeed())

			Expect(revoked(replacement.SerialNumber)).To(BeTrue(),
				"the subject's current certificate must be revoked, as it always was")
			Expect(revoked(original.SerialNumber)).To(BeTrue(),
				"a predecessor inside its window is a second working credential for this subject "+
					"and must be retired by the same revocation")
			Expect(pending()).To(BeEmpty(),
				"the entry must leave the list, so the sweep does not carry a serial already revoked")
		})

		It("leaves another subject's pending entry alone", func() {
			mine := issue("node-w")
			theirs := issue("node-x")
			_, err := myCA.AutoRenew(ctx, mine)
			Expect(err).NotTo(HaveOccurred())
			_, err = myCA.AutoRenew(ctx, theirs)
			Expect(err).NotTo(HaveOccurred())

			Expect(myCA.Revoke(ctx, "node-w")).To(Succeed())

			Expect(revoked(theirs.SerialNumber)).To(BeFalse(),
				"revoking one subject must not retire another's superseded certificate")
			entries := pending()
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Subject).To(Equal("node-x"))
		})
	})

	Describe("revoking a subject when the pending list misbehaves", func() {
		It("still revokes the subject when the list cannot be read", func() {
			original := issue("node-ac")
			base := storage.NewFilesystemBackend(tmpDir)
			failStore := storage.NewWithBackend(
				&supersededFailBackend{Backend: base, failGet: storage.KeySuperseded}, tmpDir)
			failing := ca.New(failStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(failing.Init(ctx)).To(Succeed())
			before := failing.SupersedeFailures()

			// Partial containment beats none: turning the read failure into a
			// returned error would make `revoke --certname` fail outright during
			// a storage blip.
			Expect(failing.Revoke(ctx, "node-ac")).To(Succeed(),
				"an unreadable pending list must not stop the subject being revoked")
			Expect(revoked(original.SerialNumber)).To(BeTrue())
			Expect(failing.SupersedeFailures()).To(Equal(before + 1))
		})

		// revokeLocked calls retireSupersededForSubjectLocked *before* looking up
		// the subject's own serial, and its comment gives this as the reason: a
		// subject whose inventory lookup fails must still lose its superseded
		// credentials rather than none of them. Nothing exercised that ordering,
		// so moving the call after the lookup would have moved no assertion —
		// on a containment path.
		It("retires the predecessor even when the subject's own lookup fails", func() {
			myCA.SupersedeAfter = time.Hour
			original := issue("node-af")
			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			Expect(pending()).To(HaveLen(1), "precondition: a predecessor is inside its window")

			// Only the inventory read fails, so the pending list is readable and
			// the CRL is writable; what breaks is the lookup of the subject's
			// current serial, which is the step the ordering protects against.
			// Armed *after* Init: Init verifies the inventory HMAC, which reads
			// the inventory, so a backend already failing that read cannot get
			// a CA constructed at all.
			fb := &supersededFailBackend{Backend: storage.NewFilesystemBackend(tmpDir)}
			failing := ca.New(storage.NewWithBackend(fb, tmpDir), ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(failing.Init(ctx)).To(Succeed())
			fb.failGet = storage.KeyInventory

			// Revoke itself fails: it could not find the subject's certificate.
			Expect(failing.Revoke(ctx, "node-af")).NotTo(Succeed())

			Expect(revoked(original.SerialNumber)).To(BeTrue(),
				"the superseded predecessor must be retired even though the revocation that "+
					"followed it could not complete; partial containment beats none")
			Expect(pending()).To(BeEmpty(),
				"and it must leave the list, having actually been revoked")
		})

		It("can answer the unknown-subject sentinel with the counter already moved", func() {
			// docs/api.md tells operators that neither status code on
			// PUT /certificate_status is a statement about
			// puppetca_crl_update_failures_total, in either direction. The 409
			// half is the lock refusal, documented above. This is the other
			// half, and it is the one a reader would doubt: a 404 that DID move
			// the counter, because the superseded-predecessor retirement runs
			// before the lookup that produces the sentinel.
			//
			// Nothing pinned it. The ordering spec above reaches this branch
			// through a backend whose inventory Get fails with a generic error,
			// which is counted and answers 409 -- not the sentinel arm. The
			// sentinel specs in ca_test.go have no predecessors and say so.
			// Between them the combination went untested, so reordering the
			// retirement after the lookup would leave this documented sentence
			// false with nothing red.
			myCA.SupersedeAfter = time.Hour
			original := issue("node-counted-404")
			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			Expect(pending()).To(HaveLen(1), "precondition: a predecessor is inside its window")

			// The predecessor's retirement fails and is counted: an unparseable
			// CRL makes every revocation fail, as the spec below relies on too.
			Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())
			// The subject's own lookup then reaches fs.ErrNotExist rather than
			// failing verification -- the MAC has to go with the inventory, or
			// this lands on the counted ErrInventoryTampered branch instead and
			// the spec would pass while testing the wrong thing.
			Expect(os.Remove(store.InventoryPath())).To(Succeed())
			Expect(os.Remove(filepath.Join(
				filepath.Dir(store.InventoryPath()), ".inventory.hmac"))).To(Succeed())

			before := myCA.CRLUpdateFailures()
			err = myCA.Revoke(ctx, "node-counted-404")
			Expect(err).To(MatchError(ca.ErrSubjectUnknown),
				"this is the error the API layer answers 404")
			Expect(myCA.CRLUpdateFailures()).To(BeNumerically(">", before),
				"and the counter moved on the way out, which is why the docs tell "+
					"operators not to infer it from the status code")
		})

		It("keeps a predecessor on the list when its revocation fails", func() {
			myCA.SupersedeAfter = time.Hour
			original := issue("node-ad")
			_, err := myCA.AutoRenew(ctx, original)
			Expect(err).NotTo(HaveOccurred())
			Expect(pending()).To(HaveLen(1))

			// An unparseable CRL makes every revocation fail. The predecessor
			// must stay recorded: absent from the CRL *and* absent from the list
			// is the one state nothing recovers from.
			Expect(store.UpdateCRL(ctx, []byte("not a valid CRL"))).To(Succeed())
			before := myCA.SupersedeFailures()
			Expect(myCA.Revoke(ctx, "node-ad")).NotTo(Succeed())

			entries := pending()
			Expect(entries).To(HaveLen(1),
				"a predecessor whose revocation failed must stay on the list for the sweep")
			Expect(entries[0].Serial).To(Equal(hexSerial(original.SerialNumber)))
			// Equal, not ">": this function can increment twice in one call —
			// once for a failed revocation and once for a failed write — so a
			// loose matcher could not tell the intended single increment from
			// an accidental double.
			Expect(myCA.SupersedeFailures()).To(Equal(before + 1))
		})

		It("still revokes, and counts, when the pruned list cannot be written back", func() {
			original := issue("node-ae")
			// Seeded through the working store, then revoked through a CA whose
			// writes of this key fail: read-OK, revoke-OK, write-fail.
			writePending([]pendingEntry{
				{Serial: hexSerial(original.SerialNumber), Subject: "node-ae", RevokeAt: time.Now().UTC().Add(time.Hour)},
			})
			base := storage.NewFilesystemBackend(tmpDir)
			failStore := storage.NewWithBackend(
				&supersededFailBackend{Backend: base, failPut: storage.KeySuperseded}, tmpDir)
			failing := ca.New(failStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(failing.Init(ctx)).To(Succeed())
			before := failing.SupersedeFailures()

			Expect(failing.Revoke(ctx, "node-ae")).To(Succeed(),
				"a list that cannot be pruned must not fail the revocation the caller asked for")
			Expect(revoked(original.SerialNumber)).To(BeTrue(),
				"the predecessor must still be retired; the unprunable list is the lesser problem")
			Expect(failing.SupersedeFailures()).To(Equal(before+1),
				"an unprunable list must be counted; that counter is the alert's only input")
		})
	})

	Describe("ReconcileSuperseded when the list itself is unreadable", func() {
		// The whole-pass failure modes — a lock it could not take, a list it
		// could not read, a write-back that failed — leave every entry
		// unrevoked. If they are not counted, a storage fault that blocks the
		// sweep indefinitely leaves both new signals reading clean: a flat
		// counter, and a pending gauge that would report a healthy zero. The one
		// alert that bounds this exposure could then never fire.
		It("reports the failure and counts the pass", func() {
			base := storage.NewFilesystemBackend(tmpDir)
			failStore := storage.NewWithBackend(
				&supersededFailBackend{Backend: base, failGet: storage.KeySuperseded}, tmpDir)
			failing := ca.New(failStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(failing.Init(ctx)).To(Succeed())
			before := failing.SupersedeFailures()

			_, err := failing.ReconcileSuperseded(ctx)
			Expect(err).To(HaveOccurred(), "a sweep that cannot read the list must say so")
			Expect(failing.SupersedeFailures()).To(Equal(before+1),
				"a pass that left every entry unrevoked must be counted, or the alert cannot fire")

			// And the count must not present as a drained list.
			_, perr := failing.PendingSupersessions(ctx)
			Expect(perr).To(HaveOccurred(),
				"an unreadable list must surface as an error, not as a count of zero")
		})
	})

	// This used to be the deferral arm: below the reserve the per-entry loop
	// retired one entry and carried the rest to the next pass, because N
	// entries cost N CRL re-signs and a backlog could not fit in one lock hold.
	// #176 collapsed those into one re-sign, so the reserve is gone and a pass
	// on the same deadline clears the whole backlog. The spec is kept, aimed at
	// the property that replaced it — every other sweep spec runs on
	// context.Background(), so without this one nothing exercises the sweep
	// with a deadline near enough to matter at all. ReconcileSuperseded's own
	// WithTimeout keeps an earlier parent deadline, so the short context here
	// really is the one the pass runs under.
	Describe("ReconcileSuperseded on a deadline that used to ration the pass", func() {
		It("drains the whole backlog rather than deferring part of it", func() {
			first := issue("node-y")
			second := issue("node-z")
			writePending([]pendingEntry{
				{Serial: hexSerial(first.SerialNumber), Subject: "node-y", RevokeAt: time.Now().UTC().Add(-2 * time.Hour)},
				{Serial: hexSerial(second.SerialNumber), Subject: "node-z", RevokeAt: time.Now().UTC().Add(-time.Minute)},
			})
			before := myCA.SupersedeFailures()

			// Below what the old reserve check (LockTimeout/2) allowed, so the
			// pre-batch sweep revoked node-y here and deferred node-z.
			shortCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			count, err := myCA.ReconcileSuperseded(shortCtx)
			Expect(err).NotTo(HaveOccurred())

			Expect(count).To(Equal(2),
				"one re-sign covers both entries, so a deadline that used to stop the pass "+
					"after the first no longer rations it")
			// Anchored on each serial, so a batch that lost one fails here
			// naming it rather than passing on a count that happens to match.
			Expect(revoked(first.SerialNumber)).To(BeTrue(), "node-y must be on the CRL")
			Expect(revoked(second.SerialNumber)).To(BeTrue(), "node-z must be on the CRL")

			Expect(pending()).To(BeEmpty(),
				"an entry that is on the CRL is no longer owed a revocation, so the pass "+
					"must prune it")
			Expect(myCA.SupersedeFailures()).To(Equal(before),
				"a pass that left nothing unrevoked is not a failure, and counting it as one "+
					"would fire PuppetCASupersedeFailing on every healthy sweep")
		})
	})

	Describe("PendingSupersessions", func() {
		It("counts what is on the list and reports zero before anything is recorded", func() {
			n, err := myCA.PendingSupersessions(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(BeZero())

			myCA.SupersedeAfter = time.Hour
			cert := issue("node-m")
			_, err = myCA.AutoRenew(ctx, cert)
			Expect(err).NotTo(HaveOccurred())

			n, err = myCA.PendingSupersessions(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(1))
		})

		// It is called on a scrape interval, so a blob that will never parse
		// must not emit a warning and increment the counter every few seconds.
		It("does not count a corrupt list as a failure", func() {
			Expect(store.SaveSuperseded(ctx, []byte("{not json"))).To(Succeed())
			before := myCA.SupersedeFailures()

			n, err := myCA.PendingSupersessions(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(BeZero())
			Expect(myCA.SupersedeFailures()).To(Equal(before),
				"a scrape-interval reader must not latch the failure counter")
		})
	})
})

// supersededFailBackend wraps a real filesystem backend and fails one key's
// read or write, which is what a store whose pending-supersession blob alone is
// broken looks like from the CA.
type supersededFailBackend struct {
	storage.Backend
	failPut string
	failGet string
}

func (b *supersededFailBackend) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if b.failPut != "" && key == b.failPut {
		return errors.New("simulated backend failure writing " + key)
	}
	return b.Backend.Put(ctx, key, data, kind)
}

func (b *supersededFailBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if b.failGet != "" && key == b.failGet {
		return nil, errors.New("simulated backend failure reading " + key)
	}
	return b.Backend.Get(ctx, key)
}

// hexSerial renders a serial the way the CA records it on the pending list:
// uppercase hex with no leading zeros. Spelled out here rather than exported
// from package ca, so a change to that formatting shows up as a failing
// assertion about the stored blob instead of both sides moving together.
func hexSerial(n *big.Int) string {
	return fmt.Sprintf("%X", n)
}
