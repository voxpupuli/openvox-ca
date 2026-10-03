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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

var _ = Describe("CA RevokeSerial", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-revokeserial-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

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

	// issue signs a certificate for subject through the normal path and returns
	// its serial in the CA's canonical rendering (uppercase hex, no padding).
	issue := func(subject string) string {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())

		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		return strings.ToUpper(cert.SerialNumber.Text(16))
	}

	// orphan reproduces the state the issue describes: a certificate was issued,
	// a replacement was minted for the same subject, and the record that would
	// have retired the first one never landed. The inventory still names both;
	// only the replacement is stored, so Revoke(subject) now resolves to it.
	// Returns (superseded, live).
	orphan := func(subject string) (string, string) {
		superseded := issue(subject)
		Expect(store.DeleteCert(ctx, subject)).To(Succeed())
		live := issue(subject)
		Expect(live).NotTo(Equal(superseded))
		return superseded, live
	}

	// captureLogs runs fn with the default logger redirected to a buffer and
	// returns what was written, at Info and above so the success record is
	// visible alongside the Warn lines.
	captureLogs := func(fn func()) string {
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
		defer slog.SetDefault(orig)
		fn()
		return buf.String()
	}

	// crlSerials reports the serials currently on the CRL, canonically rendered.
	crlSerials := func() []string {
		crl := parseStoredCRL(store)
		out := make([]string, 0, len(crl.RevokedCertificateEntries))
		for _, e := range crl.RevokedCertificateEntries {
			out = append(out, strings.ToUpper(e.SerialNumber.Text(16)))
		}
		return out
	}

	Describe("the state it exists for", func() {
		It("revokes a superseded serial that revoking by subject cannot reach", func() {
			superseded, live := orphan("orphan-node")

			// The premise: by name, the CA would retire the live credential and
			// leave the superseded one valid — strictly worse than doing nothing.
			byName, err := store.LatestSerialForSubject(ctx, "orphan-node")
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.ToUpper(byName)).To(Equal(live))

			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			// ConsistOf is exact, so this states both halves at once: the
			// superseded serial is on the CRL and the live replacement is not.
			Expect(crlSerials()).To(ConsistOf(superseded),
				"expected exactly the superseded serial; the live replacement must survive")
		})

		It("leaves the live certificate usable", func() {
			superseded, live := orphan("orphan-usable")
			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			liveInt, ok := new(big.Int).SetString(live, 16)
			Expect(ok).To(BeTrue())
			revoked, err := myCA.IsRevokedSerial(ctx, liveInt)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeFalse())
		})
	})

	Describe("the live-certificate guard", func() {
		It("refuses the serial of the certificate stored for its subject", func() {
			serial := issue("live-node")

			err := myCA.RevokeSerial(ctx, serial, false)
			Expect(err).To(MatchError(ca.ErrSerialIsCurrent))
			Expect(crlSerials()).To(BeEmpty())
		})

		It("names the subject and the remedy, so the operator can act on it", func() {
			serial := issue("live-named")

			err := myCA.RevokeSerial(ctx, serial, false)
			// The same string is rendered into an HTTP response body, so it has
			// to be actionable without assuming the reader is using the CLI:
			// the operation is named first, the flags only as a parenthetical.
			Expect(err.Error()).To(ContainSubstring("live-named"))
			Expect(err.Error()).To(ContainSubstring("revoke that subject by name"))
			Expect(err.Error()).To(ContainSubstring("force set"))
			Expect(err.Error()).To(ContainSubstring("--certname live-named"))
		})

		It("revokes it anyway when forced", func() {
			serial := issue("live-forced")

			logged := captureLogs(func() {
				Expect(myCA.RevokeSerial(ctx, serial, true)).To(Succeed())
			})
			Expect(crlSerials()).To(ConsistOf(serial))

			// The audit trail is the whole reason force is on the Info line: a
			// forced revocation and one the guards cleared are otherwise
			// indistinguishable at the default level, and this is the path that
			// deliberately takes a live credential out of circulation.
			Expect(logged).To(ContainSubstring("Revoking the certificate currently stored for a subject"))
			Expect(logged).To(ContainSubstring("Certificate revoked by serial"))
			Expect(logged).To(ContainSubstring("force=true"))
		})

		It("records an unforced revocation as unforced", func() {
			superseded, _ := orphan("unforced-logged")

			logged := captureLogs(func() {
				Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())
			})

			Expect(logged).To(ContainSubstring("force=false"))
			Expect(logged).NotTo(ContainSubstring("Revoking the certificate currently stored"))
		})

		It("does not fire for a subject whose certificate has been deleted", func() {
			// A cleaned subject keeps its inventory rows but has no stored
			// certificate, so nothing is in circulation to protect.
			serial := issue("cleaned-node")
			Expect(store.DeleteCert(ctx, "cleaned-node")).To(Succeed())

			Expect(myCA.RevokeSerial(ctx, serial, false)).To(Succeed())
			Expect(crlSerials()).To(ConsistOf(serial))
		})

		It("fails closed when the stored certificate cannot be read", func() {
			serial := issue("unreadable-node")
			// Corrupt the stored certificate: the guard can no longer tell
			// whether this serial is the one in circulation, and guessing "it
			// is not" would drop the protection exactly when storage is sick.
			Expect(os.WriteFile(store.SignedDir()+"/unreadable-node.pem",
				[]byte("not a certificate"), 0o644)).To(Succeed())

			err := myCA.RevokeSerial(ctx, serial, false)
			Expect(err).To(MatchError(ca.ErrSerialStateUnknown))
			Expect(crlSerials()).To(BeEmpty())

			// Distinct from ErrSerialIsCurrent: the guard did not fire, it could
			// not run, and the remedy is to retry rather than to decide the live
			// certificate should go.
			Expect(err).NotTo(MatchError(ca.ErrSerialIsCurrent))
			// The storage error names a path; it must not ride out on the
			// message, which the API renders into a response body.
			Expect(err.Error()).NotTo(ContainSubstring(tmpDir))
			Expect(err.Error()).To(ContainSubstring("unreadable-node"))
			Expect(err.Error()).To(ContainSubstring("retry once storage is healthy"))
			Expect(err.Error()).To(ContainSubstring("force set"))

			logged := captureLogs(func() {
				Expect(myCA.RevokeSerial(ctx, serial, true)).To(Succeed())
			})
			Expect(crlSerials()).To(ConsistOf(serial))

			// Forcing past a guard that could not run is its own event: the
			// revocation happened with the check never having been made.
			Expect(logged).To(ContainSubstring("without confirming the stored certificate"))
		})
	})

	Describe("input handling", func() {
		It("rejects a serial this CA has no record of issuing", func() {
			err := myCA.RevokeSerial(ctx, "DEADBEEF", false)
			Expect(err).To(MatchError(ca.ErrSerialUnknown))
			Expect(crlSerials()).To(BeEmpty())

			// The other half of the deliberate split in revokeSerialCheckedLocked:
			// a serial that was never issued is operator error, not a revocation
			// the CA failed to record, so it must not page anyone.
			Expect(myCA.CRLUpdateFailures()).To(BeZero(),
				"a typo'd serial must not count as a failed revocation")
		})

		It("counts an inventory read that failed, unlike one that simply found nothing", func() {
			// The inventory HMAC is verified before the scan, so tampering makes
			// the lookup fail rather than answer — the tamper signal the metric's
			// documented meaning ("a revocation that could not be recorded")
			// covers, and the one case that separates the two arms of the split.
			issue("counted-node")
			Expect(os.WriteFile(store.InventoryPath(),
				[]byte("00 2026-01-01T00:00:00UTC 2027-01-01T00:00:00UTC /CN=forged\n"),
				0o600)).To(Succeed())

			err := myCA.RevokeSerial(ctx, "DEADBEEF", false)
			Expect(err).To(MatchError(storage.ErrInventoryTampered))
			Expect(err).NotTo(MatchError(ca.ErrSerialUnknown))
			Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 1))
			Expect(crlSerials()).To(BeEmpty())
		})

		It("refuses a forged inventory entry rather than admitting its serial", func() {
			// The whole point of verifying: without it, a serial this CA never
			// issued would resolve to a subject and land on the CRL, where no
			// expiry sweep could ever remove it — CleanupExpiredCerts drops
			// entries only for serials it finds in the inventory. force must not
			// help here either.
			issue("forge-node")
			Expect(os.WriteFile(store.InventoryPath(),
				[]byte("BEEF 2026-01-01T00:00:00UTC 2027-01-01T00:00:00UTC /CN=forge-node\n"),
				0o600)).To(Succeed())

			Expect(myCA.RevokeSerial(ctx, "BEEF", false)).To(MatchError(storage.ErrInventoryTampered))
			Expect(myCA.RevokeSerial(ctx, "BEEF", true)).To(MatchError(storage.ErrInventoryTampered))
			Expect(crlSerials()).To(BeEmpty())
		})

		It("does not let force admit an unknown serial", func() {
			// A CRL entry for a serial not in the inventory can never be cleaned
			// out again: CleanupExpiredCerts drops entries only for serials it
			// finds there. Force must not be able to create one.
			err := myCA.RevokeSerial(ctx, "DEADBEEF", true)
			Expect(err).To(MatchError(ca.ErrSerialUnknown))
			Expect(crlSerials()).To(BeEmpty())
		})

		// One Entry per input rather than a loop: Gomega aborts a spec at the
		// first failed Expect, so a loop would report one accepted input and
		// never evaluate the rest.
		DescribeTable("rejects input that is not a hexadecimal serial",
			func(bad string) {
				Expect(myCA.RevokeSerial(ctx, bad, false)).To(MatchError(storage.ErrMalformedSerial))
				Expect(crlSerials()).To(BeEmpty())
			},
			Entry("empty", ""),
			Entry("whitespace only", "  "),
			Entry("non-hex letters", "zzz"),
			Entry("a bare 0x", "0x"),
			Entry("two 0x prefixes", "0x0x1234"),
			Entry("negative", "-1"),
			Entry("embedded space", "12 34"),
		)

		// RevokeSerial canonicalises before it looks anything up, so what these
		// pin is that the operator's rendering reaches the same certificate.
		// That the *stored* rendering is equally irrelevant is SubjectForSerial's
		// contract, and is pinned in internal/storage — a certificate issued by
		// this CA always lands in the inventory canonically, so nothing here
		// could tell the difference.
		DescribeTable("accepts any rendering the operator types",
			func(render func(string) string) {
				superseded, _ := orphan("render-node")
				Expect(myCA.RevokeSerial(ctx, render(superseded), false)).To(Succeed())
				Expect(crlSerials()).To(ConsistOf(superseded))
			},
			Entry("canonical", func(s string) string { return s }),
			Entry("lowercase", strings.ToLower),
			Entry("zero-padded", func(s string) string { return "0000" + s }),
			Entry("surrounded by whitespace", func(s string) string { return "  " + s + "\n" }),
			// As the filesystem inventory writes it, so a serial copied from
			// inventory.txt works as it is.
			Entry("0x-prefixed, as inventory.txt writes it", func(s string) string { return "0x" + s }),
			Entry("0X-prefixed", func(s string) string { return "0X" + s }),
		)

		It("is idempotent: a second revocation adds no second entry", func() {
			superseded, _ := orphan("idempotent-node")

			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())
			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			Expect(crlSerials()).To(ConsistOf(superseded))
		})
	})

	Describe("the state it leaves behind", func() {
		It("reports the serial as revoked over OCSP", func() {
			superseded, _ := orphan("ocsp-node")
			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			serialInt, ok := new(big.Int).SetString(superseded, 16)
			Expect(ok).To(BeTrue())
			revoked, err := myCA.IsRevokedSerial(ctx, serialInt)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		})

		It("survives a restart: the revocation is in the signed CRL, not just memory", func() {
			superseded, _ := orphan("restart-node")
			Expect(myCA.RevokeSerial(ctx, superseded, false)).To(Succeed())

			reloaded := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(reloaded.Init(ctx)).To(Succeed())

			serialInt, ok := new(big.Int).SetString(superseded, 16)
			Expect(ok).To(BeTrue())
			revoked, err := reloaded.IsRevokedSerial(ctx, serialInt)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		})
	})
})
