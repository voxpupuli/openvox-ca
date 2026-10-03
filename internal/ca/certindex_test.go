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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// unknownRepairBackend wraps a real structured backend, relabelling one
// subject's Statuses record as CertStateUnknown with no projection — the
// shape the etcd backend reports for ambiguous (duplicated legacy) serials —
// and, once recording is enabled, logging every certificate-index write so
// the repair pass's skip behaviour is observable.
type unknownRepairBackend struct {
	*storage.SQLBackend
	subject   string
	recording bool
	writes    []string
}

func (b *unknownRepairBackend) Statuses(ctx context.Context, stateFilter string) ([]storage.CertRecord, error) {
	recs, err := b.SQLBackend.Statuses(ctx, stateFilter)
	for i := range recs {
		if recs[i].Subject == b.subject {
			recs[i].State = storage.CertStateUnknown
			recs[i].RevokedAt = nil
			recs[i].CertProjection = storage.CertProjection{}
		}
	}
	return recs, err
}

func (b *unknownRepairBackend) record(op, serial string) {
	if b.recording {
		b.writes = append(b.writes, op+":"+serial)
	}
}

func (b *unknownRepairBackend) SetRevoked(ctx context.Context, serial string, at time.Time) error {
	b.record("SetRevoked", serial)
	return b.SQLBackend.SetRevoked(ctx, serial, at)
}

func (b *unknownRepairBackend) ClearRevoked(ctx context.Context, serial string) error {
	b.record("ClearRevoked", serial)
	return b.SQLBackend.ClearRevoked(ctx, serial)
}

func (b *unknownRepairBackend) SetProjection(ctx context.Context, serial string, proj storage.CertProjection) error {
	b.record("SetProjection", serial)
	return b.SQLBackend.SetProjection(ctx, serial, proj)
}

// signLeafWithAuthRole builds a leaf certificate for subject signed directly
// by the cached test CA, carrying a pp_auth_role authorization extension —
// something the normal signing path can never produce, since it strips
// auth-arc OIDs from CSRs. Returns the certificate PEM, ready for
// ImportCertificate.
func signLeafWithAuthRole(subject, role string) []byte {
	keyBlock, _ := pem.Decode(cachedKeyPEM)
	Expect(keyBlock).NotTo(BeNil())
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	Expect(err).NotTo(HaveOccurred())
	certBlock, _ := pem.Decode(cachedCrtPEM)
	Expect(certBlock).NotTo(BeNil())
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	Expect(err).NotTo(HaveOccurred())

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	roleValue, err := asn1.MarshalWithParams(role, "utf8")
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x1D01),
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 13}, // pp_auth_role
			Value: roleValue,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

var _ = Describe("CA certificate index", func() {
	var (
		ctx   = context.Background()
		myCA  *ca.CA
		store *storage.StorageService
	)

	// newCA builds and initialises a CA over the given storage service,
	// pre-seeded with the cached test CA material.
	newCA := func(s *storage.StorageService) *ca.CA {
		c := ca.New(s, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(s.EnsureDirs(ctx)).To(Succeed())
		Expect(s.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(s.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(s.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(s.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(s.TouchInventory(ctx)).To(Succeed())
		Expect(c.Init(ctx)).To(Succeed())
		return c
	}

	signLive := func(c *ca.CA, subject string) {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
	}

	// storedFingerprint computes the display fingerprint of the certificate
	// currently stored for subject, from the authoritative PEM.
	storedFingerprint := func(s *storage.StorageService, subject string) string {
		certPEM, err := s.GetCert(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		Expect(block).NotTo(BeNil())
		return ca.SHA256ColonFingerprint(block.Bytes)
	}

	newSQLiteService := func() *storage.StorageService {
		dir := GinkgoT().TempDir()
		b, err := storage.NewSQLBackend(storage.SQLConfig{
			Dialect: storage.SQLitePure,
			DSN:     "file:" + filepath.Join(dir, "ca.db"),
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = b.Close() })
		Expect(b.EnsureReady(ctx)).To(Succeed())
		return storage.NewWithBackend(b, dir)
	}

	Context("on a SQL backend", func() {
		BeforeEach(func() {
			store = newSQLiteService()
			myCA = newCA(store)
		})

		It("clears a revocation the CRL no longer corroborates when repair runs", func() {
			signLive(myCA, "node1")
			Expect(myCA.Revoke(ctx, "node1")).To(Succeed())

			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].State).To(Equal(storage.CertStateRevoked))

			// Restore the pristine (empty) CRL over the one Revoke signed —
			// the CRL-from-backup scenario. The index row still claims a
			// revocation the signed CRL no longer corroborates; the repair
			// pass at the next startup must clear it.
			Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
			restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(restarted.Init(ctx)).To(Succeed())

			recs, _, err = store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].State).To(Equal(storage.CertStateSigned))
			Expect(recs[0].RevokedAt).To(BeNil())
		})

		It("leaves the projection empty when the stored certificate is not the one the row names", func() {
			// The safety guard the backfill exists around. A row whose serial does
			// not match the stored PEM does not describe that certificate -- a
			// crash between the blob write and the inventory write produces exactly
			// that -- and stamping it with the other certificate's fingerprint,
			// validity and auth extensions would make the status API assert
			// something untrue about a credential.
			signLive(myCA, "node1")

			// Replace the stored PEM with a different certificate under the same
			// subject, so the row's serial no longer matches what is on disk.
			other := signLeafWithAuthRole("node1", "webserver")
			Expect(store.SaveCert(ctx, "node1", other)).To(Succeed())

			// Clear the projection so the repair pass has something to backfill.
			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(store.SetCertProjection(ctx, recs[0].Serial, storage.CertProjection{})).To(Succeed())

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(restarted.Init(ctx)).To(Succeed(),
				"a mismatched row must not stop the CA starting")

			recs, _, err = store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].Fingerprint).To(BeEmpty(),
				"the projection must stay empty rather than describe another certificate")
			Expect(buf.String()).To(ContainSubstring("serial does not match index record"))
		})

		It("skips a malformed serial without abandoning the rest of the repair", func() {
			// The repair walks every record, so one unparseable serial must not
			// stop the records after it from being reconciled. A `continue` that
			// was a `return` would leave the rest of the index stale, and the
			// index is what the status API answers from.
			signLive(myCA, "good-node")
			Expect(myCA.Revoke(ctx, "good-node")).To(Succeed())

			// A record whose serial is not hex at all. It needs a stored
			// certificate blob as well as the row: CertStatuses reports only
			// subjects that have one, so a row without a blob never reaches the
			// repair loop at all -- which is why this branch was unreachable from
			// the inventory alone.
			Expect(store.AppendInventoryRecord(ctx, "zz-not-hex 2026-01-01T00:00:00UTC 2036-01-01T00:00:00UTC /broken-node",
				&storage.CertProjection{})).To(Succeed())
			Expect(store.SaveCert(ctx, "broken-node", signLeafWithAuthRole("broken-node", "webserver"))).To(Succeed())

			// Restore the pristine CRL so the good record needs its revocation
			// cleared -- work the repair can only do if it gets past the bad row.
			Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())

			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(orig)

			restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(restarted.Init(ctx)).To(Succeed())

			// Both layers report it: the serial index built from the inventory
			// blob, and the index repair walking the rows.
			Expect(buf.String()).To(ContainSubstring("skipping malformed serial in inventory"))
			Expect(buf.String()).To(ContainSubstring("malformed serial in index record"))

			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			// The claim is that the record *after* the malformed one is still
			// reconciled, and that only holds because Statuses orders by subject
			// and "broken-node" sorts first. Asserted, so a rename cannot quietly
			// turn this into a spec that passes whatever the loop does.
			Expect(recs[0].Subject).To(Equal("broken-node"),
				"the malformed row must be reconciled first for this spec to mean anything")
			bySubject := map[string]storage.CertRecord{}
			for _, r := range recs {
				bySubject[r.Subject] = r
			}
			Expect(bySubject).To(HaveKey("good-node"))
			Expect(bySubject["good-node"].State).To(Equal(storage.CertStateSigned),
				"the record after the malformed one must still be reconciled")
			Expect(bySubject["good-node"].RevokedAt).To(BeNil())
		})

		It("re-projects a revocation that was already recorded", func() {
			// Revoke returns early when the serial is already in the CRL, which is
			// the retry path -- an operator repeating a command, or a replica
			// catching up. If the early return skipped the index write, an index
			// row that missed the first projection would stay wrong for ever,
			// because every later attempt takes the same early exit.
			signLive(myCA, "node1")
			Expect(myCA.Revoke(ctx, "node1")).To(Succeed())

			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(store.ClearCertRevoked(ctx, recs[0].Serial)).To(Succeed())

			Expect(myCA.Revoke(ctx, "node1")).To(Succeed(),
				"revoking an already-revoked certificate is not an error")

			recs, _, err = store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].State).To(Equal(storage.CertStateRevoked),
				"the retry must re-project the revocation the index had lost")
			Expect(recs[0].RevokedAt).NotTo(BeNil())
		})

		It("projects an inventory record on a backend with no index, without failing", func() {
			// AppendInventoryRecord's contract is that the projection is ignored on
			// a backend without the capability. Nothing asserted it, so a change
			// that made the projection mandatory would break every blob backend at
			// signing time and pass here.
			blobDir := GinkgoT().TempDir()
			blobStore := storage.New(blobDir)
			Expect(blobStore.EnsureDirs(ctx)).To(Succeed())
			Expect(blobStore.TouchInventory(ctx)).To(Succeed())

			line := "aa 2026-01-01T00:00:00UTC 2036-01-01T00:00:00UTC /node1"
			Expect(blobStore.AppendInventoryRecord(ctx, line, &storage.CertProjection{
				Fingerprint: "SHA256:whatever",
			})).To(Succeed(), "the projection must be ignored, not rejected")

			data, err := blobStore.ReadInventory(ctx)
			Expect(err).NotTo(HaveOccurred())
			// Equality, not a substring: the inventory line is a byte-compatibility
			// contract with Puppet's inventory.txt, so "the projection is ignored"
			// must mean nothing extra was written -- a substring would pass just as
			// happily if a fingerprint were appended. The line is in OpenVox
			// Server's format, which is what the filesystem backend writes.
			Expect(string(data)).To(Equal("0x00AA 2026-01-01T00:00:00UTC 2036-01-01T00:00:00UTC /CN=node1\n"))

			_, ok, err := blobStore.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeFalse(), "a blob backend has no index to answer from")
		})

		It("projects auth extensions from an imported certificate through the index", func() {
			// Signing strips auth-arc OIDs from CSRs (privilege escalation
			// guard), so the only way a stored certificate legitimately
			// carries one is the import path — build a leaf signed directly
			// by the test CA with pp_auth_role and import it.
			certPEM := signLeafWithAuthRole("import-node", "webserver")
			res, err := myCA.ImportCertificate(ctx, "import-node", certPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Imported).To(BeTrue())

			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].AuthExtensions).To(Equal(map[string]string{"pp_auth_role": "webserver"}),
				"the auth extension must survive sign→projection→JSON column→record")
			Expect(recs[0].Fingerprint).To(Equal(storedFingerprint(store, "import-node")))
		})

		It("reconciles a zero-padded row serial against the CRL when repair runs", func() {
			signLive(myCA, "padded-node")
			Expect(myCA.Revoke(ctx, "padded-node")).To(Succeed())

			// A legacy blob import can carry the same serial zero-padded.
			// Plant one as the subject's latest issuance, projection-less and
			// still claiming "signed": only the repair pass's big.Int
			// normalisation can connect it to the CRL entry, which the CA
			// keys by the canonical %X form.
			certPEM, err := store.GetCert(ctx, "padded-node")
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(certPEM)
			Expect(block).NotTo(BeNil())
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			padded := "00" + fmt.Sprintf("%X", cert.SerialNumber)
			line := storage.FormatInventoryLine(padded, cert.NotBefore, cert.NotAfter, "padded-node")
			Expect(store.AppendInventory(ctx, line)).To(Succeed())

			restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(restarted.Init(ctx)).To(Succeed())

			recs, _, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(1))
			Expect(recs[0].Serial).To(Equal(padded))
			Expect(recs[0].State).To(Equal(storage.CertStateRevoked),
				"repair must match the padded row serial to the canonical CRL entry")
			Expect(recs[0].RevokedAt).NotTo(BeNil())
			Expect(recs[0].Fingerprint).To(Equal(storedFingerprint(store, "padded-node")),
				"the backfill accepts the pairing: the padded row and the PEM name the same certificate")
		})

		It("records the projection at signing and the revocation at revoke time", func() {
			signLive(myCA, "node1")
			signLive(myCA, "node2")
			Expect(myCA.Revoke(ctx, "node2")).To(Succeed())

			recs, ok, err := store.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
			Expect(recs).To(HaveLen(2))

			bySubject := map[string]storage.CertRecord{}
			for _, r := range recs {
				bySubject[r.Subject] = r
			}
			Expect(bySubject["node1"].State).To(Equal(storage.CertStateSigned))
			Expect(bySubject["node1"].RevokedAt).To(BeNil())
			Expect(bySubject["node1"].Fingerprint).To(Equal(storedFingerprint(store, "node1")),
				"the projected fingerprint must match the stored PEM")
			Expect(bySubject["node2"].State).To(Equal(storage.CertStateRevoked),
				"Revoke must project into the index without a restart")
			Expect(bySubject["node2"].RevokedAt).NotTo(BeNil())
		})
	})

	Context("after migrating a blob-backed CA into a SQL backend", func() {
		It("backfills projections and revocation state from the PEMs and CRL at startup", func() {
			// Build a filesystem CA with one live and one revoked certificate.
			fsDir := GinkgoT().TempDir()
			fsStore := storage.New(fsDir)
			fsCA := newCA(fsStore)
			signLive(fsCA, "node1")
			signLive(fsCA, "node2")
			Expect(fsCA.Revoke(ctx, "node2")).To(Succeed())

			// Migrate it into a fresh SQLite backend. The inventory arrives as
			// parsed rows with no projection and no revocation state.
			sqlStore := newSQLiteService()
			_, err := storage.MigrateService(ctx, fsStore, sqlStore, storage.MigrateOptions{})
			Expect(err).NotTo(HaveOccurred())

			recs, ok, err := sqlStore.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(ok).To(BeTrue())
			Expect(recs).To(HaveLen(2))
			for _, r := range recs {
				Expect(r.Fingerprint).To(BeEmpty(), "migrated rows start projection-less")
				Expect(r.State).To(Equal(storage.CertStateSigned))
			}

			// Initialising a CA over the migrated backend runs the index
			// repair pass, which reconciles the rows from the authoritative
			// artefacts: the stored PEMs and the signed CRL.
			sqlCA := ca.New(sqlStore, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(sqlCA.Init(ctx)).To(Succeed())

			recs, _, err = sqlStore.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(2))
			bySubject := map[string]storage.CertRecord{}
			for _, r := range recs {
				bySubject[r.Subject] = r
			}
			Expect(bySubject["node1"].Fingerprint).To(Equal(storedFingerprint(sqlStore, "node1")))
			Expect(bySubject["node1"].State).To(Equal(storage.CertStateSigned))
			Expect(bySubject["node2"].Fingerprint).To(Equal(storedFingerprint(sqlStore, "node2")))
			Expect(bySubject["node2"].State).To(Equal(storage.CertStateRevoked))
			Expect(bySubject["node2"].RevokedAt).NotTo(BeNil())

			// The repaired states must agree with the CRL, entry for entry:
			// the single CRL entry carries node2's serial.
			crlPEM, err := sqlStore.GetCRL(ctx)
			Expect(err).NotTo(HaveOccurred())
			block, _ := pem.Decode(crlPEM)
			Expect(block).NotTo(BeNil())
			crl, err := x509.ParseRevocationList(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(crl.RevokedCertificateEntries).To(HaveLen(1))
			node2Serial := new(big.Int)
			_, ok = node2Serial.SetString(bySubject["node2"].Serial, 16)
			Expect(ok).To(BeTrue(), "index serial must be hex")
			Expect(crl.RevokedCertificateEntries[0].SerialNumber.Cmp(node2Serial)).To(BeZero(),
				"the revoked index record's serial must be the CRL entry's serial")
		})

		It("skips unknown-state records during repair while still repairing siblings", func() {
			// The etcd backend reports CertStateUnknown for records whose
			// serial it cannot address one-to-one; index writes for them are
			// refused, so the repair pass must skip them entirely — no
			// backfill attempt, no state reconciliation, no per-start
			// warnings — while siblings are repaired as normal. Simulate the
			// backend with a wrapper that relabels one subject's record.
			dir := GinkgoT().TempDir()
			inner, err := storage.NewSQLBackend(storage.SQLConfig{
				Dialect: storage.SQLitePure,
				DSN:     "file:" + filepath.Join(dir, "ca.db"),
			})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = inner.Close() })
			Expect(inner.EnsureReady(ctx)).To(Succeed())
			wrapper := &unknownRepairBackend{SQLBackend: inner, subject: "node-unknown"}
			wrapped := storage.NewWithBackend(wrapper, dir)
			wrappedCA := newCA(wrapped)

			signLive(wrappedCA, "node-unknown")
			signLive(wrappedCA, "node-sibling")
			// Leave the sibling's index claiming a revocation the pristine
			// CRL does not corroborate, so repair has real work to do for it.
			Expect(wrappedCA.Revoke(ctx, "node-sibling")).To(Succeed())
			Expect(wrapped.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())

			recs, _, err := wrapped.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(recs).To(HaveLen(2))
			var unknownSerial string
			for _, r := range recs {
				if r.Subject == "node-unknown" {
					unknownSerial = r.Serial
					Expect(r.State).To(Equal(storage.CertStateUnknown))
					Expect(r.Fingerprint).To(BeEmpty(), "relabelled record must look backfillable")
				}
			}
			Expect(unknownSerial).NotTo(BeEmpty())

			// Snapshot the stored row through the INNER backend: the wrapper
			// rewrites node-unknown's record on every read, so untouchedness
			// can only be asserted against the unwrapped rows.
			innerBefore, err := inner.Statuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			var storedBefore storage.CertRecord
			for _, r := range innerBefore {
				if r.Subject == "node-unknown" {
					storedBefore = r
				}
			}
			Expect(storedBefore.Serial).To(Equal(unknownSerial))

			// Record index writes only from the repair pass onwards.
			wrapper.recording = true
			restarted := ca.New(wrapped, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			Expect(restarted.Init(ctx)).To(Succeed())

			for _, w := range wrapper.writes {
				Expect(w).NotTo(ContainSubstring(unknownSerial),
					"repair must not write to an unknown-state record: %v", wrapper.writes)
			}
			Expect(wrapper.writes).NotTo(BeEmpty(), "the sibling's stale revocation must have been repaired")

			recs, _, err = wrapped.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			bySubject := map[string]storage.CertRecord{}
			for _, r := range recs {
				bySubject[r.Subject] = r
			}
			Expect(bySubject["node-sibling"].State).To(Equal(storage.CertStateSigned),
				"the sibling must be repaired despite the unknown record being skipped")
			Expect(bySubject["node-unknown"].State).To(Equal(storage.CertStateUnknown),
				"the unknown record must still be listed as unknown")

			// Untouchedness is asserted against the inner backend's rows —
			// the wrapper's rewrite cannot mask a mutation there.
			innerAfter, err := inner.Statuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			var storedAfter storage.CertRecord
			for _, r := range innerAfter {
				if r.Subject == "node-unknown" {
					storedAfter = r
				}
			}
			Expect(storedAfter).To(Equal(storedBefore), "the unknown record's stored row must be untouched by the repair")
		})
	})
})
