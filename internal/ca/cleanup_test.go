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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// cleanupInventoryFormat matches the layout the signing path writes and
// CleanupExpiredCerts parses.
const cleanupInventoryFormat = "2006-01-02T15:04:05UTC"

// partialPruneBackend wraps a real structured backend, delegating everything
// and injecting an error after a successful prune — modelling a batched
// backend (etcd) that durably removed entries and then failed. Per the
// PruneEntries contract the removed entries are still returned with the
// error.
type partialPruneBackend struct {
	*storage.SQLBackend
	pruneErr error
}

func (b *partialPruneBackend) PruneEntries(ctx context.Context, keep func(storage.InventoryEntry) bool, advanceHead func(prev []byte, e storage.InventoryEntry) []byte) ([]storage.InventoryEntry, error) {
	removed, err := b.SQLBackend.PruneEntries(ctx, keep, advanceHead)
	if err != nil || len(removed) == 0 {
		return removed, err
	}
	return removed, b.pruneErr
}

var _ = Describe("CA CleanupExpiredCerts", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
		caKey  crypto.Signer
		caCert *x509.Certificate
	)

	// signLive issues a real certificate for subject via the normal path; its
	// NotAfter is in the future (capped to the CA's remaining lifetime).
	signLive := func(subject string) {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
	}

	// seedCert creates a leaf certificate signed by the cached test CA with the
	// given serial and NotAfter, saves it as the stored cert for subject, appends
	// a matching inventory entry, and revokes it so its serial lands in the CRL.
	// notAfter may be in the past, which the normal signing path cannot produce.
	seedCert := func(subject string, serial *big.Int, notAfter time.Time) {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(csrPEM)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      csr.Subject,
			NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
			NotAfter:     notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		Expect(store.SaveCert(ctx, subject, certPEM)).To(Succeed())

		entry := fmt.Sprintf("%s %s %s /%s",
			serial.Text(16),
			template.NotBefore.Format(cleanupInventoryFormat),
			notAfter.Format(cleanupInventoryFormat),
			subject)
		Expect(store.AppendInventory(ctx, entry)).To(Succeed())

		// Revoke so the serial is present in the CRL (Revoke resolves the serial
		// from the inventory entry just appended).
		Expect(myCA.Revoke(ctx, subject)).To(Succeed())
	}

	inventoryString := func() string {
		data, err := store.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred()) // also asserts the integrity head verifies
		return string(data)
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-cleanup-test")
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

		keyBlock, _ := pem.Decode(cachedKeyPEM)
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		certBlock, _ := pem.Decode(cachedCrtPEM)
		caCert, err = x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("removes an expired cert from the inventory, the CRL, and storage", func() {
		signLive("live-node")
		expiredSerial := big.NewInt(0xABCD)
		seedCert("expired-node", expiredSerial, time.Now().Add(-3*365*24*time.Hour))

		// Precondition: the seeded cert is revoked and present everywhere.
		Expect(parseStoredCRL(store).RevokedCertificateEntries).To(HaveLen(1))
		Expect(store.HasCert(ctx, "expired-node")).To(BeTrue())
		Expect(inventoryString()).To(ContainSubstring("/expired-node"))

		removed, err := myCA.CleanupExpiredCerts(ctx, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(1))

		inv := inventoryString()
		Expect(inv).NotTo(ContainSubstring("/expired-node"))
		Expect(inv).To(ContainSubstring("/live-node"))
		Expect(parseStoredCRL(store).RevokedCertificateEntries).To(BeEmpty())
		Expect(store.HasCert(ctx, "expired-node")).To(BeFalse())
		Expect(store.HasCert(ctx, "live-node")).To(BeTrue())
	})

	It("does not remove certs that are still within the retention grace period", func() {
		// Expired only 1 hour ago, but retention is 30 days: must be kept.
		seedCert("recent-node", big.NewInt(0x1234), time.Now().Add(-time.Hour))

		removed, err := myCA.CleanupExpiredCerts(ctx, 30*24*time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(0))
		Expect(inventoryString()).To(ContainSubstring("/recent-node"))
		Expect(parseStoredCRL(store).RevokedCertificateEntries).To(HaveLen(1))
	})

	It("returns zero and changes nothing when no certs have expired", func() {
		signLive("live-node")
		before := inventoryString()

		removed, err := myCA.CleanupExpiredCerts(ctx, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(0))
		Expect(inventoryString()).To(Equal(before))
	})

	It("keeps entries whose NotAfter cannot be parsed rather than dropping them", func() {
		// A malformed NotAfter field must never be treated as expired.
		Expect(store.AppendInventory(ctx, "00FF 2024-01-01T00:00:00UTC not-a-timestamp /weird-node")).To(Succeed())

		removed, err := myCA.CleanupExpiredCerts(ctx, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(0))
		Expect(inventoryString()).To(ContainSubstring("/weird-node"))
	})

	It("cleans up returned entries and reports the count even when the prune errors", func() {
		// Batched backends (etcd) can durably remove entries and then fail;
		// PruneInventory returns those entries alongside the error, and the
		// cleanup must still drop their CRL entries and stored certs — the
		// inventory no longer names them, so no later run could. Model that
		// with a backend whose prune succeeds and then reports an error.
		injected := fmt.Errorf("simulated mid-prune failure")
		inner, err := storage.NewSQLBackend(storage.SQLConfig{
			Dialect: storage.SQLitePure,
			DSN:     "file:" + filepath.Join(tmpDir, "partial-prune.db"),
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = inner.Close() })
		Expect(inner.EnsureReady(ctx)).To(Succeed())
		store = storage.NewWithBackend(&partialPruneBackend{SQLBackend: inner, pruneErr: injected},
			filepath.Join(tmpDir, "partial-private"))
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())

		seedCert("expired-node", big.NewInt(0xEE01), time.Now().Add(-3*365*24*time.Hour))
		Expect(parseStoredCRL(store).RevokedCertificateEntries).To(HaveLen(1))

		removed, err := myCA.CleanupExpiredCerts(ctx, time.Hour)
		Expect(err).To(MatchError(injected), "the prune error must surface to the caller")
		Expect(removed).To(Equal(1), "the durably removed entry must still be counted")

		// The cleanup for the returned entry ran despite the error: nothing
		// is orphaned.
		Expect(inventoryString()).NotTo(ContainSubstring("/expired-node"))
		Expect(parseStoredCRL(store).RevokedCertificateEntries).To(BeEmpty(),
			"the CRL entry must be dropped despite the prune error")
		Expect(store.HasCert(ctx, "expired-node")).To(BeFalse(),
			"the stored cert must be deleted despite the prune error")
	})

	It("preserves a renewed cert under the same subject when an old serial expires", func() {
		// Stored cert is the live (renewed) one; the expired entry carries a
		// different, older serial. Cleanup must drop the old inventory/CRL entry
		// but leave the current stored cert in place.
		signLive("renewed-node")
		liveCertBefore, err := store.GetCert(ctx, "renewed-node")
		Expect(err).NotTo(HaveOccurred())

		oldSerial := big.NewInt(0x5151)
		// Append an old, expired inventory entry + CRL revocation for the same
		// subject, without overwriting the stored (renewed) cert.
		entry := fmt.Sprintf("%s %s %s /%s", oldSerial.Text(16),
			time.Now().Add(-4*365*24*time.Hour).Format(cleanupInventoryFormat),
			time.Now().Add(-3*365*24*time.Hour).Format(cleanupInventoryFormat),
			"renewed-node")
		Expect(store.AppendInventory(ctx, entry)).To(Succeed())

		removed, err := myCA.CleanupExpiredCerts(ctx, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(1))

		// The current cert for the subject survived because its serial differs
		// from the expired one.
		liveCertAfter, err := store.GetCert(ctx, "renewed-node")
		Expect(err).NotTo(HaveOccurred())
		Expect(liveCertAfter).To(Equal(liveCertBefore))

		inv := inventoryString()
		Expect(inv).To(ContainSubstring("/renewed-node"))
		Expect(strings.Count(inv, "/renewed-node")).To(Equal(1))
	})
})

var _ = Describe("CA CleanMultiple", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		myCA   *ca.CA
		store  *storage.StorageService
	)

	// issue saves and signs a fresh CSR for subject, mirroring how Clean is
	// exercised elsewhere in the suite.
	issue := func(subject string) {
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-cleanmultiple-test")
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

	It("marks every existing subject as cleaned and removes its cert", func() {
		issue("node-a")
		issue("node-b")
		issue("node-c")

		result := myCA.CleanMultiple(ctx, []string{"node-a", "node-b", "node-c"})

		Expect(result.Cleaned).To(ConsistOf("node-a", "node-b", "node-c"))
		Expect(result.NotFound).To(BeEmpty())
		Expect(result.CleanErrors).To(BeEmpty())

		// Each cleaned subject's certificate must be gone from storage.
		Expect(store.HasCert(ctx, "node-a")).To(BeFalse())
		Expect(store.HasCert(ctx, "node-b")).To(BeFalse())
		Expect(store.HasCert(ctx, "node-c")).To(BeFalse())
	})

	It("reports per-subject success and not-found for a mixed batch", func() {
		issue("present-1")
		issue("present-2")

		result := myCA.CleanMultiple(ctx, []string{
			"present-1", "ghost-1", "present-2", "ghost-2",
		})

		Expect(result.Cleaned).To(ConsistOf("present-1", "present-2"))
		Expect(result.NotFound).To(ConsistOf("ghost-1", "ghost-2"))
		Expect(result.CleanErrors).To(BeEmpty())

		Expect(store.HasCert(ctx, "present-1")).To(BeFalse())
		Expect(store.HasCert(ctx, "present-2")).To(BeFalse())
	})

	It("returns empty result slices for an empty subject list", func() {
		result := myCA.CleanMultiple(ctx, []string{})

		Expect(result.Cleaned).To(BeEmpty())
		Expect(result.NotFound).To(BeEmpty())
		Expect(result.CleanErrors).To(BeEmpty())
	})
})
