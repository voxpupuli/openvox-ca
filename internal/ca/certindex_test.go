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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

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
	})
})
