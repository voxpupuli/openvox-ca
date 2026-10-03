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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// These specs start the CA on a filesystem inventory that OpenVox Server
// wrote, with no import step: its lines carry a "0x" serial zero-padded to
// four digits and a "/CN=" subject, where this CA writes neither. Every reader
// that resolves an entry by name or by serial has to see through that, or a
// certificate OpenVox Server issued silently cannot be revoked, answered for,
// or cleaned up.
var _ = Describe("A filesystem inventory written by OpenVox Server", func() {
	var (
		ctx    = context.Background()
		tmpDir string
		store  *storage.StorageService
		myCA   *ca.CA
		caKey  crypto.Signer
		caCert *x509.Certificate
	)

	// ovsLine renders an inventory line the way OpenVox Server's writer does.
	ovsLine := func(serial int64, notBefore, notAfter time.Time, cn string) string {
		return fmt.Sprintf("0x%04X %s %s /CN=%s\n", serial,
			notBefore.UTC().Format(storage.InventoryTimeFormat),
			notAfter.UTC().Format(storage.InventoryTimeFormat), cn)
	}

	// mint signs a leaf as OpenVox Server would have, with its sequential
	// serial, outside this CA's own issuance path.
	mint := func(serial int64, cn string, notBefore, notAfter time.Time) *x509.Certificate {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			DNSNames:     []string{cn},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}, caCert, &key.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		cert, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	// issuedByOVS stores a certificate and its inventory line as OpenVox
	// Server leaves them: the PEM in signed/, the line appended to the file
	// with no integrity value touched.
	issuedByOVS := func(serial int64, cn string, notBefore, notAfter time.Time, current bool) *x509.Certificate {
		cert := mint(serial, cn, notBefore, notAfter)
		if current {
			Expect(store.SaveCert(ctx, cn,
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))).To(Succeed())
		}
		Expect(store.Backend().AppendLine(ctx, storage.KeyInventory,
			[]byte(ovsLine(serial, notBefore, notAfter, cn)), storage.BlobPrivate)).To(Succeed())
		return cert
	}

	now := time.Now().UTC().Truncate(time.Second)
	lastYear, nextYear := now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-ovs-inventory-test")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(tmpDir)).To(Succeed()) })

		keyBlock, _ := pem.Decode(cachedKeyPEM)
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		certBlock, _ := pem.Decode(cachedCrtPEM)
		caCert, err = x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		store = storage.New(tmpDir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
	})

	It("writes a line OpenVox Server's own reader resolves when it signs", func() {
		// The reader is OpenVox Server's, transcribed: find-matching-valid-
		// serial-numbers splits the line on " ", compares the subject with
		// its leading "/" dropped against "CN=<certname>", and parses the
		// serial with base-16-str->biginteger, which drops the first two
		// characters unconditionally. A line this CA writes must survive all
		// three, or OpenVox Server cannot revoke what this CA issued by name.
		Expect(myCA.Init(ctx)).To(Succeed())
		csrPEM, _ := buildCSR("agent.example.com")
		_, err := myCA.SaveRequest(ctx, "agent.example.com", csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, "agent.example.com")
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())

		inv, err := store.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		row := strings.Split(strings.TrimSuffix(string(inv), "\n"), " ")
		Expect(row).To(HaveLen(4))
		Expect(row[3][1:]).To(Equal("CN=agent.example.com"), "is-subject-in-inventory-row?")
		serial, ok := new(big.Int).SetString(row[0][2:], 16)
		Expect(ok).To(BeTrue(), "base-16-str->biginteger")
		Expect(serial).To(Equal(cert.SerialNumber))
		Expect(row[2]).To(Equal(cert.NotAfter.UTC().Format(storage.InventoryTimeFormat)), "is-not-expired?")
	})

	It("revokes by name a certificate OpenVox Server issued", func() {
		leaf := issuedByOVS(2, "agent.example.com", lastYear, nextYear, true)
		Expect(myCA.Init(ctx)).To(Succeed())

		Expect(myCA.Revoke(ctx, "agent.example.com")).To(Succeed())
		Expect(myCA.IsRevokedSerial(ctx, leaf.SerialNumber)).To(BeTrue())
	})

	It("revokes by name the newest certificate OpenVox Server issued under a renewed name", func() {
		// OpenVox Server renewed web.example.com from 0x0003 to 0x0004; the
		// newest line is the one revocation by name resolves.
		issuedByOVS(3, "web.example.com", lastYear, nextYear, false)
		current := issuedByOVS(4, "web.example.com", lastYear.AddDate(0, 1, 0), nextYear, true)
		Expect(myCA.Init(ctx)).To(Succeed())

		Expect(myCA.Revoke(ctx, "web.example.com")).To(Succeed())
		Expect(myCA.IsRevokedSerial(ctx, current.SerialNumber)).To(BeTrue())
	})

	It("revokes by serial a superseded certificate OpenVox Server issued", func() {
		// SubjectForSerial is the lookup that admits a serial at all; read as
		// "0x0003" it could not be parsed and the serial was "unknown".
		old := issuedByOVS(3, "web.example.com", lastYear, nextYear, false)
		issuedByOVS(4, "web.example.com", lastYear.AddDate(0, 1, 0), nextYear, true)
		Expect(myCA.Init(ctx)).To(Succeed())

		Expect(myCA.RevokeSerial(ctx, "3", false)).To(Succeed())
		Expect(myCA.IsRevokedSerial(ctx, old.SerialNumber)).To(BeTrue())
	})

	It("answers OCSP for a certificate OpenVox Server issued", func() {
		// The serial index is built from the inventory at Init; a line it
		// could not parse made the certificate "unknown" to the responder.
		leaf := issuedByOVS(2, "agent.example.com", lastYear, nextYear, true)
		Expect(myCA.Init(ctx)).To(Succeed())

		Expect(ocspStatusFor(myCA, leaf)).To(Equal(xocsp.Good))
		Expect(myCA.Revoke(ctx, "agent.example.com")).To(Succeed())
		Expect(ocspStatusFor(myCA, leaf)).To(Equal(xocsp.Revoked))
	})

	It("cleans up an expired certificate OpenVox Server issued, CRL entry and all", func() {
		gone := issuedByOVS(6, "gone.example.com", now.AddDate(-3, 0, 0), now.AddDate(-2, 0, 0), true)
		issuedByOVS(7, "kept.example.com", lastYear, nextYear, true)

		// OpenVox Server revoked it before it expired.
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number:     big.NewInt(2),
			ThisUpdate: now.Add(-time.Hour),
			NextUpdate: now.AddDate(0, 0, 30),
			RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: gone.SerialNumber, RevocationTime: now.AddDate(-2, -1, 0)},
			},
		}, caCert, caKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))).To(Succeed())
		Expect(myCA.Init(ctx)).To(Succeed())
		Expect(myCA.IsRevokedSerial(ctx, gone.SerialNumber)).To(BeTrue(), "precondition")

		Expect(myCA.CleanupExpiredCerts(ctx, 0)).To(Equal(1))

		Expect(myCA.IsRevokedSerial(ctx, gone.SerialNumber)).To(BeFalse(),
			"the expired serial must leave the CRL with its inventory line")
		_, err = os.Stat(filepath.Join(tmpDir, "signed", "gone.example.com.pem"))
		Expect(err).To(MatchError(os.ErrNotExist), "and its stored certificate must go")

		inv, err := store.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(inv)).To(Equal(ovsLine(7, lastYear, nextYear, "kept.example.com")),
			"the surviving line must still be OpenVox Server's, byte for byte")
	})

	It("refuses to import a certificate OpenVox Server already recorded", func() {
		leaf := issuedByOVS(2, "agent.example.com", lastYear, nextYear, false)
		Expect(myCA.Init(ctx)).To(Succeed())

		_, err := myCA.ImportCertificate(ctx, "agent.example.com",
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
		Expect(err).To(MatchError(ca.ErrSerialExists))
		inv, err := store.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(strings.Count(string(inv), "\n")).To(Equal(1), "no second line for the same serial")
	})
})
