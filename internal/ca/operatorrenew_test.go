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
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("CA RenewStored", func() {
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

	issue := func(subject string) *x509.Certificate {
		GinkgoHelper()
		csrPEM, _ := buildCSR(subject)
		_, err := myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		certPEM, err := myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCert(certPEM)
	}

	stored := func(subject string) *x509.Certificate {
		GinkgoHelper()
		data, err := store.GetCert(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
		return parseCert(data)
	}

	// revoked answers from the stored CRL, not the in-memory copy.
	revoked := func(serial *big.Int) bool {
		GinkgoHelper()
		crlPEM, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		block, _ := pem.Decode(crlPEM)
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(serial) == 0 {
				return true
			}
		}
		return false
	}

	pending := func() []pendingEntry {
		GinkgoHelper()
		data, err := store.GetSuperseded(ctx)
		if os.IsNotExist(err) {
			return nil
		}
		Expect(err).NotTo(HaveOccurred())
		var entries []pendingEntry
		Expect(json.Unmarshal(data, &entries)).To(Succeed())
		return entries
	}

	// storeSignedBy writes a certificate for subject straight into storage,
	// signed by signer (self-signed when signer is nil), over a key of the
	// given RSA size. It is how a spec places a stored certificate no issuance
	// path would produce: a foreign one, or one below key policy.
	storeSignedBy := func(subject string, bits int, notAfter time.Time, signer *x509.Certificate, signerKey any) *x509.Certificate {
		GinkgoHelper()
		key, err := rsa.GenerateKey(rand.Reader, bits)
		Expect(err).NotTo(HaveOccurred())
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: subject},
			NotBefore:    notAfter.Add(-2 * time.Hour),
			NotAfter:     notAfter,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if signer == nil {
			signer, signerKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCert(ctx, subject, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))).To(Succeed())
		cert, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-renewstored-test")
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
		Expect(os.RemoveAll(tmpDir)).To(Succeed())
	})

	Describe("reissuing over the stored key", func() {
		It("issues a new serial for the same key, and stores it", func() {
			original := issue("keep-node")

			renewedPEM, err := myCA.RenewStored(ctx, "keep-node", nil)
			Expect(err).NotTo(HaveOccurred())
			renewed := parseCert(renewedPEM)

			Expect(renewed.SerialNumber).NotTo(Equal(original.SerialNumber))
			Expect(renewed.PublicKey).To(Equal(original.PublicKey))
			Expect(renewed.Subject.CommonName).To(Equal("keep-node"))
			Expect(stored("keep-node").SerialNumber).To(Equal(renewed.SerialNumber))
		})

		It("retires the predecessor at once when no window is configured", func() {
			original := issue("keep-now")

			_, err := myCA.RenewStored(ctx, "keep-now", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(revoked(original.SerialNumber)).To(BeTrue())
			Expect(pending()).To(BeEmpty())
		})

		It("puts the predecessor on the pending list when a window is configured", func() {
			myCA.SupersedeAfter = time.Hour
			original := issue("keep-later")

			_, err := myCA.RenewStored(ctx, "keep-later", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(revoked(original.SerialNumber)).To(BeFalse())
			entries := pending()
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Subject).To(Equal("keep-later"))
			Expect(entries[0].Serial).To(Equal(hexSerial(original.SerialNumber)))
		})

		It("leaves the predecessor valid when revoke_on_auto_renew is off, as AutoRenew does", func() {
			myCA.RevokeOnAutoRenew = false
			original := issue("keep-both")

			_, err := myCA.RenewStored(ctx, "keep-both", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(revoked(original.SerialNumber)).To(BeFalse())
			Expect(pending()).To(BeEmpty())
		})

		It("carries pp_cli_auth forward over the same key", func() {
			res, err := myCA.GenerateWithOptions(ctx, "admin-node", ca.GenerateOptions{
				AuthGrants: []ca.AuthGrant{ca.PpCliAuth()},
			})
			Expect(err).NotTo(HaveOccurred())
			original := parseCert(res.CertificatePEM)

			renewedPEM, err := myCA.RenewStored(ctx, "admin-node", nil)
			Expect(err).NotTo(HaveOccurred())
			renewed := parseCert(renewedPEM)

			Expect(renewed.PublicKey).To(Equal(original.PublicKey))
			Expect(renewed.Extensions).To(ContainElement(HaveField("Id", ca.OIDPpCliAuth)))
		})

		It("leaves a request queued for the subject alone, as AutoRenew does", func() {
			issue("queued-keep")
			queued, _ := buildCSR("queued-keep")
			Expect(store.SaveCSR(ctx, "queued-keep", queued)).To(Succeed())

			_, err := myCA.RenewStored(ctx, "queued-keep", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.HasCSR(ctx, "queued-keep")).To(BeTrue())
		})

		It("refuses a stored key below policy", func() {
			caCert := parseCert(cachedCrtPEM)
			keyBlock, _ := pem.Decode(cachedKeyPEM)
			caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			weak := storeSignedBy("weak-node", 1024, time.Now().Add(time.Hour), caCert, caKey)

			_, err = myCA.RenewStored(ctx, "weak-node", nil)
			Expect(err).To(MatchError(ca.ErrKeyPolicy))
			Expect(stored("weak-node").SerialNumber).To(Equal(weak.SerialNumber))
		})
	})

	Describe("re-keying onto a CSR", func() {
		It("issues for the CSR's key and retires the predecessor", func() {
			original := issue("rekey-node")
			csrPEM, csr := buildCSR("rekey-node")

			renewedPEM, err := myCA.RenewStored(ctx, "rekey-node", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			renewed := parseCert(renewedPEM)

			Expect(renewed.PublicKey).To(Equal(csr.PublicKey))
			Expect(renewed.PublicKey).NotTo(Equal(original.PublicKey))
			Expect(stored("rekey-node").SerialNumber).To(Equal(renewed.SerialNumber))
			Expect(revoked(original.SerialNumber)).To(BeTrue())
		})

		It("takes nothing from the CSR but its key", func() {
			// The pp_cli_auth refusal below rests on this: a CSR asking for
			// authority, names or a subject of its own gets none of them.
			original := issue("parity-node")
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())
			cliAuth, err := asn1.MarshalWithParams("true", "utf8")
			Expect(err).NotTo(HaveOccurred())
			role, err := asn1.MarshalWithParams("web", "utf8")
			Expect(err).NotTo(HaveOccurred())
			ppRole := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 1, 13}
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject:  pkix.Name{CommonName: "parity-node", Organization: []string{"Asked For"}},
				DNSNames: []string{"asked.example.com"},
				ExtraExtensions: []pkix.Extension{
					{Id: ca.OIDPpCliAuth, Value: cliAuth},
					{Id: ppRole, Value: role},
				},
			}, key)
			Expect(err).NotTo(HaveOccurred())

			renewedPEM, err := myCA.RenewStored(ctx, "parity-node",
				pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
			Expect(err).NotTo(HaveOccurred())
			renewed := parseCert(renewedPEM)

			Expect(renewed.PublicKey).To(Equal(&key.PublicKey))
			Expect(renewed.RawSubject).To(Equal(original.RawSubject))
			Expect(renewed.DNSNames).To(Equal(original.DNSNames))
			for _, ext := range renewed.Extensions {
				Expect(ext.Id.Equal(ca.OIDPpCliAuth)).To(BeFalse(), "a re-key must not grant pp_cli_auth")
				Expect(ext.Id.Equal(ppRole)).To(BeFalse(), "a re-key must not take a Puppet extension from the CSR")
			}
		})

		It("clears a request already queued for the subject", func() {
			issue("queued-rekey")
			queued, _ := buildCSR("queued-rekey")
			Expect(store.SaveCSR(ctx, "queued-rekey", queued)).To(Succeed())
			csrPEM, _ := buildCSR("queued-rekey")

			_, err := myCA.RenewStored(ctx, "queued-rekey", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(store.HasCSR(ctx, "queued-rekey")).To(BeFalse())
		})

		It("retires the predecessor even when revoke_on_auto_renew is off, as Renew does", func() {
			myCA.RevokeOnAutoRenew = false
			original := issue("rekey-always")
			csrPEM, _ := buildCSR("rekey-always")

			_, err := myCA.RenewStored(ctx, "rekey-always", csrPEM)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked(original.SerialNumber)).To(BeTrue())
		})

		It("refuses a certificate carrying pp_cli_auth, and issues nothing", func() {
			res, err := myCA.GenerateWithOptions(ctx, "admin-rekey", ca.GenerateOptions{
				AuthGrants: []ca.AuthGrant{ca.PpCliAuth()},
			})
			Expect(err).NotTo(HaveOccurred())
			original := parseCert(res.CertificatePEM)
			csrPEM, _ := buildCSR("admin-rekey")

			_, err = myCA.RenewStored(ctx, "admin-rekey", csrPEM)
			Expect(err).To(MatchError(ca.ErrRekeyAuthorised))
			Expect(stored("admin-rekey").SerialNumber).To(Equal(original.SerialNumber))
			Expect(revoked(original.SerialNumber)).To(BeFalse())
		})

		It("refuses a CSR for another name", func() {
			issue("csr-owner")
			csrPEM, _ := buildCSR("someone-else")

			_, err := myCA.RenewStored(ctx, "csr-owner", csrPEM)
			Expect(err).To(MatchError(ca.ErrRenewalCSR))
		})

		It("refuses a CSR whose signature does not verify", func() {
			issue("csr-forged")
			_, csr := buildCSR("csr-forged")
			raw := append([]byte(nil), csr.Raw...)
			raw[len(raw)-1] ^= 0xff
			forged := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})

			_, err := myCA.RenewStored(ctx, "csr-forged", forged)
			Expect(err).To(MatchError(ca.ErrRenewalCSR))
		})

		It("refuses bytes that are not a PEM CSR", func() {
			issue("csr-garbage")
			_, err := myCA.RenewStored(ctx, "csr-garbage", []byte("not a csr"))
			Expect(err).To(MatchError(ca.ErrRenewalCSR))
		})
	})

	Describe("refusals", func() {
		It("refuses a subject with no stored certificate", func() {
			_, err := myCA.RenewStored(ctx, "nobody", nil)
			Expect(err).To(MatchError(ca.ErrNotFound))
		})

		It("refuses a subject this CA manages, and issues nothing", func() {
			original := issue("managed-node")
			myCA.ManagedCerts = []ca.ManagedCert{{Spec: ca.CertSpec{Subject: "managed-node"}}}

			_, err := myCA.RenewStored(ctx, "managed-node", nil)
			Expect(err).To(MatchError(ca.ErrManagedSubject))
			Expect(stored("managed-node").SerialNumber).To(Equal(original.SerialNumber))
		})

		It("refuses a revoked certificate", func() {
			issue("revoked-node")
			Expect(myCA.Revoke(ctx, "revoked-node")).To(Succeed())

			_, err := myCA.RenewStored(ctx, "revoked-node", nil)
			Expect(err).To(MatchError(ca.ErrCertRevoked))
		})

		It("refuses a certificate already on the pending-supersession list", func() {
			original := issue("superseded-node")
			data, err := json.Marshal([]pendingEntry{{
				Serial: hexSerial(original.SerialNumber), Subject: "superseded-node",
				RevokeAt: time.Now().Add(time.Hour),
			}})
			Expect(err).NotTo(HaveOccurred())
			Expect(store.SaveSuperseded(ctx, data)).To(Succeed())

			_, err = myCA.RenewStored(ctx, "superseded-node", nil)
			Expect(err).To(MatchError(ca.ErrCertSuperseded))
		})

		DescribeTable("refuses an expired certificate, and issues nothing",
			func(withAuth bool) {
				caCert := parseCert(cachedCrtPEM)
				keyBlock, _ := pem.Decode(cachedKeyPEM)
				caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				Expect(err).NotTo(HaveOccurred())
				var expired *x509.Certificate
				if withAuth {
					// A lapsed administrator credential, the case that makes
					// this refusal a security property rather than a policy.
					key, err := rsa.GenerateKey(rand.Reader, 2048)
					Expect(err).NotTo(HaveOccurred())
					value, err := asn1.MarshalWithParams("true", "utf8")
					Expect(err).NotTo(HaveOccurred())
					tmpl := &x509.Certificate{
						SerialNumber:    big.NewInt(time.Now().UnixNano()),
						Subject:         pkix.Name{CommonName: "expired-node"},
						NotBefore:       time.Now().Add(-3 * time.Hour),
						NotAfter:        time.Now().Add(-time.Hour),
						ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
						ExtraExtensions: []pkix.Extension{{Id: ca.OIDPpCliAuth, Value: value}},
					}
					der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
					Expect(err).NotTo(HaveOccurred())
					Expect(store.SaveCert(ctx, "expired-node",
						pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))).To(Succeed())
					expired, err = x509.ParseCertificate(der)
					Expect(err).NotTo(HaveOccurred())
				} else {
					expired = storeSignedBy("expired-node", 2048, time.Now().Add(-time.Hour), caCert, caKey)
				}

				_, err = myCA.RenewStored(ctx, "expired-node", nil)
				Expect(err).To(MatchError(ca.ErrRenewalExpired))
				Expect(stored("expired-node").SerialNumber).To(Equal(expired.SerialNumber))
			},
			Entry("an ordinary certificate", false),
			Entry("one carrying pp_cli_auth", true),
		)

		It("refuses a stored certificate this CA did not sign", func() {
			foreign := storeSignedBy("foreign-node", 2048, time.Now().Add(time.Hour), nil, nil)

			_, err := myCA.RenewStored(ctx, "foreign-node", nil)
			Expect(err).To(MatchError(ca.ErrForeignCertificate))
			Expect(stored("foreign-node").SerialNumber).To(Equal(foreign.SerialNumber))
		})
	})
})
