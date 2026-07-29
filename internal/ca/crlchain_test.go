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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// upstreamCA builds a self-signed CA and an empty CRL from it, standing in for
// an ancestor whose CRL an intermediate must republish.
func upstreamCA(cn string) (*x509.Certificate, []byte) {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	Expect(err).NotTo(HaveOccurred())
	skid := sha1.Sum(pubDER)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          skid[:],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())

	return cert, emptyCRLFrom(cert, key)
}

func emptyCRLFrom(cert *x509.Certificate, key crypto.Signer) []byte {
	GinkgoHelper()
	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// crlBlocks counts X509 CRL PEM blocks in a blob.
func crlBlocks(blob []byte) []*x509.RevocationList {
	GinkgoHelper()
	var out []*x509.RevocationList
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		out = append(out, crl)
	}
}

var _ = Describe("CRL chain preservation", func() {
	var (
		ctx      context.Context
		caDir    string
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		caDir = GinkgoT().TempDir()
		store = storage.New(caDir)
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		upstream, upsCRL = upstreamCA("Upstream Root CA")
	})

	// storeChain writes our current CRL followed by the upstream one, which is
	// the state a sub-CA deployment is in after importing a chain.
	storeChain := func() {
		GinkgoHelper()
		ours, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ours...), upsCRL...))).To(Succeed())
	}

	It("keeps upstream CRLs when the CA re-signs its own", func() {
		// The bug this MR fixes: re-signing replaced the whole blob with a
		// single block, so the ancestor CRL agents need for full-chain
		// revocation checking vanished at the first revocation or refresh.
		storeChain()

		Expect(myCA.ReissueCRL(ctx)).To(Succeed())

		blob, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		chain := crlBlocks(blob)
		Expect(chain).To(HaveLen(2))
		Expect(chain[0].AuthorityKeyId).To(Equal(myCA.CACert.SubjectKeyId))
		Expect(chain[1].AuthorityKeyId).To(Equal(upstream.SubjectKeyId))
	})

	It("keeps upstream CRLs across a revocation", func() {
		storeChain()

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		blob, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		chain := crlBlocks(blob)
		Expect(chain).To(HaveLen(2))
		Expect(chain[0].RevokedCertificateEntries).To(HaveLen(1))
		Expect(chain[1].AuthorityKeyId).To(Equal(upstream.SubjectKeyId))
	})

	It("does not duplicate our own CRL on repeated re-signs", func() {
		storeChain()
		Expect(myCA.ReissueCRL(ctx)).To(Succeed())
		Expect(myCA.ReissueCRL(ctx)).To(Succeed())
		Expect(myCA.ReissueCRL(ctx)).To(Succeed())

		blob, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(crlBlocks(blob)).To(HaveLen(2))
	})

	It("is a no-op on a CA with no upstream", func() {
		// A self-signed root has nothing to preserve; the result must be a
		// single block exactly as before this change.
		Expect(myCA.ReissueCRL(ctx)).To(Succeed())

		blob, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(crlBlocks(blob)).To(HaveLen(1))
	})

	It("bumps only our own CRL number, leaving upstream untouched", func() {
		storeChain()
		before := crlBlocks(mustGetCRL(store, ctx))

		Expect(myCA.ReissueCRL(ctx)).To(Succeed())

		after := crlBlocks(mustGetCRL(store, ctx))
		Expect(after[0].Number.Cmp(before[0].Number)).To(Equal(1), "our CRL number must advance")
		Expect(after[1].Number).To(Equal(before[1].Number), "upstream CRL must be byte-identical")
		Expect(after[1].Raw).To(Equal(before[1].Raw))
	})

	It("refuses to re-sign when the stored CRL belongs to another CA", func() {
		// Reachable when the CA certificate is replaced under a running
		// process: c.CACert is read once at startup, so an unrestarted replica
		// would otherwise overwrite an ancestor's CRL believing it was its own.
		Expect(store.UpdateCRL(ctx, upsCRL)).To(Succeed())

		err := myCA.ReissueCRL(ctx)
		Expect(err).To(MatchError(ContainSubstring("issued by a different CA")))
		Expect(err).To(MatchError(ContainSubstring("needs a restart")))
	})
})

func mustGetCRL(store *storage.StorageService, ctx context.Context) []byte {
	GinkgoHelper()
	blob, err := store.GetCRL(ctx)
	Expect(err).NotTo(HaveOccurred())
	return blob
}

var _ = Describe("CRL chain ordering at import", func() {
	var (
		ctx      context.Context
		store    *storage.StorageService
		keyPEM   []byte
		certPEM  []byte
		ourCRL   []byte
		upstream *x509.Certificate
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())

		var err error
		keyPEM, certPEM, ourCRL, err = testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())

		upstream, upsCRL = upstreamCA("Upstream Root CA")
	})

	It("moves this CA's CRL to the front when supplied last", func() {
		// Operators assemble chains by hand and have no reason to know that
		// every reader takes block 0 as ours. Correcting it once at import
		// beats misreading it on every subsequent load.
		misordered := append(append([]byte{}, upsCRL...), ourCRL...)
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, misordered)).To(Succeed())

		chain := crlBlocks(mustGetCRL(store, ctx))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].AuthorityKeyId).To(Equal(upstream.SubjectKeyId))
	})

	It("generates our CRL and leads with it when the chain is upstream-only", func() {
		// Supplying only ancestors is legitimate: this CA has issued nothing
		// yet, so it has no revocations of its own to import.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, upsCRL)).To(Succeed())

		chain := crlBlocks(mustGetCRL(store, ctx))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].AuthorityKeyId).To(Equal(upstream.SubjectKeyId))

		block, _ := pem.Decode(certPEM)
		ourCert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(chain[0].AuthorityKeyId).To(Equal(ourCert.SubjectKeyId))
	})

	It("rejects a chain with no parseable CRL", func() {
		err := ca.ImportCA(ctx, store, certPEM, keyPEM, []byte("not a crl\n"))
		Expect(err).To(MatchError(ContainSubstring("does not contain a valid X509 CRL")))
	})
})
