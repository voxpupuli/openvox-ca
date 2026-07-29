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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"path/filepath"
	"sync"
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

// crlBlocks parses every X509 CRL block in a blob, in order, failing the spec if
// any block is unparseable — which several callers rely on as an implicit check.
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
		before := crlBlocks(mustGetCRL(ctx, store))

		Expect(myCA.ReissueCRL(ctx)).To(Succeed())

		after := crlBlocks(mustGetCRL(ctx, store))
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
		Expect(err).To(MatchError(ContainSubstring("not signed by the CA certificate")))
		Expect(err).To(MatchError(ContainSubstring("needs a restart")))
	})

	It("keeps an upstream CRL that carries no Authority Key Identifier", func() {
		// The extension is optional and `openssl ca -gencrl` omits it under the
		// stock openssl.cnf, so an ancestor CRL routinely lacks one. Ownership
		// is decided by signature precisely so such a CRL is still recognisably
		// not ours and survives, instead of being silently dropped.
		bare := upstreamCRLWithoutAKI()
		ours, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ours...), bare...))).To(Succeed())

		Expect(myCA.ReissueCRL(ctx)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[0].AuthorityKeyId).To(Equal(myCA.CACert.SubjectKeyId))
		Expect(chain[1].AuthorityKeyId).To(BeEmpty())
	})

	It("preserves two ancestors in order, not merely as a set", func() {
		// The target topology is root -> intermediate -> this CA, so a real
		// chain carries two upstream blocks. With only one, "preserves order"
		// and "preserves the set" are indistinguishable.
		mid, midCRL := upstreamCA("Upstream Intermediate CA")
		ours, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		blob := append(append([]byte{}, ours...), midCRL...)
		blob = append(blob, upsCRL...)
		Expect(store.UpdateCRL(ctx, blob)).To(Succeed())

		Expect(myCA.ReissueCRL(ctx)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(3))
		Expect(chain[0].AuthorityKeyId).To(Equal(myCA.CACert.SubjectKeyId))
		Expect(chain[1].AuthorityKeyId).To(Equal(mid.SubjectKeyId))
		Expect(chain[2].AuthorityKeyId).To(Equal(upstream.SubjectKeyId))
	})

	It("keeps our revocations at block 0 across a chained re-sign", func() {
		// The block-0 contract exists so readStoredCRL and revoke read our own
		// entries back. If our CRL were ever emitted second, reissue would
		// re-sign from the ancestor's empty entry list and every revocation
		// would vanish — while every other chain spec still passed.
		storeChain()

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		before := crlBlocks(mustGetCRL(ctx, store))
		Expect(before[0].RevokedCertificateEntries).To(HaveLen(1))

		Expect(myCA.ReissueCRL(ctx)).To(Succeed())

		after := crlBlocks(mustGetCRL(ctx, store))
		Expect(after).To(HaveLen(2))
		Expect(after[0].RevokedCertificateEntries).To(HaveLen(1))
		Expect(after[0].RevokedCertificateEntries[0].SerialNumber).
			To(Equal(before[0].RevokedCertificateEntries[0].SerialNumber))
		Expect(after[1].Raw).To(Equal(before[1].Raw))
	})
})

var _ = Describe("CRL chain read failures", func() {
	It("fails the re-sign rather than flattening the chain", func() {
		// The chain-preserving read is the second read of the blob, so the only
		// reachable trigger is a transient backend failure. Treating it as
		// "nothing upstream to preserve" would write a single block over
		// ancestors that are still there — permanently, since this CA cannot
		// re-sign an ancestor's list.
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		backend := &flakyCRLBackend{Backend: storage.NewFilesystemBackend(dir)}
		store := storage.NewWithBackend(backend, filepath.Join(dir, "private"))

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		_, upsCRL := upstreamCA("Upstream Root CA")
		ours, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ours...), upsCRL...))).To(Succeed())
		before := mustGetCRL(ctx, store)

		// readStoredCRL reads first and succeeds; crlChainLocked's read fails.
		backend.failGetCRLAfter(1)
		Expect(myCA.ReissueCRL(ctx)).To(MatchError(ContainSubstring("preserve its upstream blocks")))

		backend.stopFailing()
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "the stored chain must be untouched")
		// Exactly one: readStoredCRL succeeded and crlChainLocked failed, so a
		// second increment would mean the counting moved back to the call sites
		// this change centralised it away from.
		Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 1))
	})

	// Counting was moved into readStoredCRL precisely because reissue, refresh
	// and cleanup previously returned this error uncounted, leaving the metric
	// the shipped mixin alerts on flat while the CA logged every tick. Reverting
	// that would otherwise keep the whole suite green.
	DescribeTable("counts a foreign stored CRL as a CRL-update failure on every re-sign path",
		func(drive func(*ca.CA, context.Context) error) {
			ctx := context.Background()
			store := storage.New(GinkgoT().TempDir())

			myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
			myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
			Expect(myCA.Init(ctx)).To(Succeed())

			// Replace the stored CRL with one this CA did not sign, which is
			// what readStoredCRL refuses.
			_, upsCRL := upstreamCA("Upstream Root CA")
			Expect(store.UpdateCRL(ctx, upsCRL)).To(Succeed())

			Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 0))
			Expect(drive(myCA, ctx)).To(MatchError(ca.ErrForeignStoredCRL))
			Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 1))
		},
		Entry("reissue", func(c *ca.CA, ctx context.Context) error { return c.ReissueCRL(ctx) }),
		Entry("refresh", func(c *ca.CA, ctx context.Context) error {
			// A window wide enough that the stored CRL is always due.
			_, err := c.RefreshCRLIfDue(ctx, 100*365*24*time.Hour)
			return err
		}),
		// The cleanup path is not driven here: dropCRLEntriesLocked only reaches
		// readStoredCRL once there are expired inventory entries to remove, so
		// exercising it needs a fabricated expired certificate rather than a
		// foreign CRL. It shares the same readStoredCRL, and the two entries
		// above are what pin the centralised counting.
	)
})

// flakyCRLBackend fails Get on the CRL key after a set number of successful
// reads, standing in for a transient fault on a network backend.
type flakyCRLBackend struct {
	storage.Backend
	mu        sync.Mutex
	remaining int
	failing   bool
}

func (b *flakyCRLBackend) failGetCRLAfter(n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.remaining, b.failing = n, true
}

func (b *flakyCRLBackend) stopFailing() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failing = false
}

func (b *flakyCRLBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeyCRL {
		b.mu.Lock()
		if b.failing {
			if b.remaining <= 0 {
				b.mu.Unlock()
				return nil, errors.New("backend unavailable")
			}
			b.remaining--
		}
		b.mu.Unlock()
	}
	return b.Backend.Get(ctx, key)
}

// upstreamCRLWithoutAKI builds an ancestor CRL carrying no Authority Key
// Identifier — the shape `openssl ca -gencrl` produces, because the stock
// openssl.cnf leaves crl_extensions commented out.
//
// Note the issuing certificate does have a Subject Key Identifier: that is the
// realistic combination, and it is precisely why keying ownership on the AKI
// fails. The information needed to match is present on the certificate and
// simply absent from the CRL.
func upstreamCRLWithoutAKI() []byte {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).NotTo(HaveOccurred())

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Upstream CA With Bare CRL"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())

	// x509.CreateRevocationList always stamps an AKI, which is exactly why our
	// own CRLs always carry one — so build this one by hand.
	return handRolledCRL(cert, key)
}

func mustGetCRL(ctx context.Context, store *storage.StorageService) []byte {
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

	It("leaves the stored chain alone when no --crl-chain is supplied", func() {
		// Omitting the flag used to generate a fresh empty CRL and overwrite,
		// which on a CA that had been issuing for months destroyed every
		// ancestor block this branch exists to preserve *and* every revocation
		// recorded so far — silently, and looking healthy afterwards, because
		// block 0 was legitimately ours. Nothing supplied means nothing to
		// change.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(append([]byte{}, ourCRL...), upsCRL...))).To(Succeed())
		before := mustGetCRL(ctx, store)
		Expect(crlBlocks(before)).To(HaveLen(2))

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, nil)).To(Succeed())
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "the stored chain must be untouched")
	})

	It("still generates a CRL when no chain is supplied and storage holds none", func() {
		// The legitimate first-import case the old behaviour was written for.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, nil)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(1))
		Expect(chain[0].Number.Int64()).To(Equal(int64(1)))
	})

	It("refuses rather than overwriting when no chain is supplied and nothing stored is ours", func() {
		// Reordering cannot help here and generating would discard the stored
		// blocks, so the operator is told what to supply instead.
		Expect(store.UpdateCRL(ctx, upsCRL)).To(Succeed())

		err := ca.ImportCA(ctx, store, certPEM, keyPEM, nil)
		Expect(err).To(MatchError(ContainSubstring("no CRL signed by the CA certificate")))
		Expect(mustGetCRL(ctx, store)).To(Equal(upsCRL), "nothing may be overwritten")
	})

	It("fails the import rather than fabricating a CRL when the stored blob cannot be read", func() {
		// The read used to be swallowed into "there is nothing stored", which
		// licensed generating an empty CRL over live revocations. Every reader
		// takes block 0, so that un-revokes the fleet.
		dir := GinkgoT().TempDir()
		backend := &flakyCRLBackend{Backend: storage.NewFilesystemBackend(dir)}
		flaky := storage.NewWithBackend(backend, filepath.Join(dir, "private"))
		Expect(ca.ImportCA(ctx, flaky, certPEM, keyPEM, ourCRL)).To(Succeed())
		before := mustGetCRL(ctx, flaky)

		backend.failGetCRLAfter(0)
		err := ca.ImportCA(ctx, flaky, certPEM, keyPEM, upsCRL)
		Expect(err).To(MatchError(ContainSubstring("reading the stored CRL before replacing it")))

		backend.stopFailing()
		Expect(mustGetCRL(ctx, flaky)).To(Equal(before))
	})

	It("moves this CA's CRL to the front when supplied last", func() {
		// Operators assemble chains by hand and have no reason to know that
		// every reader takes block 0 as ours. Correcting it once at import
		// beats misreading it on every subsequent load.
		misordered := append(append([]byte{}, upsCRL...), ourCRL...)
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, misordered)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].AuthorityKeyId).To(Equal(upstream.SubjectKeyId))
	})

	It("keeps the highest-numbered copy when the bundle carries two of ours", func() {
		// A bundle assembled from a backup directory easily contains a stale
		// export alongside the current one. Taking whichever came first made
		// block 0 depend on the operator's concatenation order: a stale copy
		// leading gets cached by loadCRLCache, the next re-sign advances from
		// its number and drops the newer block, and revocations recorded after
		// the stale export silently stop being seen — while chain length and
		// CRL number both look healthy.
		stale := reNumberedCRL(certPEM, keyPEM, 1)
		current := reNumberedCRL(certPEM, keyPEM, 9)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(stale, current...))).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(1), "the superseded copy must be dropped, not kept as an ancestor")
		Expect(chain[0].Number.Int64()).To(Equal(int64(9)))
	})

	It("keeps the highest-numbered copy whichever order they appear in", func() {
		stale := reNumberedCRL(certPEM, keyPEM, 1)
		current := reNumberedCRL(certPEM, keyPEM, 9)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(current, stale...))).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(1))
		Expect(chain[0].Number.Int64()).To(Equal(int64(9)))
	})

	It("falls back to ThisUpdate when a duplicate of ours carries no CRL number", func() {
		// RFC 5280 requires cRLNumber, but a hand-rolled CRL may omit it and the
		// comparison still has to terminate and pick correctly. reNumberedCRL
		// always sets a number, so nothing else reaches this branch — and if it
		// inverted, the effect is the stale-block-0 bug the tie-break fixes.
		certBlock, _ := pem.Decode(certPEM)
		ourCert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		keyBlock, _ := pem.Decode(keyPEM)
		ourKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		numberless := handRolledCRL(ourCert, ourKey)
		numbered := reNumberedCRL(certPEM, keyPEM, 9)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(numberless, numbered...))).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(1))
		Expect(chain[0].Number).NotTo(BeNil(),
			"the numbered copy is the later one, so it must win over the numberless one")
		Expect(chain[0].Number.Int64()).To(Equal(int64(9)))
	})

	It("fails the import rather than fabricating a CRL when the stored blob will not decode", func() {
		// The other half of the swallowed-error fix. A valid PEM envelope round
		// corrupt DER is what a truncated paste or a hand-assembled file
		// produces, and treating it as "nothing stored" would generate an empty
		// CRL over live revocations.
		corrupt := []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n")
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ourCRL...), corrupt...))).To(Succeed())
		before := mustGetCRL(ctx, store)

		err := ca.ImportCA(ctx, store, certPEM, keyPEM, nil)
		Expect(err).To(MatchError(ContainSubstring("decoding the stored CRL before replacing it")))
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "nothing may be overwritten")
	})

	It("generates our CRL and leads with it when the chain is upstream-only", func() {
		// Supplying only ancestors is legitimate: this CA has issued nothing
		// yet, so it has no revocations of its own to import.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, upsCRL)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
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

	It("keeps an imported CRL of ours that carries no Authority Key Identifier", func() {
		// The regression this guards: matching ownership by AKI meant a CRL
		// without one was taken for an ancestor's, a fresh empty CRL was
		// generated and prepended, and every revocation the operator imported
		// stopped being seen — silently, because every reader takes block 0.
		block, _ := pem.Decode(certPEM)
		ourCert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		keyBlock, _ := pem.Decode(keyPEM)
		parsedKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		bare := handRolledCRL(ourCert, parsedKey)
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, bare)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(1), "no empty CRL should have been generated over it")
		Expect(chain[0].Raw).To(Equal(crlBlocks(bare)[0].Raw))
	})

	It("keeps our existing revocations when only ancestors are re-imported", func() {
		// How an operator refreshes ancestor CRLs with the tools available
		// today: re-run import with a newer ancestor bundle. Generating an empty
		// CRL for ourselves there would un-revoke the whole fleet, and it would
		// look healthy — block 0 would be ours, just empty.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, ourCRL)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())
		_, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		revoked := crlBlocks(mustGetCRL(ctx, store))[0]
		Expect(revoked.RevokedCertificateEntries).To(HaveLen(1))

		// Refresh the ancestors only, exactly as an operator would.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, upsCRL)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[0].RevokedCertificateEntries).To(HaveLen(1),
			"our revocations must survive an ancestors-only import")
		Expect(chain[0].RevokedCertificateEntries[0].SerialNumber).
			To(Equal(revoked.RevokedCertificateEntries[0].SerialNumber))
		Expect(chain[1].AuthorityKeyId).To(Equal(upstream.SubjectKeyId))
	})

	It("rejects a chain whose ancestor block is corrupt", func() {
		// The blob is served verbatim to every agent, and Puppet's default
		// certificate_revocation = chain makes an agent parse all of it, so a
		// bad block must fail here rather than fleet-wide.
		corrupt := []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n")
		err := ca.ImportCA(ctx, store, certPEM, keyPEM, append(append([]byte{}, ourCRL...), corrupt...))
		Expect(err).To(MatchError(ContainSubstring("parsing CRL 2 in chain")))
	})

	It("ignores non-CRL blocks without storing them", func() {
		// Commentary and stray PEM are tolerated on the way in, but the stored
		// blob is re-encoded from what was parsed, so none of it is served.
		noise := []byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n")
		withNoise := append(append([]byte{}, noise...), ourCRL...)
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(withNoise, upsCRL...))).To(Succeed())

		stored := mustGetCRL(ctx, store)
		Expect(crlBlocks(stored)).To(HaveLen(2))
		Expect(stored).NotTo(ContainSubstring("BEGIN CERTIFICATE"))
	})
})

var _ = Describe("CRL cache loading", func() {
	It("starts with a warning rather than failing when block 0 is not ours", func() {
		// A deliberate availability trade-off: the read path warns and carries
		// on, where the write path fails closed. Refusing to start would leave
		// the CA entirely unavailable over a condition an operator can fix
		// while it serves.
		ctx := context.Background()
		caDir := GinkgoT().TempDir()
		store := storage.New(caDir)

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		_, upsCRL := upstreamCA("Upstream Root CA")
		Expect(store.UpdateCRL(ctx, upsCRL)).To(Succeed())

		// Capture the warning: asserting only that Init succeeds cannot fail,
		// because Init succeeded before the ownership check existed and would
		// succeed again if it were deleted. The warning is the whole behaviour.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed(), "a foreign block 0 must not stop the CA starting")
		Expect(buf.String()).To(ContainSubstring("does not lead with this CA's own CRL"))
	})

	It("emits no such warning on a healthy chain", func() {
		// The companion the assertion above needs: a check that fired
		// unconditionally would satisfy it just as well.
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed())
		Expect(buf.String()).NotTo(ContainSubstring("does not lead with this CA's own CRL"))
	})

	It("answers revocation from our own block when a foreign one leads", func() {
		// Warning and then using the foreign list anyway would let every
		// certificate this CA revoked go on authenticating: an ancestor's CRL
		// contains none of our serials. The whole blob is already read, so the
		// block that is ours is found rather than assumed to be first.
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		_, err := myCA.Generate(ctx, "doomed.example.com", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "doomed.example.com")).To(Succeed())

		ourCRL := mustGetCRL(ctx, store)
		revoked := crlBlocks(ourCRL)[0].RevokedCertificateEntries
		Expect(revoked).To(HaveLen(1))
		serial := revoked[0].SerialNumber

		// A hand-assembled blob with the ancestor first.
		_, upsCRL := upstreamCA("Upstream Root CA")
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, upsCRL...), ourCRL...))).To(Succeed())

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed())
		wasRevoked, err := restarted.IsRevokedSerial(ctx, serial)
		Expect(err).NotTo(HaveOccurred())
		Expect(wasRevoked).To(BeTrue(),
			"a certificate we revoked must stay revoked whatever order the blob is in")
	})
})

// tbsCertList is the signed portion of an X.509 CRL, deliberately without the
// crlExtensions field so the result carries no Authority Key Identifier.
type tbsCertList struct {
	Version    int
	Signature  pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	ThisUpdate time.Time
	NextUpdate time.Time `asn1:"optional"`
}

type certificateList struct {
	TBS       asn1.RawValue
	Signature pkix.AlgorithmIdentifier
	Sig       asn1.BitString
}

// handRolledCRL signs a minimal, extension-free CRL for cert. Everything the
// standard library emits carries an AKI, so producing the shape this test needs
// means assembling the DER directly.
func handRolledCRL(cert *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	GinkgoHelper()
	// ecdsa-with-SHA256
	algo := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}

	now := time.Now().UTC().Truncate(time.Second)
	tbs := tbsCertList{
		Version:    1, // v2
		Signature:  algo,
		Issuer:     asn1.RawValue{FullBytes: cert.RawSubject},
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(30 * 24 * time.Hour),
	}
	tbsDER, err := asn1.Marshal(tbs)
	Expect(err).NotTo(HaveOccurred())

	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	Expect(err).NotTo(HaveOccurred())

	der, err := asn1.Marshal(certificateList{
		TBS:       asn1.RawValue{FullBytes: tbsDER},
		Signature: algo,
		Sig:       asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	})
	Expect(err).NotTo(HaveOccurred())

	parsed, err := x509.ParseRevocationList(der)
	Expect(err).NotTo(HaveOccurred(), "the hand-rolled CRL must be parseable")
	Expect(parsed.AuthorityKeyId).To(BeEmpty())

	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// reNumberedCRL signs an empty CRL for the CA in certPEM/keyPEM at the given
// CRL number, standing in for successive exports of this CA's own CRL.
func reNumberedCRL(certPEM, keyPEM []byte, number int64) []byte {
	GinkgoHelper()
	certBlock, _ := pem.Decode(certPEM)
	Expect(certBlock).NotTo(BeNil())
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	Expect(err).NotTo(HaveOccurred())

	keyBlock, _ := pem.Decode(keyPEM)
	Expect(keyBlock).NotTo(BeNil())
	parsed, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		anyKey, pkcs8Err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		Expect(pkcs8Err).NotTo(HaveOccurred())
		signer, ok := anyKey.(crypto.Signer)
		Expect(ok).To(BeTrue())
		return crlAtNumber(cert, signer, number)
	}
	return crlAtNumber(cert, parsed, number)
}

func crlAtNumber(cert *x509.Certificate, key crypto.Signer, number int64) []byte {
	GinkgoHelper()
	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: now,
		NextUpdate: now.Add(30 * 24 * time.Hour),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}
