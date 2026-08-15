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
	"os"
	"path/filepath"
	"strings"
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
		// A backend read that fails must not be read as "nothing upstream to
		// preserve": that would write a single block over ancestors which are
		// still there — permanently, since this CA cannot re-sign an ancestor's
		// list.
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

		// Fail the read the re-sign depends on. It used to take two — this spec
		// skipped the first and failed the second, which was the only trigger
		// then reachable, because the chain-preserving read was its own fetch.
		// There is one read now, so failing it from the start is the same test.
		backend.failGetCRLAfter(0)
		Expect(myCA.ReissueCRL(ctx)).To(MatchError(ContainSubstring("failed to load CRL")))

		backend.stopFailing()
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "the stored chain must be untouched")
		// Exactly one: readStoredCRL counts, and a second increment would mean
		// the counting moved back to the call sites this change centralised it
		// away from.
		Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 1))
	})

	It("answers revocation from the newest of our blocks, not from a stale block 0", func() {
		// The stored shape an upgrade produces: the released build's import
		// validated block 0 and wrote the operator's bundle verbatim, so
		// `--crl-chain stale.pem current.pem root.pem` is a blob this code has to
		// read. A stale block 0 of our own passes the ownership check, so the
		// search for our block -- which existed only for a *foreign* block 0 --
		// never ran, and the cache answered from a list missing every serial
		// revoked since the export. A certificate this CA revoked authenticated.
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		stale, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Generate(ctx, "doomed.example.com", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "doomed.example.com")).To(Succeed())
		current := crlBlocks(mustGetCRL(ctx, store))[0]
		serial := current.RevokedCertificateEntries[0].SerialNumber

		_, upsCRL := upstreamCA("Upstream Root CA")
		blob := append(append([]byte{}, stale...),
			pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: current.Raw})...)
		Expect(store.UpdateCRL(ctx, append(blob, upsCRL...))).To(Succeed())

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed())

		revoked, err := restarted.IsRevokedSerial(ctx, serial)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(),
			"a certificate we revoked must stay revoked when a stale copy of our CRL leads")
		Expect(buf.String()).To(ContainSubstring("found later in the stored chain"))
		Expect(buf.String()).To(ContainSubstring("position=1"))
	})

	It("re-signs from the newest of our blocks, so the number cannot regress", func() {
		// The same blob on the write path. Advancing from a stale block 0 bumps
		// from its number -- regressing a sequence docs/metrics.md publishes as
		// monotonic -- carries its entry list forward, and then the chain assembly
		// drops every block of ours including the newer one, destroying those
		// revocations for good.
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		stale, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())

		_, err = myCA.Generate(ctx, "doomed.example.com", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "doomed.example.com")).To(Succeed())
		current := crlBlocks(mustGetCRL(ctx, store))[0]
		serial := current.RevokedCertificateEntries[0].SerialNumber

		_, upsCRL := upstreamCA("Upstream Root CA")
		blob := append(append([]byte{}, stale...),
			pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: current.Raw})...)
		Expect(store.UpdateCRL(ctx, append(blob, upsCRL...))).To(Succeed())

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed())
		Expect(restarted.ReissueCRL(ctx)).To(Succeed())

		// The line that tells an operator why the number jumped past the block
		// they were looking at.
		Expect(buf.String()).To(ContainSubstring("leads with a superseded copy of our own"))

		after := crlBlocks(mustGetCRL(ctx, store))
		Expect(after).To(HaveLen(2), "the ancestor survives; both copies of ours collapse to one")
		Expect(after[0].Number.Cmp(current.Number)).To(Equal(1),
			"the number must advance from the newest of our blocks, not the stale one")
		Expect(after[0].RevokedCertificateEntries).To(HaveLen(1))
		Expect(after[0].RevokedCertificateEntries[0].SerialNumber).To(Equal(serial),
			"the revocation recorded after the stale export must survive the re-sign")
	})

	It("fails the re-sign when an ancestor block will not decode", func() {
		// Block 0 parses and is ours, so the read succeeds and the failure lands
		// in the chain assembly. The alternative — carrying the bad block
		// forward, or dropping it — publishes a blob that agents doing
		// full-chain revocation checking reject, from a CA that reported success.
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		ours, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		corrupt := []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n")
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ours...), corrupt...))).To(Succeed())
		before := mustGetCRL(ctx, store)

		Expect(myCA.ReissueCRL(ctx)).To(MatchError(ContainSubstring("decoding the stored CRL chain")))
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "nothing may be overwritten")
		Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 1),
			"a re-sign that did not happen is a CRL-update failure, counted once")
	})

	It("still deletes a certificate when the CRL cannot be amended, and says what that leaves", func() {
		// Clean's job is to remove the certificate, so a revoke failure does not
		// stop it -- but the outcome is a certificate that is gone from storage
		// and still a valid credential until it expires. A foreign stored CRL
		// reaches this state, and reaches it *because* this branch lets a CA
		// start with one rather than refusing: the write path then fails closed
		// on the first Clean.
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		gen, err := myCA.Generate(ctx, "doomed.example.com", nil)
		Expect(err).NotTo(HaveOccurred())
		blk, _ := pem.Decode(gen.CertificatePEM)
		Expect(blk).NotTo(BeNil())
		doomed, err := x509.ParseCertificate(blk.Bytes)
		Expect(err).NotTo(HaveOccurred())
		doomedSerial := strings.ToUpper(doomed.SerialNumber.Text(16))

		_, upsCRL := upstreamCA("Upstream Root CA")
		Expect(store.UpdateCRL(ctx, upsCRL)).To(Succeed())
		before := mustGetCRL(ctx, store)

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		Expect(myCA.Clean(ctx, "doomed.example.com")).To(Succeed(),
			"a CRL that cannot be amended must not leave the certificate in place too")

		_, err = store.GetCert(ctx, "doomed.example.com")
		Expect(err).To(HaveOccurred(), "the certificate must be gone from storage")

		// Unrevoked, and specifically so: the stored CRL is untouched, which is
		// what makes the deleted certificate still valid.
		Expect(mustGetCRL(ctx, store)).To(Equal(before))
		Expect(buf.String()).To(ContainSubstring("stays a valid credential until it expires"))

		// The serial has to be in that line. It is the only place it is still
		// recorded once the certificate is gone from storage, and docs/api.md
		// sends the operator here to find it so they can retire the certificate
		// with `revoke --serial`. Without this, dropping revokeLocked's wrap
		// leaves the warning naming a subject and no serial, and nothing fails.
		Expect(buf.String()).To(ContainSubstring(doomedSerial),
			"the WARN line must name the serial; it is what the recovery command needs")
	})

	It("reads the stored blob once per re-sign, not once per purpose", func() {
		// The re-sign needs two things from storage — the number and entries to
		// carry forward, and the ancestor blocks to preserve — and used to fetch
		// the blob once for each. Under the cluster CRL lock on a network backend
		// that is a wasted round trip, and the two reads could disagree: the
		// entries came from one and the ancestors from the other.
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		backend := &countingCRLBackend{Backend: storage.NewFilesystemBackend(dir)}
		store := storage.NewWithBackend(backend, filepath.Join(dir, "private"))

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		_, upsCRL := upstreamCA("Upstream Root CA")
		ours, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ours...), upsCRL...))).To(Succeed())

		backend.resetCRLGets()
		Expect(myCA.ReissueCRL(ctx)).To(Succeed())
		Expect(backend.crlGets()).To(Equal(1),
			"one read serves both halves of the re-sign; two means the chain "+
				"assembly went back to the backend for its own copy")

		// And the ancestor is still there, so the single read is not a saving
		// made by dropping what the second read was for.
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
	})

	It("counts a CRL lock it could not take, on every writer that takes it", func() {
		// The arm nobody counted. Every writer's own failures are counted beneath
		// the lock -- readStoredCRL and signCRLLocked both do it -- but when the
		// lock cannot be taken the closure never runs, so nothing beneath it
		// counts anything and the error only ever reached a log line.
		//
		// It bites hardest where crl_chain_file is *not* configured, which is the
		// common deployment: the background refresher fails every tick, this
		// CA's own CRL runs to NextUpdate, and every series reads healthy.
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		base := storage.NewFilesystemBackend(dir)
		store := storage.NewWithBackend(base, filepath.Join(dir, "private"))

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())

		// Swap in a backend that will not hand out the lock.
		wedged := storage.NewWithBackend(&unlockableBackend{Backend: base},
			filepath.Join(dir, "private"))
		myCA.Storage = wedged

		before := myCA.CRLUpdateFailures()
		Expect(myCA.ReissueCRL(ctx)).NotTo(Succeed())
		Expect(myCA.CRLUpdateFailures()).To(Equal(before+1), "ReissueCRL")

		_, err = myCA.RefreshCRLIfDue(ctx, 24*time.Hour)
		Expect(err).To(HaveOccurred())
		Expect(myCA.CRLUpdateFailures()).To(Equal(before+2), "RefreshCRLIfDue")

		Expect(myCA.Revoke(ctx, "node1.test")).NotTo(Succeed())
		Expect(myCA.CRLUpdateFailures()).To(Equal(before+3), "Revoke")

		// The fourth writer, and the one whose omission was invisible: cleanup
		// runs unattended on a timer, so a lock it can never take is exactly the
		// failure that would otherwise sit in a log nobody reads.
		Expect(myCA.CleanupExpiredCerts(ctx, 0)).Error().To(HaveOccurred())
		Expect(myCA.CRLUpdateFailures()).To(Equal(before+4), "CleanupExpiredCerts")
	})

	// The documented exemption, pinned so it stays a decision rather than drift.
	// Clean's revoke is best-effort inside an operation that has already
	// succeeded, so a lock it could not take is logged and not counted -- unlike
	// the four writers above. Wrapping it in withCRLLockCounted would move this
	// assertion, which is what makes the exemption visible rather than implied.
	It("does not count a lock Clean could not take for its best-effort revoke", func() {
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		base := storage.NewFilesystemBackend(dir)
		store := storage.NewWithBackend(base, filepath.Join(dir, "private"))

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		res, err := myCA.Generate(ctx, "doomed.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())

		// Refuse only the CRL lock: Clean takes the subject lock first, and
		// refusing that would fail before the arm under test.
		refusing := &crlLockRefusingBackend{Backend: base}
		myCA.Storage = storage.NewWithBackend(refusing, filepath.Join(dir, "private"))

		before := myCA.CRLUpdateFailures()
		Expect(myCA.Clean(ctx, "doomed.test")).To(Succeed(),
			"Clean swallows the revoke failure, as docs/api.md publishes")
		Expect(refusing.refused).To(BeNumerically(">", 0),
			"the fixture must actually have refused the CRL lock; if lockNameCRL is "+
				"renamed it grants everything and the assertion below means nothing")
		Expect(myCA.CRLUpdateFailures()).To(Equal(before),
			"a best-effort revoke that could not take the lock is logged, not counted")
	})

	It("blames the file, not storage, when the refresh pass fails on the file itself", func() {
		// The other half of the attribution rule. Rounds 3 and 4 spent two
		// commits separating these two counters; without this assertion the
		// sentinel check can be deleted and the split collapses back to counting
		// a file fault twice, firing PuppetCACRLUpdateFailing alongside and
		// sending the responder to check storage that is perfectly healthy.
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		path := filepath.Join(GinkgoT().TempDir(), "corrupt.pem")
		Expect(os.WriteFile(path, []byte("<html>502 Bad Gateway</html>\n"), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).To(HaveOccurred())

		Expect(myCA.CRLChainFailures()).To(BeNumerically("==", 1))
		Expect(myCA.CRLUpdateFailures()).To(BeZero(),
			"the file is what failed; the storage counter must not move too")
	})

	It("blames storage, not the file, when the refresh pass fails beneath a healthy file", func() {
		// Moving crlChainFailures to the chokepoint stopped it absorbing this
		// pass's lock and storage faults -- but nothing then picked them up, so
		// a quiet CA with wedged storage failed its hourly refresh behind a log
		// line with every series flat. Both halves need pinning: the file's
		// counter must stay still, and the CRL-maintenance counter must move.
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		backend := &flakyCRLBackend{Backend: storage.NewFilesystemBackend(dir)}
		store := storage.NewWithBackend(backend, filepath.Join(dir, "private"))

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		upstream, upsCRL := upstreamCA("Healthy Ancestor CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})...))).To(Succeed())

		// A perfectly good file. The fault is underneath it.
		path := filepath.Join(GinkgoT().TempDir(), "good.pem")
		Expect(os.WriteFile(path, upsCRL, 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		backend.failGetCRLAfter(0)
		_, err = myCA.RefreshCRLChainFile(ctx)
		Expect(err).To(HaveOccurred())
		backend.stopFailing()

		Expect(myCA.CRLChainFailures()).To(BeZero(),
			"a storage fault must not page anyone to go and inspect a healthy file")
		Expect(myCA.CRLUpdateFailures()).To(BeNumerically("==", 1),
			"but it must not vanish either -- the chain was not republished. Exactly "+
				"one: two would mean the arm was counted both here and by the CRL layer")
	})

	It("fails the re-sign rather than publishing a rollback when the chain read fails", func() {
		// The re-sign path reads the stored chain exactly once, and hands those
		// bytes to the regression check rather than fetching a second copy. So
		// the single read is the enforcement point: if it fails, the re-sign
		// must fail with it. Publishing anyway would mean assembling a chain
		// with no idea what is already published, and the file here carries a
		// rollback -- the next revocation would push CRL number 7 over the
		// stored 99, un-revoking fleet-wide everything the ancestor revoked in
		// between. publishedUpstream refuses a nil blob for the same reason:
		// "nothing published" and "nothing could be read" are indistinguishable
		// by the time they reach it.
		ctx := context.Background()
		dir := GinkgoT().TempDir()
		backend := &flakyCRLBackend{Backend: storage.NewFilesystemBackend(dir)}
		store := storage.NewWithBackend(backend, filepath.Join(dir, "private"))

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		anc, ancKey, _ := upstreamCAWithKey("Flaky Ancestor CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anc.Raw})...))).To(Succeed())

		storedCRL, err := store.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, storedCRL...),
			emptyCRLNumbered(anc, ancKey, 99)...))).To(Succeed())
		before := mustGetCRL(ctx, store)

		// The file carries the rollback the guard exists to refuse.
		path := filepath.Join(GinkgoT().TempDir(), "rollback.pem")
		Expect(os.WriteFile(path, emptyCRLNumbered(anc, ancKey, 7), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		backend.failGetCRLAfter(0)
		Expect(myCA.ReissueCRL(ctx)).To(HaveOccurred())

		backend.stopFailing()
		Expect(mustGetCRL(ctx, store)).To(Equal(before),
			"the published chain must be untouched, still carrying 99")
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
		Entry("revoke", func(c *ca.CA, ctx context.Context) error {
			// The one path whose own increment this change *removed*, because
			// readStoredCRL counts now — so it is the entry that would catch
			// either half of the mistake: a double count, or a lost one. It
			// needs a certificate to revoke, which the other two do not.
			if _, err := c.Generate(ctx, "doomed.example.com", nil); err != nil {
				return err
			}
			return c.Revoke(ctx, "doomed.example.com")
		}),
		// The cleanup path is not driven here: dropCRLEntriesLocked only reaches
		// readStoredCRL once there are expired inventory entries to remove, so
		// exercising it needs a fabricated expired certificate rather than a
		// foreign CRL. It shares the same readStoredCRL, and the two entries
		// above are what pin the centralised counting.
	)
})

// crlLockRefusingBackend refuses the CRL lock and grants every other, so a spec
// can reach a CRL-lock arm without failing at the subject lock in front of it.
type crlLockRefusingBackend struct {
	storage.Backend
	refused int
}

func (b *crlLockRefusingBackend) AcquireLock(_ context.Context, name string) (storage.Unlocker, error) {
	if name == lockNameCRLValue {
		b.refused++
		return nil, errors.New("lock unavailable")
	}
	// Granted rather than delegated: Locker is an optional capability, so the
	// embedded backend may not have one, and what this spec needs is only that
	// the subject lock in front of the arm under test succeeds.
	return grantedLock{}, nil
}

type grantedLock struct{}

func (grantedLock) Unlock() error { return nil }

// lockNameCRLValue mirrors the unexported lockNameCRL, which this external test
// package cannot see. If the two ever diverge this fixture grants every lock and
// the spec asserting "not counted" passes for the wrong reason -- so the spec
// checks refused, which only a genuine match can make non-zero.
const lockNameCRLValue = "crl"

// unlockableBackend advertises Locker and always refuses. Deliberately not
// ErrDistributedLockingUnsupported, which WithLock falls through on by design;
// this models the arm that matters -- etcd with a lost session, or a SQL
// advisory lock that could not be taken.
type unlockableBackend struct {
	storage.Backend
}

func (b *unlockableBackend) AcquireLock(context.Context, string) (storage.Unlocker, error) {
	return nil, errors.New("lock unavailable")
}

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

// countingCRLBackend records CRL writes, and can append a revocation between
// two CRL reads so a re-read under the lock is distinguishable from a plan
// computed before it.
type countingCRLBackend struct {
	storage.Backend
	mu          sync.Mutex
	puts        int
	gets        int
	mutateOnGet int
	mutateWith  []byte
}

func (b *countingCRLBackend) crlPuts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.puts
}

func (b *countingCRLBackend) crlGets() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gets
}

// resetCRLGets zeroes the read counter so a spec can count the reads made by one
// operation rather than by the setup that preceded it.
func (b *countingCRLBackend) resetCRLGets() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gets = 0
}

// mutateBeforeGet arranges for blob to be written just before the nth CRL read
// counted from now, simulating a revocation landing between the plan and the
// write. The read counter is reset, since it accumulates across calls.
func (b *countingCRLBackend) mutateBeforeGet(n int, blob []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gets = 0
	b.mutateOnGet, b.mutateWith = n, blob
}

// disarm cancels a pending mutation. Call it before asserting: otherwise the
// assertion's own read can trigger the mutation and satisfy the expectation
// without the code under test having done anything — which is how the first
// version of this spec passed while pinning nothing.
func (b *countingCRLBackend) disarm() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mutateOnGet = 0
}

func (b *countingCRLBackend) Put(ctx context.Context, key string, data []byte, kind storage.BlobKind) error {
	if key == storage.KeyCRL {
		b.mu.Lock()
		b.puts++
		b.mu.Unlock()
	}
	return b.Backend.Put(ctx, key, data, kind)
}

func (b *countingCRLBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeyCRL {
		b.mu.Lock()
		b.gets++
		fire := b.mutateOnGet != 0 && b.gets == b.mutateOnGet
		blob := b.mutateWith
		if fire {
			b.mutateOnGet = 0
		}
		b.mu.Unlock()
		if fire {
			if err := b.Backend.Put(ctx, storage.KeyCRL, blob, storage.BlobPublic); err != nil {
				return nil, err
			}
		}
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

	It("performs no CRL write at all when there is nothing to change", func() {
		// The point of the nil plan is the absence of a write, not the content:
		// re-encoding the same blocks yields identical bytes, so a byte-equality
		// assertion passes whether the short-circuit is there or not. What an
		// operator would notice is the stored modification time moving, which
		// makes every agent re-download an unchanged CRL.
		dir := GinkgoT().TempDir()
		backend := &countingCRLBackend{Backend: storage.NewFilesystemBackend(dir)}
		counted := storage.NewWithBackend(backend, filepath.Join(dir, "private"))

		Expect(ca.ImportCA(ctx, counted, certPEM, keyPEM,
			append(append([]byte{}, ourCRL...), upsCRL...))).To(Succeed())
		after := backend.crlPuts()
		Expect(after).To(BeNumerically(">", 0), "the first import must write")

		Expect(ca.ImportCA(ctx, counted, certPEM, keyPEM, nil)).To(Succeed())
		Expect(backend.crlPuts()).To(Equal(after),
			"a cert/key-only re-import must not rewrite an already-correct chain")
	})

	It("decides under the lock, so a revocation landing mid-import is not discarded", func() {
		// The plan is computed twice: once to fail fast before the cert and key
		// writes, then again inside the CRL lock. Folding those into one -- an
		// obvious "we plan twice" cleanup -- would silently drop a revocation
		// that arrived in between and regress the CRL number.
		dir := GinkgoT().TempDir()
		backend := &countingCRLBackend{Backend: storage.NewFilesystemBackend(dir)}
		counted := storage.NewWithBackend(backend, filepath.Join(dir, "private"))
		Expect(ca.ImportCA(ctx, counted, certPEM, keyPEM, ourCRL)).To(Succeed())

		// A newer own CRL appears just before the second read.
		newer := reNumberedCRL(certPEM, keyPEM, 42)
		backend.mutateBeforeGet(2, newer)

		Expect(ca.ImportCA(ctx, counted, certPEM, keyPEM, upsCRL)).To(Succeed())
		backend.disarm()

		chain := crlBlocks(mustGetCRL(ctx, counted))
		Expect(chain[0].Number.Int64()).To(Equal(int64(42)),
			"the chain written must be built from the read taken under the lock")
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

	It("writes neither certificate nor key when the CRL step refuses", func() {
		// The refusal runs before the cert and key writes, which are not
		// undoable. Deciding afterwards would leave a replaced certificate
		// beside an untouched old CRL, with no rollback — and the specs above
		// cannot see it, because their stores hold no prior CA to overwrite.
		otherKey, otherCert, otherCRL, err := testutil.GenerateTestCAECDSA()
		Expect(err).NotTo(HaveOccurred())
		Expect(ca.ImportCA(ctx, store, otherCert, otherKey, otherCRL)).To(Succeed())

		// Now make the stored chain hold nothing of the *incoming* CA's.
		Expect(store.UpdateCRL(ctx, upsCRL)).To(Succeed())

		err = ca.ImportCA(ctx, store, certPEM, keyPEM, nil)
		Expect(err).To(MatchError(ContainSubstring("no CRL signed by the CA certificate")))

		storedCert, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(storedCert).To(Equal(otherCert), "the certificate must not have been replaced")
		storedKey, err := store.GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(storedKey).To(Equal(otherKey), "the key must not have been replaced")
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

	It("warns about an expired ancestor on the ancestors-only refresh path", func() {
		// The path the migration guide recommends, because our own CRL is
		// already stored. The warning used to live behind orderCRLChain's
		// early return for exactly this shape, so the only detector of a
		// condition no metric covers was skipped where it was most needed.
		expired := expiringUpstreamCA("Stale Root CA", -time.Hour)

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, expired)).To(Succeed())
		Expect(buf.String()).To(ContainSubstring("has already expired"))
		Expect(buf.String()).To(ContainSubstring("Stale Root CA"))
	})

	It("warns about an expired ancestor when our own CRL leads the bundle too", func() {
		// Both shapes, deliberately: the round-3 defect was the warning firing
		// on one and not the other, and pinning only the shape that was broken
		// would let the mirror regression through — including on the ordinary
		// first-import shape most operators take.
		expired := expiringUpstreamCA("Stale Root CA", -time.Hour)

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(append([]byte{}, ourCRL...), expired...))).To(Succeed())
		Expect(buf.String()).To(ContainSubstring("has already expired"))
	})

	It("emits no expiry warning for a healthy ancestor", func() {
		// The companion the two assertions above need: a check that fired
		// unconditionally would satisfy them just as well.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(append([]byte{}, ourCRL...), upsCRL...))).To(Succeed())
		Expect(buf.String()).NotTo(ContainSubstring("has already expired"))
	})

	It("warns when the chain carries two CRLs for the same ancestor", func() {
		_, first := upstreamCA("Shared Root CA")
		second := append(append([]byte{}, upsCRL...), first...)

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(second, first...))).To(Succeed())
		Expect(buf.String()).To(ContainSubstring("more than one CRL for the same ancestor"))
	})

	It("warns once, not once per copy, when the chain carries three of one ancestor", func() {
		// The dedup latch is a counter zeroed after it fires, and with exactly
		// two copies "fires once" and "fires once per copy above the first" are
		// the same number -- so the spec above passes either way. Three copies
		// separate them: a latch that only skipped the block it had already
		// reported would warn twice here, and an operator refreshing ancestors
		// from a backup directory is exactly who produces three.
		_, extra := upstreamCA("Shared Root CA")
		three := append(append([]byte{}, extra...), extra...)
		three = append(three, extra...)

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(append([]byte{}, ourCRL...), three...))).To(Succeed())
		Expect(strings.Count(buf.String(), "more than one CRL for the same ancestor")).To(Equal(1))
		// And it reported the right number, so the count is not merely deduped
		// by dropping copies.
		Expect(buf.String()).To(ContainSubstring("copies=3"))
	})

	It("warns once per duplicated ancestor, not once per chain", func() {
		// The latch is per issuer, and one duplicated ancestor cannot show that:
		// a single global flag would satisfy the spec above exactly. Two matter
		// because the topology this exists for is root -> intermediate -> us, so
		// two ancestors is the ordinary case, and a backup directory that
		// duplicates one duplicates both.
		_, rootCRL := upstreamCA("Shared Root CA")
		bundle := append([]byte{}, ourCRL...)
		for _, block := range [][]byte{upsCRL, upsCRL, rootCRL, rootCRL} {
			bundle = append(bundle, block...)
		}

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, bundle)).To(Succeed())
		Expect(strings.Count(buf.String(), "more than one CRL for the same ancestor")).To(Equal(2),
			"each duplicated ancestor is its own problem to fix")
		Expect(buf.String()).To(ContainSubstring("Upstream Root CA"))
		Expect(buf.String()).To(ContainSubstring("Shared Root CA"))
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

	DescribeTable("a numbered copy of ours beats a numberless one, whichever order they arrive in",
		// A numberless CRL of ours is routine, not a curiosity: `openssl ca
		// -gencrl` under the stock openssl.cnf emits a V1 list, which cannot carry
		// cRLNumber at all. Whichever block ends up at position 0 is what the next
		// re-sign advances from, and advancing from a numberless one restarts the
		// sequence at 1 -- regressing a number docs/metrics.md publishes as
		// monotonic, and leaving an RFC 5280 client free to keep serving the copy
		// it already has, so a revocation recorded afterwards is never seen.
		//
		// The previous spec covered only the order where the numbered block also
		// had the later ThisUpdate, so a pure ThisUpdate comparison satisfied it.
		// Both orders separate the two rules.
		func(numberedFirst bool) {
			certBlock, _ := pem.Decode(certPEM)
			ourCert, err := x509.ParseCertificate(certBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())
			keyBlock, _ := pem.Decode(keyPEM)
			ourKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
			Expect(err).NotTo(HaveOccurred())

			// The numberless block is stamped an hour into the future, so it is
			// the *later* of the two and must still lose. With the default
			// (an hour ago) both rules agree and the table proves nothing.
			numberless := handRolledCRLAt(ourCert, ourKey,
				time.Now().UTC().Truncate(time.Second).Add(time.Hour))
			numbered := reNumberedCRL(certPEM, keyPEM, 9)
			bundle := append(append([]byte{}, numberless...), numbered...)
			if numberedFirst {
				bundle = append(append([]byte{}, numbered...), numberless...)
			}

			Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, bundle)).To(Succeed())

			chain := crlBlocks(mustGetCRL(ctx, store))
			Expect(chain).To(HaveLen(1))
			Expect(chain[0].Number).NotTo(BeNil(),
				"a numberless block 0 would reset the next CRL number to 1")
			Expect(chain[0].Number.Int64()).To(Equal(int64(9)))
		},
		Entry("numberless first", false),
		Entry("numbered first", true),
	)

	It("picks the later of two numberless copies of ours", func() {
		// The ThisUpdate fallback, which lost its only spec when the
		// numbered-beats-numberless rule was added: in the table above the
		// numberless block always loses through the new arms, so the comparison
		// below them is never reached. An operator whose predecessor CA was
		// managed by `openssl ca -gencrl` has only V1 exports, so a bundle
		// assembled from a backup directory can hold two of them and nothing else
		// decides between them.
		certBlock, _ := pem.Decode(certPEM)
		ourCert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())
		keyBlock, _ := pem.Decode(keyPEM)
		ourKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		Expect(err).NotTo(HaveOccurred())

		base := time.Now().UTC().Truncate(time.Second)
		older := handRolledCRLAt(ourCert, ourKey, base.Add(-24*time.Hour))
		newer := handRolledCRLAt(ourCert, ourKey, base)

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, append(append([]byte{}, older...), newer...))).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(1))
		Expect(chain[0].Number).To(BeNil(), "both copies are numberless")
		Expect(chain[0].ThisUpdate.Unix()).To(Equal(base.Unix()),
			"the later of two numberless copies must lead")
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

	It("keeps the newest of our blocks when the stored blob holds two, not the first", func() {
		// The shape the released build's import could store: it validated block 0
		// and then wrote the operator's bundle verbatim, so
		// `--crl-chain stale.pem current.pem root.pem` is a stored blob this code
		// has to read after an upgrade.
		//
		// orderCRLChain already resolves this for an *incoming* bundle, by CRL
		// number. ownCRLIn read the stored one and took the first match, so an
		// ancestors-only refresh -- the documented way to refresh ancestors --
		// promoted the stale copy to block 0. The number regresses and every
		// revocation recorded after the stale export stops being published, with
		// no warning anywhere: the import path emits no chain-length line, and
		// orderCRLChain's superseded warning only ever sees the incoming bundle.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, ourCRL)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		_, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		current := crlBlocks(mustGetCRL(ctx, store))[0]
		Expect(current.RevokedCertificateEntries).To(HaveLen(1))
		serial := current.RevokedCertificateEntries[0].SerialNumber

		// Stale copy first, current second: the concatenation order an operator
		// gets from a backup directory.
		stale := ourCRL
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, stale...),
			pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: current.Raw})...))).To(Succeed())

		// Refresh the ancestors only, which is when ownCRLIn is consulted.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, upsCRL)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[0].Number.Cmp(current.Number)).To(Equal(0),
			"the newest of our blocks must lead, so the CRL number cannot regress")
		Expect(chain[0].RevokedCertificateEntries).To(HaveLen(1),
			"and the revocations recorded after the stale export must survive")
		Expect(chain[0].RevokedCertificateEntries[0].SerialNumber).To(Equal(serial))
	})

	It("warns about a lapsed ancestor even when the import writes nothing", func() {
		// The two no-op shapes -- nothing supplied and already in order -- return
		// before the write. The expiry check is a pure read of what is being
		// served, and an import that changes nothing still republishes a lapsed
		// ancestor to every agent. Since no series and no alert covers ancestor
		// expiry, skipping the check here left the only detector unreachable on
		// the shape an operator uses to *check* their chain.
		expired := expiringUpstreamCA("Lapsed Root CA", -time.Hour)
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM,
			append(append([]byte{}, ourCRL...), expired...))).To(Succeed())
		before := mustGetCRL(ctx, store)

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		// No --crl-chain: nothing to change, nothing written.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, nil)).To(Succeed())
		Expect(mustGetCRL(ctx, store)).To(Equal(before), "this shape must not write")
		Expect(buf.String()).To(ContainSubstring("has already expired"),
			"the only detector of ancestor expiry must run on the shape that writes nothing")
	})

	It("keeps the stored copy of our CRL when the supplied bundle carries an older one", func() {
		// The third position of one operator error, and the worst. Two copies in
		// the bundle, or two in storage, both leave the current copy available to
		// choose; a stale copy in the bundle against a newer one in storage means
		// writing the bundle deletes the only current copy. An operator
		// assembling one bundle from a backup directory to refresh ancestors
		// supplies exactly that.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, ourCRL)).To(Succeed())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		_, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		current := crlBlocks(mustGetCRL(ctx, store))[0]
		serial := current.RevokedCertificateEntries[0].SerialNumber

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		// ourCRL is the stale export: it predates the revocation above.
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM,
			append(append([]byte{}, ourCRL...), upsCRL...))).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain[0].Number.Cmp(current.Number)).To(Equal(0),
			"the stored copy is newer, so it must survive the import")
		Expect(chain[0].RevokedCertificateEntries).To(HaveLen(1))
		Expect(chain[0].RevokedCertificateEntries[0].SerialNumber).To(Equal(serial))
		Expect(buf.String()).To(ContainSubstring("older than the stored one"))
	})

	It("reorders a stored chain that leads with an ancestor, and writes it", func() {
		// The repair path: with a foreign block 0 every write fails closed and the
		// cache falls back, so `import` with no --crl-chain is what fixes it. The
		// no-write arm of that branch is well covered; this is the arm that has to
		// write, and if it ever reported "nothing changed" the import would report
		// success while the CA stayed stuck refusing revocations.
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, upsCRL...), ourCRL...))).To(Succeed())

		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM, nil)).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[0].AuthorityKeyId).NotTo(Equal(upstream.SubjectKeyId),
			"our own block must lead after the repair")
		Expect(chain[1].AuthorityKeyId).To(Equal(upstream.SubjectKeyId))

		// And the write path is unstuck.
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())
		Expect(myCA.ReissueCRL(ctx)).To(Succeed())
	})

	It("warns once about superseded copies of ours, not once per plan", func() {
		// planCRLImport runs twice -- once to validate before anything is written,
		// once under the lock -- so a warning inside it reported one problem as
		// two, and an operator counting the lines would look for two stale
		// exports.
		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		reNumbered := reNumberedCRL(certPEM, keyPEM, 2)
		Expect(ca.ImportCA(ctx, store, certPEM, keyPEM,
			append(append([]byte{}, ourCRL...), reNumbered...))).To(Succeed())
		Expect(strings.Count(buf.String(), "Discarding superseded copies")).To(Equal(1))
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

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed())
		wasRevoked, err := restarted.IsRevokedSerial(ctx, serial)
		Expect(err).NotTo(HaveOccurred())
		Expect(wasRevoked).To(BeTrue(),
			"a certificate we revoked must stay revoked whatever order the blob is in")

		// Both lines. Reading past a foreign block 0 keeps the CA answering
		// correctly, but every write path still fails closed on this blob, so the
		// remedy has to survive the repair -- and it must stay distinguishable
		// from the stale-duplicate case, which needs no operator action.
		Expect(buf.String()).To(ContainSubstring("does not lead with this CA's own CRL"),
			"the remedy must be named on the shape where writes are refused")
		Expect(buf.String()).To(ContainSubstring("found later in the stored chain"))
	})

	It("starts on a foreign block 0 whose chain will not decode, saying it could not look further", func() {
		// The fallback's own failure branch. Block 0 is foreign, so the search
		// for our own block later in the chain begins -- and the chain does not
		// decode, so there is nothing to find. Startup must still succeed, with
		// both warnings: the read path's availability trade-off holds here too,
		// and the second line is what tells an operator why the first one could
		// not be improved on.
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		_, err := myCA.Generate(ctx, "doomed.example.com", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "doomed.example.com")).To(Succeed())
		revoked := crlBlocks(mustGetCRL(ctx, store))[0].RevokedCertificateEntries
		Expect(revoked).To(HaveLen(1))
		serial := revoked[0].SerialNumber

		// Our own block is not in this blob at all, so the search has nothing to
		// find even before the decode fails.
		_, upsCRL := upstreamCA("Upstream Root CA")
		corrupt := []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n")
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, upsCRL...), corrupt...))).To(Succeed())

		var buf bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(orig)

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed(),
			"an undecodable chain behind a foreign block 0 must not stop the CA starting")
		Expect(buf.String()).To(ContainSubstring("does not lead with this CA's own CRL"))
		Expect(buf.String()).To(ContainSubstring("Could not decode the stored CRL chain"))

		// The consequence, recorded rather than implied: it is answering from the
		// foreign block, so a certificate this CA revoked reads as not revoked.
		// That is the availability trade-off the read path makes deliberately --
		// a running CA with two loud warnings, rather than one that will not
		// start -- and the reason the write path fails closed on the same state.
		wasRevoked, err := restarted.IsRevokedSerial(ctx, serial)
		Expect(err).NotTo(HaveOccurred())
		Expect(wasRevoked).To(BeFalse(),
			"an ancestor's list holds none of our serials; this is what the warnings are for")
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
	return handRolledCRLAt(cert, key, time.Now().UTC().Truncate(time.Second).Add(-time.Hour))
}

// handRolledCRLNoNextUpdate signs a CRL that omits nextUpdate entirely. It is
// OPTIONAL in RFC 5280's ASN.1, and x509.CreateRevocationList refuses to mint
// one, so the only way to have the shape a non-conforming ancestor CA can
// legitimately emit is to assemble the DER.
func handRolledCRLNoNextUpdate(cert *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	GinkgoHelper()
	algo := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}

	tbsDER, err := asn1.Marshal(tbsCertList{
		Version:    1, // v2
		Signature:  algo,
		Issuer:     asn1.RawValue{FullBytes: cert.RawSubject},
		ThisUpdate: time.Now().UTC().Truncate(time.Second).Add(-time.Hour),
	})
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
	Expect(parsed.NextUpdate).To(BeZero(), "the fixture must actually omit nextUpdate")

	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// handRolledCRLAt is handRolledCRL with ThisUpdate under the caller's control.
// A numberless CRL that is also the *later* of the two is what separates "a
// numbered block wins" from "the later block wins" -- with the fixed -1h stamp,
// both rules give the same answer whichever order the bundle arrives in.
func handRolledCRLAt(cert *x509.Certificate, key *ecdsa.PrivateKey, thisUpdate time.Time) []byte {
	GinkgoHelper()
	// ecdsa-with-SHA256
	algo := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}

	tbs := tbsCertList{
		Version:    1, // v2
		Signature:  algo,
		Issuer:     asn1.RawValue{FullBytes: cert.RawSubject},
		ThisUpdate: thisUpdate,
		NextUpdate: thisUpdate.Add(30 * 24 * time.Hour),
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

// expiringUpstreamCA builds an ancestor whose CRL nextUpdate sits at now+offset,
// so a negative offset yields one that has already lapsed.
func expiringUpstreamCA(cn string, offset time.Duration) []byte {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).NotTo(HaveOccurred())
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	cert, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())

	now := time.Now().UTC()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(4),
		ThisUpdate: now.Add(-72 * time.Hour),
		NextUpdate: now.Add(offset),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
}

var _ = Describe("CRL cache loading: a corrupt ancestor block", func() {
	// The previous build's import stored a multi-block --crl-chain byte for
	// byte while validating only block 0, so an existing deployment can
	// legitimately hold a blob whose trailing block does not parse. Refusing to
	// start on data the previous build wrote would be an upgrade break, and it
	// would be harsher than this function's policy for a strictly worse
	// condition — a foreign block 0, which only warns.
	It("starts, serving block 0, rather than refusing", func() {
		ctx := context.Background()
		store := storage.New(GinkgoT().TempDir())

		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		_, err := myCA.Generate(ctx, "doomed.example.com", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Revoke(ctx, "doomed.example.com")).To(Succeed())

		ours := mustGetCRL(ctx, store)
		serial := crlBlocks(ours)[0].RevokedCertificateEntries[0].SerialNumber

		corrupt := []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n")
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ours...), corrupt...))).To(Succeed())

		restarted := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		restarted.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(restarted.Init(ctx)).To(Succeed(),
			"a corrupt trailing block must not take the CA offline")

		wasRevoked, err := restarted.IsRevokedSerial(ctx, serial)
		Expect(err).NotTo(HaveOccurred())
		Expect(wasRevoked).To(BeTrue(), "block 0 still answers revocation questions")
	})
})
