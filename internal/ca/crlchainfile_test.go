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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// writeChainFile writes blobs to a temp file and returns its path.
func writeChainFile(blobs ...[]byte) string {
	GinkgoHelper()
	path := filepath.Join(GinkgoT().TempDir(), "upstream-crls.pem")
	var joined []byte
	for _, b := range blobs {
		joined = append(joined, b...)
	}
	Expect(os.WriteFile(path, joined, 0o644)).To(Succeed())
	return path
}

// upstreamCAWithKey is upstreamCA, also returning the key so a spec can issue a
// second CRL from the same issuer.
func upstreamCAWithKey(cn string) (*x509.Certificate, crypto.Signer, []byte) {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	cert := selfSignedCA(cn, key)
	return cert, key, emptyCRLNumbered(cert, key, 7)
}

// crlFromImpostorNamed issues a CRL whose issuer DN matches cn but whose
// signature comes from an unrelated key.
func crlFromImpostorNamed(cn string) []byte {
	GinkgoHelper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	return emptyCRLNumbered(selfSignedCA(cn, key), key, 11)
}

// selfSignedCA mints a self-signed CA certificate for cn under key.
func selfSignedCA(cn string, key *ecdsa.PrivateKey) *x509.Certificate {
	GinkgoHelper()
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
	return cert
}

// emptyCRLNumbered issues an empty CRL from cert with the given CRL number.
func emptyCRLNumbered(cert *x509.Certificate, key crypto.Signer, number int64) []byte {
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

// emptyCRLExpiring issues an empty CRL from cert whose NextUpdate is `in` from
// now, so two CRLs from the same issuer can be told apart by deadline.
func emptyCRLExpiring(cert *x509.Certificate, key crypto.Signer, number int64, in time.Duration) []byte {
	GinkgoHelper()
	now := time.Now().UTC()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: now,
		NextUpdate: now.Add(in),
	}, cert, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

var _ = Describe("crl_chain_file", func() {
	var (
		ctx      context.Context
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		upstream, upsCRL = upstreamCA("Upstream Root CA")
	})

	// trustUpstream appends the upstream certificate to the stored CA bundle,
	// which is what an imported chain looks like and what makes its CRL
	// verifiable.
	trustUpstream := func() {
		GinkgoHelper()
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...), upstreamPEM...))).To(Succeed())
	}

	It("is a no-op when unconfigured", func() {
		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("publishes an upstream CRL the CA bundle vouches for", func() {
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeTrue())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	It("discards a CRL no certificate in the bundle signed", func() {
		// SECURITY: this content is served verbatim to every agent. Without
		// the check the file would be a way to inject arbitrary bytes into
		// every agent's CRL store.
		_, strangerCRL := upstreamCA("Unrelated CA")
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(strangerCRL)

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse(), "nothing verified, so nothing to publish")
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("keeps the verified CRLs and drops the unverifiable ones from one file", func() {
		_, strangerCRL := upstreamCA("Unrelated CA")
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(strangerCRL, upsCRL)

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	It("ignores a CRL of our own found in the file", func() {
		// Ours is rebuilt from the inventory on every re-sign; taking it from a
		// file would let a stale copy supersede live revocations.
		trustUpstream()
		ourCRL := mustGetCRL(ctx, store)
		myCA.CRLChainFile = writeChainFile(ourCRL, upsCRL)

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2), "our own block appears once, from the inventory")
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	It("does not rewrite when the file has not changed", func() {
		// The rewrite bumps our CRL number, so doing it every pass would churn
		// the number for no reason and wake every consumer each cycle.
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeTrue())
		before := crlBlocks(mustGetCRL(ctx, store))[0].Number

		rewritten, err = myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse())
		Expect(crlBlocks(mustGetCRL(ctx, store))[0].Number).To(Equal(before))
	})

	It("removes an upstream CRL dropped from the file", func() {
		// The file is declarative: what it says is what gets published, so a
		// CRL taken out of it is meant to disappear.
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))

		myCA.CRLChainFile = writeChainFile()
		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeTrue())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("survives a configured file that does not exist yet", func() {
		// A mounted Secret may not have landed. Refusing to serve would turn a
		// slow rollout into an outage.
		trustUpstream()
		myCA.CRLChainFile = filepath.Join(GinkgoT().TempDir(), "absent.pem")

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("fails rather than publishing a file it cannot parse", func() {
		trustUpstream()
		path := filepath.Join(GinkgoT().TempDir(), "bad.pem")
		Expect(os.WriteFile(path, []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n"), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).To(MatchError(ContainSubstring("crl_chain_file")),
			"the error must name the file, not just fail")
		Expect(err).To(MatchError(ContainSubstring("parsing CRL 1")))
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1), "the published chain is untouched")
	})

	It("keeps the file's CRLs across an ordinary revocation", func() {
		// The re-sign path and the refresh path must agree about what upstream
		// means, or a revocation would drop what the file put there.
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[0].RevokedCertificateEntries).To(HaveLen(1))
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	// The count bound, not the byte bound. One ancestor with a long revocation
	// list is legitimately large and few; a file of many small CRLs is what
	// costs, because every entry has its signer resolved by trial verification
	// against the whole bundle several times per evaluation, with the CRL lock
	// and c.mu held. Refused like any other unusable file: the published chain
	// stays as it was.
	It("refuses a file holding more CRLs than the entry bound allows", func() {
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		before := mustGetCRL(ctx, store)
		failures := myCA.CRLChainFailures()

		var many []byte
		for i := 0; i < 65; i++ {
			many = append(many, upsCRL...)
		}
		myCA.CRLChainFile = writeChainFile(many)

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).To(MatchError(ContainSubstring("more than the 64 allowed")))
		Expect(myCA.CRLChainFailures()).To(Equal(failures+1),
			"a refusal nothing counts is a refusal nothing can alert on")
		Expect(mustGetCRL(ctx, store)).To(Equal(before),
			"the published chain must survive a file that was refused")
	})

	Describe("UpstreamCRLStatuses", func() {
		It("reports the upstream entries and not our own", func() {
			trustUpstream()
			myCA.CRLChainFile = writeChainFile(upsCRL)
			Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

			statuses, err := myCA.UpstreamCRLStatuses(mustGetCRL(ctx, store))
			Expect(err).NotTo(HaveOccurred())
			Expect(statuses).To(HaveLen(1))
			Expect(statuses[0].Issuer).To(ContainSubstring("Upstream Root CA"))
			Expect(statuses[0].NextUpdate).NotTo(BeZero())
		})

		// Two ancestors under one shared root can carry the same DN, and this
		// file pairs CRLs by signing certificate precisely so that both are
		// published. The metric has only the DN to label with, so two statuses
		// for one DN would be two samples with identical label sets: Gather
		// drops the second and errors on every scrape, leaving that ancestor
		// with no expiry series and PuppetCAUpstreamCRLExpired unable to fire
		// for it. One status per DN, carrying the nearest deadline, is what the
		// alert needs -- and asserting the *earlier* of the two is what stops a
		// "keep the first one seen" implementation passing.
		It("reports one status per issuer DN, carrying the nearest deadline", func() {
			aCert, aKey, _ := upstreamCAWithKey("Shared DN CA")
			bCert, bKey, _ := upstreamCAWithKey("Shared DN CA")
			Expect(aCert.RawIssuer).To(Equal(bCert.RawIssuer), "the fixture needs identical DNs")

			ours, err := store.GetCACert(ctx)
			Expect(err).NotTo(HaveOccurred())
			bundle := append([]byte{}, ours...)
			for _, cert := range []*x509.Certificate{aCert, bCert} {
				bundle = append(bundle, pem.EncodeToMemory(
					&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
			}
			Expect(store.SaveCACert(ctx, bundle)).To(Succeed())

			// A expires in 20 days and is published first; B expires in 2 and is
			// the one an operator has to act on.
			both := append(append([]byte{}, emptyCRLExpiring(aCert, aKey, 1, 20*24*time.Hour)...),
				emptyCRLExpiring(bCert, bKey, 1, 2*24*time.Hour)...)
			myCA.CRLChainFile = writeChainFile(both)
			Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

			blob := mustGetCRL(ctx, store)
			Expect(crlBlocks(blob)).To(HaveLen(3), "both ancestors must still be published")

			statuses, err := myCA.UpstreamCRLStatuses(blob)
			Expect(err).NotTo(HaveOccurred())
			Expect(statuses).To(HaveLen(1), "two samples sharing a label set are one dropped series")
			Expect(statuses[0].Issuer).To(ContainSubstring("Shared DN CA"))
			Expect(statuses[0].NextUpdate).To(BeTemporally("<", time.Now().Add(3*24*time.Hour)),
				"the nearest deadline is the one the expiry alert exists to catch")
		})

		It("is empty on a CA with no upstream", func() {
			statuses, err := myCA.UpstreamCRLStatuses(mustGetCRL(ctx, store))
			Expect(err).NotTo(HaveOccurred())
			Expect(statuses).To(BeEmpty())
		})
	})
})

var _ = Describe("crl_chain_file: absent versus empty", func() {
	// The file is authoritative, so what it means when it cannot be read
	// decides whether ancestor CRLs survive. Absent is "no statement" and must
	// preserve; empty is a declaration and must be honoured. Getting these the
	// same way round is unrecoverable: this CA cannot re-sign another CA's list.
	var (
		ctx      context.Context
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())

		upstream, upsCRL = upstreamCA("Upstream Root CA")

		// A published two-block chain, as an import leaves it.
		ours := mustGetCRL(ctx, store)
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, ours...), upsCRL...))).To(Succeed())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
	})

	It("keeps the published chain when a revocation runs with the file absent", func() {
		// The trigger that matters. crlChainLocked is reached from
		// signCRLLocked — the single write path for every CRL amendment — so
		// this is not a maintenance-tick edge case: one revocation on a replica
		// whose Secret has not mounted would truncate the chain fleet-wide.
		myCA.CRLChainFile = filepath.Join(GinkgoT().TempDir(), "never-mounted.pem")

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2), "a revocation truncated the published chain")
		Expect(chain[0].RevokedCertificateEntries).To(HaveLen(1))
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})

	It("keeps the published chain when a reissue runs with the file absent", func() {
		myCA.CRLChainFile = filepath.Join(GinkgoT().TempDir(), "never-mounted.pem")
		Expect(myCA.ReissueCRL(ctx)).To(Succeed())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
	})

	It("does not rewrite from a refresh pass with the file absent", func() {
		myCA.CRLChainFile = filepath.Join(GinkgoT().TempDir(), "never-mounted.pem")
		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
	})

	It("honours an empty file as a declaration to publish nothing extra", func() {
		// The other side of the distinction: a zero-byte file is how an
		// operator says the chain should carry only our own CRL.
		myCA.CRLChainFile = writeChainFile()

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeTrue())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("honours an empty file on the revocation path too", func() {
		myCA.CRLChainFile = writeChainFile()

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
	})

	It("keeps the published chain when the file is unreadable rather than absent", func() {
		// A permission error is not a statement either. Distinct from absent
		// because it takes the error branch, and distinct from corrupt because
		// nothing was parsed.
		if os.Geteuid() == 0 {
			Skip("mode 0000 does not deny open(2) to root, so this cannot be set up")
		}
		path := filepath.Join(GinkgoT().TempDir(), "unreadable.pem")
		Expect(os.WriteFile(path, upsCRL, 0o000)).To(Succeed())
		myCA.CRLChainFile = path

		// The read fails, so the re-sign fails rather than truncating.
		err := myCA.ReissueCRL(ctx)
		Expect(err).To(HaveOccurred())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
	})

	It("still publishes what a readable file names", func() {
		// The guard must not have disabled the feature.
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...), upstreamPEM...))).To(Succeed())
		myCA.CRLChainFile = writeChainFile(upsCRL)

		Expect(myCA.ReissueCRL(ctx)).To(Succeed())
		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Issuer.CommonName).To(Equal("Upstream Root CA"))
	})
})

var _ = Describe("crl_chain_file: what makes a CRL acceptable", func() {
	var (
		ctx      context.Context
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsKey   crypto.Signer
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.LeafKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		upstream, upsKey, upsCRL = upstreamCAWithKey("Upstream Root CA")
	})

	trustUpstream := func() {
		GinkgoHelper()
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...), upstreamPEM...))).To(Succeed())
	}

	It("rejects a CRL matching the bundle's issuer name but signed by another key", func() {
		// The check is a signature, not a name comparison. Nothing else in the
		// suite distinguishes the two, so relaxing it to issuer-DN matching —
		// which a parent rotating its CRL-signing key would motivate — would
		// land green. Under a shared root two siblings can hold the same DN,
		// so a name match would accept a CRL from the wrong CA entirely.
		trustUpstream()
		impostorCRL := crlFromImpostorNamed("Upstream Root CA")
		myCA.CRLChainFile = writeChainFile(impostorCRL)

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeFalse(), "a same-named CRL from a different key was published")
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1))
		Expect(myCA.CRLChainDiscarded()).To(BeNumerically(">", 0))
	})

	It("republishes a newer CRL from the same issuer", func() {
		// The transition the feature exists to serve: the parent reissues its
		// CRL and the operator refreshes the file. Nothing covered it — every
		// other spec adds or removes an issuer rather than replacing one.
		trustUpstream()
		myCA.CRLChainFile = writeChainFile(upsCRL)
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		first := crlBlocks(mustGetCRL(ctx, store))
		Expect(first).To(HaveLen(2))

		newer := emptyCRLNumbered(upstream, upsKey, 99)
		myCA.CRLChainFile = writeChainFile(newer)

		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rewritten).To(BeTrue(), "a newer CRL from the same issuer was not picked up")

		after := crlBlocks(mustGetCRL(ctx, store))
		Expect(after).To(HaveLen(2))
		Expect(after[1].Number.Int64()).To(Equal(int64(99)))
	})

	DescribeTable("refuses content that yields no CRL rather than treating it as an empty declaration",
		// The file is authoritative, so "no upstream CRLs" deletes every
		// ancestor -- permanently, because this CA cannot re-sign another CA's
		// list. pem.Decode cannot tell a truncated block from rubbish: it
		// returns nil for a block with no END line, for DER, for a certificate
		// bundle and for an HTML error page alike. Reading any of those as the
		// empty declaration is how `cat > file`, the refresh mechanism the
		// documentation recommends, silently dropped the chain mid-write.
		//
		// A genuinely empty file still means "publish nothing extra"; that is
		// the case below this table.
		func(content string) {
			trustUpstream()
			Expect(store.UpdateCRL(ctx, append(append([]byte{}, mustGetCRL(ctx, store)...), upsCRL...))).
				To(Succeed())
			Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))

			path := filepath.Join(GinkgoT().TempDir(), "chain.pem")
			Expect(os.WriteFile(path, []byte(content), 0o644)).To(Succeed())
			myCA.CRLChainFile = path

			_, err := myCA.RefreshCRLChainFile(ctx)
			Expect(err).To(HaveOccurred())
			Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2),
				"the published chain must survive a file we could not read")
		},
		Entry("a block truncated mid-write", "-----BEGIN X509 CRL-----\nZm9v\n"),
		Entry("not PEM at all", "<html>502 Bad Gateway</html>\n"),
		Entry("a certificate bundle by mistake",
			"-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"),
	)

	It("refuses a valid CRL followed by a truncated one", func() {
		// The likeliest mid-write shape: the first block flushed, the second
		// cut. Decoding stops at the incomplete block and reports success, so
		// the chain silently loses whatever came after it.
		trustUpstream()
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, mustGetCRL(ctx, store)...), upsCRL...))).
			To(Succeed())

		path := filepath.Join(GinkgoT().TempDir(), "cut.pem")
		cut := append(append([]byte{}, upsCRL...), []byte("-----BEGIN X509 CRL-----\nZm9v\n")...)
		Expect(os.WriteFile(path, cut, 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).To(MatchError(ContainSubstring("does not end on a PEM block boundary")))
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
	})

	It("refuses a valid CRL followed by a tail that never reached its BEGIN line", func() {
		// The rule used to be `bytes.Contains(rest, "-----BEGIN")`, which reads
		// the tail for evidence that a block had started. A write cut inside the
		// *text preamble* of the next block carries no such evidence, so the file
		// decoded as a valid, shorter declaration -- and because the file is
		// authoritative, a missing ancestor reads as a deliberate removal. The
		// chain shrank with no error and no counter.
		//
		// This is the shape `openssl crl -text` produces, which is exactly why
		// the tolerance was added; the tolerance was unnecessary, because that
		// commentary *precedes* its block and pem.Decode already skips it.
		trustUpstream()
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, mustGetCRL(ctx, store)...), upsCRL...))).
			To(Succeed())

		path := filepath.Join(GinkgoT().TempDir(), "preamble.pem")
		cut := append(append([]byte{}, upsCRL...),
			[]byte("Certificate Revocation List (CRL):\n    Version 2 (0x1)\n")...)
		Expect(os.WriteFile(path, cut, 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).To(MatchError(ContainSubstring("does not end on a PEM block boundary")))
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
	})

	It("accepts commentary that precedes a block, which is where bundles carry it", func() {
		// The other direction of the same rule: tightening the tail must not
		// refuse `openssl crl -text` output, whose dump comes before the PEM and
		// which therefore ends on a block boundary.
		trustUpstream()
		path := filepath.Join(GinkgoT().TempDir(), "commented.pem")
		commented := append([]byte("Certificate Revocation List (CRL):\n    Version 2 (0x1)\n"),
			upsCRL...)
		Expect(os.WriteFile(path, commented, 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
	})

	It("finds the signer anywhere in the bundle, not just at the end", func() {
		// Every accepting spec trusted exactly one ancestor, so the verifying
		// certificate was always the last entry and the search was never
		// exercised: `return crlSignedBy(candidates[len(candidates)-1], crl)`
		// passed. That breaks the deployment this feature exists for --
		// root -> intermediate -> this CA -- by discarding the intermediate's
		// CRL on every refresh.
		intermediate, intKey, _ := upstreamCAWithKey("Intermediate CA")
		root, _, _ := upstreamCAWithKey("Root CA")

		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		bundle := append([]byte{}, ours...)
		for _, cert := range []*x509.Certificate{intermediate, root} {
			bundle = append(bundle, pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		}
		Expect(store.SaveCACert(ctx, bundle)).To(Succeed())

		// The intermediate signs, and it is not the last entry.
		path := filepath.Join(GinkgoT().TempDir(), "mid.pem")
		Expect(os.WriteFile(path, emptyCRLNumbered(intermediate, intKey, 3), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Issuer.CommonName).To(Equal("Intermediate CA"))
		Expect(myCA.CRLChainDiscarded()).To(BeZero(),
			"a CRL the bundle does vouch for must not be discarded")
	})

	It("keeps the published CRL when the file carries an older one, on every write path", func() {
		// Everything reaching this point is signature-valid, so an older CRL
		// from the right issuer passes every other check -- and publishing it
		// un-revokes, fleet-wide, everything the parent revoked in between.
		//
		// The check used to live beside RefreshCRLChainFile, where it failed the
		// whole pass. Two things were wrong with that. It guarded one of the two
		// write paths, so the maintenance task refused the rolled-back file --
		// loudly, with alerts asserting the chain was protected -- and the next
		// revocation published it anyway through crlChainLocked. And failing the
		// pass is the wrong response to a rollback: unlike a corrupt file, the
		// published chain is still correct, so refusing lets anyone who can write
		// the file deny revocation. The rule now lives in upstreamCRLs, which
		// both writers call, and substitutes rather than fails.
		//
		// The second half of this spec is the mutation the old arrangement could
		// not notice: revoke after the refusal and assert 99 is still published.
		keyedCert, keyedKey, _ := upstreamCAWithKey("Rollback Root CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		keyedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keyedCert.Raw})
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...), keyedPEM...))).To(Succeed())

		newer := emptyCRLNumbered(keyedCert, keyedKey, 99)
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, mustGetCRL(ctx, store)...), newer...))).
			To(Succeed())

		older := emptyCRLNumbered(keyedCert, keyedKey, 7)
		path := filepath.Join(GinkgoT().TempDir(), "rollback.pem")
		Expect(os.WriteFile(path, older, 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		// The maintenance path: no error, nothing rewritten, 99 still published.
		rewritten, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred(),
			"a rollback must not block revocation the way a corrupt file does")
		Expect(rewritten).To(BeFalse())
		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Number.Int64()).To(Equal(int64(99)))

		Expect(myCA.CRLChainRegressed()).NotTo(BeZero(),
			"the regression must be counted, and on its own counter")
		Expect(myCA.CRLChainDiscarded()).To(BeZero(),
			"a rollback is not a discard: the remedies are opposite, so the "+
				"counters must be too")

		// The revocation path. This is the one the old guard never covered.
		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		chain = crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Number.Int64()).To(Equal(int64(99)),
			"a revocation must not be the thing that publishes the rolled-back CRL")
	})

	It("pairs CRLs by signing certificate, not by issuer distinguished name", func() {
		// crlSignedBy's comment argues at length that a shared root can issue two
		// sub-CAs carrying the same DN, so DN-keyed pairing compares one
		// ancestor's CRL against another's. The regression check was keyed on
		// RawIssuer, against that reasoning: two ancestors with identical DNs and
		// independent CRL numbering would have had one silently suppress the
		// other.
		aCert, aKey, _ := upstreamCAWithKey("Shared DN CA")
		bCert, bKey, _ := upstreamCAWithKey("Shared DN CA")
		Expect(aCert.RawIssuer).To(Equal(bCert.RawIssuer), "the fixture needs identical DNs")
		Expect(aCert.Raw).NotTo(Equal(bCert.Raw))

		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		bundle := append([]byte{}, ours...)
		for _, cert := range []*x509.Certificate{aCert, bCert} {
			bundle = append(bundle, pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
		}
		Expect(store.SaveCACert(ctx, bundle)).To(Succeed())

		// A is at 99. B is at 7 -- lower, but a different ancestor entirely, so
		// it is not a regression and must be published.
		Expect(store.UpdateCRL(ctx, append(append([]byte{}, mustGetCRL(ctx, store)...),
			emptyCRLNumbered(aCert, aKey, 99)...))).To(Succeed())

		path := filepath.Join(GinkgoT().TempDir(), "shared-dn.pem")
		both := append(append([]byte{}, emptyCRLNumbered(aCert, aKey, 99)...),
			emptyCRLNumbered(bCert, bKey, 7)...)
		Expect(os.WriteFile(path, both, 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(3))
		Expect(myCA.CRLChainRegressed()).To(BeZero(),
			"a different ancestor that happens to share a DN is not a rollback")
	})

	It("fails a revocation rather than publishing a corrupt file", func() {
		// Fail-closed is the right choice — the alternative is truncating the
		// chain — but it newly couples revocation to an externally refreshed
		// file, so it is worth pinning rather than leaving implicit.
		trustUpstream()
		path := filepath.Join(GinkgoT().TempDir(), "corrupt.pem")
		Expect(os.WriteFile(path, []byte("-----BEGIN X509 CRL-----\nZm9v\n-----END X509 CRL-----\n"), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())

		Expect(myCA.Revoke(ctx, "node1.test")).NotTo(Succeed(),
			"a corrupt chain file must not be published, and must not pass silently")
	})
})

var _ = Describe("crl_chain_file: size and duplicates", func() {
	var (
		ctx      context.Context
		store    *storage.StorageService
		myCA     *ca.CA
		upstream *x509.Certificate
		upsKey   crypto.Signer
		upsCRL   []byte
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.New(GinkgoT().TempDir())
		myCA = ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		Expect(myCA.Init(ctx)).To(Succeed())
		upstream, upsKey, upsCRL = upstreamCAWithKey("Upstream Root CA")
	})

	trustUpstream := func() {
		GinkgoHelper()
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		upstreamPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Raw})
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...), upstreamPEM...))).To(Succeed())
	}

	It("publishes one CRL per issuer, keeping the highest CRL number", func() {
		// The refresh mechanisms this feature is built around are file
		// concatenation, so a CronJob that appends rather than replaces grows
		// the file by one stale copy per run. Publishing both is how a
		// revocation gets un-revoked for a client that stops at the first
		// match.
		trustUpstream()
		newer := emptyCRLNumbered(upstream, upsKey, 9) // upsCRL is number 7
		myCA.CRLChainFile = writeChainFile(upsCRL, newer)

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2), "ours plus one upstream, not two upstream")
		Expect(chain[1].Number.Int64()).To(Equal(int64(9)))
	})

	It("keeps the highest number whichever order the copies appear in", func() {
		trustUpstream()
		newer := emptyCRLNumbered(upstream, upsKey, 9)
		myCA.CRLChainFile = writeChainFile(newer, upsCRL)

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).NotTo(HaveOccurred())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Number.Int64()).To(Equal(int64(9)))
	})

	It("accepts a file close to the limit, so the bound cannot be quietly lowered", func() {
		// The bound was pinned from one side only: raising it fails the
		// oversized spec, but lowering it to 64 KiB left everything green --
		// while making the feature unusable on a root CA with a few thousand
		// revocations, whose CRL comfortably exceeds that.
		//
		// This padding is 1 MiB, so it is lowering the bound *below 1 MiB* that
		// now costs a spec; `2 << 20` still passes. That is deliberate rather
		// than lazy -- padding to just under 4 MiB would make every run of this
		// spec allocate and hash the full bound -- and 1 MiB already covers the
		// stated motivation with room to spare.
		trustUpstream()
		padded := append(bytes.Repeat([]byte("# padding\n"), (1<<20)/10), upsCRL...)
		Expect(len(padded)).To(BeNumerically("<", 4<<20))

		path := filepath.Join(GinkgoT().TempDir(), "big.pem")
		Expect(os.WriteFile(path, padded, 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2),
			"a file comfortably under the bound must publish")
	})

	It("refuses an oversized file rather than reading a truncated chain", func() {
		// Silent truncation would drop upstream CRLs with no error, which is
		// the failure the absent-file handling exists to prevent. This is read
		// under both the CRL lock and c.mu, on the path every revocation takes.
		trustUpstream()
		path := filepath.Join(GinkgoT().TempDir(), "huge.pem")
		padding := bytes.Repeat([]byte("# padding\n"), (4<<20)/10+1)
		Expect(os.WriteFile(path, append(append([]byte{}, upsCRL...), padding...), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		_, err := myCA.RefreshCRLChainFile(ctx)
		Expect(err).To(MatchError(ContainSubstring("larger than")))
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(1), "nothing published from a file we would not read whole")
	})

	It("pairs against the newest published CRL when an ancestor has more than one", func() {
		// monotonicUpstream builds its comparison map from the published chain,
		// and that side is not deduped: orderCRLChain collapses duplicates of
		// this CA's own CRL only, and warnAboutAncestors warns about ancestor
		// duplicates while publishing "all of them as supplied". So a stored
		// [ours, A#9, A#5] is a shape an import can really produce.
		//
		// Assigning into the map unconditionally kept whichever came last, which
		// is an artefact of how the operator concatenated their bundle. A#7 then
		// compared against A#5, looked newer, and the rollback was published --
		// round 2's CRITICAL, reachable again one layer down.
		anc, ancKey, _ := upstreamCAWithKey("Duplicated Ancestor CA")
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anc.Raw})...))).To(Succeed())

		// Newest first, then a stale copy -- so "last wins" picks the wrong one.
		stored := append(append([]byte{}, mustGetCRL(ctx, store)...),
			emptyCRLNumbered(anc, ancKey, 9)...)
		stored = append(stored, emptyCRLNumbered(anc, ancKey, 5)...)
		Expect(store.UpdateCRL(ctx, stored)).To(Succeed())

		myCA.CRLChainFile = writeChainFile(emptyCRLNumbered(anc, ancKey, 7))

		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		Expect(myCA.CRLChainRegressed()).NotTo(BeZero(),
			"7 is older than the newest published copy, 9")

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())
		Expect(myCA.Revoke(ctx, "node1.test")).To(Succeed())

		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Number.Int64()).To(Equal(int64(9)))
	})

	It("counts an ancestor the file has stopped listing", func() {
		// The shrink alarm was drawn at the degenerate boundary only: going from
		// two ancestors to one moved no counter and logged nothing at any level,
		// because crlChainDiscarded counts CRLs the file *carries* that nothing
		// signed, and an absent one is not carried. Same cause as the empty-file
		// case -- a glob that matched one file fewer -- and just as permanent.
		second, secondKey, secondCRL := upstreamCAWithKey("Second Ancestor CA")
		trustUpstream()
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Raw})...))).To(Succeed())
		Expect(secondKey).NotTo(BeNil())

		myCA.CRLChainFile = writeChainFile(upsCRL, secondCRL)
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(3))
		Expect(myCA.CRLChainRemoved()).To(BeZero())

		// The file now lists one of the two. The other is dropped -- honoured,
		// because the file is authoritative, but unrecoverable here.
		Expect(os.WriteFile(myCA.CRLChainFile, upsCRL, 0o644)).To(Succeed())
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())

		Expect(crlBlocks(mustGetCRL(ctx, store))).To(HaveLen(2))
		// Two, not one: a pass that actually rewrites evaluates the file twice --
		// once to decide, and once more inside crlChainLocked when
		// reissueCRLLocked re-signs under the lock. That is the "per CRL per
		// evaluation" cadence documented for the discard and regression counters,
		// and this one shares it. Pinned at its value so the cadence cannot drift
		// without a spec noticing.
		Expect(myCA.CRLChainRemoved()).To(Equal(uint64(2)))
		Expect(myCA.CRLChainDiscarded()).To(BeZero(),
			"an ancestor the file omits is not a CRL the bundle refused")
	})

	It("orders number-less CRLs by ThisUpdate, in the file and against the published chain", func() {
		// `openssl ca -gencrl` omits cRLNumber unless crl_extensions is
		// configured, which the stock openssl.cnf leaves commented out -- so a
		// number-less ancestor CRL is ordinary in this feature's audience. Both
		// comparison sites fall back to ThisUpdate via newerCRL, and nothing
		// exercised that: every fixture reaching crl_chain_file set Number, so
		// reverting either site to an inline `a.Number != nil && b.Number != nil`
		// check left the suite green while silently keeping whichever copy came
		// first.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		anc := selfSignedCA("Numberless Ancestor CA", key)
		ours, err := store.GetCACert(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(store.SaveCACert(ctx, append(append([]byte{}, ours...),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anc.Raw})...))).To(Succeed())

		base := time.Now().UTC().Truncate(time.Second).Add(-24 * time.Hour)
		older := handRolledCRLAt(anc, key, base)
		newer := handRolledCRLAt(anc, key, base.Add(6*time.Hour))

		// dedupeCRLs: the appending-CronJob shape, older copy first. Keeping the
		// first would hand a client the ancestor's stale list.
		myCA.CRLChainFile = writeChainFile(older, newer)
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		chain := crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].Number).To(BeNil(), "the fixture must really carry no cRLNumber")
		Expect(chain[1].ThisUpdate).To(BeTemporally("==", base.Add(6*time.Hour)))

		// monotonicUpstream: the file now offers only the older one. Without the
		// ThisUpdate fallback this is not seen as a regression and is published.
		Expect(os.WriteFile(myCA.CRLChainFile, older, 0o644)).To(Succeed())
		Expect(myCA.RefreshCRLChainFile(ctx)).Error().NotTo(HaveOccurred())
		Expect(myCA.CRLChainRegressed()).NotTo(BeZero())

		chain = crlBlocks(mustGetCRL(ctx, store))
		Expect(chain).To(HaveLen(2))
		Expect(chain[1].ThisUpdate).To(BeTemporally("==", base.Add(6*time.Hour)),
			"the newer number-less CRL must survive a rollback to the older one")
	})

	It("counts a chain-file failure on the revocation path, not only the refresh pass", func() {
		// crlChainFailures had one increment site, inside RefreshCRLChainFile.
		// An unreadable file fails every revocation through crlChainLocked, and
		// that moved nothing -- so the alert carrying the right remedy could not
		// fire until the next hourly pass, while PuppetCACRLUpdateFailing sent
		// the responder to check storage instead. The same shape monotonicUpstream
		// was moved to the chokepoint to fix, one artefact over.
		trustUpstream()
		path := filepath.Join(GinkgoT().TempDir(), "bad.pem")
		Expect(os.WriteFile(path, []byte("<html>502 Bad Gateway</html>\n"), 0o644)).To(Succeed())
		myCA.CRLChainFile = path

		res, err := myCA.Generate(ctx, "node1.test", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(res).NotTo(BeNil())

		Expect(myCA.CRLChainFailures()).To(BeZero())
		Expect(myCA.Revoke(ctx, "node1.test")).NotTo(Succeed())
		Expect(myCA.CRLChainFailures()).NotTo(BeZero(),
			"the file is what failed, so the file's counter must move")
	})
})
