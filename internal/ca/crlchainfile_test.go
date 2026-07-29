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
})
