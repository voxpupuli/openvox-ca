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
	"math/big"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// The specs below model the HA deployment the bug lives in: two CA instances
// over one storage directory, standing in for two replicas sharing a Postgres,
// MySQL, etcd or Redis backend. Only the pairing matters — every one of those
// backends presents the CRL to both replicas as one shared blob, which is the
// only property being exercised.

// attachReplica builds a second, independently initialised CA over an existing
// storage directory. It has its own in-memory CRL cache, which is the whole
// point: it is the replica that did not perform the revocation.
func attachReplica(dir string) *ca.CA {
	GinkgoHelper()
	store := storage.New(dir)
	replica := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
	Expect(replica.Init(context.Background())).To(Succeed())
	return replica
}

// signedCert signs a certificate for subject and returns it parsed.
func signedCert(c *ca.CA, subject string) *x509.Certificate {
	GinkgoHelper()
	csrPEM, err := testutil.GenerateCSR(subject)
	Expect(err).NotTo(HaveOccurred())
	_, err = c.SaveRequest(context.Background(), subject, csrPEM)
	Expect(err).NotTo(HaveOccurred())
	certPEM, err := c.Sign(context.Background(), subject)
	Expect(err).NotTo(HaveOccurred())
	return decodeCert(certPEM)
}

var _ = Describe("SyncCRLCache", func() {
	var (
		tmpDir  string
		signer  *ca.CA // the replica that performs the revocation
		replica *ca.CA // the replica that must learn about it
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-crlsync-test")
		Expect(err).NotTo(HaveOccurred())
		signer = setupOCSPCA(tmpDir)
		replica = attachReplica(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	It("makes a revocation performed elsewhere take effect here", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-revoked-node")

		Expect(signer.Revoke(ctx, "crlsync-revoked-node")).To(Succeed())

		// The bug: the replica that did not revoke keeps admitting the
		// certificate, because it answers from a CRL cache only its own
		// re-signs update.
		stale, err := replica.IsRevokedSerial(ctx, cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(stale).To(BeFalse(), "precondition: the replica should not yet know about the revocation")

		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue(), "the stored CRL had advanced, so it should have been installed")

		revoked, err := replica.IsRevokedSerial(ctx, cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(), "the replica must reject the revoked serial after syncing")
		Expect(replica.CRLSyncFailures()).To(BeZero())
	})

	It("reports no change when the stored CRL has not advanced", func() {
		ctx := context.Background()
		Expect(signer.Revoke(ctx, "crlsync-noop-node")).NotTo(Succeed(), "no such certificate")

		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse(), "nothing has re-signed the CRL since the replica started")
	})

	It("installs each successive revocation exactly once", func() {
		ctx := context.Background()
		first := signedCert(signer, "crlsync-first-node")
		second := signedCert(signer, "crlsync-second-node")

		Expect(signer.Revoke(ctx, "crlsync-first-node")).To(Succeed())
		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())

		// A second sync with nothing new must be a no-op, so the job can run on
		// a short timer without churning the cache or the OCSP responses hung
		// off it.
		updated, err = replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse())

		Expect(signer.Revoke(ctx, "crlsync-second-node")).To(Succeed())
		updated, err = replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())

		for _, cert := range []*x509.Certificate{first, second} {
			revoked, err := replica.IsRevokedSerial(ctx, cert.SerialNumber)
			Expect(err).NotTo(HaveOccurred())
			Expect(revoked).To(BeTrue())
		}
	})

	It("never goes backwards to an older CRL", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-rollback-node")

		// Capture the CRL from before the revocation, then apply the revocation
		// to both replicas.
		beforePEM, err := signer.Storage.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(signer.Revoke(ctx, "crlsync-rollback-node")).To(Succeed())
		_, err = replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())

		// Put the older CRL back, standing in for a read that landed on a
		// lagging replica of the storage backend. Installing it would silently
		// unrevoke a certificate this process has already rejected, so the
		// lower CRL number must be declined.
		Expect(signer.Storage.UpdateCRL(ctx, beforePEM)).To(Succeed())

		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeFalse(), "a lower CRL number must not replace the cache")

		revoked, err := replica.IsRevokedSerial(ctx, cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(), "the revocation must survive a stale read")
	})

	It("refuses a stored CRL this CA did not sign", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-foreign-node")
		Expect(signer.Revoke(ctx, "crlsync-foreign-node")).To(Succeed())
		_, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())

		// A CRL from an unrelated authority, numbered far ahead of ours so that
		// the number comparison alone would happily install it. Accepting it
		// would empty this replica's revocation list.
		Expect(signer.Storage.UpdateCRL(ctx, foreignCRLPEM(9999))).To(Succeed())

		before := replica.CRLSyncFailures()
		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no CRL signed by the CA certificate this process is using"))
		Expect(updated).To(BeFalse())
		Expect(replica.CRLSyncFailures()).To(Equal(before+1), "the refusal must be counted for alerting")

		revoked, err := replica.IsRevokedSerial(ctx, cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue(), "the CRL we already hold must be kept (fail closed)")
	})

	// The refusal is only worth anything if the paths that *re-sign* the stored
	// CRL refuse it too. They do not merely read it: they take its number and
	// its entries, sign them with this CA's real key, and write the result back
	// — so a foreign CRL the sync had correctly declined would be laundered by
	// the next revocation into one every check accepts, carrying whatever
	// revocations it did or did not contain.
	It("does not launder a foreign CRL into a signed one when revoking", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-launder-node")
		Expect(signer.Revoke(ctx, "crlsync-launder-node")).To(Succeed())
		_ = signedCert(signer, "crlsync-launder-other-node")

		// Someone with write access to the backend replaces the stored CRL with
		// one of their own, numbered far ahead so it would win any comparison.
		poison := foreignCRLPEM(9999)
		Expect(signer.Storage.UpdateCRL(ctx, poison)).To(Succeed())

		Expect(signer.Revoke(ctx, "crlsync-launder-other-node")).NotTo(Succeed(),
			"revoking against a CRL this CA did not sign must fail rather than re-sign it")

		// The stored blob must still be theirs — unsigned by us and therefore
		// refused everywhere — rather than a validly signed CRL built from it.
		stored, err := signer.Storage.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored).To(Equal(poison), "the CA must not have re-signed over it")

		// And the revocation it already knew about is still enforced, because
		// the refusal left the cache alone.
		revoked, err := signer.IsRevokedSerial(ctx, cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(revoked).To(BeTrue())
	})

	It("does not launder a foreign CRL when reissuing or refreshing", func() {
		ctx := context.Background()
		poison := foreignCRLPEM(9999)
		Expect(signer.Storage.UpdateCRL(ctx, poison)).To(Succeed())

		// A window far larger than any validity, so the job would re-sign if it
		// were willing to.
		reissued, err := signer.RefreshCRLIfDue(ctx, 3650*24*time.Hour)
		Expect(err).To(HaveOccurred())
		Expect(reissued).To(BeFalse())

		Expect(signer.ReissueCRL(ctx)).NotTo(Succeed())

		stored, err := signer.Storage.GetCRL(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(stored).To(Equal(poison))
	})

	// main's loadCRLCache keeps a foreign block 0 and warns rather than refusing
	// to start, so the cache is not always one of ours. Ordering our CRL against
	// a foreign one compares numbers from two different issuers: an ancestor's
	// 47 would outrank our freshly seeded 1 for ever, and the decline would be
	// silent — no counter, no alert, and the replica answering revocation from a
	// list this CA never signed.
	It("replaces a cached CRL this CA did not sign, whatever the numbers say", func() {
		ctx := context.Background()

		// Start a replica whose stored chain carries only an ancestor's CRL,
		// numbered far above anything of ours. It warns and caches that block.
		dir, err := os.MkdirTemp("", "openvox-ca-crlsync-foreign-cache")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { os.RemoveAll(dir) })

		store := storage.New(dir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		Expect(store.SaveCAKey(ctx, cachedKeyPEM)).To(Succeed())
		Expect(store.SaveCACert(ctx, cachedCrtPEM)).To(Succeed())
		Expect(store.UpdateCRL(ctx, foreignCRLPEM(47))).To(Succeed())
		Expect(store.WriteSerial(ctx, "0001")).To(Succeed())
		Expect(store.TouchInventory(ctx)).To(Succeed())

		stranded := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(stranded.Init(ctx)).To(Succeed(), "a foreign block 0 must not stop the CA starting")

		// The operator repairs storage with a CRL of ours. Its number is 1,
		// well below the ancestor's 47.
		Expect(store.UpdateCRL(ctx, cachedCrlPEM)).To(Succeed())

		updated, err := stranded.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue(), "our CRL must replace a foreign one regardless of number")

		num, ok := stranded.CachedCRLNumber()
		Expect(ok).To(BeTrue())
		Expect(num.Cmp(big.NewInt(1))).To(BeZero(), "must now be deciding from our own CRL")
	})

	It("counts a CRL it cannot read", func() {
		ctx := context.Background()
		Expect(signer.Storage.UpdateCRL(ctx, []byte("not a PEM block"))).To(Succeed())

		before := replica.CRLSyncFailures()
		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).To(HaveOccurred())
		Expect(updated).To(BeFalse())
		Expect(replica.CRLSyncFailures()).To(Equal(before + 1))
	})

	It("stops the OCSP responder answering Good for a serial revoked elsewhere", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-ocsp-node")

		// Attach after signing: the OCSP responder answers Unknown for a serial
		// missing from its serial index, and that index is built once at Init.
		// Which is a staleness of its own, but not this one — the concern here
		// is a signed Good response outliving the CRL that contradicts it.
		replica := attachReplica(tmpDir)

		// The cache holds one answer per request hash, and this is the one
		// path that installs a CRL without Revoke's own eviction alongside it,
		// so every hash is primed here: a Good left under any one of them would
		// be served for OCSPValidity.
		hashes := []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512}
		requests := make(map[crypto.Hash][]byte, len(hashes))
		for _, hash := range hashes {
			reqDER, err := xocsp.CreateRequest(cert, replica.CACert, &xocsp.RequestOptions{Hash: hash})
			Expect(err).NotTo(HaveOccurred())
			requests[hash] = reqDER

			// Prime the replica's OCSP cache with a signed Good response. Its
			// NextUpdate is hours out, so without invalidation it would outlive
			// the CRL reload. The second answer's shorter MaxAge proves it was
			// served from the cache rather than signed again.
			first, err := replica.AnswerOCSP(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred())
			resp, err := xocsp.ParseResponse(first.DER, replica.CACert)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Status).To(Equal(xocsp.Good))
			second, err := replica.AnswerOCSP(ctx, reqDER)
			Expect(err).NotTo(HaveOccurred())
			Expect(second.MaxAge).To(BeNumerically("<", first.MaxAge), "%v's Good must be cached", hash)
		}

		Expect(signer.Revoke(ctx, "crlsync-ocsp-node")).To(Succeed())
		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())

		for _, hash := range hashes {
			respDER, err := replica.OCSPResponse(ctx, requests[hash])
			Expect(err).NotTo(HaveOccurred())
			resp, err := xocsp.ParseResponse(respDER, replica.CACert)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Status).To(Equal(xocsp.Revoked),
				"the pre-signed %v Good response must be dropped when the CRL that contradicts it is installed", hash)
		}
	})

	It("refuses to renew a certificate revoked on another replica", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-renew-node")

		Expect(signer.Revoke(ctx, "crlsync-renew-node")).To(Succeed())

		// The replica's cached CRL still predates the revocation, so the auth
		// middleware would admit this certificate. Renewal is the one request
		// that turns that into a permanent bypass — it mints a new serial no CRL
		// will ever list — so it must not rely on the cache.
		stale, err := replica.IsRevokedSerial(ctx, cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(stale).To(BeFalse(), "precondition: the replica has not yet synced")

		_, err = replica.AutoRenew(ctx, cert)
		Expect(err).To(MatchError(ca.ErrCertRevoked))
	})

	// The CSR path also re-keys, so a revoked agent getting through it walks
	// away with a credential whose private key the CA has never seen.
	It("refuses to re-key a certificate revoked on another replica", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-rekey-node")
		csrPEM, err := testutil.GenerateCSR("crlsync-rekey-node")
		Expect(err).NotTo(HaveOccurred())

		Expect(signer.Revoke(ctx, "crlsync-rekey-node")).To(Succeed())

		stale, err := replica.IsRevokedSerial(ctx, cert.SerialNumber)
		Expect(err).NotTo(HaveOccurred())
		Expect(stale).To(BeFalse(), "precondition: the replica has not yet synced")

		_, err = replica.Renew(ctx, "crlsync-rekey-node", csrPEM, cert)
		Expect(err).To(MatchError(ca.ErrCertRevoked))
	})

	// Fail-closed on an unusable CRL, but not on a failed refresh: a storage
	// blip must cost freshness, not every renewal in the fleet.
	It("still enforces a revocation it already knows about when the refresh fails", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-renew-degraded-node")

		Expect(signer.Revoke(ctx, "crlsync-renew-degraded-node")).To(Succeed())
		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())

		// Now break the stored CRL, so the pre-renewal refresh fails and the
		// check falls back to the copy in memory.
		Expect(signer.Storage.UpdateCRL(ctx, []byte("not a CRL"))).To(Succeed())

		before := replica.CRLSyncFailures()
		_, err = replica.AutoRenew(ctx, cert)
		Expect(err).To(MatchError(ca.ErrCertRevoked))
		Expect(replica.CRLSyncFailures()).To(Equal(before+1),
			"the refresh must actually have failed, or this proves nothing about the fallback")
	})

	// Both checks refuse, so the order only decides the answer. A revoked
	// identity must be told it is revoked (403), not pointed at the re-key path
	// by a key-policy 422 that never mentions the revocation.
	It("reports a revoked certificate as revoked even when its key is below policy", func() {
		ctx := context.Background()
		weak := weakRevokedCert(signer, "crlsync-weak-revoked-node")

		_, err := replica.AutoRenew(ctx, weak)
		Expect(err).To(MatchError(ca.ErrCertRevoked))
		Expect(err).NotTo(MatchError(ca.ErrKeyPolicy))
	})

	It("still renews a certificate that is not revoked", func() {
		ctx := context.Background()
		cert := signedCert(signer, "crlsync-renew-ok-node")

		renewed, err := replica.AutoRenew(ctx, cert)
		Expect(err).NotTo(HaveOccurred())
		Expect(decodeCert(renewed).SerialNumber.Cmp(cert.SerialNumber)).NotTo(BeZero(),
			"renewal should issue a fresh serial")
	})

	It("leaves the cached OCSP responses of serials it did not revoke alone", func() {
		ctx := context.Background()
		revokedCert := signedCert(signer, "crlsync-ocsp-target-node")
		bystander := signedCert(signer, "crlsync-ocsp-bystander-node")

		// Attach after signing so both serials are in the replica's OCSP index.
		replica := attachReplica(tmpDir)

		bystanderReq, err := testutil.BuildOCSPRequest(bystander, replica.CACert)
		Expect(err).NotTo(HaveOccurred())
		before, err := replica.OCSPResponse(ctx, bystanderReq)
		Expect(err).NotTo(HaveOccurred())

		Expect(signer.Revoke(ctx, "crlsync-ocsp-target-node")).To(Succeed())
		updated, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(updated).To(BeTrue())

		// Byte-identical means it came back from the cache rather than being
		// re-signed. Dropping every revoked serial's entry on each sync instead
		// of only the newly revoked ones would re-sign the whole revoked set on
		// every revocation anywhere in the fleet.
		after, err := replica.OCSPResponse(ctx, bystanderReq)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "an unrelated serial's cached response must survive the sync")

		// ...and the serial that was revoked must not have survived.
		targetReq, err := testutil.BuildOCSPRequest(revokedCert, replica.CACert)
		Expect(err).NotTo(HaveOccurred())
		targetResp, err := replica.OCSPResponse(ctx, targetReq)
		Expect(err).NotTo(HaveOccurred())
		parsed, err := xocsp.ParseResponse(targetResp, replica.CACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(parsed.Status).To(Equal(xocsp.Revoked))
	})

	It("reports the CRL number it is deciding from", func() {
		ctx := context.Background()
		_ = signedCert(signer, "crlsync-number-node")

		before, ok := replica.CachedCRLNumber()
		Expect(ok).To(BeTrue())

		Expect(signer.Revoke(ctx, "crlsync-number-node")).To(Succeed())
		unmoved, ok := replica.CachedCRLNumber()
		Expect(ok).To(BeTrue())
		Expect(unmoved.Cmp(before)).To(BeZero(),
			"the reported number must not move until the replica actually installs the new CRL")

		_, err := replica.SyncCRLCache(ctx)
		Expect(err).NotTo(HaveOccurred())

		after, ok := replica.CachedCRLNumber()
		Expect(ok).To(BeTrue())
		Expect(after.Cmp(before)).To(Equal(1))
	})
})

// weakRevokedCert issues a certificate for subject, revokes it, and returns a
// certificate carrying that same (now revoked) serial but a 1024-bit key —
// below this CA's key-strength policy. Both refusals therefore apply to it, so
// it pins which one AutoRenew reports.
//
// The serial is reused rather than the key rotated because revocation is by
// serial: the CRL entry the real issuance produced is what makes this one
// revoked.
func weakRevokedCert(c *ca.CA, subject string) *x509.Certificate {
	GinkgoHelper()
	ctx := context.Background()
	issued := signedCert(c, subject)
	Expect(c.Revoke(ctx, subject)).To(Succeed())

	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	Expect(err).NotTo(HaveOccurred())

	caKeyBlock, _ := pem.Decode(cachedKeyPEM)
	Expect(caKeyBlock).NotTo(BeNil())
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber: issued.SerialNumber,
		Subject:      pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{subject},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, decodeCert(cachedCrtPEM), &weakKey.PublicKey, caKey)
	Expect(err).NotTo(HaveOccurred())
	weak, err := x509.ParseCertificate(der)
	Expect(err).NotTo(HaveOccurred())
	return weak
}

// foreignCRLPEM returns a PEM CRL with the given number, signed by a throwaway
// CA that has nothing to do with the suite's.
func foreignCRLPEM(number int64) []byte {
	GinkgoHelper()
	keyPEM, crtPEM, _, err := testutil.GenerateTestCA()
	Expect(err).NotTo(HaveOccurred())

	keyBlock, _ := pem.Decode(keyPEM)
	Expect(keyBlock).NotTo(BeNil())
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	Expect(err).NotTo(HaveOccurred())

	now := time.Now()
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}, decodeCert(crtPEM), key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
}
