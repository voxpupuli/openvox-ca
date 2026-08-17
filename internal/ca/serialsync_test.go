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
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// ocspStatusFor asks c's responder about cert and returns the parsed status.
// Every spec below is ultimately about one of three answers, so the plumbing
// between them is factored out rather than repeated.
func ocspStatusFor(c *ca.CA, cert *x509.Certificate) int {
	GinkgoHelper()
	reqDER, err := testutil.BuildOCSPRequest(cert, c.CACert)
	Expect(err).NotTo(HaveOccurred())
	respDER, err := c.OCSPResponse(context.Background(), reqDER)
	Expect(err).NotTo(HaveOccurred())
	resp, err := xocsp.ParseResponse(respDER, c.CACert)
	Expect(err).NotTo(HaveOccurred())
	return resp.Status
}

// The specs below model the same HA deployment SyncCRLCache's do: two CA
// instances over one storage directory, standing in for two replicas sharing a
// Postgres, MySQL, etcd or Redis backend. The only property being exercised is
// that both see one inventory.
var _ = Describe("SyncSerialIndex", func() {
	var (
		tmpDir  string
		signer  *ca.CA // the replica that issues
		replica *ca.CA // the replica that must learn about what it issued
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-serialsync-test")
		Expect(err).NotTo(HaveOccurred())
		signer = setupOCSPCA(tmpDir)
		// Attached before anything is signed, so its index is built from an
		// inventory that does not yet hold the serials below — which is exactly
		// the state a long-running replica is in.
		replica = attachReplica(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	// The bug, stated as a proposition. Without the sync the second assertion
	// fails: the certificate is valid, the replica would happily serve it over
	// every other endpoint, and its responder calls it unknown for ever.
	It("stops the responder calling a peer's certificate unknown", func() {
		cert := signedCert(signer, "peer-signed.example.com")

		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Unknown),
			"precondition: the replica has not yet read the inventory row for this serial")

		delta, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(delta.Added).To(BeNumerically(">=", 1))

		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Good),
			"after the sync the replica must recognise a serial its peer issued")
	})

	// The half of the impact that is about revocation rather than recognition.
	// An index miss short-circuits before the CRL is consulted, so a peer's
	// responder could not say `revoked` about a certificate signed elsewhere
	// even when its own CRL listed it. Both syncs are needed and they are
	// independent: the CRL one supplies the revocation, this one supplies the
	// permission to look.
	It("lets the responder say revoked about a peer's certificate", func() {
		cert := signedCert(signer, "peer-revoked.example.com")
		Expect(signer.Revoke(context.Background(), "peer-revoked.example.com")).To(Succeed())

		_, err := replica.SyncCRLCache(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Unknown),
			"precondition: a current CRL alone cannot lift an index miss")

		_, err = replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Revoked))
	})

	// The reason OCSPResponse does not cache an unknown. Were it cached, the
	// query in the precondition would pin that answer for OCSPValidity — four
	// hours — and the sync below would have no observable effect until it
	// expired, which is the "only a restart clears it" symptom the issue
	// describes surviving the fix.
	It("takes effect on the next request, not four hours later", func() {
		cert := signedCert(signer, "not-pinned.example.com")

		// Ask twice: one query is enough to populate a cache, and a second
		// proves the first was not simply overwritten.
		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Unknown))
		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Unknown))

		_, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())

		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Good),
			"an unknown must not be cached, or the index refresh is invisible until it expires")
	})

	It("is idempotent: a second pass over an unchanged inventory changes nothing", func() {
		signedCert(signer, "idempotent.example.com")

		first, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Changed()).To(BeTrue())

		second, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(second.Changed()).To(BeFalse())
		Expect(second.Total).To(Equal(first.Total))
	})

	It("drops serials a peer's cleanup has pruned, and their cached responses", func() {
		cert := signedCert(signer, "pruned.example.com")
		_, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())

		// Prime the replica's response cache while the serial is still known,
		// so the removal has something to invalidate.
		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Good))

		// Prune the row straight from storage rather than through
		// CleanupExpiredCerts, which would need a certificate old enough to be
		// eligible and a CA cert old enough to have signed it. Storage is all a
		// peer's cleanup leaves behind for this replica to observe, and a
		// missing inventory row is exactly what it leaves.
		dropped, err := signer.Storage.PruneInventory(context.Background(),
			func(e storage.InventoryEntry) bool { return e.Subject != "pruned.example.com" })
		Expect(err).NotTo(HaveOccurred())
		Expect(dropped).To(HaveLen(1))

		delta, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(delta.Removed).To(BeNumerically(">=", 1))

		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Unknown),
			"a cached good must not outlive the index entry it was derived from")
	})

	// The read happens outside c.mu so it cannot block the auth path, which means
	// a pass and an issuance genuinely do run concurrently. This is the
	// concurrency-safety half of that — no torn map, no lost update once the
	// passes have settled, and under -race no unsynchronised access.
	//
	// It is deliberately NOT the epoch guard's spec, though it looks like one.
	// The interleaving that guard exists for is corrected by the following pass,
	// so this assertion holds with the guard removed; serialindexepoch_test.go
	// states the guard directly instead, and says why there.
	It("keeps its index consistent while passes and issuances overlap", func() {
		const signings = 25

		ctx, stop := context.WithCancel(context.Background())
		var syncs sync.WaitGroup
		syncs.Add(1)
		go func() {
			defer syncs.Done()
			for ctx.Err() == nil {
				_, _ = replica.SyncSerialIndex(context.Background())
			}
		}()

		certs := make([]*x509.Certificate, 0, signings)
		for i := range signings {
			certs = append(certs, signedCert(replica, fmt.Sprintf("racer-%02d.example.com", i)))
		}

		stop()
		syncs.Wait()

		// One settling pass, for the same reason the job runs on a timer: the
		// assertion is that the index converges, not that it is never mid-flight.
		_, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())

		for i, cert := range certs {
			Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Good),
				"racer-%02d must be in the index once the passes have settled", i)
		}
	})

	It("counts an unreadable inventory rather than emptying the index", func() {
		signedCert(signer, "counted.example.com")
		_, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())
		before := replica.SerialIndexSize()
		Expect(before).To(BeNumerically(">=", 1))

		Expect(os.Remove(replica.Storage.InventoryPath())).To(Succeed())

		_, err = replica.SyncSerialIndex(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(replica.SerialIndexSyncFailures()).To(BeNumerically(">=", 1))
		Expect(replica.SerialIndexSize()).To(Equal(before),
			"a failed read must leave the index it could not verify alone")
	})
})
