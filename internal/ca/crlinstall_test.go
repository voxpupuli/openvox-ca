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
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	xocsp "golang.org/x/crypto/ocsp"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// These cover the sibling defect raised on issue #183: per-process OCSP state
// that is rebuilt from authoritative state on some paths and not others. #182
// made SyncCRLCache evict the responses a newly loaded CRL contradicts, but the
// other two paths that install a CRL did not, and whichever path installs a
// given CRL first is the one that decides. Losing that race left a pre-signed
// `good` for a revoked certificate until it expired — the one direction in
// which this responder can be affirmatively wrong.
var _ = Describe("OCSP cache invalidation on every CRL install", func() {
	var (
		tmpDir  string
		signer  *ca.CA
		replica *ca.CA
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "openvox-ca-crlinstall-test")
		Expect(err).NotTo(HaveOccurred())
		signer = setupOCSPCA(tmpDir)
		replica = attachReplica(tmpDir)
	})

	AfterEach(func() {
		os.RemoveAll(tmpDir)
	})

	// primeGood signs a certificate on the signer, makes the replica recognise
	// it, and gets the replica to pre-sign and cache a `good` for it — the state
	// every spec here starts from.
	primeGood := func(subject string) *x509.Certificate {
		GinkgoHelper()
		cert := signedCert(signer, subject)
		_, err := replica.SyncSerialIndex(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Good))
		return cert
	}

	It("evicts when the replica re-signs the CRL rather than syncing it", func() {
		cert := primeGood("resigned.example.com")
		Expect(signer.Revoke(context.Background(), "resigned.example.com")).To(Succeed())

		// A refreshBefore longer than the CRL's whole validity forces the
		// re-sign branch, which installs a CRL carrying the peer's revocation
		// without SyncCRLCache ever running. This is the race in the field: the
		// refresher and the sync job both poll, and either can get there first.
		reissued, err := replica.RefreshCRLIfDue(context.Background(), 100*365*24*time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(reissued).To(BeTrue(), "precondition: this must take the re-sign branch")

		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Revoked),
			"a re-sign that adopts a peer's revocation must drop the good it contradicts")
	})

	It("evicts when the replica adopts a CRL a peer re-signed", func() {
		cert := primeGood("adopted.example.com")
		Expect(signer.Revoke(context.Background(), "adopted.example.com")).To(Succeed())

		// refreshBefore of zero means nothing is ever due, so this takes the
		// adopt branch: the stored CRL is newer, and the replica installs it
		// without re-signing.
		reissued, err := replica.RefreshCRLIfDue(context.Background(), 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(reissued).To(BeFalse(), "precondition: this must take the adopt branch")

		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Revoked),
			"adopting a peer's CRL must drop the good it contradicts")
	})

	It("evicts when the replica reissues the CRL on demand", func() {
		cert := primeGood("reissued.example.com")
		Expect(signer.Revoke(context.Background(), "reissued.example.com")).To(Succeed())

		Expect(replica.ReissueCRL(context.Background())).To(Succeed())

		Expect(ocspStatusFor(replica, cert)).To(Equal(xocsp.Revoked),
			"an operator-driven reissue must not leave the responder vouching for a revoked cert")
	})
})
