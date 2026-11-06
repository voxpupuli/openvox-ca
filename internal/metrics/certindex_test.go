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

package metrics_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/metrics"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// The leaf families, which on a backend with a certificate index the collector
// reads from the index rather than from each stored certificate (#435).
var leafFamilies = []string{
	"openvoxca_leaf_certificate_info",
	"openvoxca_leaf_certificate_not_before_timestamp_seconds",
	"openvoxca_leaf_certificate_not_after_timestamp_seconds",
	"openvoxca_leaf_certificates",
}

var _ = Describe("Collector over a certificate index", func() {
	var (
		ctx     context.Context
		dir     string
		counter *certReadCounter
		myCA    *ca.CA
	)

	BeforeEach(func() {
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		be, err := storage.NewSQLBackend(storage.SQLConfig{
			Dialect: storage.SQLitePure,
			DSN:     "file:" + filepath.Join(dir, "ca.db"),
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(be.Close)
		Expect(be.EnsureReady(ctx)).To(Succeed())

		counter = &certReadCounter{Backend: be}
		myCA = ca.New(storage.NewWithBackend(counter, dir), ca.AutosignConfig{Mode: "off"}, "puppet.test")
		Expect(myCA.Init(ctx)).To(Succeed())
		_, indexed, err := myCA.Storage.CertStatuses(ctx, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(indexed).To(BeTrue(), "precondition: the store must offer the certificate index")
	})

	signCert := func(subject string) {
		GinkgoHelper()
		csrPEM, err := testutil.GenerateCSR(subject)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, subject, csrPEM)
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.Sign(ctx, subject)
		Expect(err).NotTo(HaveOccurred())
	}

	// storeMinted signs a certificate with the CA key and stores it without
	// going through issuance, so a spec can choose what, if anything, the index
	// says about it.
	storeMinted := func(subject string, serial int64) *x509.Certificate {
		GinkgoHelper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		notBefore := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: subject},
			NotBefore:    notBefore,
			NotAfter:     notBefore.Add(90 * 24 * time.Hour),
		}, myCA.CACert, &key.PublicKey, myCA.CAKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(myCA.Storage.SaveCert(ctx, subject,
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))).To(Succeed())
		cert, err := x509.ParseCertificate(der)
		Expect(err).NotTo(HaveOccurred())
		return cert
	}

	// scanGather gathers through a store that hides the index, which is the
	// path every backend without one takes: one read per stored certificate.
	scanGather := func() gathered {
		GinkgoHelper()
		indexed := myCA.Storage
		DeferCleanup(func() { myCA.Storage = indexed })
		myCA.Storage = storage.NewWithBackend(&indexHidingBackend{Backend: counter}, dir)
		return gather(metrics.NewCollector(myCA))
	}

	It("reads no stored certificate, and reports what reading every one would", func() {
		signCert("signed-node")
		signCert("revoked-node")
		Expect(myCA.Revoke(ctx, "revoked-node")).To(Succeed())
		signCert("second-signed-node")
		// The index path takes the subject set from Statuses, which joins its
		// rows against stored certificates; the scan path takes it from the
		// listing. A cleaned certificate keeps its row, so this is what shows
		// the two agree on leaving it out.
		signCert("cleaned-node")
		Expect(myCA.Clean(ctx, "cleaned-node")).To(Succeed())
		csrPEM, err := testutil.GenerateCSR("pending-node")
		Expect(err).NotTo(HaveOccurred())
		_, err = myCA.SaveRequest(ctx, "pending-node", csrPEM)
		Expect(err).NotTo(HaveOccurred())

		// A row in OpenVox Server's spelling, as a migrated inventory carries
		// one: prefixed and zero-padded. Its label must still be the one a
		// parsed certificate gets.
		legacy := storeMinted("legacy-node", 0xA1B)
		Expect(myCA.Storage.AppendInventory(ctx, storage.FormatInventoryLine(
			"0x0A1B", legacy.NotBefore, legacy.NotAfter, "legacy-node"))).To(Succeed())

		counter.reads.Store(0)
		viaIndex := gather(metrics.NewCollector(myCA))
		Expect(counter.reads.Load()).To(BeZero(), "the index must answer for every certificate it has a row for")

		viaScan := scanGather()
		Expect(counter.reads.Load()).To(Equal(int64(4)),
			"precondition: the comparison is against the path that reads each of the four certificates")

		for _, name := range leafFamilies {
			Expect(seriesOf(viaIndex, name)).To(Equal(seriesOf(viaScan, name)),
				"%s must not depend on which path produced it", name)
		}
		Expect(viaIndex.findByLabels("openvoxca_leaf_certificate_info",
			map[string]string{"subject": "legacy-node", "serial": "A1B", "state": "signed"})).NotTo(BeNil())
		Expect(viaIndex.findByLabels("openvoxca_leaf_certificate_info",
			map[string]string{"subject": "revoked-node", "state": "revoked"})).NotTo(BeNil())
		Expect(viaIndex.findByLabels("openvoxca_leaf_certificate_info",
			map[string]string{"subject": "pending-node", "state": "requested"})).NotTo(BeNil())
		Expect(viaIndex.findByLabels("openvoxca_leaf_certificate_info",
			map[string]string{"subject": "cleaned-node"})).To(BeNil(), "a cleaned certificate is not live")
	})

	// The window between storing a certificate and writing its row. The
	// certificate is live, so leaving it out would hide its expiry.
	It("reads the stored certificate for a subject the index has no row for", func() {
		signCert("indexed-node")
		rowless := storeMinted("rowless-node", 0xB00)

		counter.reads.Store(0)
		g := gather(metrics.NewCollector(myCA))
		Expect(counter.reads.Load()).To(Equal(int64(1)))
		notAfter := g.findByLabels("openvoxca_leaf_certificate_not_after_timestamp_seconds",
			map[string]string{"subject": "rowless-node", "serial": "B00", "state": "signed"})
		Expect(notAfter).NotTo(BeNil())
		Expect(gaugeValue(notAfter)).To(Equal(float64(rowless.NotAfter.Unix())))
	})

	// One entry per way leafFromRecord can refuse a row. A row that parses in
	// part must not publish the part it has: a NotAfter read as the zero time
	// would page every expiry alert for a healthy certificate.
	DescribeTable("reads the stored certificate when its index row does not parse",
		func(row func(nb, na string) string) {
			cert := storeMinted("unparsed-node", 0xC00)
			nb := cert.NotBefore.UTC().Format(storage.InventoryTimeFormat)
			na := cert.NotAfter.UTC().Format(storage.InventoryTimeFormat)
			Expect(myCA.Storage.AppendInventory(ctx, row(nb, na))).To(Succeed())

			// Without this the spec cannot tell a row that does not parse from no
			// row at all, which the spec above already covers.
			records, _, err := myCA.Storage.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(ContainElement(HaveField("InventoryEntry.Subject", "unparsed-node")),
				"precondition: the index must return the row")

			counter.reads.Store(0)
			g := gather(metrics.NewCollector(myCA))
			Expect(counter.reads.Load()).To(Equal(int64(1)))
			notAfter := g.findByLabels("openvoxca_leaf_certificate_not_after_timestamp_seconds",
				map[string]string{"subject": "unparsed-node", "serial": "C00"})
			Expect(notAfter).NotTo(BeNil(), "a row that will not parse must not cost the certificate its series")
			Expect(gaugeValue(notAfter)).To(Equal(float64(cert.NotAfter.Unix())))
		},
		Entry("a serial that is not hexadecimal", func(nb, na string) string {
			return "zz " + nb + " " + na + " /unparsed-node"
		}),
		Entry("a NotBefore that does not parse", func(_, na string) string {
			return "C00 not-a-time " + na + " /unparsed-node"
		}),
		Entry("a NotAfter that does not parse", func(nb, _ string) string {
			return "C00 " + nb + " not-a-time /unparsed-node"
		}),
	)

	// One line per gather, carrying the count, whatever the number of rows:
	// each such row costs the round trip the index exists to save, and a line
	// per row per scrape would bury the one thing worth reading.
	It("warns once per gather, with a count, when index rows do not parse", func() {
		for i, subject := range []string{"unparsed-a", "unparsed-b"} {
			cert := storeMinted(subject, int64(0xD00+i))
			Expect(myCA.Storage.AppendInventory(ctx, fmt.Sprintf("%X not-a-time not-a-time /%s",
				cert.SerialNumber, subject))).To(Succeed())
		}

		// Captured from here, after the fixture, so nothing the setup logged can
		// satisfy the assertion.
		var logged bytes.Buffer
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
		DeferCleanup(func() { slog.SetDefault(orig) })

		gather(metrics.NewCollector(myCA))
		Expect(strings.Count(logged.String(), "index rows do not parse")).To(Equal(1), "log = %q", logged.String())
		Expect(logged.String()).To(ContainSubstring("level=WARN"))
		Expect(logged.String()).To(ContainSubstring("rows=2"))
	})

	// Failing the gather, rather than falling back to reading every
	// certificate, is the choice: the fallback is the cost #435 removed, and on
	// a large fleet it would overrun the budget anyway, only later and having
	// spent the round trips. A failed gather is held and alerted on.
	It("fails the gather, reading no certificate, when the index cannot be read", func() {
		signCert("index-node")
		indexed := myCA.Storage
		DeferCleanup(func() { myCA.Storage = indexed })
		idx, ok := counter.Backend.(storage.CertIndex)
		Expect(ok).To(BeTrue(), "precondition: the backend offers the certificate index")
		myCA.Storage = storage.NewWithBackend(&failingStatusesBackend{Backend: counter, CertIndex: idx}, dir)

		counter.reads.Store(0)
		g := gather(metrics.NewCollector(myCA))
		Expect(gaugeValue(g.findUnlabelled("openvoxca_collector_scrape_success"))).To(Equal(0.0))
		Expect(counter.reads.Load()).To(BeZero(), "an unreadable index must not fall back to the per-certificate scan")
	})

	// A migrated row spells its serial as OpenVox Server wrote it. The CRL is
	// keyed by the canonical form, so the lookup must use the normalised serial:
	// the raw one would miss, and a revoked certificate would read as signed and
	// page for an expiry nobody needs to act on. Every other revoked row in these
	// specs is written by Sign in the canonical form already, so none of them
	// can tell the two apart.
	It("finds a migrated row's revocation in the CRL", func() {
		cert := storeMinted("migrated-node", 0xB0B)
		Expect(myCA.Storage.AppendInventory(ctx, storage.FormatInventoryLine(
			"0x0B0B", cert.NotBefore, cert.NotAfter, "migrated-node"))).To(Succeed())
		// By serial, and forced because it is the certificate in circulation:
		// revoking by subject refuses a row spelt this way, which is a gap of
		// its own and not this spec's subject.
		Expect(myCA.RevokeSerial(ctx, "B0B", true)).To(Succeed())
		Expect(myCA.RevokedSerials()).To(HaveKey("B0B"), "precondition: the CRL must list the serial")

		counter.reads.Store(0)
		g := gather(metrics.NewCollector(myCA))
		Expect(counter.reads.Load()).To(BeZero(), "precondition: the index path must be the one under test")
		Expect(g.findByLabels("openvoxca_leaf_certificate_info",
			map[string]string{"subject": "migrated-node", "serial": "B0B", "state": "revoked"})).NotTo(BeNil())
	})

	// The row's state is a projection, written best-effort beside the CRL and
	// reconciled only at startup, so it can say either thing wrongly. The
	// expiry alerts exclude state="revoked": a revoked certificate shown as
	// signed pages for an expiry nobody needs to act on, and a live one shown
	// as revoked never pages at all.
	DescribeTable("takes revocation state from the CRL, not from the row",
		func(revoke bool, want string) {
			signCert("state-node")
			serial := leafSerial(gather(metrics.NewCollector(myCA)), "state-node")
			rowState := storage.CertStateRevoked
			if revoke {
				Expect(myCA.Revoke(ctx, "state-node")).To(Succeed())
				Expect(myCA.Storage.ClearCertRevoked(ctx, serial)).To(Succeed())
				rowState = storage.CertStateSigned
			} else {
				Expect(myCA.Storage.MarkCertRevoked(ctx, serial, time.Now())).To(Succeed())
			}
			// Both writes are silent no-ops for a serial no row bears, which would
			// leave the row agreeing with the CRL and the spec passing whichever
			// the collector read.
			records, _, err := myCA.Storage.CertStatuses(ctx, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(records).To(ContainElement(And(
				HaveField("InventoryEntry.Subject", "state-node"),
				HaveField("State", rowState))),
				"precondition: the row must disagree with the CRL")

			g := gather(metrics.NewCollector(myCA))
			Expect(g.findByLabels("openvoxca_leaf_certificate_info",
				map[string]string{"subject": "state-node", "state": want})).NotTo(BeNil())
		},
		Entry("revoked in the CRL, signed in the row", true, "revoked"),
		Entry("signed in the CRL, revoked in the row", false, "signed"),
	)
})

// leafSerial reads a subject's serial label off a gather.
func leafSerial(g gathered, subject string) string {
	GinkgoHelper()
	for _, m := range g["openvoxca_leaf_certificate_info"].GetMetric() {
		if labels := labelsOf(m); labels["subject"] == subject {
			return labels["serial"]
		}
	}
	Fail(fmt.Sprintf("no leaf series for %q", subject))
	return ""
}

// certReadCounter counts reads of stored certificates. It unwraps to the
// backend it wraps, so the certificate index and the structured inventory
// behind it stay visible to the storage service.
type certReadCounter struct {
	storage.Backend
	reads atomic.Int64
}

func (b *certReadCounter) Get(ctx context.Context, key string) ([]byte, error) {
	if strings.HasPrefix(key, storage.CertKey("")) {
		b.reads.Add(1)
	}
	return b.Backend.Get(ctx, key)
}

func (b *certReadCounter) Unwrap() storage.Backend { return b.Backend }

// failingStatusesBackend offers a certificate index whose listing fails.
type failingStatusesBackend struct {
	storage.Backend
	storage.CertIndex
}

func (b *failingStatusesBackend) Statuses(context.Context, string) ([]storage.CertRecord, error) {
	return nil, errors.New("simulated certificate index failure")
}

// indexHidingBackend has no Unwrap, so the storage service sees no certificate
// index behind it and takes the path a backend without one takes.
type indexHidingBackend struct {
	storage.Backend
}
