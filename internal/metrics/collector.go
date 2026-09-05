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

// Package metrics exposes a Prometheus exporter for the Puppet CA. In addition
// to the standard Go runtime / process collectors and HTTP request metrics
// (wired up in metrics.go), it provides a custom collector that, on every
// scrape, reports the state of the CA certificate, its CRL, and every known
// (non-deleted) leaf certificate — including issue/expiry timestamps and
// issuance status — so operators can alert on impending expiry and pending
// requests.
package metrics

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// namespace is the common Prometheus metric prefix for every CA-specific
// series. It is deliberately distinct from the Go/process collectors so that
// puppetca_* groups the exporter's domain metrics together.
const namespace = "puppetca"

// Leaf certificate issuance states reported via the `state` label. "expired" is
// intentionally not a state: expiry is derived by alerting rules from the
// not_after timestamp metric, which keeps a single source of truth and lets the
// same certificate be both signed/revoked and expired.
const (
	stateRequested = "requested" // a pending CSR with no issued certificate yet
	stateSigned    = "signed"    // an issued certificate not present in the CRL
	stateRevoked   = "revoked"   // an issued certificate listed in the CRL
)

// defaultGatherTimeout bounds a single scrape's storage access. prometheus
// Collect has no context of its own, so the collector imposes its own deadline
// to avoid a slow/unavailable backend wedging the scrape indefinitely.
const defaultGatherTimeout = 10 * time.Second

// Collector implements prometheus.Collector, translating the CA's live state
// into metrics on each scrape. It reads through the CA's StorageService, so it
// observes whichever backend (filesystem, etcd, redis, SQL) the CA is using.
type Collector struct {
	ca      *ca.CA
	timeout time.Duration

	// Descriptors, built once in NewCollector and reused on every scrape.
	scrapeSuccess  *prometheus.Desc
	scrapeDuration *prometheus.Desc
	caReady        *prometheus.Desc

	crlUpdateFailures *prometheus.Desc
	crlSyncFailures   *prometheus.Desc
	crlCachedNumber   *prometheus.Desc

	ocspIndexSyncFailures *prometheus.Desc
	ocspIndexSerials      *prometheus.Desc
	supersedeFailures     *prometheus.Desc
	supersedePending      *prometheus.Desc

	signingInFlight *prometheus.Desc
	signingLimit    *prometheus.Desc
	signingShed     *prometheus.Desc

	caInfo      *prometheus.Desc
	caNotBefore *prometheus.Desc
	caNotAfter  *prometheus.Desc

	crlNumber     *prometheus.Desc
	crlThisUpdate *prometheus.Desc
	crlNextUpdate *prometheus.Desc

	crlChainNextUpdate      *prometheus.Desc
	crlChainLastRead        *prometheus.Desc
	crlChainRefreshFailures *prometheus.Desc
	crlChainDiscarded       *prometheus.Desc
	crlChainRegressed       *prometheus.Desc
	crlChainRemoved         *prometheus.Desc
	crlRevoked              *prometheus.Desc

	leafInfo       *prometheus.Desc
	leafNotBefore  *prometheus.Desc
	leafNotAfter   *prometheus.Desc
	leafStateCount *prometheus.Desc
}

// NewCollector returns a Collector for the given CA. The CA need not be fully
// initialised yet: until it is, the exporter reports puppetca_ca_ready 0 and
// omits the CA/CRL/leaf series rather than failing the scrape.
func NewCollector(c *ca.CA) *Collector {
	return &Collector{
		ca:      c,
		timeout: defaultGatherTimeout,
		scrapeSuccess: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "collector", "scrape_success"),
			"1 if the most recent CA metrics scrape succeeded, 0 otherwise.",
			nil, nil),
		scrapeDuration: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "collector", "scrape_duration_seconds"),
			"Time taken to gather the CA, CRL and leaf certificate metrics.",
			nil, nil),
		caReady: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "ca_ready"),
			"1 when the CA has finished initialising and can serve requests, 0 otherwise.",
			nil, nil),
		crlUpdateFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "update_failures_total"),
			"Total failures to amend the CRL — a CRL that could not be re-signed, written or read, "+
				"on any of the revoke, reissue, refresh and expired-cert cleanup paths, plus, on the "+
				"revoke path only, a malformed serial or a failed inventory read while resolving the "+
				"subject's serial. Not every revocation that missed the CRL lands here: one refused "+
				"at a cross-node lock acquisition, or at a same-host one on filesystem and SQLite, "+
				"fails ahead of any CRL work and is logged only, so this is a lower bound, while on "+
				"filesystem and SQLite a revocation that queued past lockTimeout behind another "+
				"goroutine in this process fails at that inventory read and is counted. A rising value means the "+
				"CRL is not being maintained; for revocations it means a superseded certificate may "+
				"still be a valid credential.",
			nil, nil),
		crlSyncFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "sync_failures_total"),
			"Total failures to reload the stored CRL into the copy this replica's revocation checks "+
				"read — an unreadable or unparseable CRL, or one this CA did not sign. While it is "+
				"rising, a certificate revoked on another replica may still be accepted here.",
			nil, nil),
		ocspIndexSyncFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ocsp_index", "sync_failures_total"),
			"Total failures to reload the inventory into the serial index this replica's OCSP "+
				"responder answers from — an unreadable inventory, or one whose integrity MAC no "+
				"longer verifies. While it is rising, this replica answers 'unknown' for "+
				"certificates signed elsewhere since the last successful pass.",
			nil, nil),
		signingInFlight: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_signing", "in_flight"),
			"CA-key signatures in flight right now, across certificate issuance, CRL re-signing and "+
				"the OCSP responder together — they share one bound because they share one key. "+
				"Read it against puppetca_ca_signing_limit: what matters is the headroom, not the "+
				"absolute number. Always 0 when signing is unbounded.",
			nil, nil),
		signingLimit: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_signing", "limit"),
			"Configured ceiling on concurrent CA-key signatures (ca_signing_concurrency). 0 means "+
				"unbounded, in which case an unauthenticated caller can drive as many concurrent "+
				"signatures against the CA key as it can open connections.",
			nil, nil),
		signingShed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_signing", "shed_total"),
			"Total OCSP responses refused with RFC 6960 tryLater because the CA-key signing bound "+
				"was full. Only the OCSP responder sheds; issuance and CRL re-signing queue for a "+
				"slot instead and never appear here. A rising value is the bound working rather than "+
				"a fault, but it means verifiers are being turned away, so it asks whether the limit "+
				"matches this deployment's signer — sustained shedding on a signer with capacity to "+
				"spare means the limit is too low, while shedding under an unauthenticated flood is "+
				"the protection this metric exists to make visible.",
			nil, nil),
		ocspIndexSerials: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ocsp_index", "serials"),
			"Number of certificate serials this replica's OCSP responder recognises. Every replica "+
				"sharing a backend should converge on the same value within one sync interval; a "+
				"replica persistently below the others is reporting valid certificates as unknown.",
			nil, nil),
		supersedeFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "supersede", "failures_total"),
			"Total failures to schedule or carry out the revocation of a certificate a renewal "+
				"replaced: a supersession the renewal path could not record, a pending-revocation "+
				"list that could not be read or parsed, a sweep pass that could not take the CRL "+
				"lock or write the list back, and each pass that left an entry unrevoked or "+
				"discarded one whose serial it could never revoke. One pass counts "+
				"once however many entries it failed on. Only where "+
				"superseded_cert_revoke_after_sec is 0 is nothing recorded — the revocation then "+
				"happens inside the renewal, and a failure there lands in "+
				"puppetca_crl_update_failures_total instead — so this stays flat there, with one "+
				"exception: the sweep, every renewal and every subject revocation read the pending "+
				"list whatever the setting says, and a store that cannot serve that key raises "+
				"this even with the window closed. A rising value means a certificate a renewal "+
				"replaced may still be a valid credential.",
			nil, nil),
		supersedePending: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "supersede", "pending"),
			"Certificates a renewal has replaced that are still inside their overlap window and "+
				"not yet revoked. Each one is a credential this CA still accepts even though "+
				"something newer has taken its place, so this is the live measure of the exposure "+
				"superseded_cert_revoke_after_sec buys. It returns to zero as the sweep drains "+
				"the list; a value that does not fall means the sweep is not completing — check "+
				"puppetca_supersede_failures_total, which a failing pass raises once however many "+
				"entries were due, and the log for 'Could not revoke superseded certificates'. "+
				"Absent, "+
				"rather than zero, when the list could not be read: zero is what a drained list "+
				"reports, so it must not also be what an unreadable one reports.",
			nil, nil),
		crlCachedNumber: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "cached_number"),
			"CRL sequence number of the copy this replica is answering revocation checks from. "+
				"Lags puppetca_crl_number by at most one sync interval; a persistent gap means this "+
				"replica is enforcing an out-of-date revocation list.",
			nil, nil),
		caInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_certificate", "info"),
			"Static information about the CA certificate; constant value 1.",
			[]string{"common_name", "serial", "issuer"}, nil),
		caNotBefore: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_certificate", "not_before_timestamp_seconds"),
			"NotBefore (issue) time of the CA certificate, in seconds since the Unix epoch.",
			nil, nil),
		caNotAfter: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "ca_certificate", "not_after_timestamp_seconds"),
			"NotAfter (expiry) time of the CA certificate, in seconds since the Unix epoch.",
			nil, nil),
		crlNumber: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "number"),
			"Monotonically increasing CRL sequence number (X.509 cRLNumber extension).",
			nil, nil),
		crlThisUpdate: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "this_update_timestamp_seconds"),
			"ThisUpdate time of the current CRL, in seconds since the Unix epoch.",
			nil, nil),
		crlNextUpdate: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "next_update_timestamp_seconds"),
			"NextUpdate (expiry) time of the current CRL, in seconds since the Unix epoch.",
			nil, nil),
		crlChainNextUpdate: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl_chain", "next_update_timestamp_seconds"),
			"NextUpdate (expiry) time of each upstream CRL published alongside this CA's own, "+
				"labelled by issuer, in seconds since the Unix epoch. Deliberately a separate series "+
				"from puppetca_crl_next_update_timestamp_seconds: an expiring upstream CRL is fixed at "+
				"the parent CA, not here, so it needs its own alert and its own runbook.",
			[]string{"issuer"}, nil),
		crlChainLastRead: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl_chain", "last_read_timestamp_seconds"),
			"When crl_chain_file was last read successfully, or 0 if it never has been. "+
				"Exported only where crl_chain_file is configured, so absent means the "+
				"feature is off and 0 means it is on but the file has never been opened -- "+
				"a wrong path, or a mount that never landed. It does NOT detect a subPath "+
				"mount: that reads successfully forever, so this advances exactly as it "+
				"does on a healthy file.",
			nil, nil,
		),
		crlChainRefreshFailures: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl_chain", "refresh_failures_total"),
			"Total failed reads of crl_chain_file -- unreadable, unparseable, not ending on a PEM "+
				"block boundary, or too large. Counted where the file is read, so it moves on every "+
				"CRL amendment as well as on each refresh pass, and revocation is blocked until "+
				"the file is fixed. The published chain is left alone and the next attempt retries. "+
				"A refresh pass that fails for some other reason -- a lock it could not take, "+
				"storage it could not read -- moves puppetca_crl_update_failures_total instead, so "+
				"a rise here always means the file.",
			nil, nil),
		crlChainDiscarded: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl_chain", "discarded_total"),
			"Total CRLs dropped from crl_chain_file because no certificate in the CA bundle signed "+
				"them. The file is authoritative, so a discard means the published chain is smaller "+
				"than the operator's file says it should be — the one case where it shrinks silently. "+
				"The remedy is to complete the CA bundle. A CRL passed over for being stale is "+
				"counted separately, by puppetca_crl_chain_regressed_total, because that one is "+
				"fixed at whatever writes the file instead.",
			nil, nil),
		crlChainRemoved: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl_chain", "removed_total"),
			"Total ancestors whose published CRL has been dropped from the chain, either "+
				"because crl_chain_file stopped listing them or because their certificate has "+
				"left the stored CA bundle, so nothing signs that CRL any more. The removal is "+
				"honoured -- the file is authoritative -- but it cannot be undone here, because "+
				"this CA cannot re-sign another CA's list. A deliberate removal increments this "+
				"on the pass that applies it; a `cat` glob that matched one file fewer "+
				"increments it the same way, which is why it is worth an alert. The log line "+
				"names which cause fired, and the remedies differ: fix whatever writes the file, "+
				"or re-import the CA bundle. An incomplete bundle moves this counter and "+
				"puppetca_crl_chain_discarded_total together -- the latter counts CRLs the file does carry "+
				"but nothing in the bundle signed.",
			nil, nil),
		crlChainRegressed: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl_chain", "regressed_total"),
			"Total CRLs in crl_chain_file passed over because the published chain already carried "+
				"a newer one from the same ancestor. The published CRL is kept, so revocation is "+
				"unaffected; a rising value means the file is stale, rolled back or replayed. Check "+
				"whatever refreshes it, not the CA bundle.",
			nil, nil),
		crlRevoked: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "crl", "revoked_certificates"),
			"Number of certificates currently listed in the CRL.",
			nil, nil),
		leafInfo: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "leaf_certificate", "info"),
			"One series per known (non-deleted) leaf certificate or pending request; constant value 1. "+
				"For pending requests the serial label is empty.",
			[]string{"subject", "serial", "state"}, nil),
		leafNotBefore: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "leaf_certificate", "not_before_timestamp_seconds"),
			"NotBefore (issue) time of a leaf certificate, in seconds since the Unix epoch. "+
				"Not emitted for pending requests, which have no issued certificate.",
			[]string{"subject", "serial", "state"}, nil),
		leafNotAfter: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "leaf_certificate", "not_after_timestamp_seconds"),
			"NotAfter (expiry) time of a leaf certificate, in seconds since the Unix epoch. "+
				"Not emitted for pending requests, which have no issued certificate.",
			[]string{"subject", "serial", "state"}, nil),
		leafStateCount: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "leaf_certificates"),
			"Number of known (non-deleted) leaf certificates by issuance state.",
			[]string{"state"}, nil),
	}
}

// Describe implements prometheus.Collector. The exporter uses an unchecked
// collector model (it emits dynamic, per-certificate label sets each scrape),
// but advertising the descriptors still lets the registry detect duplicate
// metric names at registration time.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.scrapeSuccess
	ch <- c.scrapeDuration
	ch <- c.caReady
	ch <- c.crlUpdateFailures
	ch <- c.crlSyncFailures
	ch <- c.supersedeFailures
	ch <- c.supersedePending
	ch <- c.crlCachedNumber
	ch <- c.ocspIndexSyncFailures
	ch <- c.ocspIndexSerials
	ch <- c.signingInFlight
	ch <- c.signingLimit
	ch <- c.signingShed
	ch <- c.caInfo
	ch <- c.caNotBefore
	ch <- c.caNotAfter
	ch <- c.crlNumber
	ch <- c.crlThisUpdate
	ch <- c.crlNextUpdate
	ch <- c.crlChainNextUpdate
	ch <- c.crlChainLastRead
	ch <- c.crlChainRefreshFailures
	ch <- c.crlChainDiscarded
	ch <- c.crlChainRegressed
	ch <- c.crlChainRemoved
	ch <- c.crlRevoked
	ch <- c.leafInfo
	ch <- c.leafNotBefore
	ch <- c.leafNotAfter
	ch <- c.leafStateCount
}

// Collect implements prometheus.Collector. It gathers a fresh snapshot of CA
// state under its own deadline and emits the corresponding metrics. A gather
// failure is reported via puppetca_collector_scrape_success rather than
// aborting the whole /metrics response, so the Go/process/HTTP metrics still
// scrape even when storage is momentarily unavailable.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	start := time.Now()
	snap, err := c.gather(ctx)
	duration := time.Since(start)

	ch <- prometheus.MustNewConstMetric(c.scrapeDuration, prometheus.GaugeValue, duration.Seconds())

	// These are in-process tallies of the CA's own state, independent of the
	// storage gather, so emit them even when the gather below fails — an
	// unreadable backend must not blind operators to CRL-maintenance failures,
	// nor to a replica enforcing an out-of-date revocation list. The cached CRL
	// number in particular is most worth having when storage reads are the thing
	// going wrong, since that is what makes a replica fall behind.
	ch <- prometheus.MustNewConstMetric(c.crlUpdateFailures, prometheus.CounterValue,
		float64(c.ca.CRLUpdateFailures()))
	ch <- prometheus.MustNewConstMetric(c.crlSyncFailures, prometheus.CounterValue,
		float64(c.ca.CRLSyncFailures()))
	ch <- prometheus.MustNewConstMetric(c.ocspIndexSyncFailures, prometheus.CounterValue,
		float64(c.ca.SerialIndexSyncFailures()))
	ch <- prometheus.MustNewConstMetric(c.ocspIndexSerials, prometheus.GaugeValue,
		float64(c.ca.SerialIndexSize()))
	ch <- prometheus.MustNewConstMetric(c.supersedeFailures, prometheus.CounterValue,
		float64(c.ca.SupersedeFailures()))
	// Emitted alongside the failure counters, and for the same reason: these
	// are in-process state, so an unreadable storage backend must not blind an
	// operator to the responder shedding. The limit is emitted even when it is
	// 0 — "unbounded" is exactly the state worth being able to alert on.
	inFlight, limit := c.ca.SigningInFlight()
	ch <- prometheus.MustNewConstMetric(c.signingInFlight, prometheus.GaugeValue, float64(inFlight))
	ch <- prometheus.MustNewConstMetric(c.signingLimit, prometheus.GaugeValue, float64(limit))
	ch <- prometheus.MustNewConstMetric(c.signingShed, prometheus.CounterValue,
		float64(c.ca.SigningShedTotal()))
	if cached, ok := c.ca.CachedCRLNumber(); ok {
		num, _ := new(big.Float).SetInt(cached).Float64()
		ch <- prometheus.MustNewConstMetric(c.crlCachedNumber, prometheus.GaugeValue, num)
	}
	// Emitted whenever the feature is configured, including before the first
	// read, when it reads 0.
	//
	// Keying on first-read instead was the obvious choice and the wrong one: it
	// made the series absent both on a CA that had never opened its file and on
	// every CA in the fleet with no crl_chain_file at all. Nothing else
	// distinguishes those two -- the counters are unconditional and read 0 in
	// both -- so absent() could not be written into an alert without firing on
	// every instance that never configured the feature, and the case the series
	// was added for stayed unalertable.
	if c.ca.CRLChainFile != "" {
		var stamp float64
		if last := c.ca.CRLChainLastRead(); !last.IsZero() {
			stamp = float64(last.Unix())
		}
		ch <- prometheus.MustNewConstMetric(c.crlChainLastRead, prometheus.GaugeValue, stamp)
	}
	ch <- prometheus.MustNewConstMetric(c.crlChainRefreshFailures, prometheus.CounterValue,
		float64(c.ca.CRLChainFailures()))
	ch <- prometheus.MustNewConstMetric(c.crlChainDiscarded, prometheus.CounterValue,
		float64(c.ca.CRLChainDiscarded()))
	ch <- prometheus.MustNewConstMetric(c.crlChainRegressed, prometheus.CounterValue,
		float64(c.ca.CRLChainRegressed()))
	ch <- prometheus.MustNewConstMetric(c.crlChainRemoved, prometheus.CounterValue,
		float64(c.ca.CRLChainRemoved()))

	if err != nil {
		slog.Warn("Prometheus CA metrics scrape failed", "error", err)
		ch <- prometheus.MustNewConstMetric(c.scrapeSuccess, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.scrapeSuccess, prometheus.GaugeValue, 1)

	ch <- prometheus.MustNewConstMetric(c.caReady, prometheus.GaugeValue, boolToFloat(snap.caReady))

	if snap.haveCA {
		ch <- prometheus.MustNewConstMetric(c.caInfo, prometheus.GaugeValue, 1,
			snap.caCommonName, snap.caSerial, snap.caIssuer)
		ch <- prometheus.MustNewConstMetric(c.caNotBefore, prometheus.GaugeValue, timestamp(snap.caNotBefore))
		ch <- prometheus.MustNewConstMetric(c.caNotAfter, prometheus.GaugeValue, timestamp(snap.caNotAfter))
	}

	if snap.haveCRL {
		ch <- prometheus.MustNewConstMetric(c.crlNumber, prometheus.GaugeValue, snap.crlNumber)
		ch <- prometheus.MustNewConstMetric(c.crlThisUpdate, prometheus.GaugeValue, timestamp(snap.crlThisUpdate))
		ch <- prometheus.MustNewConstMetric(c.crlNextUpdate, prometheus.GaugeValue, timestamp(snap.crlNextUpdate))
		ch <- prometheus.MustNewConstMetric(c.crlRevoked, prometheus.GaugeValue, float64(snap.crlRevokedCount))
	}

	if snap.haveSupersedePending {
		ch <- prometheus.MustNewConstMetric(c.supersedePending, prometheus.GaugeValue,
			float64(snap.supersedePending))
	}

	for _, up := range snap.upstreamCRLs {
		ch <- prometheus.MustNewConstMetric(c.crlChainNextUpdate, prometheus.GaugeValue,
			timestamp(up.NextUpdate), up.Issuer)
	}

	stateCounts := map[string]int{stateRequested: 0, stateSigned: 0, stateRevoked: 0}
	for _, leaf := range snap.leaves {
		stateCounts[leaf.state]++
		ch <- prometheus.MustNewConstMetric(c.leafInfo, prometheus.GaugeValue, 1,
			leaf.subject, leaf.serial, leaf.state)
		if leaf.hasCert {
			ch <- prometheus.MustNewConstMetric(c.leafNotBefore, prometheus.GaugeValue,
				timestamp(leaf.notBefore), leaf.subject, leaf.serial, leaf.state)
			ch <- prometheus.MustNewConstMetric(c.leafNotAfter, prometheus.GaugeValue,
				timestamp(leaf.notAfter), leaf.subject, leaf.serial, leaf.state)
		}
	}
	for state, count := range stateCounts {
		ch <- prometheus.MustNewConstMetric(c.leafStateCount, prometheus.GaugeValue, float64(count), state)
	}
}

// leafCert is one row of the per-certificate snapshot.
type leafCert struct {
	subject   string
	serial    string
	state     string
	notBefore time.Time
	notAfter  time.Time
	hasCert   bool // false for pending requests (no issued certificate)
}

// snapshot is the immutable view of CA state captured by a single scrape.
type snapshot struct {
	caReady bool

	haveCA       bool
	caCommonName string
	caSerial     string
	caIssuer     string
	caNotBefore  time.Time
	caNotAfter   time.Time

	haveCRL         bool
	crlNumber       float64
	crlThisUpdate   time.Time
	crlNextUpdate   time.Time
	crlRevokedCount int

	haveSupersedePending bool
	supersedePending     int

	// upstreamCRLs are the non-self blocks of the published chain, one series
	// each. Empty on a CA that issues its own root, which is the common case.
	upstreamCRLs []ca.UpstreamCRLStatus

	leaves []leafCert
}

// gather reads the CA certificate, CRL and every known leaf certificate from
// storage and returns them as a snapshot. It returns an error only for failures
// that prevent enumerating certificates at all (e.g. the signed-cert listing
// fails); a missing or unparseable CRL is tolerated and simply omits the CRL
// metrics, since a freshly bootstrapped CA may not have published one yet.
func (c *Collector) gather(ctx context.Context) (snapshot, error) {
	var snap snapshot

	snap.caReady = c.ca.IsReady()
	// CACert is written once during Init and not mutated afterwards, so reading
	// it after IsReady reports true is safe without holding the CA lock.
	if snap.caReady && c.ca.CACert != nil {
		cert := c.ca.CACert
		snap.haveCA = true
		snap.caCommonName = cert.Subject.CommonName
		snap.caSerial = serialHex(cert.SerialNumber)
		snap.caIssuer = cert.Issuer.CommonName
		snap.caNotBefore = cert.NotBefore
		snap.caNotAfter = cert.NotAfter
	}

	// Parse the CRL once. The set of revoked serials drives leaf state below, so
	// we avoid CA.IsRevoked (which re-reads and re-parses each cert from storage).
	revoked := map[string]bool{}
	if crlPEM, err := c.ca.Storage.GetCRL(ctx); err == nil {
		if crl, perr := parseCRL(crlPEM); perr == nil {
			snap.haveCRL = true
			if crl.Number != nil {
				// CRL numbers can exceed float64's exact-integer range in theory;
				// in practice they are small counters, so float64 is fine and
				// keeps the metric a plain gauge.
				snap.crlNumber, _ = new(big.Float).SetInt(crl.Number).Float64()
			}
			snap.crlThisUpdate = crl.ThisUpdate
			snap.crlNextUpdate = crl.NextUpdate
			snap.crlRevokedCount = len(crl.RevokedCertificateEntries)
			for _, entry := range crl.RevokedCertificateEntries {
				revoked[serialHex(entry.SerialNumber)] = true
			}
			// From the blob already in hand, not a second read: see the
			// "parse the CRL once" note above.
			if upstream, uerr := c.ca.UpstreamCRLStatuses(crlPEM); uerr == nil {
				snap.upstreamCRLs = upstream
			} else {
				slog.Warn("Prometheus exporter: failed to read the upstream CRL chain", "error", uerr)
			}
		} else {
			slog.Warn("Prometheus exporter: failed to parse CRL", "error", perr)
		}
	}

	// Certificates awaiting delayed revocation. Absent on any CA that has never
	// recorded one, which reads as a genuine zero.
	//
	// A read *failure* omits the series rather than reporting zero, the same
	// way haveCRL omits the CRL series above. Zero is the value this gauge takes
	// when the exposure it measures is gone, so publishing it on a list nobody
	// could read would say "drained" about the one state where the list may be
	// full and the sweep stuck — and would do it while looking healthy. An
	// omitted series goes stale and is visible as such. The failure itself is
	// counted by the sweep, which meets the same error once per pass.
	if pending, perr := c.ca.PendingSupersessions(ctx); perr != nil {
		slog.Warn("Prometheus exporter: failed to read pending supersessions", "error", perr)
	} else {
		snap.supersedePending = pending
		snap.haveSupersedePending = true
	}

	// Signed certificates: enumerate the live (non-deleted) signed set. A cleaned
	// certificate is removed from this listing even though its inventory line
	// persists, which is exactly the "known (non-deleted)" set the operator wants.
	signed, err := c.ca.Storage.ListCerts(ctx)
	if err != nil {
		return snapshot{}, fmt.Errorf("listing signed certificates: %w", err)
	}
	seen := make(map[string]bool, len(signed))
	for _, subject := range signed {
		seen[subject] = true
		certPEM, err := c.ca.Storage.GetCert(ctx, subject)
		if err != nil {
			// The cert was deleted between listing and reading, or is briefly
			// unreadable; skip it rather than failing the whole scrape.
			slog.Debug("Prometheus exporter: skipping unreadable certificate", "subject", subject, "error", err)
			continue
		}
		cert, err := parseCert(certPEM)
		if err != nil {
			slog.Warn("Prometheus exporter: skipping unparseable certificate", "subject", subject, "error", err)
			continue
		}
		serial := serialHex(cert.SerialNumber)
		state := stateSigned
		if revoked[serial] {
			state = stateRevoked
		}
		snap.leaves = append(snap.leaves, leafCert{
			subject:   subject,
			serial:    serial,
			state:     state,
			notBefore: cert.NotBefore,
			notAfter:  cert.NotAfter,
			hasCert:   true,
		})
	}

	// Pending requests: CSRs without a corresponding signed certificate. These
	// carry no issued cert, so only the info/count series describe them.
	pending, err := c.ca.Storage.ListCSRs(ctx)
	if err != nil {
		return snapshot{}, fmt.Errorf("listing certificate requests: %w", err)
	}
	for _, subject := range pending {
		if seen[subject] {
			continue
		}
		snap.leaves = append(snap.leaves, leafCert{
			subject: subject,
			state:   stateRequested,
		})
	}

	return snap, nil
}

// parseCert decodes a PEM-encoded X.509 certificate.
func parseCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseCRL decodes a PEM-encoded X.509 CRL, taking the first block.
//
// The cache reads whichever block this CA signed most recently (ca.selectOwnCRL)
// rather than block 0, so puppetca_crl_number and puppetca_crl_cached_number
// agree only while block 0 is that block — which it is on any CA whose chain was
// written by import or a re-sign, both of which put ours first. On a
// hand-assembled blob that leads with an ancestor the two describe different
// issuers, and the mixin's lag alert would read the difference as a lag. Startup
// warns about exactly that blob and every write path refuses it, so it is a
// state to repair rather than one to monitor: see docs/metrics.md.
func parseCRL(pemData []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseRevocationList(block.Bytes)
}

// serialHex formats a serial number as uppercase hexadecimal without leading
// zeros, matching the representation used in the CA's inventory file and CRL so
// that labels line up with the operator's other tooling.
func serialHex(n *big.Int) string {
	return fmt.Sprintf("%X", n)
}

// timestamp renders t as fractional seconds since the Unix epoch, the
// convention for Prometheus *_timestamp_seconds gauges. A zero time yields 0.
func timestamp(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixNano()) / 1e9
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
