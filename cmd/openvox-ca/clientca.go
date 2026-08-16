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

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/config"
)

// parseAnchorBundle reads a PEM bundle of trust anchors.
//
// A missing, unreadable or certificate-free file is a startup error, not a
// warning. Under the default require policy an empty anchor pool rejects every
// client of that domain, so a path typo would present as a total, silent
// authentication outage for one issuer while the CA otherwise looked healthy.
// Failing here makes it a deployment error instead of a production incident.
func parseAnchorBundle(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d in %s: %w", len(certs)+1, path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s contains no certificates", path)
	}
	return certs, nil
}

// buildTrustDomains assembles the domain list: ours first, then each client_ca
// entry in configuration order.
//
// The order is the middleware's contract — see api.TrustDomain — so it is
// established here, once, rather than left to whatever order a map iteration
// produced.
func buildTrustDomains(cfg *serverConfig, ownCert *x509.Certificate, adminCNs map[string]bool) ([]api.TrustDomain, error) {
	domains := []api.TrustDomain{
		api.OwnTrustDomain(ownCert, adminCNs, !cfg.NoPpCliAuth),
	}

	for i := range cfg.ClientCA {
		entry := &cfg.ClientCA[i]
		anchors, err := parseAnchorBundle(entry.File)
		if err != nil {
			return nil, fmt.Errorf("client_ca %q: %w", entry.Name, err)
		}

		pool := x509.NewCertPool()
		for _, anchor := range anchors {
			pool.AddCert(anchor)
			warnIfSelfSigned(entry, anchor)
		}
		warnIfGrantsSpanAnchors(entry, anchors)

		admins := make(map[string]bool, len(entry.AdminCNs))
		for _, cn := range entry.AdminCNs {
			admins[cn] = true
		}
		if len(admins) > 0 {
			slog.Info("client_ca entry grants admin access to named common names",
				"client_ca", entry.Name, "admin_cns", entry.AdminCNs)
		}
		if entry.AllowPpCliAuth {
			// SECURITY: honouring pp_cli_auth from an issuer means every
			// certificate that issuer chooses to stamp with the extension is an
			// admin here. For a Server CA under the same operator's control
			// that is correct, and is how the CA CLI authenticates upstream.
			// For a CA the operator does not control it is a full delegation of
			// admin admission.
			// NIST 800-53: AC-6 (Least Privilege)
			slog.Warn("client_ca entry honours pp_cli_auth: any certificate this issuer stamps "+
				"with pp_cli_auth=true is an administrator of this CA",
				"client_ca", entry.Name)
		}

		domain := api.NewForeignTrustDomain(entry.Name, pool, anchors, admins, entry.AllowPpCliAuth)

		// Load once here, so a crl_file that cannot be read or parsed refuses
		// startup rather than starting a server that rejects every client of
		// this domain under require. The anchor bundle beside it already fails
		// closed; there is no reason for the file that decides revocation to be
		// more forgiving than the one that decides trust. Later reloads are
		// best-effort by design — see refreshClientCRLs — because by then a
		// working set exists and keeping it beats discarding it.
		crls, err := loadDomainCRLs(entry, anchors)
		if err != nil {
			return nil, fmt.Errorf("client_ca %q: %w", entry.Name, err)
		}
		// Partial-CRL discards are not reported here: main.go runs an immediate
		// refreshClientCRLs pass before serving, which reports them once with
		// the dedupe state that stops an unchanged file repeating hourly.
		// Warning in both places printed every startup twice.
		domain.SetRevocationSet(api.NewClientCRLSet(crls, anchors))
		warnAboutCRLCoverage(entry, cfg.ResolvedPolicy(), crls, anchors)

		domains = append(domains, domain)
	}
	return domains, nil
}

// warnIfSelfSigned reports a root certificate used as an entry's anchor.
//
// Anchoring on a root is legitimate when the root really is the intended
// boundary, so this warns rather than refuses — but it is the natural mistake,
// because "the CA bundle" usually means the whole chain, and the consequence is
// invisible: the entry's authority, including its admin_cns, silently extends
// to every intermediate that root has issued or ever will.
//
// Unconditional and not suppressible. An operator who means it can read past
// one line at startup; an operator who does not needs to see it.
func warnIfSelfSigned(entry *config.ClientCA, anchor *x509.Certificate) {
	if anchor.CheckSignatureFrom(anchor) != nil {
		return
	}
	slog.Warn("client_ca anchor is a self-signed root: this entry now trusts every certificate "+
		"issued anywhere beneath it, including by intermediates that do not exist yet, and its "+
		"admin_cns apply to all of them. Anchor on the issuing CA instead if you meant to scope it.",
		"client_ca", entry.Name, "anchor", anchor.Subject.CommonName)
}

// warnIfGrantsSpanAnchors reports an entry whose grants reach further than the
// operator is likely to think.
//
// admin_cns and allow_pp_cli_auth are properties of the *entry*, and an entry's
// file may hold any number of anchors. So two issuers in one bundle share one
// admin list: a name the operator meant for one of them is honoured from either.
// The documentation says the opposite in as many words -- "a name means
// something only within its issuer's namespace" -- and that is the sentence an
// operator acts on.
//
// The same widening as the self-signed-root case beside this, which is already
// warned about unconditionally, so this is warned about the same way. Splitting
// the entry per issuer is the fix, and it costs nothing: entries are cheap.
func warnIfGrantsSpanAnchors(entry *config.ClientCA, anchors []*x509.Certificate) {
	if len(anchors) < 2 || (len(entry.AdminCNs) == 0 && !entry.AllowPpCliAuth) {
		return
	}
	names := make([]string, 0, len(anchors))
	for _, a := range anchors {
		names = append(names, a.Subject.CommonName)
	}
	slog.Warn("client_ca entry grants admin authority across more than one anchor: its admin_cns "+
		"and allow_pp_cli_auth apply to certificates from every anchor in its file, so a name "+
		"granted for one issuer is honoured from the others too. Split the entry, one per issuer, "+
		"if you meant to scope the grant.",
		"client_ca", entry.Name, "anchors", strings.Join(names, ", "))
}

// warnAboutPartialCRLs reports CRLs not counted towards coverage because they
// cover only part of their issuer's revocations, with the entry and file the
// api package cannot know. Their serials are still enforced.
//
// Worth a warning rather than a debug line because the file looks valid: every
// CRL in it verifies, and the operator's evidence that the delivery works is
// that nothing complained.
func warnAboutPartialCRLs(entry *config.ClientCA, set *api.ClientCRLSet) {
	discarded := set.Discarded()
	if len(discarded) == 0 {
		return
	}
	slog.Warn("Not counting client CRLs that cover only part of their issuer's revocations: "+
		"a delta CRL, or one scoped to an issuing distribution point, lists a fraction of "+
		"what its issuer has revoked, and this CA is handed a file rather than fetching the "+
		"rest. The serials they name are still enforced; they just cannot show this issuer "+
		"is covered. Deliver the issuer's full CRL.",
		"client_ca", entry.Name, "path", entry.CRLFile,
		"discarded", strings.Join(discarded, "; "))
}

// regressesCRLSet reports whether candidate would move any anchor backwards,
// and the subject of an anchor it would, so the refusal can name the issuer
// that regressed -- an operator holding a bundle of several upstreams needs to
// know which one to chase.
//
// Separate from losesCoverage because the two answer different questions: that
// one asks whether an anchor lost its CRL, this one whether an anchor's CRL got
// older. A replayed file passes the first and fails the second.
func regressesCRLSet(current, candidate *api.ClientCRLSet, now time.Time) (string, bool) {
	return current.Regresses(candidate, now)
}

// losesCoverage reports whether candidate covers less than current does.
//
// Compared per anchor *key*, not per common name. Names collapse: a CA that
// renews and rekeys keeps its subject, so a bundle carrying both certificates
// through the overlap has two independent coverage slots under one name, and a
// name-keyed comparison saw one. The guard then passed a strictly narrower
// reload -- exactly what it exists to stop -- in the topology this feature was
// built for.
//
// Both halves of coverage matter. Losing a *current* CRL breaks `require`;
// losing a CRL entirely also breaks `check`, which consults expired ones for
// the serials they name, so dropping one silently re-admits everything it
// listed.
func losesCoverage(current, candidate *api.ClientCRLSet, now time.Time) bool {
	if candidate == nil {
		return true
	}
	wasPresent, wasCurrent := current.Coverage(now)
	isPresent, isCurrent := candidate.Coverage(now)
	for key := range wasPresent {
		if !isPresent[key] {
			return true
		}
	}
	for key := range wasCurrent {
		if !isCurrent[key] {
			return true
		}
	}
	return false
}

// warnAboutCRLCoverage reports anchors this entry holds no current CRL for.
//
// Advisory, and worded as such. Whether an uncovered anchor matters depends on
// whether any client's chain terminates there, which cannot be known at
// startup: a bundle holding an issuing CA and the root above it needs only the
// issuing CA's CRL, because nobody chains to the root. The previous wording
// asserted that every client of the entry would be rejected, which was false
// for exactly that shape and pushed the operator towards
// client_revocation_policy: check -- an availability worry answered by turning
// off leaf revocation checking, along the path of least resistance.
//
// It also cannot see the case it used to claim. An entry anchored on a shared
// root, whose clients come from an intermediate below it, loads the root's CRL
// happily -- the root signed it -- while the intermediate's own CRL is signed by
// the intermediate and so is discarded. The chain then has an issuer with no
// CRL and every client is refused, with full anchor coverage reported here.
// Nothing at load time can distinguish that from a healthy entry;
// puppetca_client_crl_refusals_total is what reports it, because by then a
// client has actually been turned away.
func warnAboutCRLCoverage(entry *config.ClientCA, policy string, crls []*x509.RevocationList,
	anchors []*x509.Certificate,
) {
	if policy != config.RevocationRequire {
		return
	}
	gaps := api.NewClientCRLSet(crls, anchors).CoverageGaps(time.Now())
	if len(gaps) == 0 {
		return
	}
	slog.Warn("client_ca entry has anchors with no currently valid CRL under the require policy: "+
		"any client whose chain terminates at one of them is rejected. If this entry is anchored on "+
		"a shared root, note the issuing CA's own CRL is signed by that CA and not by the anchor, so "+
		"it cannot be verified here — anchor on the issuing CA instead. Switching to "+
		"client_revocation_policy: check would restore service by disabling leaf revocation checking "+
		"for this entry, which is rarely what is wanted",
		"client_ca", entry.Name, "path", entry.CRLFile,
		"uncovered_anchors", strings.Join(gaps, ", "))
}

// loadDomainCRLs reads and verifies the CRLs for one client_ca entry.
//
// SECURITY: each CRL must verify against an anchor in *this same entry's*
// bundle. Never against another entry's, and never against client-supplied
// intermediates — that would confuse a load-time trust decision with a
// per-request one. Without the check, a writable crl_file is a way to *clear*
// revocations rather than merely add them: replace a CRL naming a revoked
// certificate with an empty one and it is valid again.
//
// A CRL that verifies against nothing is discarded with a warning, and under
// the require policy its issuer is therefore treated as having no CRL at all.
func loadDomainCRLs(entry *config.ClientCA, anchors []*x509.Certificate) ([]*x509.RevocationList, error) {
	if entry.CRLFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(entry.CRLFile)
	if err != nil {
		return nil, fmt.Errorf("reading crl_file %s: %w", entry.CRLFile, err)
	}

	var out []*x509.RevocationList
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing CRL %d in %s: %w", len(out)+1, entry.CRLFile, err)
		}
		if !api.VerifyCRLAgainst(crl, anchors) {
			slog.Warn("Discarding a CRL that no anchor in this client_ca entry signed",
				"client_ca", entry.Name, "path", entry.CRLFile, "issuer", crl.Issuer.String())
			continue
		}
		out = append(out, crl)
	}
	return out, nil
}

// refreshClientCRLs reloads every configured domain's CRLs and swaps them in.
//
// Anchors are load-time only and deliberately do not reload: a half-applied CRL
// reload costs at most a stale revocation, whereas a half-applied *anchor*
// reload — new file on disk, old pool in memory, or the reverse across
// replicas — locks out every client of that domain, and the recovery is the
// restart it was trying to avoid. Rotating an anchor is a rare, planned event;
// the supported procedure is to add the new anchor as a second entry, roll the
// fleet, then remove the old one and roll again.
func refreshClientCRLs(cfg *serverConfig, domains []api.TrustDomain, m *clientCRLMetrics) {
	policy := cfg.ResolvedPolicy()
	for i := range cfg.ClientCA {
		entry := &cfg.ClientCA[i]
		// Domain zero is ours, so entry i is domain i+1.
		domain := &domains[i+1]

		crls, err := loadDomainCRLs(entry, domain.Anchors)
		now := time.Now()
		var candidate *api.ClientCRLSet
		if err == nil {
			candidate = api.NewClientCRLSet(crls, domain.Anchors)
		}

		if candidate != nil && m.shouldWarnDiscards(entry.Name, candidate.Discarded()) {
			warnAboutPartialCRLs(entry, candidate)
		}

		// Computed before the switch rather than inside a case guard, because
		// the refusal names the anchor that moved and a case cannot bind a
		// value. Empty where there is no crl_file to reload, where the read
		// failed, and where nothing went backwards -- the first two of which
		// the err and losesCoverage arms below already answer for.
		regressedAnchor, regressed := "", false
		droppedAnchor, dropped := "", false
		if entry.CRLFile != "" && err == nil {
			regressedAnchor, regressed = regressesCRLSet(domain.RevocationSet(), candidate, now)
			droppedAnchor, dropped = domain.RevocationSet().PartialsDropped(candidate, now)
		}

		switch {
		case err != nil:
			// Keep whatever is loaded; the next pass retries. Replacing a good
			// set with nothing would reject every client of this domain under
			// require, which a transient read error must not do.
			slog.Error("Could not reload client CRLs; keeping the current set",
				"client_ca", entry.Name, "error", err)
		case entry.CRLFile != "" && losesCoverage(domain.RevocationSet(), candidate, now):
			// The reload covers fewer anchors than what is already installed.
			//
			// Gating this on "yielded nothing at all" protected against total
			// failure and not against partial, which is the likelier of the two:
			// a bundle assembled from several upstreams loses one of them, or one
			// issuer rotates its key so its new CRL no longer verifies. The old
			// test let that install a set covering fewer anchors and discard the
			// good one, refusing every client of the anchor that went missing --
			// while a wholly broken file was safely retained.
			slog.Error("crl_file reload would cover fewer anchors than the current set; "+
				"keeping the current set",
				"client_ca", entry.Name, "path", entry.CRLFile,
				"now_uncovered", strings.Join(candidate.CoverageGaps(now), ", "))
		case regressed:
			// Verifies, covers every anchor the current set covers, and is still
			// older than what is installed. Applying it would re-admit every
			// serial revoked since it was signed, and nothing else on this path
			// would notice: coverage is unchanged and the signature is good.
			// The upstream chain refuses the same shape for the same reason;
			// see monotonicUpstream.
			slog.Error("crl_file reload would move an anchor backwards; keeping the current set",
				"client_ca", entry.Name, "path", entry.CRLFile,
				"issuer", regressedAnchor)
		case dropped:
			// Partial CRLs are invisible to the two guards above: they are filed
			// apart, so an anchor's coverage and freshness read the same whether
			// or not its delta is present. Since a delta can deny a client, a
			// reload that quietly drops one re-admits every serial only it named
			// -- narrowing enforcement while looking like an ordinary refresh.
			slog.Error("crl_file reload would drop a partial CRL whose serials are enforced, "+
				"without its issuer's full CRL moving on; keeping the current set",
				"client_ca", entry.Name, "path", entry.CRLFile,
				"issuer", droppedAnchor)
		default:
			domain.SetRevocationSet(candidate)
			m.recordReload(entry.Name, now)
		}

		// Published on every branch, not only the successful one. The gauge is
		// what an operator alerts on, and a domain whose very first load failed
		// is exactly when they need it: skipping the set here means the series
		// is never created, and `== 0` cannot fire on a series that does not
		// exist. The mixin ORs in absent() for the same reason on `up`.
		// Zero-initialised so the series exists from the first scrape. A
		// CounterVec child appears only when it is first incremented, so
		// increase() -- which needs two samples -- could never see a burst that
		// began and ended inside one interval, and the first increment of any
		// burst was structurally invisible. Not policy-gated, but not because
		// refusals occur under every policy -- they do not: both ErrNoUsableCRL
		// arms are require-only, so under check and skip this counter is
		// provably zero. It is ungated so the series exists whatever the policy,
		// including after an operator changes it to require.
		if m != nil {
			m.refusals.WithLabelValues(entry.Name).Add(0)
		}

		// Published only under require. crl_file is optional under check and
		// skip -- "that CA publishes OCSP instead, and I accept the risk" -- so a
		// domain with no CRLs is a correct configuration there, and publishing 0
		// for it fired the mixin's only critical authentication alert forever on
		// a healthy server. The realistic response to that is to silence the
		// rule, which takes the require case down with it.
		if m != nil && policy == config.RevocationRequire {
			m.set(entry.Name, domain.RevocationSet().Usable(now))
		}
	}
}

// runClientCRLReloader reloads foreign CRL bundles on a timer, for the lifetime
// of ctx.
//
// No pass before the first tick: the serve command loads the set once before it
// starts serving, because under the require policy an empty set rejects every
// client of that domain, and a first request must not meet one.
func runClientCRLReloader(ctx context.Context, cfg *serverConfig, domains []api.TrustDomain, m *clientCRLMetrics, interval time.Duration) {
	slog.Info("Starting client CRL reload job", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Debug("Client CRL reload job stopping")
			return
		case <-ticker.C:
			refreshClientCRLs(cfg, domains, m)
		}
	}
}

// clientCRLMetrics exposes whether each foreign trust domain currently has
// usable revocation material.
//
// Under the require policy three recoverable conditions — every CRL for a
// domain expired, every CRL discarded as unverifiable, or every CRL discarded
// as partial-scope — reject every client of that domain. Without this gauge the first symptom is agents failing to
// authenticate with a 403 whose cause is three layers from where an operator
// would look.
//
// Two signals, because one cannot do it. The gauge answers what is knowable at
// load time -- does this entry hold anything current -- and the counter answers
// what is not: whether clients are actually being refused, which depends on the
// chains they present and so cannot be estimated before they arrive.
type clientCRLMetrics struct {
	usable     *prometheus.GaugeVec
	refusals   *prometheus.CounterVec
	lastReload *prometheus.GaugeVec

	// warnedDiscards remembers, per client_ca entry, the partial-CRL discards
	// last reported, so a standing misconfiguration is not reprinted on every
	// refresh while a newly introduced one still is.
	//
	// Kept here rather than compared against the installed set, which is what
	// the first version did: the installed set only changes when a reload is
	// *accepted*, so a candidate that is refused -- exactly the case where the
	// operator has just broken the delivery -- differed from it every pass and
	// warned every hour, which is the behaviour the suppression exists to stop.
	discardMu      sync.Mutex
	warnedDiscards map[string]string
}

// shouldWarnDiscards reports whether this entry's discards differ from the last
// reported, recording them either way.
func (m *clientCRLMetrics) shouldWarnDiscards(entry string, discards []string) bool {
	if m == nil {
		// No exporter configured, so there is no per-entry state to dedupe
		// against. Reporting every pass beats reporting nothing: the warning is
		// the only signal a partial delivery gives, and without metrics it is
		// the only signal at all.
		return len(discards) > 0
	}

	joined := strings.Join(discards, "; ")

	m.discardMu.Lock()
	defer m.discardMu.Unlock()
	previous, seen := m.warnedDiscards[entry]
	if m.warnedDiscards == nil {
		m.warnedDiscards = map[string]string{}
	}
	// Recorded on every pass including the empty one, so the state clears when
	// the fault does. Returning early on an empty set left the old discards
	// remembered, and a delivery broken, fixed, then broken the same way again
	// stayed silent for ever.
	m.warnedDiscards[entry] = joined

	return len(discards) > 0 && (!seen || previous != joined)
}

// newClientCRLMetrics registers the gauge, or returns nil when the exporter is
// disabled.
func newClientCRLMetrics(reg prometheus.Registerer) *clientCRLMetrics {
	if reg == nil {
		return nil
	}
	m := &clientCRLMetrics{
		usable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "puppetca",
			Subsystem: "client_crl",
			Name:      "usable",
			Help: "1 when a client_ca trust domain holds any currently valid CRL, 0 when it holds " +
				"none. Exported only under client_revocation_policy=require, where a 0 means the " +
				"domain has nothing to check against; crl_file is optional under check and skip, so " +
				"a domain without CRLs is correct there and publishing 0 would alert on a healthy " +
				"server. This does NOT report partial coverage: whether an uncovered anchor matters " +
				"depends on chains that have not arrived, so a domain can read 1 while clients of " +
				"one of its anchors are refused. puppetca_client_crl_refusals_total is the signal " +
				"for that, because it counts refusals that actually happened.",
		}, []string{"client_ca"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "puppetca",
			Subsystem: "client_crl",
			Name:      "refusals_total",
			Help: "Clients refused because revocation information was missing -- their issuer " +
				"had no currently valid CRL, or the presented certificate is itself a trust " +
				"anchor and nothing can attest to its status -- under " +
				"client_revocation_policy=require. Unlike the usable gauge this is not an " +
				"estimate: it counts requests actually turned away, so it sees a partially " +
				"covered entry -- one anchor's CRL missing while another's is fine -- which no " +
				"load-time check can distinguish from a healthy one. Alert on increase() > 0.",
		}, []string{"client_ca"}),
		lastReload: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "puppetca",
			Subsystem: "client_crl",
			Name:      "last_reload_timestamp_seconds",
			Help: "When this client_ca entry's crl_file was last applied, in seconds since the " +
				"epoch. A reload that fails, that would cover fewer anchors than the set " +
				"already in use, that would drop an enforced partial CRL, or that would " +
				"move an anchor backwards to an older CRL, " +
				"deliberately keeps the previous set -- which is right for " +
				"availability and invisible on every other series, because the retained CRLs " +
				"are still current and clients are still served. Meanwhile the file has stopped " +
				"being applied, so revocations published since are not honoured. Alert on this " +
				"going stale relative to client_crl_refresh_interval_sec.",
		}, []string{"client_ca"}),
	}
	reg.MustRegister(m.usable, m.refusals, m.lastReload)
	return m
}

// recordReload stamps a successful application of an entry's crl_file.
func (m *clientCRLMetrics) recordReload(domain string, at time.Time) {
	if m == nil {
		return
	}
	// Sub-second, as Prometheus timestamps are: whole seconds cannot distinguish
	// two passes inside the same second, which is exactly what a spec asserting
	// "a failed reload does not advance this" has to do.
	m.lastReload.WithLabelValues(domain).Set(float64(at.UnixNano()) / 1e9)
}

// recordRefusal counts one client turned away for want of a usable CRL.
func (m *clientCRLMetrics) recordRefusal(domain string) {
	if m == nil {
		return
	}
	m.refusals.WithLabelValues(domain).Inc()
}

// set records whether a domain's CRLs are usable.
func (m *clientCRLMetrics) set(name string, usable bool) {
	if m == nil {
		return
	}
	value := 0.0
	if usable {
		value = 1
	}
	m.usable.WithLabelValues(name).Set(value)
}
