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

		domains = append(domains, api.TrustDomain{
			Name:      entry.Name,
			Roots:     pool,
			Anchors:   anchors,
			AdminCNs:  admins,
			PpCliAuth: entry.AllowPpCliAuth,
		})
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
		if len(crl.AuthorityKeyId) == 0 {
			// Matched to issuers by AKI; a DN fallback would consult the wrong
			// CA's revocations under a shared root, where two siblings can hold
			// the same DN.
			slog.Warn("Discarding a CRL with no Authority Key Identifier",
				"client_ca", entry.Name, "path", entry.CRLFile, "issuer", crl.Issuer.String())
			continue
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
	for i := range cfg.ClientCA {
		entry := &cfg.ClientCA[i]
		// Domain zero is ours, so entry i is domain i+1.
		domain := &domains[i+1]

		crls, err := loadDomainCRLs(entry, domain.Anchors)
		if err != nil {
			// Keep whatever is loaded; the next pass retries. Replacing a good
			// set with nothing would reject every client of this domain under
			// require, which a transient read error must not do.
			slog.Error("Could not reload client CRLs; keeping the current set",
				"client_ca", entry.Name, "error", err)
			continue
		}
		domain.SetRevocationSet(api.NewClientCRLSet(crls))
		if m != nil {
			m.set(entry.Name, domain.RevocationSet().Usable(time.Now()))
		}
	}
}

// clientCRLTask reloads foreign CRL bundles on the maintenance ticker.
func clientCRLTask(cfg *serverConfig, domains []api.TrustDomain, m *clientCRLMetrics) maintenanceTask {
	return maintenanceTask{
		name: "client-crl-reload",
		run: func(context.Context) {
			refreshClientCRLs(cfg, domains, m)
		},
	}
}

// clientCRLMetrics exposes whether each foreign trust domain currently has
// usable revocation material.
//
// Under the require policy two recoverable conditions — every CRL for a domain
// expired, or every CRL discarded as unverifiable — reject every client of that
// domain. Without this gauge the first symptom is agents failing to
// authenticate with a 403 whose cause is three layers from where an operator
// would look.
type clientCRLMetrics struct {
	usable *prometheus.GaugeVec
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
			Help: "1 when a client_ca trust domain has at least one currently valid CRL, 0 otherwise. " +
				"Under client_revocation_policy=require a 0 rejects every client of that domain, so " +
				"alert on it: the alternative is diagnosing a fleet-wide 403 from the agent side.",
		}, []string{"client_ca"}),
	}
	reg.MustRegister(m.usable)
	return m
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
