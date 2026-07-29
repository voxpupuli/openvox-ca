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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"

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
