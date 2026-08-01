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

package config

import (
	"fmt"
	"strings"
	"time"
)

// Client revocation policies for foreign trust domains.
const (
	// RevocationRequire rejects a client whose issuer has no currently valid
	// CRL. The default whenever client_ca is set: it forces an explicit
	// operator decision rather than defaulting into a hole.
	RevocationRequire = "require"
	// RevocationCheck verifies against whatever CRLs are loaded and allows a
	// client whose issuer has none. The "that CA publishes OCSP instead, and I
	// accept the risk" setting.
	RevocationCheck = "check"
	// RevocationSkip performs no revocation check for foreign issuers.
	RevocationSkip = "skip"
)

// ClientCA is one configured foreign trust domain: an issuer whose client
// certificates this CA will authenticate, and the authority they carry.
//
// It never affects what this CA *issues*, only whom it will talk to. Our own
// CA is always trusted and is not expressible here.
type ClientCA struct {
	// Name identifies the entry in logs, metrics and errors. Required, and
	// must be unique.
	Name string `yaml:"name"`

	// File is a PEM bundle of trust anchors for this entry alone.
	//
	// Put the *issuing* CA here, not the root above it. An anchor need not be
	// self-signed: anchoring on an intermediate accepts what that intermediate
	// issued and nothing else, which is what keeps two sibling CAs under a
	// shared root separate. Naming the root instead extends this entry's
	// authority — including its AdminCNs — to every intermediate that root has
	// issued or ever will.
	File string `yaml:"file"`

	// CRLFile is a PEM bundle of CRLs for the issuers in File.
	//
	// It covers what those CAs *issued*, never those CAs themselves: a trust
	// anchor is trusted by configuration, so revoking one is an operator
	// action — remove or replace this entry — not a CRL event.
	//
	// Not to be confused with crl_chain_file, which points the other way: that
	// one carries this CA's own ancestors' CRLs and is published to agents.
	CRLFile string `yaml:"crl_file"`

	// AdminCNs are common names granted admin authority when presented by a
	// certificate from this issuer. Defaults to none, so adding an entry
	// authenticates an issuer without granting it anything.
	AdminCNs []string `yaml:"admin_cns"`

	// AllowPpCliAuth honours the pp_cli_auth extension on certificates from
	// this issuer. Off by default, because turning it on delegates admin
	// admission to that CA: every certificate it chooses to stamp becomes an
	// admin here.
	AllowPpCliAuth bool `yaml:"allow_pp_cli_auth"`
}

// ClientCAConfig is the client_ca block plus its shared revocation policy.
type ClientCAConfig struct {
	// ClientCA lists the foreign trust domains, tried in this order after our
	// own. File-only, like kubernetes_export: a list of structures with no
	// sensible flat encoding.
	ClientCA []ClientCA `yaml:"client_ca"`

	// ClientRevocationPolicy governs revocation checking for foreign issuers
	// only; our own CA's clients are always checked against our own CRL.
	ClientRevocationPolicy string `yaml:"client_revocation_policy"`

	// ClientCRLRefreshIntervalSec is how often the foreign CRL bundles named by
	// each entry's crl_file are re-read. 0 selects the built-in default (1h).
	//
	// The CRLs reload; the anchors deliberately do not. See refreshClientCRLs.
	ClientCRLRefreshIntervalSec int `yaml:"client_crl_refresh_interval_sec"`
}

// ClientCRLRefreshInterval resolves how often foreign CRL bundles are re-read,
// falling back to an hour when unset or non-positive -- the same bound
// crl_chain_file uses, and for the same reason: the file is refreshed by
// whatever already delivers it, and this only notices.
func (c *ClientCAConfig) ClientCRLRefreshInterval() time.Duration {
	if c.ClientCRLRefreshIntervalSec > 0 {
		return time.Duration(c.ClientCRLRefreshIntervalSec) * time.Second
	}
	return time.Hour
}

// Enabled reports whether any foreign trust domain is configured.
func (c *ClientCAConfig) Enabled() bool { return c != nil && len(c.ClientCA) > 0 }

// ResolvedPolicy is Policy with any unrecognised value folded to require.
//
// Validation rejects a bad policy string, but it lives in this package and runs
// on one construction path, so every consumer that acts on the value coerces
// rather than assuming it was reached. Three sites had hand-written copies of
// that coercion and the newest one omitted it, which left enforcement refusing
// clients as require while the gauge for those clients was never published.
func (c *ClientCAConfig) ResolvedPolicy() string {
	p := c.Policy()
	if p != RevocationSkip && p != RevocationCheck {
		return RevocationRequire
	}
	return p
}

// Policy returns the configured revocation policy, defaulting to require when
// unset. It does not validate the value; see ResolvedPolicy.
func (c *ClientCAConfig) Policy() string {
	if c.ClientRevocationPolicy == "" {
		return RevocationRequire
	}
	return c.ClientRevocationPolicy
}

// Validate normalises the block in place and reports the first problem.
func (c *ClientCAConfig) Validate() error {
	switch c.Policy() {
	case RevocationRequire, RevocationCheck, RevocationSkip:
	default:
		return fmt.Errorf("invalid client_revocation_policy %q (must be %q, %q or %q)",
			c.ClientRevocationPolicy, RevocationRequire, RevocationCheck, RevocationSkip)
	}

	seen := make(map[string]bool, len(c.ClientCA))
	for i := range c.ClientCA {
		entry := &c.ClientCA[i]
		entry.Name = strings.TrimSpace(entry.Name)
		if entry.Name == "" {
			return fmt.Errorf("client_ca entry %d: name is required", i)
		}
		if seen[entry.Name] {
			return fmt.Errorf("client_ca entry %d: duplicate name %q", i, entry.Name)
		}
		seen[entry.Name] = true

		if strings.TrimSpace(entry.File) == "" {
			return fmt.Errorf("client_ca %q: file is required (a PEM bundle of trust anchors)", entry.Name)
		}
		if c.Policy() == RevocationRequire && strings.TrimSpace(entry.CRLFile) == "" {
			// Under require, an issuer with no CRL rejects every one of its
			// clients. Saying so at startup beats discovering it as a
			// fleet-wide 403 whose cause is three layers away.
			return fmt.Errorf("client_ca %q: crl_file is required under client_revocation_policy %q; "+
				"set crl_file, or choose %q to allow issuers without one",
				entry.Name, RevocationRequire, RevocationCheck)
		}
	}
	return nil
}
