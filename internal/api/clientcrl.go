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

package api

import (
	"crypto/x509"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/config"
)

// Revocation policies, re-exported so the api package does not force every
// caller to import internal/config for a string constant.
const (
	RevocationRequire = config.RevocationRequire
	RevocationCheck   = config.RevocationCheck
	RevocationSkip    = config.RevocationSkip
)

// ClientCRLSet is the revocation material for one foreign trust domain,
// swapped atomically when the domain's crl_file is reloaded.
//
// Keyed by Authority Key Identifier, matched against a candidate issuer's
// Subject Key Identifier. Not by distinguished name: under a shared root two
// sibling CAs can hold the same DN, so a DN match would consult the wrong CA's
// revocations. A CRL carrying no AKI is rejected at load rather than matched by
// DN as a fallback — Puppet Server takes the same position, keying its CRL map
// on the extension and throwing on a submitted CRL that lacks one.
type ClientCRLSet struct {
	// byIssuerKeyID maps an issuer's SubjectKeyId to its CRLs.
	byIssuerKeyID map[string][]*x509.RevocationList
}

// NewClientCRLSet builds a set from CRLs already verified against their
// domain's anchors. Any CRL without an Authority Key Identifier is skipped.
func NewClientCRLSet(crls []*x509.RevocationList) *ClientCRLSet {
	set := &ClientCRLSet{byIssuerKeyID: map[string][]*x509.RevocationList{}}
	for _, crl := range crls {
		if len(crl.AuthorityKeyId) == 0 {
			continue
		}
		key := string(crl.AuthorityKeyId)
		set.byIssuerKeyID[key] = append(set.byIssuerKeyID[key], crl)
	}
	return set
}

// forIssuer returns the currently valid CRLs issued by cert.
//
// A CRL whose NextUpdate has passed counts as absent. Without that, `require`
// silently degrades to `skip` over time: an expired CRL would go on satisfying
// the "has a CRL" test while saying nothing about revocations since.
func (s *ClientCRLSet) forIssuer(cert *x509.Certificate, now time.Time) []*x509.RevocationList {
	if s == nil || len(cert.SubjectKeyId) == 0 {
		return nil
	}
	var valid []*x509.RevocationList
	for _, crl := range s.byIssuerKeyID[string(cert.SubjectKeyId)] {
		if crl.NextUpdate.IsZero() || crl.NextUpdate.After(now) {
			valid = append(valid, crl)
		}
	}
	return valid
}

// Usable reports whether at least one issuer has a currently valid CRL. Drives
// puppetca_client_crl_usable, because under `require` the two recoverable
// conditions — every CRL expired, or every CRL discarded as unverifiable —
// reject every client of the domain, and the first symptom is otherwise a 403
// three layers from where an operator would look.
func (s *ClientCRLSet) Usable(now time.Time) bool {
	if s == nil {
		return false
	}
	for _, crls := range s.byIssuerKeyID {
		for _, crl := range crls {
			if crl.NextUpdate.IsZero() || crl.NextUpdate.After(now) {
				return true
			}
		}
	}
	return false
}

// clientCRLs holds the atomically-swappable CRL set for a domain.
type clientCRLs struct {
	current atomic.Pointer[ClientCRLSet]
}

// Set installs a reloaded CRL set.
func (c *clientCRLs) Set(s *ClientCRLSet) { c.current.Store(s) }

// Get returns the current set, which may be nil before the first load.
func (c *clientCRLs) Get() *ClientCRLSet { return c.current.Load() }

// checkChainRevocation walks a verified chain and reports the first revoked
// certificate, or an error when the policy demands a CRL that is not there.
//
// **The whole chain, not just the leaf.** A sibling CA revoked by the shared
// root must not go on authenticating its leaves — the same argument that makes
// `certificate_revocation = leaf` a downgrade for agents applies to this CA
// checking its clients.
//
// **The anchor is never checked**, because it has no issuer inside the chain. A
// trust anchor is trusted by configuration, not by anything it presents, and
// the parent's CRL is not something this CA is positioned to evaluate for an
// anchor it was told to trust. The consequence is worth stating plainly:
// revoking a trusted domain is an operator action — remove or replace the
// client_ca entry — not a CRL event. An operator who has diligently wired up
// crl_file will reasonably assume it covers the CA named in the same block. It
// does not: crl_file covers what that CA *issued*, never that CA itself.
//
// A chain of length one — the presented certificate *is* a configured anchor,
// which a client_ca entry makes reachable — yields no issuer pairs at all.
// Under `require` that is a rejection rather than a silent pass, because
// nothing can attest to its revocation status.
func checkChainRevocation(chain []*x509.Certificate, set *ClientCRLSet, policy string, now time.Time) error {
	if policy == RevocationSkip {
		return nil
	}
	if len(chain) < 2 {
		if policy == RevocationRequire {
			return fmt.Errorf("the presented certificate is itself a trust anchor, " +
				"so nothing can attest to its revocation status")
		}
		return nil
	}

	for i := 0; i < len(chain)-1; i++ {
		subject, issuer := chain[i], chain[i+1]
		crls := set.forIssuer(issuer, now)
		if len(crls) == 0 {
			if policy == RevocationRequire {
				return fmt.Errorf("no currently valid CRL for issuer %q", issuer.Subject.CommonName)
			}
			continue
		}
		for _, crl := range crls {
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(subject.SerialNumber) == 0 {
					return fmt.Errorf("certificate %q is revoked by %q",
						subject.Subject.CommonName, issuer.Subject.CommonName)
				}
			}
		}
	}
	return nil
}

// VerifyCRLAgainst reports whether crl was signed by one of anchors.
//
// SECURITY: every CRL is verified at load, against its own entry's anchors and
// never against another entry's or against client-supplied intermediates —
// those would confuse a load-time trust decision with a per-request one.
// Without this, a writable crl_file is a way to *clear* revocations, not merely
// to add them: an attacker who can write the file could replace a CRL listing
// their revoked certificate with an empty one.
func VerifyCRLAgainst(crl *x509.RevocationList, anchors []*x509.Certificate) bool {
	for _, anchor := range anchors {
		if crl.CheckSignatureFrom(anchor) == nil {
			return true
		}
	}
	return false
}
