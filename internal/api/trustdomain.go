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
)

// TrustDomain is one set of client certificate issuers, with the authority its
// certificates carry *within this CA*.
//
// The unit of trust is the domain, not the certificate: a name asserted in a
// certificate means something only inside the namespace of the issuer that
// signed it, so admin grants, revocation sources and identity claims are all
// per-domain. Verification runs against one domain's anchors at a time and
// never against a merged pool — a merged pool would make "trusted" a single
// global property, which is precisely what must not happen when the anchors are
// siblings under a shared root.
type TrustDomain struct {
	// Name identifies the domain in logs and metrics. Empty for our own CA.
	Name string

	// Roots are the anchors for this domain alone. A chain must terminate at
	// one of them to be attributed here.
	//
	// An anchor need not be self-signed, and that is the point: anchoring on an
	// intermediate accepts what that intermediate issued and nothing else, so
	// two sibling CAs under a shared root stay separate. Putting the shared
	// root in here instead silently widens this domain's authority — including
	// its AdminCNs — to every intermediate that root has issued or ever will.
	Roots *x509.CertPool

	// AdminCNs are the common names granted admin authority *in this domain*.
	// A name from another issuer is a different name.
	AdminCNs map[string]bool

	// PpCliAuth honours the pp_cli_auth extension on certificates from this
	// domain. Enabling it for a foreign issuer delegates admin admission to
	// that CA: every certificate it chooses to stamp becomes an admin here.
	PpCliAuth bool
}

// IsOwn reports whether this is domain zero — this CA's own issuer.
func (d *TrustDomain) IsOwn() bool { return d.Name == "" }

// Describe names the domain for a log line.
func (d *TrustDomain) Describe() string {
	if d.IsOwn() {
		return "this CA"
	}
	return fmt.Sprintf("client_ca %q", d.Name)
}

// OwnTrustDomain builds domain zero from this CA's certificate and the settings that
// have always configured admin access.
//
// It is constructed unconditionally and cannot be expressed as a client_ca
// entry, so an operator cannot remove it, rename it, or accidentally drop their
// own CA out of the trust set. With no client_ca configured the domain list has
// length one and every lookup collapses to today's behaviour — which is a
// design constraint, not a coincidence: if the general mechanism ever required
// the default deployment to declare a trust domain or name its own CA, the
// model would be wrong.
func OwnTrustDomain(caCert *x509.Certificate, adminCNs map[string]bool, ppCliAuth bool) TrustDomain {
	roots := x509.NewCertPool()
	if caCert != nil {
		roots.AddCert(caCert)
	}
	return TrustDomain{
		Roots:     roots,
		AdminCNs:  adminCNs,
		PpCliAuth: ppCliAuth,
	}
}

// verifiedChain is the outcome of attributing a client certificate: which
// domain accepted it, and the chain that domain built.
type verifiedChain struct {
	Domain *TrustDomain
	Chain  []*x509.Certificate
}

// attribute finds the first trust domain that can verify cert, and returns the
// chain it built.
//
// **Domain order is part of the contract, not an implementation detail.**
// Domain zero is always tried first, then client_ca entries in configuration
// order. Without a fixed order, a client holding certificates from two trusted
// domains — or presenting a chain that satisfies more than one — would choose
// its own attribution, and with it its own admin grants. Trying ours first also
// means a foreign domain can never capture a certificate this CA issued.
//
// Attribution comes from which domain verified and from nothing else. An
// earlier design compared the chain's second element against our own issuer;
// that is unsound, because CertPool.findPotentialParents selects candidates by
// RawIssuer and uses the Subject Key Identifier only to *order* them, never to
// require a match — so a chain built by a foreign domain can carry an arbitrary
// Subject and SKI of the client's choosing. Since each domain verifies against
// its own anchors alone, a successful Verify against domain d already means
// "issued under d"; comparing chain contents afterwards adds nothing and
// introduces a forgeable operand.
//
// intermediates is built from the certificates the client presented after the
// leaf. That pool is client-supplied and safe: an intermediates pool can only
// help build a path to an anchor that is *already* trusted, never introduce
// one. Supplying a shared root and a sibling CA does not make the sibling's
// leaf acceptable to a domain anchored on this CA.
func attribute(domains []TrustDomain, cert *x509.Certificate, presented []*x509.Certificate) (*verifiedChain, error) {
	intermediates := x509.NewCertPool()
	for _, c := range presented {
		intermediates.AddCert(c)
	}

	var lastErr error
	for i := range domains {
		chains, err := cert.Verify(x509.VerifyOptions{
			Roots:         domains[i].Roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			lastErr = err
			continue
		}
		return &verifiedChain{Domain: &domains[i], Chain: chains[0]}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no trust domains are configured")
	}
	return nil, lastErr
}
