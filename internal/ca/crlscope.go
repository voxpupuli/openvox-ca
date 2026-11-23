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

package ca

import (
	"crypto/x509"
	"encoding/asn1"
)

// The two extensions that narrow a CRL's scope (RFC 5280 s5.2.4 and s5.2.5).
var (
	oidDeltaCRLIndicator      = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPnt = asn1.ObjectIdentifier{2, 5, 29, 28}
)

// PartialScope reports whether a CRL declares itself narrower than its
// issuer's full revocation list, and which extension says so.
//
// Presence is the whole test. An issuing distribution point can in principle
// describe a scope equal to the full list, but parsing it to find out means
// implementing a decision this CA has no way to act on: if the IDP names a
// distribution point, the complete picture lives somewhere else, and the
// operator has to point the source there instead.
//
// One definition for the three places a CRL from a configured source is taken
// on trust as an issuer's whole list -- client_ca, and the upstream chain from
// crl_chain.file and crl_chain.urls -- so they cannot drift apart on what
// "partial" means. openvox-ca-ctl import --crl-chain does not call it: an
// import stores what the operator hands it, and the crl_chain.urls merge then
// takes the stored CRLs as its baseline like any other.
func PartialScope(crl *x509.RevocationList) (string, bool) {
	for _, ext := range crl.Extensions {
		switch {
		case ext.Id.Equal(oidDeltaCRLIndicator):
			return "delta CRL", true
		case ext.Id.Equal(oidIssuingDistributionPnt):
			return "issuing distribution point", true
		}
	}
	return "", false
}
