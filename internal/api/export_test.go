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
	"time"
)

// AttributeForTest exposes attribute to the external api_test package.
//
// In an _test.go file so it is compiled only for tests and never becomes part
// of the shipped API. Attribution is the security property the trust-domain
// model exists to establish, and testing it needs sibling CAs under a shared
// root — a topology no exported constructor can assemble.
//
// Returns nil when no domain accepts the certificate.
func AttributeForTest(domains []TrustDomain, cert *x509.Certificate, presented []*x509.Certificate) *TrustDomain {
	got, err := attribute(domains, cert, presented)
	if err != nil {
		return nil
	}
	return got.Domain
}

// CheckChainRevocationForTest exposes checkChainRevocation to the external
// api_test package. Test-only, as above.
func CheckChainRevocationForTest(chain []*x509.Certificate, set *ClientCRLSet, policy string, now time.Time) error {
	return checkChainRevocation(chain, set, policy, now)
}
