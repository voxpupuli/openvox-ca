// Copyright (C) 2026 Trevor Vaughan
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
	"encoding/asn1"
	"errors"
	"fmt"

	"crypto/x509/pkix"
)

// ErrInvalidAuthGrant is returned when a GenerateOptions carries an AuthGrant
// that no constructor produced, or the same OID twice.
var ErrInvalidAuthGrant = errors.New("invalid authorisation grant")

// AuthGrant is a Puppet authorisation-arc extension (1.3.6.1.4.1.34380.1.3.*)
// that an in-process caller may ask GenerateWithOptions to stamp onto a
// certificate.
//
// SECURITY: the CSR signing path strips this arc from submitted requests
// (signWithDuration), because a CSR that could request pp_cli_auth would let
// any agent ask for CA admin. This type is the deliberate exception to that,
// and its shape is what keeps the exception narrow:
//
//   - the fields are unexported and there is exactly one constructor, so no
//     value can arrive from a request body, a query parameter, a config file or
//     encoding/json — reaching this seam takes a source-level call;
//   - the value is a closed set, not an OID plus arbitrary bytes, so there is
//     no "stamp whatever you like" path even for in-process callers.
//
// Both of those guard against accident, not against a determined refactor:
// PpCliAuth and GenerateWithOptions are exported, and internal/api already
// imports this package. What makes it a gate rather than a convention is the
// spec in internal/api asserting that package never names either of them.
//
// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
type AuthGrant struct {
	oid   asn1.ObjectIdentifier
	value string
}

// PpCliAuth grants CA administrator access: pp_cli_auth with the UTF8String
// value "true". A certificate carrying it is admin on this CA unless
// no_pp_cli_auth is set, which is a great deal of authority for one boolean —
// see the caller-side warnings in cmd/openvox-ca/generate.go.
func PpCliAuth() AuthGrant {
	return AuthGrant{oid: OIDPpCliAuth, value: "true"}
}

// String renders the grant for logs and operator-facing messages, using the
// Puppet short name where one exists.
func (g AuthGrant) String() string {
	if len(g.oid) == 0 {
		return "<invalid>"
	}
	return fmt.Sprintf("%s=%s", OIDKey(g.oid), g.value)
}

// extension encodes the grant as an X.509 extension.
//
// The value must be a UTF8String (DER tag 0x0c), not the PrintableString that
// plain asn1.Marshal would emit for a Go string. internal/api's hasPpCliAuth
// unmarshals into a string and would accept either, but Puppet emits UTF8String
// and so does the openssl recipe this feature replaces; a certificate that
// differs here looks identical in `openssl x509 -text` while potentially being
// read differently by anything stricter.
//
// Not critical: a verifier that does not understand the OID must not reject the
// certificate over it, which is how every other Puppet-arc extension behaves.
func (g AuthGrant) extension() (pkix.Extension, error) {
	if len(g.oid) == 0 {
		return pkix.Extension{}, fmt.Errorf("%w: zero value, use a constructor such as PpCliAuth()", ErrInvalidAuthGrant)
	}
	value, err := asn1.MarshalWithParams(g.value, "utf8")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding %s: %w", g, err)
	}
	return pkix.Extension{Id: g.oid, Critical: false, Value: value}, nil
}

// authGrantExtensions converts grants to extensions, rejecting zero values and
// duplicate OIDs. Called before any key generation or storage access so a
// malformed request costs nothing.
func authGrantExtensions(grants []AuthGrant) ([]pkix.Extension, error) {
	if len(grants) == 0 {
		return nil, nil
	}
	exts := make([]pkix.Extension, 0, len(grants))
	seen := make(map[string]struct{}, len(grants))
	for _, g := range grants {
		ext, err := g.extension()
		if err != nil {
			return nil, err
		}
		key := ext.Id.String()
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("%w: %s requested more than once", ErrInvalidAuthGrant, OIDKey(ext.Id))
		}
		seen[key] = struct{}{}
		exts = append(exts, ext)
	}
	return exts, nil
}
