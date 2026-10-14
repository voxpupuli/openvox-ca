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

import "errors"

// reservedKeySubject is the one subject this CA never generates a private key
// for. A generated key for subject S is written to <cadir>/private/S_key.pem,
// so the key for "ca" lands on private/ca_key.pem: the CA key itself in a cadir
// an earlier openvox-ca created, and the CA key's legacy location in a fresh
// one, where the filesystem backend then refuses to start on two different CA
// keys (#495).
const reservedKeySubject = "ca"

// ErrReservedSubject is returned by every path that generates a private key
// for a subject -- POST /generate, offline `openvox-ca generate`, and managed
// certificates -- when the subject is "ca". The message is fixed text naming
// nothing but the subject the caller chose, so it is safe to return verbatim.
//
// Submitting a CSR for "ca" is still accepted, as OpenVox Server accepts it: a
// CSR carries the requester's own public key, so nothing here writes a private
// key for it. Managed certificates are refused as well although their keys go
// to their own store rather than private/, so that "ca" means one thing on
// every path that generates a key.
var ErrReservedSubject = errors.New(`the subject "ca" is reserved: this CA does not ` +
	`generate a private key for it, because that key would be written over the CA's own. ` +
	`Choose another certname, or submit a CSR for "ca" instead`)

// CheckKeySubject refuses a subject this CA must not generate a private key
// for. It does not repeat ValidateSubject; callers run both, that one first.
func CheckKeySubject(subject string) error {
	if subject == reservedKeySubject {
		return ErrReservedSubject
	}
	return nil
}
