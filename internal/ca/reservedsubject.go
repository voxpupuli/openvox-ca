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
// for. A key the server keeps for subject S is written to
// <cadir>/private/S_key.pem whatever the storage backend, so the key for "ca"
// would land on private/ca_key.pem: a leaf key under the CA key's own file
// name, which an operator or a backup script could easily take for the CA key
// (#495). Nothing reads it as the CA key, but the reservation costs one
// certname, and lifting it later breaks nobody where adding it back would.
const reservedKeySubject = "ca"

// ErrReservedSubject is returned by every path that generates a private key
// for a subject -- POST /generate, offline `openvox-ca generate`, and managed
// certificates -- when the subject is "ca". The message is fixed text naming
// nothing but the subject the caller chose, so it is safe to return verbatim.
//
// Only two of them would write that file: POST /generate, and offline generate
// without --key-out. The others are refused as
// well, so that "ca" means one thing on every path that generates a key, and
// the message therefore says why the name is reserved rather than what this
// particular request would have done.
//
// Submitting a CSR for "ca" is still accepted, as OpenVox Server accepts it: a
// CSR carries the requester's own public key, so nothing here writes a private
// key for it. That remedy is left to the documentation, because it does not
// fit a managed certificate, which never involves a CSR.
var ErrReservedSubject = errors.New(`the subject "ca" is reserved: this CA generates ` +
	`no private key for it, because the server's key file for "ca" would be ` +
	`private/ca_key.pem, which is easily mistaken for the CA's own key. ` +
	`Choose another certname`)

// CheckKeySubject refuses a subject this CA must not generate a private key
// for. It does not repeat ValidateSubject: "ca" passes that check, and a
// subject that fails it is refused there by every caller that generates a key.
func CheckKeySubject(subject string) error {
	if subject == reservedKeySubject {
		return ErrReservedSubject
	}
	return nil
}
