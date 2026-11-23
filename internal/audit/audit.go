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

// Package audit names the audit events openvox-ca logs.
//
// An audit record is an ordinary log record that carries an `event` attribute.
// Its message text is for a human and may be reworded in any release; the
// event value, and the attributes documented beside it, are what an operator
// matches on, and from 1.0.0 they change only in a major release. The set is
// closed: docs/configuration.md#audit-events lists every value, and a value
// emitted anywhere else is a value that table is missing.
//
// Names use the `<subject>.<action>` grammar the webhook event types share, so
// one convention covers both.
//
// The package imports nothing of openvox-ca's, so every process that logs one
// can name it: the frontend, the isolated signer and the offline
// `openvox-ca generate` alike. None of them needs a metrics endpoint or a
// webhook to emit one.
package audit

import "log/slog"

// Key is the attribute an audit record carries its event name under.
const Key = "event"

const (
	// CertificateAuthGrantIssued is a certificate issued carrying a Puppet
	// authorisation extension (pp_cli_auth and its kin): a CA administrator
	// credential minted by `openvox-ca generate`, or one carried forward by a
	// renewal. One record per grant. Attributes: subject, grant, and on a
	// renewal, renewal ("same key" or "re-key").
	CertificateAuthGrantIssued = "certificate.auth_grant_issued"

	// SignerRequestRefused is a signing request the isolated signer refused
	// because it asked for a signature the CA never makes. The frontend never
	// builds one, so it means a frontend that is broken or no longer ours.
	// Attributes: error.
	SignerRequestRefused = "signer.request_refused"
)

// Event returns the attribute that makes a log record the audit record for
// name.
func Event(name string) slog.Attr {
	return slog.String(Key, name)
}
