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

// Package fileexport keeps local copies of the CA certificate and CRL current,
// for a consumer on the same host that reads them from a file -- an OpenVox
// Server compiler, or anything else configured with a `localcacert` and a
// `hostcrl`. It is optional: when no targets are configured nothing in this
// package runs.
//
// It exists for the deployments that have no such file already. With the
// filesystem backend the CA's own directory holds a CRL that is current by
// construction, and the packages link the Puppet-compatible paths into it.
// PostgreSQL, MySQL, etcd and Redis have no directory to link to.
//
// # Freshness
//
// A stale CRL is worse than no CRL: Puppet's default certificate_revocation =
// chain fails closed once the copy it holds passes its NextUpdate. So the
// exporter does not wait to be told something changed. Every interval it reads
// the current material from storage and compares it with each file, rewriting
// only the files that differ. That covers a revocation made by this process, a
// revocation made by another replica (which this process's CRL-update channel
// deliberately does not hear about), a CA bundle change, and a file someone
// else overwrote.
//
// A file that cannot be written is left exactly as it was. Removing it would
// make the consumer fail closed at once rather than when the old CRL expires,
// which on the default 30-day validity is days away. The
// last_success_timestamp_seconds gauge, stamped every time a target is
// confirmed current, is what OpenVoxCAFileExportStale alerts on.
package fileexport

import "github.com/voxpupuli/openvox-ca/internal/fileexport/fileexportconfig"

// The configuration types live in fileexportconfig so that internal/config can
// declare the block without importing this package. They are aliased here so
// callers can name them from either.
type (
	Config = fileexportconfig.Config
	Target = fileexportconfig.Target
)

// Re-exported from fileexportconfig; see there. Only the names this package and
// its callers use: the other scopes are fileexportconfig's to name.
const (
	MaterialCert = fileexportconfig.MaterialCert
	MaterialCRL  = fileexportconfig.MaterialCRL
	ScopeChain   = fileexportconfig.ScopeChain
)
