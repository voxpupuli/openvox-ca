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

// Package k8sexport publishes the CA certificate and/or CRL into Kubernetes
// Secrets and ConfigMaps. It is an optional feature: when no targets are
// configured nothing in this package runs. Objects are reconciled with
// server-side apply so each export is an idempotent create-or-update.
//
// The exporter authenticates with the pod's in-cluster ServiceAccount, so it is
// only available when openvox-ca itself runs inside a Kubernetes cluster.
package k8sexport

import "github.com/voxpupuli/openvox-ca/internal/k8sexport/exportconfig"

// The configuration types live in exportconfig, which does not import
// client-go, so that a binary decoding the server's configuration need not link
// it. They are aliased here so this package's callers name them as they always
// have.
type (
	Config   = exportconfig.Config
	Metadata = exportconfig.Metadata
	Target   = exportconfig.Target
)

// Re-exported from exportconfig; see there.
const (
	KindSecret    = exportconfig.KindSecret
	KindConfigMap = exportconfig.KindConfigMap
	ScopeSelf     = exportconfig.ScopeSelf
	ScopeChain    = exportconfig.ScopeChain
	ScopeRoot     = exportconfig.ScopeRoot
)
