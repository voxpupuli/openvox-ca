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

// Package constants holds identifiers that more than one package must spell
// identically. It imports nothing, so any package can depend on it without
// taking on the rest of the tree.
package constants

// MetricsNamespace is the Prometheus namespace every openvox-ca metric is
// registered under, so each series is exported as openvoxca_<subsystem>_<name>.
// It is an operator-facing contract: dashboards, recording rules and the
// shipped mixin's alerts all match on it.
const MetricsNamespace = "openvoxca"
