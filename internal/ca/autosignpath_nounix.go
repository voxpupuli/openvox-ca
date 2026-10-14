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

//go:build !unix

package ca

import "os"

// fileOwner cannot read an owner on this platform, so every entry on an
// autosign executable's path is reported, and the operator has to opt out to
// run one at all.
func fileOwner(os.FileInfo) (uint32, bool) { return 0, false }

// fileLinks cannot read a link count on this platform, so no directory is
// taken for a kubelet volume.
func fileLinks(os.FileInfo) (uint64, bool) { return 0, false }
