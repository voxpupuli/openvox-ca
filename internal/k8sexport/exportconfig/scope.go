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

package exportconfig

import "encoding/pem"

// PEMBlocks splits a PEM blob into its individual blocks of the given type,
// each still PEM-encoded.
//
// Block boundaries are all the scoping needs, so this deliberately does not
// parse certificates or CRLs: an exporter republishes what the CA already
// validated on the way in, and re-deriving trust decisions here would be a
// second, weaker copy of them.
func PEMBlocks(data []byte, blockType string) [][]byte {
	var out [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != blockType {
			continue
		}
		out = append(out, pem.EncodeToMemory(block))
	}
}

// Scoped selects the part of a PEM chain a scope asks for. An unrecognised
// scope cannot occur after validation; an empty chain passes through untouched
// so the caller's own empty-material guard reports it.
//
// It lives here, beside the scope constants, rather than in either exporter,
// because the Kubernetes and filesystem exporters both publish by scope and
// must agree on what each one selects. Two copies would be two answers, and the
// one that drifted would narrow what a target publishes without anyone asking.
func Scoped(chain []byte, blockType, scope string) []byte {
	// An unset scope means the same thing here as it does in validation: the
	// whole chain. Validation is what normally fills it in, so this only
	// matters for a target assembled in code rather than loaded from
	// configuration -- but the two must not disagree about the default, or a
	// missed Validate() call would silently narrow what a target publishes,
	// which is the failure this feature's default was chosen to avoid.
	if scope == ScopeChain || scope == "" {
		return chain
	}
	blocks := PEMBlocks(chain, blockType)
	if len(blocks) == 0 {
		return chain
	}
	if scope == ScopeRoot {
		return blocks[len(blocks)-1]
	}
	return blocks[0]
}
