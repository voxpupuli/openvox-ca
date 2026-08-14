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

package storage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Shared scaffolding for the key/value backends that store the inventory as
// decomposed records rather than one append-only blob: etcd (issue #138) and
// Redis/Valkey (issue #139). The two differ entirely in how they commit —
// etcd uses compare-then-op transactions, Redis a server-side Lua script —
// but they agree on what a stored record looks like, on how a legacy blob is
// parsed into records, and on how a serial that cannot be addressed
// one-to-one is marked. Keeping that agreement in one place is not merely
// tidiness: the wire format and the ambiguity sentinel are both on-disk
// contracts, and two copies would be free to drift apart silently.
//
// The SQL backends do not use any of this: they decompose into typed columns
// and get the same properties from the database's own indices.

// serialAmbiguous is the by-serial index value recorded for a serial that
// appears on more than one imported record (possible only in a legacy blob:
// blob backends never had a cluster-wide uniqueness guarantee, and every
// other write path rejects duplicates). A one-to-one index cannot name all
// bearers, so instead of silently aliasing certificate-index writes onto an
// arbitrary record, the sentinel makes them explicit no-ops while still
// keeping the serial reserved against reissue.
const serialAmbiguous = "ambiguous"

// inventoryRecordJSON is the stored JSON form of a CertRecord. The field set
// is spelled out (rather than marshalling CertRecord directly) so the wire
// format is explicit and stable against refactors of the in-memory structs.
type inventoryRecordJSON struct {
	Serial         string            `json:"serial"`
	NotBefore      string            `json:"not_before"`
	NotAfter       string            `json:"not_after"`
	Subject        string            `json:"subject"`
	Fingerprint    string            `json:"fingerprint,omitempty"`
	DNSAltNames    []string          `json:"dns_alt_names,omitempty"`
	AuthExtensions map[string]string `json:"auth_extensions,omitempty"`
	State          string            `json:"state,omitempty"`
	RevokedAt      *time.Time        `json:"revoked_at,omitempty"`
}

func encodeInventoryRecord(rec CertRecord) ([]byte, error) {
	if rec.State == "" {
		rec.State = CertStateSigned
	}
	return json.Marshal(inventoryRecordJSON{
		Serial:         rec.Serial,
		NotBefore:      rec.NotBefore,
		NotAfter:       rec.NotAfter,
		Subject:        rec.Subject,
		Fingerprint:    rec.Fingerprint,
		DNSAltNames:    rec.DNSAltNames,
		AuthExtensions: rec.AuthExtensions,
		State:          rec.State,
		RevokedAt:      rec.RevokedAt,
	})
}

// decodeInventoryRecord is the inverse of encodeInventoryRecord. Unlike the
// SQL row decoder — which can salvage the canonical columns when only the
// projection JSON is corrupt — the whole record shares one JSON value here, so
// an undecodable value is a hard error: there is nothing left to fall back on.
func decodeInventoryRecord(data []byte) (CertRecord, error) {
	var r inventoryRecordJSON
	if err := json.Unmarshal(data, &r); err != nil {
		return CertRecord{}, fmt.Errorf("decoding inventory record: %w", err)
	}
	rec := CertRecord{
		InventoryEntry: InventoryEntry{
			Serial:    r.Serial,
			NotBefore: r.NotBefore,
			NotAfter:  r.NotAfter,
			Subject:   r.Subject,
		},
		CertProjection: CertProjection{
			Fingerprint:    r.Fingerprint,
			DNSAltNames:    r.DNSAltNames,
			AuthExtensions: r.AuthExtensions,
		},
		State:     r.State,
		RevokedAt: r.RevokedAt,
	}
	if rec.State == "" {
		rec.State = CertStateSigned
	}
	return rec, nil
}

// indexedRecord pairs a decoded record with its sequence number — the
// monotonically increasing issuance counter both decomposed backends allocate
// and order their entries by.
type indexedRecord struct {
	seq uint64
	rec CertRecord
}

func entriesOf(recs []indexedRecord) []InventoryEntry {
	entries := make([]InventoryEntry, len(recs))
	for i, r := range recs {
		entries[i] = r.rec.InventoryEntry
	}
	return entries
}

// parseInventoryRecords parses an inventory.txt blob into projection-less
// records. Malformed lines are rejected so a corrupt import fails loudly
// rather than silently dropping entries.
func parseInventoryRecords(data []byte) ([]CertRecord, error) {
	var recs []CertRecord
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, ok := parseInventoryEntry(line)
		if !ok {
			return nil, fmt.Errorf("malformed inventory line %q", line)
		}
		recs = append(recs, CertRecord{InventoryEntry: e, State: CertStateSigned})
	}
	return recs, nil
}

// rejectDuplicateSerials returns ErrDuplicateSerial (wrapped) when two records
// share a serial, mirroring the unique index a SQL import would trip over.
func rejectDuplicateSerials(recs []CertRecord) error {
	seen := make(map[string]bool, len(recs))
	for _, r := range recs {
		if seen[r.Serial] {
			return fmt.Errorf("%w: %s", ErrDuplicateSerial, r.Serial)
		}
		seen[r.Serial] = true
	}
	return nil
}

// duplicateSerials returns each serial that appears on more than one record,
// once, in first-seen order.
func duplicateSerials(recs []CertRecord) []string {
	counts := make(map[string]int, len(recs))
	for _, r := range recs {
		counts[r.Serial]++
	}
	var dups []string
	seen := make(map[string]bool)
	for _, r := range recs {
		if counts[r.Serial] > 1 && !seen[r.Serial] {
			dups = append(dups, r.Serial)
			seen[r.Serial] = true
		}
	}
	return dups
}

// recordsArePrefixOf reports whether the stored entries are exactly the
// import-written prefix of recs: sequence numbers 1..len(entries) carrying the
// same canonical fields. That is the state an interrupted import leaves
// behind (the wipe ran, then some batches committed), and the only state a
// re-run may safely overwrite.
func recordsArePrefixOf(entries []indexedRecord, recs []CertRecord) bool {
	if len(entries) > len(recs) {
		return false
	}
	for i, e := range entries {
		if e.seq != uint64(i)+1 || e.rec.InventoryEntry != recs[i].InventoryEntry {
			return false
		}
	}
	return true
}
