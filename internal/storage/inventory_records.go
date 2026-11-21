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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Shared scaffolding for the key/value backends that store the inventory as
// decomposed records rather than one append-only blob: etcd (issue #138) and
// Redis/Valkey (issue #139). The two differ entirely in how they commit —
// etcd uses compare-then-op transactions, Redis a server-side Lua script —
// but they agree on what a stored record looks like, on how inventory.txt
// text is parsed into records, and on how a serial that cannot be addressed
// one-to-one is marked. Keeping that agreement in one place is not merely
// tidiness: the wire format and the ambiguity sentinel are both on-disk
// contracts, and two copies would be free to drift apart silently.
//
// The SQL backends do not use any of this: they decompose into typed columns
// and get the same properties from the database's own indices.

// serialAmbiguous is the by-serial index value recorded for a serial that
// appears on more than one record. Nothing writes it any more: every write
// path rejects duplicates. It was written when a store's single inventory blob
// was converted to per-entry records, as v1.0.0-alpha1 still did on first
// start, and a blob could hold repeats because blob backends never had a
// cluster-wide uniqueness guarantee. Stores converted then keep it, so it is
// still read. A one-to-one index cannot name all bearers, so instead of
// silently aliasing certificate-index writes onto an arbitrary record, the
// sentinel makes them explicit no-ops while still keeping the serial reserved
// against reissue.
const serialAmbiguous = "ambiguous"

// errUndecomposedInventory refuses a key/value store whose inventory marker
// still holds an inventory blob. Builds of main from before v1.0.0-alpha1 kept
// the whole inventory there; v1.0.0-alpha1 converted it to per-entry records
// on first start and left the marker empty, and nothing since writes a payload
// to it. This version no longer converts, and read as the per-entry format
// such a store would look empty, or smaller than it is where a conversion was
// interrupted, so it is refused instead: at startup, on every read of the
// inventory, and by the integrity report.
var errUndecomposedInventory = errors.New("the inventory is still a single blob, " +
	"the format builds of openvox-ca from before v1.0.0-alpha1 wrote, and this version " +
	"reads only the per-entry format; start the store once on v1.0.0-alpha1, which " +
	"converts it, then start this version")

// inventoryRecordJSON is the stored JSON form of a CertRecord. The field set
// is spelled out (rather than marshalling CertRecord directly) so the wire
// format is explicit and stable against refactors of the in-memory structs.
// not_before and not_after hold the formatted inventory.txt strings verbatim,
// not RFC3339 times — see InventoryEntry in backend.go. Every decomposed
// backend must store them identically, or rendering the inventory back to text
// stops being byte-identical to inventory.txt.
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
	// IPAltNames is a pointer so that an absent key and an empty list decode
	// differently: every populated projection writes the key, [] included,
	// and its absence beside a fingerprint marks a record written before the
	// field existed.
	IPAltNames *[]string `json:"ip_alt_names,omitempty"`
	// Fingerprints needs no such marker: a record without it reads as one
	// holding no other digests, not as a missing projection.
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}

func encodeInventoryRecord(rec CertRecord) ([]byte, error) {
	if rec.State == "" {
		rec.State = CertStateSigned
	}
	var ipNames *[]string
	if rec.Fingerprint != "" {
		ips := rec.IPAltNames
		if ips == nil {
			ips = []string{}
		}
		ipNames = &ips
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
		IPAltNames:     ipNames,
		Fingerprints:   rec.Fingerprints,
	})
}

// decodeInventoryRecord is the inverse of encodeInventoryRecord. Unlike the
// SQL row decoder — which can salvage the canonical columns when only the
// projection JSON is corrupt — the whole record shares one JSON value here, so
// an undecodable value is a hard error: there is nothing left to fall back on.
//
// A projection without ip_alt_names predates that field and cannot say whether
// the certificate has IP SANs, so it decodes as no projection at all, as the
// SQL decoder treats its NULL column. A mutation that re-encodes such a record
// (SetRevoked, say) therefore writes it back without its stale projection,
// which leaves it in the state the repair pass backfills.
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
			Fingerprints:   r.Fingerprints,
		},
		State:     r.State,
		RevokedAt: r.RevokedAt,
	}
	if rec.State == "" {
		rec.State = CertStateSigned
	}
	switch {
	case r.IPAltNames != nil && len(*r.IPAltNames) > 0:
		rec.IPAltNames = *r.IPAltNames
	case r.IPAltNames == nil && rec.Fingerprint != "":
		rec.CertProjection = CertProjection{}
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

// renderInventoryText renders records to inventory.txt text, byte-identical to
// what the append-only blob held — the contract the KeyInventory blob shim
// owes Migrate and the OCSP index build on every decomposed backend.
//
// A record set that renders to nothing yields a non-nil empty slice, so a
// touched-but-empty inventory reads as present-but-empty rather than absent,
// matching the blob backends' Get.
func renderInventoryText(recs []indexedRecord) []byte {
	var buf bytes.Buffer
	for _, r := range recs {
		buf.WriteString(canonicalInventoryLine(r.rec.InventoryEntry))
		buf.WriteByte('\n')
	}
	if buf.Len() == 0 {
		return []byte{}
	}
	return buf.Bytes()
}

// latestPerSubject folds recs (in ascending issuance order) to one record per
// subject — the latest issuance wins — keeps only subjects that still hold a
// stored certificate, and returns them in subject order, optionally narrowed
// to stateFilter. This is the semantics of the CertIndex.Statuses contract for
// the backends that cannot push the fold into an indexed query; see that
// contract in backend.go.
//
// ambiguous reports whether a serial's index entry carries the ambiguity
// sentinel. Such records are reported as CertStateUnknown, which tells the
// reader to derive state from the signed CRL instead of trusting a value that
// revocation writes were never able to update. The sentinel, not a live
// duplicate count, is the source of truth: it survives a partial prune, so a
// lone remaining bearer whose writes were refused while it was ambiguous stays
// unknown until the serial is fully released.
func latestPerSubject(recs []indexedRecord, stored map[string]bool, ambiguous func(serial string) bool, stateFilter string) []CertRecord {
	latest := make(map[string]CertRecord, len(recs))
	for _, r := range recs {
		rec := r.rec
		if ambiguous(rec.Serial) {
			rec.State = CertStateUnknown
			rec.RevokedAt = nil
		}
		latest[rec.Subject] = rec
	}

	subjects := make([]string, 0, len(latest))
	for subject := range latest {
		if stored[subject] {
			subjects = append(subjects, subject)
		}
	}
	sort.Strings(subjects)

	records := make([]CertRecord, 0, len(subjects))
	for _, subject := range subjects {
		rec := latest[subject]
		if stateFilter != "" && rec.State != stateFilter {
			continue
		}
		records = append(records, rec)
	}
	return records
}

// pruneBacklogGrowing reports whether a prune's deferred-match count exceeds
// perCall, what one whole call can remove — the signal that, at the current
// cleanup cadence, the backlog is growing rather than draining, which the
// deferral log escalates to a warning. Below that threshold a deferral is
// expected (a one-off backlog draining over several runs) and logs at info.
func pruneBacklogGrowing(deferred, perCall int) bool {
	return deferred > perCall
}
