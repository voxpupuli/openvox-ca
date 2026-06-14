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
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

// sqlInventoryRow is one issued-certificate record in the structured inventory
// table. id is an autoincrement surrogate key that also defines issuance order,
// which drives both the rendered inventory.txt ordering and the integrity hash
// chain. NotBefore/NotAfter are stored verbatim as the formatted strings the
// signing path produces so that rendering is byte-identical to the legacy blob.
type sqlInventoryRow struct {
	bun.BaseModel `bun:"table:puppet_ca_inventory,alias:inv"`

	ID        int64  `bun:"id,pk,autoincrement"`
	Serial    string `bun:"serial,notnull,type:varchar(128)"`
	Subject   string `bun:"subject,notnull,type:varchar(512)"`
	NotBefore string `bun:"not_before,notnull,type:varchar(64)"`
	NotAfter  string `bun:"not_after,notnull,type:varchar(64)"`
}

func inventoryRowFromEntry(e InventoryEntry) *sqlInventoryRow {
	return &sqlInventoryRow{
		Serial:    e.Serial,
		Subject:   e.Subject,
		NotBefore: e.NotBefore,
		NotAfter:  e.NotAfter,
	}
}

func (r sqlInventoryRow) entry() InventoryEntry {
	return InventoryEntry{
		Serial:    r.Serial,
		NotBefore: r.NotBefore,
		NotAfter:  r.NotAfter,
		Subject:   r.Subject,
	}
}

// SQLBackend implements InventoryStore: the certificate inventory lives in the
// puppet_ca_inventory table rather than a single KeyInventory blob. The
// KeyInventory row in puppet_ca_blobs is kept only as an empty presence marker
// recording that the inventory has been initialised (TouchInventory), so that
// Exists/HasInventory report true for a touched-but-empty inventory. The
// integrity head stays in the KeyInventoryHMAC blob row, advanced by a hash
// chain (see StorageService.AppendInventory).
var _ InventoryStore = (*SQLBackend)(nil)

// AppendEntry inserts e and advances the integrity head atomically. The whole
// operation runs in one transaction that locks the presence-marker row, so
// concurrent appenders — including separate replicas — serialise and the hash
// chain cannot fork. newHead is invoked inside that transaction with the
// current head (nil when none); a nil newHead means integrity is disabled and
// the stored head is left untouched.
func (b *SQLBackend) AppendEntry(ctx context.Context, e InventoryEntry, newHead func(prev []byte) []byte) error {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	const maxAttempts = 10
	for attempt := 0; ; attempt++ {
		err := b.appendEntryOnce(ctx, e, newHead)
		if err == nil {
			return nil
		}
		if attempt+1 >= maxAttempts || !isRetryableSQLError(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 5 * time.Millisecond):
		}
	}
}

func (b *SQLBackend) appendEntryOnce(ctx context.Context, e InventoryEntry, newHead func(prev []byte) []byte) error {
	return b.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Lock the presence marker (created by TouchInventory during bootstrap)
		// to serialise appends across replicas before reading the head. On the
		// rare first append with no prior touch the marker is absent and no row
		// is locked; appendMu still serialises within this process, and CA
		// bootstrap is guarded by the distributed "bootstrap" lock.
		if _, err := b.blobDataTx(ctx, tx, KeyInventory, true); err != nil {
			return err
		}

		if _, err := tx.NewInsert().Model(inventoryRowFromEntry(e)).Exec(ctx); err != nil {
			return err
		}

		if newHead != nil {
			prev, err := b.blobDataTx(ctx, tx, KeyInventoryHMAC, false)
			if err != nil {
				return err
			}
			if err := b.upsert(ctx, tx, &sqlBlob{
				Key:        KeyInventoryHMAC,
				Data:       newHead(prev),
				Kind:       int(BlobPrivate),
				ModifiedAt: time.Now(),
			}); err != nil {
				return err
			}
		}

		// Ensure the presence marker exists and bump its mtime.
		return b.upsert(ctx, tx, &sqlBlob{
			Key:        KeyInventory,
			Data:       []byte{},
			Kind:       int(BlobPrivate),
			ModifiedAt: time.Now(),
		})
	})
}

// Entries returns every inventory entry in issuance order.
func (b *SQLBackend) Entries(ctx context.Context) ([]InventoryEntry, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	var rows []sqlInventoryRow
	if err := b.db.NewSelect().Model(&rows).Order("id ASC").Scan(ctx); err != nil {
		return nil, err
	}
	entries := make([]InventoryEntry, len(rows))
	for i, r := range rows {
		entries[i] = r.entry()
	}
	return entries, nil
}

// LatestSerialForSubject returns the most recently issued serial for subject,
// wrapping fs.ErrNotExist when the subject has no entry.
func (b *SQLBackend) LatestSerialForSubject(ctx context.Context, subject string) (string, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	row := new(sqlInventoryRow)
	err := b.db.NewSelect().
		Model(row).
		Column("serial").
		Where("subject = ?", subject).
		Order("id DESC").
		Limit(1).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", &fs.PathError{Op: "latest-serial", Path: subject, Err: fs.ErrNotExist}
		}
		return "", err
	}
	return row.Serial, nil
}

// PruneEntries removes the rows for which keep returns false and rewrites the
// integrity head over the survivors in a single transaction, so a concurrent
// reader on another replica never observes the rows and the chained head out of
// sync. Survivors keep their original ids (and thus issuance order); only the
// dropped rows are deleted. The presence-marker row is locked first so this
// serialises with AppendEntry across replicas, exactly as appends do.
func (b *SQLBackend) PruneEntries(ctx context.Context, keep func(InventoryEntry) bool, recomputeHead func(survivors []InventoryEntry) []byte) ([]InventoryEntry, error) {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	const maxAttempts = 10
	for attempt := 0; ; attempt++ {
		removed, err := b.pruneEntriesOnce(ctx, keep, recomputeHead)
		if err == nil {
			return removed, nil
		}
		if attempt+1 >= maxAttempts || !isRetryableSQLError(err) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 5 * time.Millisecond):
		}
	}
}

func (b *SQLBackend) pruneEntriesOnce(ctx context.Context, keep func(InventoryEntry) bool, recomputeHead func(survivors []InventoryEntry) []byte) ([]InventoryEntry, error) {
	var removed []InventoryEntry
	err := b.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		removed = nil // reset so a retried transaction does not double-count

		// Lock the presence marker to serialise with appends before reading rows.
		if _, err := b.blobDataTx(ctx, tx, KeyInventory, true); err != nil {
			return err
		}

		var rows []sqlInventoryRow
		if err := tx.NewSelect().Model(&rows).Order("id ASC").Scan(ctx); err != nil {
			return err
		}

		survivors := make([]InventoryEntry, 0, len(rows))
		var removeIDs []int64
		for _, r := range rows {
			e := r.entry()
			if keep(e) {
				survivors = append(survivors, e)
			} else {
				removed = append(removed, e)
				removeIDs = append(removeIDs, r.ID)
			}
		}
		if len(removeIDs) == 0 {
			return nil
		}

		if _, err := tx.NewDelete().Model((*sqlInventoryRow)(nil)).Where("id IN (?)", bun.List(removeIDs)).Exec(ctx); err != nil {
			return err
		}

		if recomputeHead != nil {
			return b.upsert(ctx, tx, &sqlBlob{
				Key:        KeyInventoryHMAC,
				Data:       recomputeHead(survivors),
				Kind:       int(BlobPrivate),
				ModifiedAt: time.Now(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// --- KeyInventory blob shim ---
//
// A structured backend must still serve the KeyInventory logical key through
// Get/Put/Exists/AppendLine so that Migrate and the OCSP index build remain
// backend-agnostic. These helpers render rows to inventory.txt text and parse
// text back to rows; Get/Put/Exists/Delete/AppendLine in sql.go dispatch to
// them when key == KeyInventory.

// getInventory renders the inventory table to byte-identical inventory.txt
// text. It returns fs.ErrNotExist when the inventory has never been
// initialised (no presence marker), matching the filesystem backend.
func (b *SQLBackend) getInventory(ctx context.Context) ([]byte, error) {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	exists, err := b.db.NewSelect().Model((*sqlBlob)(nil)).Where("blob_key = ?", KeyInventory).Exists(ctx)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, &fs.PathError{Op: "get", Path: KeyInventory, Err: fs.ErrNotExist}
	}

	var rows []sqlInventoryRow
	if err := b.db.NewSelect().Model(&rows).Order("id ASC").Scan(ctx); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, r := range rows {
		buf.WriteString(canonicalInventoryLine(r.entry()))
		buf.WriteByte('\n')
	}
	// Normalise to a non-nil empty slice so a touched-but-empty inventory reads
	// as present-but-empty, not absent (matching the blob backends' Get).
	if buf.Len() == 0 {
		return []byte{}, nil
	}
	return buf.Bytes(), nil
}

// putInventory replaces the entire inventory with the entries parsed from data
// (an inventory.txt blob) and sets the presence marker. Used by TouchInventory
// (empty data) and by Migrate when importing into a structured backend. The
// integrity head is not touched here: Migrate recomputes it afterwards, and
// TouchInventory writes an empty inventory whose baseline head is established on
// first verification.
func (b *SQLBackend) putInventory(ctx context.Context, data []byte) error {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	return b.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewDelete().Model((*sqlInventoryRow)(nil)).Where("1 = 1").Exec(ctx); err != nil {
			return err
		}
		if err := insertInventoryLines(ctx, tx, data); err != nil {
			return err
		}
		return b.upsert(ctx, tx, &sqlBlob{
			Key:        KeyInventory,
			Data:       []byte{},
			Kind:       int(BlobPrivate),
			ModifiedAt: time.Now(),
		})
	})
}

// appendInventoryLines appends the entries parsed from data as new rows and
// ensures the presence marker exists, without touching the integrity head.
// StorageService routes inventory appends through AppendEntry, so this only
// runs if a caller invokes Backend.AppendLine(KeyInventory, ...) directly.
func (b *SQLBackend) appendInventoryLines(ctx context.Context, data []byte) error {
	b.appendMu.Lock()
	defer b.appendMu.Unlock()

	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	return b.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := insertInventoryLines(ctx, tx, data); err != nil {
			return err
		}
		return b.upsert(ctx, tx, &sqlBlob{
			Key:        KeyInventory,
			Data:       []byte{},
			Kind:       int(BlobPrivate),
			ModifiedAt: time.Now(),
		})
	})
}

// deleteInventory removes all entries and the presence marker, wrapping
// fs.ErrNotExist when the inventory was never initialised.
func (b *SQLBackend) deleteInventory(ctx context.Context) error {
	ctx, cancel := b.callCtx(ctx)
	defer cancel()

	return b.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		res, err := tx.NewDelete().Model((*sqlBlob)(nil)).Where("blob_key = ?", KeyInventory).Exec(ctx)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return &fs.PathError{Op: "delete", Path: KeyInventory, Err: fs.ErrNotExist}
		}
		_, err = tx.NewDelete().Model((*sqlInventoryRow)(nil)).Where("1 = 1").Exec(ctx)
		return err
	})
}

// insertInventoryLines parses an inventory.txt blob and inserts one row per
// non-blank line, in order. Malformed lines are rejected so a corrupt import
// fails loudly rather than silently dropping records.
func insertInventoryLines(ctx context.Context, tx bun.Tx, data []byte) error {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, ok := parseInventoryEntry(line)
		if !ok {
			return fmt.Errorf("malformed inventory line %q", line)
		}
		if _, err := tx.NewInsert().Model(inventoryRowFromEntry(e)).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// blobDataTx reads a blob's data within tx, returning nil when the row is
// absent. When forUpdate is set (and the dialect supports row locks) it takes a
// FOR UPDATE lock so concurrent transactions serialise on the row.
func (b *SQLBackend) blobDataTx(ctx context.Context, tx bun.Tx, key string, forUpdate bool) ([]byte, error) {
	row := new(sqlBlob)
	q := tx.NewSelect().Model(row).Column("data").Where("blob_key = ?", key)
	if forUpdate && b.db.Dialect().Name() != dialect.SQLite {
		q = q.For("UPDATE")
	}
	switch err := q.Scan(ctx); {
	case err == nil:
		return row.Data, nil
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	default:
		return nil, err
	}
}
