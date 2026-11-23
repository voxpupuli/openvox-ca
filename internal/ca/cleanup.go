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

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// CleanupExpiredCerts removes certificates whose NotAfter is older than retain
// ago from the inventory, drops their entries from the CRL, deletes their stored
// signed certificate (when the on-disk cert still has the expired serial, so a
// renewal under the same subject is preserved), and invalidates the in-memory
// serial index and OCSP cache for the removed serials. It reports how many
// certificates were removed.
//
// retain is a grace period measured from each certificate's NotAfter: a cert is
// eligible only once now-retain has passed its expiry. retain may be zero (purge
// as soon as expired); negative values are treated as zero.
//
// Replica safety: each step runs under the cluster-wide CRL lock, so it
// serialises with Revoke and the CRL refresher across replicas, and replicas
// running this at once share a large backlog step by step without pruning any
// entry twice. The inventory rewrite keeps entries and integrity head
// consistent at every observable point, but on backends that prune in batches
// (etcd) it may partially complete on error; the entries PruneInventory returns
// are always exactly the ones removed, so the CRL/blob cleanup below runs even
// when the prune itself reports an error. An entry that cannot be time-parsed
// is conservatively kept, never dropped.
//
// It works in steps of at most sweepStepEntries certificates, each a separate
// acquisition of the CRL lock taken through withCRLLockYielding and held for at
// most sweepStepBudget, plus any CA signature in flight (#347). A revocation in
// this process does not queue behind a step that has not taken the lock, unless
// that step is already waiting on another process, and waits for at most the
// step in progress. One on another replica waits for that step and for any step
// another replica already has queued; locking.md's known gaps say what each of
// those leaves. Each step is complete on its own: what it prunes it also drops
// from the CRL and deletes, so stopping between steps loses nothing, and the
// next pass carries on where this one stopped. ctx ends the pass between steps
// and ends a step's wait for the lock, but never a step that holds it; see
// sweepStep.
func (c *CA) CleanupExpiredCerts(ctx context.Context, retain time.Duration) (int, error) {
	if retain < 0 {
		retain = 0
	}
	cutoff := time.Now().Add(-retain)

	// Every step's prune reads the whole inventory, so an entry it cannot
	// parse would be warned about once a step; once a pass is the signal.
	warned := make(map[string]bool)
	progress := newSweepProgress("Expired-certificate cleanup", "removed")
	var removed int
	for {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		n, more, err := c.cleanupExpiredStep(ctx, cutoff, warned)
		removed += n
		// n == 0 as well as !more: a step that pruned nothing has nothing to
		// show for itself, and taking another would only repeat it.
		if err != nil || !more || n == 0 {
			return removed, err
		}
		progress.step(removed)
		if err := c.pauseBetweenSweepSteps(ctx); err != nil {
			return removed, err
		}
	}
}

// cleanupExpiredStep is one step of CleanupExpiredCerts: it prunes at most
// sweepStepEntries certificates that expired before cutoff, and cleans up after
// exactly the ones it pruned. more reports that it left eligible certificates
// for a further step. warned carries the serials already warned about as
// unparseable across the pass's steps.
func (c *CA) cleanupExpiredStep(parent context.Context, cutoff time.Time,
	warned map[string]bool) (removed int, more bool, err error) {
	limit := c.sweepStepEntries()

	err = c.sweepStep(parent, c.withCRLLockYielding, func(ctx context.Context) error {
		c.mu.Lock()
		defer c.mu.Unlock()

		// The prune gets half of the hold's budget, and the cleanup after it
		// the rest. A prune that runs out of time is exactly when a partial
		// prune is most likely, and the cleanup below must still run for the
		// entries it durably removed. Splitting the budget gives it time to
		// run without holding the lock any longer than the budget, which is
		// what a concurrent revocation waiting on this lock is counting on.
		pruneCtx, cancelPrune := shareOfStep(ctx)
		defer cancelPrune()
		pruneStart := time.Now()

		// Prune the inventory first; the returned entries tell us exactly which
		// serials to drop from the CRL and which caches/blobs to clean up. A
		// batched backend (etcd) may error mid-prune with some entries already
		// durably removed — those are still returned, and they must be cleaned
		// up NOW: the inventory no longer names them, so a later run could
		// never rediscover them and their CRL entries and cert blobs would be
		// orphaned forever. Hold the prune error and surface it at the end.
		//
		// The cap is applied by serial and remembered, rather than counted,
		// because every structured backend calls the predicate again when it
		// retries a prune that lost a race with an append. A counter would
		// already stand at the cap on the retry, keep every entry, and end the
		// pass with nothing removed; a set picks the same entries again.
		selected := make(map[string]bool, limit)
		dropped, pruneErr := c.Storage.PruneInventory(pruneCtx, func(e storage.InventoryEntry) bool {
			notAfter, perr := time.Parse(storage.InventoryTimeFormat, e.NotAfter)
			if perr != nil {
				if !warned[e.Serial] {
					warned[e.Serial] = true
					slog.Warn("Cleanup: keeping inventory entry with unparseable NotAfter",
						"serial", e.Serial, "subject", e.Subject, "not_after", e.NotAfter, "error", perr)
				}
				return true
			}
			if !notAfter.Before(cutoff) {
				return true
			}
			if selected[e.Serial] {
				return false
			}
			if len(selected) >= limit {
				more = true
				return true
			}
			selected[e.Serial] = true
			return false
		})
		if len(dropped) == 0 {
			// A prune that ran out of its share and removed nothing will do so
			// on every later pass too: it reads and verifies the whole
			// inventory however few entries the step takes, and no setting
			// lengthens the share. Say so, or the operator sees only a deadline.
			if errors.Is(pruneErr, context.DeadlineExceeded) && pruneCtx.Err() != nil {
				return fmt.Errorf("the inventory prune ran out of its share of a sweep step after %s; "+
					"every step reads the whole inventory, so the inventory's size, not the backlog, "+
					"is the limit (see docs/configuration.md, enable_expired_cert_cleanup): %w",
					time.Since(pruneStart).Round(time.Millisecond), pruneErr)
			}
			return pruneErr
		}
		// The entries below are durably gone whatever else happens, so report
		// them even if a later cleanup step (or the prune itself) failed —
		// otherwise a partial run logs "failed" with no hint that state
		// changed permanently.
		removed = len(dropped)

		// Collect the removed serials (normalised) and refresh in-memory caches.
		removedSerials := make(map[string]*big.Int, len(dropped))
		for _, e := range dropped {
			n := new(big.Int)
			if _, ok := n.SetString(e.Serial, 16); !ok {
				slog.Warn("Cleanup: malformed serial in pruned inventory entry, skipping CRL/cache cleanup",
					"serial", e.Serial, "subject", e.Subject)
				continue
			}
			key := serialHexStr(n)
			removedSerials[key] = n
			c.unindexSerialLocked(key)
		}

		// A CRL failure must not abort the rest: the "clean up NOW" rule above
		// applies to the cert blobs just as much, and the deletion loop
		// already logs-and-swallows its own per-subject failures.
		crlErr := c.dropCRLEntriesLocked(ctx, removedSerials)

		// Delete the stored signed cert for each removed subject, but only when
		// the cert still on file carries the expired serial (otherwise the
		// subject has been renewed and the current cert must be preserved).
		for _, e := range dropped {
			c.deleteStoredCertIfSerialMatches(ctx, e.Subject, e.Serial)
		}

		return errors.Join(pruneErr, crlErr)
	})
	return removed, more, err
}

// dropCRLEntriesLocked re-signs the CRL with every revocation entry whose serial
// is in removed filtered out. It is a no-op (no re-sign) when none of the
// removed serials currently appear in the CRL. The cluster CRL lock and c.mu
// must both be held by the caller.
func (c *CA) dropCRLEntriesLocked(ctx context.Context, removed map[string]*big.Int) error {
	stored, err := c.readStoredCRL(ctx)
	if err != nil {
		return err
	}

	kept := make([]x509.RevocationListEntry, 0, len(stored.own.RevokedCertificateEntries))
	changed := false
	for _, entry := range stored.own.RevokedCertificateEntries {
		if _, drop := removed[serialHexStr(entry.SerialNumber)]; drop {
			changed = true
			continue
		}
		kept = append(kept, entry)
	}
	if !changed {
		return nil
	}
	return c.signCRLLocked(ctx, stored, kept)
}

// deleteStoredCertIfSerialMatches deletes the signed certificate stored for
// subject only when its serial equals expectSerial (case-insensitive hex match
// via serialHexStr). Failures are logged and swallowed: the inventory/CRL have
// already been updated, and a leftover cert blob is harmless clutter the next
// run will not retry (the inventory entry is gone). The caller must hold c.mu.
func (c *CA) deleteStoredCertIfSerialMatches(ctx context.Context, subject, expectSerial string) {
	certPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		return // no stored cert (or unreadable); nothing to delete
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}
	want := new(big.Int)
	if _, ok := want.SetString(expectSerial, 16); !ok {
		return
	}
	if serialHexStr(cert.SerialNumber) != serialHexStr(want) {
		// Subject was renewed since this entry was issued; keep the current cert.
		return
	}
	if err := c.Storage.DeleteCert(ctx, subject); err != nil {
		slog.Warn("Cleanup: failed to delete expired signed certificate",
			"subject", subject, "serial", expectSerial, "error", err)
	}
}
