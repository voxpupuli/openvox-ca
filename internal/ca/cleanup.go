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
	"log/slog"
	"math/big"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// inventoryTimeFormat is the layout the signing path writes NotBefore/NotAfter
// with (see signCSR). It is parsed back here to decide which inventory entries
// have expired. The trailing "UTC" is a literal in the layout (Go's zone token
// is "MST"), so parsing yields a UTC time with the recorded wall-clock digits.
const inventoryTimeFormat = "2006-01-02T15:04:05UTC"

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
// Replica safety: the whole operation runs under the cluster-wide CRL lock, so
// it serialises with Revoke and the CRL refresher across replicas. The inventory
// rewrite itself is atomic per backend (see StorageService.PruneInventory). An
// entry that cannot be time-parsed is conservatively kept, never dropped.
func (c *CA) CleanupExpiredCerts(ctx context.Context, retain time.Duration) (int, error) {
	if retain < 0 {
		retain = 0
	}
	cutoff := time.Now().Add(-retain)

	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()

	var removed int
	err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
		c.mu.Lock()
		defer c.mu.Unlock()

		// Prune the inventory first; the returned entries tell us exactly which
		// serials to drop from the CRL and which caches/blobs to clean up.
		dropped, err := c.Storage.PruneInventory(ctx, func(e storage.InventoryEntry) bool {
			notAfter, perr := time.Parse(inventoryTimeFormat, e.NotAfter)
			if perr != nil {
				slog.Warn("Cleanup: keeping inventory entry with unparseable NotAfter",
					"serial", e.Serial, "subject", e.Subject, "not_after", e.NotAfter, "error", perr)
				return true
			}
			return !notAfter.Before(cutoff)
		})
		if err != nil {
			return err
		}
		if len(dropped) == 0 {
			return nil
		}

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
			delete(c.serialIndex, key)
			delete(c.ocspCache, key)
		}

		if err := c.dropCRLEntriesLocked(ctx, removedSerials); err != nil {
			return err
		}

		// Delete the stored signed cert for each removed subject, but only when
		// the cert still on file carries the expired serial (otherwise the
		// subject has been renewed and the current cert must be preserved).
		for _, e := range dropped {
			c.deleteStoredCertIfSerialMatches(ctx, e.Subject, e.Serial)
		}

		removed = len(dropped)
		return nil
	})
	return removed, err
}

// dropCRLEntriesLocked re-signs the CRL with every revocation entry whose serial
// is in removed filtered out. It is a no-op (no re-sign) when none of the
// removed serials currently appear in the CRL. The cluster CRL lock and c.mu
// must both be held by the caller.
func (c *CA) dropCRLEntriesLocked(ctx context.Context, removed map[string]*big.Int) error {
	crl, err := c.readStoredCRL(ctx)
	if err != nil {
		return err
	}

	kept := make([]x509.RevocationListEntry, 0, len(crl.RevokedCertificateEntries))
	changed := false
	for _, entry := range crl.RevokedCertificateEntries {
		if _, drop := removed[serialHexStr(entry.SerialNumber)]; drop {
			changed = true
			continue
		}
		kept = append(kept, entry)
	}
	if !changed {
		return nil
	}
	return c.signCRLLocked(ctx, crl.Number, kept)
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
