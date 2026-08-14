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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// SHA256ColonFingerprint renders the SHA-256 digest of der as colon-separated
// hex pairs, the form Puppet displays certificate fingerprints in. It is the
// single producer of the fingerprint stored in the certificate index and
// emitted by the status API, so the two can never disagree on format.
func SHA256ColonFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	raw := hex.EncodeToString(sum[:])
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(raw); i += 2 {
		parts = append(parts, raw[i:i+2])
	}
	return strings.Join(parts, ":")
}

// certProjectionFor derives the certificate-index display projection from a
// parsed certificate. Every field is immutable for the certificate's life,
// which is what makes storing them alongside the inventory row safe: they can
// never drift from the PEM because neither can change after signing.
func certProjectionFor(cert *x509.Certificate) storage.CertProjection {
	return storage.CertProjection{
		Fingerprint:    SHA256ColonFingerprint(cert.Raw),
		DNSAltNames:    cert.DNSNames,
		AuthExtensions: AuthExtensionMap(cert.Extensions),
	}
}

// rebuildCertIndex reconciles the certificate index with its authoritative
// sources: stored certificate PEMs (for the display projection) and the
// in-memory CRL cache (for revocation state). It is a no-op on backends
// without the CertIndex capability, cheap when the index is already in sync,
// and safe to re-run at every startup — the index is a projection, and this
// is the repair path that makes that claim honest. Rows are touched only when
// they disagree with the artefacts:
//
//   - a record missing its projection (typically imported from a legacy
//     inventory blob, where rows carry no display fields) is backfilled by
//     parsing the subject's stored PEM once;
//   - a record whose revocation state disagrees with the signed CRL is
//     rewritten to match it.
//
// Only records the index can ever serve (the latest issuance per subject with
// a stored certificate) are reconciled; historical rows are invisible to
// Statuses, so their staleness is harmless. Failures are logged and skipped
// rather than propagated: a partially repaired index still degrades
// gracefully, because readers fall back to the PEM for any record left
// without a projection. c.mu must be held by the caller (for cachedCRL).
func (c *CA) rebuildCertIndex(ctx context.Context) {
	records, ok, err := c.Storage.CertStatuses(ctx, "")
	if !ok {
		return
	}
	if err != nil {
		slog.Warn("Certificate index repair: listing index records failed", "error", err)
		return
	}

	revoked := c.revokedSerialsLocked()

	// The backfill reads and parses one stored PEM per projection-less record,
	// so the first start after a blob→SQL migration legitimately takes a while
	// on a large fleet. Announce the work up front and report progress, so the
	// operator watching that first start sees a moving backfill rather than an
	// apparent hang between "Loaded existing CA" and the listener coming up.
	var missing int
	for _, rec := range records {
		if rec.Fingerprint == "" && rec.State != storage.CertStateUnknown {
			missing++
		}
	}
	if missing > 0 {
		slog.Info("Certificate index repair: backfilling projections from stored certificates",
			"records", missing)
	}

	const progressEvery = 1000
	var projected, restated int
	for i, rec := range records {
		// The backfill is one stored-PEM read and one row write per record, so on
		// a large fleet this pass runs for minutes -- and it inherits whatever
		// budget Init had, which on the lost-bootstrap-race path is the 60-second
		// bootstrap-lock timeout. Without this check a cancelled context produced
		// one warning per remaining record, burying the cause under thousands of
		// lines, and then reported "Certificate index repaired" for a pass that
		// had done a quarter of the work.
		if err := ctx.Err(); err != nil {
			slog.Warn("Certificate index repair interrupted; the next start resumes it",
				"records_done", i, "records_total", len(records),
				"projections_backfilled", projected, "states_corrected", restated,
				"error", err)
			return
		}
		if rec.State == storage.CertStateUnknown {
			// The backend cannot address this record's serial one-to-one
			// (duplicated legacy serial on etcd/redis): index writes for it are
			// refused, so backfill and reconciliation can never converge.
			// Readers derive its state from the CRL instead; skip it rather
			// than re-attempt and warn on every start.
			continue
		}
		if rec.Fingerprint == "" && c.backfillCertProjection(ctx, rec) {
			projected++
			if projected%progressEvery == 0 {
				slog.Info("Certificate index repair: backfill progress",
					"done", projected, "total", missing)
			}
		}

		// Serials are stored verbatim as issued; normalise through big.Int for
		// the CRL comparison so legacy zero-padded forms still match, but keep
		// the verbatim form for the row update.
		n := new(big.Int)
		if _, ok := n.SetString(rec.Serial, 16); !ok {
			slog.Warn("Certificate index repair: malformed serial in index record",
				"subject", rec.Subject, "serial", rec.Serial)
			continue
		}
		revokedAt, inCRL := revoked[serialHexStr(n)]
		switch {
		case inCRL && rec.State != storage.CertStateRevoked:
			if err := c.Storage.MarkCertRevoked(ctx, rec.Serial, revokedAt); err != nil {
				slog.Warn("Certificate index repair: marking record revoked failed",
					"subject", rec.Subject, "serial", rec.Serial, "error", err)
			} else {
				restated++
			}
		case !inCRL && rec.State == storage.CertStateRevoked:
			if err := c.Storage.ClearCertRevoked(ctx, rec.Serial); err != nil {
				slog.Warn("Certificate index repair: clearing stale revocation failed",
					"subject", rec.Subject, "serial", rec.Serial, "error", err)
			} else {
				restated++
			}
		}
	}
	if projected > 0 || restated > 0 {
		slog.Info("Certificate index repaired",
			"projections_backfilled", projected, "states_corrected", restated)
	}
}

// RevokedSerials returns the CRL's revocations as normalised serial → revocation
// time, built once from the cached CRL.
//
// Exported because the certificate-index read path needs the same answer the
// repair pass needs, and needs it for a whole page of records: one pass over the
// CRL plus a map lookup per record, rather than a linear scan of the CRL per
// record. Taking the state from the index row instead would be cheaper still and
// is what the handler used to do -- but the row is a projection that a swallowed
// write can leave behind, and the CRL is the signed fact.
func (c *CA) RevokedSerials() map[string]time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.revokedSerialsLocked()
}

// revokedSerialsLocked is RevokedSerials for a caller that already holds c.mu.
// Init does, for the whole of itself, and the repair pass runs inside it -- so
// taking the read lock there would deadlock, sync.RWMutex being non-reentrant.
func (c *CA) revokedSerialsLocked() map[string]time.Time {
	revoked := make(map[string]time.Time)
	if c.cachedCRL != nil {
		for _, entry := range c.cachedCRL.RevokedCertificateEntries {
			revoked[serialHexStr(entry.SerialNumber)] = entry.RevocationTime
		}
	}
	return revoked
}

// backfillCertProjection fills rec's missing display projection from the
// subject's stored PEM, reporting whether it did. The PEM must carry rec's
// serial: a mismatch means the row does not describe the stored certificate
// (e.g. a crash window between blob and inventory writes) and is left alone
// rather than stamped with another certificate's fields.
func (c *CA) backfillCertProjection(ctx context.Context, rec storage.CertRecord) bool {
	certPEM, err := c.Storage.GetCert(ctx, rec.Subject)
	if err != nil {
		slog.Warn("Certificate index repair: reading stored certificate failed",
			"subject", rec.Subject, "error", err)
		return false
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		slog.Warn("Certificate index repair: stored certificate is not PEM", "subject", rec.Subject)
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		slog.Warn("Certificate index repair: parsing stored certificate failed",
			"subject", rec.Subject, "error", err)
		return false
	}

	recSerial := new(big.Int)
	if _, ok := recSerial.SetString(rec.Serial, 16); !ok {
		return false
	}
	if recSerial.Cmp(cert.SerialNumber) != 0 {
		slog.Warn("Certificate index repair: stored certificate serial does not match index record, leaving projection empty",
			"subject", rec.Subject, "index_serial", rec.Serial, "cert_serial", serialHexStr(cert.SerialNumber))
		return false
	}

	if err := c.Storage.SetCertProjection(ctx, rec.Serial, certProjectionFor(cert)); err != nil {
		slog.Warn("Certificate index repair: writing projection failed",
			"subject", rec.Subject, "serial", rec.Serial, "error", err)
		return false
	}
	return true
}
