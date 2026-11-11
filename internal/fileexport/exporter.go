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

package fileexport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/voxpupuli/openvox-ca/internal/k8sexport/exportconfig"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// MaterialSource provides the current CA certificate and CRL in PEM form. It is
// satisfied by *storage.StorageService, and kept narrow so it is easy to fake.
type MaterialSource interface {
	GetCACert(ctx context.Context) ([]byte, error)
	GetCRL(ctx context.Context) ([]byte, error)
}

// Exporter keeps the configured files in step with the CA certificate and CRL
// in storage.
type Exporter struct {
	cfg     Config
	src     MaterialSource
	metrics *Metrics // may be nil (metrics disabled)
}

// New constructs an Exporter. cfg must already have been validated
// (Config.Validate). m may be nil to disable instrumentation.
func New(cfg Config, src MaterialSource, m *Metrics) *Exporter {
	// Publish the sync counters at zero now, so "configured but never
	// succeeded" is a series rather than an absence. See initTargets.
	m.initTargets(cfg.Targets)
	return &Exporter{cfg: cfg, src: src, metrics: m}
}

// SyncAll brings every configured file in line with the current material. It
// reads each material at most once. A failure on one target is logged and
// collected but does not stop the others; the joined error (or nil) is
// returned.
//
// Every target records a result on every call, whatever failed upstream: a
// material that cannot be read fails the targets that asked for it, and the
// per-target loop still runs. A cycle that returned early would leave the stale
// alert's last_success frozen with no last_error beside it to say why.
func (e *Exporter) SyncAll(ctx context.Context) error {
	mats := e.fetchMaterials(ctx)

	var errs []error
	for i := range e.cfg.Targets {
		t := &e.cfg.Targets[i]
		err := mats.forTarget(t)
		if err == nil {
			err = syncTarget(t, mats.pemFor(t))
		}
		e.metrics.recordSync(t, err)
		if err != nil {
			slog.Warn("File export failed for target",
				"path", t.Path, "material", t.Material, "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", t.Path, err))
		}
	}
	return errors.Join(errs...)
}

// materials holds one cycle's cert and CRL PEM alongside the error from reading
// each, so a cert that cannot be read fails only the cert targets.
type materials struct {
	certPEM []byte
	certErr error
	crlPEM  []byte
	crlErr  error
}

// forTarget returns the read error that should fail t, or nil.
func (m *materials) forTarget(t *Target) error {
	if t.Material == MaterialCert {
		return m.certErr
	}
	return m.crlErr
}

// pemFor returns the part of the material t asked for, narrowed by its scope.
func (m *materials) pemFor(t *Target) []byte {
	if t.Material == MaterialCert {
		return exportconfig.Scoped(m.certPEM, "CERTIFICATE", t.Scope)
	}
	return exportconfig.Scoped(m.crlPEM, "X509 CRL", t.Scope)
}

// fetchMaterials reads the cert and CRL PEM, fetching each only if some target
// requires it. A read error is recorded against its material, never returned.
func (e *Exporter) fetchMaterials(ctx context.Context) materials {
	var wantCert, wantCRL bool
	for i := range e.cfg.Targets {
		wantCert = wantCert || e.cfg.Targets[i].Material == MaterialCert
		wantCRL = wantCRL || e.cfg.Targets[i].Material == MaterialCRL
	}

	var m materials
	if wantCert {
		if m.certPEM, m.certErr = e.src.GetCACert(ctx); m.certErr != nil {
			m.certErr = fmt.Errorf("reading CA certificate for export: %w", m.certErr)
		}
	}
	if wantCRL {
		if m.crlPEM, m.crlErr = e.src.GetCRL(ctx); m.crlErr != nil {
			m.crlErr = fmt.Errorf("reading CRL for export: %w", m.crlErr)
		}
	}
	return m
}

// syncTarget makes the file at t.Path hold want, writing it only if it does not
// already.
//
// What is at the path decides what happens:
//
//   - A regular file holding exactly want is left alone -- not rewritten, not
//     touched, its mode and owner whatever the operator made them. Most cycles
//     end here.
//   - A regular file holding anything else, or nothing at the path, is
//     replaced through storage.AtomicWriteFile: a temporary file beside it,
//     created with mode 0644, flushed, and renamed over the path. A reader
//     sees the old file or the new one, never a partial one. The replacement
//     is a new inode, so a mode or owner set by hand on the old file does not
//     carry over; nothing here chmods or chowns a file it did not create.
//   - A symbolic link, dangling or not, is replaced by a regular file, and a
//     warning names where it pointed. Nothing is ever written through a link:
//     rename(2) replaces the link itself. This is the expected case for an
//     operator who has moved off the filesystem backend and points the export
//     at the Puppet-compatible path the packages had linked into the old CA
//     directory.
//   - Anything else -- a directory, a FIFO, a device -- is refused. A FIFO in
//     particular is never opened, since reading one would block this loop.
//
// The parent directory must already exist; nothing here creates one.
//
// The Lstat and the read are two steps, so something swapped in between them
// is read as whatever it is by then. That is not a boundary worth closing:
// whoever can replace files in the operator's export directory can already
// write the copy any consumer reads.
func syncTarget(t *Target, want []byte) error {
	// Never write an empty material. It would replace a still-valid CA
	// certificate or CRL with nothing, which every consumer reads as a failure
	// -- the outcome keeping the old file exists to avoid.
	if len(want) == 0 {
		return fmt.Errorf("refusing to export an empty %s", t.Material)
	}

	info, err := os.Lstat(t.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Nothing there yet: write it.
	case err != nil:
		return fmt.Errorf("checking %s: %w", t.Path, err)
	case info.Mode().IsRegular():
		current, err := sameContent(t.Path, info, want)
		if err != nil {
			return err
		}
		if current {
			return nil
		}
	case info.Mode()&fs.ModeSymlink != 0:
		dest, _ := os.Readlink(t.Path)
		slog.Warn("File export is replacing a symbolic link with a regular file; "+
			"nothing is written through the link",
			"path", t.Path, "link_target", dest)
	default:
		return fmt.Errorf("%s exists and is not a regular file (%s); "+
			"remove it or choose another path", t.Path, info.Mode().Type())
	}

	if err := storage.AtomicWriteFile(t.Path, want, storage.FilePermPublic); err != nil {
		return err
	}
	slog.Info("File export wrote target", "path", t.Path, "material", t.Material, "scope", t.Scope)
	return nil
}

// sameContent reports whether the regular file at path already holds want.
// The size is compared first, so a file of the wrong length -- including one an
// operator pointed this at by mistake, however large -- is never read.
func sameContent(path string, info fs.FileInfo, want []byte) (bool, error) {
	if info.Size() != int64(len(want)) {
		return false, nil
	}
	have, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("reading %s to compare it: %w", path, err)
	}
	return bytes.Equal(have, want), nil
}
