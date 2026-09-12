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

package certstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// File modes for the material a file store writes.
//
// The key is readable only by the user running the CA, and the certificate and
// chain are world-readable because they are public.
//
// SECURITY: 0600 means the file store serves a component running as the same
// user as the CA, and only that. Neither group ownership nor a directory ACL
// reaches it -- the group bits are zero, and storage.AtomicWriteFile chmods the
// file to this mode before the rename, which sets an ACL's mask from those same
// zero bits. A chown or chmod applied by hand is discarded at the next renewal,
// because the file is replaced by a new inode rather than rewritten.
//
// A component running as a different user needs a mode or ownership setting
// this store does not have. That is a real limit rather than an oversight, and
// it is stated here and in docs/configuration.md so it is found before a
// deployment depends on it.
// NIST 800-53: AC-6 (Least Privilege), SC-12 (Cryptographic Key Management)
const (
	keyFileMode  fs.FileMode = 0o600
	certFileMode fs.FileMode = 0o644
)

// FileStore keeps a certificate and its private key in a pair of local files,
// optionally alongside the CA certificate chain.
//
// It is the non-Kubernetes shape of a component store, and it exists for a
// reason rather than as a fallback: the bootstrap deadlock described in #189
// applies to a systemd unit as much as to a pod. A CA using an external signer
// or `ca_key_provider: openbao` cannot mint its own serving certificate,
// because `openvox-ca-ctl generate` needs an admin certificate that does not
// exist until the CA is already serving.
//
// # Where it differs from a Secret store, and why
//
// Two differences, both of them properties of a filesystem rather than choices:
//
//   - There is no adoption. A file carries no record of who wrote it, so there
//     is nothing for `adopt_existing` to consult -- which is why that field
//     belongs to the Secret store rather than to the entry. Material already at
//     these paths is read, judged against the spec like any other, and replaced
//     when it does not satisfy it. A certificate this CA did not issue is
//     replaced on that ground alone.
//   - A write is not atomic across the pair. Each file is written to a
//     temporary path and renamed, so no reader ever sees a half-written file --
//     but two renames are two operations, and a reader between them sees one
//     issuance's certificate with another's key. A Secret has no such window,
//     because server-side apply carries all three keys in one request.
//
// The window is bounded and self-healing rather than harmless. A mismatched
// pair fails every handshake made against it, and a component that loaded one
// has to be restarted or told to reload; but the store is left holding a
// coherent pair, because the last rename completes microseconds later. A crash
// between the two renames leaves a mismatch that the next reconcile pass sees
// as a key that is not the certificate's, and replaces.
//
// The certificate is renamed last, deliberately. A component watching this
// directory for a renewal almost always watches the certificate -- it is the
// file with an expiry -- so landing it last means the watcher fires on a pair
// that is already complete.
type FileStore struct {
	cfg     FilesConfig
	caCerts CACertSource
}

// NewFileStore builds a store for one certificate.
func NewFileStore(cfg FilesConfig, caCerts CACertSource) *FileStore {
	return &FileStore{cfg: cfg, caCerts: caCerts}
}

// String names the store for a log line or an error.
func (f *FileStore) String() string { return fmt.Sprintf("the file pair at %s", f.cfg.Cert) }

// Load reads the stored certificate and key.
//
// An absent file is not an error: absent material is an input to the reconcile
// decision, and reporting it as a failure would stop the very pass that writes
// it. Any other read failure is an error and stops this entry for this pass,
// because reconciling against material we could not read would reissue on every
// pass for as long as the filesystem is unhappy.
func (f *FileStore) Load(_ context.Context) (certPEM, keyPEM []byte, err error) {
	certPEM, err = readIfPresent(f.cfg.Cert)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = readIfPresent(f.cfg.Key)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// readIfPresent reads path, returning no content and no error when it does not
// exist.
func readIfPresent(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}

// Save writes the key, the CA chain if one is configured, and the certificate,
// each atomically and in that order.
//
// The directories must already exist. This store will not create them, and that
// is deliberate: one of these files is a private key, so who may read the
// directory holding it is a decision for whoever lays the deployment out. A
// store that created a missing directory would have to guess a mode, and the
// question it would be guessing at -- which users other than the CA's own may
// traverse a directory holding a private key -- is one only whoever lays the
// deployment out can answer. Failing names the directory instead, and the next
// pass retries once it exists.
func (f *FileStore) Save(ctx context.Context, certPEM, keyPEM []byte) error {
	// Read before anything is written, so a chain we cannot read fails the
	// write rather than leaving a new certificate beside a stale chain.
	var caPEM []byte
	if f.cfg.CA != "" {
		var err error
		caPEM, err = f.caCerts.GetCACert(ctx)
		if err != nil {
			return fmt.Errorf("reading the CA certificate chain for %s: %w", f, err)
		}
		if len(caPEM) == 0 {
			return fmt.Errorf("refusing to write an empty CA certificate chain to %s", f.cfg.CA)
		}
	}

	for _, path := range f.paths() {
		if err := checkDir(path); err != nil {
			return err
		}
	}

	// The key first: it is the file whose absence makes a certificate useless,
	// and on a first write the certificate should never be the thing that
	// exists alone.
	if err := storage.AtomicWriteFile(f.cfg.Key, keyPEM, keyFileMode); err != nil {
		return err
	}
	if f.cfg.CA != "" {
		if err := storage.AtomicWriteFile(f.cfg.CA, caPEM, certFileMode); err != nil {
			return err
		}
	}
	// Last, so a watcher that fires on the certificate sees a complete pair.
	return storage.AtomicWriteFile(f.cfg.Cert, certPEM, certFileMode)
}

// paths returns the files this store writes, in no particular order.
func (f *FileStore) paths() []string {
	paths := []string{f.cfg.Key, f.cfg.Cert}
	if f.cfg.CA != "" {
		paths = append(paths, f.cfg.CA)
	}
	return paths
}

// checkDir reports a missing or unusable parent directory as this entry's
// failure, naming the directory.
//
// Checked before the first write rather than discovered at the second: a
// certificate whose key landed and whose chain did not is a worse state to
// leave behind than a pass that wrote nothing, and the two files usually share
// a directory, so one bad path would otherwise be found halfway through.
func checkDir(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("the directory for %s does not exist: create %s with the "+
			"ownership and mode the component needs, since it will hold a private key",
			path, dir)
	}
	if err != nil {
		return fmt.Errorf("checking the directory for %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("the directory for %s is not a directory: %s", path, dir)
	}
	return nil
}
