// Copyright (C) 2026 Chris Boot
// Copyright (C) 2026 Trevor Vaughan
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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// File permissions used by the filesystem backend. Exposed because callers
// that still reach directly into the filesystem (tests, migration helpers)
// need to match them.
const (
	FilePermPrivate = 0600
	FilePermPublic  = 0644
	DirPerm         = 0750
)

// fsLockDir is the cadir subdirectory holding same-host lock files. It sits
// beside signed/, requests/ and private/ rather than inside one of them: the
// files are neither CA material nor request material, and a name a migration or
// a backup script already knows to skip is easier to reason about than one
// hidden among keys. Nothing lists or copies it — List serves only the
// requests/ and signed/ prefixes, and a store migration moves logical keys.
const fsLockDir = "locks"

// fsLayout maps logical keys to paths relative to the backend's baseDir.
// Keys of the form "csr/<subject>" and "cert/<subject>" are handled
// explicitly in pathFor, as is KeyCAKey, which caKeyLocation resolves (a fresh
// cadir gets fsCAKeyPath).
var fsLayout = map[string]string{
	KeyCACert:        "ca_crt.pem",
	KeyCAPubKey:      "ca_pub.pem",
	KeyCRL:           "ca_crl.pem",
	KeySerial:        "serial",
	KeyInventory:     "inventory.txt",
	KeyInventoryHMAC: ".inventory.hmac",
	KeyHMACKey:       "private/.inventory_hmac_key",
	KeySuperseded:    "superseded.json",
}

// fsCAKeyPath is where OpenVox Server keeps its CA key, and so where this
// backend keeps it: a cadir handed back to OpenVox Server has to have the key
// where it looks. fsLegacyCAKeyPath is where this backend kept it before, and a
// cadir with the key only there goes on using it there. See caKeyLocation.
const (
	fsCAKeyPath       = "ca_key.pem"
	fsLegacyCAKeyPath = "private/ca_key.pem"
)

// ErrCAKeyConflict is returned for every CA key operation on a cadir holding
// both ca_key.pem and private/ca_key.pem with different contents. Either could
// be the key this CA signs with, and picking one would sign with a key the
// operator may not have meant, or hand OpenVox Server one this CA never used.
var ErrCAKeyConflict = errors.New("two different CA keys in the cadir")

// ErrCAKeyLinkBroken is returned for a CA key file that is a symlink leading
// nowhere. It deliberately does not wrap fs.ErrNotExist: callers read that as
// "no key here" (migrate skips the key, Init takes the no-key branches), and a
// link where the key belongs is a key that is meant to be there.
var ErrCAKeyLinkBroken = errors.New("the CA key file is a link that leads nowhere")

// FilesystemBackend stores blobs as files under a single base directory.
// It is the default Backend implementation. It keeps OpenVox Server's own CA
// directory layout and inventory line format, and reads a cadir an earlier
// version of openvox-ca wrote (the key in private/, canonical inventory lines)
// in place, without rearranging it.
type FilesystemBackend struct {
	baseDir  string
	appendMu sync.Mutex // serialises AppendLine across the backend
	locks    *fileLocks // same-host locks, as flock(2) holds under fsLockDir
}

// NewFilesystemBackend constructs a FilesystemBackend rooted at baseDir.
func NewFilesystemBackend(baseDir string) *FilesystemBackend {
	return &FilesystemBackend{
		baseDir: baseDir,
		locks:   newFileLocks(filepath.Join(baseDir, fsLockDir)),
	}
}

// AcquireSameHostLock takes the named lock as an exclusive flock(2) on a file
// under <baseDir>/locks, excluding another process on this host — an
// `openvox-ca-ctl` command, or a second server — from the same name.
//
// It deliberately promises nothing across hosts, and this backend still
// implements no Locker, so anything asking whether the store coordinates across
// *replicas* continues to be told no. That is the honest answer:
// docs/storage-backends.md scopes the filesystem backend to single-node
// installs, and flock(2) over NFS is not a basis for widening it.
func (b *FilesystemBackend) AcquireSameHostLock(ctx context.Context, name string) (Unlocker, error) {
	return b.locks.acquire(ctx, name)
}

// AcquireInstanceLock takes the store-wide lock permitting one running instance,
// as an exclusive flock(2) under <baseDir>/locks alongside the per-name locks.
//
// The cadir is the store, so locking within it is locking the store. It shares
// the lock directory rather than taking a lock of its own beside it so that a
// single chown fixes every lock a store has, which is the recovery the
// permission error in inaccessibleLockFile sends operators to.
func (b *FilesystemBackend) AcquireInstanceLock() (Unlocker, error) {
	return b.locks.acquireInstance()
}

// BaseDir returns the filesystem root.
func (b *FilesystemBackend) BaseDir() string { return b.baseDir }

// Path returns the filesystem path for key, or empty if key is unknown.
// Used for diagnostic messages and by StorageService's legacy *Path methods.
func (b *FilesystemBackend) Path(key string) string {
	p, err := b.pathFor(key)
	if err != nil {
		return ""
	}
	return p
}

// caKeyFiler is implemented by a backend that keeps the CA key in a local file
// outside the private-key directory CheckKeyPermissions scans.
type caKeyFiler interface {
	CAKeyFile() string
}

// CAKeyFile returns the path of the CA key file this backend would read, or ""
// when there is none or it cannot be resolved. It never reads the key: see
// caKeyLocation.
func (b *FilesystemBackend) CAKeyFile() string {
	p, err := b.caKeyLocation()
	if err != nil {
		return ""
	}
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// caKeyLocation resolves where the CA key is: ca_key.pem, OpenVox Server's
// location, unless only private/ca_key.pem exists, which is where a cadir this
// backend created before it moved keeps it. The key is read and written where it
// is found rather than moved, so neither kind of cadir is rearranged by starting
// on it, and a fresh one gets OpenVox Server's layout.
//
// SECURITY: it decides from the files' existence alone and never reads either.
// Exists, ModTime, Path and CAKeyFile resolve through it, and those are reached
// by the network-facing frontend (its startup permission check, Init's
// bootstrap checks), which by design never has the CA key in its address space
// (docs/ca-key-security.md). Whether two copies agree is checked only by
// checkCAKeyConflict, from the operations that handle the key itself.
// NIST 800-53: SC-3 (Security Function Isolation)
func (b *FilesystemBackend) caKeyLocation() (string, error) {
	top := filepath.Join(b.baseDir, fsCAKeyPath)
	legacy := filepath.Join(b.baseDir, fsLegacyCAKeyPath)
	// Lstat: a dangling ca_key.pem link is a key that is meant to be there,
	// and must fail on use rather than fall through to the private/ copy.
	_, err := os.Lstat(top)
	if err == nil {
		return top, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	_, err = os.Lstat(legacy)
	if err == nil {
		return legacy, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return top, nil
}

// checkCAKeyConflict refuses a cadir holding both ca_key.pem and
// private/ca_key.pem with different contents: either could be the key this CA
// signs with, and picking one would sign with a key the operator may not have
// meant, or hand OpenVox Server one this CA never used. Identical copies are
// accepted. The error names both paths, and the operator decides.
//
// It reads both files, so only Get, Put and Delete call it: they handle the key
// itself, and run only in the processes allowed to hold it (the signer, a
// single-process server, the operator CLI). A file that exists but cannot be
// read is an error here, never treated as absent, so it cannot hand an
// operation the other copy instead.
func (b *FilesystemBackend) checkCAKeyConflict() error {
	top := filepath.Join(b.baseDir, fsCAKeyPath)
	legacy := filepath.Join(b.baseDir, fsLegacyCAKeyPath)
	topData, present, err := readCAKeyCopy(top)
	if err != nil || !present {
		return err
	}
	defer clear(topData)
	legacyData, present, err := readCAKeyCopy(legacy)
	if err != nil || !present {
		return err
	}
	defer clear(legacyData)
	if !bytes.Equal(topData, legacyData) {
		return fmt.Errorf("%w: %s and %s differ; remove the one that is not this CA's key",
			ErrCAKeyConflict, top, legacy)
	}
	return nil
}

func (b *FilesystemBackend) pathFor(key string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	if key == KeyCAKey {
		return b.caKeyLocation()
	}
	if rel, ok := fsLayout[key]; ok {
		return filepath.Join(b.baseDir, rel), nil
	}
	switch {
	case strings.HasPrefix(key, csrPrefix):
		subj := strings.TrimPrefix(key, csrPrefix)
		return filepath.Join(b.baseDir, "requests", subj+".pem"), nil
	case strings.HasPrefix(key, certPrefix):
		subj := strings.TrimPrefix(key, certPrefix)
		return filepath.Join(b.baseDir, "signed", subj+".pem"), nil
	}
	return "", fmt.Errorf("unknown key %q", key)
}

// The filesystem backend's syscalls cannot be interrupted mid-flight, so
// ctx is honoured only at the start of each operation. ctxErr returns the
// caller's cancellation error if ctx is already done; otherwise nil.
func ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (b *FilesystemBackend) EnsureReady(ctx context.Context) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	for _, d := range []string{
		b.baseDir,
		filepath.Join(b.baseDir, "signed"),
		filepath.Join(b.baseDir, "requests"),
		filepath.Join(b.baseDir, "private"),
		// Created here as well as lazily on first use, so the server owns it
		// from first boot. Left to the lazy path it would be created by
		// whichever process first needed a lock, quite possibly a `ctl` command
		// run under sudo — the root-owned directory AcquireSameHostLock then has
		// to refuse. Creating it at start also turns a permission problem into a
		// startup failure an operator is watching for, rather than one that
		// surfaces weeks later on whichever request first needs that lock.
		filepath.Join(b.baseDir, fsLockDir),
	} {
		if err := os.MkdirAll(d, DirPerm); err != nil {
			return err
		}
	}
	return nil
}

func (b *FilesystemBackend) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return nil, err
	}
	if key == KeyCAKey {
		if err := b.checkCAKeyConflict(); err != nil {
			return nil, err
		}
		data, present, err := readCAKeyCopy(p)
		if err != nil {
			return nil, err
		}
		if !present {
			return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		}
		return data, nil
	}
	return os.ReadFile(p)
}

func (b *FilesystemBackend) Put(ctx context.Context, key string, data []byte, kind BlobKind) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return err
	}
	if key == KeyCAKey {
		if err := b.removeLegacyCAKeyCopy(p); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), DirPerm); err != nil {
		return err
	}
	return AtomicWriteFile(p, data, permFor(kind))
}

func (b *FilesystemBackend) Delete(ctx context.Context, key string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return err
	}
	if key == KeyCAKey {
		if err := b.removeLegacyCAKeyCopy(p); err != nil {
			return err
		}
	}
	return os.Remove(p)
}

// readCAKeyCopy reads one copy of the CA key, reporting it absent only when
// nothing at all is at p. A link there that leads nowhere is an error, as
// caKeyLocation treats it: read as absent, it would pass the conflict check and
// let a write or a delete remove the other copy, which may be the only key.
func readCAKeyCopy(p string) (data []byte, present bool, err error) {
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	data, err = os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, true, fmt.Errorf("%w: %s", ErrCAKeyLinkBroken, p)
	}
	if err != nil {
		return nil, true, err
	}
	return data, true, nil
}

// removeLegacyCAKeyCopy prepares a write or a delete of the CA key at p. It
// refuses two different keys (checkCAKeyConflict); otherwise, when p is the
// top-level file, any private/ copy holds the same bytes, and it goes first.
// Left behind, it would either differ from the key just written, so every
// later read refuses, or be found again after a delete. Removing it before
// touching p means a failure at either step leaves no half-changed pair: the
// top-level file still holds the key it held.
func (b *FilesystemBackend) removeLegacyCAKeyCopy(p string) error {
	if err := b.checkCAKeyConflict(); err != nil {
		return err
	}
	legacy := filepath.Join(b.baseDir, fsLegacyCAKeyPath)
	if legacy == p {
		return nil
	}
	if err := os.Remove(legacy); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (b *FilesystemBackend) Exists(ctx context.Context, key string) (bool, error) {
	if err := ctxErr(ctx); err != nil {
		return false, err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		if key == KeyCAKey {
			// Stat follows a link; a CA key link that leads nowhere is not
			// an absent key (see ErrCAKeyLinkBroken).
			if _, lerr := os.Lstat(p); lerr == nil {
				return false, fmt.Errorf("%w: %s", ErrCAKeyLinkBroken, p)
			}
		}
		return false, nil
	}
	return false, err
}

func (b *FilesystemBackend) List(ctx context.Context, prefix string) ([]string, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	var dir, outPrefix string
	switch prefix {
	case csrPrefix:
		dir = filepath.Join(b.baseDir, "requests")
		outPrefix = csrPrefix
	case certPrefix:
		dir = filepath.Join(b.baseDir, "signed")
		outPrefix = certPrefix
	default:
		return nil, fmt.Errorf("unsupported list prefix %q", prefix)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		out = append(out, outPrefix+strings.TrimSuffix(e.Name(), ".pem"))
	}
	return out, nil
}

func (b *FilesystemBackend) AppendLine(ctx context.Context, key string, data []byte, kind BlobKind) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	b.appendMu.Lock()
	defer b.appendMu.Unlock()
	p, err := b.pathFor(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), DirPerm); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, permFor(kind))
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	// Flush the appended bytes to stable storage so a crash cannot lose a
	// just-written inventory or CRL line.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (b *FilesystemBackend) ModTime(ctx context.Context, key string) (time.Time, error) {
	if err := ctxErr(ctx); err != nil {
		return time.Time{}, err
	}
	p, err := b.pathFor(key)
	if err != nil {
		return time.Time{}, err
	}
	info, err := os.Stat(p)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func (b *FilesystemBackend) Close() error { return nil }

func permFor(kind BlobKind) os.FileMode {
	if kind == BlobPrivate {
		return FilePermPrivate
	}
	return FilePermPublic
}

// AtomicWriteFile writes data to a temporary file in the same directory as
// target, sets perm on it, then renames it into place. This prevents partial
// writes from leaving a corrupt file on disk (e.g. during a crash or power
// loss).
//
// Exported because the offline subcommands write public PEM material to
// operator-supplied paths and must do it the same way: docs/storage-backends.md
// advertises the property for CA material, and a bundle an automation step is
// about to deploy fleet-wide should not be weaker than the copy in storage.
// One implementation rather than two so the two cannot drift.
//
// The mode is applied to the descriptor before the rename, so the file never
// exists at the target path under the caller's umask.
func AtomicWriteFile(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating a temporary file beside %s: %w", target, err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", target, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("setting permissions on %s: %w", target, err)
	}
	// Flush the data to stable storage before the rename. Without this the
	// rename can be reordered ahead of the data on a crash, leaving a
	// zero-length or stale file in place of a CA key, cert, or CRL. It also
	// surfaces ENOSPC on filesystems that defer the error past close(2).
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("flushing %s: %w", target, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", target, err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", target, err)
	}
	// fsync the parent directory so the rename itself survives a crash. The
	// data is already on disk and renamed, so a failure here is best-effort.
	if dirF, err := os.Open(dir); err != nil {
		slog.Warn("Failed to open parent directory for fsync after rename", "dir", dir, "error", err)
	} else {
		if err := dirF.Sync(); err != nil {
			slog.Warn("Failed to fsync parent directory after rename", "dir", dir, "error", err)
		}
		_ = dirF.Close()
	}
	return nil
}
