// Copyright (C) 2026 Trevor Vaughan
// Copyright (C) 2026 Chris Boot
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
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

// StorageService provides the higher-level storage API used by the CA and
// API layers. It delegates all blob I/O to a pluggable Backend and handles
// inventory HMAC sequencing, append/read locks, and the per-subject private
// key directory (always local).
type StorageService struct {
	backend     Backend
	serialMu    sync.Mutex
	inventoryMu sync.RWMutex
	crlMu       sync.RWMutex
	fileMu      sync.RWMutex
	hmacKey     []byte // set by InitHMAC; nil disables integrity checks

	// localPrivateKeyDir holds server-generated per-subject private keys.
	// These are kept on the local filesystem regardless of the configured
	// backend: they are client material that operators don't want exposed
	// through a shared remote store.
	localPrivateKeyDir string

	// localLocks is the process-local fallback for WithLock when the
	// underlying backend does not implement Locker. One sync.Mutex per
	// lock name, lazily created.
	localLocks sync.Map
}

// WithLock runs fn while holding the named lock. When the underlying
// backend implements Locker, the lock is coordinated across nodes;
// otherwise it falls back to a process-local named mutex, sufficient for
// single-node backends. The lock is always released when fn returns,
// including on panic.
//
// Names should be stable and descriptive (e.g. "bootstrap", "crl",
// "subject:<name>") since all callers using the same name contend on the
// same lock.
func (s *StorageService) WithLock(ctx context.Context, name string, fn func() error) error {
	if lk, ok := s.backend.(Locker); ok {
		ul, err := lk.AcquireLock(ctx, name)
		if err == nil {
			defer func() {
				if err := ul.Unlock(); err != nil {
					slog.Warn("Failed to release distributed lock", "name", name, "error", err)
				}
			}()
			return fn()
		}
		if !errors.Is(err, ErrDistributedLockingUnsupported) {
			return fmt.Errorf("acquiring distributed lock %q: %w", name, err)
		}
		// Backend advertises Locker but cannot actually provide one (e.g.
		// OverlayBackend wrapping a filesystem base); fall through to the
		// process-local mutex, which is correct for single-node backends.
	}
	m := s.localNamedLock(name)
	m.Lock()
	defer m.Unlock()
	return fn()
}

// localNamedLock returns the process-local mutex for name, creating it
// on first use. Mutexes are never removed from the map; the namespace
// is small and bounded.
func (s *StorageService) localNamedLock(name string) *sync.Mutex {
	if v, ok := s.localLocks.Load(name); ok {
		return v.(*sync.Mutex)
	}
	v, _ := s.localLocks.LoadOrStore(name, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// New constructs a StorageService backed by a filesystem rooted at baseDir.
// Per-subject generated private keys are stored in baseDir/private alongside
// the filesystem backend's other private files.
func New(baseDir string) *StorageService {
	return NewWithBackend(NewFilesystemBackend(baseDir), filepath.Join(baseDir, "private"))
}

// NewWithBackend constructs a StorageService with an explicit backend and a
// local directory for per-subject private keys. The private key directory is
// always on the local filesystem regardless of the chosen backend.
func NewWithBackend(backend Backend, localPrivateKeyDir string) *StorageService {
	return &StorageService{
		backend:            backend,
		localPrivateKeyDir: localPrivateKeyDir,
	}
}

// Backend returns the underlying Backend. Exposed for advanced use cases
// (diagnostic output, backend-specific tuning). Most callers should prefer
// the higher-level methods on StorageService.
func (s *StorageService) Backend() Backend { return s.backend }

// EnsureDirs prepares the backend and the local private-key directory for use.
func (s *StorageService) EnsureDirs() error {
	if err := s.backend.EnsureReady(); err != nil {
		return err
	}
	if s.localPrivateKeyDir != "" {
		if err := os.MkdirAll(s.localPrivateKeyDir, DirPerm); err != nil {
			return err
		}
	}
	return nil
}

// --- Serial ---

func (s *StorageService) WriteSerial(val string) error {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	return s.backend.Put(KeySerial, []byte(val), BlobPublic)
}

func (s *StorageService) GetSerial() ([]byte, error) {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	return s.backend.Get(KeySerial)
}

func (s *StorageService) HasSerial() (bool, error) {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	return s.backend.Exists(KeySerial)
}

// --- Inventory ---

// InitHMAC loads or generates the inventory HMAC key and verifies the
// existing inventory. Call this once during CA initialisation.
func (s *StorageService) InitHMAC() error {
	key, err := s.EnsureHMACKey()
	if err != nil {
		return err
	}
	s.hmacKey = key
	return s.VerifyInventoryHMAC(key)
}

func (s *StorageService) AppendInventory(entry string) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()

	if err := s.backend.AppendLine(KeyInventory, []byte(entry+"\n"), BlobPrivate); err != nil {
		return err
	}

	if s.hmacKey != nil {
		if err := s.updateInventoryHMACLocked(s.hmacKey); err != nil {
			slog.Warn("Failed to update inventory HMAC", "error", err)
		}
	}
	return nil
}

func (s *StorageService) ReadInventory() ([]byte, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()

	if s.hmacKey != nil {
		if err := s.verifyInventoryHMACLocked(s.hmacKey); err != nil {
			return nil, err
		}
	}
	return s.backend.Get(KeyInventory)
}

// TouchInventory creates an empty inventory blob if one does not already
// exist. Called during CA bootstrap and import to seed the inventory.
func (s *StorageService) TouchInventory() error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()
	ok, err := s.backend.Exists(KeyInventory)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return s.backend.Put(KeyInventory, []byte{}, BlobPrivate)
}

func (s *StorageService) HasInventory() (bool, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()
	return s.backend.Exists(KeyInventory)
}

// readInventoryForHMAC returns the inventory bytes, treating an absent blob
// as empty so that a missing inventory hashes the same as an empty one.
// Caller must hold inventoryMu (read or write).
func (s *StorageService) readInventoryForHMAC() ([]byte, error) {
	data, err := s.backend.Get(KeyInventory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return []byte{}, nil
		}
		return nil, err
	}
	return data, nil
}

// --- CRL ---

func (s *StorageService) UpdateCRL(pemData []byte) error {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	return s.backend.Put(KeyCRL, pemData, BlobPrivate)
}

func (s *StorageService) GetCRL() ([]byte, error) {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	return s.backend.Get(KeyCRL)
}

// CRLModTime returns the last-modified time of the CRL blob, for
// If-Modified-Since handling. Backends that don't track mtime return zero.
func (s *StorageService) CRLModTime() (time.Time, error) {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	return s.backend.ModTime(KeyCRL)
}

// --- CA material ---

func (s *StorageService) GetCACert() ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(KeyCACert)
}

func (s *StorageService) SaveCACert(data []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(KeyCACert, data, BlobPublic)
}

func (s *StorageService) HasCACert() (bool, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Exists(KeyCACert)
}

func (s *StorageService) GetCAKey() ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(KeyCAKey)
}

func (s *StorageService) SaveCAKey(data []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(KeyCAKey, data, BlobPrivate)
}

func (s *StorageService) HasCAKey() (bool, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Exists(KeyCAKey)
}

func (s *StorageService) SaveCAPubKey(data []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(KeyCAPubKey, data, BlobPublic)
}

// --- CSR / Cert per subject ---

func (s *StorageService) SaveCSR(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(CSRKey(subject), pemData, BlobPublic)
}

func (s *StorageService) GetCSR(subject string) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(CSRKey(subject))
}

func (s *StorageService) SaveCert(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Put(CertKey(subject), pemData, BlobPublic)
}

func (s *StorageService) GetCert(subject string) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return s.backend.Get(CertKey(subject))
}

func (s *StorageService) DeleteCSR(subject string) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Delete(CSRKey(subject))
}

func (s *StorageService) DeleteCert(subject string) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return s.backend.Delete(CertKey(subject))
}

// HasCert reports whether a signed certificate exists for subject.
func (s *StorageService) HasCert(subject string) bool {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	ok, _ := s.backend.Exists(CertKey(subject))
	return ok
}

// HasCSR reports whether a pending CSR exists for subject.
func (s *StorageService) HasCSR(subject string) bool {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	ok, _ := s.backend.Exists(CSRKey(subject))
	return ok
}

// ListCSRs returns the subject names of all pending certificate requests.
func (s *StorageService) ListCSRs() ([]string, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	keys, err := s.backend.List(csrPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, csrPrefix))
	}
	return out, nil
}

// ListCerts returns the subject names of all signed certificates.
func (s *StorageService) ListCerts() ([]string, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	keys, err := s.backend.List(certPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, strings.TrimPrefix(k, certPrefix))
	}
	return out, nil
}

// --- Per-subject private keys (always local) ---

// PrivateKeyPath returns the filesystem path to subject's server-generated
// private key. Private keys are always stored on the local filesystem.
func (s *StorageService) PrivateKeyPath(subject string) string {
	return filepath.Join(s.localPrivateKeyDir, subject+"_key.pem")
}

// SavePrivateKey persists a server-generated private key for subject. The
// key is always written to the local filesystem, never the configured backend.
func (s *StorageService) SavePrivateKey(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if err := os.MkdirAll(s.localPrivateKeyDir, DirPerm); err != nil {
		return err
	}
	return os.WriteFile(s.PrivateKeyPath(subject), pemData, FilePermPrivate)
}

// CheckKeyPermissions reports private key files whose permissions are more
// permissive than expected (0600). Scans the local private-key directory,
// which for the filesystem backend also contains the CA key.
func (s *StorageService) CheckKeyPermissions() []KeyPermWarning {
	if s.localPrivateKeyDir == "" {
		return nil
	}
	entries, err := os.ReadDir(s.localPrivateKeyDir)
	if err != nil {
		return nil
	}
	var warnings []KeyPermWarning
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_key.pem") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		perm := info.Mode().Perm()
		if perm&^os.FileMode(FilePermPrivate) != 0 {
			warnings = append(warnings, KeyPermWarning{
				Path: filepath.Join(s.localPrivateKeyDir, e.Name()),
				Mode: perm,
			})
		}
	}
	return warnings
}

// --- Legacy path accessors (filesystem-backend only) ---
//
// These return empty strings when the backend is not filesystem-rooted.
// They exist for diagnostic logging and test fixtures; core code should
// use the content-oriented methods above.

// CADir returns the filesystem root of the backend, or "" for non-filesystem backends.
func (s *StorageService) CADir() string {
	if p, ok := s.backend.(PathProvider); ok {
		return p.BaseDir()
	}
	return ""
}

func (s *StorageService) fsPath(key string) string {
	if p, ok := s.backend.(PathProvider); ok {
		return p.Path(key)
	}
	return ""
}

func (s *StorageService) CACertPath() string    { return s.fsPath(KeyCACert) }
func (s *StorageService) CAKeyPath() string     { return s.fsPath(KeyCAKey) }
func (s *StorageService) CAPubKeyPath() string  { return s.fsPath(KeyCAPubKey) }
func (s *StorageService) CRLPath() string       { return s.fsPath(KeyCRL) }
func (s *StorageService) SerialPath() string    { return s.fsPath(KeySerial) }
func (s *StorageService) InventoryPath() string { return s.fsPath(KeyInventory) }
func (s *StorageService) HMACKeyPath() string   { return s.fsPath(KeyHMACKey) }

// CSRDir returns the directory where pending CSRs are stored (filesystem backend only).
func (s *StorageService) CSRDir() string {
	if p, ok := s.backend.(PathProvider); ok {
		return filepath.Join(p.BaseDir(), "requests")
	}
	return ""
}

// SignedDir returns the directory where signed certificates are stored (filesystem backend only).
func (s *StorageService) SignedDir() string {
	if p, ok := s.backend.(PathProvider); ok {
		return filepath.Join(p.BaseDir(), "signed")
	}
	return ""
}

// --- Inventory HMAC integrity ---

const hmacKeyLen = 32

// EnsureHMACKey loads or generates the HMAC key used for inventory integrity.
// The key is stored via the backend under KeyHMACKey.
func (s *StorageService) EnsureHMACKey() ([]byte, error) {
	if data, err := s.backend.Get(KeyHMACKey); err == nil && len(data) == hmacKeyLen {
		return data, nil
	}
	key := make([]byte, hmacKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating HMAC key: %w", err)
	}
	if err := s.backend.Put(KeyHMACKey, key, BlobPrivate); err != nil {
		return nil, fmt.Errorf("writing HMAC key: %w", err)
	}
	return key, nil
}

// computeInventoryHMAC computes HMAC-SHA256 of the inventory contents.
// Caller must hold inventoryMu.
func (s *StorageService) computeInventoryHMAC(hmacKey []byte) ([]byte, error) {
	data, err := s.readInventoryForHMAC()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// UpdateInventoryHMAC recomputes and writes the HMAC for the current inventory.
// It is safe to call externally (e.g. after migrating an existing inventory).
func (s *StorageService) UpdateInventoryHMAC(hmacKey []byte) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()
	return s.updateInventoryHMACLocked(hmacKey)
}

func (s *StorageService) updateInventoryHMACLocked(hmacKey []byte) error {
	sum, err := s.computeInventoryHMAC(hmacKey)
	if err != nil {
		return fmt.Errorf("computing inventory HMAC: %w", err)
	}
	return s.backend.Put(KeyInventoryHMAC, sum, BlobPrivate)
}

// VerifyInventoryHMAC checks the inventory against its stored HMAC. Returns
// ErrInventoryTampered on mismatch, or initialises a baseline HMAC on first run.
func (s *StorageService) VerifyInventoryHMAC(hmacKey []byte) error {
	s.inventoryMu.Lock()
	defer s.inventoryMu.Unlock()
	return s.verifyInventoryHMACLocked(hmacKey)
}

func (s *StorageService) verifyInventoryHMACLocked(hmacKey []byte) error {
	storedMAC, err := s.backend.Get(KeyInventoryHMAC)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			slog.Info("No inventory HMAC found; initializing integrity baseline")
			return s.updateInventoryHMACLocked(hmacKey)
		}
		return fmt.Errorf("reading inventory HMAC: %w", err)
	}

	computedMAC, err := s.computeInventoryHMAC(hmacKey)
	if err != nil {
		return fmt.Errorf("computing inventory HMAC for verification: %w", err)
	}

	if !hmac.Equal(storedMAC, computedMAC) {
		return ErrInventoryTampered
	}
	return nil
}

// ErrInventoryTampered is returned when the inventory HMAC verification fails.
var ErrInventoryTampered = fmt.Errorf("inventory file integrity check failed: HMAC mismatch (possible tampering)")
