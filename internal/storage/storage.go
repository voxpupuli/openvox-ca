// Copyright (C) 2026 Trevor Vaughan
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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	FilePermPrivate = 0600
	FilePermPublic  = 0644
	DirPerm         = 0750
)

type StorageService struct {
	baseDir     string
	serialMu    sync.Mutex
	inventoryMu sync.RWMutex
	crlMu       sync.RWMutex
	fileMu      sync.RWMutex // General file system lock for certs/csrs
	hmacKey     []byte       // HMAC-SHA256 key for inventory integrity; nil disables
}

func New(baseDir string) *StorageService {
	return &StorageService{
		baseDir: baseDir,
	}
}

func (s *StorageService) EnsureDirs() error {
	dirs := []string{
		s.baseDir,
		filepath.Join(s.baseDir, "signed"),
		filepath.Join(s.baseDir, "requests"),
		filepath.Join(s.baseDir, "private"), // For CA key
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, DirPerm); err != nil {
			return err
		}
	}
	return nil
}

func (s *StorageService) WriteSerial(val string) error {
	s.serialMu.Lock()
	defer s.serialMu.Unlock()
	return os.WriteFile(filepath.Join(s.baseDir, "serial"), []byte(val), FilePermPublic)
}

// InitHMAC loads or generates the inventory HMAC key and verifies the
// existing inventory. Call this once during CA initialization.
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

	f, err := os.OpenFile(filepath.Join(s.baseDir, "inventory.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, FilePermPrivate)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(entry + "\n"); err != nil {
		return err
	}

	// Update HMAC after successful write.
	if s.hmacKey != nil {
		if err := s.UpdateInventoryHMAC(s.hmacKey); err != nil {
			slog.Warn("Failed to update inventory HMAC", "error", err)
		}
	}
	return nil
}

func (s *StorageService) ReadInventory() ([]byte, error) {
	s.inventoryMu.RLock()
	defer s.inventoryMu.RUnlock()

	// Verify HMAC integrity before returning inventory contents.
	if s.hmacKey != nil {
		if err := s.VerifyInventoryHMAC(s.hmacKey); err != nil {
			return nil, err
		}
	}
	return os.ReadFile(s.InventoryPath())
}

func (s *StorageService) CRLPath() string {
	return filepath.Join(s.baseDir, "ca_crl.pem")
}

func (s *StorageService) UpdateCRL(pemData []byte) error {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	return atomicWriteFile(s.CRLPath(), pemData, FilePermPrivate)
}

// atomicWriteFile writes data to a temporary file in the same directory as
// target, then renames it into place. This prevents partial writes from
// leaving a corrupt file on disk (e.g. during a crash or power loss).
func atomicWriteFile(target string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, target)
}

func (s *StorageService) GetCRL() ([]byte, error) {
	s.crlMu.RLock()
	defer s.crlMu.RUnlock()
	return os.ReadFile(s.CRLPath())
}

func (s *StorageService) CADir() string {
	return s.baseDir
}

func (s *StorageService) CAKeyPath() string {
	return filepath.Join(s.baseDir, "private", "ca_key.pem")
}

func (s *StorageService) CACertPath() string {
	return filepath.Join(s.baseDir, "ca_crt.pem")
}

func (s *StorageService) CAPubKeyPath() string {
	return filepath.Join(s.baseDir, "ca_pub.pem")
}

// Helpers for paths — subject is pre-validated as ^[a-z0-9._-]+$ by the CA layer.
func (s *StorageService) reqPath(subject string) string {
	return filepath.Join(s.baseDir, "requests", subject+".pem")
}

func (s *StorageService) signedPath(subject string) string {
	return filepath.Join(s.baseDir, "signed", subject+".pem")
}

// CSRDir returns the directory where pending CSRs are stored.
func (s *StorageService) CSRDir() string {
	return filepath.Join(s.baseDir, "requests")
}

// SignedDir returns the directory where signed certificates are stored.
func (s *StorageService) SignedDir() string {
	return filepath.Join(s.baseDir, "signed")
}

func (s *StorageService) SaveCSR(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.WriteFile(s.reqPath(subject), pemData, FilePermPublic)
}

func (s *StorageService) GetCSR(subject string) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return os.ReadFile(s.reqPath(subject))
}

func (s *StorageService) SaveCert(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.WriteFile(s.signedPath(subject), pemData, FilePermPublic)
}

func (s *StorageService) GetCert(subject string) ([]byte, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return os.ReadFile(s.signedPath(subject))
}

func (s *StorageService) DeleteCSR(subject string) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.Remove(s.reqPath(subject))
}

func (s *StorageService) DeleteCert(subject string) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.Remove(s.signedPath(subject))
}

// HasCert reports whether a signed certificate exists for subject.
func (s *StorageService) HasCert(subject string) bool {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	_, err := os.Stat(s.signedPath(subject))
	return err == nil
}

// HasCSR reports whether a pending CSR exists for subject.
func (s *StorageService) HasCSR(subject string) bool {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	_, err := os.Stat(s.reqPath(subject))
	return err == nil
}

func (s *StorageService) InventoryPath() string {
	return filepath.Join(s.baseDir, "inventory.txt")
}

func (s *StorageService) SerialPath() string {
	return filepath.Join(s.baseDir, "serial")
}

func (s *StorageService) PrivateKeyPath(subject string) string {
	return filepath.Join(s.baseDir, "private", subject+"_key.pem")
}

// KeyPermWarning describes a private key file whose permissions are more
// permissive than expected.
type KeyPermWarning struct {
	Path string
	Mode os.FileMode
}

// CheckKeyPermissions checks that private key files have the expected
// permissions (FilePermPrivate). Returns a list of warnings for any files
// whose permissions are more permissive than expected.
// An empty return means all files are OK (or no key files exist yet).
func (s *StorageService) CheckKeyPermissions() []KeyPermWarning {
	privateDir := filepath.Join(s.baseDir, "private")
	entries, err := os.ReadDir(privateDir)
	if err != nil {
		return nil // directory may not exist yet
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
		if perm&^os.FileMode(FilePermPrivate) != 0 { // any bit set beyond FilePermPrivate (0600)
			warnings = append(warnings, KeyPermWarning{
				Path: filepath.Join(privateDir, e.Name()),
				Mode: perm,
			})
		}
	}
	return warnings
}

func (s *StorageService) SavePrivateKey(subject string, pemData []byte) error {
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	return os.WriteFile(s.PrivateKeyPath(subject), pemData, FilePermPrivate)
}

// ListCSRs returns the subject names of all pending certificate requests.
func (s *StorageService) ListCSRs() ([]string, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return listSubjectsInDir(s.CSRDir())
}

// ListCerts returns the subject names of all signed certificates.
func (s *StorageService) ListCerts() ([]string, error) {
	s.fileMu.RLock()
	defer s.fileMu.RUnlock()
	return listSubjectsInDir(s.SignedDir())
}

func listSubjectsInDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	subjects := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".pem" {
			continue
		}
		subjects = append(subjects, strings.TrimSuffix(e.Name(), ".pem"))
	}
	return subjects, nil
}

// --- Inventory HMAC integrity ---

const hmacKeyLen = 32

// HMACKeyPath returns the path to the inventory HMAC key file.
func (s *StorageService) HMACKeyPath() string {
	return filepath.Join(s.baseDir, "private", ".inventory_hmac_key")
}

// inventoryHMACPath returns the path to the inventory HMAC file.
func (s *StorageService) inventoryHMACPath() string {
	return filepath.Join(s.baseDir, ".inventory.hmac")
}

// EnsureHMACKey loads or generates the HMAC key used for inventory integrity.
// Returns the key bytes. The key is stored in private/.inventory_hmac_key with 0600.
func (s *StorageService) EnsureHMACKey() ([]byte, error) {
	keyPath := s.HMACKeyPath()
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == hmacKeyLen {
		return data, nil
	}

	key := make([]byte, hmacKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating HMAC key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), DirPerm); err != nil {
		return nil, fmt.Errorf("creating HMAC key directory: %w", err)
	}
	if err := os.WriteFile(keyPath, key, FilePermPrivate); err != nil {
		return nil, fmt.Errorf("writing HMAC key: %w", err)
	}
	return key, nil
}

// computeInventoryHMAC computes HMAC-SHA256 of the inventory file contents.
func (s *StorageService) computeInventoryHMAC(hmacKey []byte) ([]byte, error) {
	data, err := os.ReadFile(s.InventoryPath())
	if err != nil {
		if os.IsNotExist(err) {
			data = []byte{}
		} else {
			return nil, err
		}
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// UpdateInventoryHMAC recomputes and writes the HMAC for the current inventory.
func (s *StorageService) UpdateInventoryHMAC(hmacKey []byte) error {
	sum, err := s.computeInventoryHMAC(hmacKey)
	if err != nil {
		return fmt.Errorf("computing inventory HMAC: %w", err)
	}
	return os.WriteFile(s.inventoryHMACPath(), sum, FilePermPrivate)
}

// VerifyInventoryHMAC checks the inventory file against its stored HMAC.
// Returns nil if valid, ErrInventoryTampered if tampered, or another error.
func (s *StorageService) VerifyInventoryHMAC(hmacKey []byte) error {
	storedMAC, err := os.ReadFile(s.inventoryHMACPath())
	if err != nil {
		if os.IsNotExist(err) {
			// No HMAC file yet — first run or migration. Compute and store it.
			slog.Info("No inventory HMAC found; initializing integrity baseline")
			return s.UpdateInventoryHMAC(hmacKey)
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
