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

package ca

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// Encrypted PEM envelope format (inside the PEM block body):
//
//	version    1 byte   (currently 0x01)
//	salt      32 bytes  (random, for Argon2id)
//	nonce     12 bytes  (random, for AES-256-GCM)
//	ciphertext variable (AES-256-GCM encrypted PKCS#8 DER + 16-byte GCM tag)
//
// Key derivation: Argon2id(passphrase, salt, time=3, memory=64 MiB, threads=4) → 32 bytes.
// Plaintext: PKCS#8 DER encoding of the private key.

const (
	keyEncVersion  = 0x01
	keyEncSaltLen  = 32
	keyEncNonceLen = 12
	keyEncMinLen   = 1 + keyEncSaltLen + keyEncNonceLen + aes.BlockSize // version + salt + nonce + min ciphertext

	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 4
	argon2KeyLen  = 32

	encryptedPEMType = "ENCRYPTED PRIVATE KEY"

	// passphraseFileLen is the length of an auto-generated passphrase (hex-encoded random bytes).
	passphraseFileLen = 32
)

// KeyPassphraseConfig holds the passphrase source for CA key encryption.
type KeyPassphraseConfig struct {
	// PassphraseFile is a path to a file containing the passphrase (first line, trimmed).
	PassphraseFile string
	// PassphraseEnvVar is the name of the environment variable holding the passphrase.
	// Defaults to PUPPET_CA_KEY_PASSPHRASE.
	PassphraseEnvVar string
}

// deriveKey derives a 32-byte AES key from passphrase and salt using Argon2id.
func deriveKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// encryptKeyPEM encrypts a private key (as PKCS#8 DER) with the given
// passphrase and returns PEM-encoded encrypted data.
func encryptKeyPEM(pkcs8DER, passphrase []byte) ([]byte, error) {
	salt := make([]byte, keyEncSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, pkcs8DER, nil)

	// Assemble envelope: version || salt || nonce || ciphertext.
	envelope := make([]byte, 0, 1+len(salt)+len(nonce)+len(ciphertext))
	envelope = append(envelope, keyEncVersion)
	envelope = append(envelope, salt...)
	envelope = append(envelope, nonce...)
	envelope = append(envelope, ciphertext...)

	return pem.EncodeToMemory(&pem.Block{
		Type:  encryptedPEMType,
		Bytes: envelope,
	}), nil
}

// decryptKeyDER decrypts an encrypted PEM envelope and returns the PKCS#8 DER.
func decryptKeyDER(envelope, passphrase []byte) ([]byte, error) {
	if len(envelope) < keyEncMinLen {
		return nil, fmt.Errorf("encrypted key envelope too short")
	}
	if envelope[0] != keyEncVersion {
		return nil, fmt.Errorf("unsupported encrypted key version: %d", envelope[0])
	}

	offset := 1
	salt := envelope[offset : offset+keyEncSaltLen]
	offset += keyEncSaltLen
	nonce := envelope[offset : offset+keyEncNonceLen]
	offset += keyEncNonceLen
	ciphertext := envelope[offset:]

	key := deriveKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong passphrase?): %w", err)
	}
	return plaintext, nil
}

// isEncryptedPEM reports whether the PEM block is an encrypted private key.
func isEncryptedPEM(block *pem.Block) bool {
	return block != nil && block.Type == encryptedPEMType
}

// encryptAndMarshalKey encrypts a crypto.Signer private key with the given
// passphrase and returns PEM-encoded encrypted data.
func encryptAndMarshalKey(key any, passphrase []byte) ([]byte, error) {
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshalling key to PKCS#8: %w", err)
	}
	return encryptKeyPEM(pkcs8DER, passphrase)
}

// resolvePassphrase determines the CA key passphrase from the configured sources.
// Resolution order: PassphraseFile → environment variable → auto-generated file.
// Returns (passphrase, wasAutoGenerated, error).
func resolvePassphrase(cfg KeyPassphraseConfig, caDir string) ([]byte, bool, error) {
	envVar := cfg.PassphraseEnvVar
	if envVar == "" {
		envVar = "PUPPET_CA_KEY_PASSPHRASE"
	}

	// 1. Explicit file.
	if cfg.PassphraseFile != "" {
		pp, err := readPassphraseFile(cfg.PassphraseFile)
		if err != nil {
			return nil, false, fmt.Errorf("reading --ca-key-passphrase-file %s: %w", cfg.PassphraseFile, err)
		}
		return pp, false, nil
	}

	// 2. Environment variable.
	if val := os.Getenv(envVar); val != "" {
		return []byte(val), false, nil
	}

	// 3. Auto-generated file at <cadir>/private/.ca_key_passphrase.
	autoPath := autoPassphrasePath(caDir)
	if data, err := readPassphraseFile(autoPath); err == nil {
		return data, false, nil
	}

	// 4. Generate a new passphrase and write it.
	pp := make([]byte, passphraseFileLen)
	if _, err := rand.Read(pp); err != nil {
		return nil, false, fmt.Errorf("generating passphrase: %w", err)
	}
	// Hex-encode for safe file storage.
	hexPP := []byte(fmt.Sprintf("%x", pp))

	if err := os.MkdirAll(filepath.Dir(autoPath), storage.DirPerm); err != nil {
		return nil, false, fmt.Errorf("creating passphrase directory: %w", err)
	}
	if err := os.WriteFile(autoPath, hexPP, storage.FilePermPrivate); err != nil {
		return nil, false, fmt.Errorf("writing auto-generated passphrase to %s: %w", autoPath, err)
	}
	return hexPP, true, nil
}

// readPassphraseFile reads a passphrase from a file (first line, whitespace-trimmed).
func readPassphraseFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Use first line only, trim whitespace.
	for i, b := range data {
		if b == '\n' || b == '\r' {
			data = data[:i]
			break
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("passphrase file %s is empty", path)
	}
	return data, nil
}

// autoPassphrasePath returns the path to the auto-generated passphrase file.
func autoPassphrasePath(caDir string) string {
	return filepath.Join(caDir, "private", ".ca_key_passphrase")
}
