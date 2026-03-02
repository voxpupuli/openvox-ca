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

package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/tvaughan/puppet-ca/internal/storage"
)

// ImportCA imports an external CA cert/key into a storage directory.
// It validates the cert/key pair, writes the files, and initialises
// the serial and inventory files when they are absent.
//
// Supported key formats: RSA PKCS1 ("RSA PRIVATE KEY"), EC SEC1
// ("EC PRIVATE KEY"), and PKCS8 ("PRIVATE KEY") for both RSA and ECDSA.
//
// crlPEM may be nil; when nil a fresh empty CRL is generated and written.
//
// This is an offline operation — no CA daemon is required.
func ImportCA(store *storage.StorageService, certBundlePEM, keyPEM, crlPEM []byte) error {
	// --- Parse and validate cert ---
	block, _ := pem.Decode(certBundlePEM)
	if block == nil {
		return fmt.Errorf("cert-bundle does not contain a valid PEM block")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert: %w", err)
	}
	if !caCert.IsCA {
		return fmt.Errorf("certificate is not a CA certificate (IsCA=false)")
	}

	// --- Parse and validate private key ---
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("private-key does not contain a valid PEM block")
	}

	var caKey crypto.Signer
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA PKCS1 private key: %w", err)
		}
		caKey = k
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse EC private key: %w", err)
		}
		caKey = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return fmt.Errorf("PKCS8 private key does not implement crypto.Signer")
		}
		caKey = signer
	default:
		// Try PKCS1, then PKCS8, regardless of header for compatibility.
		if k1, err1 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err1 == nil {
			caKey = k1
		} else if k8, err8 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err8 == nil {
			signer, ok := k8.(crypto.Signer)
			if !ok {
				return fmt.Errorf("PKCS8 private key does not implement crypto.Signer")
			}
			caKey = signer
		} else {
			return fmt.Errorf("failed to parse CA private key (PKCS1: %v; PKCS8: %v)", err1, err8)
		}
	}

	// --- Verify key matches cert (algorithm-agnostic) ---
	certPubDER, err := x509.MarshalPKIXPublicKey(caCert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal cert public key: %w", err)
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(caKey.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal private key's public component: %w", err)
	}
	if !bytes.Equal(certPubDER, keyPubDER) {
		return fmt.Errorf("private key does not match the certificate's public key")
	}

	// --- Ensure directories exist ---
	if err := store.EnsureDirs(); err != nil {
		return fmt.Errorf("failed to create CA directories: %w", err)
	}

	// --- Write CA key (mode 0640) ---
	if err := os.WriteFile(store.CAKeyPath(), keyPEM, storage.FilePermPrivate); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	// --- Write CA cert (mode 0644) ---
	if err := os.WriteFile(store.CACertPath(), certBundlePEM, storage.FilePermPublic); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	// --- Write CA public key ---
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(caKey.Public())
	if err == nil {
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
		_ = os.WriteFile(store.CAPubKeyPath(), pubKeyPEM, storage.FilePermPublic)
	}

	// --- Handle CRL ---
	if crlPEM != nil {
		crlBlock, _ := pem.Decode(crlPEM)
		if crlBlock == nil {
			return fmt.Errorf("crl-chain does not contain a valid PEM block")
		}
		if _, err := x509.ParseRevocationList(crlBlock.Bytes); err != nil {
			return fmt.Errorf("failed to parse CRL: %w", err)
		}
		if err := store.UpdateCRL(crlPEM); err != nil {
			return fmt.Errorf("failed to write CRL: %w", err)
		}
	} else {
		// Generate a fresh empty CRL.
		now := time.Now().UTC()
		crlTemplate := &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now,
			NextUpdate: now.Add(CRLValidity),
		}
		crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
		if err != nil {
			return fmt.Errorf("failed to create initial CRL: %w", err)
		}
		generatedCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
		if err := store.UpdateCRL(generatedCRL); err != nil {
			return fmt.Errorf("failed to write CRL: %w", err)
		}
	}

	// --- Initialise serial if absent ---
	if _, err := os.Stat(store.SerialPath()); os.IsNotExist(err) {
		if err := store.WriteSerial("0001"); err != nil {
			return fmt.Errorf("failed to write serial: %w", err)
		}
	}

	// --- Initialise inventory if absent ---
	if _, err := os.Stat(store.InventoryPath()); os.IsNotExist(err) {
		f, err := os.OpenFile(store.InventoryPath(), os.O_CREATE|os.O_RDONLY, storage.FilePermPublic)
		if err != nil {
			return fmt.Errorf("failed to create inventory: %w", err)
		}
		f.Close()
	}

	return nil
}
