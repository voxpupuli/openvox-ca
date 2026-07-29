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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
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
// This is an offline operation; no CA daemon is required.
func ImportCA(ctx context.Context, store *storage.StorageService, certBundlePEM, keyPEM, crlPEM []byte) error {
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

	caKey, err := parsePrivateKeyDER(keyBlock.Type, keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
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
	if err := store.EnsureDirs(ctx); err != nil {
		return fmt.Errorf("failed to create CA directories: %w", err)
	}

	// --- Write CA key ---
	if err := store.SaveCAKey(ctx, keyPEM); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	// --- Write CA cert ---
	if err := store.SaveCACert(ctx, certBundlePEM); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	// --- Write CA public key ---
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(caKey.Public())
	if err == nil {
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
		_ = store.SaveCAPubKey(ctx, pubKeyPEM)
	}

	// --- Handle CRL ---
	if crlPEM != nil {
		// Validate every block, not just the first. The blob is served verbatim
		// to every agent, so an unparseable block further down would surface as
		// a broken CRL across the fleet rather than as an import error here.
		incoming := decodeCRLChain(crlPEM)
		if len(incoming) == 0 {
			return fmt.Errorf("crl-chain does not contain a valid X509 CRL PEM block")
		}

		// Every reader takes block 0 as this CA's own CRL, so put it there.
		// An operator assembling a chain by hand has no reason to know that,
		// and correcting it once at import is better than misreading it on
		// every subsequent load.
		ordered, foundOurs := orderCRLChain(crlPEM, caCert)
		if !foundOurs {
			// A chain of purely upstream CRLs is legitimate — an operator may
			// supply ancestors and expect this CA to issue its own. Generate
			// ours and lead with it.
			ourCRL, err := generateEmptyCRL(caCert, caKey)
			if err != nil {
				return err
			}
			ordered = append(ourCRL, ordered...)
		}

		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, ordered); err != nil {
			return fmt.Errorf("failed to write CRL: %w", err)
		}
	} else {
		generatedCRL, err := generateEmptyCRL(caCert, caKey)
		if err != nil {
			return err
		}
		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, generatedCRL); err != nil {
			return fmt.Errorf("failed to write CRL: %w", err)
		}
	}

	// --- Initialise serial if absent ---
	hasSerial, err := store.HasSerial(ctx)
	if err != nil {
		return fmt.Errorf("checking serial: %w", err)
	}
	if !hasSerial {
		if err := store.WriteSerial(ctx, "0001"); err != nil {
			return fmt.Errorf("failed to write serial: %w", err)
		}
	}

	// --- Initialise inventory if absent ---
	if err := store.TouchInventory(ctx); err != nil {
		return fmt.Errorf("failed to create inventory: %w", err)
	}

	return nil
}

// generateEmptyCRL signs a fresh, empty CRL for cert.
func generateEmptyCRL(cert *x509.Certificate, key crypto.Signer) ([]byte, error) {
	now := time.Now().UTC()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(CRLValidity),
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, cert, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial CRL: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}
