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

	// --- Validate the CRL bundle before writing anything ---
	//
	// Ahead of the writes below, deliberately. A rejection that had already
	// stored the key and certificate would leave a cadir the server starts
	// from — treating the absent CRL as a fresh install and seeding an empty
	// one (see seedSupportingState), so the revocations in the bundle the
	// operator was trying to import go silently missing. Failing before the
	// first write leaves storage untouched and the import repeatable.
	if crlPEM != nil {
		crlBlock, _ := pem.Decode(crlPEM)
		if crlBlock == nil {
			return fmt.Errorf("crl-chain does not contain a valid PEM block")
		}
		if _, err := x509.ParseRevocationList(crlBlock.Bytes); err != nil {
			return fmt.Errorf("failed to parse CRL: %w", err)
		}
		// Reject a bundle that does not lead with a CRL issued by the
		// certificate being imported.
		//
		// Block 0 is this CA's own CRL everywhere in the server — see
		// ownStoredCRLLocked — so a bundle that leads with an ancestor's
		// produces a CA that refuses to start. This command is the last point
		// at which the operator still has the file in front of them and can
		// reorder it; supplying an ancestor's CRL is an easy mistake to make
		// from the migration guide's recipe.
		if !bundleLeadsWithCRLFrom(crlPEM, caCert) {
			return fmt.Errorf("the first CRL in --crl-chain was not signed by the CA certificate being imported; " +
				"put this CA's own CRL first in the bundle (ancestors' CRLs may follow it)")
		}
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

	// --- Write CRL --- (already validated above, before any write)
	if crlPEM != nil {
		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, crlPEM); err != nil {
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
