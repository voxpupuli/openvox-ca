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
	"errors"
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
// This is a thin wrapper over ImportCAMaterial for the case where the CA's
// private key is a local PEM blob. When the key lives at a provider (an OpenBao
// Transit key, a PKCS#11 token) there is no blob to pass and callers use
// ImportCAMaterial directly with a crypto.Signer.
//
// This is an offline operation; no CA daemon is required.
func ImportCA(ctx context.Context, store *storage.StorageService, certBundlePEM, keyPEM, crlPEM []byte) error {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("private-key does not contain a valid PEM block")
	}
	caKey, err := parsePrivateKeyDER(keyBlock.Type, keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return ImportCAMaterial(ctx, store, certBundlePEM, keyPEM, crlPEM, caKey, CRLValidity)
}

// ErrCACertExists reports that storage already holds a CA certificate and the
// caller did not ask to replace it.
var ErrCACertExists = errors.New("a CA certificate already exists")

// ErrCACertWrite wraps a failure to write the CA certificate blob, so callers
// can tell it apart from the validation and CRL failures that surround it.
// Guidance about read-only mounts is only ever right for this one.
var ErrCACertWrite = errors.New("writing the CA certificate")

// retryHint is how a caller finishes an import that failed after the CA
// certificate had already been written. It differs per entry point, and getting
// it wrong is worst precisely here: the operator reads it while storage is
// knowingly inconsistent, so a remedy their command rejects costs them a round
// trip at the least convenient moment.
type retryHint string

const (
	// retryWithForce suits ImportCACertificate, whose command has --force and
	// whose existing-certificate check would otherwise refuse the re-run.
	retryWithForce retryHint = "re-run this command with --force to finish the import"
	// retryPlain suits ImportCA: openvox-ca-ctl import has no --force flag, and
	// performs no existing-certificate check, so a plain re-run finishes the job.
	retryPlain retryHint = "re-run this command to finish the import"
)

// incompleteImportError annotates a failure that happened after the CA
// certificate was already written.
//
// Storage is then holding the new certificate beside a CRL — and possibly a
// public key — belonging to whatever was there before, and nothing detects that
// afterwards: loadCA compares the key to the certificate, and loadCRLCache
// parses the CRL without checking who issued it. So a replica restarted in this
// state comes up cleanly and serves a CRL no agent can verify against the CA
// certificate it just fetched. The operator has to know to act, which means the
// error has to say so.
func incompleteImportError(err error, retry retryHint) error {
	return fmt.Errorf("%w. The CA certificate has already been written, so storage is "+
		"now inconsistent: %s, or run 'openvox-ca-ctl reissue-crl' to re-sign the CRL "+
		"under the new certificate", err, retry)
}

// ImportCACertificate installs a CA certificate chain signed by an external
// parent, for a CA whose private key is held elsewhere — a Transit key, a
// PKCS#11 token, or a local blob this function never touches.
//
// signer proves the certificate binds this CA's key. When storage already holds
// a certificate the import is refused unless force is set, in which case the
// stored CRL is re-signed under the incoming certificate so it stays verifiable.
//
// The whole sequence runs under the bootstrap lock. Replacing a live CA
// certificate is a read-modify-write spanning the certificate and the CRL, and
// the documented procedure restarts replicas *after* the import — so replicas
// are serving throughout. Without the lock a revocation landing mid-import
// either overwrites the re-signed CRL with one nothing can verify, or is itself
// lost. Reporting whether a certificate was replaced lets the caller name the
// restart that must follow.
func ImportCACertificate(ctx context.Context, store *storage.StorageService, certBundlePEM []byte, signer crypto.Signer, crlValidity time.Duration, force bool) (replaced bool, err error) {
	certs, err := ParseCABundle(certBundlePEM)
	if err != nil {
		return false, fmt.Errorf("cert-bundle: %w", err)
	}
	if err := ValidateCABundleOrder(certs); err != nil {
		return false, fmt.Errorf("cert-bundle: %w", err)
	}
	if err := AssertSignerMatchesCert(certs[0], signer); err != nil {
		return false, err
	}

	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	err = store.WithLock(lockCtx, lockNameBootstrap, func() error {
		hasCert, err := store.HasCACert(ctx)
		if err != nil {
			return fmt.Errorf("checking for an existing CA certificate: %w", err)
		}
		if hasCert && !force {
			return fmt.Errorf("%w: refusing to replace it, because every certificate issued under the "+
				"current one stops verifying if the replacement does not chain to it. Pass --force if "+
				"that is intended", ErrCACertExists)
		}
		replaced = hasCert

		// The stored CRL was signed by the key being replaced and names the
		// subject being replaced; whether this import is a re-key, a re-subject
		// or both, nothing can verify it afterwards. Revocation entries are
		// carried across.
		var crlPEM []byte
		if hasCert {
			crlPEM, err = ResignStoredCRL(ctx, store, certs[0], signer, crlValidity)
			if err != nil {
				return err
			}
		}
		return importCAMaterial(ctx, store, certBundlePEM, nil, crlPEM, signer, crlValidity, retryWithForce)
	})
	if err != nil {
		return false, err
	}
	return replaced, nil
}

// ImportCAMaterial writes an externally-issued CA certificate bundle and its
// CRL into storage, after proving that signer holds the private key the leading
// certificate binds.
//
// signer is the proof, not the payload: it establishes that this CA will be
// able to sign under the certificate being imported. keyPEM is the payload and
// may be nil — when the key lives at a provider there is no blob to persist,
// and passing nil skips the key write entirely while leaving every other check
// in place. Callers holding a local key pass both; the two are redundant by
// construction in that case, and deliberately so, because the roles differ.
//
// crlPEM may be nil, in which case a fresh empty CRL is generated and signed
// with signer, valid for crlValidity.
func ImportCAMaterial(ctx context.Context, store *storage.StorageService, certBundlePEM, keyPEM, crlPEM []byte, signer crypto.Signer, crlValidity time.Duration) error {
	return importCAMaterial(ctx, store, certBundlePEM, keyPEM, crlPEM, signer, crlValidity, retryPlain)
}

func importCAMaterial(ctx context.Context, store *storage.StorageService, certBundlePEM, keyPEM, crlPEM []byte, signer crypto.Signer, crlValidity time.Duration, retry retryHint) error {
	// --- Parse and validate the certificate bundle ---
	certs, err := ParseCABundle(certBundlePEM)
	if err != nil {
		return fmt.Errorf("cert-bundle: %w", err)
	}
	if err := ValidateCABundleOrder(certs); err != nil {
		return fmt.Errorf("cert-bundle: %w", err)
	}
	caCert := certs[0]

	// --- SECURITY: prove the signer holds the key this certificate binds ---
	if err := AssertSignerMatchesCert(caCert, signer); err != nil {
		return err
	}

	// --- Ensure directories exist ---
	if err := store.EnsureDirs(ctx); err != nil {
		return fmt.Errorf("failed to create CA directories: %w", err)
	}

	// --- Write CA key, when there is one to write ---
	if keyPEM != nil {
		if err := store.SaveCAKey(ctx, keyPEM); err != nil {
			return fmt.Errorf("failed to write CA key: %w", err)
		}
	}

	// --- Write CA cert (the whole bundle, root last) ---
	// Re-encoded from the parsed chain rather than passed through, so what is
	// stored and served is exactly what was validated. The DER is unchanged.
	//
	// This is the point of no return. Everything after it can still fail, and a
	// failure then leaves storage holding the new certificate beside material
	// signed under the old one — a state nothing detects on the next start,
	// because loadCA only checks key-against-certificate and loadCRLCache does
	// not verify the CRL's issuer at all. So every later error is annotated
	// with what already landed and what fixes it; see incompleteImportError.
	if err := store.SaveCACert(ctx, EncodeCABundle(certs)); err != nil {
		return fmt.Errorf("%w: %w", ErrCACertWrite, err)
	}

	// --- Write CA public key ---
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal signing key's public component: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	if err := store.SaveCAPubKey(ctx, pubKeyPEM); err != nil {
		return incompleteImportError(fmt.Errorf("failed to write CA public key: %w", err), retry)
	}

	// --- Handle CRL ---
	if crlPEM != nil {
		// Validate every block, not just the first: a CRL chain supplied here is
		// served verbatim to agents, so an unparseable block further down would
		// surface as a broken CRL on every node rather than an import error.
		//
		// SECURITY: a block that is not a CRL is refused rather than skipped,
		// and what gets stored is re-encoded from what parsed rather than the
		// operator's file. Both for the reason ParseCABundle gives for the
		// certificate bundle: this blob is world-readable and is served to
		// every agent unauthenticated, on a route that requires no client
		// certificate. Skipping unknown blocks and storing the file verbatim
		// would publish anything concatenated alongside the CRLs — including,
		// for a file assembled by the obvious `cat key.pem crl.pem` mistake,
		// the CA private key.
		var validated bytes.Buffer
		rest := crlPEM
		blocks := 0
		for {
			var crlBlock *pem.Block
			crlBlock, rest = pem.Decode(rest)
			if crlBlock == nil {
				break
			}
			if crlBlock.Type != "X509 CRL" {
				return fmt.Errorf("crl-chain contains a %q block: supply only CRLs, "+
					"as this file is stored world-readable and served to every agent",
					crlBlock.Type)
			}
			if _, err := x509.ParseRevocationList(crlBlock.Bytes); err != nil {
				return fmt.Errorf("failed to parse CRL %d in crl-chain: %w", blocks+1, err)
			}
			if err := pem.Encode(&validated, &pem.Block{Type: "X509 CRL", Bytes: crlBlock.Bytes}); err != nil {
				return fmt.Errorf("re-encoding CRL %d in crl-chain: %w", blocks+1, err)
			}
			blocks++
		}
		if blocks == 0 {
			return fmt.Errorf("crl-chain does not contain a valid X509 CRL PEM block")
		}
		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, validated.Bytes()); err != nil {
			return incompleteImportError(fmt.Errorf("failed to write CRL: %w", err), retry)
		}
	} else {
		// Generate a fresh empty CRL.
		now := time.Now().UTC()
		crlTemplate := &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now,
			NextUpdate: now.Add(crlValidity),
		}
		crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, signer)
		if err != nil {
			return incompleteImportError(fmt.Errorf("failed to create initial CRL: %w", err), retry)
		}
		generatedCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
		// Import-time write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := store.UpdateCRL(ctx, generatedCRL); err != nil {
			return incompleteImportError(fmt.Errorf("failed to write CRL: %w", err), retry)
		}
	}

	// --- Initialise serial if absent ---
	hasSerial, err := store.HasSerial(ctx)
	if err != nil {
		return incompleteImportError(fmt.Errorf("checking serial: %w", err), retry)
	}
	if !hasSerial {
		if err := store.WriteSerial(ctx, "0001"); err != nil {
			return incompleteImportError(fmt.Errorf("failed to write serial: %w", err), retry)
		}
	}

	// --- Initialise inventory if absent ---
	if err := store.TouchInventory(ctx); err != nil {
		return incompleteImportError(fmt.Errorf("failed to create inventory: %w", err), retry)
	}

	return nil
}
