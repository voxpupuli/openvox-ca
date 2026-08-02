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
	"io/fs"
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
// crlPEM may be nil, meaning no --crl-chain was supplied. That leaves the stored
// CRL chain as it is, reordered so this CA's own block leads; a fresh empty CRL
// is generated only when storage holds none, and the import is refused when
// storage holds a chain with no CRL of ours to lead it. It used to overwrite
// with a generated CRL unconditionally, which destroyed both the ancestor blocks
// and every recorded revocation.
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

	// --- Check the CRL is acceptable before writing anything ---
	//
	// The CRL step can refuse — it could not before this branch — and the cert
	// and key writes below are not undoable, so discovering the refusal
	// afterwards would leave a replaced certificate beside an untouched old CRL.
	// This is a validation pass only: its result is deliberately discarded, and
	// the authoritative decision is taken again under the CRL lock below, so
	// that the read it depends on and the write that follows are atomic with
	// respect to a concurrent revocation.
	if _, err := planCRLImport(ctx, store, crlPEM, caCert, caKey); err != nil {
		return err
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

	// --- Decide and write the CRL, both under the lock ---
	//
	// The whole read-modify-write is inside the lock: a revocation landing
	// between the read and the write would otherwise be silently discarded and
	// the CRL number would regress, which metrics.md documents as monotonic.
	// Re-import is the documented way to refresh ancestor CRLs on a CA that has
	// been issuing for months, so that window is not hypothetical.
	//
	// The lock is only genuinely cross-process on backends that implement one;
	// on filesystem and sqlite it degrades to a process-local mutex, so a live
	// import there still races the server and the documentation says to stop it
	// first.
	//
	// A nil plan means the stored chain is already exactly what should be there,
	// so nothing is written — re-taking the lock to rewrite identical bytes
	// would still bump the stored modification time, and every agent would
	// re-download a CRL that had not changed.
	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	if err := store.WithLock(lockCtx, lockNameCRL, func() error {
		plan, err := planCRLImport(ctx, store, crlPEM, caCert, caKey)
		if err != nil {
			return err
		}
		if plan == nil {
			return nil
		}
		// Warned here rather than inside orderCRLChain, so the checks run on
		// every import shape including the ancestors-only one.
		if len(plan) > 1 {
			warnAboutAncestors(plan[1:])
		}
		return writeCRLChain(ctx, store, plan)
	}); err != nil {
		return err
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

// planCRLImport decides what the stored CRL chain should become, without
// writing anything, so a refusal cannot leave the cert and key already replaced.
// A nil result means the stored chain is already correct and must be left alone.
//
// crlPEM may be nil, meaning the operator supplied no --crl-chain. That is not
// an instruction to discard the stored CRL: it used to generate a fresh empty
// one and overwrite, which on a CA that had been issuing for months destroyed
// every ancestor block this branch exists to preserve *and* every revocation
// recorded so far — silently, and looking entirely healthy afterwards, because
// block 0 was legitimately ours. Nothing supplied means nothing to change.
func planCRLImport(ctx context.Context, store *storage.StorageService, crlPEM []byte,
	caCert *x509.Certificate, caKey crypto.Signer,
) ([]*x509.RevocationList, error) {
	stored, err := storedCRLChain(ctx, store)
	if err != nil {
		return nil, err
	}

	if crlPEM == nil {
		if len(stored) > 0 {
			// Keep what is there. Reordering it is still worth doing, since a
			// foreign block 0 makes every reader answer revocation questions
			// from the wrong list.
			ordered, foundOurs := orderCRLChain(stored, caCert)
			if !foundOurs {
				return nil, fmt.Errorf("the stored CRL chain contains no CRL signed by the CA certificate "+
					"being imported, and no --crl-chain was supplied to replace it: pass --crl-chain "+
					"with this CA's own CRL, or remove the stored CRL to have a fresh empty one generated "+
					"(%d block(s) currently stored)", len(stored))
			}
			if sameCRLOrder(stored, ordered) {
				// Already exactly right: writing identical bytes would bump the
				// stored modification time and make every agent re-download.
				return nil, nil
			}
			return ordered, nil
		}
		generated, err := generateEmptyCRL(caCert, caKey)
		if err != nil {
			return nil, err
		}
		return []*x509.RevocationList{generated}, nil
	}

	// Every CRL block must parse. The blob is served verbatim to every agent,
	// and Puppet's default certificate_revocation = chain makes an agent parse
	// all of it, so an unparseable block further down would surface as a broken
	// CRL across the fleet rather than as an import error here.
	incoming, err := decodeCRLChain(crlPEM)
	if err != nil {
		return nil, fmt.Errorf("crl-chain: %w", err)
	}
	if len(incoming) == 0 {
		return nil, fmt.Errorf("crl-chain does not contain a valid X509 CRL PEM block")
	}

	// Every reader takes block 0 as this CA's own CRL, so put it there. An
	// operator assembling a chain by hand has no reason to know that, and
	// correcting it once at import is better than misreading it on every
	// subsequent load.
	ordered, foundOurs := orderCRLChain(incoming, caCert)
	if !foundOurs {
		// A chain of purely upstream CRLs is legitimate — an operator may
		// supply ancestors and expect this CA to issue its own. It is also how
		// someone refreshes ancestor CRLs with the tools available today, on a
		// CA that has been issuing for months.
		//
		// So prefer a CRL of ours already in storage over a fresh empty one.
		// Leading with an empty CRL would leave every reader taking block 0 and
		// concluding nothing is revoked, which looks entirely healthy and
		// silently un-revokes the fleet.
		ourCRL := ownCRLIn(stored, caCert)
		if ourCRL == nil {
			ourCRL, err = generateEmptyCRL(caCert, caKey)
			if err != nil {
				return nil, err
			}
		}
		ordered = append([]*x509.RevocationList{ourCRL}, ordered...)
	}
	return ordered, nil
}

// writeCRLChain persists a chain, re-encoded from the parsed blocks rather than
// passed through, so what is stored and served is exactly what was validated.
//
// Import-time write: it deliberately skips the crlNotify signal, which is not
// reachable from here (there is no CA instance). On a fresh import nothing is
// listening yet. On a live ancestor refresh that means consumers driven by the
// notification — the Kubernetes exporter above all — keep publishing the
// previous chain until the next re-sign or a restart, which the documentation
// says to follow the refresh with.
func writeCRLChain(ctx context.Context, store *storage.StorageService, chain []*x509.RevocationList) error {
	if err := store.UpdateCRL(ctx, encodeCRLChain(chain)); err != nil {
		return fmt.Errorf("failed to write CRL: %w", err)
	}
	return nil
}

// storedCRLChain returns the CRL blocks currently in storage.
//
// Absent is (nil, nil); anything else is an error. The distinction is the whole
// point: collapsing a failed read or an undecodable blob into "there is nothing
// stored" licenses the caller to overwrite with a fresh empty CRL, which
// discards every revocation recorded so far and leaves every reader concluding
// nothing is revoked. crlChainLocked draws the same line for the same reason,
// and the backend contract guarantees absence is reported as fs.ErrNotExist.
func storedCRLChain(ctx context.Context, store *storage.StorageService) ([]*x509.RevocationList, error) {
	existing, err := store.GetCRL(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the stored CRL before replacing it: %w", err)
	}
	stored, err := decodeCRLChain(existing)
	if err != nil {
		return nil, fmt.Errorf("decoding the stored CRL before replacing it: %w", err)
	}
	return stored, nil
}

// sameCRLOrder reports whether two chains hold the same blocks in the same
// order. Pointer identity is enough: both slices come from one decode.
func sameCRLOrder(a, b []*x509.RevocationList) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ownCRLIn returns the CRL in chain that cert signed, or nil when there is none.
func ownCRLIn(chain []*x509.RevocationList, cert *x509.Certificate) *x509.RevocationList {
	for _, crl := range chain {
		if crlSignedBy(cert, crl) {
			return crl
		}
	}
	return nil
}

// generateEmptyCRL signs a fresh, empty CRL for cert.
//
// Number 1 is correct because every caller has established that storage holds
// no CRL of ours to advance from — either storage is empty, or the imported
// chain carries only ancestors and nothing of ours was stored either.
// Re-signing an existing CRL goes through signCRLLocked, which bumps.
func generateEmptyCRL(cert *x509.Certificate, key crypto.Signer) (*x509.RevocationList, error) {
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
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the generated CRL: %w", err)
	}
	return crl, nil
}
