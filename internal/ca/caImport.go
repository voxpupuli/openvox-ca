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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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

	lockCtx, cancel := context.WithTimeout(ctx, LockTimeout)
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

	// --- Check the CRL is acceptable before writing anything ---
	//
	// The CRL step can refuse — it could not before this branch — and the cert
	// and key writes below are not undoable, so discovering the refusal
	// afterwards would leave a replaced certificate beside an untouched old CRL.
	// This is a validation pass only: its result is deliberately discarded, and
	// the authoritative decision is taken again under the CRL lock below, so
	// that the read it depends on and the write that follows are atomic with
	// respect to a concurrent revocation.
	if _, _, _, err := planCRLImport(ctx, store, crlPEM, caCert, signer); err != nil {
		return err
	}

	// --- Write CA key, when there is one to write ---
	//
	// Nil when the key lives at a provider: import-ca-cert proves the
	// certificate binds the provider's key and never sees key material, so
	// there is no blob to store.
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
	// Past the point of no return: SaveCACert above has already replaced the
	// certificate, so any failure here leaves storage inconsistent and takes
	// the incompleteImportError annotation. That covers savePubKeyPEM's
	// marshalling half too, which AssertSignerMatchesCert has already ruled out
	// by marshalling this same public component to compare it with the
	// certificate.
	if err := savePubKeyPEM(ctx, store, signer.Public()); err != nil {
		return incompleteImportError(fmt.Errorf("failed to write CA public key: %w", err), retry)
	}

	// --- Decide and write the CRL, both under the lock ---
	//
	// The whole read-modify-write is inside the lock: a revocation landing
	// between the read and the write would otherwise be silently discarded and
	// the CRL number would regress, which metrics.md documents as monotonic.
	// Re-import is the documented way to refresh ancestor CRLs on a CA that has
	// been issuing for months, so that window is not hypothetical.
	//
	// The lock is cross-process on every backend since #187 — the single-node
	// ones coordinate two processes on a host with flock(2) — so a live import
	// no longer loses a concurrent revocation. The documentation still says to
	// stop the server first, because the inventory append this and the server
	// both perform is under no shared lock on any backend (#204).
	//
	// A nil plan means the stored chain is already exactly what should be there,
	// so nothing is written — re-taking the lock to rewrite identical bytes
	// would still bump the stored modification time, and every agent would
	// re-download a CRL that had not changed.
	lockCtx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	if err := store.WithLock(lockCtx, lockNameCRL, func() error {
		plan, superseded, changed, err := planCRLImport(ctx, store, crlPEM, caCert, signer)
		if err != nil {
			return err
		}
		// Logged here, not inside orderCRLChain: planCRLImport runs twice -- once
		// to validate before anything is written, once under the lock -- so a
		// warning inside it reported one problem as two.
		if superseded > 0 {
			slog.Warn("Discarding superseded copies of this CA's own CRL from the imported chain",
				"discarded", superseded, "kept_crl_number", plan[0].Number)
		}
		// Checked before the early return, so every import shape gets it --
		// including the two that write nothing. These are pure reads of the chain
		// about to be published, and an import that changes nothing still leaves
		// a lapsed ancestor being served to every agent. This warning is the only
		// detector of that: no series and no alert covers ancestor expiry.
		if len(plan) > 1 {
			warnAboutAncestors(plan[1:])
		}
		if !changed {
			return nil
		}
		return writeCRLChain(ctx, store, plan)
	}); err != nil {
		return err
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

// planCRLImport decides what the stored CRL chain should become, without
// writing anything, so a refusal cannot leave the cert and key already replaced.
// It returns the chain that will be published, how many superseded copies of our
// own CRL it discarded, and whether writing it would change anything: false means
// the stored chain is already correct and must be left alone. The chain is
// returned either way, because the caller's ancestor checks have to run on what is
// being served, not only on what is being written. The discard count is returned
// rather than logged because this function runs twice per import.
//
// crlPEM may be nil, meaning the operator supplied no --crl-chain. That is not
// an instruction to discard the stored CRL: it used to generate a fresh empty
// one and overwrite, which on a CA that had been issuing for months destroyed
// every ancestor block this branch exists to preserve *and* every revocation
// recorded so far — silently, and looking entirely healthy afterwards, because
// block 0 was legitimately ours. Nothing supplied means nothing to change.
func planCRLImport(ctx context.Context, store *storage.StorageService, crlPEM []byte,
	caCert *x509.Certificate, caKey crypto.Signer,
) ([]*x509.RevocationList, int, bool, error) {
	stored, err := storedCRLChain(ctx, store)
	if err != nil {
		return nil, 0, false, err
	}

	if crlPEM == nil {
		if len(stored) > 0 {
			// Keep what is there. Reordering it is still worth doing, since a
			// foreign block 0 makes every reader answer revocation questions
			// from the wrong list.
			ordered, dropped, foundOurs := orderCRLChain(stored, caCert)
			if !foundOurs {
				return nil, 0, false, fmt.Errorf("the stored CRL chain contains no CRL signed by the CA certificate "+
					"being imported, and no --crl-chain was supplied to replace it: pass --crl-chain "+
					"with this CA's own CRL, or remove the stored CRL to have a fresh empty one generated "+
					"(%d block(s) currently stored)", len(stored))
			}
			if sameCRLOrder(stored, ordered) {
				// Already exactly right: writing identical bytes would bump the
				// stored modification time and make every agent re-download.
				return ordered, dropped, false, nil
			}
			return ordered, dropped, true, nil
		}
		generated, err := newEmptyCRL(caCert, caKey, CRLValidity)
		if err != nil {
			return nil, 0, false, err
		}
		return []*x509.RevocationList{generated}, 0, true, nil
	}

	// Every CRL block must parse. The blob is served verbatim to every agent,
	// and Puppet's default certificate_revocation = chain makes an agent parse
	// all of it, so an unparseable block further down would surface as a broken
	// CRL across the fleet rather than as an import error here.
	incoming, err := decodeCRLChain(crlPEM)
	if err != nil {
		return nil, 0, false, fmt.Errorf("crl-chain: %w", err)
	}
	if len(incoming) == 0 {
		return nil, 0, false, fmt.Errorf("crl-chain does not contain a valid X509 CRL PEM block")
	}

	// Every reader takes block 0 as this CA's own CRL, so put it there. An
	// operator assembling a chain by hand has no reason to know that, and
	// correcting it once at import is better than misreading it on every
	// subsequent load.
	ordered, superseded, foundOurs := orderCRLChain(incoming, caCert)
	if foundOurs {
		// A supplied chain is authoritative about *ancestors*, but not about which
		// copy of our own CRL is current. An operator assembling one bundle from a
		// backup directory can easily supply a stale export of ours alongside the
		// ancestors they meant to refresh, and writing it back regresses the CRL
		// number and un-publishes every revocation recorded since -- deleting the
		// only current copy, where the two adjacent cases (two copies in the
		// bundle, two in storage) merely choose between copies that both survive.
		//
		// So the same newest-wins rule applies across the two sources.
		if stale := ownCRLIn(stored, caCert); stale != nil && newerCRL(stale, ordered[0]) {
			slog.Warn("The supplied chain's copy of this CA's CRL is older than the stored one; "+
				"keeping the stored copy",
				"supplied_crl_number", ordered[0].Number, "stored_crl_number", stale.Number)
			ordered[0] = stale
		}
	}
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
			ourCRL, err = newEmptyCRL(caCert, caKey, CRLValidity)
			if err != nil {
				return nil, 0, false, err
			}
		}
		ordered = append([]*x509.RevocationList{ourCRL}, ordered...)
	}
	// A supplied chain is authoritative, so it is always written -- even when it
	// happens to match, since the operator asked for it and the re-encode is
	// byte-identical anyway.
	return ordered, superseded, true, nil
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

// ownCRLIn returns the newest CRL in chain that cert signed, or nil when there is
// none.
//
// Newest, not first, and by the same newerCRL comparison orderCRLChain applies to
// an incoming bundle -- the two answer the same question about different inputs,
// and a stored blob can hold more than one block of ours. The released build's
// import validated block 0 and then wrote the operator's bundle verbatim, so
// `--crl-chain stale.pem current.pem root.pem` is a stored shape this code has to
// read after an upgrade.
//
// Taking the first match there resolved to the stale copy, and an ancestors-only
// refresh -- the documented way to refresh ancestors -- then promoted it to block
// 0. The CRL number regresses and every revocation recorded after the stale
// export stops being published, silently: the import path emits no chain-length
// warning, and orderCRLChain's superseded warning only ever sees the incoming
// bundle, which holds none of ours on that path.
func ownCRLIn(chain []*x509.RevocationList, cert *x509.Certificate) *x509.RevocationList {
	var ours *x509.RevocationList
	for _, crl := range chain {
		if crlSignedBy(cert, crl) && (ours == nil || newerCRL(crl, ours)) {
			ours = crl
		}
	}
	return ours
}
