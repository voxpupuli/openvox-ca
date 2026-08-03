// Copyright (C) 2026 Trevor Vaughan
// Copyright (C) 2026 Chris Boot
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
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"time"
)

// Named lock identifiers used with StorageService.WithLock. These names
// are stable across releases since every replica must agree on them for
// the cross-node coordination to work.
const (
	lockNameBootstrap = "bootstrap"
	lockNameCRL       = "crl"
	lockSubjectPrefix = "subject:"
)

// lockTimeout bounds how long Init/Sign/Revoke will wait to acquire a
// distributed lock before giving up. Long enough to ride out a brief
// leader election, short enough that a stuck lease on a crashed replica
// does not hang startup past the lease TTL on the etcd backend.
const lockTimeout = 60 * time.Second

// subjectLockName returns the distributed-lock name used to serialise
// operations on a single subject (CSR submission, signing, cleaning).
func subjectLockName(subject string) string { return lockSubjectPrefix + subject }

func (c *CA) Init(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// ExternalSigner (frontend proxying to an isolated signer) and KeyProvider
	// (this process reaching the key itself) are mutually exclusive by design:
	// a frontend never loads or generates a key, and loadCA would silently
	// prefer ExternalSigner and ignore the KeyProvider if both were set.
	// Reject the misconfiguration explicitly rather than let it pass quietly.
	if c.ExternalSigner != nil && c.KeyProvider != nil {
		return fmt.Errorf("CA misconfigured: ExternalSigner and KeyProvider are mutually exclusive")
	}

	if err := c.Storage.EnsureDirs(ctx); err != nil {
		return err
	}

	// Initialize inventory HMAC integrity checking.
	if err := c.Storage.InitHMAC(ctx); err != nil {
		return fmt.Errorf("inventory integrity check failed: %w", err)
	}

	// Fast path: load an already-bootstrapped CA without taking a
	// distributed lock. Once a CA exists, all replicas can read it.
	loadErr := c.loadCA(ctx)
	if loadErr == nil {
		return c.finishLoadExisting(ctx)
	}

	// When using an external signer (key isolation mode), the frontend must
	// never bootstrap a new CA (that's the signer's responsibility). If the
	// cert/CRL aren't on disk yet, the signer hasn't finished bootstrapping.
	if c.ExternalSigner != nil {
		return fmt.Errorf("failed to load CA in frontend mode (signer should have bootstrapped): %w", loadErr)
	}

	// Slow path: another replica may be bootstrapping right now. Acquire the
	// bootstrap lock before deciding whether to generate a fresh CA, and
	// re-check the keyspace after winning the lock so we don't race two
	// replicas into writing different CAs.
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	return c.Storage.WithLock(ctx, lockNameBootstrap, func() error {
		if err := c.loadCA(ctx); err == nil {
			slog.Info("Loaded CA bootstrapped by another replica", "cert", c.Storage.CACertPath())
			return c.finishLoadExisting(ctx)
		}
		hasCert, errCert := c.Storage.HasCACert(ctx)
		if errCert != nil {
			return fmt.Errorf("checking CA cert: %w", errCert)
		}
		hasKey, errKey := c.hasCAKey(ctx)
		if errKey != nil {
			return fmt.Errorf("checking CA key: %w", errKey)
		}
		// Fail closed when a KeyProvider already holds a key but the CA
		// certificate is missing (the DR case: storage/cert wiped while the
		// provider's key persists). bootstrapCA would call KeyProvider.Generate
		// on that populated slot, and a provider implementing Generate as
		// create-or-rotate would silently rotate the live CA key — destroying
		// the ability to verify every previously issued certificate. Refuse
		// with guidance rather than regenerate. (Only for KeyProvider mode:
		// the local-file bootstrap path keeps its long-standing behaviour.)
		if c.KeyProvider != nil && !hasCert && hasKey {
			return fmt.Errorf("CA key provider already holds a key but the CA certificate is missing from storage: "+
				"refusing to bootstrap, as that would rotate the existing CA key and invalidate all previously issued "+
				"certificates. Restore the CA certificate, or remove the orphaned provider key before bootstrapping: %w", loadErr)
		}
		if !hasCert || !hasKey {
			slog.Info("No existing CA found, bootstrapping new CA")
			return c.bootstrapCA(ctx)
		}
		return fmt.Errorf("failed to load existing CA: %w", loadErr)
	})
}

// finishLoadExisting runs the post-load bookkeeping (serial index, CRL
// cache). c.mu must be held by the caller. When the CRL is absent from the
// backend but the cert+key loaded successfully — the common case when an
// existing CA cert/key is mounted via an overlay against a fresh remote
// backend — seed the CRL, inventory, and serial counter under the bootstrap
// lock so startup can complete.
func (c *CA) finishLoadExisting(ctx context.Context) error {
	slog.Info("Loaded existing CA", "cert", c.Storage.CACertPath())
	if err := c.buildSerialIndex(ctx); err != nil {
		slog.Warn("Failed to build OCSP serial index", "error", err)
	}
	err := c.loadCRLCache(ctx)
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to load CRL into memory: %w", err)
	}
	// In frontend-only mode the signer process owns bootstrapping; a missing
	// CRL here means the signer hasn't finished yet and retrying is its job.
	if c.ExternalSigner != nil {
		return fmt.Errorf("failed to load CRL into memory: %w", err)
	}
	if err := c.seedSupportingState(ctx); err != nil {
		return fmt.Errorf("seeding CA supporting state: %w", err)
	}
	return c.loadCRLCache(ctx)
}

// seedSupportingState writes the CRL, inventory, and serial counter that
// bootstrapCA would normally create, for the case where the cert+key already
// exist (e.g. mounted via an overlay against an empty backend). Runs under
// the bootstrap lock so concurrent replicas don't race to seed.
func (c *CA) seedSupportingState(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	return c.Storage.WithLock(ctx, lockNameBootstrap, func() error {
		// Another replica may have seeded between our initial check and the
		// lock acquisition.
		if _, err := c.Storage.GetCRL(ctx); err == nil {
			return nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("re-checking CRL: %w", err)
		}
		now := time.Now().UTC()
		crlTemplate := &x509.RevocationList{
			Number:     big.NewInt(1),
			ThisUpdate: now,
			NextUpdate: now.Add(c.crlValidity()),
		}
		crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, c.CACert, c.CAKey)
		if err != nil {
			return fmt.Errorf("creating initial CRL: %w", err)
		}
		crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
		// Bootstrap-only write: runs before any CRL consumer exists, so it
		// deliberately skips the crlNotify signal (see signCRLLocked).
		if err := c.Storage.UpdateCRL(ctx, crlPEM); err != nil {
			return fmt.Errorf("writing initial CRL: %w", err)
		}
		if err := c.Storage.TouchInventory(ctx); err != nil {
			return fmt.Errorf("creating inventory: %w", err)
		}
		hasSerial, err := c.Storage.HasSerial(ctx)
		if err != nil {
			return fmt.Errorf("checking serial: %w", err)
		}
		if !hasSerial {
			if err := c.Storage.WriteSerial(ctx, "0001"); err != nil {
				return fmt.Errorf("writing serial: %w", err)
			}
		}
		slog.Info("Seeded CA supporting state for existing cert+key",
			"cert", c.Storage.CACertPath())
		return nil
	})
}

// loadCA reads and validates the CA key and certificate from disk.
// It accepts RSA keys (PKCS1 and PKCS8) and ECDSA keys (SEC1 and PKCS8),
// and verifies that the private key matches the certificate's public key.
//
// When ExternalSigner is set, key loading from disk is skipped entirely:
// the private key lives in a separate signer process and is never loaded
// into the frontend's address space. When KeyProvider is set instead, the
// key is loaded through it (e.g. an OpenBao Transit key) rather than from a
// local PEM file.
func (c *CA) loadCA(ctx context.Context) error {
	switch {
	case c.ExternalSigner != nil:
		// Key isolation mode: use the remote signer instead of loading the
		// private key from disk. The signer process verified key/cert match
		// when it loaded the key.
		c.CAKey = c.ExternalSigner
	case c.KeyProvider != nil:
		key, err := c.KeyProvider.Load(ctx)
		if err != nil {
			return err
		}
		c.CAKey = key
	default:
		if err := c.loadCAKeyFromDisk(ctx); err != nil {
			return err
		}
	}

	// Always load the certificate (it's public).
	certPEM, err := c.Storage.GetCACert(ctx)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	// Verify that the loaded key matches the certificate's public key.
	// Skip when using an external signer; the signer process verifies this,
	// and the RemoteSigner's Public() is derived from the cert anyway.
	if c.ExternalSigner == nil {
		certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal cert public key for validation: %w", err)
		}
		keyPubDER, err := x509.MarshalPKIXPublicKey(c.CAKey.Public())
		if err != nil {
			return fmt.Errorf("failed to marshal loaded key's public key for validation: %w", err)
		}
		if !bytes.Equal(certPubDER, keyPubDER) {
			return fmt.Errorf("CA private key does not match CA certificate's public key")
		}
	}

	c.CACert = cert
	return nil
}

// loadCAKeyFromDisk reads and parses the CA private key from disk.
// Supports RSA (PKCS1, PKCS8), ECDSA (SEC1, PKCS8), and encrypted PEM.
func (c *CA) loadCAKeyFromDisk(ctx context.Context) error {
	keyPEM, err := c.Storage.GetCAKey(ctx)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	// Handle encrypted keys: decrypt first, then parse the PKCS#8 DER.
	if isEncryptedPEM(block) {
		passphrase, _, err := resolvePassphrase(c.KeyPassphrase, c.Storage.CADir())
		if err != nil {
			return fmt.Errorf("resolving CA key passphrase: %w", err)
		}
		pkcs8DER, err := decryptKeyDER(block.Bytes, passphrase)
		if err != nil {
			return fmt.Errorf("decrypting CA key: %w", err)
		}
		k, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
		if err != nil {
			return fmt.Errorf("parsing decrypted CA key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return fmt.Errorf("decrypted CA key does not implement crypto.Signer")
		}
		c.CAKey = signer
		return nil
	}

	key, err := parsePrivateKeyDER(block.Type, block.Bytes)
	if err != nil {
		return err
	}
	c.CAKey = key
	return nil
}

func (c *CA) bootstrapCA(ctx context.Context) error {
	hostname := c.Hostname
	if hostname == "" {
		hostname = "puppet"
	}

	// Resolve key config; fall back to default if not set.
	keyCfg := c.CAKeyConfig
	if keyCfg.Algo == "" {
		keyCfg = DefaultCAKeyConfig
	}

	slog.Debug("Generating CA key", "algo", string(keyCfg.Algo), "size", keyCfg.Size)
	var key crypto.Signer
	var err error
	if c.KeyProvider != nil {
		key, err = c.KeyProvider.Generate(ctx, keyCfg)
	} else {
		key, err = generateKey(keyCfg)
	}
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// SubjectKeyIdentifier: SHA-1 of SubjectPublicKeyInfo DER (RFC 5280 §4.2.1.2).
	subjectKeyID, err := subjectKeyIDFromPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("failed to compute SubjectKeyIdentifier: %w", err)
	}

	// Build subject DN.
	subject := pkix.Name{
		CommonName: "Puppet CA: " + hostname,
	}
	if c.CASubject.Org != "" {
		subject.Organization = []string{c.CASubject.Org}
	}
	if c.CASubject.OrgUnit != "" {
		subject.OrganizationalUnit = []string{c.CASubject.OrgUnit}
	}
	if c.CASubject.Country != "" {
		subject.Country = []string{c.CASubject.Country}
	}
	if c.CASubject.Locality != "" {
		subject.Locality = []string{c.CASubject.Locality}
	}
	if c.CASubject.Province != "" {
		subject.Province = []string{c.CASubject.Province}
	}

	now := time.Now().UTC()

	caValidity := certValidity
	if c.CAValidityDays > 0 {
		caValidity = time.Duration(c.CAValidityDays) * 24 * time.Hour
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID,
	}

	// Apply pathLenConstraint when CAPathLength >= 0.
	// -1 (the default) means unconstrained: leave MaxPathLen/MaxPathLenZero at
	// their zero values, which Go's x509 package interprets as "no constraint".
	if c.CAPathLength >= 0 {
		template.MaxPathLen = c.CAPathLength
		template.MaxPathLenZero = (c.CAPathLength == 0)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return fmt.Errorf("failed to create CA cert: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA cert: %w", err)
	}
	c.CAKey = key
	c.CACert = parsedCert

	// Save private key. Skipped entirely when KeyProvider is set: the key
	// lives at its provider (e.g. an OpenBao Transit key) and there is no
	// local blob to write or encrypt.
	if c.KeyProvider == nil {
		var keyPEM []byte
		if c.EncryptCAKey {
			passphrase, autoGenerated, err := resolvePassphrase(c.KeyPassphrase, c.Storage.CADir())
			if err != nil {
				return fmt.Errorf("resolving CA key passphrase: %w", err)
			}
			keyPEM, err = encryptAndMarshalKey(key, passphrase)
			if err != nil {
				return fmt.Errorf("encrypting CA key: %w", err)
			}
			if autoGenerated {
				slog.Info("CA key passphrase auto-generated",
					"path", autoPassphrasePath(c.Storage.CADir()))
			}
			slog.Info("CA private key encrypted at rest")
		} else {
			keyPEM, err = marshalPrivateKeyPEM(key)
			if err != nil {
				return fmt.Errorf("failed to marshal CA key: %w", err)
			}
		}
		if err := c.Storage.SaveCAKey(ctx, keyPEM); err != nil {
			return fmt.Errorf("failed to write CA key: %w", err)
		}
	}

	// Save CA cert.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err := c.Storage.SaveCACert(ctx, certPEM); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}

	// Write a public key file alongside the cert.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	if err == nil {
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
		_ = c.Storage.SaveCAPubKey(ctx, pubKeyPEM)
	}

	// Generate empty CRL.
	crlTemplate := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(c.crlValidity()),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, c.CACert, c.CAKey)
	if err != nil {
		return fmt.Errorf("failed to create initial CRL: %w", err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	// Bootstrap-only write: runs before any CRL consumer exists, so it
	// deliberately skips the crlNotify signal (see signCRLLocked).
	if err := c.Storage.UpdateCRL(ctx, crlPEM); err != nil {
		return fmt.Errorf("failed to write initial CRL: %w", err)
	}

	// Cache the CRL we just created.
	parsedCRL, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return fmt.Errorf("failed to parse initial CRL for cache: %w", err)
	}
	c.cachedCRL = parsedCRL

	// Touch inventory.
	if err := c.Storage.TouchInventory(ctx); err != nil {
		return fmt.Errorf("failed to create inventory: %w", err)
	}

	slog.Info("CA bootstrapped",
		"cn", template.Subject.CommonName,
		"algo", string(keyCfg.Algo),
		"size", keyCfg.Size,
		"cadir", c.Storage.CADir(),
	)
	return nil
}

// loadCRLCache reads the CRL from disk and caches it in memory.
// Must be called with c.mu held.
func (c *CA) loadCRLCache(ctx context.Context) error {
	crlPEM, err := c.Storage.GetCRL(ctx)
	if err != nil {
		return fmt.Errorf("reading CRL: %w", err)
	}
	// Block 0 is parsed on its own, and is the only part whose failure is fatal.
	// Decoding the whole blob here would make a single corrupt trailing block
	// abort startup — which is both harsher than this function's own policy for
	// a strictly worse condition (a foreign block 0, warned about below) and
	// unnecessary: the cache answers from block 0, and handleGetCRL streams the
	// blob without parsing it, so a malformed ancestor block affects neither.
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		return fmt.Errorf("CRL is empty or not PEM-encoded")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CRL: %w", err)
	}

	// The cache answers "did we revoke this serial", so it must hold our own
	// CRL. Block 0 is ours by construction — signCRLLocked writes it first and
	// import reorders to match — but a hand-assembled blob could put an
	// ancestor's CRL there, and checking revocation against an ancestor's list
	// would let a certificate this CA revoked go on authenticating.
	//
	// A warning rather than a hard failure: refusing to start leaves the CA
	// entirely unavailable, where continuing gives a running CA with a loud,
	// actionable message. The write path (readStoredCRL) does fail closed,
	// because re-signing over an ancestor's CRL destroys it.
	//
	// The remedy offered is a re-import. 'openvox-ca-ctl reissue-crl' is
	// deliberately not suggested: it reaches readStoredCRL and fails closed on
	// this very condition, so it would send the operator to a command that
	// returns 500 without surfacing why.
	if !c.ownsCRL(crl) {
		slog.Warn("Stored CRL does not lead with this CA's own CRL; revocation checks may be using the wrong list. "+
			"Re-import the CRL chain with this CA's own CRL first",
			"crl_authority_key_id", fmt.Sprintf("%x", crl.AuthorityKeyId),
			"ca_subject_key_id", fmt.Sprintf("%x", c.CACert.SubjectKeyId))

		// Search the rest of the chain for the block this CA actually signed,
		// rather than answering revocation questions from an ancestor's list —
		// which contains none of our serials, so every certificate we revoked
		// would authenticate.
		//
		// When the chain holds no block of ours at all there is nothing better
		// to cache, so the foreign block stays: the same outcome as an empty
		// CRL, and the deliberate availability trade-off described above. A
		// chain that will not decode is treated the same way — the warning
		// stands, and startup continues.
		if chain, decodeErr := decodeCRLChain(crlPEM); decodeErr == nil {
			if ours := ownCRLIn(chain, c.CACert); ours != nil {
				slog.Warn("Using this CA's own CRL found later in the stored chain",
					"position", indexOfCRL(chain, ours))
				crl = ours
			}
		} else {
			slog.Warn("Could not decode the stored CRL chain to look for this CA's own block; "+
				"continuing with block 0", "error", decodeErr)
		}
	}

	c.cachedCRL = crl
	return nil
}

// indexOfCRL returns the position of crl in chain, for diagnostics.
func indexOfCRL(chain []*x509.RevocationList, crl *x509.RevocationList) int {
	for i, candidate := range chain {
		if candidate == crl {
			return i
		}
	}
	return -1
}
