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
)

// ErrKeyProviderKeyNotFound is returned (wrapped) by KeyProvider.Load when the
// provider's backing key does not exist yet. Implementations outside this
// package (e.g. internal/signer/openbao's Transit-backed KeyProvider) return this
// exact sentinel so CA.Init can tell "no key yet, safe to bootstrap" apart
// from a real error (e.g. the backend is unreachable) without depending on
// provider-specific error types.
var ErrKeyProviderKeyNotFound = errors.New("key provider: key not found")

// KeyProvider abstracts where the CA's own private key lives and how a
// crypto.Signer for it is obtained. A nil KeyProvider on CA preserves today's
// behaviour exactly: the key is a PEM blob read/written through c.Storage
// (SaveCAKey/GetCAKey/HasCAKey), optionally encrypted with a passphrase (see
// keyenc.go).
//
// Set before calling Init(). Mutually exclusive with ExternalSigner: a
// KeyProvider is consulted only by the process that actually holds/reaches
// the key (the isolated signer child, or the single-process role);
// ExternalSigner is used by the frontend, which never loads or generates a
// key itself and instead proxies Sign calls to that process over IPC.
//
// Verification contract: a returned crypto.Signer must sign under exactly the
// key its Public() reports. The CA relies on this to catch a key rotated at
// its provider out from under a running process — loadCA pins Public() to the
// CA certificate at startup, and x509.CreateCertificate re-verifies every
// issued signature against that same public key (see signing.go), so a signer
// that starts signing with a different key is rejected rather than emitting an
// unverifiable certificate. Implementations must not silently rotate the key
// backing an already-loaded Signer.
type KeyProvider interface {
	// Load returns a Signer for the provider's existing key. Returns an
	// error wrapping ErrKeyProviderKeyNotFound if none exists yet.
	Load(ctx context.Context) (crypto.Signer, error)

	// Generate creates a new key per cfg and returns a Signer for it. It is
	// normally reached only during CA bootstrap, after Load has reported no key
	// exists — but implementations MUST NOT assume that: Generate MUST fail
	// (not rotate or overwrite) if a key already exists. The CA can reach this
	// method with a key already present in a disaster-recovery edge (cert lost,
	// provider key persists), and for a provider whose "create" is really
	// create-or-rotate that would silently rotate the live CA key. The CA also
	// guards this at the call site (see Init), so the two checks are
	// defence-in-depth; a provider must still fail closed on its own.
	Generate(ctx context.Context, cfg KeyConfig) (crypto.Signer, error)
}

// hasCAKey reports whether the CA's private key already exists, using
// KeyProvider when one is configured (so an OpenBao/PKCS#11-backed key is checked
// at its actual source) or falling back to the Storage-backed blob check
// otherwise. Checking Storage.HasCAKey when a KeyProvider is set would always
// report false (no local key blob is ever written in that mode) and would
// wrongly look like "no key yet" any time loadCA fails for an unrelated
// reason (e.g. a transient provider outage), causing Init to bootstrap a
// second key on top of an already-bootstrapped CA.
func (c *CA) hasCAKey(ctx context.Context) (bool, error) {
	if c.KeyProvider != nil {
		_, err := c.KeyProvider.Load(ctx)
		if err == nil {
			return true, nil
		}
		if errors.Is(err, ErrKeyProviderKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	return c.Storage.HasCAKey(ctx)
}

// LoadOrCreateCAKey resolves this CA's private key without requiring that a CA
// certificate exist yet.
//
// Init and loadCA cannot serve this case: they load the key *and* the
// certificate and pin one to the other, which is exactly right once the CA is
// established and useless beforehand. Producing a certificate signing request
// for an external parent to sign is the one operation that legitimately needs
// the key alone — the certificate it will eventually be bound to does not exist
// until the parent has signed.
//
// When create is true and no key exists, one is generated: at the provider when
// a KeyProvider is configured, otherwise locally and written through Storage
// honouring EncryptCAKey. When create is false a missing key is reported as
// ErrKeyProviderKeyNotFound so the caller can name the flag that would create
// it.
func (c *CA) LoadOrCreateCAKey(ctx context.Context, create bool) (crypto.Signer, error) {
	keyCfg := c.CAKeyConfig
	if keyCfg.Algo == "" {
		keyCfg = DefaultCAKeyConfig
	}

	if c.KeyProvider != nil {
		key, err := c.KeyProvider.Load(ctx)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, ErrKeyProviderKeyNotFound) {
			return nil, err
		}
		if !create {
			return nil, err
		}
		return c.KeyProvider.Generate(ctx, keyCfg)
	}

	// Local key: present in storage, or generated and written here.
	hasKey, err := c.Storage.HasCAKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking for an existing CA key: %w", err)
	}
	if hasKey {
		c.mu.Lock()
		defer c.mu.Unlock()
		if err := c.loadCAKeyFromDisk(ctx); err != nil {
			return nil, err
		}
		return c.CAKey, nil
	}
	if !create {
		return nil, fmt.Errorf("%w: no CA key in storage", ErrKeyProviderKeyNotFound)
	}

	// Creating the key is a storage mutation two operators can race — two
	// `csr --create-key` runs against a shared backend — and the loser would
	// overwrite a key the winner has already sent to a parent for signing. Take
	// the lock bootstrap uses and re-check inside it.
	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	var created crypto.Signer
	if err := c.Storage.WithLock(lockCtx, lockNameBootstrap, func() error {
		hasKey, err := c.Storage.HasCAKey(ctx)
		if err != nil {
			return fmt.Errorf("checking for an existing CA key: %w", err)
		}
		if hasKey {
			return nil
		}
		key, err := generateKey(keyCfg)
		if err != nil {
			return fmt.Errorf("generating CA key: %w", err)
		}
		keyPEM, err := c.marshalCAKeyForStorage(key)
		if err != nil {
			return err
		}
		if err := c.Storage.EnsureDirs(ctx); err != nil {
			return fmt.Errorf("creating CA directories: %w", err)
		}
		if err := c.Storage.SaveCAKey(ctx, keyPEM); err != nil {
			return fmt.Errorf("writing CA key: %w", err)
		}
		created = key
		return nil
	}); err != nil {
		return nil, err
	}
	if created != nil {
		return created, nil
	}

	// Lost the race: load what the winner wrote. Outside the storage lock, so
	// c.mu is never taken while holding it.
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.loadCAKeyFromDisk(ctx); err != nil {
		return nil, err
	}
	return c.CAKey, nil
}

// marshalCAKeyForStorage encodes a freshly generated CA key for persistence,
// applying at-rest encryption when EncryptCAKey is set.
//
// The single encoder for both paths that create a CA key — bootstrapCA and
// csr --create-key — so a key created by either is indistinguishable from the
// other. It is shared rather than merely mirrored because the failure mode of a
// divergence is silent and severe: a CA key written in plaintext despite
// encrypt_ca_key, discovered whenever someone next reads the file.
func (c *CA) marshalCAKeyForStorage(key crypto.Signer) ([]byte, error) {
	if !c.EncryptCAKey {
		keyPEM, err := marshalPrivateKeyPEM(key)
		if err != nil {
			return nil, fmt.Errorf("marshalling CA key: %w", err)
		}
		return keyPEM, nil
	}
	passphrase, autoGenerated, err := resolvePassphrase(c.KeyPassphrase, c.Storage.CADir())
	if err != nil {
		return nil, fmt.Errorf("resolving CA key passphrase: %w", err)
	}
	keyPEM, err := encryptAndMarshalKey(key, passphrase)
	if err != nil {
		return nil, fmt.Errorf("encrypting CA key: %w", err)
	}
	if autoGenerated {
		slog.Info("CA key passphrase auto-generated", "path", autoPassphrasePath(c.Storage.CADir()))
	}
	slog.Info("CA private key encrypted at rest")
	return keyPEM, nil
}

// BuildCSR produces a PKCS#10 certificate signing request for this CA's own
// key, for an external parent to sign, resolving the key through
// LoadOrCreateCAKey (see there for what create means).
//
// The subject is taken from an existing CA certificate when there is one, so a
// re-issuance reproduces the established DN byte for byte; otherwise it is
// built from hostname and the configured subject fields, identically to what
// bootstrapCA would self-sign.
//
// The subject is resolved before the key, and deliberately so: a run that
// cannot determine a subject must not leave a newly created CA key behind. At a
// provider that key may not be removable with openvox-ca at all, and it is the
// state Init refuses to start over.
//
// The request deliberately carries no BasicConstraints extension. A parent CA
// sets basic constraints from its own policy, and openvox-ca's own signing path
// rejects CSRs asserting CA:TRUE — so requesting it would produce an artefact a
// sibling openvox-ca could not sign.
func (c *CA) BuildCSR(ctx context.Context, hostname string, create bool) ([]byte, error) {
	subject, rawSubject, err := c.csrSubject(ctx, hostname)
	if err != nil {
		return nil, err
	}

	key, err := c.LoadOrCreateCAKey(ctx, create)
	if err != nil {
		return nil, err
	}

	// RawSubject preserves the established DN exactly. Re-encoding via
	// pkix.Name would emit Go's fixed attribute order and silently drop any
	// attribute pkix.Name does not model (DC, emailAddress) — on the one
	// artefact whose entire purpose is that a third party signs it and every
	// agent then matches the issuer against what it already trusts.
	template := &x509.CertificateRequest{Subject: subject, RawSubject: rawSubject}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// csrSubject resolves the DN a request should carry, returning both the parsed
// form and — when it comes from an existing certificate — its original DER.
//
// A storage failure is not "no certificate yet". Conflating them would let a
// transient backend fault or an unreadable ca_cert_file overlay make an
// established CA emit a request under a different DN, which a parent would then
// sign and import-ca-cert would accept: nothing downstream compares subjects.
func (c *CA) csrSubject(ctx context.Context, hostname string) (pkix.Name, []byte, error) {
	certPEM, err := c.Storage.GetCACert(ctx)
	switch {
	case err == nil:
		certs, err := ParseCABundle(certPEM)
		if err != nil {
			return pkix.Name{}, nil, fmt.Errorf("reading the existing CA certificate to reuse its subject: %w", err)
		}
		return certs[0].Subject, certs[0].RawSubject, nil
	case !errors.Is(err, fs.ErrNotExist):
		return pkix.Name{}, nil, fmt.Errorf("reading the existing CA certificate to reuse its subject: %w", err)
	}
	if hostname == "" {
		return pkix.Name{}, nil, fmt.Errorf("hostname is required to build a certificate request when no CA " +
			"certificate exists yet: set --hostname, PUPPET_CA_HOSTNAME, or hostname in the config file")
	}
	return CASubjectName(hostname, c.CASubject), nil, nil
}
