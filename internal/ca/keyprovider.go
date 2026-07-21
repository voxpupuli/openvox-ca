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
	"errors"
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
