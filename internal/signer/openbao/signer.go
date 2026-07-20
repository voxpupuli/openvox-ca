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

package openbao

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/openbao/openbao/api/v2"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// Signer implements crypto.Signer by proxying every operation to an OpenBao
// Transit secrets engine key. The private key material never leaves OpenBao;
// this process only ever sends a digest and receives a signature back.
type Signer struct {
	tm    *TokenManager
	mount string
	key   string
	pub   crypto.PublicKey
}

// newSigner fetches the Transit key's current public component and wraps it
// as a Signer. Returns an error wrapping ca.ErrKeyProviderKeyNotFound if the
// key does not exist.
func newSigner(ctx context.Context, tm *TokenManager, mount, key string) (*Signer, error) {
	pub, err := fetchPublicKey(ctx, tm, mount, key)
	if err != nil {
		return nil, err
	}
	return &Signer{tm: tm, mount: mount, key: key, pub: pub}, nil
}

// Public returns the public key of the Transit key's current (latest)
// version, as cached at construction. The CA's own public key never
// changes after bootstrap, so this is not re-fetched per call.
func (s *Signer) Public() crypto.PublicKey {
	return s.pub
}

// Sign proxies the signing operation to OpenBao Transit. rand is ignored;
// randomness is provided by OpenBao. On a 403 (token revoked out-of-band,
// clock skew, etc.) it forces a re-authentication via the TokenManager and
// retries once before surfacing the error — the CA recovers within a single
// retried request rather than waiting for the background renewal loop.
//
// crypto.Signer.Sign carries no context, so the whole call — the Transit sign
// round trip plus any reactive re-authentication and single retry, which all
// share this deadline — is bounded by the configured login timeout (see
// TokenManager.loginTimeout). This matters because the CA holds its
// process-wide mutex across x509.CreateCertificate — and therefore across this
// network call — so an unbounded Sign against a stalled Transit backend would
// pin that mutex and stall all issuance; the deadline caps how long that can
// last. See docs/openbao-transit.md ("Performance and outage behaviour").
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.tm.loginTimeout)
	defer cancel()
	var sig []byte
	err := s.withReauth(ctx, func() error {
		var e error
		sig, e = s.sign(ctx, digest, opts)
		return e
	})
	return sig, err
}

// withReauth runs op; if it fails with a 403 (token revoked out-of-band,
// clock skew causing early expiry, etc.) it forces an immediate
// re-authentication via the TokenManager and retries op once, so the CA
// recovers within a single request rather than waiting for the background
// renewal loop to notice. Non-403 errors, and the outcome of the retry, are
// returned unchanged.
func (s *Signer) withReauth(ctx context.Context, op func() error) error {
	err := op()
	if err == nil || !isPermissionDenied(err) {
		return err
	}
	if reauthErr := s.tm.Reauth(ctx); reauthErr != nil {
		return fmt.Errorf("request failed (%w) and re-authentication failed: %w", err, reauthErr)
	}
	return op()
}

func (s *Signer) sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlgo, err := transitHashAlgorithm(opts.HashFunc())
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(digest),
		"prehashed":      true,
		"hash_algorithm": hashAlgo,
	}
	if _, isRSA := s.pub.(*rsa.PublicKey); isRSA {
		if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
			data["signature_algorithm"] = "pss"
		} else {
			data["signature_algorithm"] = "pkcs1v15"
		}
	}

	path := fmt.Sprintf("%s/sign/%s", s.mount, s.key)
	secret, err := s.tm.Client().Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("transit sign: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("transit sign: empty response")
	}
	sigStr, _ := secret.Data["signature"].(string)
	if sigStr == "" {
		return nil, fmt.Errorf("transit sign: response has no signature field")
	}
	return decodeTransitSignature(sigStr)
}

// decodeTransitSignature strips Transit's "vault:v<N>:" key-version prefix
// and base64-decodes the remainder into raw signature bytes — ASN.1 DER for
// ECDSA, or the raw PKCS#1v1.5/PSS bytes for RSA, matching what
// x509.CreateCertificate et al. expect a crypto.Signer to return.
func decodeTransitSignature(sig string) ([]byte, error) {
	const prefix = "vault:v"
	if !strings.HasPrefix(sig, prefix) {
		return nil, fmt.Errorf("transit sign: unrecognised signature format %q", sig)
	}
	rest := sig[len(prefix):]
	idx := strings.IndexByte(rest, ':')
	if idx < 0 {
		return nil, fmt.Errorf("transit sign: unrecognised signature format %q", sig)
	}
	b64 := rest[idx+1:]
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("transit sign: decoding signature: %w", err)
	}
	return der, nil
}

// transitHashAlgorithm maps a crypto.Hash to Transit's hash_algorithm name.
func transitHashAlgorithm(h crypto.Hash) (string, error) {
	switch h {
	case crypto.SHA256:
		return "sha2-256", nil
	case crypto.SHA384:
		return "sha2-384", nil
	case crypto.SHA512:
		return "sha2-512", nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm %v for OpenBao transit signing", h)
	}
}

// isPermissionDenied reports whether err is an OpenBao API error with HTTP
// status 403.
func isPermissionDenied(err error) bool {
	var respErr *api.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == 403
}

// isNotFound reports whether err is an OpenBao API error with HTTP status
// 404 (e.g. the transit mount itself doesn't exist).
func isNotFound(err error) bool {
	var respErr *api.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == 404
}

// fetchPublicKey reads the Transit key's metadata and returns the parsed
// public key of its latest version. Returns an error wrapping
// ca.ErrKeyProviderKeyNotFound if the key does not exist: OpenBao's Read
// returns (nil, nil) for a missing secret path, and a 404 ResponseError when
// the mount itself doesn't exist (e.g. the operator hasn't enabled the
// transit engine yet) — both are treated as "not found" here so CA.Init can
// tell that apart from a real connectivity/permission error.
func fetchPublicKey(ctx context.Context, tm *TokenManager, mount, key string) (crypto.PublicKey, error) {
	path := fmt.Sprintf("%s/keys/%s", mount, key)
	secret, err := tm.Client().Logical().ReadWithContext(ctx, path)
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("%w: %s/%s: %w", ca.ErrKeyProviderKeyNotFound, mount, key, err)
		}
		return nil, fmt.Errorf("reading transit key %q: %w", key, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: %s/%s", ca.ErrKeyProviderKeyNotFound, mount, key)
	}

	latest, err := latestKeyVersion(secret.Data)
	if err != nil {
		return nil, err
	}

	pemStr, ok := latest["public_key"].(string)
	if !ok || pemStr == "" {
		return nil, fmt.Errorf("transit key %q has no public_key (is it an asymmetric key type?)", key)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("transit key %q: public_key is not valid PEM", key)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("transit key %q: parsing public key: %w", key, err)
	}
	return pub, nil
}

// latestKeyVersion picks out the entry for the key's latest_version from a
// "GET <mount>/keys/<name>" response's Data map.
func latestKeyVersion(data map[string]interface{}) (map[string]interface{}, error) {
	keys, ok := data["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("transit key metadata has no \"keys\" map")
	}

	// latest_version arrives as json.Number: the SDK decodes response bodies
	// with (*json.Decoder).UseNumber() (see ParseSecret in the OpenBao SDK)
	// specifically to avoid float64 precision loss on large integers. Also
	// accept a plain string or float64 for robustness against other decode
	// paths (e.g. a caller that re-marshals/unmarshals a Secret generically).
	var latestStr string
	switch v := data["latest_version"].(type) {
	case json.Number:
		latestStr = v.String()
	case string:
		latestStr = v
	case float64:
		latestStr = fmt.Sprintf("%d", int64(v))
	default:
		return nil, fmt.Errorf("transit key metadata has no usable \"latest_version\"")
	}

	version, ok := keys[latestStr].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("transit key metadata missing entry for latest_version %s", latestStr)
	}
	return version, nil
}

// KeyProvider implements ca.KeyProvider (internal/ca/keyprovider.go) backed by
// an OpenBao Transit key. Load reads an existing key (the recommended,
// documented path: an operator creates or imports it directly in OpenBao out
// of band); Generate creates a new Transit key on demand, mirroring today's
// local-key bootstrap behaviour, for the case where an operator would rather
// let openvox-ca provision it on first boot.
type KeyProvider struct {
	tm    *TokenManager
	mount string
	key   string
}

// NewKeyProvider builds a KeyProvider that manages the Transit key named by
// tm's configuration. tm is not owned by the returned KeyProvider — the
// caller is responsible for closing it.
func NewKeyProvider(tm *TokenManager, mount, key string) *KeyProvider {
	return &KeyProvider{tm: tm, mount: mount, key: key}
}

// Load returns a Signer for the existing Transit key, or an error wrapping
// ca.ErrKeyProviderKeyNotFound if it has not been created yet.
func (p *KeyProvider) Load(ctx context.Context) (crypto.Signer, error) {
	return newSigner(ctx, p.tm, p.mount, p.key)
}

// Generate creates a new Transit key of the type described by cfg, then
// returns a Signer for it. Fails if a key with this name already exists.
func (p *KeyProvider) Generate(ctx context.Context, cfg ca.KeyConfig) (crypto.Signer, error) {
	transitType, err := transitKeyType(cfg)
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/keys/%s", p.mount, p.key)
	if _, err := p.tm.Client().Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"type": transitType,
	}); err != nil {
		return nil, fmt.Errorf("creating transit key %q (type %s): %w", p.key, transitType, err)
	}
	return newSigner(ctx, p.tm, p.mount, p.key)
}

// transitKeyType maps a ca.KeyConfig to OpenBao Transit's key "type" string.
// Zero Size selects the same defaults ca.generateKey applies locally (RSA
// 4096, ECDSA P-256) so OpenBao-provisioned and file-provisioned CAs
// bootstrap with matching defaults.
func transitKeyType(cfg ca.KeyConfig) (string, error) {
	algo := cfg.Algo
	if algo == "" {
		algo = ca.KeyAlgoRSA
	}
	switch algo {
	case ca.KeyAlgoRSA:
		switch cfg.Size {
		case 0, 4096:
			return "rsa-4096", nil
		case 2048:
			return "rsa-2048", nil
		case 3072:
			return "rsa-3072", nil
		default:
			return "", fmt.Errorf("unsupported RSA key size %d for OpenBao transit (must be 2048, 3072, or 4096)", cfg.Size)
		}
	case ca.KeyAlgoECDSA:
		switch cfg.Size {
		case 0, 256:
			return "ecdsa-p256", nil
		case 384:
			return "ecdsa-p384", nil
		case 521:
			return "ecdsa-p521", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA key size %d for OpenBao transit (must be 256, 384, or 521)", cfg.Size)
		}
	default:
		return "", fmt.Errorf("unsupported key algorithm %q for OpenBao transit", cfg.Algo)
	}
}
