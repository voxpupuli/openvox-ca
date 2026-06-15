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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// KeyAlgo identifies the asymmetric key algorithm to use when generating a key.
type KeyAlgo string

const (
	KeyAlgoRSA   KeyAlgo = "rsa"
	KeyAlgoECDSA KeyAlgo = "ecdsa"
)

// KeyConfig describes the algorithm and size used when generating a key.
//
// For RSA, Size is the bit length: 2048, 3072, or 4096.
// For ECDSA, Size selects the NIST curve: 256 (P-256), 384 (P-384), or 521 (P-521).
// A zero Size uses the algorithm-specific default (RSA: 4096; ECDSA: 256).
// A zero Algo defaults to RSA.
type KeyConfig struct {
	Algo KeyAlgo
	Size int
}

// DefaultCAKeyConfig is the built-in key config for new CA certificates.
var DefaultCAKeyConfig = KeyConfig{Algo: KeyAlgoRSA, Size: 4096}

// DefaultLeafKeyConfig is the built-in key config for leaf certificates
// issued via server-side key generation (Generate).
var DefaultLeafKeyConfig = KeyConfig{Algo: KeyAlgoRSA, Size: 2048}

// ValidateKeyConfig returns an error if cfg contains an unsupported algorithm or
// key size. A zero Algo is treated as RSA; a zero Size is accepted (the
// algorithm-specific default is applied by generateKey).
func ValidateKeyConfig(cfg KeyConfig) error {
	algo := cfg.Algo
	if algo == "" {
		algo = KeyAlgoRSA
	}
	switch algo {
	case KeyAlgoRSA:
		if cfg.Size == 0 {
			return nil // default will be applied
		}
		if cfg.Size < 2048 {
			return fmt.Errorf("RSA key size %d is below the minimum of 2048 bits", cfg.Size)
		}
		if cfg.Size != 2048 && cfg.Size != 3072 && cfg.Size != 4096 {
			return fmt.Errorf("unsupported RSA key size %d (must be 2048, 3072, or 4096)", cfg.Size)
		}
	case KeyAlgoECDSA:
		if cfg.Size == 0 {
			return nil // default P-256
		}
		if cfg.Size != 256 && cfg.Size != 384 && cfg.Size != 521 {
			return fmt.Errorf("unsupported ECDSA key size %d (must be 256, 384, or 521)", cfg.Size)
		}
	default:
		return fmt.Errorf("unsupported key algorithm %q (must be %q or %q)", cfg.Algo, KeyAlgoRSA, KeyAlgoECDSA)
	}
	return nil
}

// validatePublicKey enforces the CA's key-strength policy on a client-submitted
// public key, mirroring ValidateKeyConfig (which governs server-side key
// generation): RSA keys must be at least 2048 bits, and ECDSA keys must use an
// approved NIST curve (P-256, P-384, or P-521). Any other key type or weaker
// parameter is rejected so the CA never issues a certificate over a weak key.
func validatePublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < 2048 {
			return fmt.Errorf("RSA public key size %d is below the minimum of 2048 bits", bits)
		}
		return nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		default:
			name := "unknown"
			if k.Curve != nil {
				name = k.Curve.Params().Name
			}
			return fmt.Errorf("unsupported ECDSA curve %q (must be P-256, P-384, or P-521)", name)
		}
	default:
		return fmt.Errorf("unsupported public key type %T (must be RSA >= 2048 bits or ECDSA P-256/P-384/P-521)", pub)
	}
}

// generateKey creates a fresh private key according to cfg.
// RSA with Size 0 defaults to 4096 bits; ECDSA with Size 0 defaults to P-256.
func generateKey(cfg KeyConfig) (crypto.Signer, error) {
	if err := ValidateKeyConfig(cfg); err != nil {
		return nil, err
	}
	algo := cfg.Algo
	if algo == "" {
		algo = KeyAlgoRSA
	}
	switch algo {
	case KeyAlgoRSA:
		size := cfg.Size
		if size == 0 {
			size = 4096
		}
		return rsa.GenerateKey(rand.Reader, size)
	case KeyAlgoECDSA:
		var curve elliptic.Curve
		switch cfg.Size {
		case 0, 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	default:
		// Already caught by ValidateKeyConfig; unreachable.
		return nil, fmt.Errorf("unsupported key algorithm %q", cfg.Algo)
	}
}

// marshalPrivateKeyPEM returns the PEM encoding of a private key.
// RSA keys use PKCS1 format ("RSA PRIVATE KEY").
// ECDSA keys use SEC 1 format ("EC PRIVATE KEY").
// Any other key type falls back to PKCS8 ("PRIVATE KEY").
func marshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("marshaling EC private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	default:
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshaling private key as PKCS8: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
}

// subjectKeyIDFromPublicKey computes the 20-byte SubjectKeyIdentifier as the
// SHA-1 of the SubjectPublicKeyInfo DER encoding of pub (RFC 5280 §4.2.1.2).
// This method works for both RSA and ECDSA public keys.
func subjectKeyIDFromPublicKey(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling public key for SubjectKeyIdentifier: %w", err)
	}
	h := sha1.Sum(der)
	return h[:], nil
}

// parsePrivateKeyDER parses a PEM block's DER bytes into a crypto.Signer.
// Supports RSA PKCS1, EC SEC1, PKCS8, and falls back to trying PKCS1 then
// PKCS8 for unrecognized PEM types.
func parsePrivateKeyDER(blockType string, der []byte) (crypto.Signer, error) {
	switch blockType {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA PKCS1 private key: %w", err)
		}
		return k, nil
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS8 private key does not implement crypto.Signer")
		}
		return signer, nil
	default:
		// Try PKCS1 and PKCS8 regardless of header for maximum compatibility
		// with keys generated by external tools.
		if k1, err1 := x509.ParsePKCS1PrivateKey(der); err1 == nil {
			return k1, nil
		} else if k8, err8 := x509.ParsePKCS8PrivateKey(der); err8 == nil {
			signer, ok := k8.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("PKCS8 private key does not implement crypto.Signer")
			}
			return signer, nil
		} else {
			return nil, fmt.Errorf("unrecognized PEM type %q (PKCS1: %v; PKCS8: %v)", blockType, err1, err8)
		}
	}
}
