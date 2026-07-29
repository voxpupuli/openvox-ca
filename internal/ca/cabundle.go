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
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// ParseCABundle decodes every CERTIFICATE block in bundlePEM, in file order.
//
// Blocks that are neither certificates nor private keys are skipped rather than
// rejected: an operator pasting a bundle exported from another tool may
// legitimately carry comments or textual certificate dumps, and refusing the
// whole file over an ignorable block would be unhelpful.
//
// A private-key block is rejected outright. The tolerated shape here is exactly
// the one `bao write pki/intermediate/generate/exported ... format=pem_bundle`
// produces, and the CA certificate is stored world-readable and served
// unauthenticated at GET /certificate/ca — so a key that slipped through would
// be published. Callers also re-encode from the parsed certificates before
// storing (see EncodeCABundle), but that is defence in depth: an operator who
// hands this command their private key deserves to be told, not silently
// filtered.
func ParseCABundle(bundlePEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, fmt.Errorf("bundle contains a %q block: supply only certificates, "+
				"as this file is stored world-readable and served to every agent", block.Type)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d in bundle: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("bundle contains no CERTIFICATE blocks")
	}
	return certs, nil
}

// EncodeCABundle renders certs back to a PEM blob in order.
//
// Storing this rather than the operator's file makes what is served identical
// to what was validated. The DER is untouched — each block is the certificate's
// own Raw — so the only thing lost is PEM commentary.
func EncodeCABundle(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return buf.Bytes()
}

// AssertSignerMatchesCert proves that signer holds the private key cert binds.
//
// This is the single check that makes importing a CA certificate without its
// private key safe: without it the CA could be left holding a certificate it
// cannot sign under, so every issuance would fail and every certificate already
// issued under the previous key would stop verifying. It is deliberately
// algorithm-agnostic — marshalled SubjectPublicKeyInfo compared byte for byte —
// rather than type-switching per algorithm.
//
// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
func AssertSignerMatchesCert(cert *x509.Certificate, signer crypto.Signer) error {
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal cert public key: %w", err)
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal signing key's public component: %w", err)
	}
	if !bytes.Equal(certPubDER, keyPubDER) {
		return fmt.Errorf("the CA key does not match the certificate's public key: refusing to import a "+
			"certificate this CA could not sign under (certificate subject %q)", cert.Subject.CommonName)
	}
	return nil
}

// ValidateCABundleOrder checks that certs is a complete certificate chain
// ordered nearest-first: certs[0] is this CA's own signing certificate, each
// entry is issued by the next, and the last is a self-signed root.
//
// The ordering is not a stylistic preference. loadCA parses only the first PEM
// block of the stored bundle and pins the CA key to it, so a bundle in any
// other order fails at startup. GET /certificate/ca serves the blob verbatim,
// and that order is what a Puppet agent expects in its localcacert.
//
// A complete chain to a self-signed root is mandatory. Allowing a bundle to
// stop at an intermediate would leave the CRL chain unverifiable (nothing in
// the bundle could check the root's CRL, which is the one an agent most needs
// for full-chain revocation checking) and would make an export scope promising
// a trust anchor return an intermediate instead.
func ValidateCABundleOrder(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("bundle contains no certificates")
	}

	if !certs[0].IsCA {
		return fmt.Errorf("first certificate in bundle (%q) is not a CA certificate (IsCA=false); "+
			"the bundle must start with this CA's own signing certificate",
			certs[0].Subject.CommonName)
	}

	// A parent that signs with the wrong profile produces a certificate that
	// installs cleanly and then cannot do the job: no keyCertSign means every
	// certificate this CA issues is rejected by a conforming verifier, and no
	// cRLSign means the same for every CRL it publishes. Both are worth failing
	// the import over, because the alternative is discovering it fleet-wide.
	//
	// A KeyUsage of zero means the extension is absent, which RFC 5280 leaves
	// unconstrained; only an extension that is present and omits the bit is a
	// refusal. pathlen:0 is deliberately not checked — it permits issuing
	// end-entity certificates and forbids issuing further CAs, which is exactly
	// what openvox-ca does, so it is the correct profile rather than a fault.
	// Validity is checked for the same reason the profile is, and the argument
	// is if anything stronger: a certificate outside its window installs
	// cleanly and is then rejected by every agent verifying the chain. Only
	// certs[0] is ever checked again afterwards (at issuance, by
	// signing.go), so an expired issuer or root further up the bundle would
	// never be noticed here at all — it would surface as chain-verification
	// failures across the fleet, after the bundle had been written and served.
	// Realistic causes are mundane: a stale root.pem copy, an offline root past
	// its window, a parent that silently truncated the requested ttl.
	now := time.Now()
	for i, cert := range certs {
		which := fmt.Sprintf("certificate %d in bundle (%q)", i+1, cert.Subject.CommonName)
		if i == 0 {
			which = fmt.Sprintf("first certificate in bundle (%q)", cert.Subject.CommonName)
		}
		if now.Before(cert.NotBefore) {
			return fmt.Errorf("%s is not valid until %s; check the clock on this host and the "+
				"validity the parent CA issued", which, cert.NotBefore.UTC().Format(time.RFC3339))
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("%s expired at %s; every agent would reject the chain, so it is "+
				"refused here rather than fleet-wide", which, cert.NotAfter.UTC().Format(time.RFC3339))
		}
	}

	if ku := certs[0].KeyUsage; ku != 0 {
		if ku&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("first certificate in bundle (%q) has a KeyUsage extension without keyCertSign, "+
				"so it cannot issue certificates; ask the parent CA to re-issue it with a CA profile",
				certs[0].Subject.CommonName)
		}
		if ku&x509.KeyUsageCRLSign == 0 {
			return fmt.Errorf("first certificate in bundle (%q) has a KeyUsage extension without cRLSign, "+
				"so it cannot publish a revocation list; ask the parent CA to re-issue it with a CA profile",
				certs[0].Subject.CommonName)
		}
	}

	for i := 0; i < len(certs)-1; i++ {
		child, parent := certs[i], certs[i+1]
		if !parent.IsCA {
			return fmt.Errorf("certificate %d in bundle (%q) is not a CA certificate but is used as an issuer",
				i+2, parent.Subject.CommonName)
		}
		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("certificate %d in bundle (%q) is not signed by certificate %d (%q): %w; "+
				"the bundle must be ordered nearest-first, ending with the root",
				i+1, child.Subject.CommonName, i+2, parent.Subject.CommonName, err)
		}
	}

	root := certs[len(certs)-1]
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("the last certificate in the bundle (%q) is not self-signed, so the chain does not "+
			"reach a root; supply the complete chain including the root certificate", root.Subject.CommonName)
	}

	return nil
}

// ResignStoredCRL re-signs the CRL currently in storage under cert and signer,
// preserving every revocation entry and bumping the CRL number.
//
// Replacing a CA certificate invalidates the stored CRL: it was signed by the
// key being replaced and names the subject being replaced, so after the import
// nothing can verify it and readStoredCRL's issuer check would reject it. The
// revocations it records are still meaningful, though — they name serials this
// CA issued — so they are carried across rather than discarded.
//
// Returns nil when storage holds no CRL yet, leaving the caller to generate a
// fresh empty one.
func ResignStoredCRL(ctx context.Context, store *storage.StorageService, cert *x509.Certificate, signer crypto.Signer, validity time.Duration) ([]byte, error) {
	existing, err := store.GetCRL(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the existing CRL: %w", err)
	}
	block, _ := pem.Decode(existing)
	if block == nil {
		return nil, fmt.Errorf("the stored CRL is not PEM-encoded")
	}
	old, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the existing CRL: %w", err)
	}

	next := big.NewInt(1)
	if old.Number != nil {
		next.Add(old.Number, big.NewInt(1))
	}
	now := time.Now().UTC()
	template := &x509.RevocationList{
		Number:                    next,
		RevokedCertificateEntries: old.RevokedCertificateEntries,
		ThisUpdate:                now,
		NextUpdate:                now.Add(validity),
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, cert, signer)
	if err != nil {
		return nil, fmt.Errorf("re-signing the CRL under the imported certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}
