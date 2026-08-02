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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"regexp"
	"time"
)

// maxDNSAltNames is the maximum number of DNS alt names allowed per certificate.
const maxDNSAltNames = 100

// maxDNSNameLen is the maximum length of a single DNS alt name (RFC 1035 limit).
const maxDNSNameLen = 253

// dnsNameRegex matches valid DNS hostnames (RFC 952 / RFC 1123).
var dnsNameRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// validateDNSAltNames checks that DNS alt names are well-formed hostnames
// within reasonable bounds.
func validateDNSAltNames(names []string) error {
	if len(names) > maxDNSAltNames {
		return fmt.Errorf("too many DNS alt names (%d > %d)", len(names), maxDNSAltNames)
	}
	for _, name := range names {
		if len(name) > maxDNSNameLen {
			return fmt.Errorf("DNS alt name %q exceeds maximum length (%d > %d)", name, len(name), maxDNSNameLen)
		}
		if !dnsNameRegex.MatchString(name) {
			return fmt.Errorf("invalid DNS alt name %q: must be a valid hostname", name)
		}
	}
	return nil
}

// GenerateResult holds the PEM-encoded private key and signed certificate
// produced by a server-side Generate call.
type GenerateResult struct {
	PrivateKeyPEM  []byte
	CertificatePEM []byte
}

// GenerateOptions controls a server-side certificate generation.
type GenerateOptions struct {
	// DNSAltNames are added as subjectAltName DNS entries. When empty and
	// PromoteCNToSAN is set, the subject is promoted to a SAN instead.
	DNSAltNames []string

	// AuthGrants are Puppet authorisation-arc extensions to stamp onto the
	// certificate. These bypass the filter the CSR path applies to submitted
	// requests; see AuthGrant for why that is safe here and what keeps it so.
	AuthGrants []AuthGrant

	// TTL overrides the certificate lifetime. Zero means the configured
	// LeafValidityDays, or the built-in default when that is unset.
	TTL time.Duration

	// ReplaceExisting revokes the certificate currently stored for the subject
	// and issues a replacement, rather than failing with ErrCertExists. It is
	// not an error when there is nothing to replace: the job is to end with a
	// certificate, not to remove one.
	ReplaceExisting bool

	// RetainPrivateKeyInStorage saves the generated key to
	// private/{subject}_key.pem. The zero value does not: a key the CA has no
	// use for is a liability, and this path is always the local filesystem
	// regardless of the configured backend, so on an ephemeral cadir the copy
	// is lost at the next restart anyway. Generate opts in for wire
	// compatibility with the API, which has always left a copy.
	RetainPrivateKeyInStorage bool

	// EmitKey, when set, receives the freshly generated private key in PEM form
	// after it is generated and BEFORE anything destructive or persistent
	// happens -- before the subject lock is taken, before any revocation, and
	// before issuance. A non-nil error from it aborts the call having changed
	// nothing.
	//
	// This lets a caller put the key somewhere durable first. It matters for
	// replacement: once the certificate being replaced is revoked, a failure to
	// write the key would leave the subject with no usable credential and its
	// previous one on the CRL, and CRL entries cannot be withdrawn. Passing the
	// bytes out rather than accepting a path keeps this package out of the
	// business of knowing where an operator wants their key.
	EmitKey func(keyPEM []byte) error
}

// Generate creates a fresh key pair for subject, signs a certificate for it
// without requiring a client-submitted CSR, saves the private key to
// private/{subject}_key.pem, and returns both PEMs.
//
// This is the network-reachable form, called by the /generate handler. Its
// signature deliberately has no extension parameter: an HTTP caller must not be
// able to reach the AuthGrants seam, and cannot without a source change here.
//
// The key algorithm and size are controlled by CA.LeafKeyConfig; defaults
// to RSA 2048 when not set.
//
// Returns ErrCertExists (wrapped) if a valid (non-revoked) certificate already
// exists for subject.
func (c *CA) Generate(ctx context.Context, subject string, dnsAltNames []string) (*GenerateResult, error) {
	return c.GenerateWithOptions(ctx, subject, GenerateOptions{
		DNSAltNames:               dnsAltNames,
		RetainPrivateKeyInStorage: true,
	})
}

// GenerateWithOptions is Generate with the knobs the offline CLI needs.
//
// Unlike the old implementation it does not build an internal CSR and feed it
// back through the signing path. That round trip existed only so sign() could
// be reused, and it had two costs: the auth-OID filter meant for submitted
// requests also applied to certificates this CA generated for itself, and the
// CSR was briefly visible in storage where a concurrent "sign all" could pick
// it up and issue a second certificate for the subject. Calling issueLeafLocked
// directly removes both, and keeps the filter exactly where it belongs -- on
// the path that parses network input.
func (c *CA) GenerateWithOptions(ctx context.Context, subject string, opts GenerateOptions) (*GenerateResult, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}

	// Validate DNS alt names: must be valid hostnames, bounded count and length.
	if err := validateDNSAltNames(opts.DNSAltNames); err != nil {
		return nil, err
	}

	// Fail fast on an uninitialised CA. issueLeafLocked carries the
	// authoritative guard, but it is now reached after the CRL cache refresh,
	// which on an uninitialised CA fails first with a "reading CRL" error --
	// losing the sentinel callers use to tell "not ready yet" from "broken".
	c.mu.RLock()
	initialised := c.CACert != nil && c.CAKey != nil
	c.mu.RUnlock()
	if !initialised {
		return nil, ErrNotInitialized
	}

	// Encode the grants before generating a key, so a malformed request costs
	// nothing.
	extraExtensions, err := authGrantExtensions(opts.AuthGrants)
	if err != nil {
		return nil, err
	}

	// Resolve leaf key config; fall back to default if not set.
	leafCfg := c.LeafKeyConfig
	if leafCfg.Algo == "" {
		leafCfg = DefaultLeafKeyConfig
	}

	// Key generation is CPU-bound and touches no shared state, so it runs
	// outside the lock. generateKey validates the config, so an off-policy
	// algorithm or size fails here, before anything is written.
	key, err := generateKey(leafCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key for %s: %w", subject, err)
	}

	keyPEM, err := marshalPrivateKeyPEM(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key for %s: %w", subject, err)
	}

	// Hand the key to the caller before anything irreversible happens.
	if opts.EmitKey != nil {
		if err := opts.EmitKey(keyPEM); err != nil {
			return nil, err
		}
	}

	// RFC 2818 3.1: TLS clients match the name against SANs, not the CN. The
	// CSR path promotes the CN when a request carries no SANs; do the same here
	// so a generated certificate behaves identically to a signed one.
	dnsNames := opts.DNSAltNames
	if c.PromoteCNToSAN && len(dnsNames) == 0 {
		dnsNames = []string{subject}
	}

	// Serialise on the cluster-wide per-subject lock, as every other issuance
	// path does (Sign, SignWithTTL, SaveRequest, Renew, Clean,
	// ImportCertificate). Generate used to hold just c.mu, which coordinates
	// nothing between processes -- so two replicas, or a replica and an
	// operator running an offline subcommand, could each pass
	// evictRevokedLocked and both issue for the same subject.
	//
	// Lock ordering: subject-lock (distributed) -> c.mu, matching Sign.
	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()

	var result *GenerateResult
	lockErr := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		// Read phase. Its own closure because c.mu must not be held across the
		// nested CRL lock below: c.mu is a non-reentrant RWMutex, and every
		// lockNameCRL acquisition in this package takes the distributed lock
		// first and c.mu second. Holding c.mu across WithLock would invert that
		// ordering against RefreshCRLIfDue and Revoke.
		serial, replacing, err := func() (string, bool, error) {
			c.mu.Lock()
			defer c.mu.Unlock()

			// Re-read the CRL under the lock. evictRevokedLocked decides whether an
			// existing certificate may be replaced by consulting c.cachedCRL, which
			// is otherwise only ever populated at Init and by this process's own
			// revocations. Without this, a subject revoked by another replica after
			// our Init is invisible here and we answer ErrCertExists where we should
			// evict and re-issue.
			if err := c.loadCRLCache(ctx); err != nil {
				return "", false, fmt.Errorf("refreshing CRL cache for %s: %w", subject, err)
			}
			if !opts.ReplaceExisting || !c.Storage.HasCert(ctx, subject) {
				return "", false, nil
			}
			s, err := c.storedCertSerialLocked(ctx, subject)
			if err != nil {
				return "", false, err
			}
			return s, true, nil
		}()
		if err != nil {
			return err
		}

		// Revoke phase. CRL lock outside c.mu, matching AutoRenew.
		//
		// The serial comes from the stored certificate, not from
		// LatestSerialForSubject: revokeLocked resolves the latter, and
		// revoke.go warns against exactly that for replacement paths, because
		// the inventory's newest row for a subject and the certificate actually
		// in storage can differ. Revoking the wrong serial is irreversible.
		if replacing {
			if err := c.Storage.WithLock(ctx, lockNameCRL, func() error {
				c.mu.Lock()
				defer c.mu.Unlock()
				return c.revokeSerialLocked(ctx, serial)
			}); err != nil {
				// Fail closed. Clean logs and continues here because it is
				// removing the certificate either way; a replacement path that
				// did the same would leave two live certificates for one
				// subject, which is what the subject lock exists to prevent.
				return fmt.Errorf("could not revoke the existing certificate for %s, "+
					"so no replacement was issued: %w", subject, err)
			}
		}

		// Issue phase.
		c.mu.Lock()
		defer c.mu.Unlock()

		if replacing {
			// signCRLLocked refreshes the cache when it appends, but
			// revokeSerialLocked returns early without calling it when the
			// serial was already on the CRL. Re-read so evictRevokedLocked sees
			// the revocation either way.
			if err := c.loadCRLCache(ctx); err != nil {
				return c.replacementFailed(subject, fmt.Errorf("refreshing CRL cache: %w", err))
			}
		}

		if err := c.evictRevokedLocked(ctx, subject); err != nil {
			if replacing {
				return c.replacementFailed(subject, err)
			}
			return err
		}

		certPEM, err := c.issueLeafLocked(ctx, subject,
			pkix.Name{CommonName: subject}, key.Public(),
			subjectAltNames{DNSNames: dnsNames}, extraExtensions, opts.TTL)
		if err != nil {
			if replacing {
				return c.replacementFailed(subject, err)
			}
			return err
		}

		if opts.RetainPrivateKeyInStorage {
			if err := c.Storage.SavePrivateKey(ctx, subject, keyPEM); err != nil {
				// Clean up the just-issued certificate to avoid inconsistent state
				// where a cert exists on disk but the corresponding private key doesn't.
				if delErr := c.Storage.DeleteCert(ctx, subject); delErr != nil {
					slog.Warn("Failed to clean up cert after private key save failure",
						"subject", subject, "error", delErr)
				}
				saveErr := fmt.Errorf("failed to save private key for %s: %w", subject, err)
				if replacing {
					// The rollback above leaves the subject with no certificate
					// at all, while its predecessor is already on the CRL. That
					// is the state the caller most needs told about, and the
					// raw save error does not mention it.
					return c.replacementFailed(subject, saveErr)
				}
				return saveErr
			}

			// SECURITY: Log that a private key has been persisted to server storage.
			// Generated keys remain on disk indefinitely; operators should implement
			// external lifecycle controls (rotation, cleanup) for these keys.
			// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
			slog.Debug("Generated private key persisted to server filesystem",
				"subject", subject, "path", c.Storage.PrivateKeyPath(subject))
		}

		// A pending CSR for this subject would otherwise survive and stay
		// signable, yielding a second certificate for a name that already has
		// one. The old implementation destroyed it as a side effect of
		// overwriting the CSR slot with its own; do it deliberately instead.
		if c.Storage.HasCSR(ctx, subject) {
			if err := c.Storage.DeleteCSR(ctx, subject); err != nil {
				slog.Warn("Could not remove pending CSR superseded by generation",
					"subject", subject, "error", err)
			} else {
				slog.Debug("Removed pending CSR superseded by generation", "subject", subject)
			}
		}

		for _, g := range opts.AuthGrants {
			// SECURITY: an authorisation grant is the most privileged thing this
			// CA issues. Logged here rather than at the call site so it is
			// recorded whoever reaches this seam.
			// NIST 800-53: AC-6 (Least Privilege), AU-2 (Event Logging)
			slog.Warn("Issued certificate carrying a Puppet authorisation extension",
				"subject", subject, "grant", g.String())
		}

		slog.Debug("Certificate generated", "subject", subject, "algo", string(leafCfg.Algo))
		result = &GenerateResult{
			PrivateKeyPEM:  keyPEM,
			CertificatePEM: certPEM,
		}
		return nil
	})
	if lockErr != nil {
		return nil, lockErr
	}
	return result, nil
}

// storedCertSerialLocked returns the serial of the certificate currently stored
// for subject, for a replacement to revoke. c.mu must be held.
//
// The stored certificate is the authority here, not the inventory: that is what
// evictRevokedLocked consults, and revoking anything else would put a serial on
// the CRL that does not correspond to the credential being retired.
func (c *CA) storedCertSerialLocked(ctx context.Context, subject string) (string, error) {
	certPEM, err := c.Storage.GetCert(ctx, subject)
	if err != nil {
		return "", fmt.Errorf("reading the stored certificate for %s: %w", subject, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		// Do not fall through to issuance. evictRevokedLocked also fails an
		// unparseable certificate, but it does so with ErrCertExists, whose
		// remedy is "pass --force" -- which is what the operator just did. Say
		// something they can act on instead.
		return "", fmt.Errorf("the stored certificate for %s cannot be decoded; remove it with "+
			"'openvox-ca-ctl clean --certname %s' and retry", subject, subject)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("the stored certificate for %s cannot be parsed (%v); remove it with "+
			"'openvox-ca-ctl clean --certname %s' and retry", subject, err, subject)
	}
	return serialHexStr(cert.SerialNumber), nil
}

// replacementFailed wraps a failure that happens after the old certificate has
// already been revoked.
//
// This state is not recoverable by retrying blindly: CRL entries are only ever
// appended, so the predecessor stays revoked whatever happens next. Surfacing
// the bare error would be worse than unhelpful for ErrCertExists, whose message
// tells the operator to pass --force -- which is how they got here.
func (c *CA) replacementFailed(subject string, err error) error {
	return fmt.Errorf("the existing certificate for %s was revoked, but no replacement was issued: %w."+
		"\nThat revocation cannot be undone. Re-run to issue a replacement", subject, err)
}
