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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"time"
)

// ErrManagedSubject is returned by RenewStored for a subject this CA keeps
// alive itself: a managed_certs entry, or its own self-provisioned serving
// certificate. The reconcile loop holds that certificate's key and renews it on
// its own schedule, so a renewal by hand would leave the stored certificate and
// the key the loop delivers out of step.
var ErrManagedSubject = errors.New("certificate is managed by this CA")

// ErrRekeyAuthorised is returned by RenewStored for a re-key of a certificate
// carrying an extension in the Puppet authorisation arc, pp_cli_auth among
// them.
var ErrRekeyAuthorised = errors.New("re-keying a certificate that carries authorisation extensions is refused")

// ErrRenewalExpired is returned by RenewStored for a stored certificate whose
// validity has ended.
var ErrRenewalExpired = errors.New("certificate has expired")

// ErrRenewalCSR is wrapped by RenewStored when the CSR it is given cannot be
// used: unparseable, a failed proof-of-possession signature, or a Common Name
// other than the subject being renewed.
var ErrRenewalCSR = errors.New("invalid renewal CSR")

// RenewStored renews the certificate stored for subject on an operator's
// authority, rather than on the authority of the certificate itself as Renew
// and AutoRenew do. It is the admin-tier counterpart of those two, for a
// certificate whose holder runs no agent to renew it (#247).
//
// The two shapes mirror the agent route's. An empty csrPEM reissues over the
// stored certificate's own public key, as AutoRenew does; that needs no private
// key, only the public half the certificate already carries. A CSR re-keys onto
// its public key, as Renew does, and must be for subject. Either way the
// certificate being renewed supplies the subject and every extension, and the
// request adds nothing: see reissueLeafLocked.
//
// What it refuses, and why:
//
//   - a subject with no stored certificate: ErrNotFound;
//   - a managed subject: ErrManagedSubject;
//   - a stored certificate this CA did not sign: ErrForeignCertificate;
//   - a revoked one, or one already on the pending-supersession list:
//     ErrCertRevoked or ErrCertSuperseded, as on the agent paths;
//   - an expired one: ErrRenewalExpired. The agent paths never see one,
//     because newAuthMiddleware refuses an expired certificate before it can
//     present itself for renewal, and assertOwnCertificate and refuseIfRevoked
//     leave the validity window to it. A stored certificate passes no
//     middleware, so this path has to ask itself, or an expired credential --
//     pp_cli_auth included -- could be brought back for whoever still holds its
//     key. A lapsed certificate is cleaned and generated afresh instead;
//   - a re-key of a certificate carrying authorisation-arc extensions:
//     ErrRekeyAuthorised. Renewal carries pp_cli_auth forward, so a re-key here
//     would hand a CA administrator credential to whoever holds the new key --
//     which the API cannot otherwise do (see AuthGrant). The same-key reissue
//     stays open, because it extends a credential only for the key that
//     already held it;
//   - a key below policy, the stored one included: ErrKeyPolicy, from
//     issueLeafLocked.
//
// The replaced certificate is retired exactly as the agent path with the same
// body would retire it: a re-key always, a same-key reissue when
// RevokeOnAutoRenew is set. Retiring goes through supersedeReplaced, so the
// server's SupersedeAfter decides whether that is now or after the overlap
// window.
//
// The caller must NOT hold c.mu. Lock order is subject -> crl -> c.mu, as on
// Renew.
func (c *CA) RenewStored(ctx context.Context, subject string, csrPEM []byte) ([]byte, error) {
	if err := ValidateSubject(subject); err != nil {
		return nil, err
	}
	// The managed set is configuration, fixed for the life of the process, so
	// it needs no lock to read.
	if slices.ContainsFunc(c.ManagedCerts, func(m ManagedCert) bool { return m.Spec.Subject == subject }) {
		return nil, fmt.Errorf("%w: %s is renewed by this CA's own reconcile loop", ErrManagedSubject, subject)
	}

	var csr *x509.CertificateRequest
	if len(csrPEM) > 0 {
		block, _ := pem.Decode(csrPEM)
		if block == nil {
			return nil, fmt.Errorf("%w: not a PEM-encoded CSR", ErrRenewalCSR)
		}
		var err error
		csr, err = x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRenewalCSR, err)
		}
		// SECURITY: proof of possession for the key the certificate will name.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication)
		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("%w: signature does not verify: %v", ErrRenewalCSR, err)
		}
		if csr.Subject.CommonName != subject {
			return nil, fmt.Errorf("%w: its Common Name is %q, not %q", ErrRenewalCSR, csr.Subject.CommonName, subject)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, LockTimeout)
	defer cancel()
	var out []byte
	err := c.Storage.WithLock(ctx, subjectLockName(subject), func() error {
		// Read under the lock: the certificate being renewed must be the one
		// stored when the replacement is written, or a concurrent renewal's
		// result would be superseded by a copy of its own predecessor.
		stored, err := c.loadStoredCert(ctx, subject)
		if err != nil {
			return err
		}
		// SECURITY: renewal copies the stored certificate's names and
		// authority onto a fresh one, so it has to be ours, and live.
		// NIST 800-53: AC-3 (Access Enforcement), IA-5(2) (PKI-Based Authentication)
		if err := c.assertOwnCertificate(stored); err != nil {
			return err
		}
		if err := c.refuseIfRevoked(ctx, stored, subject); err != nil {
			return err
		}
		// SECURITY: see ErrRenewalExpired.
		// NIST 800-53: IA-5(2) (PKI-Based Authentication), AC-3 (Access Enforcement)
		if now := c.issueNow(); now.After(stored.NotAfter) {
			return fmt.Errorf("%w: the certificate stored for %s expired at %s", ErrRenewalExpired,
				subject, stored.NotAfter.UTC().Format(time.RFC3339))
		}
		pubKey := stored.PublicKey
		if csr != nil {
			// SECURITY: see ErrRekeyAuthorised.
			// NIST 800-53: AC-6 (Least Privilege)
			if slices.ContainsFunc(stored.Extensions, func(e pkix.Extension) bool { return IsAuthOID(e.Id) }) {
				return fmt.Errorf("%w: %s carries one; reissue it over its own key, or mint a new credential "+
					"with the offline openvox-ca generate", ErrRekeyAuthorised, subject)
			}
			pubKey = csr.PublicKey
		}

		certPEM, err := func() ([]byte, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			certPEM, err := c.reissueLeafLocked(ctx, subject, stored, pubKey)
			if err != nil {
				return nil, err
			}
			// A re-key removes any request queued for the subject, as Renew
			// does; a same-key reissue leaves it, as AutoRenew does.
			if csr != nil {
				if err := c.Storage.DeleteCSR(ctx, subject); err != nil && !errors.Is(err, fs.ErrNotExist) {
					slog.Warn("Could not delete pending CSR after renewal", "subject", subject, "error", err)
				}
			}
			return certPEM, nil
		}()
		if err != nil {
			return err
		}
		out = certPEM

		if csr == nil && !c.RevokeOnAutoRenew {
			return nil
		}
		// Best effort, as on both agent paths: the failure is counted by
		// supersedeReplaced's callees, and the renewal stands.
		oldSerial := serialHexStr(stored.SerialNumber)
		if err := c.supersedeReplaced(ctx, subject, oldSerial); err != nil {
			slog.Warn("RenewStored: failed to retire replaced certificate", "subject", subject, "serial", oldSerial, "error", err)
		}
		return nil
	})
	return out, err
}

// loadStoredCert reads and parses the certificate stored for subject,
// answering ErrNotFound when there is none.
func (c *CA) loadStoredCert(ctx context.Context, subject string) (*x509.Certificate, error) {
	data, err := c.Storage.GetCert(ctx, subject)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: no certificate is stored for %s", ErrNotFound, subject)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the certificate for %s: %w", subject, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("the certificate stored for %s is not PEM", subject)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the certificate stored for %s: %w", subject, err)
	}
	return cert, nil
}
