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
	"crypto/x509/pkix"
	"sync"
	"sync/atomic"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// CASubjectConfig holds optional X.509 subject fields for a bootstrapped CA
// certificate. Zero fields use defaults; CommonName in the signed cert is
// always derived from Hostname as "Puppet CA: <hostname>" unless overridden
// by the Org/OrgUnit/Country/Locality/Province fields below.
type CASubjectConfig struct {
	Org      string
	OrgUnit  string
	Country  string
	Locality string
	Province string
}

// CASubjectName builds the X.509 subject DN for this CA's own certificate.
//
// It is exported and used from two places that MUST agree: bootstrapCA, which
// self-signs a certificate carrying this DN, and the certificate signing
// request emitted for an external parent to sign. A CSR whose subject differs
// from the DN the CA would otherwise use produces an intermediate certificate
// issued for the wrong name — discovered only after a third party has signed
// it, which is expensive to undo. Keeping one builder makes the two
// structurally incapable of disagreeing.
func CASubjectName(hostname string, cfg CASubjectConfig) pkix.Name {
	subject := pkix.Name{
		CommonName: "Puppet CA: " + hostname,
	}
	if cfg.Org != "" {
		subject.Organization = []string{cfg.Org}
	}
	if cfg.OrgUnit != "" {
		subject.OrganizationalUnit = []string{cfg.OrgUnit}
	}
	if cfg.Country != "" {
		subject.Country = []string{cfg.Country}
	}
	if cfg.Locality != "" {
		subject.Locality = []string{cfg.Locality}
	}
	if cfg.Province != "" {
		subject.Province = []string{cfg.Province}
	}
	return subject
}

type CA struct {
	Storage        *storage.StorageService
	CACert         *x509.Certificate
	CAKey          crypto.Signer
	AutosignConfig AutosignConfig
	Hostname       string

	// CAKeyConfig controls the algorithm and key size used when bootstrapping a
	// new CA certificate. Zero value uses DefaultCAKeyConfig (RSA 4096).
	// Ignored when a CA already exists on disk.
	CAKeyConfig KeyConfig

	// LeafKeyConfig controls the algorithm and key size for server-side
	// generated leaf certificates (Generate). Zero value uses
	// DefaultLeafKeyConfig (RSA 2048).
	LeafKeyConfig KeyConfig

	// CASubject holds optional subject DN fields for a bootstrapped CA
	// certificate. Ignored when a CA already exists on disk.
	CASubject CASubjectConfig

	// CAPathLength sets the BasicConstraints pathLenConstraint on a bootstrapped
	// CA certificate. -1 (the default) means no constraint (unconstrained). 0
	// means no intermediate CAs are allowed. N > 0 means up to N levels of
	// intermediate CAs. Ignored when a CA already exists on disk.
	CAPathLength int

	// CAValidityDays overrides the default CA certificate lifetime when
	// bootstrapping a new CA. Zero uses the built-in default (~5 years).
	// Ignored when a CA already exists on disk.
	CAValidityDays int

	// LeafValidityDays overrides the default leaf certificate lifetime used
	// when signing CSRs and generating server-side key pairs. Zero uses the
	// built-in default (~5 years). A per-request cert_ttl always takes
	// precedence over this value.
	LeafValidityDays int

	// OCSPURLs, when non-nil, causes newly issued certs to embed an AIA
	// extension pointing at the OCSP responder. Set before calling Init().
	OCSPURLs []string

	// CRLURLs, when non-nil, causes newly issued certs to embed a CRL
	// Distribution Points extension (RFC 5280 §4.2.1.13) so that verifiers
	// can automatically retrieve the CRL. Set before calling Init().
	CRLURLs []string

	// CRLValidityDays overrides the default CRL validity window. Zero uses the
	// built-in default (30 days).
	CRLValidityDays int

	// KeyPassphrase configures how the CA private key is encrypted at rest.
	// When set, the key is stored as an encrypted PEM (AES-256-GCM + Argon2id).
	// When nil/zero, keys are stored as unencrypted PEM (backward compatible).
	KeyPassphrase KeyPassphraseConfig

	// EncryptCAKey controls whether the CA key is encrypted at rest.
	// When true, the key is encrypted using the resolved passphrase.
	EncryptCAKey bool

	// PromoteCNToSAN, when true (the default), adds the CSR's Common Name as a
	// DNS Subject Alternative Name when the CSR carries no SANs. RFC 2818 §3.1
	// deprecated CN-based hostname verification in favour of the SAN extension;
	// modern TLS clients (Go stdlib, Chrome, etc.) ignore the CN entirely. Set
	// to false only when issuing certificates to legacy clients that cannot
	// handle the SAN extension.
	PromoteCNToSAN bool

	// RevokeOnAutoRenew, when true (the default), revokes the certificate
	// being replaced by AutoRenew (the empty-body /certificate_renewal path)
	// once its successor is safely signed and stored, so only the newest
	// serial for a subject is ever valid. OpenVox Server's own Clojure CA
	// does not do this — both the old and new certs (same key) stay valid
	// until the old one naturally expires. Set to false to match that
	// behaviour exactly. This does not affect the CSR-based Renew path
	// (a genuine re-key), which always revokes the certificate it replaces.
	RevokeOnAutoRenew bool

	// ExternalSigner, when non-nil, is used instead of loading the CA private
	// key from disk. This enables key isolation: the private key lives in a
	// separate process and signing requests are proxied over IPC.
	// Set before calling Init(). When set, Init() skips key file loading and
	// the key-cert match verification (the signer process verifies this).
	ExternalSigner crypto.Signer

	// KeyProvider, when non-nil, is consulted instead of the local PEM-file
	// logic (loadCAKeyFromDisk/generateKey/SaveCAKey) for loading or
	// bootstrapping the CA's private key — e.g. internal/signer/openbao's
	// OpenBao Transit-backed provider. Set before calling Init(), only in
	// the process that actually holds/reaches the key (the isolated signer
	// child, or the single-process role); mutually exclusive with
	// ExternalSigner, which is used by the frontend instead. See
	// keyprovider.go.
	KeyProvider KeyProvider
	serialIndex map[string]string         // uppercase hex serial (no leading zeros) → subject; protected by mu
	ocspCache   map[string]ocspCacheEntry // same key; protected by mu
	cachedCRL   *x509.RevocationList      // in-memory CRL for auth checks; protected by mu
	mu          sync.RWMutex

	// crlUpdateFailures counts failures to amend the CRL: a CRL that could not
	// be re-signed, written or read, on any of the four paths that write one
	// (revoke, cleanup, reissue, refresh) — the read half centrally, in
	// readStoredCRL, which is what makes this cover all four — plus, on the
	// revoke path only, a bad serial or a failed inventory read while resolving
	// the subject's serial. That last one is how a revocation which merely
	// queued past LockTimeout lands here on the single-node backends, where the
	// spent deadline is not spotted until the read; one refused at a cross-node
	// acquisition fails earlier and is not counted. See docs/metrics.md.
	// Some callers treat these as fatal and return the error; others — notably
	// the best-effort revoke of a superseded certificate on renewal — swallow
	// it so the primary operation still succeeds. Either way a rising count
	// means the CRL is not being maintained and, for revocations, that a
	// superseded certificate may still be a valid credential. Exposed via the
	// metrics exporter (puppetca_crl_update_failures_total) for alerting.
	crlUpdateFailures atomic.Uint64

	// crlSyncFailures counts failures to refresh the in-memory CRL from storage
	// (see SyncCRLCache): an unreadable or unparseable stored CRL, or one this
	// CA did not sign. Distinct from crlUpdateFailures, which counts failures to
	// *amend* the CRL — this one is about a replica falling behind an amendment
	// some other replica made. While it rises, this process is deciding
	// revocation from a CRL that may predate a revocation elsewhere in the
	// fleet, so a certificate revoked there may still be admitted here. Exposed
	// via the metrics exporter (puppetca_crl_sync_failures_total) for alerting.
	crlSyncFailures atomic.Uint64

	// Four counters, because they answer four different questions, and their
	// remedies differ: one points at the file's contents, one at the CA bundle,
	// one at whatever writes the file, and one at the file's mount.
	//
	// They do not share a cadence, which matters when sizing an alert window.
	// crlChainFailures increments once per maintenance *pass*. The other three
	// increment once per CRL per *evaluation*, and crl_chain_file is evaluated
	// on every CRL amendment as well as on the maintenance pass, so those three
	// track revocation rate rather than the number of bad CRLs in the file --
	// strictly more often than the failure counter, which is the direction a
	// window sized against the slowest of them stays safe in. See
	// mixin/config.libsonnet, which is calibrated on exactly this.
	//
	// crlChainFailures counts refresh passes that could not publish the upstream
	// chain at all -- unreadable, unparseable, truncated or oversized. The
	// published chain is left alone and the next pass retries.
	//
	// crlChainDiscarded counts CRLs dropped from crl_chain_file because nothing
	// in the CA bundle signed them. This is the case where the chain quietly
	// *shrinks*: the file is authoritative, so a CRL the operator put there and
	// this CA would not accept simply stops being published.
	//
	// crlChainRegressed counts CRLs in crl_chain_file that were older than the
	// one already published for the same ancestor, and so were not used -- see
	// monotonicUpstream. It is deliberately not folded into crlChainDiscarded:
	// the two have opposite remedies. A discard means the CA bundle is missing
	// an ancestor, so the operator checks the bundle; a regression means the
	// file itself is stale, rolled back or replayed, so the operator checks
	// whatever writes it. One counter would have sent a paged responder to
	// verify a bundle that was already complete.
	//
	// crlChainRemoved counts ancestors the file has stopped listing while their
	// CRL was published. The file is authoritative, so this is honoured rather
	// than refused -- but it is unrecoverable here, and a `cat` glob that
	// matched one file fewer produces it just as readily as a deliberate
	// removal does. Distinct from crlChainDiscarded: that one counts CRLs the
	// file *does* carry which nothing in the bundle signed.
	//
	// Surfaced as puppetca_crl_chain_refresh_failures_total,
	// puppetca_crl_chain_discarded_total, puppetca_crl_chain_regressed_total and
	// puppetca_crl_chain_removed_total.
	crlChainFailures  atomic.Uint64
	crlChainDiscarded atomic.Uint64
	crlChainRegressed atomic.Uint64
	crlChainRemoved   atomic.Uint64

	// crlChainLastRead is the Unix time of the last successful read of
	// crl_chain_file, or zero if it has never been read.
	//
	// It exists for the case the counters cannot reach: an absent file is
	// deliberately not a failure -- it makes no statement -- so a crl_chain_file
	// pointing at a path that never mounted leaves every counter at zero and
	// every series flat and healthy while the ancestors age out. This series
	// stays at zero, which is the signal.
	//
	// It does *not* detect a subPath mount, and an earlier revision of this
	// comment wrongly claimed it did. A subPath mount is read successfully
	// forever, so the stamp advances every cycle exactly as it does on a healthy
	// file; the two are indistinguishable here. What catches a frozen mount is
	// the upstream CRL's own nextUpdate marching towards expiry --
	// PuppetCAUpstreamCRLExpiringSoon firing on a CA that has crl_chain_file
	// configured *is* the subPath signature.
	crlChainLastRead atomic.Int64

	// CRLChainFile is a PEM bundle of upstream CRLs merged into the published
	// chain. Empty disables the feature, which is the whole of it for a CA that
	// issues its own root. Every CRL in the file is signature-verified against
	// the stored CA bundle before it is published — see upstreamCRLs.
	CRLChainFile string

	// crlNotify carries a coalesced signal each time the CRL is re-signed (see
	// signCRLLocked). It is buffered to depth 1 and written non-blockingly, so a
	// burst of revocations collapses to a single pending notification and an
	// absent consumer never blocks signing. Consume it via CRLUpdated().
	crlNotify chan struct{}
}

func New(s *storage.StorageService, autosignCfg AutosignConfig, hostname string) *CA {
	return &CA{
		Storage:           s,
		AutosignConfig:    autosignCfg,
		Hostname:          hostname,
		CAPathLength:      -1,   // unconstrained by default
		PromoteCNToSAN:    true, // on by default; RFC 2818 deprecates CN-only certs
		RevokeOnAutoRenew: true, // on by default; only the newest serial should be valid
		serialIndex:       make(map[string]string),
		ocspCache:         make(map[string]ocspCacheEntry),
		crlNotify:         make(chan struct{}, 1),
	}
}

// CRLUpdateFailures returns the number of times the CA failed to amend the
// CRL — a revocation it could not record, or a CRL it could not re-sign or
// write (across the revoke, cleanup, reissue and refresh paths). A rising
// value means the CRL is not being maintained; the metrics exporter surfaces
// it as puppetca_crl_update_failures_total.
func (c *CA) CRLUpdateFailures() uint64 {
	return c.crlUpdateFailures.Load()
}

// CRLSyncFailures returns the number of times the CA failed to refresh its
// in-memory CRL from storage (see SyncCRLCache). A rising value means this
// replica's revocation checks are answering from a CRL that may be behind the
// stored one, so a certificate revoked on another replica may still be
// accepted here; the metrics exporter surfaces it as
// puppetca_crl_sync_failures_total.
func (c *CA) CRLSyncFailures() uint64 {
	return c.crlSyncFailures.Load()
}

// CRLChainFailures returns how many upstream-chain refresh passes failed.
// Surfaced as puppetca_crl_chain_refresh_failures_total.
func (c *CA) CRLChainFailures() uint64 { return c.crlChainFailures.Load() }

// CRLChainDiscarded returns how many CRLs have been dropped from
// crl_chain_file because no certificate in the CA bundle signed them. Surfaced
// as puppetca_crl_chain_discarded_total; a rising value means the published
// chain is smaller than the operator's file says it should be.
func (c *CA) CRLChainDiscarded() uint64 { return c.crlChainDiscarded.Load() }

// CRLChainRegressed returns how many CRLs in crl_chain_file have been passed
// over because the published chain already carried a newer one from the same
// ancestor. Surfaced as puppetca_crl_chain_regressed_total; a rising value means
// the file is stale, rolled back or replayed, and points at whatever writes it
// rather than at the CA bundle.
func (c *CA) CRLChainRegressed() uint64 { return c.crlChainRegressed.Load() }

// CRLChainRemoved returns how many ancestors crl_chain_file has stopped listing
// while their CRL was published. Surfaced as
// puppetca_crl_chain_removed_total; the removal is honoured because the file is
// authoritative, but it cannot be undone here, so a rising value wants checking
// against whether the operator meant it.
func (c *CA) CRLChainRemoved() uint64 { return c.crlChainRemoved.Load() }

// CRLChainLastRead returns when crl_chain_file was last read successfully, or
// the zero time if it never has been. See the field comment for why a feature
// whose whole value is "the file is re-read" needs to say whether it is.
func (c *CA) CRLChainLastRead() time.Time {
	sec := c.crlChainLastRead.Load()
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// CRLUpdated returns a channel that receives a value each time the CRL is
// re-signed (revoke, reissue, background refresh, or expired-cert cleanup).
// Notifications are coalesced: the channel is buffered to depth 1 and written
// non-blockingly, so when several CRL updates happen before the consumer reads,
// only a single pending signal is observed. Intended for a single consumer
// (e.g. the Kubernetes exporter) that re-reads the current CRL on each wake-up.
func (c *CA) CRLUpdated() <-chan struct{} {
	return c.crlNotify
}

// IsReady reports whether the CA has been fully initialized and can serve requests.
func (c *CA) IsReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.CACert != nil && c.CAKey != nil
}

// LoadKey loads the CA private key and certificate from disk without full
// initialization (no HMAC, serial index, or CRL cache).
func (c *CA) LoadKey(ctx context.Context) (crypto.Signer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.loadCA(ctx); err != nil {
		return nil, err
	}
	return c.CAKey, nil
}
