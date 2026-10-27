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

package config

import (
	"github.com/voxpupuli/openvox-ca/internal/certstore/certconfig"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport/exportconfig"
)

// ServerConfig is the openvox-ca server's configuration file: every key the
// server accepts, and nothing else. cmd/openvox-ca defines its serverConfig on
// it and adds the defaults, the environment overlay and the accessors; it lives
// here so that openvox-ca-ctl migrate, which reads the same files, can decode
// them against the same schema rather than a subset of it. A key added to the
// server is a field added here, and both binaries then accept it.
//
// Identifiers these comments name without a package -- defaultShutdownDrain,
// parseConfiguredByteCount, defaultMemoryBudgetPercent and the like -- are
// cmd/openvox-ca's.
type ServerConfig struct {
	CADir             string `yaml:"cadir"`
	AutosignConfig    string `yaml:"autosign_config"`
	Host              string `yaml:"host"`
	Port              int    `yaml:"port"`
	Hostname          string `yaml:"hostname"`
	Verbosity         int    `yaml:"verbosity"`
	LogFile           string `yaml:"logfile"`
	TLSCert           string `yaml:"tls_cert"`
	TLSKey            string `yaml:"tls_key"`
	PuppetServer      string `yaml:"puppet_server"`
	PuppetServerFile  string `yaml:"puppet_server_file"`
	NoPpCliAuth       bool   `yaml:"no_pp_cli_auth"`
	NoTLSRequired     bool   `yaml:"no_tls_required"`
	AllowPublicStatus bool   `yaml:"allow_public_status"`
	OCSPUrl           string `yaml:"ocsp_url"`
	CRLUrl            string `yaml:"crl_url"`

	// CRLChainFile is a PEM bundle of upstream CRLs published alongside this
	// CA's own, for agents doing full-chain revocation checking (Puppet's
	// default). Re-read by the crl-chain-refresh job, so refreshing the file is
	// how an operator keeps ancestor CRLs current — every CRL in it is
	// signature-verified against the stored CA bundle before it is served.
	// Empty disables the feature.
	CRLChainFile string `yaml:"crl_chain_file"`

	// CRLChainRefreshIntervalSec is how often that file is re-read and the
	// published CRL rewritten if its upstream blocks changed. 0 = built-in
	// default (1h). Gated on crl_chain_file alone: an operator publishing an
	// upstream chain is not necessarily running any other periodic job.
	CRLChainRefreshIntervalSec int `yaml:"crl_chain_refresh_interval_sec"`

	// MetricsListen, when non-empty, enables the Prometheus exporter on the
	// given address (e.g. "127.0.0.1:9140" or ":9140"). The exporter serves
	// /metrics over plain HTTP on a separate listener from the Puppet API and is
	// disabled by default because it reveals certificate subjects (node
	// hostnames); restrict it to a trusted network or loopback.
	MetricsListen string `yaml:"metrics_listen"`

	// ShutdownTimeoutSec bounds the frontend's graceful HTTP-drain budget on
	// SIGTERM: the time in-flight requests are given to complete before the
	// listener is torn down. 0 selects the built-in default (defaultShutdownDrain).
	// The launcher derives its own, slightly larger, hard-kill deadline from
	// this value (drain + launcherShutdownHeadroom) so a child is never killed
	// mid-drain. Operators raising this must also raise their orchestrator's
	// termination grace period (Kubernetes terminationGracePeriodSeconds
	// defaults to 30s) or the platform will SIGKILL the pod first.
	ShutdownTimeoutSec int `yaml:"shutdown_timeout_sec"`

	// The default deployment is a process tree -- a launcher supervising an
	// isolated signer and a frontend -- and GOMEMLIMIT is a per-process knob, so
	// the launcher divides one tree-wide budget between the three rather than
	// letting each apply the whole of it. These three keys tune that division;
	// none of them is needed for the defaults to be sensible.
	//
	// MemoryReserveLauncher and MemoryReserveSigner are the fixed shares the
	// launcher and signer receive, as an integer with an optional IEC suffix,
	// with or without the trailing B ("24MiB", "24Mi", "25165824"). That is
	// deliberately wider than GOMEMLIMIT's own grammar, which requires the B;
	// see parseConfiguredByteCount. The frontend takes the remainder,
	// because in steady state it is the process whose footprint grows with the
	// fleet. The signer's share is the one an operator can outgrow: its startup
	// peak is fleet-proportional at roughly 420 bytes per certificate, and
	// raising the container limit does not reach it. The share also carries the
	// runtime's own footprint, so the usable headroom in the 24MiB default is
	// nearer 16MiB: raise memory_reserve_signer beyond roughly 40,000
	// certificates. Empty selects the built-in defaults.
	MemoryReserveLauncher string `yaml:"memory_reserve_launcher"`
	MemoryReserveSigner   string `yaml:"memory_reserve_signer"`

	// MemoryBudgetPercent is how much of a cgroup memory ceiling the tree may
	// claim when the budget is derived rather than stated. GOMEMLIMIT bounds Go
	// runtime memory only -- the binary's resident text, kernel memory charged
	// to the cgroup, and a memory-backed cadir all count against the same
	// ceiling from outside it -- so claiming the whole of it would make the
	// runtimes collect harder only once the cgroup was already at the wall.
	// 0 selects the built-in default (defaultMemoryBudgetPercent); values
	// outside 1-100 are ignored in favour of it. It does not apply to an
	// explicit GOMEMLIMIT, which is taken at face value because the operator
	// naming a number has already chosen their own headroom.
	MemoryBudgetPercent int `yaml:"memory_budget_percent"`

	// Key generation options (apply only when bootstrapping a new CA).
	CAKeyAlgo   string `yaml:"ca_key_algo"`
	CAKeySize   int    `yaml:"ca_key_size"`
	LeafKeyAlgo string `yaml:"leaf_key_algo"`
	LeafKeySize int    `yaml:"leaf_key_size"`

	// CA certificate subject fields (apply only when bootstrapping a new CA).
	CASubjectOrg      string `yaml:"ca_subject_org"`
	CASubjectOU       string `yaml:"ca_subject_ou"`
	CASubjectCountry  string `yaml:"ca_subject_country"`
	CASubjectLocality string `yaml:"ca_subject_locality"`
	CASubjectProvince string `yaml:"ca_subject_province"`

	// Validity and path length options (apply only when bootstrapping a new CA,
	// except LeafValidityDays and CRLValidityDays which apply on every
	// signing/revocation operation).
	CAPathLength     int `yaml:"ca_path_length"`     // -1=unconstrained (default), 0=leaf-only, N=N levels
	CAValidityDays   int `yaml:"ca_validity_days"`   // 0 = built-in default (~5 years)
	LeafValidityDays int `yaml:"leaf_validity_days"` // 0 = built-in default (~5 years)
	CRLValidityDays  int `yaml:"crl_validity_days"`  // 0 = built-in default (30 days)
	CSRRateLimit     int `yaml:"csr_rate_limit"`     // max CSR submissions per IP per minute; 0 disables, -1/unset = built-in default (60)

	// CASigningConcurrency caps concurrent CA-key signatures across issuance,
	// CRL re-signing and the OCSP responder together. Same three-state
	// convention as CSRRateLimit: 0 disables the bound (unbounded signing),
	// -1/unset takes the built-in default, positive values pass through.
	//
	// The default is a ceiling rather than a tuning — it exists to stop
	// unbounded growth, not to match any particular signer. Deployments using
	// an isolated signer over IPC or ca_key_provider: openbao should set this
	// to what that signer can actually sustain, which openvox-ca has no way to
	// discover.
	CASigningConcurrency int `yaml:"ca_signing_concurrency"`

	// Background CRL refresh keeps the CRL's NextUpdate from lapsing when no
	// certificates are being revoked. Safe to run on every replica: the work is
	// serialised on the shared CRL lock, so only one replica re-signs per cycle.
	DisableCRLRefresh     bool `yaml:"disable_crl_refresh"`      // true = never auto-refresh the CRL
	CRLRefreshIntervalSec int  `yaml:"crl_refresh_interval_sec"` // how often to check; 0 = built-in default (1h)
	CRLRefreshBeforeSec   int  `yaml:"crl_refresh_before_sec"`   // re-sign when remaining validity < this; 0 = crl_validity/3

	// CRLSyncIntervalSec is how often each replica re-reads the stored CRL into
	// the copy its revocation checks answer from, and so bounds how long a
	// certificate revoked on another replica keeps working here. Not covered by
	// disable_crl_refresh, which governs re-signing rather than propagation.
	CRLSyncIntervalSec int `yaml:"crl_sync_interval_sec"` // how often to reload the CRL; 0 = built-in default (60s)

	// OCSPIndexSyncIntervalSec is how often each replica re-reads the inventory
	// into the serial index its OCSP responder answers from, and so bounds how
	// long that responder says `unknown` about a certificate signed on another
	// replica. Separate from crl_sync_interval_sec because the two answer
	// different questions at different costs: that one re-reads a single small
	// CRL blob and bounds a certificate outliving its revocation, this one
	// re-reads the whole inventory and bounds a correct certificate being
	// reported as unrecognised.
	OCSPIndexSyncIntervalSec int `yaml:"ocsp_index_sync_interval_sec"` // how often to reload the OCSP serial index; 0 = built-in default (5m)

	// Background expired-certificate cleanup. Disabled by default: when enabled,
	// a job periodically removes certificates that expired more than the
	// retention grace period ago from the inventory and the CRL (and deletes
	// their stored signed certificate). Safe to run on every replica: the work is
	// serialised on the shared CRL lock, so only one replica prunes per cycle.
	EnableExpiredCertCleanup      bool `yaml:"enable_expired_cert_cleanup"`       // true = run the cleanup job
	ExpiredCertRetentionSec       int  `yaml:"expired_cert_retention_sec"`        // grace period after NotAfter before removal; 0 = built-in default (30d)
	ExpiredCertCleanupIntervalSec int  `yaml:"expired_cert_cleanup_interval_sec"` // how often to run; 0 = built-in default (24h)

	// CA key encryption at rest.
	EncryptCAKey        bool   `yaml:"encrypt_ca_key"`         // encrypt the CA private key at rest (AES-256-GCM + Argon2id)
	CAKeyPassphraseFile string `yaml:"ca_key_passphrase_file"` // path to file containing the CA key passphrase

	// InsecureAllowWorldReadableKeys downgrades the startup refusal on
	// world-accessible key material to a warning. Named for what it is: an
	// operator reaching for this should see what they are turning off in the
	// key itself.
	InsecureAllowWorldReadableKeys bool `yaml:"insecure_allow_world_readable_keys"`

	// InsecureAllowUnsafeAutosignPath runs the autosign executable even when
	// an entry on its path could be replaced by someone other than root or
	// the CA's own user, warning instead of refusing. Named, like the key
	// opt-out above, for what it turns off.
	InsecureAllowUnsafeAutosignPath bool `yaml:"insecure_allow_unsafe_autosign_path"`

	// PromoteCNToSAN adds the CN as a DNS SAN when the CSR has no SANs (default: true).
	PromoteCNToSAN bool `yaml:"promote_cn_to_san"`
	// AllowSubjectAltNames lets a submitted CSR request Subject Alternative
	// Names of its own (default: false, matching OpenVox Server's
	// allow-subject-alt-names). When false, a CSR carrying any SAN other than a
	// lone DNS entry equal to its own certname is refused at signing time. Does
	// not affect either generate path (`openvox-ca generate --dns` or the
	// admin-only `POST /generate/{subject}?dns=`), whose names come from an
	// administrator rather than from an agent's CSR.
	AllowSubjectAltNames bool `yaml:"allow_subject_alt_names"`
	// AllowDuplicateCerts lets a submitted CSR replace a subject's pending CSR,
	// or be queued alongside its signed or revoked certificate (default: false,
	// matching OpenVox Server's allow-duplicate-certs). When false, such a
	// submission is refused with a 400 until the subject is cleaned.
	AllowDuplicateCerts bool `yaml:"allow_duplicate_certs"`
	// PuppetDateTimeFormat formats JSON date/time fields using the original Puppet CA
	// style ("2006-01-02T15:04:05MST") instead of RFC 3339 (default: false).
	PuppetDateTimeFormat bool `yaml:"puppet_datetime_format"`
	// SerialNumberFormat selects how certificate status responses encode
	// serial_number: "number" (the default, OpenVox Server's JSON number) or
	// "hex" (an uppercase colon-separated string, as openssl prints it).
	// "hex" changes the field's JSON type, so it departs from OpenVox Server.
	SerialNumberFormat string `yaml:"serial_number_format"`
	// RevokeOnAutoRenew revokes the certificate replaced by the empty-body
	// (no-CSR) /certificate_renewal auto-renewal path once its successor is
	// signed and stored, so only the newest serial per subject stays valid
	// (default: true). Set to false to match OpenVox Server's own Clojure CA,
	// which leaves the replaced certificate valid until it naturally expires.
	RevokeOnAutoRenew bool `yaml:"revoke_on_auto_renew"`

	// SupersededCertRevokeAfterSec is how long a certificate a renewal has
	// replaced stays valid before it is revoked, instead of being revoked
	// inside the renewal call. Three states, per the CSRRateLimit convention:
	//
	//	 0  revoke immediately, inside the renewal — an explicit operator choice,
	//	    and the behaviour of every release before this setting existed
	//	>0  that duration
	//	-1  unset: the built-in default (24h)
	//
	// The default grants an overlap window in which both the replaced and the
	// replacement certificate verify, so relying parties can pick up the new
	// one without a gap — which is what makes a certificate other parties are
	// actively verifying safe to renew at all.
	//
	// It is also a deliberate weakening, and since it is the default it is one
	// every deployment inherits on upgrade: for the length of the window the
	// replaced certificate — and, on the CSR-based re-key path, the replaced
	// private key — is still a credential this CA accepts. Set 0 to restore the
	// previous behaviour. What keeps the window bounded rather than open-ended
	// is ca.CA.refuseIfSuperseded, which stops a certificate inside its window
	// renewing itself into a fresh full-lifetime successor.
	//
	// 24h is the same window the serving-certificate work settled on for the
	// same question asked about a different subject. That work is not in this
	// repository, so this deliberately does not name its setting: a comment
	// pointing at a config key nobody can grep for is worse than no pointer.
	//
	// It governs both renewal paths. RevokeOnAutoRenew still decides whether
	// the auto-renewal path retires its predecessor at all.
	SupersededCertRevokeAfterSec int `yaml:"superseded_cert_revoke_after_sec"`
	// SupersededCertSweepIntervalSec is how often the sweep that performs those
	// delayed revocations runs; 0 = built-in default (15m). The interval is
	// added to the effective delay in the worst case, so keep it well below
	// superseded_cert_revoke_after_sec.
	SupersededCertSweepIntervalSec int `yaml:"superseded_cert_sweep_interval_sec"`

	// LeafBackdateSec is how far before the moment of issuance a leaf
	// certificate's NotBefore is set, so a verifier whose clock is behind this
	// one still accepts a certificate just signed; 0 = built-in default (5m).
	//
	// It is a clock-skew tolerance, not a margin for a broken fleet: an agent
	// further out than this rejects a certificate the CA signed a moment ago as
	// not yet valid, and keeps rejecting it until its clock is fixed. Raise it
	// only where NTP cannot be relied on. It applies to every leaf this CA
	// issues -- from a CSR, generated, renewed or managed -- and not to the
	// CA's own certificate, which is backdated a fixed 24 hours at bootstrap.
	LeafBackdateSec int `yaml:"leaf_backdate_sec"`

	// ManagedCertIntervalSec is how often the managed-certificate reconcile
	// loop walks its configured set; 0 = built-in default (15m). It only has to
	// be short relative to the renew-before windows in force, and short enough
	// that a store deleted out from under the CA is repaired while somebody is
	// still looking.
	ManagedCertIntervalSec int `yaml:"managed_cert_interval_sec"`

	// KubernetesExport optionally publishes the CA certificate and/or CRL into
	// one or more Kubernetes Secrets and ConfigMaps. Disabled when no targets are
	// configured. File-only: the nested target list, labels, and annotations are
	// impractical to express as flags/env. Validated at startup.
	KubernetesExport exportconfig.Config `yaml:"kubernetes_export"`

	// ManagedCerts optionally issues and renews certificates for OpenVox
	// components into Kubernetes Secrets or local files, so that bringing up
	// OpenVox Server, OpenVoxDB and OpenVoxView needs no hand-issued
	// certificates and no hand-renewal later. Disabled when the list is empty.
	//
	// File-only, and for a stronger reason than kubernetes_export's: an entry
	// is a nested structure with a list of names and a choice of store, which
	// no flag or environment variable can express without inventing a second
	// syntax for it. Validated at startup, where a mistyped certname or an
	// impossible renewal window is refused as configuration rather than
	// discovered as a certificate that never appears.
	//
	// SECURITY: a managed certificate for a certname listed in puppet_server is
	// an admin credential, because it carries clientAuth and that listing is
	// what grants authority. See internal/certstore's package documentation.
	// NIST 800-53: AC-6 (Least Privilege)
	ManagedCerts certconfig.Config `yaml:"managed_certs"`

	// ServingCert optionally makes the CA issue and renew the certificate its
	// own listener presents, instead of being handed one through `tls_cert` /
	// `tls_key`. Nil disables it, which is the default.
	//
	// A *certconfig.Entry rather than a type of its own, deliberately: the
	// certificate the CA serves is described by the same fields a component's
	// is, lives in one of exactly the same two stores, and inherits the same
	// CA-wide defaults. A second spelling of that block would be a second thing
	// to keep in step with it, and the first divergence would be silent.
	//
	// What is not shared is the failure semantics, and that is this caller's
	// half rather than the store's: the material must be readable before the
	// listener binds and its absence is fatal, where a component store's
	// absence is routine and self-heals on the next pass. See cmd/openvox-ca/servingcert.go.
	//
	// A pointer so that `serving_cert: {}` is a configuration error -- a block
	// naming no store -- rather than a silent no-op.
	//
	// SECURITY: the serving certificate carries clientAuth by default, like
	// every other certificate this CA issues, so adding the CA's own certname
	// to puppet_server makes it an admin credential. That combination is a
	// normal shared-host deployment rather than a mistake, and it is reported
	// at startup rather than left to be inferred.
	// NIST 800-53: AC-6 (Least Privilege)
	ServingCert *certconfig.Entry `yaml:"serving_cert"`

	// Storage backend selection and parameters. Embedded inline so the YAML
	// keys (storage_backend, etcd_*, redis_*, sql_*, ca_cert_file, ca_key_file)
	// remain at the top level. Shared with the operator CLI's migrate command
	// via StorageConfig.
	StorageConfig `yaml:",inline"`

	// Foreign client trust domains (client_ca) and the revocation policy that
	// applies to them. Absent by default: with no entry there is exactly one
	// trust domain, it is ours, and authorisation is what it has always been.
	ClientCAConfig `yaml:",inline"`

	// CA key provider selection (ca_key_provider) and, when it selects
	// "openbao", the nested "openbao" settings block. Embedded inline so
	// ca_key_provider stays at the top level like StorageConfig's keys above.
	// The type lives in the shared config package (CAKeyProviderConfig)
	// so a future operator-CLI command can reuse it; today only the server
	// consumes it. "file" (default, unset) preserves today's local-key
	// behaviour; "openbao" delegates key custody and signing to an OpenBao
	// Transit key (internal/signer/openbao).
	CAKeyProviderConfig `yaml:",inline"`
}
