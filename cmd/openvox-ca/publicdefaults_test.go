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

package main

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/fileexport/fileexportconfig"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// The defaults the 1.0.0 public API covers (docs/development/releasing.md,
// "What the version number promises": every default except a performance or
// capacity one and ocsp_index_sync_interval_sec), each pinned as a literal and
// read through the path the server applies it with.
//
// Most of these already have a spec, and many compare the value only with the
// constant that supplies it, so lengthening an interval or raising a limit
// passes them all. A literal here is what fails. Where a row repeats a pin
// that exists elsewhere, it is so that this table is the list a reviewer
// checks against releasing.md, not a list of the gaps.
//
// Three covered defaults are pinned beside the code that applies them instead,
// because this package cannot reach them the way the server applies them:
//   - certificate validity (ca_validity_days, leaf_validity_days), through an
//     issued certificate in internal/ca's keys_test.go;
//   - a client_ca entry's allow_pp_cli_auth, through a loaded configuration in
//     clientca_test.go;
//   - how the key configurations resolve a half-set pair, in internal/ca's
//     keyconfig_internal_test.go; the rows below pin the defaults that
//     resolution falls back to.
//
// What each kind of change needs:
//   - an access or refusal default (what is granted, accepted or refused),
//     a key-strength default and a lifetime are breaking in either direction;
//   - an interval bounding how long a revocation or tampering takes to act on
//     is breaking when lengthened and not when shortened.
//
// Changing one needs a major release. Changing one deliberately in a major
// release means changing the literal here, and saying so in the release notes.
var _ = Describe("the covered defaults, as literals", func() {
	var cfg *serverConfig

	BeforeEach(func() {
		clearServerEnv()
		var err error
		cfg, err = loadServerConfig("")
		Expect(err).NotTo(HaveOccurred())
	})

	// configuredCA is a CA with the loaded configuration applied, as the server
	// builds it, so a default the CA resolves is read through its resolver.
	configuredCA := func() *ca.CA {
		GinkgoHelper()
		c := ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "ca.example.com")
		Expect(applyCAConfig(c, cfg)).To(Succeed())
		return c
	}

	const breaking = " is a covered default (docs/development/releasing.md): changing it needs a major release"

	DescribeTable("access, refusal and key-strength defaults",
		func(what string, actual func() any, want any) {
			Expect(actual()).To(Equal(want), what+breaking)
		},
		Entry("allow_public_status", "allow_public_status",
			func() any { return cfg.AllowPublicStatus }, false),
		Entry("no_pp_cli_auth: a pp_cli_auth certificate is an admin by default", "no_pp_cli_auth",
			func() any { return cfg.NoPpCliAuth }, false),
		Entry("allow_subject_alt_names", "allow_subject_alt_names",
			func() any { return cfg.AllowSubjectAltNames }, false),
		Entry("allow_duplicate_certs", "allow_duplicate_certs",
			func() any { return cfg.AllowDuplicateCerts }, false),
		Entry("no_tls_required", "no_tls_required",
			func() any { return cfg.NoTLSRequired }, false),
		Entry("promote_cn_to_san", "promote_cn_to_san",
			func() any { return cfg.PromoteCNToSAN }, true),
		Entry("revoke_on_auto_renew", "revoke_on_auto_renew",
			func() any { return cfg.RevokeOnAutoRenew }, true),
		Entry("autosign_config: off", "autosign_config", func() any {
			as, err := autosignConfigFrom(cfg)
			Expect(err).NotTo(HaveOccurred())
			return as.Mode
		}, "off"),
		Entry("client_revocation_policy", "client_revocation_policy",
			func() any { return cfg.ResolvedPolicy() }, "require"),
		Entry("csr_rate_limit, per address per minute", "csr_rate_limit",
			func() any { return resolveCSRRateLimit(cfg.CSRRateLimit) }, 60),
		Entry("ocsp_rate_limit, per address per minute", "ocsp_rate_limit",
			func() any { return resolveOCSPRateLimit(cfg.OCSPRateLimit) }, 300),
		Entry("insecure_allow_world_readable_keys", "insecure_allow_world_readable_keys",
			func() any { return cfg.InsecureAllowWorldReadableKeys }, false),
		Entry("insecure_allow_unsafe_autosign_path", "insecure_allow_unsafe_autosign_path",
			func() any { return cfg.InsecureAllowUnsafeAutosignPath }, false),
		Entry("insecure_allow_plain_http_generate", "insecure_allow_plain_http_generate",
			func() any { return cfg.InsecureAllowPlainHTTPGenerate }, false),
		Entry("the CA key: RSA 4096", "ca_key_algo and ca_key_size",
			func() any { return ca.DefaultCAKeyConfig }, ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 4096}),
		Entry("the leaf key: RSA 2048", "leaf_key_algo and leaf_key_size",
			func() any { return ca.DefaultLeafKeyConfig }, ca.KeyConfig{Algo: ca.KeyAlgoRSA, Size: 2048}),
	)

	DescribeTable("lifetimes, breaking in either direction",
		func(what string, actual func() time.Duration, want time.Duration) {
			Expect(actual()).To(Equal(want), what+breaking)
		},
		Entry("crl_validity_days", "crl_validity_days",
			func() time.Duration { return configuredCA().CRLValidityDuration() }, 30*24*time.Hour),
		Entry("the OCSP response lifetime", "the OCSP response lifetime (ca.OCSPValidity)",
			func() time.Duration { return ca.OCSPValidity }, 4*time.Hour),
		Entry("superseded_cert_revoke_after_sec", "superseded_cert_revoke_after_sec",
			func() time.Duration { return cfg.supersededCertRevokeAfter() }, 24*time.Hour),
	)

	DescribeTable("intervals bounding revocation or tamper detection, which may only shorten",
		func(what string, actual func() time.Duration, want time.Duration) {
			Expect(actual()).To(BeNumerically("<=", want), what+breaking+" when lengthened")
			// Exact as well, so that a shortening is a deliberate edit here
			// too rather than a silent change to what the docs state.
			Expect(actual()).To(Equal(want), what+" no longer matches the default the docs state")
		},
		Entry("crl_sync_interval_sec", "crl_sync_interval_sec",
			func() time.Duration { return cfg.crlSyncInterval() }, time.Minute),
		Entry("the CRL chain refresh interval", "crl_chain_refresh_interval_sec",
			func() time.Duration { return cfg.crlChainRefreshInterval() }, time.Hour),
		Entry("client_crl_refresh_interval_sec", "client_crl_refresh_interval_sec",
			func() time.Duration { return (&config.ClientCAConfig{}).ClientCRLRefreshInterval() }, time.Hour),
		Entry("superseded_cert_sweep_interval_sec", "superseded_cert_sweep_interval_sec",
			func() time.Duration { return cfg.supersededCertSweepInterval() }, 15*time.Minute),
		Entry("file_export's interval_sec", "file_export's interval_sec",
			func() time.Duration { return (&fileexportconfig.Config{}).Interval() }, time.Minute),
		Entry("inventory_verify_interval_sec", "inventory_verify_interval_sec",
			func() time.Duration { return cfg.inventoryVerifyInterval() }, 5*time.Minute),
	)
})
