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
	"crypto/x509"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/certstore"
	"github.com/voxpupuli/openvox-ca/internal/k8sclient"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// buildManagedCerts turns the `managed_certs` block into the entries the
// reconcile loop walks, or returns nil when none is configured.
//
// Fail-fast, like the storage block: every failure reachable here is a
// configuration failure rather than a transient one. A certname the CA's
// grammar refuses, a renewal window that can never open, a Secret store on a CA
// that is not running in a pod -- none of those gets better by waiting, and
// nothing else supplies the certificates an operator configured. Building the
// client makes no network call, so an API-server outage alone does not refuse
// startup; what does is credentials that are absent rather than unreachable.
//
// This is where managed certificates diverge from kubernetes_export, and the
// divergence is deliberate rather than an oversight. An export whose client
// cannot be built is logged and the CA carries on serving, because an export is
// auxiliary -- a stale published copy of a certificate the CA still serves over
// HTTP. A managed certificate is load-bearing for the component that needs it,
// and a CA that came up serving while quietly issuing none of them would be
// discovered when that component failed to start. So one entry with a Secret
// store makes in-cluster credentials a startup requirement for the whole
// process, which docs/configuration.md states in its own `store.secret`
// section, where an operator choosing that store will meet it.
//
// Note what is deliberately not fatal: a store that cannot be written *at
// runtime*. That is routine, is logged per entry, and self-heals on the next
// pass. The distinction is between a configuration that can never work and a
// pass that did not work this time.
func buildManagedCerts(cfg *serverConfig, absCADir string, caCerts certstore.CACertSource) ([]ca.ManagedCert, error) {
	if !cfg.ManagedCerts.Enabled() {
		return nil, nil
	}
	if err := cfg.ManagedCerts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid managed_certs config: %w", err)
	}
	// Both cross-block checks run before any client is built, so a
	// configuration error is refused without needing a cluster to refuse it --
	// which also keeps them reachable from a test. See CheckExportOverlap for
	// how an omitted namespace is handled without resolving one.
	if err := cfg.ManagedCerts.CheckExportOverlap(
		exportSecretTargets(cfg.KubernetesExport),
	); err != nil {
		return nil, fmt.Errorf("invalid managed_certs config: %w", err)
	}
	reserved, err := caOwnedPaths(cfg, absCADir)
	if err != nil {
		return nil, err
	}
	if err := cfg.ManagedCerts.CheckReservedPaths(reserved); err != nil {
		return nil, fmt.Errorf("invalid managed_certs config: %w", err)
	}

	deps := certstore.Deps{CACerts: caCerts}
	if cfg.ManagedCerts.NeedsKubernetes() {
		client, err := k8sclient.InClusterClientset("a managed certificate's Kubernetes Secret store")
		if err != nil {
			return nil, err
		}
		deps.Client = client
		// Only resolved when something relies on it, so a configuration that
		// spells out every namespace is not held up by an unreadable
		// ServiceAccount mount -- the same rule the exporter follows.
		if cfg.ManagedCerts.NeedsDefaultNamespace() {
			ns, err := k8sclient.PodNamespace()
			if err != nil {
				return nil, fmt.Errorf("resolving the namespace for a managed certificate "+
					"whose store does not name one: %w", err)
			}
			deps.DefaultNamespace = ns
		}
	}

	managed, err := cfg.ManagedCerts.Build(deps)
	if err != nil {
		return nil, err
	}
	warnIfManagedCertIsAdmin(cfg, managed)
	return managed, nil
}

// attachManagedCerts builds the managed certificates and hands them to the CA.
//
// A function rather than two lines inline in the serve command, because the
// assignment is the whole feature's switch: the reconcile job is registered
// only when ca.CA.ManagedCerts is non-empty, the configured gauge is emitted by
// walking it, and the never-issued alert has nothing to match if it stays nil.
// Every other spec sets that field by hand, so the one line that sets it in
// production was deletable with the suite green -- the same gap applyCAConfig
// and its wiring spec exist to close for ca_signing_concurrency.
func attachManagedCerts(myCA *ca.CA, cfg *serverConfig, absCADir string,
	caCerts certstore.CACertSource) error {
	managed, err := buildManagedCerts(cfg, absCADir, caCerts)
	if err != nil {
		return err
	}
	myCA.ManagedCerts = managed
	return nil
}

// exportSecretTargets lists the (namespace, name) of every Secret the
// Kubernetes exporter writes, for the overlap check.
//
// ConfigMap targets are excluded: they cannot be a managed certificate's store,
// so an overlap is impossible and reporting one would be a false refusal. Kind
// is matched case-insensitively because this runs before the export config's
// own Validate normalises it, and an operator who wrote `kind: secret` means
// the same thing.
//
// Namespaces are passed through as written. CheckExportOverlap knows that an
// omission on either side may resolve to the pod's own namespace and treats the
// pair as colliding, which is what lets this run before any client exists.
func exportSecretTargets(cfg k8sexport.Config) [][2]string {
	var out [][2]string
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if strings.EqualFold(strings.TrimSpace(t.Kind), k8sexport.KindSecret) {
			out = append(out, [2]string{t.Metadata.Namespace, t.Metadata.Name})
		}
	}
	return out
}

// caOwnedPaths lists the filesystem locations this CA keeps its own state in,
// for CheckReservedPaths.
//
// cadir is a whole tree: it holds the CA key and certificate, the CRL, and the
// filesystem and SQLite backends' state, and the names inside it are the CA's
// to choose rather than an operator's to predict. The rest are single files the
// server reads or writes under a configured name.
//
// ca_cert_file and ca_key_file are the reason this list is swept rather than
// written once. They are local-file overrides that put the CA's own certificate
// and private key outside cadir -- the usual shape when the backend is remote --
// and they live in the embedded StorageConfig rather than beside the settings
// above. The first version of this function enumerated only serverConfig's own
// fields and so omitted them, which left the one path the check exists to
// protect unprotected while the documentation said otherwise. reservedSettings
// in the spec file now measures the class instead: every path-shaped
// configuration key is either here or carries a recorded reason for not being.
//
// tls_cert and tls_key are on the list on purpose. Making the CA's own serving
// certificate a managed one is openvox-ca#326 and is a different mechanism from
// this; until it exists, an entry pointed at that pair would have the reconcile
// loop overwrite the certificate the CA is presenting on a listener it does not
// reload.
//
// Each is resolved against the process's working directory the same way the
// server itself resolves it, because a relative path in either place means the
// same thing -- and an unresolvable one is reported rather than dropped, since a
// dropped entry is a gap that looks like a passing check.
func caOwnedPaths(cfg *serverConfig, absCADir string) ([]certstore.ReservedPath, error) {
	out := []certstore.ReservedPath{{Setting: "cadir", Path: absCADir, Tree: true}}
	named := []certstore.ReservedPath{
		{Setting: "tls_cert", Path: cfg.TLSCert},
		{Setting: "tls_key", Path: cfg.TLSKey},
		{Setting: "ca_cert_file", Path: cfg.CACertFile},
		{Setting: "ca_key_file", Path: cfg.CAKeyFile},
		{Setting: "ca_key_passphrase_file", Path: cfg.CAKeyPassphraseFile},
		{Setting: "crl_chain_file", Path: cfg.CRLChainFile},
		{Setting: "logfile", Path: cfg.LogFile},
		{Setting: "puppet_server_file", Path: cfg.PuppetServerFile},
		{Setting: "autosign_config", Path: cfg.AutosignConfig},
	}
	// One entry per configured foreign trust domain, named after the entry so a
	// refusal says which. These are read on every client handshake: a
	// certificate written over an anchor would be trusted as an issuer, and one
	// written over a CRL bundle would silently stop revocation checking for
	// that domain.
	for i := range cfg.ClientCA {
		e := &cfg.ClientCA[i]
		named = append(named,
			certstore.ReservedPath{
				Setting: fmt.Sprintf("client_ca[%d].file (%s)", i, e.Name), Path: e.File},
			certstore.ReservedPath{
				Setting: fmt.Sprintf("client_ca[%d].crl_file (%s)", i, e.Name), Path: e.CRLFile},
		)
	}
	for _, r := range named {
		if strings.TrimSpace(r.Path) == "" {
			continue
		}
		abs, err := filepath.Abs(strings.TrimSpace(r.Path))
		if err != nil {
			return nil, fmt.Errorf("resolving %s for the managed_certs path check: %w",
				r.Setting, err)
		}
		r.Path = abs
		out = append(out, r)
	}
	return out, nil
}

// warnIfManagedCertIsAdmin says so when a managed certificate's certname is
// listed in puppet_server.
//
// SECURITY: such a certificate is a CA admin credential. The listing is what
// grants the authority and clientAuth is what lets it be presented, and a
// managed certificate carries clientAuth unless the entry narrows it away. This
// is not new exposure -- it is the same trust as OpenVox Server holding its
// certificate on disk today -- but the store now holds that credential, and its
// namespace, RBAC and file permissions deserve the same care as the CA's own.
// An operator left to infer that a component store is ordinary will infer
// wrongly, so this is said once at startup rather than only in the reference
// documentation.
//
// Not a refusal. This is the intended configuration for OpenVox Server, which
// is the whole point of #243 -- naming it is the objective, not preventing it.
// NIST 800-53: AC-6 (Least Privilege), AU-2 (Event Logging)
func warnIfManagedCertIsAdmin(cfg *serverConfig, managed []ca.ManagedCert) {
	// Through buildAdminAllowList, which is the single construction point for
	// this list and is what the middleware and SIGHUP both use. A second
	// comma-splitting merge here would be a second answer to "who is an
	// administrator", and the one that drifted would be this one.
	//
	// A failure is not reported here. buildAuthConfig calls the same function a
	// moment later and fails the startup with it, so saying it twice would only
	// make the first mention look like the cause.
	admins, err := buildAdminAllowList(cfg.PuppetServer, cfg.PuppetServerFile)
	if err != nil || len(admins) == 0 {
		return
	}
	for i := range managed {
		subject := managed[i].Spec.Subject
		if !admins[subject] {
			continue
		}
		if !carriesClientAuth(managed[i].Spec) {
			// Listed, but narrowed so it cannot be presented as a client. Worth
			// a word too: the listing grants nothing this certificate can use,
			// which is usually a mistake in one of the two settings.
			slog.Warn("A managed certificate's certname is listed in puppet_server, but the "+
				"certificate does not carry clientAuth, so it cannot be used to administer "+
				"this CA. Add clientAuth to its usages, or remove the name from puppet_server",
				"subject", subject)
			continue
		}
		slog.Warn("A managed certificate is a CA admin credential: its certname is listed in "+
			"puppet_server and it carries clientAuth. Whoever can read its store can "+
			"administer this CA, so protect that store as you would the CA's own key",
			"subject", subject)
	}
}

// carriesClientAuth reports whether a spec's certificate will be usable as a
// client. An unset usage list means the serverAuth+clientAuth pair every other
// issuance path uses, so it counts.
func carriesClientAuth(spec ca.CertSpec) bool {
	if len(spec.ExtKeyUsage) == 0 {
		return true
	}
	for _, u := range spec.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
