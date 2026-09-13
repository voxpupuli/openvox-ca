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

// The CA's own serving certificate: the listener's half of the managed
// certificate mechanism.
//
// The CA cannot otherwise issue the certificate it presents. That is fine when
// cert-manager or an operator supplies one, and impossible when the CA key is
// held at a provider -- cert-manager cannot act as a CA issuer without the key,
// and `openvox-ca-ctl generate` needs an admin certificate that does not exist
// until the CA is already serving.
//
// Everything about *what the certificate is* comes from elsewhere unchanged:
// internal/ca decides when to issue and renew it, and internal/certstore holds
// it in the same Secret or file pair a component certificate lives in. This
// file is only the three things neither of those can supply:
//
//  1. Issue it before the listener binds, and fail fatally if that does not
//     produce readable material.
//  2. Configure the listener from it, rather than from `tls_cert` / `tls_key`.
//  3. Update the listener on renewal, through a holder consulted per handshake,
//     so a reissue costs neither a rebuild nor a restart.
//
// # Why the fail-fast path lives here and not in the store
//
// A serving store must be readable before the listener binds and its absence is
// fatal; a component store's absence is routine and self-heals on the next
// pass. That asymmetry is a property of *this caller*, not of the store, which
// is why internal/ca takes a store as two function fields rather than as an
// interface spanning both callers -- an interface would have to express the
// difference in its contract, which is a worse place for it.
//
// servingCertStore below is not a counter-example. It spans the two *stores*
// within this one caller, so that this file can name a value that is either of
// them; it says nothing about failure semantics, and every decision about what
// is fatal is taken in this file rather than promised by that type.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/certstore"
)

// servingCertStore is a store this file can hold without knowing which flavour
// it is: internal/certstore's *FileStore or *SecretStore.
//
// Named for a message as well as read and written, because "startup failure
// looks different per store, and the message must say which" is a requirement
// rather than a nicety. A missing file is one thing; an unreachable API server,
// a missing RBAC grant, or a service account without `get` on that Secret is
// another, and "could not read the serving certificate" is not an adequate
// account of either. Both stores already name themselves in their own errors;
// String is what lets this file name one in a message the store did not raise.
type servingCertStore interface {
	fmt.Stringer
	Load(ctx context.Context) (certPEM, keyPEM []byte, err error)
	Save(ctx context.Context, certPEM, keyPEM []byte) error
}

// servingCert is the CA's own serving certificate: the store it lives in, the
// reconcile entry that keeps it current, and the holder the listener consults.
type servingCert struct {
	// store is where the material lives. Kept as a value rather than only as
	// the two function fields handed to internal/ca, so a fatal message can
	// name it.
	store servingCertStore

	// holder is what tls.Config.GetCertificate reads. Populated before the
	// listener binds and replaced on every renewal.
	holder *servingCertHolder

	// entry is what the reconcile loop walks. Its Load and Save wrap the
	// store's so that the holder is refreshed and the entry's own failures are
	// attributable; see newServingCert.
	entry ca.ManagedCert

	// lastErr is the most recent failure of this entry's own Load or Save.
	//
	// The reconcile pass reports only its first error across every entry, so a
	// component certificate's broken Secret and this certificate's missing
	// directory are indistinguishable in what it returns. Recording our own
	// failure as it happens is what lets the startup check say *why* the
	// serving store produced nothing, rather than only that it did.
	//
	// Read exactly once, by provisionServingCert, and only when the store came
	// back empty. It is not a health signal and nothing should treat it as one:
	// a Load that succeeds does not clear it, deliberately, because the failure
	// that explains an empty store is the Save that did not happen.
	lastErr atomic.Pointer[error]

	// issuedThisStart records whether this entry has written material into its
	// store. Set by every Save and never cleared, which is exact enough for its
	// one reader: provisionServingCert consults it immediately after the
	// startup pass, when the only Save that can have run is that pass's.
	issuedThisStart atomic.Bool
}

// newServingCert wraps a store into the entry the reconcile loop walks.
//
// Load and Save are both wrapped, and both wrappings earn their place:
//
//   - Save installs the material this replica just issued, so a renewal reaches
//     the listener within the pass rather than an interval later.
//   - Load installs whatever the store holds, which is how a renewal performed
//     by *another replica* reaches this one at all. Our Save never runs in that
//     case: the winner writes, our next pass loads the winner's certificate and
//     the decision finds it current, so without this the listener would keep
//     presenting the predecessor until it was revoked at the end of the
//     supersession window.
//
// Installing on Load cannot install anything worse than what the store holds,
// which is what the CA would be serving on a restart anyway.
func newServingCert(store servingCertStore, spec ca.CertSpec) *servingCert {
	s := &servingCert{
		store:  store,
		holder: &servingCertHolder{describe: store.String()},
	}
	s.entry = ca.ManagedCert{
		Spec: spec,
		Load: func(ctx context.Context) ([]byte, []byte, error) {
			certPEM, keyPEM, err := store.Load(ctx)
			if err != nil {
				s.record(err)
				return nil, nil, err
			}
			if len(certPEM) > 0 && len(keyPEM) > 0 {
				// A store holding material the listener cannot use is this
				// entry's failure even though the read succeeded, so it is
				// recorded -- but it is not returned. Returning it would stop
				// the reconcile pass that is about to replace the material,
				// which is the one thing that repairs this.
				if err := s.holder.install(certPEM, keyPEM); err != nil {
					s.record(err)
					// Logged as well as recorded. lastErr is read once, at
					// startup, and only when the store came back empty -- so
					// after the listener is up nothing else would ever mention
					// this. It is the arm that carries another replica's
					// renewal, which is the one case where unusable material
					// leaves this replica presenting the previous certificate
					// with no other signal until it expires.
					slog.Warn("The serving material in the store cannot be presented by the "+
						"listener; continuing with the certificate already installed",
						"store", store, "subject", spec.Subject, "error", err)
				}
			}
			return certPEM, keyPEM, nil
		},
		Save: func(ctx context.Context, certPEM, keyPEM []byte) error {
			if err := store.Save(ctx, certPEM, keyPEM); err != nil {
				s.record(err)
				return err
			}
			s.record(nil)
			s.issuedThisStart.Store(true)
			// Returned rather than only logged. Material this CA just issued
			// that will not form a keypair is a defect rather than a transient
			// fault, and it must not pass for a successful pass -- the store
			// already holds it, so the next pass finds it current and would
			// never mention it again.
			if err := s.holder.install(certPEM, keyPEM); err != nil {
				return fmt.Errorf("the serving certificate just written to %s cannot be "+
					"presented by the listener: %w", store, err)
			}
			return nil
		},
	}
	return s
}

// record stores (or clears) this entry's own most recent failure.
func (s *servingCert) record(err error) {
	if err == nil {
		s.lastErr.Store(nil)
		return
	}
	s.lastErr.Store(&err)
}

// ownError returns this entry's own most recent Load or Save failure, or nil.
func (s *servingCert) ownError() error {
	if p := s.lastErr.Load(); p != nil {
		return *p
	}
	return nil
}

// servingCertHolder holds the keypair the listener presents, and can be given a
// new one without disturbing established connections.
//
// The same shape as certReloader, and separate from it on purpose: certReloader
// re-reads two configured paths on SIGHUP, and this material has no path to
// re-read -- it arrives from the reconcile loop, which owns when it changes.
// The two are mutually exclusive by configuration, so exactly one of them is
// ever the listener's source.
type servingCertHolder struct {
	// current is handed to new handshakes. Read on every handshake and
	// replaced on renewal, so it is an atomic pointer rather than a lock.
	current atomic.Pointer[tls.Certificate]

	// describe names the store, for log lines.
	describe string

	// installMu makes the compare-and-store atomic. Today's callers are
	// serial -- the startup pass runs before the reconcile goroutine exists,
	// and that goroutine is one -- so this is not repairing a race that
	// exists; it is what stops the type's correctness depending on a fact
	// about its callers that nothing here states. The read path never takes
	// it, which is the property that matters for a per-handshake call.
	installMu sync.Mutex
}

// install parses the material and, if it differs from what is held, makes it
// the certificate new handshakes get.
//
// Unchanged material is a no-op rather than a store-and-log: Load installs on
// every reconcile pass, and a CA that logged a renewal every fifteen minutes
// would make the line that reports a real one worthless.
func (h *servingCertHolder) install(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("the serving material in %s is not a usable keypair: %w%s",
			h.describe, err, encryptedKeyHint(keyPEM))
	}
	// Go populates Leaf from the parse X509KeyPair already does, so this is the
	// certificate rather than a second parse of it.
	if cert.Leaf == nil {
		return fmt.Errorf("the serving certificate in %s parsed without a leaf", h.describe)
	}

	h.installMu.Lock()
	defer h.installMu.Unlock()

	prev := h.current.Load()
	if prev != nil && len(prev.Certificate) > 0 && bytes.Equal(prev.Certificate[0], cert.Certificate[0]) {
		return nil
	}
	h.current.Store(&cert)

	slog.Info("Serving certificate installed on the listener",
		"store", h.describe,
		"subject", cert.Leaf.Subject.CommonName,
		"serial", cert.Leaf.SerialNumber.String(),
		"not_after", cert.Leaf.NotAfter.Format(time.RFC3339),
		"replaced", prev != nil)

	// The same checks certReloader applies to an operator-supplied keypair, for
	// the same reason: crypto/tls presents whatever it is handed, so a
	// certificate that cannot authenticate this server is silent on this side
	// and fatal on the other. They should not fire on material this CA issued
	// -- buildServingCert refuses a usages list without serverAuth, which is
	// the only way to configure one that would -- so if one does fire it is
	// reporting a defect rather than a configuration mistake.
	if problems := servingCertProblems(cert.Leaf); len(problems) > 0 {
		slog.Warn("The serving certificate the CA issued for itself cannot serve TLS to a "+
			"client that verifies it; this is a defect rather than a setting, please report it",
			"store", h.describe,
			"subject", cert.Leaf.Subject.CommonName,
			"problems", strings.Join(problems, "; "))
	}

	// certReloader's second check, carried across so the two listener sources
	// really do report the same problems. servingCertProblems deliberately
	// excludes basicConstraints -- a CA leaf verifies and serves perfectly well,
	// so what is wrong with it is custodial rather than protocol -- and this CA
	// never issues itself one. It reaches here the way any foreign material
	// does: the Load wrapper installs whatever the store holds, which is how a
	// peer's renewal arrives and equally how anything pre-seeded into the store
	// does. The reconcile pass reissues over it, so the exposure is transient
	// unless that also fails, which is exactly when someone wants to be told.
	if cert.Leaf.IsCA {
		slog.Warn("The serving material in the store is a CA certificate; serving from it "+
			"puts a signing key on the network-facing listener. The CA will replace it on "+
			"the next reconcile pass",
			"store", h.describe, "subject", cert.Leaf.Subject.CommonName)
	}

	now := time.Now()
	switch {
	case now.After(cert.Leaf.NotAfter):
		slog.Warn("The serving certificate just installed has already expired; clients will reject it",
			"store", h.describe, "not_after", cert.Leaf.NotAfter.Format(time.RFC3339))
	case now.Before(cert.Leaf.NotBefore):
		slog.Warn("The serving certificate just installed is not valid yet; clients will reject it until then",
			"store", h.describe, "not_before", cert.Leaf.NotBefore.Format(time.RFC3339))
	}
	return nil
}

// GetCertificate satisfies tls.Config.GetCertificate. Consulted on every
// handshake, which is what makes a renewal take effect with no listener rebuild
// and no restart.
func (h *servingCertHolder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := h.current.Load()
	if cert == nil {
		// Unreachable: provisionServingCert refuses to let the server start
		// until one is installed.
		return nil, errors.New("no serving certificate has been issued yet")
	}
	return cert, nil
}

// encryptedKeyHint names the encrypted-key case when a keypair fails to load,
// as a clause to append to the error.
//
// crypto/tls accepts any PEM block whose type ends " PRIVATE KEY", so an
// "ENCRYPTED PRIVATE KEY" block passes its type check and then fails to parse.
// The failure that produces says nothing about encryption, and an operator who
// put an encrypted key in the store -- the one way this reaches material the CA
// did not generate itself -- would have no reason to suspect it. Encrypting the
// serving key is on #326's decided-against list precisely because it stopped
// the server booting; this is what makes the remaining route to it legible.
func encryptedKeyHint(keyPEM []byte) string {
	for rest := keyPEM; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return ""
		}
		if strings.Contains(block.Type, "ENCRYPTED") || len(block.Headers) > 0 {
			return ". The key is an encrypted PEM block, which crypto/tls accepts as a " +
				"private key and then cannot parse; the serving key must be unencrypted"
		}
	}
	return ""
}

// buildServingCert turns the `serving_cert` block into the CA's own serving
// certificate, or returns nil when none is configured.
//
// Fail-fast, and more so than managed certificates: every failure here is a
// configuration failure, and a CA that came up serving a certificate the
// operator did not ask for would be worse than one that refused to come up.
func buildServingCert(cfg *serverConfig, absCADir, configPath string,
	caCerts certstore.CACertSource) (*servingCert, error) {
	if cfg.ServingCert == nil {
		return nil, nil
	}

	// Self-provisioning does not write to the paths tls_cert and tls_key name.
	// The issuance decision reissues whenever the stored certificate is not
	// this CA's, so aiming it at an operator-supplied path would clobber a
	// certificate from another CA -- and aiming it anywhere else while those
	// two are set would leave two answers to which certificate the listener
	// presents. Refused rather than resolved.
	if cfg.TLSCert != "" || cfg.TLSKey != "" {
		return nil, errors.New("serving_cert and tls_cert/tls_key are mutually exclusive: " +
			"serving_cert makes the CA issue and renew the certificate its listener presents, " +
			"and tls_cert/tls_key point it at one somebody else supplies. Configure one or the " +
			"other -- and note that self-provisioning never writes to the paths tls_cert and " +
			"tls_key name, so it cannot be made to take them over")
	}

	// Validated through internal/certstore rather than beside it, so a serving
	// certificate is refused for exactly what a component certificate is
	// refused for and the two cannot drift.
	//
	// Under this block rather than the default, so every refusal names
	// `serving_cert` -- and, with Single set, names it without an index, since
	// a block holding one certificate is not a list. An operator with no
	// managed_certs block at all is never told to go and fix one.
	one := certstore.Config{*cfg.ServingCert}
	if err := one.ValidateIn(servingCertBlock); err != nil {
		return nil, err
	}
	// Write back what Validate normalised in place -- trimmed Secret names,
	// cleaned file paths -- so the store is built on the same spelling that was
	// checked, and so caOwnedPaths reserves the paths the store will write.
	*cfg.ServingCert = one[0]

	// A certificate that cannot serve TLS is refused as configuration rather
	// than issued, superseded and warned about once per renewal. `usages` is
	// the only way to reach it: unset means the serverAuth+clientAuth pair, and
	// narrowing to clientAuth alone gives the listener a certificate every
	// client that verifies it rejects.
	if err := requireServerAuth(cfg.ServingCert.Usages); err != nil {
		return nil, fmt.Errorf("invalid serving_cert config: %w", err)
	}

	// Against the CA's own files, the same check a managed certificate gets.
	// caOwnedPaths already reserves this entry's own paths, so they are
	// excluded by name: an entry colliding with itself is not a finding.
	reserved, err := caOwnedPaths(cfg, absCADir, configPath)
	if err != nil {
		return nil, err
	}
	if err := one.CheckReservedPathsIn(servingCertBlock, withoutServingCertPaths(reserved)); err != nil {
		return nil, err
	}
	// And against the Secrets the Kubernetes exporter writes, which would
	// otherwise take ca.crt from each other on every pass.
	if err := one.CheckExportOverlapIn(servingCertBlock,
		exportSecretTargets(cfg.KubernetesExport)); err != nil {
		return nil, err
	}
	// And against managed_certs, which nothing else compares this entry with.
	if err := checkManagedCertOverlap(cfg); err != nil {
		return nil, err
	}

	deps, err := servingCertDeps(one, caCerts)
	if err != nil {
		return nil, err
	}
	spec, store, err := buildServingCert1(one, deps)
	if err != nil {
		return nil, err
	}

	sc := newServingCert(store, spec)
	warnIfServingCertIsAdmin(cfg, spec)
	return sc, nil
}

// servingCertDeps assembles what internal/certstore needs that configuration
// cannot supply, for a single serving entry.
//
// Fail-fast on the same grounds as a managed certificate's Secret store, and
// more strongly: a serving store the CA cannot reach means no listener at all.
// Building the client makes no network call, so an API-server outage does not
// refuse startup; absent in-cluster credentials do.
func servingCertDeps(one certstore.Config, caCerts certstore.CACertSource) (certstore.Deps, error) {
	deps := certstore.Deps{CACerts: caCerts}
	if !one.NeedsKubernetes() {
		return deps, nil
	}
	client, err := inClusterClientset("the CA's own serving certificate Kubernetes Secret store")
	if err != nil {
		return certstore.Deps{}, err
	}
	deps.Client = client
	if one.NeedsDefaultNamespace() {
		ns, err := podNamespace()
		if err != nil {
			return certstore.Deps{}, fmt.Errorf("resolving the namespace for the CA's own "+
				"serving certificate, whose store does not name one: %w", err)
		}
		deps.DefaultNamespace = ns
	}
	return deps, nil
}

// buildServingCert1 builds the spec and the store for the single validated
// entry.
//
// The spec comes from certstore.Config.Build rather than from reading the
// entry's fields here, because the mapping from YAML to spec -- which fields
// inherit a CA-wide default, how `revoke_after: 0` differs from an absent one,
// how `usages` becomes an ExtKeyUsage list -- belongs to that package, and a
// second copy of it here would be the one that drifted.
//
// Build also constructs a store, and that one is discarded. This caller needs
// the concrete value so that a fatal message can name it, and Build erases it
// into two function fields; constructing a store touches nothing, so building
// the same one twice costs a struct.
func buildServingCert1(one certstore.Config, deps certstore.Deps) (ca.CertSpec, servingCertStore, error) {
	built, err := one.BuildIn(servingCertBlock, deps)
	if err != nil {
		return ca.CertSpec{}, nil, err
	}
	if len(built) != 1 {
		// Unreachable: one entry in, one entry out. Reported rather than
		// indexed blindly, because the spec that follows would otherwise be
		// some other certificate's.
		return ca.CertSpec{}, nil, fmt.Errorf("serving_cert produced %d entries, expected 1",
			len(built))
	}

	e := one[0]
	var store servingCertStore
	if e.Store.Secret != nil {
		ns := e.Store.Secret.Namespace
		if ns == "" {
			ns = deps.DefaultNamespace
		}
		store = certstore.NewSecretStore(deps.Client, *e.Store.Secret, ns, deps.CACerts)
	} else {
		store = certstore.NewFileStore(*e.Store.Files, deps.CACerts)
	}
	return built[0].Spec, store, nil
}

// withoutServingCertPaths drops the serving certificate's own paths from the
// reserved list.
//
// caOwnedPaths reserves them so that a `managed_certs` entry cannot overwrite
// the certificate the CA is presenting. Checking the serving entry against that
// same list would then refuse it for colliding with itself, which is not a
// finding -- so its own entries come out for that one comparison, by the
// setting name caOwnedPaths gave them.
func withoutServingCertPaths(reserved []certstore.ReservedPath) []certstore.ReservedPath {
	out := make([]certstore.ReservedPath, 0, len(reserved))
	for _, r := range reserved {
		if strings.HasPrefix(r.Setting, servingCertPathSetting) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// servingCertPathSetting prefixes the reserved-path settings naming the serving
// certificate's own file store, so withoutServingCertPaths can find them again.
const servingCertPathSetting = "serving_cert.store.files."

// servingCertBlock names the configuration block these entries came from, so
// internal/certstore's refusals say `serving_cert` rather than
// `managed_certs[0]`.
//
// Single because the block holds exactly one certificate: `serving_cert[0]`
// would misname it as precisely as the default did. The CA has one listener.
var servingCertBlock = certstore.Block{Name: "serving_cert", Single: true}

// requireServerAuth refuses a usages list that narrows the serving certificate
// out of being able to serve.
//
// An empty list is the inherited serverAuth+clientAuth pair and is fine. What
// this catches is `usages: [clientAuth]`, which produces a certificate the
// listener presents and every verifying client rejects -- a failure that looks
// like it is somewhere else entirely, because the handshake gets far enough to
// fail at the peer.
//
// Narrowing the other way, to serverAuth alone, is supported and is the case
// the setting exists for.
func requireServerAuth(usages []string) error {
	if len(usages) == 0 {
		return nil
	}
	for _, u := range usages {
		if strings.EqualFold(strings.TrimSpace(u), "serverAuth") {
			return nil
		}
	}
	return fmt.Errorf("usages %v does not include serverAuth, so the certificate the "+
		"listener presents would be rejected by every client that verifies it. Narrowing to "+
		"[serverAuth] is supported and is what this setting is for; narrowing away serverAuth "+
		"is not", usages)
}

// warnIfServingCertIsAdmin says so when the CA's own certname is listed in
// puppet_server and its serving certificate carries clientAuth.
//
// SECURITY: the two together are an admin credential. The listing is what
// grants the authority and clientAuth is what lets it be presented, and the
// serving certificate carries clientAuth by default -- the same pair every
// certificate this CA issues.
//
// That default is deliberate and the opposite of the least-privilege instinct.
// Running openvox-ca and OpenVox Server on one host sharing one serving
// certificate is a normal deployment: the CA needs serverAuth, the Server needs
// clientAuth because it talks to OpenVoxDB, and openvox-ca-ctl and the
// puppetserver CLI authenticate with it. A serverAuth-only default breaks that
// in a way that is hard to read -- the listener works and something else fails
// later.
//
// So this is a statement rather than a refusal: whoever reads the serving
// store's files or its Secret can administer this CA. An operator who added
// their CA's hostname to puppet_server without meeting this line would have to
// infer it.
// NIST 800-53: AC-6 (Least Privilege), AU-2 (Event Logging)
func warnIfServingCertIsAdmin(cfg *serverConfig, spec ca.CertSpec) {
	admins, err := buildAdminAllowList(cfg.PuppetServer, cfg.PuppetServerFile)
	if err != nil {
		// Not reported here. buildAuthConfig calls the same function a moment
		// later and fails the startup with it, and self-provisioning always
		// means TLS is on -- so unlike warnIfManagedCertIsAdmin there is no
		// plain-HTTP arm in which this would otherwise be silent.
		return
	}
	if !admins[spec.Subject] || !carriesClientAuth(spec) {
		return
	}
	slog.Warn("The CA's own serving certificate is a CA admin credential: its certname is "+
		"listed in puppet_server and it carries clientAuth. Whoever can read its store can "+
		"administer this CA, so protect that store as you would the CA's own key. Set "+
		"`serving_cert.usages: [serverAuth]` if this CA's own name should not be an "+
		"administrator",
		"subject", spec.Subject)
}

// provisionServingCert makes the certificate exist and be readable, before the
// listener binds. Every failure it reports is fatal.
//
// # What "fatal" is measured against
//
// The reconcile pass is asked to run, and then the *store* is asked what it
// holds. The second question is the one that decides, because it is the one the
// listener's ability to bind actually depends on:
//
//   - A pass that failed but left usable material behind is not fatal. A
//     certificate that is current, or is due for renewal and did not get it, is
//     still a certificate the CA can serve while the loop retries -- refusing
//     to start would turn a renewal that can wait into an outage.
//   - A pass that succeeded but left nothing readable is fatal, whatever it
//     returned.
//
// # Why the pass reconciles every entry and not only this one
//
// internal/ca reconciles the configured set; it exposes no single-entry call,
// because #242's mechanism was shaped when the set had one kind of member. The
// cost is that a component certificate's store is also consulted before the
// listener binds, which is bounded -- entries are independent, a failure is
// logged and left for the next pass -- and only paid by a deployment that
// configured self-provisioning at all.
//
// What it does not cost is attribution, which is the part that would have
// mattered: ReconcileManaged reports one error across every entry, so this
// entry's own Load and Save are wrapped to record their failures as they
// happen. That is what lets a fatal message say the directory does not exist,
// rather than that no certificate appeared.
func provisionServingCert(ctx context.Context, myCA *ca.CA, s *servingCert) error {
	if s == nil {
		return nil
	}

	// Bounded as a whole, which the pass is not on its own: internal/ca gives
	// each entry its own budget, so the pass costs the sum of them. This runs
	// before the listener binds, inside the window a Kubernetes startupProbe
	// and systemd's TimeoutStartSec are both measuring, and both were derived
	// for CA.Init alone.
	//
	// What actually reaches that sum is worth stating precisely, because the
	// obvious answer is wrong. It is NOT lock contention: each entry locks on
	// subjectLockName(subject), so two entries take two different locks and
	// cannot block one another -- reaching the sum that way would need N
	// separate peers each stalled on a different subject, which is contrived.
	// What reaches it with a single fault is the stores. A Secret store bounds
	// each API call at 30s, so three component certificates behind an API
	// server that BLACKHOLES packets is ninety seconds against a chart budget
	// of sixty. The drop matters: a network policy that refuses the connection
	// fails in milliseconds and none of this materialises, so anyone testing
	// this has to drop rather than reject or they will conclude the bound is
	// unnecessary.
	//
	// Three things follow that are easy to get wrong:
	//
	//   - A healthy pass does not spend this budget. Every entry reads its
	//     store, finds the certificate current and returns, so the common start
	//     is milliseconds and the bound is insurance. It binds only when a
	//     store is slow, which is exactly when a cap is wanted.
	//   - Ordering fixes starvation, not latency. The serving entry being first
	//     guarantees it a turn; it does not make the pass return sooner, since
	//     ReconcileManaged walks the rest before it returns. That is accepted
	//     rather than overlooked: returning as soon as this entry succeeded
	//     would need a single-entry reconcile, which internal/ca does not
	//     expose, and narrowing c.ManagedCerts around the call to fake one
	//     would mutate shared state to express a call shape the callee should
	//     offer. The request is with #322 instead.
	//   - The background loop's own immediate pass is therefore not redundant.
	//     It is what reconciles anything this bounded pass did not reach, a
	//     moment later and off the startup path. A component certificate read
	//     twice on a healthy start is the price of that safety net.
	provisionCtx, cancel := context.WithTimeout(ctx, ca.LockTimeout)
	defer cancel()
	if _, err := myCA.ReconcileManaged(provisionCtx); err != nil {
		// Logged, not returned. It may belong to another entry entirely, and
		// the question that decides is asked below.
		slog.Debug("The startup reconcile pass reported a failure; "+
			"whether it was the serving certificate's is decided by the load below",
			"error", err)
	}

	certPEM, keyPEM, err := s.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("the CA's serving certificate cannot be read from %s, so the "+
			"listener has nothing to present: %w", s.store, err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Errorf("the CA's serving certificate was not issued into %s, so the "+
			"listener has nothing to present: %w", s.store, whyNothingWasIssued(s))
	}
	if err := s.holder.install(certPEM, keyPEM); err != nil {
		return fmt.Errorf("the CA's serving certificate cannot be presented by the "+
			"listener: %w", err)
	}

	// A store that lost its material is indistinguishable from a first start,
	// and both issue. On an ephemeral container filesystem that happens at
	// every restart: the CA issues a fresh serving certificate and supersedes
	// the previous one, accumulating CRL entries for certificates nothing ever
	// presented. That is a legitimate choice -- and it should be a choice
	// rather than something discovered in a CRL months later.
	if s.issuedThisStart.Load() {
		slog.Info("Issued a new serving certificate because the store held none. If this "+
			"store does not survive a restart, every restart issues one and supersedes its "+
			"predecessor, and the CRL accumulates entries for certificates nothing presented",
			"store", s.store)
	}
	return nil
}

// whyNothingWasIssued explains an empty serving store as specifically as the
// pass allows, for the fatal message.
func whyNothingWasIssued(s *servingCert) error {
	if err := s.ownError(); err != nil {
		return err
	}
	// Reachable when the entry failed before its store was touched at all --
	// the subject lock timing out, or the CA reporting itself uninitialised.
	// The pass logs the reason as a warning against the subject; this says
	// where to look rather than inventing a cause.
	return errors.New("the reconcile pass neither wrote nor failed against the store; " +
		"see the \"Managed certificate not reconciled\" warning logged above for this certname")
}

// getCertificate returns the listener's certificate source, or nil when the CA
// is not self-provisioning and the operator-supplied pair is the source.
//
// A method on a possibly-nil receiver so the serve command can ask the question
// without a nil check of its own: there is one place that decides which of the
// two sources the listener uses, and it is this line.
func (s *servingCert) getCertificate() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s == nil {
		return nil
	}
	return s.holder.GetCertificate
}

// checkManagedCertOverlap refuses a serving certificate that collides with a
// managed one on its certname or on its Secret.
//
// internal/certstore refuses both collisions *within* a block: two entries
// sharing a certname "would replace each other on every pass" because there is
// one inventory slot per subject, and two entries sharing a Secret "would each
// remove the other's keys" because every managed certificate applies under one
// field manager, so neither apply ever raises a conflict. Both checks are built
// per call, over one slice. serving_cert and managed_certs are validated in
// separate calls and only meet afterwards, when main.go appends the serving
// entry to the same ca.ManagedCerts slice -- so neither check sees the pair,
// and internal/ca de-duplicates nothing.
//
// The victim of either collision is the certificate the listener presents. Both
// entries reconcile the same subject, each pass finds the other's certificate
// failing its own spec, and the two supersede each other for ever: the CA ends
// up presenting a certificate its own CRL revokes, the CRL grows an entry every
// interval, and where that certname is listed in puppet_server the credential
// being churned is a CA admin credential. The shared-host deployment this
// feature documents is exactly where an operator would write one certname in
// both blocks.
//
// The file-store direction is covered in three of its four pairings by
// caOwnedPaths, which reserves the serving cert and key -- so a managed entry
// whose cert, key or chain lands on either is refused. The fourth is not, and
// is closed below: the serving entry's own chain file is deliberately NOT
// reserved, because a shared chain is the ordinary layout, and that exemption
// leaves a managed entry's cert or key free to collide with it. An earlier
// version of this comment claimed internal/certstore already refused that pair;
// it does, but only within one block, and these are two blocks.
//
// Written here rather than in internal/certstore because that package has no
// notion of two blocks feeding one reconcile set -- Config.ValidateIn takes one
// block at a time. If a third consumer of the mechanism ever appears, this
// belongs there instead of being copied a second time.
func checkManagedCertOverlap(cfg *serverConfig) error {
	e := cfg.ServingCert
	if e == nil {
		return nil
	}
	for i := range cfg.ManagedCerts {
		m := &cfg.ManagedCerts[i]
		if m.Certname == e.Certname {
			return fmt.Errorf("serving_cert (%s) and managed_certs[%d] name the same "+
				"certname: they share one inventory slot, so each pass would find the "+
				"other's certificate failing its own spec and replace it, for ever -- and "+
				"the certificate being replaced is the one this CA's listener presents. "+
				"Give the component certificate a certname of its own",
				e.Certname, i)
		}
		if err := servingSecretCollision(e, m, i); err != nil {
			return err
		}
		if err := servingChainCollision(e, m, i); err != nil {
			return err
		}
	}
	return nil
}

// servingSecretCollision reports a managed certificate whose Secret store may
// name the same Secret as the serving certificate's.
//
// Compared on the name first and then on whether the two namespaces can name
// the same one, which is how internal/certstore compares its own pairs and for
// the same reason: an omitted namespace resolves to the CA pod's own, which is
// not known here because this runs before any Kubernetes client exists. So an
// omission on either side is treated as possibly-the-other and the pair is
// refused. That over-refuses only where the two genuinely differ and one was
// left blank, which costs an operator one spelled-out namespace.
func servingSecretCollision(e, m *certstore.Entry, idx int) error {
	es, ms := e.Store.Secret, m.Store.Secret
	if es == nil || ms == nil || es.Name != ms.Name {
		return nil
	}
	if es.Namespace != ms.Namespace && es.Namespace != "" && ms.Namespace != "" {
		return nil
	}
	msg := "serving_cert (%s) and managed_certs[%d] (%s) both store their material in " +
		"Secret %s/%s: every managed certificate applies under one field manager, so " +
		"neither write ever raises a conflict and the two would overwrite each other's " +
		"certificate and key on every pass -- including the one this CA's listener " +
		"presents. Give one of them a Secret of its own"
	if es.Namespace == "" || ms.Namespace == "" {
		msg += ". An omitted namespace resolves to the CA pod's own, so it is treated as " +
			"possibly naming the same Secret; spell both namespaces out if they genuinely differ"
	}
	return fmt.Errorf(msg, e.Certname, idx, m.Certname, nsOrPodNamespace(es.Namespace), es.Name)
}

// nsOrPodNamespace renders a namespace for a message, saying what an empty one
// means rather than printing nothing.
func nsOrPodNamespace(ns string) string {
	if ns == "" {
		return "<the CA pod's namespace>"
	}
	return ns
}

// servingChainCollision reports a managed certificate whose certificate or key
// file is the serving certificate's chain file.
//
// The one file pairing nothing else refuses. caOwnedPaths reserves the serving
// cert and key, so every pairing involving those is caught; the serving chain
// file is left unreserved on purpose, because every entry writes the same chain
// from the same source and sharing one is the ordinary way to lay several
// components out on a host. That exemption is about chain-to-chain sharing, and
// it accidentally permits chain-over-material too.
//
// The consequence is not cosmetic. A file store writes key, then chain, then
// certificate, so each serving issuance would overwrite the component's
// certificate -- or its private key -- with the CA chain. The component entry
// reads its store back, finds material failing its own spec, and reissues; the
// two then take turns for ever, a CRL entry per pass.
//
// Chain against chain is left alone, which is the sharing this exists to
// preserve.
func servingChainCollision(e, m *certstore.Entry, idx int) error {
	ef, mf := e.Store.Files, m.Store.Files
	if ef == nil || mf == nil || ef.CA == "" {
		return nil
	}
	for _, p := range []struct{ field, path string }{{"cert", mf.Cert}, {"key", mf.Key}} {
		if p.path != ef.CA {
			continue
		}
		return fmt.Errorf("serving_cert (%s) writes its CA chain to %q, which is "+
			"managed_certs[%d] (%s) store.files.%s: every issuance of the serving "+
			"certificate would overwrite that component's %s with the chain, and the "+
			"component would reissue over it on the next pass, for ever. Give one of them "+
			"a path of its own -- two entries may share a chain file, but nothing else",
			e.Certname, ef.CA, idx, m.Certname, p.field, p.field)
	}
	return nil
}
