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

// Package certstore holds the certificates and private keys of the components
// this CA issues for, and turns the `managed_certs` configuration block into
// the entries internal/ca's reconcile loop walks.
//
// The goal is narrow and worth stating plainly: bring up OpenVox Server,
// OpenVoxDB and OpenVoxView without hand-issuing certificates, converting them
// to Secrets or files, and hand-renewing them later. It is not a
// general-purpose certificate authority for a cluster -- a certificate the CA
// does not like is refused rather than accommodated.
//
// # Two stores, chosen rather than inferred
//
// A [SecretStore] keeps one Kubernetes Secret per certificate; a [FileStore]
// keeps a certificate and key file pair. Which one an entry uses is
// configuration -- the `store:` block names exactly one -- and never inferred
// from the environment. A CA that guessed it was in Kubernetes would surprise
// whoever ran the container deliberately, and the file store is not a fallback:
// it exists because the bootstrap deadlock in #189 applies to a systemd unit as
// much as to a pod. With `ca_key_provider: openbao` or an external signer the
// CA cannot mint its own serving certificate, because `openvox-ca-ctl generate`
// needs an admin certificate that does not exist until the CA is already
// serving.
//
// The two mean the same thing wherever they can. Where they cannot, they say
// so rather than quietly supporting one: `adopt_existing` is a field of the
// Secret store and not of the entry, because server-side apply has no
// filesystem equivalent and a file carries no record of who wrote it. See
// [FileStore] for the one other difference, which is atomicity.
//
// # The private key
//
// A store is the only copy of the private key it holds. Nothing here writes a
// leaf key to the CA's backing store or to the local cadir: internal/ca
// generates the key inside the subject lock, hands it to [SecretStore.Save] or
// [FileStore.Save], and drops it. That is the invariant the managed-certificate
// mechanism exists to preserve.
//
// # Admin credentials
//
// SECURITY: a certificate carrying clientAuth for a certname listed in
// `puppet_server` is a CA admin credential. clientAuth alone is not -- being
// presentable as a client is not authority -- and the listing alone is not
// either. Both together are, and OpenVox Server needs both, so the store
// holding OpenVox Server's key is by design an admin credential and its
// namespace and file permissions deserve the same care as the CA's own.
//
// That is not new exposure: it is the same trust as OpenVox Server holding its
// certificate on disk today. It is stated here, and in docs/configuration.md,
// because an operator who is left to infer that a component store is ordinary
// will infer wrongly.
//
// This package is an issuance surface that imports internal/ca, so it joins the
// gate in internal/api/authseam_test.go: only an operator at a terminal may
// mint an admin credential, never a request, and nothing here may reach
// ca.AuthGrant, ca.PpCliAuth, ca.GenerateOptions or GenerateWithOptions.
// `pp_cli_auth` on a managed certificate was considered and rejected --
// `puppet_server` is the mechanism and needs no extension.
//
// NIST 800-53: AC-6 (Least Privilege), CM-7 (Least Functionality)
package certstore

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// CACertSource supplies the CA certificate chain a store writes alongside each
// certificate, so a component has the trust anchor for its own peers without a
// second distribution mechanism.
//
// Satisfied by *storage.StorageService, but kept as a one-method interface so
// this package does not depend on the storage layer and is trivial to fake.
type CACertSource interface {
	GetCACert(ctx context.Context) ([]byte, error)
}

// Deps are the things a store needs that configuration cannot supply.
type Deps struct {
	// CACerts reads the CA certificate chain. Required whenever any entry
	// writes one, which is every Secret store and every file store that
	// configures a `ca` path.
	CACerts CACertSource

	// Client is the Kubernetes clientset the Secret stores use. It may be nil
	// when no entry has a Secret store; [Config.NeedsKubernetes] reports
	// whether one is needed, so the caller does not have to build a client for
	// a file-only configuration.
	Client kubernetes.Interface

	// DefaultNamespace is the namespace Secret stores that do not set their own
	// are created in -- in practice the CA pod's own.
	// [Config.NeedsDefaultNamespace] reports whether any entry relies on it.
	DefaultNamespace string
}

// Config is the `managed_certs` block: the certificates this CA keeps alive on
// behalf of something else. The feature is entirely dormant when the list is
// empty -- no goroutine, no storage key, no Kubernetes client.
//
// A slice rather than a struct wrapping one, so the server's configuration can
// name it under `managed_certs` directly and this package does not hold a
// second spelling of that key.
type Config []Entry

// Entry is one managed certificate: what it must be, and where it lives.
//
// Every field that describes the certificate maps to one field of ca.CertSpec,
// and an unset field inherits the CA-wide default rather than resetting to a
// built-in. That inheritance is the mechanism's, not this package's: `ttl: 0`
// reaches internal/ca as a zero TTL, which resolves to `leaf_validity_days` and
// then to the built-in. Re-deriving it here would be a second copy of a rule
// that already has one.
type Entry struct {
	// Certname is the certificate's Common Name, the inventory slot it
	// occupies, and the subject a pending supersession is recorded against.
	// Required. It goes through ca.ValidateSubject unchanged, so the CA's
	// existing grammar applies and a bad name is refused at startup rather than
	// discovered at issuance.
	//
	// Each name occupies the ordinary inventory slot for that subject, so a
	// component certificate and an agent certificate cannot share a certname.
	Certname string `yaml:"certname"`

	// Names are the subjectAltName DNS entries. At least one is required, and
	// they are used verbatim: `promote_cn_to_san` does not add the certname
	// here, and `allow_subject_alt_names` does not gate them, because both
	// govern what a submitted request may ask for and there is no request. See
	// ca.CertSpec.DNSNames, which is where that contract lives.
	Names []string `yaml:"names"`

	// Usages are the extended key usages, as `serverAuth` and/or `clientAuth`.
	// Unset means both -- the pair every other issuance path uses.
	//
	// A component certificate needs clientAuth because it is a CA client, so
	// narrowing to serverAuth alone is for a certificate that only ever answers
	// handshakes. Narrowing takes effect at the next reconcile pass rather than
	// at natural expiry: the mechanism treats a usage mismatch as grounds to
	// reissue, which is what stops the setting being decorative.
	//
	// An explicitly empty list means the same as an absent one. A certificate
	// with no extended key usage at all is a different thing from one narrowed
	// to a single usage, and is not something this block can ask for.
	Usages []string `yaml:"usages"`

	// TTL is the certificate lifetime. Unset inherits `leaf_validity_days`,
	// then the built-in. Whatever it says, issuance caps the result at the CA
	// certificate's own remaining life.
	TTL Duration `yaml:"ttl"`

	// RenewBefore is how far ahead of expiry a replacement is issued.
	// Required, and must be positive: a window of zero renews the certificate
	// only once it has already expired, which is not a renewal loop.
	//
	// It is an upper bound rather than the window itself. The mechanism floors
	// the effective window at half the certificate's forward lifetime, so a
	// window wider than the certificate can honour cannot produce a reissue
	// loop as the CA certificate ages.
	RenewBefore Duration `yaml:"renew_before"`

	// RevokeAfter is how long the predecessor stays valid after a replacement
	// is issued. Unset inherits `superseded_cert_revoke_after_sec`.
	//
	// A pointer because zero is a value and not an absence: `revoke_after: 0`
	// means revoke the predecessor inside the reconcile pass, with no overlap
	// at all. An entry that wants that on a CA whose default grants 24 hours
	// has no other way to say so, and a key that could not tell `0` from
	// absent would silently lose it.
	//
	// The delay itself is never recorded anywhere. It is resolved to an
	// absolute revoke-at instant when the supersession is written, which is
	// what makes per-entry windows safe across replicas: a restart loses
	// nothing, and any replica's sweep retires any entry without knowing
	// managed certificates exist.
	RevokeAfter *Duration `yaml:"revoke_after"`

	// KeyAlgo and KeySize are the key generated for this certificate; unset
	// inherits `leaf_key_algo` / `leaf_key_size`, then the built-in.
	//
	// Per-entry because the things a managed certificate serves need not agree
	// with the fleet: a component whose clients are all modern can take an
	// ECDSA key where agent certificates stay on RSA for compatibility.
	KeyAlgo string `yaml:"key_algo"`
	KeySize int    `yaml:"key_size"`

	// Store is where the certificate and its key live. Exactly one of its two
	// members must be set.
	Store StoreConfig `yaml:"store"`
}

// StoreConfig names the store an entry uses. Exactly one member is set, which
// is what makes the choice configuration rather than inference: there is no
// arrangement of these fields that leaves the CA to guess.
type StoreConfig struct {
	// Secret keeps the material in a Kubernetes Secret.
	Secret *SecretConfig `yaml:"secret"`
	// Files keeps the material in a certificate and key file pair.
	Files *FilesConfig `yaml:"files"`
}

// SecretConfig configures a Kubernetes Secret store.
type SecretConfig struct {
	// Name is the Secret's metadata.name. Required.
	Name string `yaml:"name"`
	// Namespace is the Secret's namespace -- the component's own, which is
	// usually not the CA's. Empty resolves to the CA pod's own namespace.
	Namespace string `yaml:"namespace"`
	// Labels and Annotations are applied to the Secret's metadata. The
	// mandatory app.kubernetes.io/managed-by label is merged in and always
	// wins, so ownership cannot be masked by configuration.
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`

	// AdoptExisting allows the first write to take a Secret the CA has never
	// owned. Default false, and the default is the point: a conflict on a first
	// write means somebody else's material is in that Secret, and overwriting
	// it is not the CA's call.
	//
	// It does not govern drift. A Secret the CA has owned before is always
	// reconciled, even when an external edit has reassigned one of its fields
	// -- see [SecretStore] for how the two are told apart.
	//
	// This field is on the Secret store rather than on the entry because it can
	// only mean something here. A file carries no record of who wrote it, so
	// there is nothing for a file store to adopt; making that structural is
	// better than accepting the key and explaining that it does nothing.
	AdoptExisting bool `yaml:"adopt_existing"`
}

// FilesConfig configures a local file store.
type FilesConfig struct {
	// Cert and Key are the paths the certificate and private key are written
	// to. Both required, and both absolute.
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// CA is an optional path for the CA certificate chain. Unset writes no
	// chain at all, which is right for a component that already trusts this CA
	// by some other route.
	//
	// Optional here and mandatory in a Secret, which is the one asymmetry worth
	// knowing about: a Secret's keys have to move together because omitting a
	// previously-owned key removes it, and files have no such coupling.
	CA string `yaml:"ca"`
}

// Enabled reports whether any managed certificate is configured.
func (c Config) Enabled() bool { return len(c) > 0 }

// NeedsKubernetes reports whether any entry uses a Secret store, and so whether
// the caller has to build an in-cluster client at all. A file-only
// configuration runs outside Kubernetes and must not be asked for one.
func (c Config) NeedsKubernetes() bool {
	for i := range c {
		if c[i].Store.Secret != nil {
			return true
		}
	}
	return false
}

// NeedsDefaultNamespace reports whether any Secret store omits its namespace
// and so depends on the CA pod's own being resolvable.
func (c Config) NeedsDefaultNamespace() bool {
	for i := range c {
		if s := c[i].Store.Secret; s != nil && s.Namespace == "" {
			return true
		}
	}
	return false
}

// SecretTargets reports every (namespace, name) a Secret store writes to, with
// namespaces left empty where the entry relies on the pod's own. Used to check
// managed certificates against the kubernetes_export targets; see
// [Config.CheckExportOverlap].
func (c Config) SecretTargets() [][2]string {
	var out [][2]string
	for i := range c {
		if s := c[i].Store.Secret; s != nil {
			out = append(out, [2]string{s.Namespace, s.Name})
		}
	}
	return out
}

// usageByName maps the configured spelling of an extended key usage to its
// x509 value.
//
// Two entries, deliberately. This block issues certificates for OpenVox
// components, and serverAuth and clientAuth are what such a certificate is for;
// a wider set would be a general-purpose certificate service, which is the
// thing #243 says this is not. Matching is case-insensitive, and an
// unrecognised value names both accepted spellings rather than listing what it
// is not.
var usageByName = map[string]x509.ExtKeyUsage{
	"serverauth": x509.ExtKeyUsageServerAuth,
	"clientauth": x509.ExtKeyUsageClientAuth,
}

// canonicalUsage renders a usage the way configuration spells it, for errors.
var canonicalUsage = map[string]string{
	"serverauth": "serverAuth",
	"clientauth": "clientAuth",
}

// extKeyUsage resolves the entry's configured usages.
//
// An empty result is returned for an empty list as well as an absent one, and
// means "inherit": ca.CertSpec reads a nil ExtKeyUsage as the
// serverAuth+clientAuth pair. `usages: []` therefore cannot ask for a
// certificate with no extended key usage at all, which is a different object
// and not one this block offers.
func (e *Entry) extKeyUsage() ([]x509.ExtKeyUsage, error) {
	if len(e.Usages) == 0 {
		return nil, nil
	}
	out := make([]x509.ExtKeyUsage, 0, len(e.Usages))
	seen := make(map[x509.ExtKeyUsage]bool, len(e.Usages))
	for _, name := range e.Usages {
		usage, ok := usageByName[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return nil, fmt.Errorf("unknown usage %q (must be %q or %q)",
				name, "serverAuth", "clientAuth")
		}
		// De-duplicated here rather than passed through. crypto/x509
		// de-duplicates extended key usages neither on write nor on parse, so
		// `usages: [clientAuth, clientAuth]` would produce a certificate
		// carrying it twice. The mechanism compacts both sides before
		// comparing, so that certificate would still satisfy its spec -- but
		// nothing downstream should have to rely on that, and a certificate
		// with a repeated usage is not what the operator asked for.
		if seen[usage] {
			continue
		}
		seen[usage] = true
		out = append(out, usage)
	}
	return out, nil
}

// spec builds the ca.CertSpec for this entry.
//
// Unset fields are left at their zero value rather than filled in from the CA's
// settings: internal/ca resolves TTL from LeafValidityDays, KeyConfig from
// LeafKeyConfig and a nil SupersedeAfter from the CA's own, and doing it twice
// is how the two come to disagree.
func (e *Entry) spec() (ca.CertSpec, error) {
	usages, err := e.extKeyUsage()
	if err != nil {
		return ca.CertSpec{}, err
	}
	var supersede *time.Duration
	if e.RevokeAfter != nil {
		d := e.RevokeAfter.AsDuration()
		supersede = &d
	}
	return ca.CertSpec{
		Subject:     e.Certname,
		DNSNames:    e.Names,
		ExtKeyUsage: usages,
		TTL:         e.TTL.AsDuration(),
		RenewBefore: e.RenewBefore.AsDuration(),
		KeyConfig: ca.KeyConfig{
			Algo: ca.KeyAlgo(strings.ToLower(strings.TrimSpace(e.KeyAlgo))),
			Size: e.KeySize,
		},
		SupersedeAfter: supersede,
	}, nil
}

// Validate checks every entry and returns an error describing the first problem,
// naming the entry by index and certname so an operator can find it in a list.
//
// Called once at startup, before anything touches storage. A mistyped certname,
// an impossible renewal window or a store that names neither flavour is refused
// as configuration rather than discovered as a certificate that never appears.
func (c Config) Validate() error {
	subjects := make(map[string]int, len(c))
	secrets := make(map[[2]string]int, len(c))
	paths := make(map[string]int, len(c)*2)

	for i := range c {
		e := &c[i]
		where := fmt.Sprintf("managed_certs[%d]", i)
		if e.Certname != "" {
			where = fmt.Sprintf("managed_certs[%d] (%s)", i, e.Certname)
		}

		spec, err := e.spec()
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		// The mechanism's own validation, reused rather than restated: it
		// owns what a certificate may be, and a second copy here would be one
		// more thing to keep in step with it.
		if err := spec.Validate(); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}

		// Two entries for one certname would take turns superseding each
		// other's certificate for ever: they serialise on the same subject
		// lock, so neither races, and each pass finds the other's certificate
		// failing its own spec. There is exactly one inventory slot per
		// subject, and this is where that becomes visible.
		if prev, dup := subjects[e.Certname]; dup {
			return fmt.Errorf("%s: certname %q is already used by managed_certs[%d]; "+
				"each managed certificate needs a certname of its own, because they share "+
				"one inventory slot and would replace each other on every pass",
				where, e.Certname, prev)
		}
		subjects[e.Certname] = i

		if err := e.Store.validate(where, secrets, paths, i); err != nil {
			return err
		}
	}
	return nil
}

// validate checks an entry's store block, recording what it claims so a later
// entry cannot claim the same object.
func (s *StoreConfig) validate(where string, secrets map[[2]string]int, paths map[string]int, idx int) error {
	switch {
	case s.Secret == nil && s.Files == nil:
		return fmt.Errorf("%s: store must name where the certificate lives: "+
			"either `store: {secret: {name: ...}}` for a Kubernetes Secret or "+
			"`store: {files: {cert: ..., key: ...}}` for a local file pair. "+
			"This is configuration and is never inferred from the environment",
			where)
	case s.Secret != nil && s.Files != nil:
		return fmt.Errorf("%s: store names both `secret` and `files`; "+
			"a certificate lives in exactly one place", where)
	case s.Secret != nil:
		return s.Secret.validate(where, secrets, idx)
	default:
		return s.Files.validate(where, paths, idx)
	}
}

func (s *SecretConfig) validate(where string, secrets map[[2]string]int, idx int) error {
	s.Name = strings.TrimSpace(s.Name)
	s.Namespace = strings.TrimSpace(s.Namespace)
	if s.Name == "" {
		return fmt.Errorf("%s: store.secret.name is required", where)
	}
	// Namespaces are compared as configured rather than as resolved: an entry
	// that omits the namespace and one that spells out the pod's own are the
	// same Secret, but the pod's namespace is not known at validation time.
	// This catches the case that is checkable and leaves the other to the
	// conflict semantics, which refuse rather than corrupt.
	key := [2]string{s.Namespace, s.Name}
	if prev, dup := secrets[key]; dup {
		return fmt.Errorf("%s: Secret %s/%s is already the store for managed_certs[%d]; "+
			"two certificates in one Secret would each remove the other's keys, because "+
			"omitting a previously-owned key deletes it",
			where, nsOrPod(s.Namespace), s.Name, prev)
	}
	secrets[key] = idx
	return nil
}

func (f *FilesConfig) validate(where string, paths map[string]int, idx int) error {
	f.Cert = strings.TrimSpace(f.Cert)
	f.Key = strings.TrimSpace(f.Key)
	f.CA = strings.TrimSpace(f.CA)
	if f.Cert == "" || f.Key == "" {
		return fmt.Errorf("%s: store.files needs both `cert` and `key`", where)
	}
	for _, p := range []struct{ field, path string }{
		{"cert", f.Cert}, {"key", f.Key}, {"ca", f.CA},
	} {
		if p.path == "" {
			continue
		}
		// Absolute, because the server's working directory is not something an
		// operator configures and a relative path would resolve differently
		// under systemd, in a container, and when run by hand.
		if !strings.HasPrefix(p.path, "/") {
			return fmt.Errorf("%s: store.files.%s must be an absolute path (got %q)",
				where, p.field, p.path)
		}
		if prev, dup := paths[p.path]; dup {
			return fmt.Errorf("%s: store.files.%s %q is already used by managed_certs[%d]",
				where, p.field, p.path, prev)
		}
		paths[p.path] = idx
	}
	if f.Cert == f.Key || (f.CA != "" && (f.CA == f.Cert || f.CA == f.Key)) {
		return fmt.Errorf("%s: store.files paths must differ from one another", where)
	}
	return nil
}

// nsOrPod renders a namespace for a message, saying what an empty one means
// rather than printing nothing.
func nsOrPod(ns string) string {
	if ns == "" {
		return "<the CA pod's namespace>"
	}
	return ns
}

// CheckExportOverlap refuses a configuration in which a managed certificate's
// Secret is also a kubernetes_export target.
//
// Both write `ca.crt`, under different field managers, and the exporter applies
// with force unconditionally. So each would take that key from the other and
// rewrite the object on every cycle: the exporter on every CRL update, the
// reconcile loop on every pass. Nothing breaks visibly -- the value is the same
// CA certificate either way -- but the object churns for ever and its
// managedFields flap, which is the kind of fault that is found months later.
//
// Refused here, at startup, because both lists are in the same file and the
// overlap is a typo rather than a decision. Namespaces are compared as
// configured; an entry that omits one and an export target that spells out the
// same namespace are not caught, which is the same limit the duplicate check
// has and for the same reason.
func (c Config) CheckExportOverlap(exportTargets [][2]string) error {
	if len(exportTargets) == 0 || !c.Enabled() {
		return nil
	}
	targets := make(map[[2]string]bool, len(exportTargets))
	for _, t := range exportTargets {
		targets[t] = true
	}
	for i := range c {
		s := c[i].Store.Secret
		if s == nil || !targets[[2]string{s.Namespace, s.Name}] {
			continue
		}
		return fmt.Errorf("managed_certs[%d] (%s) stores its certificate in Secret %s/%s, "+
			"which is also a kubernetes_export target: both write ca.crt, so they would "+
			"take the key from each other on every pass. Give the managed certificate a "+
			"Secret of its own, or drop the export target -- a managed certificate's "+
			"Secret already carries the CA chain",
			i, c[i].Certname, nsOrPod(s.Namespace), s.Name)
	}
	return nil
}

// Build turns a validated configuration into the entries internal/ca's
// reconcile loop walks. Call [Config.Validate] first.
//
// Each entry becomes a ca.ManagedCert whose Load and Save are the methods of
// one concrete store. They are two function fields rather than an interface
// value because the mechanism takes them that way, and it takes them that way
// deliberately: the stores it must serve differ in failure semantics and not
// merely in mechanism. A component store's absence is routine and self-heals on
// the next pass; the CA's own serving store must be readable before the
// listener binds and its absence is fatal. That difference belongs to the
// caller rather than to a shared contract, which is why this package exports
// [SecretStore] and [FileStore] as concrete types and keeps no interface
// spanning them.
func (c Config) Build(deps Deps) ([]ca.ManagedCert, error) {
	if !c.Enabled() {
		return nil, nil
	}
	if deps.CACerts == nil {
		return nil, fmt.Errorf("managed certificates need a source for the CA certificate chain")
	}
	if c.NeedsKubernetes() && deps.Client == nil {
		return nil, fmt.Errorf("a managed certificate uses a Kubernetes Secret store, " +
			"but no Kubernetes client is available (openvox-ca must run inside a pod for that store)")
	}

	out := make([]ca.ManagedCert, 0, len(c))
	for i := range c {
		e := &c[i]
		spec, err := e.spec()
		if err != nil {
			return nil, fmt.Errorf("managed_certs[%d] (%s): %w", i, e.Certname, err)
		}

		var loader interface {
			Load(context.Context) ([]byte, []byte, error)
			Save(context.Context, []byte, []byte) error
		}
		switch {
		case e.Store.Secret != nil:
			ns := e.Store.Secret.Namespace
			if ns == "" {
				ns = deps.DefaultNamespace
			}
			if ns == "" {
				return nil, fmt.Errorf("managed_certs[%d] (%s): no namespace for Secret %q, "+
					"and the CA pod's own could not be resolved",
					i, e.Certname, e.Store.Secret.Name)
			}
			loader = NewSecretStore(deps.Client, *e.Store.Secret, ns, deps.CACerts)
		default:
			loader = NewFileStore(*e.Store.Files, deps.CACerts)
		}

		out = append(out, ca.ManagedCert{
			Spec: spec,
			Load: loader.Load,
			Save: loader.Save,
		})
	}
	return out, nil
}
