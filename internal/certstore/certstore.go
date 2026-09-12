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
	"net"
	"net/url"
	"path/filepath"
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
// a store depends on the chain rather than on the CA's whole backing store, and
// so it is trivial to fake. Note this package does still import
// internal/storage, for AtomicWriteFile: one implementation of an atomic write
// rather than two is the right call, and the narrow interface here is about the
// CA's material, not about the package graph.
type CACertSource interface {
	GetCACert(ctx context.Context) ([]byte, error)
}

// Deps are the things a store needs that configuration cannot supply.
type Deps struct {
	// CACerts reads the CA certificate chain. Required whenever any managed
	// certificate is configured -- [Config.Build] refuses a nil value even for
	// a file-only configuration that writes no chain, because a caller that had
	// to predict which entries would need one would be re-deriving what the
	// entries already say.
	//
	// That is deliberately unlike Client below, which is genuinely optional and
	// has a predicate to say so.
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

	// Names are the subjectAltName DNS entries, and IPAddresses,
	// EmailAddresses and URIs are the other three types. At least one name of
	// some kind is required across all four.
	//
	// They are used verbatim: `promote_cn_to_san` does not add the certname
	// here, and `allow_subject_alt_names` does not gate them, because both
	// govern what a submitted request may ask for and there is no request. See
	// ca.CertSpec.DNSNames, which is where that contract lives.
	//
	// `names` rather than `dns_names` for the DNS list, which is the one
	// asymmetry in the four: DNS is what almost every entry uses, and it is the
	// spelling #243 wrote. The other three are named for what they carry
	// because there is nothing to infer them from -- a list of strings that
	// might be a hostname, an address or an email address would be exactly the
	// kind of guessing the store block refuses to do.
	Names          []string `yaml:"names"`
	IPAddresses    []string `yaml:"ip_addresses"`
	EmailAddresses []string `yaml:"email_addresses"`
	URIs           []string `yaml:"uris"`

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
	// It is an upper bound rather than the window itself. The mechanism caps
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

	// ReuseKey reissues against the private key already in this entry's store
	// rather than generating a fresh one. Default false, and the default is the
	// better hygiene: a key replaced on every renewal is one a disclosure stops
	// mattering about, and re-keying also makes a Secret's apply naturally
	// atomic.
	//
	// True is for the cases where the key is the identity rather than an
	// implementation detail -- a TLSA record with a key-based selector, or an
	// SPKI pin, names the key, and re-keying breaks it.
	//
	// Four things it does not mean, each of which the obvious reading gets
	// wrong:
	//
	//   - A revoked certificate is replaced with a new key whatever this says,
	//     and the CA warns. Reissuing over the same key would hand back, on a
	//     fresh serial with a full lifetime and on no CRL, exactly the material
	//     an operator revoking for key disclosure was retiring.
	//   - A stored key below the CA's key-strength policy is refused, not
	//     silently replaced. The entry fails every pass until the operator
	//     fixes it, because re-keying quietly would defeat the pin entirely.
	//   - `key_algo` and `key_size` describe what to *generate*. A reused key
	//     keeps whatever it already has, so changing them under `reuse_key`
	//     takes effect only when there is no key to reuse.
	//   - It is not a guarantee the key survives. A store whose key has gone
	//     missing gets a fresh one, loudly -- a pin really is being broken. A
	//     first issuance generates quietly, because there was never a pin.
	ReuseKey bool `yaml:"reuse_key"`

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
	ips, err := e.ipAddresses()
	if err != nil {
		return ca.CertSpec{}, err
	}
	uris, err := e.uris()
	if err != nil {
		return ca.CertSpec{}, err
	}
	emails, err := e.emails()
	if err != nil {
		return ca.CertSpec{}, err
	}
	return ca.CertSpec{
		Subject:        e.Certname,
		DNSNames:       e.Names,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           uris,
		ExtKeyUsage:    usages,
		TTL:            e.TTL.AsDuration(),
		RenewBefore:    e.RenewBefore.AsDuration(),
		KeyConfig: ca.KeyConfig{
			Algo: ca.KeyAlgo(strings.ToLower(strings.TrimSpace(e.KeyAlgo))),
			Size: e.KeySize,
		},
		ReuseKey:       e.ReuseKey,
		SupersedeAfter: supersede,
	}, nil
}

// ipAddresses parses the entry's IP alternative names.
//
// Refused here rather than passed on, because net.ParseIP returns nil for
// anything it cannot read and a nil net.IP marshals into an empty SAN entry
// instead of failing -- so a typo would reach the certificate as a name
// matching nothing, on a certificate that otherwise looks well-formed. The
// mechanism refuses an empty entry too; this is the arm that can say which
// string was wrong.
func (e *Entry) ipAddresses() ([]net.IP, error) {
	if len(e.IPAddresses) == 0 {
		return nil, nil
	}
	out := make([]net.IP, 0, len(e.IPAddresses))
	for _, raw := range e.IPAddresses {
		text := strings.TrimSpace(raw)
		ip := net.ParseIP(text)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an IP address", raw)
		}
		out = append(out, ip)
	}
	return out, nil
}

// uris parses the entry's URI alternative names.
//
// Absolute only. url.Parse accepts almost anything, including a bare word,
// which becomes a relative reference -- and a uniformResourceIdentifier SAN
// that is not absolute names nothing a verifier can compare against. An
// operator who meant a DNS name and wrote it here should be told, not given a
// certificate carrying it as a URI.
// emails trims each rfc822Name and refuses one that is not an address.
//
// The other three name types each get a startup refusal -- an IP that does not
// parse, a URI with no scheme, a DNS name the CA's own grammar rejects -- and
// this one was passed through verbatim, so a stray space or a bare word reached
// the certificate and an operator found out from whatever failed to verify it.
//
// Deliberately shallow: an address is required to have a local part and a
// domain and no spaces, and nothing further. Full RFC 5322 validation refuses
// addresses that work and accepts ones nobody wants, and a certificate's
// rfc822Name is matched byte for byte by whatever consumes it -- so the useful
// check is that the operator has written an address at all, not that a parser
// approves of its shape.
func (e *Entry) emails() ([]string, error) {
	if len(e.EmailAddresses) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(e.EmailAddresses))
	for _, raw := range e.EmailAddresses {
		text := strings.TrimSpace(raw)
		at := strings.LastIndexByte(text, '@')
		if text == "" || at <= 0 || at == len(text)-1 || strings.ContainsAny(text, " \t") {
			return nil, fmt.Errorf("%q is not an email address; an rfc822Name "+
				"alternative name is local@domain", raw)
		}
		out = append(out, text)
	}
	return out, nil
}

func (e *Entry) uris() ([]*url.URL, error) {
	if len(e.URIs) == 0 {
		return nil, nil
	}
	out := make([]*url.URL, 0, len(e.URIs))
	for _, raw := range e.URIs {
		text := strings.TrimSpace(raw)
		u, err := url.Parse(text)
		if err != nil {
			return nil, fmt.Errorf("%q is not a URI: %w", raw, err)
		}
		if !u.IsAbs() {
			return nil, fmt.Errorf("URI %q has no scheme; a uniformResourceIdentifier "+
				"alternative name must be absolute (did you mean to put it under `names`?)", raw)
		}
		out = append(out, u)
	}
	return out, nil
}

// Validate checks every entry and returns an error describing the first problem,
// naming the entry by index and certname so an operator can find it in a list.
//
// Called once at startup, before anything touches storage. A mistyped certname,
// an impossible renewal window or a store that names neither flavour is refused
// as configuration rather than discovered as a certificate that never appears.
func (c Config) Validate() error {
	subjects := make(map[string]int, len(c))
	var secrets []secretRef
	paths := newFilePaths()

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

		if err := e.Store.validate(where, &secrets, paths, i); err != nil {
			return err
		}
	}
	return nil
}

// validate checks an entry's store block, recording what it claims so a later
// entry cannot claim the same object.
func (s *StoreConfig) validate(where string, secrets *[]secretRef, paths filePaths, idx int) error {
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

func (s *SecretConfig) validate(where string, secrets *[]secretRef, idx int) error {
	s.Name = strings.TrimSpace(s.Name)
	s.Namespace = strings.TrimSpace(s.Namespace)
	if s.Name == "" {
		return fmt.Errorf("%s: store.secret.name is required", where)
	}
	// Compared the way CheckExportOverlap compares: on the name first, and then
	// on whether the two namespaces can name the same one. An omission on
	// either side resolves to the CA pod's own namespace, which is not known
	// here, so the pair is refused.
	//
	// There is no weaker fallback to lean on. Every managed certificate applies
	// under one shared field manager, so two entries pointed at one Secret each
	// read the other's apply entry as their own: ownedByUs answers true, force
	// is set, and no conflict is ever raised. They would overwrite each other's
	// certificate and key on every pass, for ever, exactly as this message
	// says -- and for a certname in puppet_server, that is a CA admin
	// credential being reissued and its predecessor revoked each time.
	//
	// Scanned in index order rather than over the map. More than one earlier
	// entry can collide with this one -- two spelled-out namespaces do not
	// collide with each other, but a third entry omitting its namespace
	// collides with both -- and a map range would name whichever the runtime
	// reached first, so the same file would blame a different entry on each
	// restart.
	for _, prev := range *secrets {
		if prev.name != s.Name || !namespacesMayCollide(prev.namespace, s.Namespace) {
			continue
		}
		msg := "%s: Secret %s/%s is already the store for managed_certs[%d]; " +
			"two certificates in one Secret would each remove the other's keys, because " +
			"omitting a previously-owned key deletes it"
		if prev.namespace == "" || s.Namespace == "" {
			// Only where a namespace was actually omitted. Saying this about
			// two entries that both spell one out describes a mistake the
			// operator did not make, and offers a remedy they have already
			// applied.
			msg += ". An omitted namespace resolves to the CA pod's own, so it is treated " +
				"as possibly naming the same Secret; spell both namespaces out if they " +
				"genuinely differ"
		}
		return fmt.Errorf(msg, where, nsOrPod(s.Namespace), s.Name, prev.idx)
	}
	*secrets = append(*secrets, secretRef{namespace: s.Namespace, name: s.Name, idx: idx})
	return nil
}

// secretRef is one Secret a managed certificate claims, kept in configuration
// order so a refusal always names the earliest entry it collides with.
type secretRef struct {
	namespace string
	name      string
	idx       int
}

func (f *FilesConfig) validate(where string, paths filePaths, idx int) error {
	// Cleaned, not merely trimmed, and cleaned in place so the writes use the
	// same spelling the duplicate check did. Two spellings of one path --
	// `/a/b/c.pem` and `/a//b/c.pem`, or one routed through `..` -- are two keys
	// in the map below and would both validate, which is the reissue loop that
	// check exists to prevent: each entry's Load reads the other's certificate,
	// finds it failing its own spec, and replaces it, every pass, for ever.
	//
	// filepath.Clean is lexical, so a symlinked directory still reaches this as
	// two distinct paths. Resolving those would mean touching the filesystem at
	// startup for paths that need not exist yet, which is a worse trade than the
	// remaining gap.
	f.Cert = cleanPath(f.Cert)
	f.Key = cleanPath(f.Key)
	f.CA = cleanPath(f.CA)
	if f.Cert == "" || f.Key == "" {
		return fmt.Errorf("%s: store.files needs both `cert` and `key`", where)
	}
	// Within the entry first, and before anything is registered below. Written
	// the other way round -- which it was -- this check is unreachable: `cert`
	// goes into the shared map, `key` then matches it, and an operator who
	// pointed both at one path was told their entry collides with itself.
	if f.Cert == f.Key || (f.CA != "" && (f.CA == f.Cert || f.CA == f.Key)) {
		return fmt.Errorf("%s: store.files paths must differ from one another", where)
	}
	// Absolute, because the server's working directory is not something an
	// operator configures and a relative path would resolve differently under
	// systemd, in a container, and when run by hand.
	for _, p := range []struct{ field, path string }{
		{"cert", f.Cert}, {"key", f.Key}, {"ca", f.CA},
	} {
		if p.path != "" && !strings.HasPrefix(p.path, "/") {
			return fmt.Errorf("%s: store.files.%s must be an absolute path (got %q)",
				where, p.field, p.path)
		}
	}
	// Across entries, where the two fields are governed by different rules.
	//
	// `cert` and `key` are exclusive: two entries writing one certificate or
	// key file each read the other's material, find it failing their own spec,
	// and reissue -- for ever, on every pass.
	//
	// `ca` is shared on purpose. Every entry writes the same CA chain, byte for
	// byte, from the same source, and no entry reads the chain file back to
	// decide whether to reissue, so the loop cannot start there. A shared
	// /etc/openvox/ca.pem is the ordinary way to lay several components out on
	// one host, and refusing it bought nothing.
	//
	// What is still refused is the cross pair, in both directions: a chain
	// written over another entry's certificate or key, or a certificate or key
	// written over another entry's chain. Both are the loop, with the chain
	// write standing in for one side of it.
	for _, p := range []struct{ field, path string }{{"cert", f.Cert}, {"key", f.Key}} {
		if prev, dup := paths.material[p.path]; dup {
			return fmt.Errorf("%s: store.files.%s %q is already used by managed_certs[%d]: "+
				"two entries writing one certificate or key file would each replace the "+
				"other's material on every pass", where, p.field, p.path, prev)
		}
		if prev, dup := paths.chain[p.path]; dup {
			return fmt.Errorf("%s: store.files.%s %q is the CA chain file of "+
				"managed_certs[%d], which is rewritten on every pass of that entry",
				where, p.field, p.path, prev)
		}
		paths.material[p.path] = idx
	}
	if f.CA != "" {
		if prev, dup := paths.material[f.CA]; dup && prev != idx {
			return fmt.Errorf("%s: store.files.ca %q is the certificate or key of "+
				"managed_certs[%d]: the chain written there would replace that entry's "+
				"material on every pass", where, f.CA, prev)
		}
		if _, seen := paths.chain[f.CA]; !seen {
			paths.chain[f.CA] = idx
		}
	}
	return nil
}

// filePaths is what a file store's paths are checked against: every `cert` and
// `key` claimed so far, which no second entry may claim, and every `ca` chain
// file, which any number of entries may share but which must not be some other
// entry's material.
type filePaths struct {
	material map[string]int
	chain    map[string]int
}

func newFilePaths() filePaths {
	return filePaths{material: map[string]int{}, chain: map[string]int{}}
}

// cleanPath trims and lexically normalises a configured path, leaving an empty
// one empty so the required-field checks still see it as absent.
func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	return filepath.Clean(p)
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
// overlap is a typo rather than a decision.
//
// The comparison is on the Secret's name first, and then on whether the two
// namespaces can name the same one -- see namespacesMayCollide, which treats an
// omission on either side as possibly matching, because both features resolve an
// omitted namespace to the CA pod's own.
func (c Config) CheckExportOverlap(exportTargets [][2]string) error {
	if len(exportTargets) == 0 || !c.Enabled() {
		return nil
	}
	for i := range c {
		s := c[i].Store.Secret
		if s == nil {
			continue
		}
		for _, t := range exportTargets {
			if t[1] != s.Name || !namespacesMayCollide(t[0], s.Namespace) {
				continue
			}
			remedy := "Give the managed certificate a Secret of its own, or drop the " +
				"export target -- a managed certificate's Secret already carries the CA chain"
			if s.Namespace == "" || t[0] == "" {
				// The conservative arm. The two namespaces may render as
				// visibly different, so say why they are being treated as one
				// and give the cheap remedy before the structural ones.
				remedy = "One of them omits its namespace, which resolves to the CA pod's own " +
					"-- not known before the Kubernetes client exists -- so the pair is " +
					"refused rather than risked. Spell both namespaces out if they genuinely " +
					"differ; otherwise " + "give the managed certificate a Secret of its own, " +
					"or drop the export target"
			}
			return fmt.Errorf("managed_certs[%d] (%s) stores its certificate in Secret %s/%s, "+
				"which is also a kubernetes_export target in %s: both write ca.crt, so they "+
				"would take the key from each other on every pass. %s",
				i, c[i].Certname, nsOrPod(s.Namespace), s.Name, nsOrPod(t[0]), remedy)
		}
	}
	return nil
}

// ReservedPath is one filesystem location the CA itself owns, for
// CheckReservedPaths. Tree marks a directory whose whole subtree is reserved
// rather than a single file. Setting names the configuration key it came from,
// so a refusal can say which one.
//
// Path must already be absolute. The caller resolves it, because what a
// relative path resolves against is the CA process's own working directory --
// which this package has no business consulting.
type ReservedPath struct {
	Setting string
	Path    string
	Tree    bool
}

// CheckReservedPaths refuses a configuration in which a managed certificate's
// file store writes over something the CA itself owns.
//
// A file store overwrites its cert, key and ca files on every issuance. Pointed
// at the CA's own directory that destroys the CA key, its certificate, the CRL
// and the backend's state -- irrecoverably, since the private key that signed
// every outstanding certificate is not reconstructible. Pointed at the serving
// pair it replaces the certificate the CA presents with one issued for a
// component. Neither is a configuration anyone means, and both are one plausible
// typo away for an operator laying out paths alongside the CA's own.
//
// SECURITY: this is a typo backstop over the CA's own state, and deliberately
// not a sandbox. The store writes as the CA's user and can reach anything that
// user can; nothing here confines it. The list is what the caller passes, which
// is the paths in the server's own configuration block -- it does not enumerate
// the credential files of the storage backends or the CA key providers (an
// OpenBao token file, a backend's client TLS key), which are numerous and grow
// with every backend. Directory permissions, not this check, are what keep a
// managed certificate out of somewhere it should not be.
//
// NIST 800-53: CM-6 (Configuration Settings), SC-28 (Protection of Information
// at Rest)
func (c Config) CheckReservedPaths(reserved []ReservedPath) error {
	if len(reserved) == 0 || !c.Enabled() {
		return nil
	}
	for i := range c {
		f := c[i].Store.Files
		if f == nil {
			continue
		}
		// Cleaned again rather than trusting Validate to have run first. This
		// is exported and the two are independent calls, so a caller that
		// reached here without validating still gets a comparison on the same
		// spelling the writes will use.
		for _, p := range []struct{ field, path string }{
			{"cert", cleanPath(f.Cert)}, {"key", cleanPath(f.Key)}, {"ca", cleanPath(f.CA)},
		} {
			if p.path == "" {
				continue
			}
			for _, r := range reserved {
				root := cleanPath(r.Path)
				if root == "" {
					continue
				}
				if !filepath.IsAbs(root) {
					// Loudly rather than silently. A relative reserved path can
					// never equal an absolute store path, so skipping it would
					// leave a gap that looks exactly like a passing check.
					return fmt.Errorf("cannot compare managed_certs file stores against %s %q: "+
						"it is not an absolute path", r.Setting, r.Path)
				}
				if !reservedCovers(root, r.Tree, p.path) {
					continue
				}
				scope := "is"
				if r.Tree {
					scope = "is inside"
				}
				return fmt.Errorf("managed_certs[%d] (%s) stores its %s at %q, which %s %s (%s): "+
					"a managed certificate's file store is overwritten on every issuance, and "+
					"these are the CA's own files. Give the certificate a path of its own",
					i, c[i].Certname, p.field, p.path, scope, r.Setting, root)
			}
		}
	}
	return nil
}

// reservedCovers reports whether a reserved path covers a store path: equality
// for a file, and containment for a tree.
//
// The separator is appended before the prefix test so that a cadir of
// /var/lib/openvox-ca does not reserve /var/lib/openvox-ca-components, which
// shares its prefix and is a different directory. A root of "/" needs no such
// suffix, and appending one would give "//", which prefixes nothing cleaned.
func reservedCovers(root string, tree bool, path string) bool {
	if path == root {
		return true
	}
	if !tree {
		return false
	}
	if root == string(filepath.Separator) {
		return strings.HasPrefix(path, root)
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

// namespacesMayCollide reports whether two configured namespaces can name the
// same one at runtime, for a Secret whose name already matches on both sides.
//
// Both features resolve an omitted namespace to the CA pod's own, which is not
// known here -- this runs before any Kubernetes client exists, deliberately, so
// that a configuration error is refused without needing a cluster to refuse it.
// So an omission on either side is treated as possibly-the-other, and the pair
// is refused.
//
// That over-refuses in one case: an entry omitting its namespace, an export
// target naming a different one, and a pod in a third. The alternative is to
// resolve the pod's namespace first, which would move this check after client
// construction and make it unreachable on any host without a ServiceAccount
// mount -- including every test. Refusing is also the safe direction: the cost
// is spelling out a namespace, and the cost of a miss is two managers rewriting
// one Secret on every pass, for ever, with nothing looking broken.
func namespacesMayCollide(a, b string) bool {
	return a == b || a == "" || b == ""
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
