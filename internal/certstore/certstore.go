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
// [FileStore] for the two others: a write is not atomic across the pair, and
// the CA chain is optional in a file store where a Secret must carry it.
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
	"fmt"

	"k8s.io/client-go/kubernetes"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/certstore/certconfig"
)

// The configuration types live in certconfig, which does not import client-go,
// so that a binary decoding the server's configuration need not link it. They
// are aliased here so this package's callers name them as they always have.
type (
	Config       = certconfig.Config
	Entry        = certconfig.Entry
	StoreConfig  = certconfig.StoreConfig
	SecretConfig = certconfig.SecretConfig
	FilesConfig  = certconfig.FilesConfig
	Block        = certconfig.Block
	ReservedPath = certconfig.ReservedPath
	Duration     = certconfig.Duration
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
	// certificate is configured -- [Build] refuses a nil value even for
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
func Build(c Config, deps Deps) ([]ca.ManagedCert, error) {
	// The zero Block is managed_certs; see certconfig.Block.
	return BuildIn(c, Block{}, deps)
}

// BuildIn is Build for entries from another configuration block.
func BuildIn(c Config, block Block, deps Deps) ([]ca.ManagedCert, error) {
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
		spec, err := e.Spec()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", block.WithCertname(i, e.Certname), err)
		}

		// The two methods, taken individually rather than through a value that
		// has both. An `interface { Load(...); Save(...) }` local would be the
		// spanning contract this package's doc comment says it does not keep --
		// the paragraph above explains why the entries carry two function
		// fields instead -- and declaring one here quietly reintroduced it for
		// the length of this loop, which is how a stated design stops matching
		// the code that is supposed to embody it.
		var (
			load func(context.Context) ([]byte, []byte, error)
			save func(context.Context, []byte, []byte) error
		)
		switch {
		case e.Store.Secret != nil:
			ns := e.Store.Secret.Namespace
			if ns == "" {
				ns = deps.DefaultNamespace
			}
			if ns == "" {
				return nil, fmt.Errorf("%s: no namespace for Secret %q, "+
					"and the CA pod's own could not be resolved",
					block.WithCertname(i, e.Certname), e.Store.Secret.Name)
			}
			store := NewSecretStore(deps.Client, *e.Store.Secret, ns, deps.CACerts)
			load, save = store.Load, store.Save
		case e.Store.Files != nil:
			store := NewFileStore(*e.Store.Files, deps.CACerts)
			load, save = store.Load, store.Save
		default:
			// Unreachable through Validate, which refuses a store naming
			// neither flavour, and this function's doc comment says to call it
			// first. But the previous shape made `files` the default rather
			// than a case, so a caller that skipped validation dereferenced a
			// nil *FilesConfig here -- a panic whose stack names this
			// package and not the entry that caused it. A second consumer
			// calling BuildIn is exactly how a documented precondition gets
			// missed, so the cost of missing it is a message that names the
			// entry.
			return nil, fmt.Errorf("%s: store names neither `secret` nor `files`; "+
				"Validate must be called before Build",
				block.WithCertname(i, e.Certname))
		}

		out = append(out, ca.ManagedCert{
			Spec: spec,
			Load: load,
			Save: save,
		})
	}
	return out, nil
}
