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

// Package k8sexport publishes the CA certificate and/or CRL into Kubernetes
// Secrets and ConfigMaps. It is an optional feature: when no targets are
// configured nothing in this package runs. Objects are reconciled with
// server-side apply so each export is an idempotent create-or-update.
//
// The exporter authenticates with the pod's in-cluster ServiceAccount, so it is
// only available when openvox-ca itself runs inside a Kubernetes cluster.
package k8sexport

import (
	"fmt"
	"strings"
)

// Kind enumerates the Kubernetes object kinds an export target may be. The
// canonical spellings match Kubernetes; configuration accepts any case and is
// normalised to these values.
const (
	KindSecret    = "Secret"
	KindConfigMap = "ConfigMap"
)

const (
	// defaultFieldManager is the server-side apply field manager used when the
	// operator does not set one. It scopes ownership of the fields this exporter
	// writes so other managers (e.g. kubectl) can co-own unrelated fields.
	defaultFieldManager = "openvox-ca"
	// defaultCertKey / defaultCRLKey are the data keys used when a target does
	// not override them. They follow common Kubernetes trust-bundle conventions.
	defaultCertKey = "ca.crt"
	defaultCRLKey  = "ca.crl"
)

// Export scopes select how much of a chain a target publishes.
const (
	// ScopeSelf publishes only this CA's own certificate or CRL — block 0 of
	// the stored bundle. Opted into per target; identical to ScopeChain on a CA
	// that issues its own root.
	ScopeSelf = "self"
	// ScopeChain publishes the stored bundle or CRL chain verbatim.
	ScopeChain = "chain"
	// ScopeRoot publishes the last certificate in the bundle: the trust anchor
	// rather than the issuing CA. Certificates only — a CRL chain has no
	// equivalent, since the root's CRL is simply one of its members.
	ScopeRoot = "root"
)

// Config is the top-level kubernetes_export configuration block. The feature is
// considered enabled when Targets is non-empty.
type Config struct {
	// FieldManager is the server-side apply field manager name. Empty selects
	// defaultFieldManager.
	FieldManager string `yaml:"field_manager"`
	// Targets is the set of Secrets/ConfigMaps to maintain.
	Targets []Target `yaml:"targets"`
}

// Metadata mirrors the shape of a Kubernetes object's metadata block, so a
// target reads like the manifest it produces.
type Metadata struct {
	// Name is the object's metadata.name (required).
	Name string `yaml:"name"`
	// Namespace is the object's namespace. Empty resolves at runtime to the
	// pod's own ServiceAccount namespace.
	Namespace string `yaml:"namespace"`
	// Labels and Annotations are applied to the object's metadata.
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

// Target describes a single Secret or ConfigMap to maintain.
type Target struct {
	// Kind is "Secret" or "ConfigMap" (case-insensitive; normalised by
	// Validate to the canonical Kubernetes spelling).
	Kind string `yaml:"kind"`
	// Metadata carries the object's name, namespace, labels and annotations.
	Metadata Metadata `yaml:"metadata"`
	// Type sets a Secret's type field (e.g. "Opaque"). Only valid for Secrets.
	// When empty the exporter does not manage the type field at all, so it can
	// co-maintain a Secret whose type is owned by another manager (e.g. a
	// kubernetes.io/tls Secret created by Flux): the API server defaults a new
	// Secret to Opaque, and an existing Secret's type is left untouched.
	Type string `yaml:"type"`
	// Cert and CRL select which materials to include. At least one must be true.
	Cert bool `yaml:"cert"`
	CRL  bool `yaml:"crl"`
	// CertKey and CRLKey name the data entries for the cert and CRL. Empty
	// selects defaultCertKey / defaultCRLKey.
	CertKey string `yaml:"cert_key"`
	CRLKey  string `yaml:"crl_key"`

	// CertScope and CRLScope select how much of each chain to publish. Empty
	// selects ScopeChain, so an existing target keeps publishing exactly what it
	// published before these fields existed. On a CA storing a single
	// certificate — every CA that issued its own root — self, chain and root are
	// byte-identical anyway.
	//
	// Both default to "chain", which is what every target published before these
	// settings existed: the stored blob verbatim. Defaulting to "self" instead
	// would have narrowed every already-deployed target on upgrade with no
	// configuration change -- a consumer's trust bundle losing its
	// intermediates, and a CRL blob losing every ancestor block, which is the
	// material crl_chain_file exists to distribute. Narrowing is therefore
	// something an operator opts into per target, and it matches what the HTTP
	// endpoints serve: GET /certificate/ca and the CRL endpoint always return
	// the full chain.
	CertScope string `yaml:"cert_scope"`
	CRLScope  string `yaml:"crl_scope"`
}

// Enabled reports whether any export target is configured.
func (c *Config) Enabled() bool {
	return c != nil && len(c.Targets) > 0
}

// Validate normalises the config in place (canonicalising kinds, applying
// defaults) and returns an error describing the first invalid target. It is
// safe to call once at startup before constructing an Exporter.
func (c *Config) Validate() error {
	if c.FieldManager == "" {
		c.FieldManager = defaultFieldManager
	}
	for i := range c.Targets {
		if err := c.Targets[i].validate(); err != nil {
			return fmt.Errorf("kubernetes_export target %d: %w", i, err)
		}
	}
	return nil
}

func (t *Target) validate() error {
	t.Kind = strings.TrimSpace(t.Kind)
	switch {
	case strings.EqualFold(t.Kind, KindSecret):
		t.Kind = KindSecret
	case strings.EqualFold(t.Kind, KindConfigMap):
		t.Kind = KindConfigMap
	case t.Kind == "":
		return fmt.Errorf("kind is required (%q or %q)", KindSecret, KindConfigMap)
	default:
		return fmt.Errorf("invalid kind %q (must be %q or %q)", t.Kind, KindSecret, KindConfigMap)
	}

	if strings.TrimSpace(t.Metadata.Name) == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if !t.Cert && !t.CRL {
		return fmt.Errorf("at least one of cert or crl must be true")
	}
	if t.Type != "" && t.Kind != KindSecret {
		return fmt.Errorf("type is only valid for Secret targets")
	}

	if t.Cert && t.CertKey == "" {
		t.CertKey = defaultCertKey
	}
	if t.CRL && t.CRLKey == "" {
		t.CRLKey = defaultCRLKey
	}

	if t.CertScope == "" {
		t.CertScope = ScopeChain
	}
	if t.CRLScope == "" {
		t.CRLScope = ScopeChain
	}
	switch t.CertScope {
	case ScopeSelf, ScopeChain, ScopeRoot:
	default:
		return fmt.Errorf("invalid cert_scope %q (must be %q, %q or %q)",
			t.CertScope, ScopeSelf, ScopeChain, ScopeRoot)
	}
	switch t.CRLScope {
	case ScopeSelf, ScopeChain:
	default:
		// No "root" for CRLs: a chain has no single anchor CRL, and the root's
		// own CRL is just one of its members.
		return fmt.Errorf("invalid crl_scope %q (must be %q or %q)",
			t.CRLScope, ScopeSelf, ScopeChain)
	}

	// A single object cannot store both materials under the same key.
	if t.Cert && t.CRL && t.CertKey == t.CRLKey {
		return fmt.Errorf("cert_key and crl_key must differ (both %q)", t.CertKey)
	}
	return nil
}
