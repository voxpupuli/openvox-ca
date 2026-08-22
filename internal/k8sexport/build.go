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

package k8sexport

import (
	"encoding/pem"

	corev1 "k8s.io/api/core/v1"
	accorev1 "k8s.io/client-go/applyconfigurations/core/v1"
)

// The managed-by label marks every object this exporter maintains so operators
// can identify and select resources owned by openvox-ca. It is always present
// and takes precedence over any operator-supplied value for the same key.
const (
	managedByLabelKey   = "app.kubernetes.io/managed-by"
	managedByLabelValue = "openvox-ca"
)

// labelsFor merges the target's configured labels with the mandatory
// managed-by label. The managed-by label always wins so ownership cannot be
// accidentally masked by configuration.
func (t *Target) labelsFor() map[string]string {
	labels := make(map[string]string, len(t.Metadata.Labels)+1)
	for k, v := range t.Metadata.Labels {
		labels[k] = v
	}
	labels[managedByLabelKey] = managedByLabelValue
	return labels
}

// pemBlocks splits a PEM blob into its individual blocks of the given type,
// each still PEM-encoded.
//
// Block boundaries are all the scoping needs, so this deliberately does not
// parse certificates or CRLs: the exporter republishes what the CA already
// validated on the way in, and re-deriving trust decisions here would be a
// second, weaker copy of them.
func pemBlocks(data []byte, blockType string) [][]byte {
	var out [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != blockType {
			continue
		}
		out = append(out, pem.EncodeToMemory(block))
	}
}

// scoped selects the part of a PEM chain a scope asks for. An unrecognised
// scope cannot occur after Validate; an empty chain passes through untouched so
// the caller's own empty-material guard reports it.
func scoped(chain []byte, blockType, scope string) []byte {
	// An unset scope means the same thing here as it does in validate(): the
	// whole chain. Validation is what normally fills it in, so this only
	// matters for a Target assembled in code rather than loaded from
	// configuration -- but the two must not disagree about the default, or a
	// missed Validate() call would silently narrow what a target publishes,
	// which is the failure this feature's default was chosen to avoid.
	if scope == ScopeChain || scope == "" {
		return chain
	}
	blocks := pemBlocks(chain, blockType)
	if len(blocks) == 0 {
		return chain
	}
	if scope == ScopeRoot {
		return blocks[len(blocks)-1]
	}
	return blocks[0]
}

// secretDataFor returns the Secret data entries for a target given the current
// cert and CRL PEM. Only the materials the target requested are included, so a
// cert-only target never carries the CRL and vice versa. Secret data is applied
// as raw bytes under the object's data field (the client base64-encodes it in
// the request); using data rather than the write-only stringData keeps
// server-side apply idempotent — a re-apply of unchanged material is a genuine
// no-op instead of rewriting the object each time.
func (t *Target) secretDataFor(certPEM, crlPEM []byte) map[string][]byte {
	data := make(map[string][]byte, 2)
	if t.Cert {
		data[t.CertKey] = scoped(certPEM, "CERTIFICATE", t.CertScope)
	}
	if t.CRL {
		data[t.CRLKey] = scoped(crlPEM, "X509 CRL", t.CRLScope)
	}
	return data
}

// configMapDataFor returns the ConfigMap data entries for a target. ConfigMap
// data is plain text, and PEM is text, so the values are kept as strings.
func (t *Target) configMapDataFor(certPEM, crlPEM []byte) map[string]string {
	data := make(map[string]string, 2)
	if t.Cert {
		data[t.CertKey] = string(scoped(certPEM, "CERTIFICATE", t.CertScope))
	}
	if t.CRL {
		data[t.CRLKey] = string(scoped(crlPEM, "X509 CRL", t.CRLScope))
	}
	return data
}

// buildSecretApply constructs the server-side apply configuration for a Secret
// target. The namespace must already be resolved (non-empty).
func (t *Target) buildSecretApply(namespace string, certPEM, crlPEM []byte) *accorev1.SecretApplyConfiguration {
	ac := accorev1.Secret(t.Metadata.Name, namespace).
		WithLabels(t.labelsFor()).
		WithData(t.secretDataFor(certPEM, crlPEM))
	// Only own the type field when one is configured, so openvox-ca can
	// co-maintain a Secret whose type (e.g. kubernetes.io/tls) is owned by
	// another manager. An unset type leaves it to the API server default on
	// creation and untouched on an existing object.
	if t.Type != "" {
		ac = ac.WithType(corev1.SecretType(t.Type))
	}
	if len(t.Metadata.Annotations) > 0 {
		ac = ac.WithAnnotations(t.Metadata.Annotations)
	}
	return ac
}

// buildConfigMapApply constructs the server-side apply configuration for a
// ConfigMap target. The namespace must already be resolved (non-empty).
func (t *Target) buildConfigMapApply(namespace string, certPEM, crlPEM []byte) *accorev1.ConfigMapApplyConfiguration {
	ac := accorev1.ConfigMap(t.Metadata.Name, namespace).
		WithLabels(t.labelsFor()).
		WithData(t.configMapDataFor(certPEM, crlPEM))
	if len(t.Metadata.Annotations) > 0 {
		ac = ac.WithAnnotations(t.Metadata.Annotations)
	}
	return ac
}
