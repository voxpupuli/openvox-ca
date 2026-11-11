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
	"github.com/voxpupuli/openvox-ca/internal/k8sclient"
	"github.com/voxpupuli/openvox-ca/internal/k8sexport/exportconfig"
	corev1 "k8s.io/api/core/v1"
	accorev1 "k8s.io/client-go/applyconfigurations/core/v1"
)

// labelsFor merges the target's configured labels with the mandatory
// managed-by label, which marks every object this exporter maintains so
// operators can identify and select resources owned by openvox-ca.
//
// The label itself lives in internal/k8sclient because the managed-certificate
// stores apply the same one, and a selector finding "everything openvox-ca
// owns" is a claim that spans both.
func labelsFor(t *Target) map[string]string {
	return k8sclient.WithManagedByLabel(t.Metadata.Labels)
}

// secretDataFor returns the Secret data entries for a target given the current
// cert and CRL PEM. Only the materials the target requested are included, so a
// cert-only target never carries the CRL and vice versa. Secret data is applied
// as raw bytes under the object's data field (the client base64-encodes it in
// the request); using data rather than the write-only stringData keeps
// server-side apply idempotent — a re-apply of unchanged material is a genuine
// no-op instead of rewriting the object each time.
func secretDataFor(t *Target, certPEM, crlPEM []byte) map[string][]byte {
	data := make(map[string][]byte, 2)
	if t.Cert {
		data[t.CertKey] = exportconfig.Scoped(certPEM, "CERTIFICATE", t.CertScope)
	}
	if t.CRL {
		data[t.CRLKey] = exportconfig.Scoped(crlPEM, "X509 CRL", t.CRLScope)
	}
	return data
}

// configMapDataFor returns the ConfigMap data entries for a target. ConfigMap
// data is plain text, and PEM is text, so the values are kept as strings.
func configMapDataFor(t *Target, certPEM, crlPEM []byte) map[string]string {
	data := make(map[string]string, 2)
	if t.Cert {
		data[t.CertKey] = string(exportconfig.Scoped(certPEM, "CERTIFICATE", t.CertScope))
	}
	if t.CRL {
		data[t.CRLKey] = string(exportconfig.Scoped(crlPEM, "X509 CRL", t.CRLScope))
	}
	return data
}

// buildSecretApply constructs the server-side apply configuration for a Secret
// target. The namespace must already be resolved (non-empty).
func buildSecretApply(t *Target, namespace string, certPEM, crlPEM []byte) *accorev1.SecretApplyConfiguration {
	ac := accorev1.Secret(t.Metadata.Name, namespace).
		WithLabels(labelsFor(t)).
		WithData(secretDataFor(t, certPEM, crlPEM))
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
func buildConfigMapApply(t *Target, namespace string, certPEM, crlPEM []byte) *accorev1.ConfigMapApplyConfiguration {
	ac := accorev1.ConfigMap(t.Metadata.Name, namespace).
		WithLabels(labelsFor(t)).
		WithData(configMapDataFor(t, certPEM, crlPEM))
	if len(t.Metadata.Annotations) > 0 {
		ac = ac.WithAnnotations(t.Metadata.Annotations)
	}
	return ac
}
