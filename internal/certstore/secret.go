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

package certstore

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	accorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes"
)

// The data keys a managed certificate's Secret carries. They are the standard
// kubernetes.io/tls pair plus the trust anchor, so the Secret can be mounted or
// referenced by anything that already understands a TLS Secret.
const (
	secretKeyCert   = "tls.crt"
	secretKeyKey    = "tls.key"
	secretKeyCACert = "ca.crt"
)

// secretType is the type every managed certificate's Secret is created with.
//
// Fixed rather than configurable, and worth knowing that Secret.type is
// immutable: adopting an existing Secret of another type fails at the API
// server with a message saying so, and the remedy is to delete it and let the
// CA create it. A Secret holding tls.crt and tls.key is a TLS Secret, and one
// typed as such is directly usable by an Ingress, a Gateway listener, or the
// chart's own tls.existingSecret.
const secretType = corev1.SecretTypeTLS

// managedCertFieldManager is the server-side apply field manager managed
// certificates write under. Not named secretFieldManager, which gosec's G101
// heuristic reads as a credential on the strength of the word "secret" -- a
// rename is a better answer than a suppression, since this is a manager name
// and nothing about it is secret.
//
// Deliberately not the exporter's. Two managers on one object are co-tenants
// and each keeps its own fields; one shared name would mean each apply removed
// whatever the other had written, because omitting a previously-owned key
// deletes it. The two features are refused from sharing a Secret at startup
// anyway -- see Config.CheckExportOverlap -- and this is the second line of
// that defence rather than a substitute for it.
const managedCertFieldManager = "openvox-ca-managed-certs"

// The managed-by label marks every Secret this package maintains. It matches
// the exporter's, so one selector finds everything openvox-ca owns.
const (
	managedByLabelKey   = "app.kubernetes.io/managed-by"
	managedByLabelValue = "openvox-ca"
)

// secretAPITimeout bounds a single call to the API server.
//
// Load and Save both run inside the entry's distributed subject lock, so a call
// that hangs holds that lock against every replica until the lock's own
// deadline expires. The in-cluster clientset carries no request timeout of its
// own, so without this a black-holed connection would do exactly that.
//
// It bounds each call, not the pass. A reconcile that issues makes three of
// them -- Load's get, Save's own get, and the apply -- inside one LockTimeout
// budget, so the aggregate is capped by the caller rather than by this
// constant, and a slow-but-not-dead API server surfaces as that closure's
// deadline rather than as a per-call timeout. Either way the entry fails for
// this pass and the next one retries; the distinction is what an operator
// reads in the error.
const secretAPITimeout = 30 * time.Second

// SecretStore keeps one certificate and its key in a Kubernetes Secret,
// alongside the CA certificate chain that verifies it.
//
// # Ownership
//
// A Secret named by `managed_certs` is fully owned by the CA. Ownership is per
// key, so the CA owns the three data entries and the label keys it sets, and
// nothing else: a co-tenant manager's labels and an operator's out-of-band
// `kubectl label` both survive, and dropping one of the CA's own labels from
// the configuration removes only that key. Two quiet consequences follow -- a
// configured label another manager already owns is taken silently, and removing
// a label from the configuration removes it from the object.
//
// Hand-edited *contents* are reverted at the next reconcile, deliberately. An
// operator who wants different material should change the configuration rather
// than the object.
//
// # Adoption versus drift
//
// Both show up as a server-side apply conflict, and they are opposite cases:
//
//   - Adoption. A conflict on a Secret the CA has never owned means somebody
//     else's material is in it, and overwriting that is not the CA's call. The
//     write fails and names the two remedies.
//   - Drift. A conflict on a Secret the CA has owned before means our own
//     object was edited. That is always reconciled.
//
// They are told apart by whether the Secret's managedFields carry an Apply
// entry for this field manager at all -- not by whether we still own the
// particular key that conflicted. That distinction is the whole of it: an
// external `kubectl patch` reassigns the edited key to the editing manager, so
// the next unforced apply conflicts even on a Secret the CA created, and a test
// of "do we own this key" would read our own Secret as somebody else's and
// stall the entry for ever.
//
// If every one of our fields is taken at once, the manager entry disappears and
// the Secret does read as somebody else's. That fails safe -- it refuses rather
// than overwrites -- and the same two remedies apply.
//
// # Why all three keys move together
//
// Server-side apply removes a key a manager previously owned and no longer
// sends. So a write that could not read the CA chain must fail rather than
// write two of the three, which is why [SecretStore.Save] reads the chain
// before it applies anything.
//
// Data is applied as `data` rather than `stringData`, and that is load-bearing
// rather than stylistic. Apply tracks ownership of `f:stringData`, not of the
// `f:data` entries the API server derives from it, so a manager writing
// stringData never owns what it appears to have written -- the removal
// semantics above simply stop applying, silently.
type SecretStore struct {
	client    kubernetes.Interface
	cfg       SecretConfig
	namespace string
	caCerts   CACertSource
}

// NewSecretStore builds a store for one certificate. namespace must already be
// resolved: the configured one, or the CA pod's own.
func NewSecretStore(client kubernetes.Interface, cfg SecretConfig, namespace string, caCerts CACertSource) *SecretStore {
	return &SecretStore{client: client, cfg: cfg, namespace: namespace, caCerts: caCerts}
}

// String names the store for a log line or an error.
func (s *SecretStore) String() string {
	return fmt.Sprintf("Secret %s/%s", s.namespace, s.cfg.Name)
}

// Load reads the stored certificate and key.
//
// An absent Secret, and a Secret missing either key, are not errors: absent
// material is an input to the reconcile decision, and reporting it as a failure
// would stop the very pass that repairs it. A real read failure is an error and
// stops this entry for this pass -- reconciling against material we could not
// read would reissue on every pass for as long as the API server is unreachable.
func (s *SecretStore) Load(ctx context.Context) (certPEM, keyPEM []byte, err error) {
	sec, err := s.get(ctx)
	if err != nil {
		return nil, nil, err
	}
	if sec == nil {
		return nil, nil, nil
	}
	return sec.Data[secretKeyCert], sec.Data[secretKeyKey], nil
}

// get reads the Secret, returning (nil, nil) when it does not exist.
func (s *SecretStore) get(ctx context.Context) (*corev1.Secret, error) {
	ctx, cancel := context.WithTimeout(ctx, secretAPITimeout)
	defer cancel()

	sec, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.cfg.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", s, err)
	}
	return sec, nil
}

// Save writes the certificate, its key and the CA chain in one server-side
// apply, so the three are never observed out of step with one another.
func (s *SecretStore) Save(ctx context.Context, certPEM, keyPEM []byte) error {
	// Before anything is written. All three keys move together, so a chain we
	// cannot read has to fail the write rather than produce a Secret whose
	// ca.crt has been removed because we stopped sending it.
	caPEM, err := s.caCerts.GetCACert(ctx)
	if err != nil {
		return fmt.Errorf("reading the CA certificate chain for %s: %w", s, err)
	}
	if len(caPEM) == 0 {
		return fmt.Errorf("refusing to write %s with an empty CA certificate chain", s)
	}

	// Fresh, rather than remembered from Load. The mechanism happens to call
	// Load first under the same lock, but Load and Save are independent
	// function values as far as it is concerned, and the CA's own serving
	// certificate will call them differently. A get here is also the more
	// accurate answer: it sees an edit made since the load.
	existing, err := s.get(ctx)
	if err != nil {
		return err
	}
	// force is what separates drift from adoption. Without a Secret there is
	// nothing to conflict with and the value does not matter; the apply creates
	// it.
	force := s.cfg.AdoptExisting || ownedByUs(existing)

	ac := accorev1.Secret(s.cfg.Name, s.namespace).
		WithType(secretType).
		WithLabels(s.labels()).
		WithData(map[string][]byte{
			secretKeyCert:   certPEM,
			secretKeyKey:    keyPEM,
			secretKeyCACert: caPEM,
		})
	if len(s.cfg.Annotations) > 0 {
		ac = ac.WithAnnotations(s.cfg.Annotations)
	}

	applyCtx, cancel := context.WithTimeout(ctx, secretAPITimeout)
	defer cancel()

	_, err = s.client.CoreV1().Secrets(s.namespace).Apply(applyCtx, ac,
		metav1.ApplyOptions{FieldManager: managedCertFieldManager, Force: force})
	if err == nil {
		return nil
	}
	if apierrors.IsConflict(err) && !force {
		// SECURITY: the material already in this Secret is somebody else's, and
		// replacing it would take a name and a credential the CA was not asked
		// to take. Refuse, and give both remedies -- the next pass retries and
		// will refuse again until one of them is applied.
		// NIST 800-53: AC-3 (Access Enforcement), AC-6 (Least Privilege)
		return fmt.Errorf("%s already holds material this CA does not own, so it was not "+
			"overwritten. Either set store.secret.adopt_existing: true for this certificate, "+
			"or delete the Secret and let the CA create it: %w", s, err)
	}
	return fmt.Errorf("writing %s: %w", s, err)
}

// labels merges the configured labels with the mandatory managed-by label,
// which always wins so ownership cannot be masked by configuration.
func (s *SecretStore) labels() map[string]string {
	labels := make(map[string]string, len(s.cfg.Labels)+1)
	for k, v := range s.cfg.Labels {
		labels[k] = v
	}
	labels[managedByLabelKey] = managedByLabelValue
	return labels
}

// ownedByUs reports whether sec carries an apply entry for this field manager,
// and so whether the CA has written this Secret before.
//
// Any entry is enough, whatever fields it still holds. An external edit moves
// the edited field to the editing manager but leaves our entry owning the rest,
// and it is the entry's existence rather than its contents that says the object
// is ours to reconcile.
//
// Operation is checked as well as the name: an Update entry under the same name
// would be somebody using `kubectl --field-manager` on a non-apply verb, which
// is not this CA writing.
func ownedByUs(sec *corev1.Secret) bool {
	if sec == nil {
		return false
	}
	for _, f := range sec.ManagedFields {
		if f.Manager == managedCertFieldManager && f.Operation == metav1.ManagedFieldsOperationApply {
			return true
		}
	}
	return false
}
