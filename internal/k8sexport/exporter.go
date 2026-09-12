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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/voxpupuli/openvox-ca/internal/k8sclient"
)

// applyTimeout bounds a single server-side apply. The exporter runs on the
// process-lifetime context, and the in-cluster clientset carries no request
// timeout, so without this a black-holed API-server connection could block the
// single exporter goroutine (and thus re-export of every target) for as long as
// the OS transport takes to give up. A per-apply deadline surfaces a stuck call
// as a counted, logged error and lets the loop proceed to the next wake-up: the
// retry the caller runs after a failed cycle, the next CRL update, or a restart.
const applyTimeout = 30 * time.Second

// MaterialSource provides the current CA certificate and CRL in PEM form. It is
// satisfied by *storage.StorageService, but kept as a narrow interface so this
// package does not depend on the storage layer and is easy to fake in tests.
type MaterialSource interface {
	GetCACert(ctx context.Context) ([]byte, error)
	GetCRL(ctx context.Context) ([]byte, error)
}

// Exporter reconciles the configured Secret/ConfigMap targets with the current
// CA certificate and CRL using server-side apply.
type Exporter struct {
	client    kubernetes.Interface
	cfg       Config
	src       MaterialSource
	defaultNS string   // resolved pod namespace; used for targets without one
	metrics   *Metrics // may be nil (metrics disabled)
}

// New constructs an Exporter from an existing clientset. cfg must already have
// been validated (Config.Validate). defaultNS is the namespace used for targets
// that do not set their own; it may be empty if every target sets a namespace.
// m may be nil to disable instrumentation.
func New(client kubernetes.Interface, cfg Config, src MaterialSource, defaultNS string, m *Metrics) *Exporter {
	e := &Exporter{client: client, cfg: cfg, src: src, defaultNS: defaultNS, metrics: m}
	// Publish the apply counters at zero now, so "configured but never
	// attempted" is a series rather than an absence. See initTargets.
	m.initTargets(cfg.Targets, defaultNS)
	return e
}

// InitTargetMetrics publishes every configured target's apply counters at zero
// without constructing an Exporter, for the case where the export cannot start
// at all: NewInCluster fails, the caller logs it, and no cycle ever runs.
//
// That case is why this is exported rather than left inside New: it is the one
// door New cannot cover, and the CA stays up and healthy while the exported
// objects quietly stop being updated. See PuppetCAKubernetesExportNotRunning in
// mixin/alerts.libsonnet.
//
// Call it only when the export is known not to be starting. Targets without
// their own namespace are labelled with an empty one, since the pod namespace
// may be exactly what could not be resolved. That placeholder is harmless here
// only because nothing will ever record an apply for them. On a path where the
// exporter might still start, it would strand a second series at zero under the
// wrong label and make PuppetCAKubernetesExportNotRunning fire for a healthy
// target for ever.
func InitTargetMetrics(cfg Config, m *Metrics) {
	m.initTargets(cfg.Targets, "")
}

// NewInCluster builds an Exporter using in-cluster ServiceAccount credentials,
// resolving the default namespace from the pod's ServiceAccount mount. cfg must
// already have been validated. m may be nil to disable instrumentation.
func NewInCluster(cfg Config, src MaterialSource, m *Metrics) (*Exporter, error) {
	client, err := k8sclient.InClusterClientset("kubernetes_export")
	if err != nil {
		return nil, err
	}
	// Only resolve the pod namespace if some target relies on it; otherwise a
	// missing namespace file should not block export.
	var defaultNS string
	if cfg.needsDefaultNamespace() {
		ns, err := k8sclient.PodNamespace()
		if err != nil {
			return nil, fmt.Errorf("resolving default namespace for a target without an explicit namespace: %w", err)
		}
		defaultNS = ns
	}
	return New(client, cfg, src, defaultNS, m), nil
}

// needsDefaultNamespace reports whether any target omits its namespace and so
// depends on the pod's own namespace being resolvable.
func (c *Config) needsDefaultNamespace() bool {
	for i := range c.Targets {
		if c.Targets[i].Metadata.Namespace == "" {
			return true
		}
	}
	return false
}

// ExportAll reconciles every configured target with the current cert/CRL. It
// reads each material at most once. A failure applying one target is logged and
// collected but does not prevent the others from being applied; the joined error
// (or nil) is returned.
//
// A material that cannot be read fails only the targets that asked for it, and
// the per-target loop always runs. The invariant this function must hold: every
// configured target records a result on every cycle, whatever failed upstream.
// Returning before the loop leaves the export alerts nothing to match on and a
// stale CA certificate or CRL that nothing can report -- see
// PuppetCAKubernetesExportNotRunning in mixin/alerts.libsonnet for why.
func (e *Exporter) ExportAll(ctx context.Context) error {
	mats := e.fetchMaterials(ctx)

	var errs []error
	for i := range e.cfg.Targets {
		t := &e.cfg.Targets[i]
		// A material this target requested could not be read: fail the target
		// with that error rather than calling the API server with material we
		// know is missing. applyTarget would refuse it anyway, but reporting
		// "refusing to export an empty CRL" would name the symptom instead of
		// the read failure that caused it.
		err := mats.forTarget(t)
		if err == nil {
			err = e.applyTarget(ctx, t, mats.certPEM, mats.crlPEM)
		}
		e.metrics.recordApply(t, e.namespaceFor(t), err)
		if err != nil {
			slog.Warn("Kubernetes export failed for target",
				"kind", t.Kind, "name", t.Metadata.Name, "namespace", e.namespaceFor(t), "error", err)
			errs = append(errs, fmt.Errorf("%s/%s: %w", t.Kind, t.Metadata.Name, err))
			continue
		}
		slog.Debug("Kubernetes export applied",
			"kind", t.Kind, "name", t.Metadata.Name, "namespace", e.namespaceFor(t))
	}
	return errors.Join(errs...)
}

// materials holds one cycle's cert and CRL PEM alongside the error from reading
// each. Read errors are carried per material rather than returned, so a cert
// that cannot be read does not fail a CRL-only target — and, more importantly,
// does not skip the per-target loop that writes the export metrics.
type materials struct {
	certPEM []byte
	certErr error
	crlPEM  []byte
	crlErr  error
}

// forTarget returns the read error that should fail t, or nil if every material
// t asked for was read. A target that requested both materials reports the cert
// failure first; the joined per-target error names the target either way.
func (m *materials) forTarget(t *Target) error {
	if t.Cert && m.certErr != nil {
		return m.certErr
	}
	if t.CRL && m.crlErr != nil {
		return m.crlErr
	}
	return nil
}

// fetchMaterials reads the cert and CRL PEM, fetching each only if some target
// requires it. It never fails the cycle: a read error is recorded against the
// material it belongs to and attributed to targets by materials.forTarget.
func (e *Exporter) fetchMaterials(ctx context.Context) materials {
	var wantCert, wantCRL bool
	for i := range e.cfg.Targets {
		wantCert = wantCert || e.cfg.Targets[i].Cert
		wantCRL = wantCRL || e.cfg.Targets[i].CRL
	}

	var m materials
	if wantCert {
		if m.certPEM, m.certErr = e.src.GetCACert(ctx); m.certErr != nil {
			m.certErr = fmt.Errorf("reading CA certificate for export: %w", m.certErr)
		}
	}
	if wantCRL {
		if m.crlPEM, m.crlErr = e.src.GetCRL(ctx); m.crlErr != nil {
			m.crlErr = fmt.Errorf("reading CRL for export: %w", m.crlErr)
		}
	}
	return m
}

// namespaceFor returns the namespace a target should be applied to: its own, or
// the resolved default.
func (e *Exporter) namespaceFor(t *Target) string {
	return namespaceForTarget(t, e.defaultNS)
}

// namespaceForTarget is namespaceFor without an Exporter, so the metric labels
// can be computed before one is constructed (see InitTargetMetrics).
func namespaceForTarget(t *Target, defaultNS string) string {
	if t.Metadata.Namespace != "" {
		return t.Metadata.Namespace
	}
	return defaultNS
}

// applyTarget server-side applies a single target. Force is set so the exporter
// reclaims any of its fields that drifted (e.g. were edited by another manager).
func (e *Exporter) applyTarget(ctx context.Context, t *Target, certPEM, crlPEM []byte) error {
	ns := e.namespaceFor(t)
	if ns == "" {
		return fmt.Errorf("no namespace resolved")
	}
	// Never publish an empty material: applying an empty value would clobber a
	// previously-good cert/CRL in the target object. A requested-but-empty
	// material means the CA is in an unexpected state, so fail this target (it is
	// counted and logged) and leave the existing object untouched.
	if t.Cert && len(certPEM) == 0 {
		return fmt.Errorf("refusing to export an empty CA certificate")
	}
	if t.CRL && len(crlPEM) == 0 {
		return fmt.Errorf("refusing to export an empty CRL")
	}
	opts := metav1.ApplyOptions{FieldManager: e.cfg.FieldManager, Force: true}

	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	switch t.Kind {
	case KindSecret:
		_, err := e.client.CoreV1().Secrets(ns).Apply(ctx, t.buildSecretApply(ns, certPEM, crlPEM), opts)
		return err
	case KindConfigMap:
		_, err := e.client.CoreV1().ConfigMaps(ns).Apply(ctx, t.buildConfigMapApply(ns, certPEM, crlPEM), opts)
		return err
	default:
		// Unreachable after Validate, but fail loudly rather than silently skip.
		return fmt.Errorf("unsupported kind %q", t.Kind)
	}
}
