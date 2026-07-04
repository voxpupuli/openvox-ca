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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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
	return &Exporter{client: client, cfg: cfg, src: src, defaultNS: defaultNS, metrics: m}
}

// NewInCluster builds an Exporter using in-cluster ServiceAccount credentials,
// resolving the default namespace from the pod's ServiceAccount mount. cfg must
// already have been validated. m may be nil to disable instrumentation.
func NewInCluster(cfg Config, src MaterialSource, m *Metrics) (*Exporter, error) {
	client, err := newInClusterClientset()
	if err != nil {
		return nil, err
	}
	// Only resolve the pod namespace if some target relies on it; otherwise a
	// missing namespace file should not block export.
	var defaultNS string
	if cfg.needsDefaultNamespace() {
		ns, err := podNamespace()
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
func (e *Exporter) ExportAll(ctx context.Context) error {
	certPEM, crlPEM, err := e.fetchMaterials(ctx)
	if err != nil {
		return err
	}

	var errs []error
	for i := range e.cfg.Targets {
		t := &e.cfg.Targets[i]
		err := e.applyTarget(ctx, t, certPEM, crlPEM)
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

// fetchMaterials reads the cert and CRL PEM, fetching each only if some target
// requires it.
func (e *Exporter) fetchMaterials(ctx context.Context) (certPEM, crlPEM []byte, err error) {
	var wantCert, wantCRL bool
	for i := range e.cfg.Targets {
		wantCert = wantCert || e.cfg.Targets[i].Cert
		wantCRL = wantCRL || e.cfg.Targets[i].CRL
	}
	if wantCert {
		certPEM, err = e.src.GetCACert(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("reading CA certificate for export: %w", err)
		}
	}
	if wantCRL {
		crlPEM, err = e.src.GetCRL(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("reading CRL for export: %w", err)
		}
	}
	return certPEM, crlPEM, nil
}

// namespaceFor returns the namespace a target should be applied to: its own, or
// the resolved default.
func (e *Exporter) namespaceFor(t *Target) string {
	if t.Metadata.Namespace != "" {
		return t.Metadata.Namespace
	}
	return e.defaultNS
}

// applyTarget server-side applies a single target. Force is set so the exporter
// reclaims any of its fields that drifted (e.g. were edited by another manager).
func (e *Exporter) applyTarget(ctx context.Context, t *Target, certPEM, crlPEM []byte) error {
	ns := e.namespaceFor(t)
	if ns == "" {
		return fmt.Errorf("no namespace resolved")
	}
	opts := metav1.ApplyOptions{FieldManager: e.cfg.FieldManager, Force: true}

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
