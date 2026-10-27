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

package k8sexport_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

// metricValue gathers reg and returns the value of the counter or gauge series
// matching name and labels, or false when no such series exists.
func metricValue(reg *prometheus.Registry, name string, labels map[string]string) (float64, bool) {
	GinkgoHelper()
	mfs, err := reg.Gather()
	Expect(err).NotTo(HaveOccurred())
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			have := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				have[lp.GetName()] = lp.GetValue()
			}
			matched := true
			for k, v := range labels {
				if have[k] != v {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue(), true
			}
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

// stubSource is a MaterialSource returning fixed PEM bytes.
type stubSource struct {
	cert, crl []byte
	certErr   error
	crlErr    error
}

func (s stubSource) GetCACert(context.Context) ([]byte, error) { return s.cert, s.certErr }
func (s stubSource) GetCRL(context.Context) ([]byte, error)    { return s.crl, s.crlErr }

var _ = Describe("Exporter", func() {
	var (
		ctx    context.Context
		client *fake.Clientset
		src    stubSource
	)

	BeforeEach(func() {
		ctx = context.Background()
		client = fake.NewClientset()
		src = stubSource{cert: []byte("CERT-PEM"), crl: []byte("CRL-PEM")}
	})

	mustValidate := func(cfg *k8sexport.Config) {
		GinkgoHelper()
		Expect(cfg.Validate()).To(Succeed())
	}

	It("applies a Secret with both materials, keys, type and managed-by label", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret",
			Metadata: k8sexport.Metadata{
				Name: "trust", Namespace: "ns1",
				Labels: map[string]string{"app": "demo"},
			},
			Type: "Opaque",
			Cert: true, CRL: true,
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKeyWithValue("ca.crt", []byte("CERT-PEM")))
		Expect(sec.Data).To(HaveKeyWithValue("ca.crl", []byte("CRL-PEM")))
		Expect(string(sec.Type)).To(Equal("Opaque"))
		Expect(sec.Labels).To(HaveKeyWithValue("app", "demo"))
		Expect(sec.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
	})

	It("does not set the type when none is configured, so it is not owned", func() {
		// A CRL-only target with no type: openvox-ca co-maintains the CRL inside
		// a Secret whose type (e.g. kubernetes.io/tls) is owned by another
		// manager, without claiming the type field itself.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKeyWithValue("ca.crl", []byte("CRL-PEM")))
		Expect(sec.Type).To(BeEmpty()) // exporter left the type field unset
	})

	It("applies a ConfigMap with only the CRL under a custom key", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind:     "ConfigMap",
			Metadata: k8sexport.Metadata{Name: "crl-cm", Namespace: "ns1"},
			CRL:      true, CRLKey: "openvox.crl",
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		cm, err := client.CoreV1().ConfigMaps("ns1").Get(ctx, "crl-cm", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Data).To(HaveKeyWithValue("openvox.crl", "CRL-PEM"))
		Expect(cm.Data).NotTo(HaveKey("ca.crt"))
		Expect(cm.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
	})

	It("uses the default namespace for targets without one", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true,
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "default-ns", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		_, err := client.CoreV1().Secrets("default-ns").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("re-exports an updated CRL on a subsequent call", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		src.crl = []byte("CRL-V1")
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		// Update the source CRL and a fresh exporter (same config) re-applies it.
		src.crl = []byte("CRL-V2")
		exp = k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Data).To(HaveKeyWithValue("ca.crl", []byte("CRL-V2")))
	})

	It("returns an error and applies nothing when the CRL cannot be read", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		src.crlErr = context.DeadlineExceeded
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("reading CRL")))

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})

	It("refuses to publish an empty material, leaving any existing object untouched", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		// The source returns no error but an empty CRL (e.g. an unexpected CA
		// state): the target must fail rather than clobber the object.
		src.crl = nil
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("empty CRL")))

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})

	It("records apply metrics per target and result", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "good", Namespace: "ns1"}, CRL: true},
			{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "bad", Namespace: "ns1"}, CRL: true},
		}}
		mustValidate(cfg)

		// Fail every ConfigMap apply so the second target records an error.
		client.PrependReactor("patch", "configmaps",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("boom")
			})

		reg := prometheus.NewRegistry()
		exp := k8sexport.New(client, *cfg, src, "", k8sexport.NewMetrics(reg))
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("ConfigMap/bad")))

		v, found := metricValue(reg, "openvoxca_k8s_export_applies_total", map[string]string{
			"kind": "Secret", "namespace": "ns1", "name": "good", "result": "success",
		})
		Expect(found).To(BeTrue())
		Expect(v).To(Equal(1.0))

		v, found = metricValue(reg, "openvoxca_k8s_export_applies_total", map[string]string{
			"kind": "ConfigMap", "namespace": "ns1", "name": "bad", "result": "error",
		})
		Expect(found).To(BeTrue())
		Expect(v).To(Equal(1.0))

		// Only the successful target gets a last-success timestamp, and only
		// the failing target gets a last-error timestamp.
		v, found = metricValue(reg, "openvoxca_k8s_export_last_success_timestamp_seconds",
			map[string]string{"kind": "Secret", "namespace": "ns1", "name": "good"})
		Expect(found).To(BeTrue())
		Expect(v).To(BeNumerically(">", 0))

		_, found = metricValue(reg, "openvoxca_k8s_export_last_success_timestamp_seconds",
			map[string]string{"kind": "ConfigMap", "namespace": "ns1", "name": "bad"})
		Expect(found).To(BeFalse())

		v, found = metricValue(reg, "openvoxca_k8s_export_last_error_timestamp_seconds",
			map[string]string{"kind": "ConfigMap", "namespace": "ns1", "name": "bad"})
		Expect(found).To(BeTrue())
		Expect(v).To(BeNumerically(">", 0))

		_, found = metricValue(reg, "openvoxca_k8s_export_last_error_timestamp_seconds",
			map[string]string{"kind": "Secret", "namespace": "ns1", "name": "good"})
		Expect(found).To(BeFalse())
	})

	It("still applies later targets when an earlier target fails", func() {
		// Failure isolation: a failing target must not stop the ones after it.
		// The failing target is first so a regress-to-early-return (return
		// instead of continue) would leave the second target uncreated.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "bad", Namespace: "ns1"}, CRL: true},
			{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "good", Namespace: "ns1"}, CRL: true},
		}}
		mustValidate(cfg)

		// Fail every Secret apply so the first (earlier) target errors.
		client.PrependReactor("patch", "secrets",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("boom")
			})

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("Secret/bad")))

		// The later ConfigMap must still have been applied.
		cm, err := client.CoreV1().ConfigMaps("ns1").Get(ctx, "good", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Data).To(HaveKeyWithValue("ca.crl", "CRL-PEM"))
	})

	It("does not read the cert when no target requests it", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true,
		}}}
		mustValidate(cfg)

		// A cert read would error, but a CRL-only export must not touch it.
		src.certErr = context.DeadlineExceeded
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())
	})

	It("keeps the managed-by label even when a target tries to override it", func() {
		// The managed-by label always wins so ownership cannot be masked by
		// configuration: an operator setting it to another value is overridden.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret",
			Metadata: k8sexport.Metadata{
				Name: "trust", Namespace: "ns1",
				Labels: map[string]string{"app.kubernetes.io/managed-by": "intruder"},
			},
			Cert: true,
		}}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
	})

	It("propagates configured annotations onto applied objects", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{
				Kind: "Secret",
				Metadata: k8sexport.Metadata{
					Name: "trust-sec", Namespace: "ns1",
					Annotations: map[string]string{"owner": "platform"},
				},
				Cert: true,
			},
			{
				Kind: "ConfigMap",
				Metadata: k8sexport.Metadata{
					Name: "trust-cm", Namespace: "ns1",
					Annotations: map[string]string{"owner": "platform"},
				},
				CRL: true,
			},
		}}
		mustValidate(cfg)

		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust-sec", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(sec.Annotations).To(HaveKeyWithValue("owner", "platform"))

		cm, err := client.CoreV1().ConfigMaps("ns1").Get(ctx, "trust-cm", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Annotations).To(HaveKeyWithValue("owner", "platform"))
	})

	It("returns an error and applies nothing when the cert cannot be read", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, Cert: true,
		}}}
		mustValidate(cfg)

		src.certErr = context.DeadlineExceeded
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("reading CA certificate")))

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})

	It("refuses to publish an empty cert, leaving any existing object untouched", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, Cert: true,
		}}}
		mustValidate(cfg)

		// The source returns no error but an empty cert: the target must fail
		// rather than clobber the object.
		src.cert = nil
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("empty CA certificate")))

		_, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})

	It("errors when a target has no namespace and no default is resolved", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true,
		}}}
		mustValidate(cfg)

		// No per-target namespace and an empty default: apply must fail rather
		// than write into the empty-string namespace.
		exp := k8sexport.New(client, *cfg, src, "", nil)
		Expect(exp.ExportAll(ctx)).To(MatchError(ContainSubstring("no namespace resolved")))

		_, err := client.CoreV1().Secrets("").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).To(HaveOccurred()) // never created
	})
	// The bug this guards: ExportAll used to return as soon as a material read
	// failed, before the per-target loop. recordApply then never ran, so no
	// per-target series was written — and every arm of
	// OpenVoxCAKubernetesExportFailing has
	// openvoxca_k8s_export_last_error_timestamp_seconds on the left, so with no
	// series neither arm could fire. One transient storage blip left every
	// target holding a stale CA certificate or CRL with nothing alerting.
	It("still records a per-target error metric when a material cannot be read", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, CRL: true},
			{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "bundle", Namespace: "ns2"}, CRL: true},
		}}
		mustValidate(cfg)

		src.crlErr = context.DeadlineExceeded
		reg := prometheus.NewRegistry()
		exp := k8sexport.New(client, *cfg, src, "", k8sexport.NewMetrics(reg))

		err := exp.ExportAll(ctx)

		// The metrics are asserted before the error text, deliberately. A
		// regression that reinstates the early return fails both, and whichever
		// is checked first is the message the next reader sees; the series
		// existing is what the alert depends on, so let that be the one.
		for _, want := range []struct{ kind, ns, name string }{
			{"Secret", "ns1", "trust"},
			{"ConfigMap", "ns2", "bundle"},
		} {
			labels := map[string]string{"kind": want.kind, "namespace": want.ns, "name": want.name}

			v, found := metricValue(reg, "openvoxca_k8s_export_last_error_timestamp_seconds", labels)
			Expect(found).To(BeTrue(),
				"no last_error series for %s/%s: the alert cannot fire", want.kind, want.name)
			Expect(v).To(BeNumerically(">", 0))

			counted := map[string]string{
				"kind": want.kind, "namespace": want.ns, "name": want.name, "result": "error",
			}
			v, found = metricValue(reg, "openvoxca_k8s_export_applies_total", counted)
			Expect(found).To(BeTrue())
			Expect(v).To(Equal(1.0))
		}

		// Every target is named, not just the first: the read failed once but
		// it is attributed to each target that asked for that material.
		Expect(err).To(MatchError(ContainSubstring("Secret/trust: reading CRL")))
		Expect(err).To(MatchError(ContainSubstring("ConfigMap/bundle: reading CRL")))
	})

	// Both directions, because the two guards in forTarget are independent: a
	// spec that only ever fails the cert read leaves `t.CRL &&` unprotected, and
	// dropping it reintroduces exactly the cross-target contamination this
	// branch exists to remove. The failing material and the surviving target
	// swap places between entries; nothing else does.
	DescribeTable("fails only the targets that asked for the material that could not be read",
		func(breaks func(*stubSource), survivorKind, survivor, casualty, wantErr, wantKey, wantVal string) {
			cfg := &k8sexport.Config{Targets: []k8sexport.Target{
				{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "certonly", Namespace: "ns1"}, Cert: true},
				{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "crlonly", Namespace: "ns1"}, CRL: true},
			}}
			mustValidate(cfg)

			breaks(&src)
			reg := prometheus.NewRegistry()
			exp := k8sexport.New(client, *cfg, src, "", k8sexport.NewMetrics(reg))

			err := exp.ExportAll(ctx)

			// The surviving target was applied for real, with the material it
			// asked for. Asserted first: this is the isolation the spec is
			// named for, and an early return breaks it and the error text
			// together.
			switch survivorKind {
			case "ConfigMap":
				cm, getErr := client.CoreV1().ConfigMaps("ns1").Get(ctx, survivor, metav1.GetOptions{})
				Expect(getErr).NotTo(HaveOccurred(), "%s was not applied despite not wanting the failed material", survivor)
				Expect(cm.Data).To(HaveKeyWithValue(wantKey, wantVal))
			default:
				sec, getErr := client.CoreV1().Secrets("ns1").Get(ctx, survivor, metav1.GetOptions{})
				Expect(getErr).NotTo(HaveOccurred(), "%s was not applied despite not wanting the failed material", survivor)
				Expect(sec.Data).To(HaveKeyWithValue(wantKey, []byte(wantVal)))
			}

			v, found := metricValue(reg, "openvoxca_k8s_export_last_success_timestamp_seconds",
				map[string]string{"kind": survivorKind, "namespace": "ns1", "name": survivor})
			Expect(found).To(BeTrue())
			Expect(v).To(BeNumerically(">", 0))

			_, found = metricValue(reg, "openvoxca_k8s_export_last_error_timestamp_seconds",
				map[string]string{"kind": survivorKind, "namespace": "ns1", "name": survivor})
			Expect(found).To(BeFalse(), "%s recorded an error for a material it never requested", survivor)

			// Symmetric: the casualty is named in the joined error and the
			// survivor is not, so neither half can drift into the other.
			Expect(err).To(MatchError(ContainSubstring(wantErr)))
			Expect(err).To(MatchError(ContainSubstring(casualty)))
			Expect(err).NotTo(MatchError(ContainSubstring(survivor)))
		},
		Entry("an unreadable cert leaves the CRL-only target alone",
			func(s *stubSource) { s.certErr = context.DeadlineExceeded },
			"ConfigMap", "crlonly", "certonly",
			"Secret/certonly: reading CA certificate", "ca.crl", "CRL-PEM"),
		Entry("an unreadable CRL leaves the cert-only target alone",
			func(s *stubSource) { s.crlErr = context.DeadlineExceeded },
			"Secret", "certonly", "crlonly",
			"ConfigMap/crlonly: reading CRL", "ca.crt", "CERT-PEM"),
	)

	It("reports the cert failure for a target that asked for both materials", func() {
		// forTarget checks Cert before CRL, so a target wanting both reports the
		// cert read failure. Documented precedence with nothing behind it is
		// just a comment; this is the assertion.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "both", Namespace: "ns1"},
			Cert: true, CRL: true,
		}}}
		mustValidate(cfg)

		src.certErr = context.DeadlineExceeded
		src.crlErr = context.Canceled
		exp := k8sexport.New(client, *cfg, src, "", nil)

		err := exp.ExportAll(ctx)
		Expect(err).To(MatchError(ContainSubstring("Secret/both: reading CA certificate")))
		Expect(err).NotTo(MatchError(ContainSubstring("reading CRL")))
	})

	It("creates apply counters at zero for every target before the first export", func() {
		// Prometheus omits a child that was never touched, so an exporter that
		// records nothing at all looks exactly like one that is not configured.
		// Pre-creating these gives OpenVoxCAKubernetesExportNotRunning a series
		// to match on. The timestamp gauges must stay absent — see initTargets.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true},
		}}
		mustValidate(cfg)

		reg := prometheus.NewRegistry()
		_ = k8sexport.New(client, *cfg, src, "pod-ns", k8sexport.NewMetrics(reg))

		// The resolved default namespace is used, matching what recordApply
		// will later label the same series with.
		for _, result := range []string{"success", "error"} {
			v, found := metricValue(reg, "openvoxca_k8s_export_applies_total", map[string]string{
				"kind": "Secret", "namespace": "pod-ns", "name": "trust", "result": result,
			})
			Expect(found).To(BeTrue(), "applies_total{result=%q} was not pre-created", result)
			Expect(v).To(Equal(0.0))
		}

		for _, name := range []string{
			"openvoxca_k8s_export_last_success_timestamp_seconds",
			"openvoxca_k8s_export_last_error_timestamp_seconds",
		} {
			_, found := metricValue(reg, name, map[string]string{
				"kind": "Secret", "namespace": "pod-ns", "name": "trust",
			})
			Expect(found).To(BeFalse(), "%s must stay absent until something happens", name)
		}
	})
	It("publishes zeroed counters for an export that never starts", func() {
		// The path where NewInCluster fails: no Exporter is ever constructed,
		// so New never runs and nothing will ever record an apply. Without
		// these series the CA stays up with readiness green, the targets freeze
		// at whatever they last held, and neither export alert has anything to
		// match. InitTargetMetrics is what makes that state reportable.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{
			{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, Cert: true},
			// No namespace of its own: the pod namespace may be exactly what
			// could not be resolved, so this is labelled with an empty one.
			{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "bundle"}, CRL: true},
		}}
		mustValidate(cfg)

		reg := prometheus.NewRegistry()
		k8sexport.InitTargetMetrics(*cfg, k8sexport.NewMetrics(reg))

		for _, want := range []struct{ kind, ns, name string }{
			{"Secret", "ns1", "trust"},
			{"ConfigMap", "", "bundle"},
		} {
			for _, result := range []string{"success", "error"} {
				v, found := metricValue(reg, "openvoxca_k8s_export_applies_total", map[string]string{
					"kind": want.kind, "namespace": want.ns, "name": want.name, "result": result,
				})
				Expect(found).To(BeTrue(),
					"no applies_total{name=%q,result=%q}: a dead export is unreportable", want.name, result)
				Expect(v).To(Equal(0.0))
			}
		}
	})

	It("tolerates a nil Metrics when the export never starts", func() {
		// Metrics are disabled whenever the Prometheus exporter is off, and
		// that path runs before anything has checked.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"}, Cert: true,
		}}}
		mustValidate(cfg)
		Expect(func() { k8sexport.InitTargetMetrics(*cfg, nil) }).NotTo(Panic())
	})
})

var _ = Describe("Export scopes", func() {
	// Chains run leaf/intermediate first, root last — the order the CA stores
	// and every consumer expects.
	const (
		// Three blocks, not two: with two, "the last certificate" and "the
		// second certificate" are the same block, so a root scope that returned
		// blocks[1] would pass. The middle block is what tells them apart.
		certChain = "-----BEGIN CERTIFICATE-----\nSU5URVJNRURJQVRF\n-----END CERTIFICATE-----\n" +
			"-----BEGIN CERTIFICATE-----\nTUlERExF\n-----END CERTIFICATE-----\n" +
			"-----BEGIN CERTIFICATE-----\nUk9PVA==\n-----END CERTIFICATE-----\n"
		crlChain = "-----BEGIN X509 CRL-----\nT1VSUw==\n-----END X509 CRL-----\n" +
			"-----BEGIN X509 CRL-----\nVVBTVFJFQU0=\n-----END X509 CRL-----\n"
	)

	var (
		ctx    context.Context
		client *fake.Clientset
		src    stubSource
	)

	BeforeEach(func() {
		ctx = context.Background()
		client = fake.NewClientset()
		src = stubSource{cert: []byte(certChain), crl: []byte(crlChain)}
	})

	exportWith := func(certScope, crlScope string) map[string][]byte {
		GinkgoHelper()
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind:      "Secret",
			Metadata:  k8sexport.Metadata{Name: "trust", Namespace: "ns1"},
			Cert:      true,
			CRL:       true,
			CertScope: certScope,
			CRLScope:  crlScope,
		}}}
		Expect(cfg.Validate()).To(Succeed())
		Expect(k8sexport.New(client, *cfg, src, "", nil).ExportAll(ctx)).To(Succeed())
		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		return sec.Data
	}

	It("defaults to chain, publishing what the target published before scopes existed", func() {
		// The upgrade property, and the reason the default is not "self": before
		// these settings existed every target got the stored blob verbatim. A
		// narrow default would have silently dropped every intermediate from a
		// consumer's trust bundle and every ancestor block from a CRL blob --
		// the material crl_chain_file exists to distribute -- with no
		// configuration change to notice and no error to catch, since a
		// scoped-down value is not empty.
		data := exportWith("", "")
		Expect(string(data["ca.crt"])).To(ContainSubstring("SU5URVJNRURJQVRF"))
		Expect(string(data["ca.crt"])).To(ContainSubstring("Uk9PVA=="),
			"an unset cert_scope must not drop the root a deployed target was publishing")
		Expect(string(data["ca.crl"])).To(ContainSubstring("T1VSUw=="))
		Expect(string(data["ca.crl"])).To(ContainSubstring("VVBTVFJFQU0="),
			"an unset crl_scope must not drop the ancestor CRLs this feature publishes")
	})

	It("publishes the whole chain under chain", func() {
		data := exportWith("chain", "chain")
		Expect(string(data["ca.crt"])).To(Equal(certChain))
		Expect(string(data["ca.crl"])).To(Equal(crlChain))
	})

	It("publishes the trust anchor under root", func() {
		// root is positional: the last block, whatever it is. It is a trust
		// anchor only if the imported bundle was a complete chain, which
		// nothing currently enforces — see the scopes section of
		// docs/kubernetes-export.md.
		data := exportWith("root", "")
		Expect(string(data["ca.crt"])).To(ContainSubstring("Uk9PVA=="))
		Expect(string(data["ca.crt"])).NotTo(ContainSubstring("SU5URVJNRURJQVRF"))
		Expect(string(data["ca.crt"])).NotTo(ContainSubstring("TUlERExF"),
			"root must be the last block, not merely a later one")
	})

	It("applies the same scoping to a ConfigMap target", func() {
		// Secret and ConfigMap build their data through different methods.
		// Asserting only the Secret leaves the ConfigMap free to regress to
		// whole-chain output with the suite green.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind:      "ConfigMap",
			Metadata:  k8sexport.Metadata{Name: "trust", Namespace: "ns1"},
			Cert:      true,
			CRL:       true,
			CertScope: "root",
			CRLScope:  "self",
		}}}
		Expect(cfg.Validate()).To(Succeed())
		Expect(k8sexport.New(client, *cfg, src, "", nil).ExportAll(ctx)).To(Succeed())

		cm, err := client.CoreV1().ConfigMaps("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(cm.Data["ca.crt"]).To(ContainSubstring("Uk9PVA=="))
		Expect(cm.Data["ca.crt"]).NotTo(ContainSubstring("SU5URVJNRURJQVRF"))
		// A narrowing crl_scope, not "chain": ScopeChain short-circuits inside
		// scoped() and returns the blob untouched, so asserting it would hold
		// with the CRL scoping deleted from the ConfigMap path entirely.
		Expect(cm.Data["ca.crl"]).To(ContainSubstring("T1VSUw=="))
		Expect(cm.Data["ca.crl"]).NotTo(ContainSubstring("VVBTVFJFQU0="),
			"crl_scope: self must narrow the ConfigMap the same way it narrows a Secret")
	})

	DescribeTable("is unchanged for a single-block chain, whichever scope is asked for",
		// A CA that issued its own root stores one block, so all three scopes
		// agree there and the setting is a no-op. It is the CA that imported a
		// chain where the scopes differ at all, which is what the specs above
		// cover.
		func(scope string) {
			single := "-----BEGIN CERTIFICATE-----\nT05MWQ==\n-----END CERTIFICATE-----\n"
			src = stubSource{cert: []byte(single), crl: []byte(crlChain)}
			Expect(string(exportWith(scope, "chain")["ca.crt"])).To(Equal(single))
		},
		Entry("defaulted", ""),
		Entry("chain", "chain"),
		Entry("root", "root"),
	)

	It("publishes block 0 for self even when block 0 is not this CA's", func() {
		// scoped is positional: self takes blocks[0] and root takes the last.
		// That rests on an invariant enforced in another package -- orderCRLChain
		// puts this CA's own CRL first -- and that invariant is knowingly
		// violable: a CA whose stored block 0 is an ancestor's CRL starts and
		// serves rather than refusing, a deliberate availability trade-off made
		// on the read path.
		//
		// So self can publish an ancestor's CRL under ca.crl, and a consumer
		// checking revocation against it sees none of this CA's revocations.
		// Pinning the behaviour rather than changing it: the export layer has no
		// way to identify which block is ours, and refusing here would turn a
		// tolerated read-path state into an export outage. The detector is the
		// warning the read path already emits.
		upstreamFirst := "-----BEGIN X509 CRL-----\nVVBTVFJFQU0=\n-----END X509 CRL-----\n" +
			"-----BEGIN X509 CRL-----\nT1VSUw==\n-----END X509 CRL-----\n"
		src = stubSource{cert: []byte(certChain), crl: []byte(upstreamFirst)}

		data := exportWith("self", "self")
		Expect(string(data["ca.crl"])).To(ContainSubstring("VVBTVFJFQU0="),
			"self is positional, so a foreign block 0 is what gets published")
		Expect(string(data["ca.crl"])).NotTo(ContainSubstring("T1VSUw=="))
	})

	// scoped() and validate() have to agree about what an unset scope means, and
	// only validate() is exercised by everything above -- every other spec here
	// calls Validate() first, which fills the scopes in. A Target built in code
	// and exported without validation is the case where scoped() answers alone,
	// and answering "self" there would narrow silently: the failure the chain
	// default exists to prevent, reachable by a missed Validate() call.
	It("publishes the whole chain for a target whose scopes were never validated", func() {
		cfg := k8sexport.Config{Targets: []k8sexport.Target{{
			Kind:     "Secret",
			Metadata: k8sexport.Metadata{Name: "trust", Namespace: "ns1"},
			Cert:     true,
			CRL:      true,
			CertKey:  "ca.crt",
			CRLKey:   "ca.crl",
		}}}
		Expect(k8sexport.New(client, cfg, src, "", nil).ExportAll(ctx)).To(Succeed())

		sec, err := client.CoreV1().Secrets("ns1").Get(ctx, "trust", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(string(sec.Data["ca.crt"])).To(Equal(certChain),
			"an unset cert_scope must mean the whole chain here too")
		Expect(string(sec.Data["ca.crl"])).To(Equal(crlChain),
			"an unset crl_scope must mean the whole chain here too")
	})

	// Validate compares against the constants exactly, so "Chain" or " chain "
	// is an unknown scope and is refused at startup rather than silently
	// narrowing what a target publishes. Pinning it because the failure mode of
	// a lenient parse is invisible: a typo would be accepted and would export
	// block 0, which looks like a working target.
	DescribeTable("refuses a scope that differs only in case or whitespace",
		func(scope string) {
			cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
				Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, Cert: true, CertScope: scope,
			}}}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("invalid cert_scope")))
		},
		Entry("capitalised", "Chain"),
		Entry("upper case", "SELF"),
		Entry("leading space", " chain"),
		Entry("trailing space", "chain "),
	)

	// The same strictness on the CRL side, which has its own switch in
	// validate() and its own set of accepted values (no "root"), so the cert
	// half passing says nothing about it.
	DescribeTable("refuses a crl_scope that differs only in case or whitespace",
		func(scope string) {
			cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
				Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, CRL: true, CRLScope: scope,
			}}}
			Expect(cfg.Validate()).To(MatchError(ContainSubstring("invalid crl_scope")))
		},
		Entry("capitalised", "Chain"),
		Entry("upper case", "SELF"),
		Entry("trailing space", "self "),
	)

	It("rejects an unknown cert scope", func() {
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, Cert: true, CertScope: "everything",
		}}}
		Expect(cfg.Validate()).To(MatchError(ContainSubstring("invalid cert_scope")))
	})

	It("rejects root as a CRL scope", func() {
		// A CRL chain has no single anchor: the root's own CRL is just one of
		// its members.
		cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
			Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, CRL: true, CRLScope: "root",
		}}}
		Expect(cfg.Validate()).To(MatchError(ContainSubstring("invalid crl_scope")))
	})
})
