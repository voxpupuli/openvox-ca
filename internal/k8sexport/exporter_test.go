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

		v, found := metricValue(reg, "puppetca_k8s_export_applies_total", map[string]string{
			"kind": "Secret", "namespace": "ns1", "name": "good", "result": "success",
		})
		Expect(found).To(BeTrue())
		Expect(v).To(Equal(1.0))

		v, found = metricValue(reg, "puppetca_k8s_export_applies_total", map[string]string{
			"kind": "ConfigMap", "namespace": "ns1", "name": "bad", "result": "error",
		})
		Expect(found).To(BeTrue())
		Expect(v).To(Equal(1.0))

		// Only the successful target gets a last-success timestamp, and only
		// the failing target gets a last-error timestamp.
		v, found = metricValue(reg, "puppetca_k8s_export_last_success_timestamp_seconds",
			map[string]string{"kind": "Secret", "namespace": "ns1", "name": "good"})
		Expect(found).To(BeTrue())
		Expect(v).To(BeNumerically(">", 0))

		_, found = metricValue(reg, "puppetca_k8s_export_last_success_timestamp_seconds",
			map[string]string{"kind": "ConfigMap", "namespace": "ns1", "name": "bad"})
		Expect(found).To(BeFalse())

		v, found = metricValue(reg, "puppetca_k8s_export_last_error_timestamp_seconds",
			map[string]string{"kind": "ConfigMap", "namespace": "ns1", "name": "bad"})
		Expect(found).To(BeTrue())
		Expect(v).To(BeNumerically(">", 0))

		_, found = metricValue(reg, "puppetca_k8s_export_last_error_timestamp_seconds",
			map[string]string{"kind": "Secret", "namespace": "ns1", "name": "good"})
		Expect(found).To(BeFalse())
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
})
