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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/k8sexport"
)

var _ = Describe("Config", func() {
	Describe("Enabled", func() {
		It("is false for an empty config", func() {
			cfg := &k8sexport.Config{}
			Expect(cfg.Enabled()).To(BeFalse())
		})

		It("is true once a target is configured", func() {
			cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
				Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, CRL: true,
			}}}
			Expect(cfg.Enabled()).To(BeTrue())
		})
	})

	Describe("Validate", func() {
		Context("with valid targets", func() {
			It("applies defaults for a Secret target", func() {
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
					Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true, CRL: true,
				}}}
				Expect(cfg.Validate()).To(Succeed())

				Expect(cfg.FieldManager).To(Equal("openvox-ca"))
				t := cfg.Targets[0]
				Expect(t.Kind).To(Equal("Secret"))
				// type is left empty so the exporter does not own the field.
				Expect(t.Type).To(BeEmpty())
				Expect(t.CertKey).To(Equal("ca.crt"))
				Expect(t.CRLKey).To(Equal("ca.crl"))
			})

			DescribeTable("normalises kind case-insensitively",
				func(kind, want string) {
					cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
						Kind: kind, Metadata: k8sexport.Metadata{Name: "trust"}, CRL: true,
					}}}
					Expect(cfg.Validate()).To(Succeed())
					Expect(cfg.Targets[0].Kind).To(Equal(want))
				},
				Entry("lowercase secret", "secret", "Secret"),
				Entry("canonical Secret", "Secret", "Secret"),
				Entry("lowercase configmap", "configmap", "ConfigMap"),
				Entry("canonical ConfigMap", "ConfigMap", "ConfigMap"),
				Entry("mixed-case CONFIGMAP", "CONFIGMAP", "ConfigMap"),
			)

			It("does not default a type for ConfigMap targets", func() {
				cfg := &k8sexport.Config{Targets: []k8sexport.Target{{
					Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "trust"}, CRL: true,
				}}}
				Expect(cfg.Validate()).To(Succeed())
				Expect(cfg.Targets[0].Type).To(BeEmpty())
				Expect(cfg.Targets[0].CRLKey).To(Equal("ca.crl"))
			})

			It("preserves an explicit field manager and keys", func() {
				cfg := &k8sexport.Config{
					FieldManager: "my-mgr",
					Targets: []k8sexport.Target{{
						Kind: "Secret", Metadata: k8sexport.Metadata{Name: "trust"}, Cert: true,
						CertKey: "tls.crt", Type: "kubernetes.io/tls",
					}},
				}
				Expect(cfg.Validate()).To(Succeed())
				Expect(cfg.FieldManager).To(Equal("my-mgr"))
				Expect(cfg.Targets[0].CertKey).To(Equal("tls.crt"))
				Expect(cfg.Targets[0].Type).To(Equal("kubernetes.io/tls"))
			})
		})

		Context("with invalid targets", func() {
			DescribeTable("rejects",
				func(t k8sexport.Target, msg string) {
					cfg := &k8sexport.Config{Targets: []k8sexport.Target{t}}
					err := cfg.Validate()
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(msg))
				},
				Entry("missing kind", k8sexport.Target{Metadata: k8sexport.Metadata{Name: "x"}, CRL: true}, "kind is required"),
				Entry("invalid kind", k8sexport.Target{Kind: "Deployment", Metadata: k8sexport.Metadata{Name: "x"}, CRL: true}, "invalid kind"),
				Entry("missing name", k8sexport.Target{Kind: "Secret", CRL: true}, "metadata.name is required"),
				Entry("neither cert nor crl", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}}, "at least one of cert or crl"),
				Entry("type on ConfigMap", k8sexport.Target{Kind: "ConfigMap", Metadata: k8sexport.Metadata{Name: "x"}, CRL: true, Type: "Opaque"}, "type is only valid for Secret"),
				Entry("colliding keys", k8sexport.Target{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "x"}, Cert: true, CRL: true, CertKey: "ca.pem", CRLKey: "ca.pem"}, "must differ"),
			)
		})

		It("reports the offending target index", func() {
			cfg := &k8sexport.Config{Targets: []k8sexport.Target{
				{Kind: "Secret", Metadata: k8sexport.Metadata{Name: "ok"}, CRL: true},
				{Kind: "bogus", Metadata: k8sexport.Metadata{Name: "bad"}, CRL: true},
			}}
			err := cfg.Validate()
			Expect(err).To(MatchError(ContainSubstring("target 1")))
		})
	})
})
