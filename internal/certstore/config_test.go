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

package certstore_test

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"go.yaml.in/yaml/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/certstore"
)

// decode parses a `managed_certs:` document the way the server's own config
// loader does, so these specs exercise the YAML keys an operator writes rather
// than the Go fields behind them. A key that was renamed or mistyped fails
// here, which a struct literal would not notice.
func decode(doc string) certstore.Config {
	GinkgoHelper()
	var wrapper struct {
		Certs certstore.Config `yaml:"managed_certs"`
	}
	Expect(yaml.Unmarshal([]byte(doc), &wrapper)).To(Succeed())
	return wrapper.Certs
}

func decodeErr(doc string) error {
	var wrapper struct {
		Certs certstore.Config `yaml:"managed_certs"`
	}
	return yaml.Unmarshal([]byte(doc), &wrapper)
}

// minimal is the smallest entry that validates: a certname, one name, a renew
// window, and a store.
const minimal = `
managed_certs:
  - certname: puppetserver.openvox.svc.cluster.local
    names: [puppetserver]
    renew_before: 720h
    store:
      secret:
        name: puppetserver-tls
        namespace: openvox
`

var _ = Describe("the managed_certs configuration", func() {
	// The specs below reach ca.CertSpec through Build, which is the only
	// consumer, so they assert what the mechanism is actually handed.
	build := func(cfg certstore.Config) []ca.ManagedCert {
		GinkgoHelper()
		Expect(cfg.Validate()).To(Succeed())
		managed, err := cfg.Build(certstore.Deps{
			CACerts: stubCA{pem: []byte("CA")},
			Client:  fake.NewClientset(),
		})
		Expect(err).NotTo(HaveOccurred())
		return managed
	}

	Describe("durations", func() {
		It("reads Go duration syntax", func() {
			cfg := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    ttl: 2160h
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`)
			Expect(cfg[0].TTL.AsDuration()).To(Equal(2160 * time.Hour))
			Expect(cfg[0].RenewBefore.AsDuration()).To(Equal(720 * time.Hour))
		})

		// `ttl: 2160` could mean hours or seconds, and guessing either is worse
		// than refusing. time.ParseDuration names the mistake for us.
		It("refuses a bare number rather than guessing a unit", func() {
			err := decodeErr(`
managed_certs:
  - certname: a.example.com
    names: [a]
    ttl: 2160
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`)
			Expect(err).To(MatchError(ContainSubstring("missing unit")))
			Expect(err).To(MatchError(ContainSubstring("2160h")))
		})
	})

	// The headline requirement of this block. A CA whose default grants a
	// 24-hour overlap has to let one entry say "no overlap at all", and a key
	// that could not tell `0` from absent would lose it silently: both would
	// arrive as a zero Duration, and the mechanism reads an unset value as
	// "inherit the CA's".
	Describe("revoke_after, which distinguishes zero from unset", func() {
		It("leaves the CA's own window in force when the key is absent", func() {
			managed := build(decode(minimal))
			Expect(managed[0].Spec.SupersedeAfter).To(BeNil())
		})

		It("carries an explicit zero through as a value, not an absence", func() {
			managed := build(decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    revoke_after: 0
    store: {files: {cert: /c.pem, key: /k.pem}}
`))
			Expect(managed[0].Spec.SupersedeAfter).NotTo(BeNil())
			Expect(*managed[0].Spec.SupersedeAfter).To(BeZero())
		})

		It("carries a window through", func() {
			managed := build(decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    revoke_after: 6h
    store: {files: {cert: /c.pem, key: /k.pem}}
`))
			Expect(*managed[0].Spec.SupersedeAfter).To(Equal(6 * time.Hour))
		})

		It("refuses a negative window", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    revoke_after: -1h
    store: {files: {cert: /c.pem, key: /k.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("revoke_after")))
		})
	})

	Describe("inheritance from the CA-wide settings", func() {
		// Unset means inherit, and the inheriting is the mechanism's job. This
		// package must hand it a zero value rather than a built-in, or there
		// would be two answers to what `leaf_validity_days` governs.
		It("leaves ttl and the key settings at zero when they are unset", func() {
			managed := build(decode(minimal))
			Expect(managed[0].Spec.TTL).To(BeZero())
			Expect(managed[0].Spec.KeyConfig).To(Equal(ca.KeyConfig{}))
		})

		It("carries a per-certificate key algorithm and size through", func() {
			managed := build(decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    key_algo: ecdsa
    key_size: 256
    store: {files: {cert: /c.pem, key: /k.pem}}
`))
			Expect(managed[0].Spec.KeyConfig).To(Equal(ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}))
		})

		It("refuses a key configuration that could never be issued", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    key_algo: rsa
    key_size: 1024
    store: {files: {cert: /c.pem, key: /k.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("1024")))
		})
	})

	Describe("usages", func() {
		It("leaves the pair every other issuance path uses when unset", func() {
			managed := build(decode(minimal))
			Expect(managed[0].Spec.ExtKeyUsage).To(BeNil())
		})

		It("narrows to what the entry asks for", func() {
			managed := build(decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    usages: [serverAuth]
    store: {files: {cert: /c.pem, key: /k.pem}}
`))
			Expect(managed[0].Spec.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
		})

		// crypto/x509 de-duplicates extended key usages neither on write nor on
		// parse, so a repeated usage would reach the certificate twice.
		It("de-duplicates a repeated usage", func() {
			managed := build(decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    usages: [clientAuth, ClientAuth]
    store: {files: {cert: /c.pem, key: /k.pem}}
`))
			Expect(managed[0].Spec.ExtKeyUsage).To(Equal([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}))
		})

		It("refuses a usage this block does not offer", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    usages: [codeSigning]
    store: {files: {cert: /c.pem, key: /k.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("codeSigning")))
			Expect(err).To(MatchError(ContainSubstring("serverAuth")))
		})
	})

	Describe("what a spec must say", func() {
		DescribeTable("refuses an entry that could never issue",
			func(doc, wantMessage string) {
				err := decode(doc).Validate()
				Expect(err).To(MatchError(ContainSubstring(wantMessage)))
			},

			Entry("no certname", `
managed_certs:
  - names: [a]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`, "subject"),

			// With no promotion and no names the certificate would carry no
			// subjectAltName extension at all, and RFC 2818 clients ignore the
			// Common Name -- so it would be refused for every name including
			// its own, while looking perfectly well-formed.
			Entry("no names of any kind", `
managed_certs:
  - certname: a.example.com
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`, "at least one subject alternative name"),

			Entry("no renew window", `
managed_certs:
  - certname: a.example.com
    names: [a]
    store: {files: {cert: /c.pem, key: /k.pem}}
`, "renew_before must be positive"),

			Entry("a certname the CA's grammar refuses", `
managed_certs:
  - certname: "../etc/passwd"
    names: [a]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`, "path traversal"),
		)

		// One inventory slot per subject: two entries for one certname
		// serialise on the same lock and each pass finds the other's
		// certificate failing its own spec, for ever.
		It("refuses two entries for one certname", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {files: {cert: /c1.pem, key: /k1.pem}}
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {files: {cert: /c2.pem, key: /k2.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("managed_certs[0]")))
			Expect(err).To(MatchError(ContainSubstring("inventory slot")))
		})
	})

	// A managed certificate may be named by DNS, IP, email or URI, and at least
	// one of some kind is required. A component reached at a fixed address has
	// nothing else to be named by, which is the case that makes it concrete.
	Describe("the other three kinds of name", func() {
		It("carries IP, email and URI names through alongside DNS", func() {
			managed := build(decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    ip_addresses: [10.0.0.5, "2001:db8::1"]
    email_addresses: [ca@example.com]
    uris: ["spiffe://example.com/ns/openvox/sa/a"]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`))
			spec := managed[0].Spec
			Expect(spec.DNSNames).To(Equal([]string{"a"}))
			Expect(spec.IPAddresses).To(HaveLen(2))
			// net.IP has a 4-byte and a 16-byte form for the same address and
			// x509 does not promise which it returns, so this compares by
			// value rather than bytewise.
			Expect(spec.IPAddresses[0].Equal(net.ParseIP("10.0.0.5"))).To(BeTrue())
			Expect(spec.IPAddresses[1].Equal(net.ParseIP("2001:db8::1"))).To(BeTrue())
			Expect(spec.EmailAddresses).To(Equal([]string{"ca@example.com"}))
			Expect(spec.URIs).To(HaveLen(1))
			Expect(spec.URIs[0].String()).To(Equal("spiffe://example.com/ns/openvox/sa/a"))
		})

		It("accepts an entry named only by IP address", func() {
			managed := build(decode(`
managed_certs:
  - certname: a.example.com
    ip_addresses: [10.0.0.5]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`))
			Expect(managed[0].Spec.DNSNames).To(BeEmpty())
			Expect(managed[0].Spec.IPAddresses).To(HaveLen(1))
		})

		// net.ParseIP returns nil for anything it cannot read, and a nil net.IP
		// marshals into an empty SAN entry rather than failing -- so a typo
		// would otherwise reach the certificate as a name matching nothing, on
		// a certificate that looks perfectly well-formed.
		It("refuses an address it cannot parse, naming the string", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    ip_addresses: ["10.0.0.256"]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("10.0.0.256")))
			Expect(err).To(MatchError(ContainSubstring("not an IP address")))
		})

		// url.Parse accepts a bare word as a relative reference, and a
		// uniformResourceIdentifier SAN that is not absolute names nothing a
		// verifier can compare against.
		It("refuses a URI with no scheme, and guesses what was meant", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    uris: [puppetserver]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("must be absolute")))
			Expect(err).To(MatchError(ContainSubstring("`names`")))
		})
	})

	Describe("reuse_key", func() {
		It("generates a fresh key on every renewal by default", func() {
			Expect(build(decode(minimal))[0].Spec.ReuseKey).To(BeFalse())
		})

		It("pins the stored key when the entry asks for it", func() {
			managed := build(decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    reuse_key: true
    store: {files: {cert: /c.pem, key: /k.pem}}
`))
			Expect(managed[0].Spec.ReuseKey).To(BeTrue())
		})
	})

	Describe("the store, which is configuration and never inference", func() {
		It("refuses an entry that names no store", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("store must name where the certificate lives")))
			Expect(err).To(MatchError(ContainSubstring("never inferred")))
		})

		It("refuses an entry that names both", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store:
      secret: {name: s}
      files: {cert: /c.pem, key: /k.pem}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("exactly one place")))
		})

		It("refuses a Secret store with no name", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {namespace: openvox}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("store.secret.name is required")))
		})

		// Two certificates in one Secret would each remove the other's keys,
		// because a manager that stops sending a key it owns deletes it.
		It("refuses two entries storing into one Secret", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: shared, namespace: openvox}}
  - certname: b.example.com
    names: [b]
    renew_before: 720h
    store: {secret: {name: shared, namespace: openvox}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("openvox/shared")))
			Expect(err).To(MatchError(ContainSubstring("remove the other's keys")))
		})

		// The sibling of the export-overlap case, and the same class: an entry
		// omitting its namespace and one spelling out the pod's own are the
		// same Secret. There is no weaker fallback here -- both entries apply
		// under one shared field manager, so each reads the other's apply entry
		// as its own and no conflict is ever raised.
		It("refuses two entries in one Secret when only one names the namespace", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: shared-tls, namespace: openvox}}
  - certname: b.example.com
    names: [b]
    renew_before: 720h
    store: {secret: {name: shared-tls}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("shared-tls")))
			Expect(err).To(MatchError(ContainSubstring("resolves to")))
		})

		It("still allows the same Secret name in two namespaces both spelled out", func() {
			Expect(decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: shared-tls, namespace: openvox}}
  - certname: b.example.com
    names: [b]
    renew_before: 720h
    store: {secret: {name: shared-tls, namespace: puppet}}
`).Validate()).To(Succeed())
		})

		It("refuses a relative path, which resolves differently in each way of running the CA", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {files: {cert: ssl/cert.pem, key: /k.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("absolute path")))
		})

		// Cleaned before comparison, so a second spelling of the same path is
		// the same path. Without that both entries validate and then replace
		// each other's certificate on every pass, for ever.
		It("refuses two entries writing one file under different spellings", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {files: {cert: /etc/ssl/cert.pem, key: /k1.pem}}
  - certname: b.example.com
    names: [b]
    renew_before: 720h
    store: {files: {cert: /etc/ssl/../ssl//cert.pem, key: /k2.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("/etc/ssl/cert.pem")))
		})

		It("refuses two entries writing one file", func() {
			err := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {files: {cert: /shared.pem, key: /k1.pem}}
  - certname: b.example.com
    names: [b]
    renew_before: 720h
    store: {files: {cert: /shared.pem, key: /k2.pem}}
`).Validate()
			Expect(err).To(MatchError(ContainSubstring("/shared.pem")))
		})
	})

	Describe("what a caller has to provide", func() {
		It("needs no Kubernetes client for a file-only configuration", func() {
			cfg := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`)
			Expect(cfg.NeedsKubernetes()).To(BeFalse())
			_, err := cfg.Build(certstore.Deps{CACerts: stubCA{pem: []byte("CA")}})
			Expect(err).NotTo(HaveOccurred())
		})

		It("says so when a Secret store has no client", func() {
			cfg := decode(minimal)
			Expect(cfg.NeedsKubernetes()).To(BeTrue())
			_, err := cfg.Build(certstore.Deps{CACerts: stubCA{pem: []byte("CA")}})
			Expect(err).To(MatchError(ContainSubstring("inside a pod")))
		})

		It("falls back to the CA pod's namespace only where an entry omits one", func() {
			cfg := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: a-tls}}
`)
			Expect(cfg.NeedsDefaultNamespace()).To(BeTrue())
			Expect(decode(minimal).NeedsDefaultNamespace()).To(BeFalse())

			_, err := cfg.Build(certstore.Deps{
				CACerts: stubCA{pem: []byte("CA")}, Client: fake.NewClientset(),
			})
			Expect(err).To(MatchError(ContainSubstring("could not be resolved")))
		})

		// The other half of that branch. The spec above pins the failure to
		// resolve a namespace; this pins the resolution itself, which decides
		// whose namespace a component's private key is written into. Asserted
		// by writing through the built store rather than by reading the config
		// back, so the namespace has to survive all the way to the apply.
		It("writes into the CA pod's namespace when an entry omits one", func() {
			cfg := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: a-tls}}
`)
			Expect(cfg.Validate()).To(Succeed())
			client := fake.NewClientset()
			managed, err := cfg.Build(certstore.Deps{
				CACerts:          stubCA{pem: []byte("CA")},
				Client:           client,
				DefaultNamespace: "ca-system",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(managed[0].Save(context.Background(), []byte("CERT"), []byte("KEY"))).To(Succeed())

			sec, err := client.CoreV1().Secrets("ca-system").
				Get(context.Background(), "a-tls", metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(sec.Data).To(HaveKeyWithValue("tls.crt", []byte("CERT")))
		})

		// The third of Build's entry guards. Its two siblings are covered
		// above; without this one the assertion depth across them is uneven,
		// and a file-only deployment is the case a caller is likeliest to
		// build a nil CACerts for.
		It("says so when no CA certificate source is supplied", func() {
			_, err := decode(minimal).Build(certstore.Deps{Client: fake.NewClientset()})
			Expect(err).To(MatchError(ContainSubstring("CA certificate chain")))
		})
	})

	// Both features write ca.crt under different field managers, and the
	// exporter forces every apply. Sharing a Secret would churn the object for
	// ever without anything looking broken, which is the kind of fault found
	// months later.
	Describe("the overlap with kubernetes_export", func() {
		It("refuses a Secret that is also an export target", func() {
			err := decode(minimal).CheckExportOverlap([][2]string{{"openvox", "puppetserver-tls"}})
			Expect(err).To(MatchError(ContainSubstring("kubernetes_export target")))
			Expect(err).To(MatchError(ContainSubstring("openvox/puppetserver-tls")))
		})

		It("allows an export target that is a different Secret", func() {
			Expect(decode(minimal).CheckExportOverlap([][2]string{{"openvox", "ca-trust"}})).To(Succeed())
		})

		// The collision the check used to miss, and the ordinary shape rather
		// than an exotic one: the export's own documentation shows `namespace`
		// as optional, so one side spelling it out and the other omitting it is
		// what an operator actually writes. Both resolve to the pod's namespace
		// and both then apply ca.crt to the same object, for ever.
		It("refuses a collision where the managed entry omits the namespace", func() {
			cfg := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: shared-tls}}
`)
			err := cfg.CheckExportOverlap([][2]string{{"ca-system", "shared-tls"}})
			Expect(err).To(MatchError(ContainSubstring("shared-tls")))
		})

		It("refuses it the other way round too, with the export target omitting one", func() {
			cfg := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {secret: {name: shared-tls, namespace: ca-system}}
`)
			err := cfg.CheckExportOverlap([][2]string{{"", "shared-tls"}})
			Expect(err).To(MatchError(ContainSubstring("shared-tls")))
		})

		It("has nothing to say about a file store", func() {
			cfg := decode(`
managed_certs:
  - certname: a.example.com
    names: [a]
    renew_before: 720h
    store: {files: {cert: /c.pem, key: /k.pem}}
`)
			Expect(cfg.CheckExportOverlap([][2]string{{"openvox", "anything"}})).To(Succeed())
		})
	})

	Describe("the subject the mechanism is handed", func() {
		It("passes the certname and names through verbatim", func() {
			managed := build(decode(minimal))
			Expect(managed).To(HaveLen(1))
			Expect(managed[0].Spec.Subject).To(Equal("puppetserver.openvox.svc.cluster.local"))
			// Verbatim: the certname is not promoted into the SAN list, because
			// promote_cn_to_san governs what a submitted request may ask for
			// and there is no request here.
			Expect(managed[0].Spec.DNSNames).To(Equal([]string{"puppetserver"}))
		})

		It("gives every entry a store", func() {
			managed := build(decode(minimal))
			Expect(managed[0].Load).NotTo(BeNil())
			Expect(managed[0].Save).NotTo(BeNil())
		})
	})
})
