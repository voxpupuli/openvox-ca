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
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	accorev1 "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/voxpupuli/openvox-ca/internal/certstore"
)

// stubCA is a CACertSource returning fixed bytes, or a fixed error.
type stubCA struct {
	pem []byte
	err error
}

func (s stubCA) GetCACert(context.Context) ([]byte, error) { return s.pem, s.err }

// The fake clientset used here is the field-managed one (fake.NewClientset),
// which implements server-side apply properly: it records managedFields per
// key, reports an unforced write over another manager's field as a conflict,
// and reassigns a field to whoever last forced it. Every claim these specs make
// about apply semantics is therefore exercised rather than asserted, which
// matters because none of it can be settled by reading this repository.
var _ = Describe("SecretStore", func() {
	const (
		ns   = "openvox"
		name = "puppetserver-tls"
	)

	var (
		ctx    context.Context
		client *fake.Clientset
		src    stubCA
	)

	BeforeEach(func() {
		ctx = context.Background()
		client = fake.NewClientset()
		src = stubCA{pem: []byte("CA-CHAIN-PEM")}
	})

	newStore := func(cfg certstore.SecretConfig) *certstore.SecretStore {
		cfg.Name = name
		return certstore.NewSecretStore(client, cfg, ns, src)
	}

	get := func() *corev1.Secret {
		GinkgoHelper()
		sec, err := client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		return sec
	}

	// applyAs writes data into the Secret under some other manager's name, the
	// way a co-tenant controller or an operator with `kubectl apply` would.
	applyAs := func(manager string, force bool, data map[string][]byte, labels map[string]string) error {
		ac := accorev1.Secret(name, ns)
		if data != nil {
			ac = ac.WithData(data)
		}
		if labels != nil {
			ac = ac.WithLabels(labels)
		}
		_, err := client.CoreV1().Secrets(ns).Apply(ctx, ac,
			metav1.ApplyOptions{FieldManager: manager, Force: force})
		return err
	}

	Describe("Load", func() {
		It("reports an absent Secret as absent material rather than an error", func() {
			certPEM, keyPEM, err := newStore(certstore.SecretConfig{}).Load(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).To(BeEmpty())
			Expect(keyPEM).To(BeEmpty())
		})

		It("reads back what Save wrote", func() {
			s := newStore(certstore.SecretConfig{})
			Expect(s.Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			certPEM, keyPEM, err := s.Load(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).To(Equal([]byte("CERT")))
			Expect(keyPEM).To(Equal([]byte("KEY")))
		})

		It("reports a Secret holding only half a pair, so the decision can replace it", func() {
			Expect(applyAs("someone-else", false,
				map[string][]byte{"tls.crt": []byte("CERT")}, nil)).To(Succeed())

			certPEM, keyPEM, err := newStore(certstore.SecretConfig{}).Load(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).To(Equal([]byte("CERT")))
			Expect(keyPEM).To(BeEmpty())
		})

		// A read failure is not absence. Reporting it as absence would make
		// every pass reissue for as long as the API server is unreachable,
		// each one superseding the last.
		It("fails when the Secret cannot be read at all", func() {
			client.PrependReactor("get", "secrets",
				func(ktesting.Action) (bool, runtime.Object, error) {
					return true, nil, errors.New("apiserver is having a moment")
				})

			_, _, err := newStore(certstore.SecretConfig{}).Load(ctx)
			Expect(err).To(MatchError(ContainSubstring("apiserver is having a moment")))
			Expect(err).To(MatchError(ContainSubstring(ns + "/" + name)))
		})
	})

	Describe("Save", func() {
		It("writes the certificate, the key and the CA chain together, as a TLS Secret", func() {
			Expect(newStore(certstore.SecretConfig{}).Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			sec := get()
			Expect(sec.Data).To(HaveKeyWithValue("tls.crt", []byte("CERT")))
			Expect(sec.Data).To(HaveKeyWithValue("tls.key", []byte("KEY")))
			Expect(sec.Data).To(HaveKeyWithValue("ca.crt", []byte("CA-CHAIN-PEM")))
			Expect(sec.Type).To(Equal(corev1.SecretTypeTLS))
		})

		It("merges configured labels and annotations with the mandatory managed-by label", func() {
			Expect(newStore(certstore.SecretConfig{
				Labels:      map[string]string{"app": "puppetserver"},
				Annotations: map[string]string{"owner": "platform"},
			}).Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			sec := get()
			Expect(sec.Labels).To(HaveKeyWithValue("app", "puppetserver"))
			Expect(sec.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
			Expect(sec.Annotations).To(HaveKeyWithValue("owner", "platform"))
		})

		It("does not let configuration mask ownership", func() {
			Expect(newStore(certstore.SecretConfig{
				Labels: map[string]string{"app.kubernetes.io/managed-by": "someone-else"},
			}).Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			Expect(get().Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
		})

		// The reason all three keys move together, exercised rather than
		// asserted: a manager that stops sending a key it owns removes it. A
		// Save that wrote the certificate and key but not the chain would
		// delete ca.crt from under whatever was mounting it.
		It("removes a key its manager stops sending", func() {
			s := newStore(certstore.SecretConfig{})
			Expect(s.Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())
			Expect(get().Data).To(HaveKey("ca.crt"))

			// The same field manager, now sending only two of the three.
			ac := accorev1.Secret(name, ns).WithData(map[string][]byte{
				"tls.crt": []byte("CERT"), "tls.key": []byte("KEY"),
			})
			_, err := client.CoreV1().Secrets(ns).Apply(ctx, ac,
				metav1.ApplyOptions{FieldManager: "openvox-ca-managed-certs", Force: true})
			Expect(err).NotTo(HaveOccurred())

			Expect(get().Data).NotTo(HaveKey("ca.crt"))
		})

		// The chain is read before anything is applied, so a chain that cannot
		// be read fails the write rather than producing a Secret whose ca.crt
		// has been removed because we stopped sending it.
		It("writes nothing when the CA chain cannot be read", func() {
			src = stubCA{err: errors.New("storage is down")}

			err := newStore(certstore.SecretConfig{}).Save(ctx, []byte("CERT"), []byte("KEY"))
			Expect(err).To(MatchError(ContainSubstring("storage is down")))

			_, getErr := client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
			Expect(getErr).To(HaveOccurred(), "no Secret should have been created")
		})

		It("refuses to write an empty CA chain", func() {
			src = stubCA{pem: nil}

			err := newStore(certstore.SecretConfig{}).Save(ctx, []byte("CERT"), []byte("KEY"))
			Expect(err).To(MatchError(ContainSubstring("empty CA certificate chain")))
		})
	})

	Describe("adoption versus drift", func() {
		// Adoption: material the CA has never owned. Overwriting it is not the
		// CA's call, so the write fails and names both remedies.
		It("refuses a Secret the CA has never owned, and leaves it untouched", func() {
			Expect(applyAs("flux", false, map[string][]byte{
				"tls.crt": []byte("THEIRS-CERT"), "tls.key": []byte("THEIRS-KEY"),
			}, nil)).To(Succeed())

			err := newStore(certstore.SecretConfig{}).Save(ctx, []byte("OURS"), []byte("OURS-KEY"))
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring("adopt_existing")))
			Expect(err).To(MatchError(ContainSubstring("delete the Secret")))

			Expect(get().Data).To(HaveKeyWithValue("tls.crt", []byte("THEIRS-CERT")))
		})

		It("takes it when adopt_existing is set", func() {
			Expect(applyAs("flux", false, map[string][]byte{
				"tls.crt": []byte("THEIRS-CERT"), "tls.key": []byte("THEIRS-KEY"),
			}, nil)).To(Succeed())

			Expect(newStore(certstore.SecretConfig{AdoptExisting: true}).
				Save(ctx, []byte("OURS"), []byte("OURS-KEY"))).To(Succeed())

			Expect(get().Data).To(HaveKeyWithValue("tls.crt", []byte("OURS")))
		})

		// Drift, and the trap the issue records: an external edit reassigns the
		// edited key to the editing manager, so the CA no longer owns tls.crt
		// even on a Secret it created. A test of "do we still own this key"
		// would read our own Secret as somebody else's and refuse for ever,
		// with adopt_existing left off as it should be. The check is whether
		// the CA has an apply entry at all, and this is the spec that separates
		// the two.
		It("reconciles its own Secret after an external edit, without adopt_existing", func() {
			s := newStore(certstore.SecretConfig{})
			Expect(s.Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			// kubectl patch, in effect: a different manager forcing our key.
			Expect(applyAs("kubectl", true,
				map[string][]byte{"tls.crt": []byte("HAND-EDITED")}, nil)).To(Succeed())
			Expect(get().Data).To(HaveKeyWithValue("tls.crt", []byte("HAND-EDITED")))

			// Proof the trap is real: an unforced apply from us now conflicts,
			// so a store that reasoned only from "did this write conflict"
			// would treat its own Secret as an adoption.
			Expect(applyAs("openvox-ca-managed-certs", false,
				map[string][]byte{"tls.crt": []byte("CERT")}, nil)).To(HaveOccurred())

			Expect(s.Save(ctx, []byte("CERT-2"), []byte("KEY-2"))).To(Succeed())
			Expect(get().Data).To(HaveKeyWithValue("tls.crt", []byte("CERT-2")))
		})

		// The second half of the ownership test, which the specs above leave to
		// prose. A managedFields entry under our own manager name but a
		// non-Apply operation is somebody running `kubectl --field-manager`,
		// not this CA writing -- so it must not count as ours. Without this the
		// Operation clause can be deleted and every other spec stays green,
		// because they discriminate on the manager name alone.
		It("does not treat a non-Apply entry under our own manager name as ours", func() {
			Expect(applyAs("flux", false, map[string][]byte{
				"tls.crt": []byte("THEIRS"),
			}, nil)).To(Succeed())

			sec, err := client.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			sec.ManagedFields = append(sec.ManagedFields, metav1.ManagedFieldsEntry{
				Manager:   "openvox-ca-managed-certs",
				Operation: metav1.ManagedFieldsOperationUpdate,
			})
			Expect(client.Tracker().Update(
				corev1.SchemeGroupVersion.WithResource("secrets"), sec, ns)).To(Succeed())

			err = newStore(certstore.SecretConfig{}).Save(ctx, []byte("OURS"), []byte("OURS-KEY"))
			Expect(err).To(MatchError(ContainSubstring("adopt_existing")),
				"an Update entry under our name is not this CA having written the Secret")
		})

		It("reverts a hand-edited value rather than preserving it", func() {
			s := newStore(certstore.SecretConfig{})
			Expect(s.Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())
			Expect(applyAs("kubectl", true,
				map[string][]byte{"ca.crt": []byte("NOT-OUR-CHAIN")}, nil)).To(Succeed())

			Expect(s.Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())
			Expect(get().Data).To(HaveKeyWithValue("ca.crt", []byte("CA-CHAIN-PEM")))
		})
	})

	Describe("co-tenancy", func() {
		It("leaves another manager's labels alone", func() {
			Expect(applyAs("flux", false, nil,
				map[string]string{"kustomize.toolkit.fluxcd.io/name": "platform"})).To(Succeed())

			Expect(newStore(certstore.SecretConfig{Labels: map[string]string{"app": "puppetserver"}}).
				Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			sec := get()
			Expect(sec.Labels).To(HaveKeyWithValue("kustomize.toolkit.fluxcd.io/name", "platform"))
			Expect(sec.Labels).To(HaveKeyWithValue("app", "puppetserver"))
		})

		// Removing a label from the configuration removes it from the object,
		// and only it. One of the two quiet consequences of owning labels per
		// key; the other -- taking a label another manager owns, silently,
		// under force -- is the price of reconciling drift at all.
		It("removes only the label it stopped setting", func() {
			cfg := certstore.SecretConfig{Labels: map[string]string{
				"app": "puppetserver", "tier": "control",
			}}
			Expect(newStore(cfg).Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())
			Expect(get().Labels).To(HaveKeyWithValue("tier", "control"))

			cfg.Labels = map[string]string{"app": "puppetserver"}
			Expect(newStore(cfg).Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			sec := get()
			Expect(sec.Labels).NotTo(HaveKey("tier"))
			Expect(sec.Labels).To(HaveKeyWithValue("app", "puppetserver"))
			Expect(sec.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "openvox-ca"))
		})
	})
})
