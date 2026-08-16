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

package config

import (
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.yaml.in/yaml/v3"
)

var _ = Describe("absIfSet", func() {
	It("passes an empty string through unchanged", func() {
		Expect(absIfSet("")).To(BeEmpty())
	})

	It("resolves a relative path to its absolute form", func() {
		got := absIfSet("certs/ca.pem")
		Expect(filepath.IsAbs(got)).To(BeTrue())
		want, err := filepath.Abs("certs/ca.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(want))
	})

	It("leaves an already-absolute, clean path unchanged", func() {
		const p = "/etc/puppet-ca/ca.pem"
		Expect(absIfSet(p)).To(Equal(p))
	})

	It("cleans an absolute path that contains redundant elements", func() {
		// filepath.Abs runs filepath.Clean, so even an absolute input is
		// normalised — the function is not a pure pass-through for absolute
		// paths, despite its name implying it only acts when "set".
		Expect(absIfSet("/etc/puppet-ca/../puppet-ca/ca.pem")).To(Equal("/etc/puppet-ca/ca.pem"))
		Expect(absIfSet("/etc/puppet-ca/")).To(Equal("/etc/puppet-ca"))
	})
})

// ResolvedPolicy is the coercion three call sites used to hand-write, and the
// newest of those omitted it — enforcement refused clients as `require` while
// the gauge for those clients was never published. Validation rejects a bad
// string, but it runs on one construction path, so a consumer reached by any
// other route must still land on the safe value.
var _ = Describe("ClientCAConfig.ResolvedPolicy", func() {
	DescribeTable("folds anything unrecognised to require",
		func(configured, want string) {
			c := &ClientCAConfig{ClientRevocationPolicy: configured}
			Expect(c.ResolvedPolicy()).To(Equal(want))
		},
		Entry("unset", "", RevocationRequire),
		Entry("require", RevocationRequire, RevocationRequire),
		Entry("check", RevocationCheck, RevocationCheck),
		Entry("skip", RevocationSkip, RevocationSkip),
		Entry("a trailing space, the usual YAML slip", "require ", RevocationRequire),
		Entry("wrong case, which Validate also refuses", "Require", RevocationRequire),
		Entry("something arbitrary", "off", RevocationRequire),
	)

	// The direction that matters: an unrecognised value must not fold to the
	// permissive end, which is what would turn a typo into revocation checking
	// switched off across a foreign domain.
	It("never folds an unrecognised value to skip", func() {
		for _, bad := range []string{"", "nonsense", "SKIP", "none", "disabled"} {
			c := &ClientCAConfig{ClientRevocationPolicy: bad}
			Expect(c.ResolvedPolicy()).NotTo(Equal(RevocationSkip),
				"a value nobody recognises must never disable revocation checking")
		}
	})
})

// The interval the client-CRL reload job runs on. The accessor's own arms are
// worth pinning, but so are the two names an operator writes: a wrong yaml tag
// leaves the job silently on the default with a valid-looking config file. The
// tag is covered below; the env key is bound in cmd/openvox-ca, so it is
// covered beside its siblings in that package's applyServerEnv table.
var _ = Describe("ClientCAConfig.ClientCRLRefreshInterval", func() {
	It("defaults to an hour when unset", func() {
		Expect((&ClientCAConfig{}).ClientCRLRefreshInterval()).To(Equal(time.Hour))
	})

	It("honours a configured value", func() {
		Expect((&ClientCAConfig{ClientCRLRefreshIntervalSec: 300}).ClientCRLRefreshInterval()).
			To(Equal(5 * time.Minute))
	})

	It("is reachable under the name an operator writes", func() {
		var c ClientCAConfig
		Expect(yaml.Unmarshal([]byte("client_crl_refresh_interval_sec: 300\n"), &c)).To(Succeed())
		Expect(c.ClientCRLRefreshInterval()).To(Equal(5*time.Minute),
			"a wrong yaml tag would leave this at the default and nothing else would say so")
	})

	It("falls back to the default for a non-positive value", func() {
		// Reaching time.NewTicker with zero or negative panics, so the guard is
		// load-bearing rather than tidy.
		Expect((&ClientCAConfig{ClientCRLRefreshIntervalSec: 0}).ClientCRLRefreshInterval()).To(Equal(time.Hour))
		Expect((&ClientCAConfig{ClientCRLRefreshIntervalSec: -30}).ClientCRLRefreshInterval()).To(Equal(time.Hour))
	})
})
