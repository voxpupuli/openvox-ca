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

package main

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("checkManifest", func() {
	// A manifest shaped like `helm template` output: comment headers, a
	// document separator before every object, and objects of other kinds.
	manifest := func(config string) string {
		return "---\n# Source: openvox-ca/templates/serviceaccount.yaml\n" +
			"apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: openvox-ca\n" +
			"---\n# Source: openvox-ca/templates/configmap.yaml\n" +
			"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: openvox-ca\n" +
			"data:\n  config.yaml: |\n" + config
	}

	It("accepts a config the server would start with, and counts it", func() {
		n, err := checkManifest(manifest("    cadir: /var/lib/openvox-ca\n    port: 8140\n"))
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(1))
	})

	It("refuses an unknown key, naming the ConfigMap and the key", func() {
		_, err := checkManifest(manifest("    cadir: /x\n    encrypt_ca_kye: true\n"))
		Expect(err).To(MatchError(And(
			ContainSubstring(`ConfigMap "openvox-ca"`),
			ContainSubstring(`unknown key "encrypt_ca_kye"`))))
	})

	// The case that motivated the check: a value of the wrong shape, which
	// no manifest validator looks inside a ConfigMap to see.
	It("refuses a value the server cannot decode", func() {
		_, err := checkManifest(manifest("    etcd_endpoints: https://a:2379,https://b:2379\n"))
		Expect(err).To(MatchError(ContainSubstring("into []string")))
	})

	// Matched by the key it carries, not by name: a release named anything
	// else renames the ConfigMap, and must not slip past.
	It("checks a ConfigMap whatever it is named", func() {
		_, err := checkManifest("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-release-openvox-ca\n" +
			"data:\n  config.yaml: |\n    prot: 8140\n")
		Expect(err).To(MatchError(And(
			ContainSubstring(`ConfigMap "my-release-openvox-ca"`),
			ContainSubstring(`unknown key "prot"`))))
	})

	It("checks nothing, without error, when no ConfigMap carries config.yaml", func() {
		n, err := checkManifest("---\napiVersion: v1\nkind: ConfigMap\n" +
			"metadata:\n  name: other\ndata:\n  autosign.conf: |\n    *.example.com\n")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeZero())
	})

	It("ignores a config.yaml carried by something other than a ConfigMap", func() {
		n, err := checkManifest("---\napiVersion: v1\nkind: Secret\n" +
			"metadata:\n  name: s\nstringData:\n  x: y\ndata:\n  config.yaml: bm90IGNvbmZpZw==\n")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(BeZero())
	})
})

var _ = Describe("checkManifests", func() {
	write := func(name, body string) string {
		path := filepath.Join(GinkgoT().TempDir(), name)
		Expect(os.WriteFile(path, []byte(body), 0o644)).To(Succeed())
		return path
	}
	configMap := func(name, config string) string {
		return "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n" +
			"data:\n  config.yaml: |\n" + config
	}

	It("counts across manifests and names the file that failed", func() {
		good := write("good.yaml", configMap("openvox-ca", "    port: 8140\n"))
		bad := write("bad.yaml", configMap("openvox-ca", "    prot: 8140\n"))

		n, err := checkManifests([]string{good})
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(1))

		_, err = checkManifests([]string{good, bad})
		Expect(err).To(MatchError(And(ContainSubstring(bad), ContainSubstring(`unknown key "prot"`))))
	})

	// A good manifest first, so that a reader which skipped the missing one
	// would still have counted something and the floor would not fire in its
	// place: the error has to be the read's own.
	It("fails on a manifest it cannot read", func() {
		good := write("good.yaml", configMap("openvox-ca", "    port: 8140\n"))
		_, err := checkManifests([]string{good, filepath.Join(GinkgoT().TempDir(), "absent.yaml")})
		Expect(err).To(MatchError(ContainSubstring("absent.yaml")))
		Expect(err.Error()).NotTo(ContainSubstring("no ConfigMap carrying"))
	})

	// A stream it cannot decode is an error, not the end of the stream: every
	// ConfigMap after the bad document would otherwise go unchecked.
	It("fails on a manifest document it cannot decode", func() {
		bad := write("bad.yaml", "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata: [not, a, map]\n"+
			configMap("openvox-ca", "    prot: 8140\n"))
		_, err := checkManifests([]string{bad})
		Expect(err).To(MatchError(ContainSubstring("reading the rendered manifest")))
	})

	// The floor: an extraction that found nothing anywhere would otherwise
	// report success over every fixture.
	It("fails when no manifest carried a config.yaml", func() {
		none := write("none.yaml", "---\napiVersion: v1\nkind: Service\nmetadata:\n  name: x\n")
		_, err := checkManifests([]string{none})
		Expect(err).To(MatchError(ContainSubstring("no ConfigMap carrying config.yaml")))
	})
})
