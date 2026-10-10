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

// White-box: the arms below are reached through podNamespaceFrom, the
// unexported seam PodNamespace delegates to. Registers into the package's one
// suite in k8sclient_suite_test.go.
package k8sclient

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The namespace this returns is where a Secret store writes when its entry does
// not name one, so a wrong answer puts a component's private key in the wrong
// namespace, and an answer that is wrong by being empty would name no namespace
// at all. Each arm is asserted on the message as well as on the failure,
// because both are read by an operator who has to tell "not in a pod" from
// "in a pod with no token mounted" -- a distinction PodNamespace's own doc
// comment insists the caller must not collapse.
var _ = Describe("reading the pod's own namespace", func() {
	var dir string

	BeforeEach(func() { dir = GinkgoT().TempDir() })

	It("returns the namespace the file holds", func() {
		path := filepath.Join(dir, "namespace")
		Expect(os.WriteFile(path, []byte("openvox"), 0o600)).To(Succeed())

		Expect(podNamespaceFrom(path)).To(Equal("openvox"))
	})

	// The mount ends with a newline in a real pod, so an implementation that
	// skipped the trim would return a namespace no API call can use.
	It("trims the trailing newline a real mount carries", func() {
		path := filepath.Join(dir, "namespace")
		Expect(os.WriteFile(path, []byte("openvox\n"), 0o600)).To(Succeed())

		Expect(podNamespaceFrom(path)).To(Equal("openvox"))
	})

	It("names the path when the file is not there", func() {
		path := filepath.Join(dir, "absent")

		ns, err := podNamespaceFrom(path)

		Expect(ns).To(BeEmpty())
		Expect(err).To(MatchError(ContainSubstring("reading pod namespace from")))
		Expect(err).To(MatchError(ContainSubstring(path)),
			"an operator needs to know which path was consulted")
	})

	// Distinct from absent, and distinctly reported: a file that exists and
	// holds nothing usable is not the same situation as no file, and returning
	// "" with a nil error would hand a caller an empty namespace that reads as
	// "use the default" further down.
	DescribeTable("refuses a file that holds no namespace",
		func(content string) {
			path := filepath.Join(dir, "namespace")
			Expect(os.WriteFile(path, []byte(content), 0o600)).To(Succeed())

			ns, err := podNamespaceFrom(path)

			Expect(ns).To(BeEmpty())
			Expect(err).To(MatchError(ContainSubstring("is empty")))
			Expect(err).To(MatchError(ContainSubstring(path)))
		},
		Entry("entirely empty", ""),
		Entry("a single newline", "\n"),
		Entry("whitespace only", "   \t\n  "),
	)
})
