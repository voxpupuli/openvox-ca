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

// The recorder needs Docker to run, so CI never does; these specs pin the
// refusals that keep a hand-run recording from damaging anything, which need
// no container.

var _ = Describe("checkReplaceable", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	It("accepts an out that does not exist yet", func() {
		Expect(checkReplaceable(filepath.Join(dir, "contract"))).To(Succeed())
	})

	It("accepts a contract this recorder wrote", func() {
		Expect(os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o600)).To(Succeed())
		Expect(checkReplaceable(dir)).To(Succeed())
	})

	DescribeTable("refuses anything else, since a run replaces out wholesale",
		func(setup func(out string) string) {
			Expect(checkReplaceable(setup(dir))).To(MatchError(ContainSubstring("is not a recorded contract")))
		},
		Entry("an empty directory", func(out string) string { return out }),
		Entry("a directory whose README is someone else's", func(out string) string {
			Expect(os.WriteFile(filepath.Join(out, "README.md"), []byte("# My project\n"), 0o600)).To(Succeed())
			return out
		}),
		Entry("a plain file", func(out string) string {
			f := filepath.Join(out, "file")
			Expect(os.WriteFile(f, []byte(contractHeader), 0o600)).To(Succeed())
			return f
		}),
	)
})

var _ = Describe("readRegular", func() {
	var src *os.Root

	BeforeEach(func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(dir, "ca_crt.pem"), []byte("PEM"), 0o600)).To(Succeed())
		Expect(os.Mkdir(filepath.Join(dir, "signed"), 0o750)).To(Succeed())
		host := filepath.Join(GinkgoT().TempDir(), "secret")
		Expect(os.WriteFile(host, []byte("host"), 0o600)).To(Succeed())
		Expect(os.Symlink(host, filepath.Join(dir, "ca_key.pem"))).To(Succeed())
		var err error
		src, err = os.OpenRoot(dir)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(src.Close)
	})

	It("reads a regular file", func() {
		Expect(readRegular(src, "ca_crt.pem")).To(Equal([]byte("PEM")))
	})

	It("refuses a symlink, which docker cp carries over and which could name a host file", func() {
		_, err := readRegular(src, "ca_key.pem")
		Expect(err).To(MatchError(ContainSubstring("not a regular file")))
	})

	It("refuses a directory", func() {
		_, err := readRegular(src, "signed")
		Expect(err).To(MatchError(ContainSubstring("not a regular file")))
	})
})

var _ = Describe("pinnedImage", func() {
	var compose string

	BeforeEach(func() {
		compose = filepath.Join(GinkgoT().TempDir(), "compose.yml")
	})

	It("reads the OpenVox Server image, skipping a commented-out one and other images", func() {
		Expect(os.WriteFile(compose, []byte(`services:
  old-puppet:
    # image: ghcr.io/openvoxproject/openvoxserver:8.0.0-main
    image: ghcr.io/openvoxproject/openvoxserver:8.14.1-main@sha256:abc
  test-runner:
    image: openvox-ca-integ:latest
`), 0o600)).To(Succeed())
		Expect(pinnedImage(compose)).To(Equal("ghcr.io/openvoxproject/openvoxserver:8.14.1-main@sha256:abc"))
	})

	It("fails when no OpenVox Server image is pinned", func() {
		Expect(os.WriteFile(compose, []byte("services:\n  x:\n    image: openvox-ca-integ:latest\n"), 0o600)).To(Succeed())
		_, err := pinnedImage(compose)
		Expect(err).To(MatchError(ContainSubstring("pins no")))
	})
})

var _ = Describe("the cited release", func() {
	DescribeTable("releaseTag takes the image tag up to its first dash",
		func(image, want string) {
			Expect(releaseTag(image)).To(Equal(want))
		},
		Entry("a variant tag with a digest", imagePrefix+"8.14.1-main@sha256:abc", "8.14.1"),
		Entry("a plain tag with a digest", imagePrefix+"8.14.1@sha256:abc", "8.14.1"),
		Entry("a plain tag", imagePrefix+"8.15.0", "8.15.0"),
	)

	It("accepts an image built from the release the citations were checked against", func() {
		Expect(checkCitedRelease(imagePrefix + citedTag + "-main@sha256:abc")).To(Succeed())
	})

	It("refuses an image built from any other release", func() {
		Expect(checkCitedRelease(imagePrefix + "99.0.0-main@sha256:abc")).To(MatchError(ContainSubstring("move citedTag")))
	})
})

var _ = Describe("swapIn", func() {
	var dir, staging, out string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		staging = filepath.Join(dir, "contract.recording-1")
		out = filepath.Join(dir, "contract")
		Expect(os.Mkdir(staging, 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(staging, "new"), nil, 0o600)).To(Succeed())
	})

	It("replaces the previous contract, leaving nothing beside it", func() {
		Expect(os.Mkdir(out, 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(out, "old"), nil, 0o600)).To(Succeed())
		Expect(swapIn(staging, out)).To(Succeed())
		Expect(filepath.Join(out, "new")).To(BeAnExistingFile())
		Expect(filepath.Join(out, "old")).NotTo(BeAnExistingFile())
		entries, err := os.ReadDir(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
	})

	It("puts a first contract in place", func() {
		Expect(swapIn(staging, out)).To(Succeed())
		Expect(filepath.Join(out, "new")).To(BeAnExistingFile())
	})

	It("puts the previous contract back when the new one cannot be moved in", func() {
		Expect(os.Mkdir(out, 0o750)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(out, "old"), nil, 0o600)).To(Succeed())
		Expect(swapIn(filepath.Join(dir, "missing"), out)).NotTo(Succeed())
		Expect(filepath.Join(out, "old")).To(BeAnExistingFile())
	})
})
