//go:build mage

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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/version"
)

var _ = Describe("releaseVersion", func() {
	// go test runs with the package directory (the repository root) as the
	// working directory, so the real internal/version/version.go is read:
	// this pins the textual parse against the actual constant, catching any
	// reformatting of the Version line that would break the workflows' and
	// hook's sed-based parsers of the same shape.
	It("round-trips the real Version constant", func() {
		ver, err := releaseVersion()
		Expect(err).NotTo(HaveOccurred())
		Expect(ver).To(Equal(version.Version))
	})
})

var _ = Describe("bareSemverRe", func() {
	DescribeTable("accepts bare semver with optional pre-release suffix",
		func(v string) { Expect(bareSemverRe.MatchString(v)).To(BeTrue()) },
		Entry("release", "0.9.0"),
		Entry("release candidate", "0.9.0-rc1"),
		Entry("development version", "0.10.0-dev"),
		Entry("dotted pre-release", "1.2.3-alpha.1"),
	)

	DescribeTable("rejects anything else",
		func(v string) { Expect(bareSemverRe.MatchString(v)).To(BeFalse()) },
		Entry("v prefix", "v0.9.0"),
		Entry("two components", "0.9"),
		Entry("four components", "0.9.0.1"),
		Entry("empty", ""),
		Entry("trailing space", "0.9.0 "),
		Entry("bare suffix", "-rc1"),
	)
})

var _ = Describe("fipsCrossCC", func() {
	// The CC environment variable changes the result, so pin it to unset for
	// each spec and restore whatever the caller had afterwards.
	BeforeEach(func() {
		if orig, ok := os.LookupEnv("CC"); ok {
			Expect(os.Unsetenv("CC")).To(Succeed())
			DeferCleanup(os.Setenv, "CC", orig)
		}
	})

	It("returns empty when CC is already set in the environment", func() {
		Expect(os.Setenv("CC", "clang")).To(Succeed())
		DeferCleanup(os.Unsetenv, "CC")
		Expect(fipsCrossCC("arm64")).To(BeEmpty())
	})

	It("returns empty for an unknown architecture", func() {
		Expect(fipsCrossCC("riscv64")).To(BeEmpty())
	})

	// Pin the exact cross-compiler names: CI only ever builds each FIPS
	// variant natively, so a wrong name here would otherwise go undetected
	// until someone cross-builds locally.
	DescribeTable("maps cross architectures to the GNU cross compilers",
		func(goarch, cc string) {
			if runtime.GOOS == "linux" && runtime.GOARCH == goarch {
				Skip("native on this host: covered by the native-build spec")
			}
			Expect(fipsCrossCC(goarch)).To(Equal(cc))
		},
		Entry("amd64", "amd64", "x86_64-linux-gnu-gcc"),
		Entry("arm64", "arm64", "aarch64-linux-gnu-gcc"),
	)

	It("returns empty for a native Linux build", func() {
		if runtime.GOOS != "linux" {
			Skip("native FIPS builds only exist on Linux")
		}
		Expect(fipsCrossCC(runtime.GOARCH)).To(BeEmpty())
	})
})

var _ = Describe("repoSlugFromURL", func() {
	DescribeTable("derives owner/repo",
		func(url, want string) {
			slug, err := repoSlugFromURL(url)
			Expect(err).NotTo(HaveOccurred())
			Expect(slug).To(Equal(want))
		},
		Entry("SSH scp-like", "git@github.com:voxpupuli/openvox-ca.git", "voxpupuli/openvox-ca"),
		Entry("SSH scp-like without .git", "git@github.com:bootc/openvox-ca", "bootc/openvox-ca"),
		Entry("HTTPS", "https://github.com/voxpupuli/openvox-ca.git", "voxpupuli/openvox-ca"),
		Entry("HTTPS without .git", "https://github.com/voxpupuli/openvox-ca", "voxpupuli/openvox-ca"),
		Entry("ssh scheme", "ssh://git@github.com/owner/repo.git", "owner/repo"),
	)

	It("rejects a URL it cannot parse", func() {
		_, err := repoSlugFromURL("not-a-url")
		Expect(err).To(MatchError(ContainSubstring("could not derive owner/repo")))
	})
})

var _ = Describe("distVariants", func() {
	It("defines the four release variants with coherent build environments", func() {
		variants := distVariants()
		Expect(variants).To(HaveLen(4))

		names := map[string]bool{}
		for _, v := range variants {
			Expect(names).NotTo(HaveKey(v.name), "duplicate variant name")
			names[v.name] = true

			Expect(v.name).To(MatchRegexp(`^linux_(amd64|arm64)(_fips)?$`))
			Expect(v.env["GOOS"]).To(Equal("linux"))
			Expect(v.name).To(ContainSubstring(v.env["GOARCH"]))

			if _, fips := v.env["GOEXPERIMENT"]; fips {
				Expect(v.name).To(HaveSuffix("_fips"))
				Expect(v.env["GOEXPERIMENT"]).To(Equal("boringcrypto"))
				Expect(v.env["CGO_ENABLED"]).To(Equal("1"))
			} else {
				Expect(v.name).NotTo(HaveSuffix("_fips"))
				Expect(v.env["CGO_ENABLED"]).To(Equal("0"))
			}
		}
	})
})

var _ = Describe("release archive contents", func() {
	// These replace a CI job that built all four variants, unpacked each
	// tarball and grepped `tar -tvz` for the entries and their modes. The
	// properties it checked are properties of the manifest and of the archive
	// writer, neither of which needs a release build to exercise.
	Describe("distArchiveFiles", func() {
		files := distArchiveFiles([]string{"openvox-ca", "openvox-ca-ctl"})

		It("ships both binaries executable and the unit not", func() {
			Expect(files).To(Equal([]archiveEntry{
				{name: "openvox-ca", mode: 0755},
				{name: "openvox-ca-ctl", mode: 0755},
				{name: "openvox-ca.service", mode: 0644},
			}))
		})

		It("names a unit that is actually in the repository", func() {
			// The manifest names a file that is copied in at build time; a
			// rename under packaging/ would otherwise break nothing until a
			// tag is pushed, at which point the tag exists and no artefacts do.
			Expect(filepath.Join("packaging", "systemd", distUnitFile)).To(BeAnExistingFile())
		})
	})

	Describe("createTarGz", func() {
		It("writes each entry with the mode the manifest asked for", func() {
			// Not the mode of the staged file: the release must extract the
			// same way whatever umask it was built under.
			srcDir := GinkgoT().TempDir()
			for _, name := range []string{"openvox-ca", "openvox-ca.service"} {
				Expect(os.WriteFile(filepath.Join(srcDir, name), []byte(name), 0600)).To(Succeed())
			}
			archive := filepath.Join(GinkgoT().TempDir(), "out.tar.gz")

			Expect(createTarGz(archive, srcDir, []archiveEntry{
				{name: "openvox-ca", mode: 0755},
				{name: "openvox-ca.service", mode: 0644},
			})).To(Succeed())

			Expect(tarEntries(archive)).To(Equal(map[string]tarEntry{
				"openvox-ca":         {mode: 0755, body: "openvox-ca"},
				"openvox-ca.service": {mode: 0644, body: "openvox-ca.service"},
			}))
		})

		It("reports a source file that is not there", func() {
			archive := filepath.Join(GinkgoT().TempDir(), "out.tar.gz")
			err := createTarGz(archive, GinkgoT().TempDir(), []archiveEntry{{name: "absent", mode: 0755}})
			Expect(err).To(MatchError(os.ErrNotExist))
		})
	})
})

// tarEntry is one unpacked archive member: the mode it would extract as and
// its contents.
type tarEntry struct {
	mode int64
	body string
}

// tarEntries reads a gzipped tarball back into a name-keyed map, so a spec can
// assert the whole archive in one comparison rather than walking it.
func tarEntries(path string) map[string]tarEntry {
	GinkgoHelper()

	f, err := os.Open(path)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()

	gz, err := gzip.NewReader(f)
	Expect(err).NotTo(HaveOccurred())
	defer gz.Close()

	entries := map[string]tarEntry{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		Expect(err).NotTo(HaveOccurred())

		body, err := io.ReadAll(tr)
		Expect(err).NotTo(HaveOccurred())
		entries[hdr.Name] = tarEntry{mode: hdr.Mode, body: string(body)}
	}
	return entries
}

var _ = Describe("Release.Prepare", func() {
	// The bare-semver guard is Prepare's first statement, returning before
	// any git, gh, or filesystem side effect, so the rejection path is
	// hermetic — this pins both the wiring and that validation stays ahead
	// of the side effects.
	It("rejects a non-bare-semver version before any side effect", func() {
		err := Release{}.Prepare("v0.9.0")
		Expect(err).To(MatchError(ContainSubstring("is not bare semver")))
	})
})

var _ = Describe("Build.DistVariant", func() {
	It("rejects an unknown variant before building anything", func() {
		err := Build{}.DistVariant("nonsense")
		Expect(err).To(MatchError(ContainSubstring(`unknown dist variant "nonsense"`)))
		Expect(err).To(MatchError(ContainSubstring("linux_arm64_fips")), "error should list the known variants")
	})
})

var _ = Describe("workflowMatrixVariants", func() {
	yamlSrc := []byte(`
jobs:
  dist:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
            runner: ubuntu-latest
          - variant: linux_arm64
            runner: ubuntu-24.04-arm
  other:
    runs-on: ubuntu-latest
`)

	It("extracts the variant names from a job's matrix include list", func() {
		names, err := workflowMatrixVariants(yamlSrc, "dist")
		Expect(err).NotTo(HaveOccurred())
		Expect(names).To(Equal([]string{"linux_amd64", "linux_arm64"}))
	})

	It("errors on a missing job", func() {
		_, err := workflowMatrixVariants(yamlSrc, "absent")
		Expect(err).To(MatchError(ContainSubstring(`"absent" not found`)))
	})

	It("errors on a job without variant matrix entries", func() {
		_, err := workflowMatrixVariants(yamlSrc, "other")
		Expect(err).To(MatchError(ContainSubstring("no matrix include entries")))
	})
})

var _ = Describe("shellVariantList", func() {
	It("extracts the loop's variant names", func() {
		names, err := shellVariantList([]byte(`for variant in linux_amd64 linux_arm64_fips; do`))
		Expect(err).NotTo(HaveOccurred())
		Expect(names).To(Equal([]string{"linux_amd64", "linux_arm64_fips"}))
	})

	It("errors when no loop is present", func() {
		_, err := shellVariantList([]byte("nothing here"))
		Expect(err).To(MatchError(ContainSubstring("no 'for variant in")))
	})
})

var _ = Describe("verifyNolintlintCarveOut", func() {
	// Against the repository's real files. Asserting Succeed() alone would be
	// vacuous: nolintlintCarveOut returns (false, nil) when the carve-out is
	// genuinely gone, and verifyNolintlintCarveOutIn then has nothing to check,
	// so a respelled or reshaped rule would pass here as "removed". The
	// presence assertion is the floor on the .golangci.yml side.
	It("finds the real carve-out, and it matches the real golangci-lint pin", func() {
		golangciSrc, err := os.ReadFile(".golangci.yml")
		Expect(err).NotTo(HaveOccurred())

		present, err := nolintlintCarveOut(golangciSrc)
		Expect(err).NotTo(HaveOccurred())
		Expect(present).To(BeTrue(),
			"the carve-out must either be present and recognised here, or removed together with "+
				"verifyNolintlintCarveOut, these specs and the AGENTS.md paragraph (see openvox-ca#313)")

		Expect(verifyNolintlintCarveOut()).To(Succeed())

		// And the premise: the carve-out exists to keep two live gosec
		// suppressions suppressible. Without this, deleting them would leave
		// the rule and this guard demanding pin maintenance for nothing.
		src, err := os.ReadFile(nolintlintCarveOutFile)
		Expect(err).NotTo(HaveOccurred())
		// As wide as the suppression itself: the exclusion's text matches any
		// unused gosec directive in this file whose explanation mentions G703,
		// so counting one spelling would let a third directive in a different
		// one be silenced without this floor noticing.
		covered := regexp.MustCompile(`//nolint:\S*gosec\S*[^\n]*G703`)
		Expect(covered.FindAllString(string(src), -1)).To(HaveLen(2),
			"the carve-out protects exactly the two G703 directives in %s", nolintlintCarveOutFile)
	})

	Describe("drift detection", func() {
		carveOut := []byte(`
linters:
  exclusions:
    rules:
      - path: ` + nolintlintCarveOutPath + `
        linters:
          - nolintlint
        text: '` + nolintlintCarveOutText + `'
`)
		noCarveOut := []byte(`
linters:
  exclusions:
    rules:
      - linters:
          - staticcheck
        text: "QF1008"
`)
		ci := []byte("      - name: Install golangci-lint\n" +
			"        run: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" +
			nolintlintCarveOutPin + "\n")
		// Deliberately unreachable rather than the next plausible release.
		// The event this guard exists for is a renovate bump, and the
		// documented remedy is to set nolintlintCarveOutPin to the new pin --
		// so a fixture spelling "the next version" would one day equal the
		// constant, bytes.Replace would find nothing, and the specs built on
		// it would silently change meaning.
		const movedPin = "v99.0.0"
		moved := bytes.Replace(ci, []byte(nolintlintCarveOutPin), []byte(movedPin), 1)

		It("accepts the carve-out while the pin is the one it was reasoned against", func() {
			Expect(verifyNolintlintCarveOutIn(carveOut, ci)).To(Succeed())
		})

		// The whole point: the pin moves in an auto-merged renovate PR, and
		// nothing else in the repository would notice the carve-out had
		// outlived its justification.
		It("rejects a moved pin while the carve-out is still present", func() {
			Expect(verifyNolintlintCarveOutIn(carveOut, moved)).To(MatchError(
				And(ContainSubstring(movedPin),
					ContainSubstring(nolintlintCarveOutPin),
					ContainSubstring("securego/gosec#1733"),
					ContainSubstring("openvox-ca#313"))))
		})

		// Both remedies must be on offer. Deleting the carve-out is the wrong
		// one on the likelier branch, and it is the one the reader reaches for
		// when the message names no other.
		It("names updating the constant as well as deleting the carve-out", func() {
			Expect(verifyNolintlintCarveOutIn(carveOut, moved)).To(MatchError(
				And(ContainSubstring("delete the carve-out"),
					ContainSubstring("update nolintlintCarveOutPin"))))
		})

		// The removal outcome this guard exists to make reachable: once the
		// carve-out goes, the pin is free to move.
		It("accepts a moved pin once the carve-out is gone", func() {
			Expect(verifyNolintlintCarveOutIn(noCarveOut, moved)).To(Succeed())
		})

		// The floor on the ci.yml side. Comparing the two files to each other
		// is not enough: with no pin to read, a deleted install line would
		// otherwise pass as "nothing to check" rather than fail as drift.
		It("rejects a carve-out whose pin cannot be read at all", func() {
			Expect(verifyNolintlintCarveOutIn(carveOut, []byte("no install line here"))).To(MatchError(
				And(ContainSubstring("no golangci-lint pin"),
					ContainSubstring("openvox-ca#313"))))
		})

		// The floor on the .golangci.yml side, and the reason the rule is
		// found by compiling its path rather than comparing its bytes.
		// Dropping the escape leaves the exclusion working exactly as before,
		// so reading it as "removed" would retire the guard in silence.
		It("rejects a carve-out whose path was respelled but still covers the file", func() {
			respelt := bytes.Replace(carveOut,
				[]byte(nolintlintCarveOutPath), []byte("internal/storage/filelock.go"), 1)
			Expect(verifyNolintlintCarveOutIn(respelt, moved)).To(MatchError(
				And(ContainSubstring(`has path "internal/storage/filelock.go"`),
					ContainSubstring("nolintlintCarveOutPath"),
					ContainSubstring("openvox-ca#313"))))
		})

		// Widening the path is the same failure wearing a different hat: the
		// exclusion covers more than before and a byte comparison sees less.
		It("rejects a carve-out whose path was widened to the whole package", func() {
			widened := bytes.Replace(carveOut,
				[]byte(nolintlintCarveOutPath), []byte("internal/storage/"), 1)
			Expect(verifyNolintlintCarveOutIn(widened, ci)).To(MatchError(
				And(ContainSubstring(`has path "internal/storage/"`),
					ContainSubstring("nolintlintCarveOutPath"),
					ContainSubstring("openvox-ca#313"))))
		})

		// The narrowness is the load-bearing half. Reverting text to a bare
		// rule ID silences require-specific and require-explanation on this
		// file too, which is the finding that put the guard here.
		It("rejects a carve-out whose text was widened to the bare rule ID", func() {
			wide := bytes.Replace(carveOut,
				[]byte("'"+nolintlintCarveOutText+"'"), []byte(`"G703"`), 1)
			Expect(verifyNolintlintCarveOutIn(wide, ci)).To(MatchError(
				And(ContainSubstring(`has text "G703"`),
					ContainSubstring("require-specific"),
					ContainSubstring("openvox-ca#313"))))
		})

		// A rule on another path is not this carve-out and must not hold the
		// pin hostage.
		It("ignores a nolintlint exclusion on a different path", func() {
			other := bytes.Replace(carveOut,
				[]byte(nolintlintCarveOutPath), []byte(`internal/ca/other\.go`), 1)
			Expect(verifyNolintlintCarveOutIn(other, moved)).To(Succeed())
		})

		// The other half of the predicate, which no fixture exercised before:
		// an exclusion at this very path that does not name nolintlint is
		// somebody else's rule.
		It("ignores an exclusion on this path that names a different linter", func() {
			notNolintlint := bytes.Replace(carveOut, []byte("- nolintlint"), []byte("- gosec"), 1)
			Expect(verifyNolintlintCarveOutIn(notNolintlint, moved)).To(Succeed())
		})

		// An exclusion with no `path` applies to every file, so it covers
		// filelock.go more widely than ours. Reading it as "carve-out removed"
		// would free the pin while a broader suppression was in force.
		It("rejects a path-less nolintlint exclusion, which covers every file", func() {
			pathless := []byte(`
linters:
  exclusions:
    rules:
      - linters:
          - nolintlint
        text: '` + nolintlintCarveOutText + `'
`)
			Expect(string(pathless)).NotTo(ContainSubstring("path:"), "the fixture must really have no path")
			Expect(verifyNolintlintCarveOutIn(pathless, moved)).To(MatchError(
				And(ContainSubstring("nolintlintCarveOutPath"),
					ContainSubstring("openvox-ca#313"))))
		})

		// Two rules covering the file leaves the guard unable to say which one
		// it was written against.
		It("rejects more than one nolintlint exclusion covering the file", func() {
			doubled := append(append([]byte{}, carveOut...), []byte(`      - path: internal/storage/
        linters:
          - nolintlint
        text: "something else"
`)...)
			Expect(verifyNolintlintCarveOutIn(doubled, ci)).To(MatchError(
				ContainSubstring("must be the only one")))
		})

		// The sibling half of the linters predicate, and the axis round 4
		// found: golangci-lint applies a rule with no `linters` key to EVERY
		// linter, so this suppresses more than the carve-out does, not less.
		It("rejects an exclusion with no linters key, which covers every linter", func() {
			noLinters := []byte(`
linters:
  exclusions:
    rules:
      - path: ` + nolintlintCarveOutPath + `
        text: '` + nolintlintCarveOutText + `'
`)
			Expect(string(noLinters)).NotTo(ContainSubstring("linters:\n          -"),
				"the fixture must really have no linters list")
			Expect(verifyNolintlintCarveOutIn(noLinters, moved)).To(MatchError(
				And(ContainSubstring("names linters []"),
					ContainSubstring("openvox-ca#313"))))
		})

		// Naming more linters than nolintlint is a wider suppression wearing
		// the carve-out's shape.
		It("rejects a carve-out that names extra linters", func() {
			extra := bytes.Replace(carveOut,
				[]byte("          - nolintlint\n"), []byte("          - nolintlint\n          - errcheck\n"), 1)
			Expect(verifyNolintlintCarveOutIn(extra, ci)).To(MatchError(
				And(ContainSubstring("errcheck"),
					ContainSubstring("openvox-ca#313"))))
		})

		// exclusions.paths is a different config node with its own processor:
		// a matching pattern drops the file for every linter. Reading that as
		// "carve-out removed" would free the pin under a far wider suppression.
		It("rejects a file-level exclusions.paths entry covering the file", func() {
			viaPaths := []byte(`
linters:
  exclusions:
    paths:
      - internal/storage/filelock\.go
`)
			Expect(verifyNolintlintCarveOutIn(viaPaths, moved)).To(MatchError(
				And(ContainSubstring("every linter"),
					ContainSubstring("openvox-ca#313"))))
		})

		// paths-except is the same suppression stated in the negative: a
		// non-empty list that does not name the file excludes it from
		// everything.
		It("rejects a paths-except list that omits the file", func() {
			viaPathsExcept := []byte(`
linters:
  exclusions:
    paths-except:
      - internal/ca/
`)
			Expect(verifyNolintlintCarveOutIn(viaPathsExcept, moved)).To(MatchError(
				ContainSubstring("every linter")))
		})

		// The rule-level path-except clause, which had no fixture at all:
		// inverting its sense left every spec green. golangci-lint drops the
		// rule for a file its path-except matches, and keeps it otherwise, so
		// both senses need pinning.
		It("still sees a carve-out whose path-except does not match the file", func() {
			guarded := bytes.Replace(carveOut,
				[]byte("      - path: "+nolintlintCarveOutPath+"\n"),
				[]byte("      - path: "+nolintlintCarveOutPath+"\n        path-except: internal/ca/\n"), 1)
			Expect(string(guarded)).To(ContainSubstring("path-except:"))
			// Still the carve-out, so a moved pin must still be refused.
			Expect(verifyNolintlintCarveOutIn(guarded, moved)).To(MatchError(
				ContainSubstring("openvox-ca#313")))
		})

		It("ignores a rule whose path-except matches the file", func() {
			exempt := bytes.Replace(carveOut,
				[]byte("      - path: "+nolintlintCarveOutPath+"\n"),
				[]byte("      - path: "+nolintlintCarveOutPath+"\n        path-except: "+nolintlintCarveOutPath+"\n"), 1)
			// golangci-lint would not apply this rule to the file, so it is
			// not a suppression and must not hold the pin.
			Expect(verifyNolintlintCarveOutIn(exempt, moved)).To(Succeed())
		})

		It("rejects a rule path-except that is not a valid regexp", func() {
			bad := bytes.Replace(carveOut,
				[]byte("      - path: "+nolintlintCarveOutPath+"\n"),
				[]byte("      - path: "+nolintlintCarveOutPath+"\n        path-except: 'internal/ca/['\n"), 1)
			Expect(verifyNolintlintCarveOutIn(bad, ci)).To(MatchError(
				ContainSubstring(`exclusion path-except "internal/ca/[" is not a valid regexp`)))
		})

		// The other outcome of the file-level paths-except loop: a list that
		// DOES name the file exempts it from the file-level exclusion, so the
		// ordinary rules analysis must run rather than the "every linter"
		// refusal. Neutering this branch left every spec green.
		It("does not treat a paths-except naming the file as excluding it", func() {
			exempt := []byte(`
linters:
  exclusions:
    paths-except:
      - internal/ca/
      - ` + nolintlintCarveOutPath + `
    rules:
      - path: ` + nolintlintCarveOutPath + `
        linters:
          - nolintlint
        text: '` + nolintlintCarveOutText + `'
`)
			err := verifyNolintlintCarveOutIn(exempt, moved)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).NotTo(ContainSubstring("every linter"),
				"the file is exempt from the file-level exclusion, so the rules analysis must decide")
			Expect(err.Error()).To(ContainSubstring(movedPin))
		})

		It("rejects an exclusions.paths entry that is not a valid regexp", func() {
			bad := []byte(`
linters:
  exclusions:
    paths:
      - 'internal/storage/['
`)
			Expect(verifyNolintlintCarveOutIn(bad, ci)).To(MatchError(
				ContainSubstring(`exclusions.paths entry "internal/storage/[" is not a valid regexp`)))
		})

		// The parse floor. Without it an unreadable .golangci.yml would take
		// the absent branch and be read as "carve-out removed".
		It("reports a .golangci.yml it cannot parse", func() {
			Expect(verifyNolintlintCarveOutIn([]byte("linters: [\n"), ci)).To(MatchError(
				ContainSubstring(".golangci.yml:")))
		})

		// The premise recorded in golangciLintPinRe's comment -- that it and
		// renovate's custom manager cannot disagree about which token is the
		// pin -- checked against the real renovate.json rather than asserted.
		It("reads the same pin token renovate's custom manager matches", func() {
			renovateSrc, err := os.ReadFile("renovate.json")
			Expect(err).NotTo(HaveOccurred())
			var doc struct {
				CustomManagers []struct {
					DepNameTemplate string   `json:"depNameTemplate"`
					MatchStrings    []string `json:"matchStrings"`
				} `json:"customManagers"`
			}
			Expect(json.Unmarshal(renovateSrc, &doc)).To(Succeed())

			var patterns []string
			for _, m := range doc.CustomManagers {
				if strings.Contains(m.DepNameTemplate, "golangci-lint") {
					patterns = append(patterns, m.MatchStrings...)
				}
			}
			Expect(patterns).NotTo(BeEmpty(),
				"renovate must still own the golangci-lint pin; this guard's premise is that it does")

			ciSrc, err := os.ReadFile(filepath.Join(".github", "workflows", "ci.yml"))
			Expect(err).NotTo(HaveOccurred())
			ours := golangciLintPinRe.FindSubmatch(ciSrc)
			Expect(ours).NotTo(BeNil())

			matched := false
			for _, pattern := range patterns {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				if m := re.FindSubmatch(ciSrc); m != nil && bytes.Contains(m[0], ours[1]) {
					matched = true
				}
			}
			Expect(matched).To(BeTrue(),
				"renovate and golangciLintPinRe must find the same pin token in ci.yml")
		})

		// An unparseable path would make golangci-lint reject the config; it
		// must not read here as "does not cover the file".
		It("rejects an exclusion path that is not a valid regexp", func() {
			bad := bytes.Replace(carveOut, []byte(nolintlintCarveOutPath), []byte(`internal/storage/[`), 1)
			Expect(verifyNolintlintCarveOutIn(bad, ci)).To(MatchError(
				ContainSubstring(`exclusion path "internal/storage/[" is not a valid regexp`)))
		})
	})
})

var _ = Describe("verifyAutomergeLabelExclusion", func() {
	// Against the repository's real ci.yml: the clause must actually be there.
	It("finds the real auto-merge job excluding the signing-review label", func() {
		Expect(verifyAutomergeLabelExclusion()).To(Succeed())
	})

	Describe("drift detection", func() {
		good := []byte(`
jobs:
  automerge:
    if: >-
      github.event_name == 'pull_request'
      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')
      && github.event.pull_request.user.login == 'renovate[bot]'
    steps:
      - run: gh pr merge --auto --merge "$PR_URL"
`)

		It("accepts a merging job that excludes the label", func() {
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", good)).To(Succeed())
		})

		// The whole point: the clause is droppable in a tidy-up, and nothing
		// else in the repository would notice it had gone.
		It("rejects a merging job whose condition drops the label clause", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"), nil, 1)
			// Both clauses are gone, and the error must name both — this is
			// the spec that distinguishes "clause deleted" from the
			// partial-match case below.
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				And(ContainSubstring(`job "automerge"`),
					ContainSubstring("github.event.pull_request.labels"),
					ContainSubstring("review-signing-path"))))
		})

		// Naming the label but not reading it from the PR's labels is not an
		// exclusion, however plausibly it reads.
		It("rejects a condition that names the label without consulting the PR's labels", func() {
			bad := bytes.Replace(good,
				[]byte("!contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("github.event.pull_request.title != 'review-signing-path'"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// The clause is required whole, not in fragments. Flipping it while an
		// unrelated !contains(...) sits elsewhere leaves every fragment present
		// — the label name, the labels context, a negation — and inverts the
		// meaning anyway. This mutation passed an earlier fragment-based
		// version of the guard, which is why the contract is the whole clause.
		It("rejects an inverted clause even when another negation is present", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("      && contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"+
					"      && !contains(github.event.pull_request.title, 'WIP')"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// Exact on shape, free on spacing: the condition is a YAML block
		// scalar that people wrap and indent to taste, and a guard that failed
		// on a reflow would be reformatted away rather than obeyed.
		It("accepts the clause however it is spaced", func() {
			spaced := bytes.Replace(good,
				[]byte("!contains(github.event.pull_request.labels.*.name, 'review-signing-path')"),
				[]byte("!contains(  github.event.pull_request.labels.*.name,   'review-signing-path'  )"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", spaced)).To(Succeed())
		})

		// Dropping the '!' does not weaken the exclusion, it reverses it: the
		// job would then merge signing bumps unattended and nothing else. A
		// guard that passes the exact inversion of what it checks for is not
		// worth having, which is why the negation is a required clause and
		// not left to "consults, not constrains".
		It("rejects a condition whose label check is not negated", func() {
			bad := bytes.Replace(good, []byte("&& !contains("), []byte("&& contains("), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				And(ContainSubstring(`job "automerge"`), ContainSubstring("!contains("))))
			// And the reported clause is the whole expression a maintainer
			// must restore, not a fragment of it.
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("labels.*.name, 'review-signing-path')")))
		})

		// Comments never reach the parsed `if:` scalar, so naming the clauses
		// in one cannot satisfy the guard. Asserted rather than assumed: the
		// immunity comes from parsing the document instead of grepping it,
		// and a future rewrite to a text search would silently lose it.
		It("is not satisfied by a comment naming the required clauses", func() {
			bad := bytes.Replace(good,
				[]byte("      && !contains(github.event.pull_request.labels.*.name, 'review-signing-path')\n"),
				[]byte(""), 1)
			bad = bytes.Replace(bad, []byte("jobs:\n"),
				[]byte("jobs:\n  # github.event.pull_request.labels review-signing-path !contains(\n"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("never consults")))
		})

		// A guard that finds nothing to guard has abstained, not passed. If
		// auto-merge is renamed or rewritten to merge some other way, this
		// must go red rather than quiet — that is the failure mode where a
		// green check is actively misleading. The cost is accepted knowingly:
		// legitimately removing auto-merge will fail this until the guard goes
		// too. See the note at the merging == 0 branch.
		It("refuses to pass when no job merges pull requests at all", func() {
			bad := bytes.Replace(good, []byte("gh pr merge --auto --merge"), []byte("echo nothing to do"), 1)
			Expect(verifyAutomergeLabelExclusionIn("ci.yml", bad)).To(MatchError(
				ContainSubstring("no job runs `gh pr merge`")))
		})
	})
})

var _ = Describe("verifyDistVariants", func() {
	// Runs against the repository's real workflow files: this is the
	// cross-check that keeps ci.yml, release.yml, and distVariants() from
	// drifting apart (it also runs as part of `mage dev:check`).
	It("finds all hand-maintained variant lists in agreement", func() {
		Expect(verifyDistVariants()).To(Succeed())
	})

	// The failure branches are what make the guard a guard: feed synthetic
	// workflow contents with exactly one list out of agreement and assert
	// the error names the disagreeing location.
	Describe("drift detection", func() {
		// Synthetic workflow fragments agreeing with distVariants()
		// (linux_amd64, linux_arm64, linux_amd64_fips, linux_arm64_fips).
		goodCI := []byte(`
jobs:
  dist:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
          - variant: linux_arm64
          - variant: linux_amd64_fips
          - variant: linux_arm64_fips
`)
		goodRel := []byte(`
jobs:
  build:
    strategy:
      matrix:
        include:
          - variant: linux_amd64
          - variant: linux_arm64
          - variant: linux_amd64_fips
          - variant: linux_arm64_fips
  release:
    steps:
      - run: |
          for variant in linux_amd64 linux_arm64 linux_amd64_fips linux_arm64_fips; do
            ls -- openvox-ca_*_"$variant".tar.gz > /dev/null
            ls -- openvox-ca_*_"$variant".spdx.json > /dev/null
            ls -- openvox-ca_*_"$variant".cdx.json > /dev/null
          done
          if [ "$tarballs" -ne 4 ]; then
            exit 1
          fi
          if [ "$sboms" -ne 8 ]; then
            exit 1
          fi
          sha256sum -- *.tar.gz *.spdx.json *.cdx.json > checksums.txt
`)

		// The generate-sbom action's output formats, whose count must equal
		// sbomFormatsPerVariant.
		goodSBOM := []byte(`
        "$SYFT" scan "dir:$scan" \
          -o "spdx-json=dist/${base}.spdx.json" \
          -o "cyclonedx-json=dist/${base}.cdx.json"
`)

		It("accepts synthetic workflows that agree with distVariants", func() {
			Expect(verifyDistVariantsIn(goodCI, goodRel, goodSBOM)).To(Succeed())
		})

		It("rejects a drifted ci.yml dist matrix and names it", func() {
			badCI := bytes.Replace(goodCI, []byte("- variant: linux_arm64_fips"), []byte("- variant: linux_riscv64_fips"), 1)
			Expect(verifyDistVariantsIn(badCI, goodRel, goodSBOM)).To(MatchError(ContainSubstring("ci.yml dist job matrix")))
		})

		It("rejects a drifted release.yml build matrix and names it", func() {
			badRel := bytes.Replace(goodRel, []byte("          - variant: linux_amd64_fips\n"), nil, 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("release.yml build job matrix")))
		})

		It("rejects a drifted checksum-step shell loop and names it", func() {
			badRel := bytes.Replace(goodRel, []byte("for variant in linux_amd64 "), []byte("for variant in "), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("checksum-step shell loop")))
		})

		It("rejects a stale tarball-count literal and names the counts", func() {
			badRel := bytes.Replace(goodRel, []byte(`-ne 4`), []byte(`-ne 3`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("expects 3 tarballs")))
		})

		// The SBOM count is a multiple of the variant count rather than equal
		// to it, so it drifts independently of the tarball count: a variant
		// added everywhere else but missed in this literal lands here. (A
		// format added to generate-sbom is caught by the format-count specs
		// below, not by this one.)
		It("rejects a stale SBOM-count literal and names the counts", func() {
			badRel := bytes.Replace(goodRel, []byte(`-ne 8`), []byte(`-ne 4`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring("expects 4 SBOMs")))
		})

		// -lt rather than -ne: the check is present but no longer the shape
		// the guard parses, which is the same branch a deleted line takes.
		// The message quotes the pattern it wanted, so the operator mismatch
		// is visible rather than leaving a maintainer staring at a check that
		// is plainly on screen.
		It("rejects an SBOM-count check the guard cannot parse", func() {
			badRel := bytes.Replace(goodRel, []byte(`"$sboms" -ne 8`), []byte(`"$sboms" -lt 8`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(ContainSubstring(`no SBOMs-count check matching`)))
		})

		// sbomFormatsPerVariant is the multiplier the SBOM count is derived
		// from, and it mirrors the generate-sbom action. These two specs are
		// what stop it becoming an unchecked copy: they are the reason a
		// format added to the action alone cannot leave every other count
		// self-consistent and wrong.
		It("rejects a generate-sbom action emitting more formats than the constant", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`-o "cyclonedx-json=dist/${base}.cdx.json"`),
				[]byte("-o \"cyclonedx-json=dist/${base}.cdx.json\" \\\n          -o \"syft-json=dist/${base}.syft.json\""), 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring("emits 3 SBOM format(s)"), ContainSubstring("syft-json"))))
		})

		It("rejects a generate-sbom action emitting fewer formats than the constant", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`          -o "cyclonedx-json=dist/${base}.cdx.json"`), nil, 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(ContainSubstring("emits 1 SBOM format(s)")))
		})

		// Zero matches is not a miscount: the guard's own pattern stopped
		// matching, which is a different problem with a different fix, so it
		// gets a message naming the pattern rather than "emits 0".
		It("says which pattern stopped matching when it can see no output flags", func() {
			badSBOM := bytes.ReplaceAll(goodSBOM, []byte(`-o "`), []byte("--output "))
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring("no SBOM output flags matching"), ContainSubstring("[a-z0-9-]"))))
		})

		// The counts can agree while the names do not. Renaming one format's
		// output file leaves sbomFormatsPerVariant satisfied and still breaks
		// the release, because release.yml globs for the old extension — and
		// it breaks it at tag time, which is the failure this whole guard
		// family exists to move earlier.
		It("rejects a renamed SBOM output whose extension release.yml never globs for", func() {
			badSBOM := bytes.Replace(goodSBOM, []byte(`${base}.cdx.json`), []byte(`${base}.bom.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, goodRel, badSBOM)).To(MatchError(
				And(ContainSubstring(".bom.json"), ContainSubstring("but release.yml names"))))
		})

		It("rejects a release.yml that globs for an extension the action never writes", func() {
			badRel := bytes.Replace(goodRel, []byte(`"$variant".cdx.json`), []byte(`"$variant".bom.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(
				ContainSubstring("but release.yml names")))
		})

		// release.yml names each document in five places. Dropping one of them
		// keeps every name valid and every count above satisfied, so nothing
		// else here would notice — but the document would go unlisted at that
		// site. Drop it from the sha256sum operands and it is published without
		// a checksum line, which means it is also missing from the attestation,
		// whose subjects are exactly those lines.
		It("rejects a release.yml that lists one SBOM document at a site but not the other", func() {
			badRel := bytes.Replace(goodRel, []byte(`sha256sum -- *.tar.gz *.spdx.json *.cdx.json`),
				[]byte(`sha256sum -- *.tar.gz *.spdx.json`), 1)
			Expect(verifyDistVariantsIn(goodCI, badRel, goodSBOM)).To(MatchError(
				ContainSubstring("every place that lists one SBOM document must list them all")))
		})
	})
})

var _ = Describe("verifyWorkflowBaseScoping", func() {
	// Runs against the repository's real ci.yml and codeql.yml: both triggers
	// are unfiltered by base and the auto-merge job carries its pin (this also
	// runs as part of `mage dev:check`).
	It("finds the real workflows unfiltered by base and the merge job pinned", func() {
		Expect(verifyWorkflowBaseScoping()).To(Succeed())
	})

	// Which files get checked is itself logic, and the real-tree spec above
	// passes just as happily for a dispatcher that checks nothing. These drive
	// it over synthetic sources so both halves of the dispatch are pinned.
	Describe("dispatch", func() {
		clean := []byte("on:\n  pull_request:\njobs: {}\n")

		It("checks every workflow it is given, not only the first", func() {
			// Pins codeql.yml's membership: drop it from baseScopedWorkflows
			// and it could be re-filtered with nothing to catch it.
			err := verifyWorkflowBaseScopingIn(map[string][]byte{
				"ci.yml":     clean,
				"codeql.yml": []byte("on:\n  pull_request:\n    branches: [\"main\"]\njobs: {}\n"),
			})
			Expect(err).To(MatchError(ContainSubstring("codeql.yml")))
		})

		It("applies the pin check, not only the trigger check", func() {
			err := verifyWorkflowBaseScopingIn(map[string][]byte{
				"ci.yml": []byte(`
on:
  pull_request:
jobs:
  automerge:
    steps:
      - run: gh pr merge --auto "$PR_URL"
`),
				"codeql.yml": clean,
			})
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// The pin check is no longer special-cased to ci.yml, so a merging job
		// that moves into another listed workflow is still caught, and the
		// error names the file it is actually in.
		It("names the workflow a misplaced merging job landed in", func() {
			err := verifyWorkflowBaseScopingIn(map[string][]byte{
				"ci.yml": clean,
				"codeql.yml": []byte(`
on:
  pull_request:
jobs:
  automerge:
    steps:
      - run: gh pr merge --auto "$PR_URL"
`),
			})
			Expect(err).To(MatchError(ContainSubstring("codeql.yml job")))
		})

		// Asserted on the branch's own message, not just the file name: a nil
		// source parses as an empty document and reaches the missing-trigger
		// error, which also names codeql.yml, so matching the name alone
		// would pass with the !ok guard deleted.
		It("reports a workflow whose source was not supplied", func() {
			Expect(verifyWorkflowBaseScopingIn(map[string][]byte{"ci.yml": clean})).To(
				MatchError(ContainSubstring("no source supplied for codeql.yml")))
		})
	})

	// The pin half. Fixtures are synthetic so the failure branches are driven
	// without touching the real workflow files.
	Describe("auto-merge base pin", func() {
		const pinClause = "      && github.event.pull_request.base.ref == github.event.repository.default_branch\n"

		unfiltered := []byte(`
on:
  push:
    branches: ["main"]
  pull_request:

jobs:
  automerge:
    if: >-
      github.event_name == 'pull_request'
      && github.event.pull_request.base.ref == github.event.repository.default_branch
      && (github.event.pull_request.user.login == 'dependabot[bot]'
      || github.event.pull_request.user.login == 'renovate[bot]')
    steps:
      - run: gh pr merge --auto --merge "$PR_URL"
`)

		It("accepts a merging job that carries the pin", func() {
			Expect(verifyAutomergeBasePinIn("ci.yml", unfiltered)).To(Succeed())
		})

		It("rejects a dropped pin and names the job", func() {
			bad := bytes.Replace(unfiltered, []byte(pinClause), nil, 1)
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("merges pull requests")))
		})

		// Losing the condition wholesale is the same defect as losing the
		// clause, and it is what a botched edit to the folded block leaves
		// behind most often.
		It("rejects a merging job with no 'if:' at all, and names the job", func() {
			bad := bytes.Replace(unfiltered, []byte(`    if: >-
      github.event_name == 'pull_request'
      && github.event.pull_request.base.ref == github.event.repository.default_branch
      && (github.event.pull_request.user.login == 'dependabot[bot]'
      || github.event.pull_request.user.login == 'renovate[bot]')
`), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// Pins the anti-pin branch. (It no longer pins the operator folded
		// into automergeBasePin: the anti-pin fires first for any inverted
		// fixture, so the operand-only spec below is what covers that.)
		It("rejects an inverted comparison, and names the job", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref != github.event.repository.default_branch"), 1)
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("the inverse of the pin")))
		})

		// Killed by dropping `==` from automergeBasePin and by nothing else.
		// The base ref is conjoined, so the conjunct requirement is satisfied
		// and cannot be what rejects it; only the operator can. Semantically a
		// non-empty string is truthy, so this pins nothing at all.
		It("rejects a bare truthy conjunct on the base ref", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref"), 1)
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("never compares")))
		})

		// The ref is consulted but never compared, so it constrains nothing.
		// Both error paths name the job, so this asserts the one substring only
		// the missing-comparison path emits.
		It("rejects a condition that consults the base ref without comparing it", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("startsWith(github.event.pull_request.base.ref, 'release/')"), 1)
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("never compares")))
		})

		// Spacing is not spelling in the direction that matters: GitHub reads
		// `a!=b` as `a != b`, so a tight inversion plus a spaced decoy must
		// still be refused. Collapsing whitespace rather than removing it let
		// this through.
		It("rejects a tight inverted pin even with a spaced decoy", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("      && github.event.pull_request.base.ref == github.event.repository.default_branch\n"),
				[]byte("      && github.event.pull_request.base.ref!=github.event.repository.default_branch\n"+
					"      && !(github.event.pull_request.base.ref == 'gh-pages')\n"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(
				MatchError(ContainSubstring("the inverse of the pin")))
		})

		// The same asymmetry misfired upward: a correct pin written tight is
		// a valid spelling and must not be reported as drift.
		It("accepts an upright pin written with no spaces", func() {
			tight := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref==github.event.repository.default_branch"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", tight)).To(Succeed())
		})

		// One keystroke, `&&` to `||`. GitHub binds && tighter, so this reads
		// as `A || (B && C)` with A true for every pull_request event: the job
		// loses the base pin *and* the author gate. The comparison is still
		// present, so only requiring it as a conjunct catches this.
		It("rejects a pin that is disjoined rather than conjoined", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("      github.event_name == 'pull_request'\n      && github.event.pull_request.base.ref"),
				[]byte("      github.event_name == 'pull_request'\n      || github.event.pull_request.base.ref"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(
				MatchError(ContainSubstring("outside any parenthesised group")))
		})

		// The same slip one operator along: the pin stays where it was and the
		// `||` moves after it. Caught for the same reason -- the disjunction is
		// top-level -- which the earlier conjunct-adjacency form missed.
		It("rejects a disjunction that follows the pin", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("github.event.repository.default_branch\n      && (github.event.pull_request.user.login"),
				[]byte("github.event.repository.default_branch\n      || (github.event.pull_request.user.login"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(
				MatchError(ContainSubstring("outside any parenthesised group")))
		})

		// Documented limit, pinned so the comment and the code cannot drift:
		// a negation wrapped around the comparison keeps it and inverts anyway.
		// Not caught, on purpose -- nobody writes it by accident, and anyone
		// writing it deliberately would delete the guard instead.
		It("does not catch a comparison negated as a whole", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("&& github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("&& !(github.event.pull_request.base.ref == github.event.repository.default_branch)"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(Succeed())
		})

		// Spellings a maintainer plausibly writes, all semantically identical
		// to the baseline. The conjunct-adjacency form rejected every one.
		It("accepts the comparison parenthesised", func() {
			ok := bytes.Replace(unfiltered,
				[]byte("&& github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("&& (github.event.pull_request.base.ref == github.event.repository.default_branch)"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", ok)).To(Succeed())
		})

		It("accepts the operands in either order", func() {
			ok := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.repository.default_branch == github.event.pull_request.base.ref"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", ok)).To(Succeed())
		})

		It("accepts a condition wrapped in ${{ }}", func() {
			ok := bytes.Replace(unfiltered, []byte("    if: >-\n"),
				[]byte("    if: >-\n      ${{\n"), 1)
			ok = bytes.Replace(ok, []byte("|| github.event.pull_request.user.login == 'renovate[bot]')\n"),
				[]byte("|| github.event.pull_request.user.login == 'renovate[bot]')\n      }}\n"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", ok)).To(Succeed())
		})

		// The decoy: invert the real pin and let a plausible neighbouring
		// clause supply the required substring. Requiring the pin alone passed
		// this, because a substring says nothing about which clause produced
		// it.
		It("rejects an inverted pin even when another clause supplies the substring", func() {
			bad := bytes.Replace(unfiltered,
				[]byte("      && github.event.pull_request.base.ref == github.event.repository.default_branch\n"),
				[]byte("      && github.event.pull_request.base.ref != github.event.repository.default_branch\n"+
					"      && !(github.event.pull_request.base.ref == 'gh-pages')\n"), 1)
			// The fixture really is a decoy: the required substring is present,
			// so a guard checking only for it would pass this.
			Expect(string(bad)).To(ContainSubstring("github.event.pull_request.base.ref =="))
			err := verifyAutomergeBasePinIn("ci.yml", bad)
			Expect(err).To(MatchError(ContainSubstring(`job "automerge"`)))
			Expect(err).To(MatchError(ContainSubstring("the inverse of the pin")))
		})

		// Spacing is not spelling: the required comparison is matched on its
		// tokens, so an extra space around the operator is not drift.
		It("accepts extra whitespace around the operator", func() {
			spaced := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref   ==   github.event.repository.default_branch"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", spaced)).To(Succeed())
		})

		// The guard checks that the condition makes the comparison, not what it
		// compares against: ci.yml uses default_branch so the pin tracks the
		// ruleset, but a literal confines the job just as well and must not be
		// reported as drift.
		It("accepts a pin written against a literal branch name", func() {
			literal := bytes.Replace(unfiltered,
				[]byte("github.event.pull_request.base.ref == github.event.repository.default_branch"),
				[]byte("github.event.pull_request.base.ref == 'main'"), 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", literal)).To(Succeed())
		})

		// Matching on what the job does, not on the name "automerge", means a
		// rename cannot quietly retire the guard.
		It("still requires the pin when the merging job is renamed", func() {
			bad := bytes.Replace(unfiltered, []byte("  automerge:\n"), []byte("  land-bot-prs:\n"), 1)
			bad = bytes.Replace(bad, []byte(pinClause), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "land-bot-prs"`)))
		})

		// A step that enables auto-merge through an action rather than an
		// inline `gh pr merge` is the same job wearing a different hat.
		It("still requires the pin when auto-merge is enabled via an action", func() {
			bad := bytes.Replace(unfiltered,
				[]byte(`      - run: gh pr merge --auto --merge "$PR_URL"`),
				[]byte(`      - uses: peter-evans/enable-pull-request-automerge@v3`), 1)
			bad = bytes.Replace(bad, []byte(pinClause), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// A job that calls a reusable workflow has no steps at all, so a
		// matcher walking only steps would skip it -- while the caller job is
		// still where the if:, the permissions and the pin live.
		It("still requires the pin when the job itself calls an auto-merge workflow", func() {
			bad := []byte(`
on:
  pull_request:

jobs:
  automerge:
    uses: ./.github/workflows/automerge.yml
`)
			Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// The pin is required whatever the trigger looks like: a filter is
		// only equivalent to it when it names the default branch alone, so
		// disarming on any filter would retire the guard exactly when a
		// widened filter started to matter.
		It("still requires the pin when the trigger filters by base", func() {
			filtered := bytes.Replace(unfiltered,
				[]byte("  pull_request:\n"), []byte("  pull_request:\n    branches: [\"main\", \"release/**\"]\n"), 1)
			filtered = bytes.Replace(filtered, []byte(pinClause), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", filtered)).To(MatchError(ContainSubstring(`job "automerge"`)))
		})

		// The parse-error branch, which only a direct call reaches:
		// verifyWorkflowBaseScopingIn runs verifyPullRequestUnfilteredIn first
		// on the same bytes, so malformed YAML always fails there in practice.
		// Specced anyway because the branch exists and the test surface can
		// reach it -- and asserted on `yaml:` rather than the file name, since
		// every error this function returns leads with the workflow name.
		It("reports malformed YAML, though only a direct call reaches this", func() {
			Expect(verifyAutomergeBasePinIn("ci.yml", []byte("on: [\n"))).To(
				MatchError(ContainSubstring("ci.yml: yaml:")))
		})

		It("ignores jobs that do not merge pull requests", func() {
			noMerge := bytes.Replace(unfiltered,
				[]byte(`      - run: gh pr merge --auto --merge "$PR_URL"`),
				[]byte(`      - run: gh pr view "$PR_URL"`), 1)
			noMerge = bytes.Replace(noMerge, []byte(pinClause), nil, 1)
			Expect(verifyAutomergeBasePinIn("ci.yml", noMerge)).To(Succeed())
		})

		// Two offenders: the reported job must be the alphabetically first,
		// so the message does not change from run to run with map order. The
		// non-merging job sorts before both and must be skipped.
		It("names the first offending job when several are unpinned", func() {
			bad := []byte(`
on:
  pull_request:

jobs:
  aardvark-lint:
    steps:
      - run: gh pr view "$PR_URL"
  merge-zulu:
    steps:
      - run: gh pr merge --auto "$PR_URL"
  merge-alpha:
    steps:
      - run: gh pr merge --auto "$PR_URL"
`)
			for range 20 {
				Expect(verifyAutomergeBasePinIn("ci.yml", bad)).To(MatchError(ContainSubstring(`job "merge-alpha"`)))
			}
		})
	})

	// The trigger half: what stops the widening this guard accompanies from
	// being silently reverted.
	Describe("pull_request trigger", func() {
		It("accepts a trigger with no base filter", func() {
			Expect(verifyPullRequestUnfilteredIn("ci.yml", []byte("on:\n  pull_request:\njobs: {}\n"))).To(Succeed())
		})

		It("accepts a trigger that filters on event type but not base", func() {
			src := []byte("on:\n  pull_request:\n    types: [opened, synchronize]\njobs: {}\n")
			Expect(verifyPullRequestUnfilteredIn("ci.yml", src)).To(Succeed())
		})

		It("rejects a base filter and names the workflow and the branches", func() {
			src := []byte("on:\n  pull_request:\n    branches: [\"main\"]\njobs: {}\n")
			err := verifyPullRequestUnfilteredIn("codeql.yml", src)
			Expect(err).To(MatchError(ContainSubstring("codeql.yml")))
			Expect(err).To(MatchError(ContainSubstring("branches: [main]")))
		})

		// branches-ignore filters on the same field -- the PR's base -- so a
		// re-narrowing written that way skips stacked PRs exactly as silently.
		It("rejects a branches-ignore filter and names the key", func() {
			src := []byte("on:\n  pull_request:\n    branches-ignore: [\"feature/**\"]\njobs: {}\n")
			err := verifyPullRequestUnfilteredIn("ci.yml", src)
			Expect(err).To(MatchError(ContainSubstring("branches-ignore: [feature/**]")))
		})

		// Deleting the trigger skips stacked PRs just as thoroughly as
		// filtering it, so it must not read as "no filter, therefore fine".
		It("rejects a workflow with no pull_request trigger at all", func() {
			src := []byte("on:\n  push:\n    branches: [\"main\"]\njobs: {}\n")
			Expect(verifyPullRequestUnfilteredIn("ci.yml", src)).To(
				MatchError(ContainSubstring("declares no pull_request trigger")))
		})

		// Asserted on the parse failure, not just the file name: every error
		// this function returns leads with the workflow name, so matching the
		// name alone would pass with the yaml.Unmarshal check deleted — the
		// malformed input would then fall through to the missing-trigger
		// error, which names ci.yml too. Same trap as the missing-source spec.
		It("reports a malformed workflow against its file name", func() {
			Expect(verifyPullRequestUnfilteredIn("ci.yml", []byte("on: [\n"))).To(
				MatchError(ContainSubstring("ci.yml: yaml:")))
		})

		// The trigger key present but carrying a scalar rather than a mapping:
		// the one error path the specs above do not reach.
		It("reports a pull_request trigger that is not a mapping", func() {
			src := []byte("on:\n  pull_request: main\njobs: {}\n")
			Expect(verifyPullRequestUnfilteredIn("ci.yml", src)).To(
				MatchError(ContainSubstring("on.pull_request")))
		})
	})
})
