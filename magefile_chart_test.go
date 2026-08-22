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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// -- chart version parsing ------------------------------------------------------

var _ = Describe("chartVersions", func() {
	// go test runs from the repository root, so this parses the real
	// Chart.yaml, pinning its textual shape against the Go regexes: reformat
	// either line, or unquote appVersion, and this fails.
	//
	// One direction only. Three other parsers read the same two lines with sed —
	// the pre-push hook (covered by its own specs below), the verify-release-tag
	// action and the publish workflow (neither covered) — and this spec reads
	// none of their expressions, so a divergence in one of those is not caught
	// here. Both uncovered ones fail closed on an empty parse, so a defect there
	// surfaces loudly at release time rather than passing silently.
	It("parses the real Chart.yaml and agrees with internal/version", func() {
		version, appVersion, err := chartVersions()
		Expect(err).NotTo(HaveOccurred())

		want, err := releaseVersion()
		Expect(err).NotTo(HaveOccurred())
		Expect(version).To(Equal(want))
		Expect(appVersion).To(Equal(want))
	})
})

var _ = Describe("chartValuesFiles", func() {
	It("finds the fixtures, including the one held to the kubeVersion floor", func() {
		files, err := chartValuesFiles()
		Expect(err).NotTo(HaveOccurred())
		Expect(files).NotTo(BeEmpty())

		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, chartFixtureName(f))
		}
		// Chart.Validate keys the floor check on this name and errors if it
		// finds no such fixture; assert the pair agree so a rename fails here
		// with an obvious message too.
		Expect(names).To(ContainElement(chartFloorFixture))
	})

	// The repository's own fixtures are all .yaml, so without these two the
	// second glob pattern and the empty-set guard are never executed by the
	// suite: a later edit could drop either and every test would still pass,
	// leaving a .yml fixture silently unvalidated by chart:lint and
	// chart:validate.
	Context("over a directory of its own", func() {
		var dir string

		BeforeEach(func() {
			dir = GinkgoT().TempDir()
		})

		It("collects .yml fixtures as well as .yaml", func() {
			Expect(os.WriteFile(filepath.Join(dir, "only-values.yml"), []byte("{}\n"), 0o644)).To(Succeed())

			files, err := chartValuesFilesIn(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(files).To(ConsistOf(filepath.Join(dir, "only-values.yml")))
		})

		It("sorts the two extensions into one stable order", func() {
			for _, name := range []string{"b-values.yml", "a-values.yaml"} {
				Expect(os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o644)).To(Succeed())
			}

			files, err := chartValuesFilesIn(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(files).To(Equal([]string{
				filepath.Join(dir, "a-values.yaml"),
				filepath.Join(dir, "b-values.yml"),
			}))
		})

		It("refuses an empty fixture set rather than validating nothing", func() {
			_, err := chartValuesFilesIn(dir)
			Expect(err).To(MatchError(ContainSubstring("no fixture values files found under")))
			Expect(err).To(MatchError(ContainSubstring(dir)))
		})
	})
})

var _ = Describe("chartRulesBlock", func() {
	// The RBAC parity check compares this helper's output for two renders. A
	// parse that silently returned the whole tail would return the *same* tail
	// for both and compare equal, so the parity assertion would pass while
	// checking nothing. Pin the three shapes it has to get right.
	It("cuts a rules block at the document separator", func() {
		manifest := "kind: Role\nrules:\n  - verbs: [\"create\"]\n---\nkind: RoleBinding\n"
		Expect(chartRulesBlock(manifest)).To(Equal("  - verbs: [\"create\"]"))
	})

	It("returns empty when there is no rules block", func() {
		Expect(chartRulesBlock("kind: Service\nspec:\n  ports: []\n")).To(BeEmpty())
	})

	It("takes the whole tail when the rules block is the last document", func() {
		Expect(chartRulesBlock("kind: Role\nrules:\n  - verbs: [\"patch\"]\n")).To(Equal(`  - verbs: ["patch"]`))
	})

	It("ignores an indented rules key, which the route templates emit", func() {
		// ingress.yaml and the Gateway routes carry "  rules:" at indent two;
		// cutting on those would compare the wrong block entirely.
		Expect(chartRulesBlock("kind: HTTPRoute\nspec:\n  rules:\n    - backendRefs: []\n")).To(BeEmpty())
	})
})

var _ = Describe("verifyChartPins", func() {
	// Runs against the repository's real files: this is the cross-check that
	// keeps Chart.yaml's advertised kubeVersion floor, the constant CI
	// validates against, and the Helm version the publish workflow packages
	// with from drifting apart. Also runs as part of `mage dev:check`.
	It("finds the real pins in agreement", func() {
		Expect(verifyChartPins()).To(Succeed())
	})

	// The failure branches are what make the guard a guard: feed synthetic
	// contents with exactly one pin out of agreement and assert the error
	// names it.
	Describe("drift detection", func() {
		goodChart := []byte("apiVersion: v2\nversion: 0.9.0-dev\nappVersion: \"0.9.0-dev\"\nkubeVersion: \">=" + kubeconformFloorVersion + "-0\"\n")
		goodCI := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
			"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: ${{ matrix.helm }}\n")
		goodPublish := []byte("jobs:\n  publish:\n    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: v3.21.3\n")

		It("accepts synthetic files that agree", func() {
			Expect(verifyChartPinsIn(goodChart, goodCI, goodPublish)).To(Succeed())
		})

		It("rejects a kubeVersion floor the constant does not match", func() {
			bad := bytes.Replace(goodChart, []byte(kubeconformFloorVersion), []byte("1.99.0"), 1)
			Expect(verifyChartPinsIn(bad, goodCI, goodPublish)).To(
				MatchError(ContainSubstring("does not match the kubeVersion floor")))
		})

		It("rejects a packaging Helm outside the validated matrix", func() {
			bad := bytes.Replace(goodPublish, []byte("v3.21.3"), []byte("v3.20.0"), 1)
			Expect(verifyChartPinsIn(goodChart, goodCI, bad)).To(
				MatchError(ContainSubstring("not in ci.yml's chart matrix")))
		})

		It("accepts the other validated matrix entry as the packaging version", func() {
			ok := bytes.Replace(goodPublish, []byte("v3.21.3"), []byte("v4.2.3"), 1)
			Expect(verifyChartPinsIn(goodChart, goodCI, ok)).To(Succeed())
		})

		It("refuses to pass when a pin cannot be parsed at all", func() {
			Expect(verifyChartPinsIn([]byte("apiVersion: v2\n"), goodCI, goodPublish)).To(
				MatchError(ContainSubstring("could not parse the kubeVersion floor")))
			Expect(verifyChartPinsIn(goodChart, []byte("jobs: {}\n"), goodPublish)).To(
				MatchError(ContainSubstring("ci.yml has no 'chart' job")))
			Expect(verifyChartPinsIn(goodChart, goodCI, []byte("jobs: {}\n"))).To(
				MatchError(ContainSubstring("helm-chart.yml has no 'publish' job")))
		})

		// The failure mode a positional parse admits: reading a pin that
		// belongs to something else and passing anyway. Both parsers key on the
		// job (and the publish one on the action) rather than on file order, so
		// a decoy ahead of the real value must not be picked up.
		It("ignores a decoy helm matrix in another job", func() {
			decoy := []byte("jobs:\n  other:\n    strategy:\n      matrix:\n        helm: [v9.9.9]\n" +
				"  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3]\n" +
				"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: ${{ matrix.helm }}\n")
			Expect(verifyChartPinsIn(goodChart, decoy, goodPublish)).To(Succeed())
		})

		It("ignores a decoy version on an earlier action step", func() {
			decoy := []byte("jobs:\n  publish:\n    steps:\n" +
				"      - uses: actions/setup-go@abc\n        with:\n          version: v9.9.9\n" +
				"      - uses: azure/setup-helm@abc\n        with:\n          version: v3.21.3\n")
			Expect(verifyChartPinsIn(goodChart, goodCI, decoy)).To(Succeed())
		})

		It("still catches the real mismatch past a decoy", func() {
			decoy := []byte("jobs:\n  publish:\n    steps:\n" +
				"      - uses: actions/setup-go@abc\n        with:\n          version: v3.21.3\n" +
				"      - uses: azure/setup-helm@abc\n        with:\n          version: v9.9.9\n")
			Expect(verifyChartPinsIn(goodChart, goodCI, decoy)).To(
				MatchError(ContainSubstring("not in ci.yml's chart matrix")))
		})

		It("refuses a publish job with no setup-helm step at all", func() {
			Expect(verifyChartPinsIn(goodChart, goodCI,
				[]byte("jobs:\n  publish:\n    steps:\n      - uses: actions/checkout@abc\n"))).To(
				MatchError(ContainSubstring("no azure/setup-helm step")))
		})

		// setup-helm with no version installs whatever is latest, so an absent
		// pin is the realistic drift — not a malformed file.
		It("refuses a setup-helm step that pins no version", func() {
			Expect(verifyChartPinsIn(goodChart, goodCI,
				[]byte("jobs:\n  publish:\n    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          token: xyz\n"))).To(
				MatchError(ContainSubstring("sets no with.version")))
		})

		It("refuses a chart job that declares no helm matrix", func() {
			Expect(verifyChartPinsIn(goodChart,
				[]byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        other: [a]\n"), goodPublish)).To(
				MatchError(ContainSubstring("no helm matrix entries")))
		})

		// The link the matrix depends on: a literal here would make both legs
		// install the same Helm and both pass, with one leg named for a version
		// it never ran.
		It("refuses a chart job that installs a literal instead of the matrix", func() {
			bad := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
				"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: v3.21.3\n")
			Expect(verifyChartPinsIn(goodChart, bad, goodPublish)).To(
				MatchError(ContainSubstring("instead of ${{ matrix.helm }}")))
		})

		It("refuses a chart job whose matrix installs nothing", func() {
			bad := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3]\n" +
				"    steps:\n      - uses: actions/checkout@abc\n")
			Expect(verifyChartPinsIn(goodChart, bad, goodPublish)).To(
				MatchError(ContainSubstring("no azure/setup-helm step")))
		})

		// A gate whose diagnosis contradicts the file it rejected is worse than
		// no gate: it sends a maintainer looking for a step that is plainly
		// there. GitHub resolves `uses:` owner/repo case-insensitively, and
		// Azure/setup-helm is the casing the action's own README uses.
		It("accepts the action reference in the casing its own README uses", func() {
			ok := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
				"    steps:\n      - uses: Azure/setup-helm@abc\n        with:\n          version: ${{ matrix.helm }}\n")
			Expect(verifyChartPinsIn(goodChart, ok, goodPublish)).To(Succeed())
		})

		// GitHub accepts an expression with no interior spaces, so rejecting it
		// would fail the gate on a workflow that installs exactly the right Helm.
		It("accepts the matrix expression without interior spaces", func() {
			ok := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
				"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: ${{matrix.helm}}\n")
			Expect(verifyChartPinsIn(goodChart, ok, goodPublish)).To(Succeed())
		})

		// The expression must still name the helm matrix and nothing else — a
		// neighbouring key would install one version under both leg names.
		It("refuses an expression naming a different matrix key", func() {
			bad := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm: [v3.21.3, v4.2.3]\n" +
				"    steps:\n      - uses: azure/setup-helm@abc\n        with:\n          version: ${{ matrix.kubernetes }}\n")
			Expect(verifyChartPinsIn(goodChart, bad, goodPublish)).To(
				MatchError(ContainSubstring("instead of ${{ matrix.helm }}")))
		})

		It("reads the publish pin through the same casing tolerance", func() {
			pub := []byte("jobs:\n  publish:\n    steps:\n      - uses: Azure/setup-helm@abc\n" +
				"        with:\n          version: v3.21.3\n")
			Expect(verifyChartPinsIn(goodChart, goodCI, pub)).To(Succeed())
		})
	})

	// The matrix is a bare list of strings, so Renovate only maintains a leg
	// that carries an annotation its customManager matches. An unannotated leg
	// is the quiet failure: nothing goes red, the version just stops moving.
	// The guard reads renovate.json's own expression rather than a copy of it,
	// so these exercise both files — drift on either side has to fail.
	Describe("Renovate annotations on the helm matrix", func() {
		const annotation = "          # renovate: datasource=github-releases depName=helm packageName=helm/helm\n"
		annotated := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm:\n" +
			annotation + "          - v3.21.3\n" +
			annotation + "          - v4.2.3\n")

		// The real renovate.json, so the fixtures are matched by the expression
		// Renovate will actually use rather than one written to suit them.
		realRenovate, readErr := os.ReadFile("renovate.json")

		BeforeEach(func() {
			Expect(readErr).NotTo(HaveOccurred())
		})

		It("accepts a matrix whose every entry is annotated", func() {
			Expect(verifyCIHelmAnnotationsIn(annotated, realRenovate)).To(Succeed())
		})

		It("rejects an entry added without an annotation", func() {
			bare := append(append([]byte{}, annotated...), []byte("          - v5.0.0\n")...)
			Expect(verifyCIHelmAnnotationsIn(bare, realRenovate)).To(
				MatchError(ContainSubstring("lists Helm v5.0.0")))
			Expect(verifyCIHelmAnnotationsIn(bare, realRenovate)).To(
				MatchError(ContainSubstring("without a '# renovate:' annotation")))
		})

		// The same fault read the other way. Note what does NOT need guarding:
		// a comment left dangling above nothing matches no annotation and is
		// inert. What bites is an annotation that still has a value under it
		// but sits outside the matrix — Renovate keeps bumping a version no job
		// runs, churning PRs against a line nobody reads.
		It("rejects an annotated list item outside the chart matrix", func() {
			stray := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm:\n" +
				annotation + "          - v3.21.3\n" +
				annotation + "          - v4.2.3\n" +
				"  other:\n    steps:\n" +
				annotation + "          - v2.17.0\n")
			Expect(verifyCIHelmAnnotationsIn(stray, realRenovate)).To(
				MatchError(ContainSubstring("annotation for v2.17.0 (line 13)")))
			Expect(verifyCIHelmAnnotationsIn(stray, realRenovate)).To(
				MatchError(ContainSubstring("not a chart matrix entry")))
		})

		// Two strays, so the report has something to choose between: the lowest
		// line is the one a reader scrolls to first.
		//
		// The repetitions sample Go's random map-iteration start offset, and
		// they are not a coin flip. Matches are collected in ascending line
		// order, so an unsorted range still happens to yield the lower line for
		// most start offsets — one in eight reverses them. Sixty-four rounds
		// put an unsorted implementation's survival near 2e-4; eight would let
		// it through about a third of the time. Correct code is deterministic,
		// so this never flakes in the other direction.
		It("reports the lowest stray line when there is more than one", func() {
			strays := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        helm:\n" +
				annotation + "          - v3.21.3\n" +
				annotation + "          - v4.2.3\n" +
				"  other:\n    steps:\n" +
				annotation + "          - v2.17.0\n" +
				annotation + "          - v2.16.0\n")
			for range 64 {
				Expect(verifyCIHelmAnnotationsIn(strays, realRenovate)).To(
					MatchError(ContainSubstring("annotation for v2.17.0 (line 13)")))
			}
		})

		// A comment naming some other package is not this annotation: it would
		// leave the leg unmanaged while looking managed to a reader. Derived
		// from the accepting fixture so the package name is the only thing that
		// can differ — a hand-written near-copy could pass on a stray typo and
		// stop testing the discrimination it is named for.
		It("does not accept an annotation for a different package", func() {
			wrong := bytes.Replace(annotated, []byte("packageName=helm/helm"), []byte("packageName=helm/chart-testing"), 1)
			Expect(verifyCIHelmAnnotationsIn(wrong, realRenovate)).To(
				MatchError(ContainSubstring("lists Helm v3.21.3")))
			Expect(verifyCIHelmAnnotationsIn(wrong, realRenovate)).To(
				MatchError(ContainSubstring("without a '# renovate:' annotation")))
		})

		// The annotation vouches only for the entry it sits above. Matching on
		// the version alone would let this decoy — the right annotation in the
		// wrong job — cover a bare matrix entry, and the leg would be exactly
		// as invisible to Renovate as if nothing had been annotated at all.
		It("does not let an annotation elsewhere in the file cover a bare entry", func() {
			decoy := []byte("jobs:\n  other:\n    steps:\n" +
				annotation + "          - v4.2.3\n" +
				"  chart:\n    strategy:\n      matrix:\n        helm:\n" +
				annotation + "          - v3.21.3\n" +
				"          - v4.2.3\n")
			// The line is the assertion here: the decoy's own v4.2.3 sits on
			// line 5, so naming line 12 is what proves the pairing is by
			// position and not by version.
			Expect(verifyCIHelmAnnotationsIn(decoy, realRenovate)).To(
				MatchError(ContainSubstring("lists Helm v4.2.3 (line 12) without a '# renovate:' annotation")))
		})

		// A quoted entry is legal YAML and identical to ciChartHelmMatrix, so
		// it looks harmless — but Renovate matches raw text and would carry the
		// quotes into the lookup, which then finds nothing and says nothing.
		// The guard has to name that, and name it as its own fault rather than
		// as a missing annotation, or the message sends a maintainer looking at
		// the comment sitting correctly right above the entry.
		It("rejects an entry written as a quoted scalar, naming the real fault", func() {
			quoted := bytes.Replace(annotated, []byte("- v4.2.3"), []byte(`- "v4.2.3"`), 1)
			Expect(verifyCIHelmAnnotationsIn(quoted, realRenovate)).To(
				MatchError(ContainSubstring(`reads "\"v4.2.3\"" from that line`)))
			Expect(verifyCIHelmAnnotationsIn(quoted, realRenovate)).To(
				MatchError(ContainSubstring("Write the version as a bare scalar")))
		})

		// The other half of the contract: renovate.json is where the annotation
		// stops being inert prose. Deleting or narrowing the customManager has
		// to fail here, or the config could be gutted with every check green.
		It("rejects a renovate.json with no annotation customManager", func() {
			Expect(verifyCIHelmAnnotationsIn(annotated, []byte(`{"customManagers": []}`))).To(
				MatchError(ContainSubstring("no regex customManager that covers .github/workflows/ci.yml")))
		})

		It("rejects a customManager narrowed so it no longer matches the annotations", func() {
			narrowed := bytes.Replace(realRenovate,
				[]byte(`# renovate: datasource=(?<datasource>`), []byte(`# renovate-disabled: datasource=(?<datasource>`), 1)
			Expect(narrowed).NotTo(Equal(realRenovate), "the customManager regex should be present to narrow")
			Expect(verifyCIHelmAnnotationsIn(annotated, narrowed)).To(
				MatchError(ContainSubstring("without a '# renovate:' annotation")))
		})

		// The other way to stop the manager reaching ci.yml, and the one the
		// regex check alone cannot see: leave the expression intact and point
		// the manager at a different file.
		//
		// Edited structurally rather than by bytes.Replace: all four managers
		// share the same managerFilePatterns string, so a textual replace
		// silently narrows whichever comes first — which is not this one, and
		// leaves the spec passing for a reason it does not name.
		It("rejects a customManager whose managerFilePatterns no longer cover ci.yml", func() {
			var cfg map[string]any
			Expect(json.Unmarshal(realRenovate, &cfg)).To(Succeed())
			managers, ok := cfg["customManagers"].([]any)
			Expect(ok).To(BeTrue(), "renovate.json should declare customManagers")

			narrowed := 0
			for _, m := range managers {
				mm, ok := m.(map[string]any)
				Expect(ok).To(BeTrue())
				ms, _ := mm["matchStrings"].([]any)
				if len(ms) > 0 && strings.Contains(ms[0].(string), "# renovate:") {
					mm["managerFilePatterns"] = []any{`/^\.github/workflows/helm-chart\.yml$/`}
					narrowed++
				}
			}
			Expect(narrowed).To(Equal(1), "exactly one annotation customManager should have been narrowed")

			elsewhere, err := json.Marshal(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(verifyCIHelmAnnotationsIn(annotated, elsewhere)).To(
				MatchError(ContainSubstring("no regex customManager that covers .github/workflows/ci.yml")))
		})

		// Anchored to the annotation manager specifically: a future manager
		// added ahead of it could otherwise absorb the mutation and leave this
		// passing while testing something else entirely.
		It("rejects a customManager whose regex Renovate could not compile", func() {
			broken := bytes.Replace(realRenovate,
				[]byte(`(?<currentValue>\\S+)`), []byte(`(?<currentValue>\\S+`), 1)
			Expect(broken).NotTo(Equal(realRenovate), "the currentValue group should be present to break")
			Expect(verifyCIHelmAnnotationsIn(annotated, broken)).To(
				MatchError(ContainSubstring("Renovate could not compile")))
			Expect(verifyCIHelmAnnotationsIn(annotated, broken)).To(
				MatchError(ContainSubstring(`# renovate: datasource=`)))
		})

		// An annotation Renovate cannot resolve is as good as no annotation:
		// with no datasourceTemplate to fall back on, it logs and skips, and
		// the leg stops being bumped with nothing going red.
		It("rejects an annotation whose datasource is misspelt", func() {
			typo := bytes.Replace(annotated,
				[]byte("datasource=github-releases"), []byte("datasource=github-release"), 1)
			Expect(typo).NotTo(Equal(annotated), "the datasource should be present to misspell")
			Expect(verifyCIHelmAnnotationsIn(typo, realRenovate)).To(
				MatchError(ContainSubstring("lists Helm v3.21.3")))
		})

		// The reader's own failure branches. Without these, mutating either to
		// a nil error leaves the suite green while the guard degrades to a
		// no-op on any ci.yml whose matrix has moved. They are asserted
		// separately because the whole point of the two messages is that they
		// send a maintainer to different lines.
		It("rejects a chart job with no helm matrix at all", func() {
			noMatrix := []byte("jobs:\n  chart:\n    strategy:\n      matrix:\n        other: [a]\n")
			Expect(verifyCIHelmAnnotationsIn(noMatrix, realRenovate)).To(
				MatchError(ContainSubstring("could not read the chart job's helm matrix")))
			Expect(verifyCIHelmAnnotationsIn(noMatrix, realRenovate)).To(
				MatchError(ContainSubstring("declares no helm matrix legs")))
		})

		It("rejects a ci.yml with no chart job, naming that instead", func() {
			noChart := []byte("jobs:\n  other:\n    steps: []\n")
			Expect(verifyCIHelmAnnotationsIn(noChart, realRenovate)).To(
				MatchError(ContainSubstring("has no 'chart' job to read a helm matrix from")))
		})

		// The permissive branch of renovateManagerCoversCI. Renovate also
		// accepts glob patterns, which this guard declines to reimplement
		// rather than risk failing the build on a correct config — a decision
		// that silently reverts if nothing holds it.
		It("accepts a customManager whose file patterns use the glob spelling", func() {
			var cfg map[string]any
			Expect(json.Unmarshal(realRenovate, &cfg)).To(Succeed())
			managers, ok := cfg["customManagers"].([]any)
			Expect(ok).To(BeTrue(), "renovate.json should declare customManagers")

			globbed := 0
			for _, m := range managers {
				mm, ok := m.(map[string]any)
				Expect(ok).To(BeTrue())
				ms, _ := mm["matchStrings"].([]any)
				if len(ms) > 0 && strings.Contains(ms[0].(string), "# renovate:") {
					mm["managerFilePatterns"] = []any{".github/workflows/*.yml"}
					globbed++
				}
			}
			Expect(globbed).To(Equal(1), "exactly one annotation customManager should have been reglobbed")

			glob, err := json.Marshal(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(verifyCIHelmAnnotationsIn(annotated, glob)).To(Succeed())
		})

		// The synthetic shapes above prove the branches; this proves the pair
		// of files actually in the repo agree, which is the thing that has to
		// hold. It names the annotation check specifically, so a failure points
		// at ci.yml or renovate.json rather than at any of the other pins.
		It("finds the real ci.yml and renovate.json in agreement", func() {
			ciSrc, err := os.ReadFile(filepath.Join(".github", "workflows", "ci.yml"))
			Expect(err).NotTo(HaveOccurred())
			Expect(verifyCIHelmAnnotationsIn(ciSrc, realRenovate)).To(Succeed())
		})
	})
})

// -- the pre-push tag gate ------------------------------------------------------

// tagGateRepo is a throwaway git repository holding one commit, whose
// internal/version and Chart.yaml contents the caller chooses. The pre-push
// hook reads both out of the *tagged commit* via `git show`, so exercising it
// means committing them rather than just writing them to disk.
type tagGateRepo struct {
	dir string
	sha string
}

// fixtureEnv is the environment every fixture git command runs with: the
// ambient one stripped of *every* GIT_* variable, then given back only what the
// fixture chooses.
//
// Stripping is the whole point, and it is not theoretical. git exports GIT_DIR,
// GIT_WORK_TREE, GIT_INDEX_FILE and GIT_OBJECT_DIRECTORY to the hooks it runs
// (see `git rev-parse --local-env-vars`), and those outrank cmd.Dir — so a
// fixture built from os.Environ() inside a pre-push hook commits into the
// *real* repository and moves its branch. The pre-push hook runs this suite via
// its `go test -tags mage .` invocation, and that is exactly what happened: six
// fixture commits landed on the branch being pushed.
//
// A hook is the only thing that leaks that environment naturally, which is why
// nothing reproduced it and it survived five green rounds of review. A spec has
// to plant it deliberately — the decoy repository below does, so the class is
// visible to `mage test:magefile` and CI now.
// HOME and XDG_CONFIG_HOME are redirected too, and they are the subtle half:
// neither carries the GIT_ prefix, and git finds its default ignore and
// attributes files under them ($XDG_CONFIG_HOME/git/ignore, else
// $HOME/.config/git/ignore) regardless of GIT_CONFIG_GLOBAL. A maintainer whose
// user-level ignore file covers *.txt would otherwise turn the decoy's
// `status --porcelain` assertion empty — failing a clean tree, and worse,
// blinding that assertion to a real index write. Redirecting them also makes the
// isolation independent of git's version, since GIT_CONFIG_GLOBAL/SYSTEM are
// silently ignored before git 2.32.
// fixtureHome is suite-scoped rather than per-spec because fixtureEnv is called
// from DeferCleanup too, and GinkgoT().TempDir() registers a cleanup of its own —
// which Ginkgo refuses from inside one. It stays empty: nothing writes to it, it
// exists only so git finds no user-level config, ignore or attributes file.
var fixtureHome string

var _ = BeforeSuite(func() {
	dir, err := os.MkdirTemp("", "openvox-ca-fixture-home-")
	Expect(err).NotTo(HaveOccurred())
	fixtureHome = dir
	DeferCleanup(func() {
		Expect(os.RemoveAll(dir)).To(Succeed())
	})
})

func fixtureEnv() []string {
	GinkgoHelper()
	Expect(fixtureHome).NotTo(BeEmpty(), "fixtureHome is unset; BeforeSuite did not run")
	env := make([]string, 0, len(os.Environ())+8)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GIT_") ||
			strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") {
			continue
		}
		env = append(env, kv)
	}
	// No signing, no hooks, no ambient identity, no user-level ignore or
	// attributes: the fixture must build identically on a maintainer's machine
	// and on a CI runner.
	return append(env,
		"HOME="+fixtureHome,
		"XDG_CONFIG_HOME="+filepath.Join(fixtureHome, ".config"),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
}

// gitIn runs one git command in dir with the fixture environment, and is the
// only site that execs git directly — the decoy repository's setup and
// inspection included. The single choke point for the environment itself is
// fixtureEnv, not this function: pushWithEnv execs the gate script rather than
// git, so it cannot route through here and has to set cmd.Env for itself, which
// leaves it the one place where forgetting is still possible. That is how these
// fixtures came to operate on the real repository, twice. Output is folded into
// the failure message so a fixture that cannot build says why.
func gitIn(dir string, args ...string) string {
	GinkgoHelper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = fixtureEnv()
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "git %s in %s: %s", strings.Join(args, " "), dir, out)
	return strings.TrimSpace(string(out))
}

func newTagGateRepo(constVersion, chartVersion, chartAppVersion string) *tagGateRepo {
	GinkgoHelper()
	dir := GinkgoT().TempDir()

	git := func(args ...string) string {
		GinkgoHelper()
		return gitIn(dir, args...)
	}

	git("init", "--quiet")

	write := func(path, body string) {
		full := filepath.Join(dir, path)
		Expect(os.MkdirAll(filepath.Dir(full), 0o755)).To(Succeed())
		Expect(os.WriteFile(full, []byte(body), 0o644)).To(Succeed())
	}

	// Only the two lines the hook parses need to be realistic; the surrounding
	// text is there so the parse has something to skip past.
	write("internal/version/version.go", fmt.Sprintf(
		"package version\n\n// preamble\nconst Version = %q\n", constVersion))
	// apiVersion deliberately precedes version, because a careless ^version:
	// parse would match it.
	write("charts/openvox-ca/Chart.yaml", fmt.Sprintf(
		"apiVersion: v2\nname: openvox-ca\nversion: %s\nappVersion: %q\n",
		chartVersion, chartAppVersion))

	git("add", "-A")
	git("commit", "--quiet", "--no-gpg-sign", "-m", "fixture")

	// Validated, because gitIn returns CombinedOutput: one stray byte on stderr
	// makes this not a sha, the gate cannot resolve it, and the gate skips —
	// which every allow-path spec would read as success.
	sha := git("rev-parse", "HEAD")
	Expect(sha).To(MatchRegexp("^[0-9a-f]{40}$"), "the fixture did not yield a commit sha")

	return &tagGateRepo{dir: dir, sha: sha}
}

// git runs a git command inside the fixture. A read is as dangerous as a write
// here: a `rev-parse HEAD` that answers from the ambient GIT_DIR hands the gate
// a commit the fixture does not contain, which the gate then skips, passing a
// spec that exists to watch it fail.
func (r *tagGateRepo) git(args ...string) string {
	GinkgoHelper()
	return gitIn(r.dir, args...)
}

// push runs the script with the pushed refs on stdin, as git delivers them:
// "<local-ref> <local-sha> <remote-ref> <remote-sha>". The script finds its
// repository by cwd here.
func (r *tagGateRepo) push(remoteRef, localSHA string) (string, error) {
	GinkgoHelper()
	return r.pushWithEnv(remoteRef, localSHA, fixtureEnv())
}

// pushAsHook runs it the way git actually does under a real pre-push hook, with
// GIT_DIR and GIT_WORK_TREE naming the repository being pushed — which is the
// fixture itself, since that is the repository whose tag is under test.
//
// Production always has those set and cwd discovery never happens there, so
// without this the script's only coverage is a configuration that never occurs.
// The two are different paths inside git, and the difference is not academic:
// stripping GIT_* is now the house rule for anything shelling out to git, and
// applying it inside the script would change its behaviour under a real push
// while leaving every cwd-discovered spec green.
func (r *tagGateRepo) pushAsHook(remoteRef, localSHA string) (string, error) {
	GinkgoHelper()
	return r.pushWithEnv(remoteRef, localSHA, append(fixtureEnv(),
		"GIT_DIR="+filepath.Join(r.dir, ".git"),
		"GIT_WORK_TREE="+r.dir,
	))
}

func (r *tagGateRepo) pushWithEnv(remoteRef, localSHA string, env []string) (string, error) {
	GinkgoHelper()
	script, err := filepath.Abs(filepath.Join(".lefthook", "pre-push", "verify-tags.sh"))
	Expect(err).NotTo(HaveOccurred())

	cmd := exec.Command("sh", script)
	cmd.Dir = r.dir
	// The caller chooses, but every caller passes an environment built from
	// fixtureEnv: the script's own `git show` must read the fixture, not whatever
	// repository an inherited GIT_DIR names, which is what made these specs
	// assert against the wrong commit.
	cmd.Env = env
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s %s %s %s\n", remoteRef, localSHA, remoteRef, strings.Repeat("0", 40)))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// -- module tidiness ------------------------------------------------------------

var _ = Describe("checkModuleTidy", func() {
	// The behaviour under test is a data-loss fix: dev:check mutates go.mod to
	// see whether tidy changes it, and used to restore with `git checkout --`,
	// which discarded a developer's uncommitted dependency bump. Nothing caught
	// that, and nothing would have caught a revert to it.
	var (
		dir   string
		files []string
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		files = []string{"go.mod", "go.sum"}
		Expect(os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "go.sum"), []byte("sum\n"), 0o644)).To(Succeed())
	})

	read := func(name string) string {
		GinkgoHelper()
		body, err := os.ReadFile(filepath.Join(dir, name))
		Expect(err).NotTo(HaveOccurred())
		return string(body)
	}

	It("passes and leaves the files alone when tidy changes nothing", func() {
		Expect(checkModuleTidy(dir, files, func() error { return nil })).To(Succeed())
		Expect(read("go.mod")).To(Equal("module x\n"))
		Expect(read("go.sum")).To(Equal("sum\n"))
	})

	// The regression that shipped once: the contents restored must be the ones
	// the caller had, not whatever is committed. Nothing here is a git
	// repository, so a `git checkout --` implementation cannot even run.
	It("restores the caller's own contents, not a committed state", func() {
		Expect(os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\nrequire y v1.2.3\n"), 0o644)).To(Succeed())

		err := checkModuleTidy(dir, files, func() error {
			return os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644)
		})
		Expect(err).To(MatchError(ContainSubstring("not tidy (go.mod)")))
		Expect(read("go.mod")).To(Equal("module x\n\nrequire y v1.2.3\n"),
			"the uncommitted require line was discarded")
	})

	It("names only the file that actually changed", func() {
		err := checkModuleTidy(dir, files, func() error {
			return os.WriteFile(filepath.Join(dir, "go.sum"), []byte("different\n"), 0o644)
		})
		// The message's fixed prefix names both files, so the parenthesised list
		// is what carries the finding — assert on that, not on the whole string.
		Expect(err).To(MatchError(ContainSubstring("not tidy (go.sum)")))
		Expect(err).NotTo(MatchError(ContainSubstring("(go.mod")))
	})

	// The path the original fix missed: tidy rewrites a file and then fails, so
	// the comparison never ran and the rewrite stayed in the developer's tree.
	It("restores even when tidy itself fails", func() {
		err := checkModuleTidy(dir, files, func() error {
			Expect(os.WriteFile(filepath.Join(dir, "go.mod"), []byte("mangled\n"), 0o644)).To(Succeed())
			return errors.New("tidy exploded")
		})
		Expect(err).To(MatchError(ContainSubstring("tidy exploded")))
		Expect(read("go.mod")).To(Equal("module x\n"), "tidy's write was left behind")
	})

	// A failed restore must not replace the finding: the developer needs to know
	// both that the module is untidy and that their file was left rewritten.
	It("reports a restore failure alongside the untidiness, not instead of it", func() {
		target := filepath.Join(dir, "go.mod")
		err := checkModuleTidy(dir, files, func() error {
			Expect(os.WriteFile(target, []byte("rewritten\n"), 0o644)).To(Succeed())
			// Read-only, so putting the snapshot back fails.
			Expect(os.Chmod(target, 0o400)).To(Succeed())
			DeferCleanup(func() { Expect(os.Chmod(target, 0o600)).To(Succeed()) })
			return nil
		})
		Expect(err).To(MatchError(ContainSubstring("not tidy (go.mod)")))
		Expect(err).To(MatchError(ContainSubstring("while putting them back")))
		Expect(err).To(MatchError(ContainSubstring("restoring go.mod")))
	})

	// The path the round-eight extraction regressed: the pre-extraction code
	// returned a hard error when a file could not be read back, and collecting it
	// instead let a successful tidy that removed go.sum report success with the
	// snapshot dropped.
	It("fails, and restores, when tidy removes one of the files", func() {
		err := checkModuleTidy(dir, files, func() error {
			return os.Remove(filepath.Join(dir, "go.sum"))
		})
		Expect(err).To(MatchError(ContainSubstring("could not be read back after the tidy check")))
		Expect(err).To(MatchError(ContainSubstring("go.sum")))
		// Reported as module drift with a remedy, not as a bare I/O fault.
		Expect(err).To(MatchError(ContainSubstring("mage dev:tidy")))
		Expect(read("go.sum")).To(Equal("sum\n"), "the removed file was not put back")
		Expect(read("go.mod")).To(Equal("module x\n"))
	})

	// The errors.Join branch: tidy fails *and* the restore fails. The
	// untidiness-plus-restore-failure spec above cannot reach it, because its
	// callback succeeds — so without this, collapsing that branch to a bare
	// `return tidyErr` passed everything.
	It("reports a failed tidy and a failed restore together", func() {
		target := filepath.Join(dir, "go.mod")
		err := checkModuleTidy(dir, files, func() error {
			Expect(os.WriteFile(target, []byte("rewritten\n"), 0o644)).To(Succeed())
			Expect(os.Chmod(target, 0o400)).To(Succeed())
			DeferCleanup(func() { Expect(os.Chmod(target, 0o600)).To(Succeed()) })
			return errors.New("tidy exploded")
		})
		Expect(err).To(MatchError(ContainSubstring("tidy exploded")))
		Expect(err).To(MatchError(ContainSubstring("restoring go.mod")))
		// And the consequence, not just the strings: the rewrite is still there,
		// which is what the joined error is warning about.
		Expect(read("go.mod")).To(Equal("rewritten\n"))
	})

	// The message names the files from the argument list; with only go.mod/go.sum
	// callers, reverting that to a hardcoded prefix went unnoticed.
	It("names the files it was given, not go.mod/go.sum", func() {
		Expect(os.WriteFile(filepath.Join(dir, "a.mod"), []byte("one\n"), 0o644)).To(Succeed())

		err := checkModuleTidy(dir, []string{"a.mod"}, func() error {
			return os.WriteFile(filepath.Join(dir, "a.mod"), []byte("two\n"), 0o644)
		})
		Expect(err).To(MatchError(ContainSubstring("a.mod are not tidy")))
		Expect(err).NotTo(MatchError(ContainSubstring("go.mod")))
	})

	It("fails when a named file does not exist", func() {
		Expect(checkModuleTidy(dir, []string{"absent.mod"}, func() error { return nil })).To(
			MatchError(ContainSubstring("before the tidy check")))
	})
})

var _ = Describe("fixtureEnv", func() {
	// Pins the strip directly, rather than only through its consequences. The
	// decoy spec proves the fixtures survive a leak; this proves the mechanism
	// they survive it by, so a named-variable allow-list replacing the prefix
	// loop fails here rather than destructively somewhere else.
	It("removes every ambient GIT_ variable", func() {
		for _, k := range []string{
			"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
			"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CONFIG",
			"GIT_CONFIG_PARAMETERS", "GIT_QUARANTINE_PATH", "GIT_PREFIX",
		} {
			GinkgoT().Setenv(k, "/should/not/survive")
		}

		// Asserted as a set, in both directions at once. A one-sided check for
		// survivors passes when fixtureEnv stops appending at all — which would
		// quietly let a maintainer's global config and identity back in — and
		// reports a legitimate value change as "a leak survived", sending the
		// reader after a fault that is not there.
		var gitVars []string
		for _, kv := range fixtureEnv() {
			if strings.HasPrefix(kv, "GIT_") {
				gitVars = append(gitVars, kv)
			}
		}
		Expect(gitVars).To(ConsistOf(
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_ATTR_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		))
	})

	// HOME and XDG_CONFIG_HOME are where git looks for its default ignore and
	// attributes files, so leaving the ambient ones in place would let a
	// maintainer's own config reach the fixtures.
	It("redirects HOME and XDG_CONFIG_HOME away from the ambient ones", func() {
		GinkgoT().Setenv("HOME", "/should/not/survive")
		GinkgoT().Setenv("XDG_CONFIG_HOME", "/should/not/survive/config")

		env := fixtureEnv()
		Expect(env).NotTo(ContainElement("HOME=/should/not/survive"))
		Expect(env).NotTo(ContainElement("XDG_CONFIG_HOME=/should/not/survive/config"))

		var homes int
		for _, kv := range env {
			if strings.HasPrefix(kv, "HOME=") {
				homes++
			}
		}
		Expect(homes).To(Equal(1), "HOME must be replaced, not duplicated")
	})
})

var _ = Describe("the pre-push tag gate", func() {
	// Untested shell driving `git show` through sed pipelines is exactly the
	// kind of thing that fails open. These specs run the real script.
	const version = "0.9.0"

	It("allows a tag whose version and chart both match", func() {
		repo := newTagGateRepo(version, version, version)
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())

		// Silence is also what a gate that skipped everything prints, so prove it
		// read this fixture: the same commit under a tag it does not match must be
		// refused, and the refusal has to name the version the fixture holds.
		out, err = repo.push("refs/tags/v0.7.0", repo.sha)
		Expect(err).To(HaveOccurred(), "the gate skipped the tag instead of reading it")
		Expect(out).To(ContainSubstring(`says "` + version + `", not "0.7.0"`))
	})

	// The environment git actually supplies to a pre-push hook: GIT_DIR naming the
	// repository being pushed, which is this fixture. Every other spec here lets
	// the script discover its repository from cwd, a configuration production
	// never presents.
	It("reads the tagged commit when git names the repository, as a real hook does", func() {
		repo := newTagGateRepo(version, version, version)
		out, err := repo.pushAsHook("refs/tags/v"+version, repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})

	It("refuses a mismatching tag when git names the repository too", func() {
		repo := newTagGateRepo("0.8.0", version, version)
		out, err := repo.pushAsHook("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring(`internal/version at the tagged commit says "0.8.0"`))
	})

	// The regression that made this suite dangerous rather than merely wrong.
	// Run from a pre-push hook, os.Environ() carries the repository being pushed
	// in GIT_DIR and friends; they outrank cmd.Dir, so the fixture committed onto
	// the real branch and the specs then asserted against the real repo. A decoy
	// stands in for the hook's repository.
	//
	// All four variables the fixtureEnv comment names are planted, not just the
	// two that happened to cause the incident. A partial strip is destructive in
	// its own right: with GIT_INDEX_FILE alone leaking, `git add -A` still finds
	// the fixture's own .git, so the fixture builds and the decoy stays empty,
	// but the staged entries are written into the other repository's index —
	// destroying whatever the developer had staged when they ran git push.
	decoyLeak := func() {
		decoy := GinkgoT().TempDir()
		gitIn(decoy, "init", "--quiet")
		// A file to stage, so a leak lands a real commit here — the harm as it
		// actually occurred — rather than failing on an empty index.
		Expect(os.WriteFile(filepath.Join(decoy, "tracked.txt"), []byte("x\n"), 0o644)).To(Succeed())

		GinkgoT().Setenv("GIT_DIR", filepath.Join(decoy, ".git"))
		GinkgoT().Setenv("GIT_WORK_TREE", decoy)
		GinkgoT().Setenv("GIT_INDEX_FILE", filepath.Join(decoy, ".git", "index"))
		GinkgoT().Setenv("GIT_OBJECT_DIRECTORY", filepath.Join(decoy, ".git", "objects"))

		// Deferred, so the decoy is proven untouched even when an assertion in
		// the spec body fails first — otherwise the one check that looks at the
		// actual harm is the one that never runs.
		DeferCleanup(func() {
			Expect(gitIn(decoy, "rev-list", "--all", "--count")).To(Equal("0"),
				"a commit landed in the decoy repository")
			Expect(gitIn(decoy, "status", "--porcelain")).To(Equal("?? tracked.txt"),
				"the decoy's index or work tree was written to")
		})
	}

	It("builds and verifies its fixture in its own repository under a leaked environment", func() {
		decoyLeak()

		repo := newTagGateRepo(version, version, version)
		// The fixture must really hold its own commit: without this, a gate that
		// skipped everything would satisfy the assertions below.
		Expect(repo.git("log", "--oneline")).To(ContainSubstring("fixture"))

		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})

	// The allow path above cannot detect a leak at the push site on its own: the
	// gate skips any commit it cannot resolve (`git rev-parse ... || continue`),
	// so a leaked environment makes it exit zero and silent, which is precisely
	// what the allow path asserts. Only a refusal proves the script read the
	// fixture.
	It("still fails closed under a leaked environment", func() {
		decoyLeak()

		repo := newTagGateRepo("0.8.0", version, version)
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred(), "the gate skipped the tag instead of refusing it")
		Expect(out).To(ContainSubstring(`internal/version at the tagged commit says "0.8.0"`))
	})

	It("refuses a tag the internal/version constant disagrees with", func() {
		repo := newTagGateRepo("0.8.0", version, version)
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("internal/version at the tagged commit says \"0.8.0\""))
	})

	It("refuses a tag the chart version disagrees with", func() {
		repo := newTagGateRepo(version, "0.8.0", version)
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring("Helm chart at the tagged commit"))
		Expect(out).To(ContainSubstring(`version="0.8.0"`))
	})

	It("refuses a tag the chart appVersion disagrees with", func() {
		repo := newTagGateRepo(version, version, "0.8.0")
		out, err := repo.push("refs/tags/v"+version, repo.sha)
		Expect(err).To(HaveOccurred())
		Expect(out).To(ContainSubstring(`appVersion="0.8.0"`))
	})

	It("refuses rather than passes when Chart.yaml cannot be parsed", func() {
		// An unquoted appVersion, the most likely way to break the parse. Both
		// halves must fail closed: an empty parse is a mismatch, not a pass.
		repo := newTagGateRepo(version, version, version)
		Expect(os.WriteFile(
			filepath.Join(repo.dir, "charts", "openvox-ca", "Chart.yaml"),
			[]byte("apiVersion: v2\nversion: "+version+"\nappVersion: "+version+"\n"), 0o644,
		)).To(Succeed())
		repo.git("commit", "--quiet", "--no-gpg-sign", "-a", "-m", "unquoted")

		hookOut, err := repo.push("refs/tags/v"+version, repo.git("rev-parse", "HEAD"))
		Expect(err).To(HaveOccurred())
		Expect(hookOut).To(ContainSubstring(`appVersion=""`))
	})

	It("ignores a branch push", func() {
		repo := newTagGateRepo("0.8.0", "0.7.0", "0.6.0")
		out, err := repo.push("refs/heads/main", repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})

	It("ignores a tag deletion", func() {
		// git signals a deletion with an all-zero local sha; there is no commit
		// to inspect, and refusing one would make a bad tag unremovable.
		repo := newTagGateRepo("0.8.0", "0.7.0", "0.6.0")
		out, err := repo.push("refs/tags/v"+version, strings.Repeat("0", 40))
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})

	It("ignores a non-version tag", func() {
		repo := newTagGateRepo("0.8.0", "0.7.0", "0.6.0")
		out, err := repo.push("refs/tags/nightly", repo.sha)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(BeEmpty())
	})
})
