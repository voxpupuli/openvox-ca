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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.yaml.in/yaml/v3"
)

// -- the release tag gate -------------------------------------------------------

// releaseGateStep is the step of the verify-release-tag action that reads the
// tagged commit's check runs: its script, and its environment with the one
// expression it may hold replaced. It is found by what it does rather than by
// its name, so renaming the step does not orphan these specs, and the step is
// refused if it uses anything this harness cannot reproduce.
func releaseGateStep() (script string, env []string) {
	GinkgoHelper()
	src, err := os.ReadFile(filepath.Join(".github", "actions", "verify-release-tag", "action.yml"))
	Expect(err).NotTo(HaveOccurred())
	var action struct {
		Runs struct {
			Steps []struct {
				Shell string            `yaml:"shell"`
				Env   map[string]string `yaml:"env"`
				Run   string            `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	Expect(yaml.Unmarshal(src, &action)).To(Succeed())

	found := 0
	for _, step := range action.Runs.Steps {
		if !strings.Contains(step.Run, "/check-runs") {
			continue
		}
		found++
		// GitHub runs a composite step's `shell: bash` as
		// `bash --noprofile --norc -eo pipefail`, which is how these specs run
		// it; another shell would be a different program.
		Expect(step.Shell).To(Equal("bash"))
		// An expression in the script is substituted by the runner before
		// bash sees it, so the script this harness runs would not be the one
		// GitHub runs.
		Expect(step.Run).NotTo(ContainSubstring("${{"))
		script = step.Run
		for k, v := range step.Env {
			switch {
			case v == "${{ github.token }}":
				v = "stub-token"
			case strings.Contains(v, "${{"):
				Fail(fmt.Sprintf("env %s=%q is an expression these specs do not know how to supply", k, v))
			}
			env = append(env, k+"="+v)
		}
	}
	Expect(found).To(Equal(1), "expected exactly one step in verify-release-tag to read check runs")
	return script, env
}

// releaseGatePermissions are the token scopes the verify-release-tag step
// needs, each at least read: contents for the compare API, checks for the
// check runs, actions for the workflow runs.
var releaseGatePermissions = []string{"contents", "checks", "actions"}

// releaseGateCallerErrors returns, for every job in sources that uses the
// verify-release-tag action, each scope in releaseGatePermissions its token
// lacks, and the names of the workflows that call it. A job's own
// `permissions:` replaces the workflow's, as GitHub applies them, and a scope
// left out of whichever applies is none. A token without a grant fails the
// gate closed, but only once a v* tag is pushed, and the tag's own workflow
// file is the one that runs, so the remedy is a fix commit and a new tag.
func releaseGateCallerErrors(sources map[string][]byte) (callers []string, errs []error) {
	for _, file := range slices.Sorted(maps.Keys(sources)) {
		var doc struct {
			Permissions yaml.Node `yaml:"permissions"`
			Jobs        map[string]struct {
				Permissions yaml.Node       `yaml:"permissions"`
				Steps       []aggregateStep `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(sources[file], &doc); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", file, err))
			continue
		}
		for _, id := range slices.Sorted(maps.Keys(doc.Jobs)) {
			job := doc.Jobs[id]
			if !slices.ContainsFunc(job.Steps, func(st aggregateStep) bool {
				return st.Uses == "./.github/actions/verify-release-tag"
			}) {
				continue
			}
			callers = append(callers, file)
			perms := doc.Permissions
			if !job.Permissions.IsZero() {
				perms = job.Permissions
			}
			for _, scope := range releaseGatePermissions {
				if !grantsRead(perms, scope) {
					errs = append(errs, fmt.Errorf("%s job %q runs verify-release-tag without %s: read", file, id, scope))
				}
			}
		}
	}
	return callers, errs
}

// grantsRead reports whether a `permissions:` node gives scope at least read.
// An absent node is the repository's default token, which this repository
// does not rely on, so it is refused like a missing scope.
func grantsRead(perms yaml.Node, scope string) bool {
	switch perms.Kind {
	case yaml.ScalarNode:
		return perms.Value == "read-all" || perms.Value == "write-all"
	case yaml.MappingNode:
		for i := 0; i+1 < len(perms.Content); i += 2 {
			if perms.Content[i].Value == scope {
				v := perms.Content[i+1].Value
				return v == "read" || v == "write"
			}
		}
	}
	return false
}

// gateCheckRun is one check run as the GitHub API lists it. A nil conclusion
// is one still queued or in progress.
type gateCheckRun struct {
	Name       string       `json:"name"`
	Status     string       `json:"status"`
	Conclusion *string      `json:"conclusion"`
	App        gateRunApp   `json:"app"`
	CheckSuite gateSuiteRef `json:"check_suite"`
}

// gateSuiteRef is the check suite a check run belongs to: one per workflow
// run.
type gateSuiteRef struct {
	ID int64 `json:"id"`
}

// gateWorkflowRun is one workflow run as the Actions API lists it.
type gateWorkflowRun struct {
	CheckSuiteID   int64       `json:"check_suite_id"`
	Event          string      `json:"event"`
	HeadBranch     string      `json:"head_branch"`
	HeadRepository gateRepoRef `json:"head_repository"`
	Repository     gateRepoRef `json:"repository"`
}

type gateRepoRef struct {
	ID int64 `json:"id"`
}

// The repository the gate runs in, and a fork of it.
var (
	gateRepo = gateRepoRef{ID: 1}
	gateFork = gateRepoRef{ID: 2}
)

// mainSuite is the check suite of the push run on main, at the fixture
// commit, of the workflow that reports name. Each aggregate comes from a
// workflow of its own, so on a real commit each is in a suite of its own, and
// the step has to collect every one of main's suites, not just one. Every
// other check is put in the first. Only these suites' check runs may count.
func mainSuite(name string) int64 {
	for i, agg := range requiredCheckAggregates {
		if agg.name == name {
			return int64(101 + i)
		}
	}
	return 101
}

// mainPushes are the push runs on main that those suites belong to, one per
// aggregate.
func mainPushes() []gateWorkflowRun {
	runs := make([]gateWorkflowRun, 0, len(requiredCheckAggregates))
	for _, agg := range requiredCheckAggregates {
		runs = append(runs, gateWorkflowRun{
			CheckSuiteID: mainSuite(agg.name), Event: "push", HeadBranch: "main",
			HeadRepository: gateRepo, Repository: gateRepo,
		})
	}
	return runs
}

// inSuite returns runs moved into suite.
func inSuite(suite int64, runs []gateCheckRun) []gateCheckRun {
	out := make([]gateCheckRun, len(runs))
	for i, r := range runs {
		r.CheckSuite = gateSuiteRef{ID: suite}
		out[i] = r
	}
	return out
}

// gateRunApp is the GitHub App that posted a check run.
type gateRunApp struct {
	Slug string `json:"slug"`
}

// actionsApp is the app main's ruleset pins every required check to.
var actionsApp = gateRunApp{Slug: "github-actions"}

func completedRun(name, conclusion string) gateCheckRun {
	return gateCheckRun{Name: name, Status: "completed", Conclusion: &conclusion, App: actionsApp,
		CheckSuite: gateSuiteRef{ID: mainSuite(name)}}
}

func inProgressRun(name string) gateCheckRun {
	return gateCheckRun{Name: name, Status: "in_progress", App: actionsApp,
		CheckSuite: gateSuiteRef{ID: mainSuite(name)}}
}

// passingAggregates is a passing run of every required aggregate, the state of
// a commit that has gone green on main.
func passingAggregates() []gateCheckRun {
	runs := make([]gateCheckRun, 0, len(requiredCheckAggregates))
	for _, agg := range requiredCheckAggregates {
		runs = append(runs, completedRun(agg.name, "success"))
	}
	return runs
}

// gatePageSize is small so that a fixture carrying otherChecks spans several
// pages, with the aggregates on later ones: a gate that read only the first
// page, or judged each page on its own, would see a different commit from the
// one the fixture describes.
const gatePageSize = 2

// stubGH stands in for gh. It understands only the calls the gate makes and
// fails on any other argument, as a real gh fails on a flag combination it
// refuses -- which is how the gate came to refuse every tag: gh rejects
// --slurp together with --jq. The filter is applied with the real jq, once per
// page as `gh api --paginate --jq` does. Without filter=all in the query it
// returns only the last run of each name, which is how GitHub's default
// filter=latest treats a later run of the same check. The workflow-runs call
// returns every fixture run whatever its query asks for, so the filtering the
// specs exercise is the step's own, not GitHub's.
const stubGH = `#!/bin/sh
printf '%s\n' "$*" >> "$STUB_DIR/calls"
[ "$1" = api ] || { echo "stub gh: unexpected command $1" >&2; exit 2; }
endpoint=$2
shift 2
paginate=0
filter=
while [ $# -gt 0 ]; do
	case $1 in
	--paginate) paginate=1 ;;
	--jq) filter=$2; shift ;;
	*) echo "stub gh: unexpected argument $1" >&2; exit 2 ;;
	esac
	shift
done
[ -n "$filter" ] || { echo "stub gh: no --jq" >&2; exit 2; }
case $endpoint in
"repos/$STUB_REPO")
	echo '{"default_branch":"main"}' | jq -r "$filter" ;;
"repos/$STUB_REPO/compare/main...$STUB_SHA")
	printf '{"status":"%s"}\n' "$STUB_COMPARE" | jq -r "$filter" ;;
"repos/$STUB_REPO/actions/runs?head_sha=$STUB_SHA&"*)
	[ -z "$STUB_FAIL_RUNS" ] || { echo "stub gh: HTTP 502: Bad Gateway" >&2; exit 1; }
	for page in "$STUB_DIR/runs"/*.json; do
		jq -r "$filter" "$page" || exit 1
		[ "$paginate" = 1 ] || break
	done ;;
"repos/$STUB_REPO/commits/$STUB_SHA/check-runs"*)
	[ -z "$STUB_FAIL_CHECKS" ] || { echo "stub gh: HTTP 502: Bad Gateway" >&2; exit 1; }
	case $endpoint in *filter=all*) set=all ;; *) set=latest ;; esac
	for page in "$STUB_DIR/$set"/*.json; do
		jq -r "$filter" "$page" || exit 1
		[ "$paginate" = 1 ] || break
	done ;;
*)
	echo "stub gh: unexpected endpoint $endpoint" >&2; exit 2 ;;
esac
`

// releaseGate is one run of the gate's check-run step against a fixture
// commit and a stubbed GitHub.
type releaseGate struct {
	runs         []gateCheckRun
	workflowRuns []gateWorkflowRun // nil means mainPushes()
	compare      string            // the compare API's status, main...commit
	checksFail   bool              // the check-runs call fails
	runsFail     bool              // the workflow-runs call fails
}

// run executes the step and returns its combined output, and the exit status
// it ended with.
func (g releaseGate) run() (string, int) {
	GinkgoHelper()
	_, err := exec.LookPath("jq")
	Expect(err).NotTo(HaveOccurred(), "these specs need jq, which the stub gh filters with")

	repo := newTagGateRepo("1.0.0", "1.0.0", "1.0.0")
	stubDir := GinkgoT().TempDir()
	Expect(os.WriteFile(filepath.Join(stubDir, "gh"), []byte(stubGH), 0o755)).To(Succeed())
	writePages(filepath.Join(stubDir, "all"), "check_runs", gatePageSize, g.runs)
	writePages(filepath.Join(stubDir, "latest"), "check_runs", gatePageSize, latestOfEachName(g.runs))
	workflowRuns := g.workflowRuns
	if workflowRuns == nil {
		workflowRuns = mainPushes()
	}
	// One workflow run per page, so that main's runs, which specs list last,
	// are on pages of their own.
	writePages(filepath.Join(stubDir, "runs"), "workflow_runs", 1, workflowRuns)

	script, stepEnv := releaseGateStep()
	scriptFile := filepath.Join(stubDir, "step.sh")
	Expect(os.WriteFile(scriptFile, []byte(script), 0o644)).To(Succeed())

	compare := g.compare
	if compare == "" {
		compare = "identical"
	}
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return ""
	}
	const repoName = "voxpupuli/openvox-ca"
	// The stub directory is prepended, not the whole PATH: the step runs the
	// real git, grep and jq, and nothing here depends on a command being
	// absent. The calls log below proves the stub, not a real gh, answered.
	env := append(append(fixtureEnv(), stepEnv...),
		"PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_REPOSITORY="+repoName,
		"STUB_DIR="+stubDir,
		"STUB_REPO="+repoName,
		"STUB_SHA="+repo.sha,
		"STUB_COMPARE="+compare,
		"STUB_FAIL_CHECKS="+flag(g.checksFail),
		"STUB_FAIL_RUNS="+flag(g.runsFail),
	)
	out, err := execGateScriptWith([]string{"bash", "--noprofile", "--norc", "-eo", "pipefail"},
		scriptFile, repo.dir, env, "")

	calls, readErr := os.ReadFile(filepath.Join(stubDir, "calls"))
	Expect(readErr).NotTo(HaveOccurred(), "the stub gh was never called; output:\n%s", out)
	Expect(string(calls)).To(ContainSubstring("/actions/runs?head_sha="+repo.sha+"&"),
		"the step did not ask for the fixture commit's workflow runs")
	// A commit main never built is refused on its workflow runs alone.
	if !g.runsFail && !strings.Contains(out, "has no workflow run from a push to main") {
		Expect(string(calls)).To(ContainSubstring("/commits/"+repo.sha+"/check-runs"),
			"the step did not ask for the fixture commit's check runs")
	}

	if err == nil {
		return out, 0
	}
	var exitErr *exec.ExitError
	Expect(errors.As(err, &exitErr)).To(BeTrue(), "running the step: %v", err)
	return out, exitErr.ExitCode()
}

// writePages writes items into dir as the pages of a listing that carries them
// under key, size to a page.
func writePages[T any](dir, key string, size int, items []T) {
	GinkgoHelper()
	Expect(os.Mkdir(dir, 0o755)).To(Succeed())
	for page := 0; page == 0 || page*size < len(items); page++ {
		chunk := items[min(page*size, len(items)):min((page+1)*size, len(items))]
		body, err := json.Marshal(map[string]any{"total_count": len(items), key: chunk})
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(dir, fmt.Sprintf("%03d.json", page)), body, 0o644)).To(Succeed())
	}
}

// latestOfEachName is what GitHub's default filter=latest would list: the
// last run of each name, in the order the names first appear.
func latestOfEachName(runs []gateCheckRun) []gateCheckRun {
	last := map[string]gateCheckRun{}
	var order []string
	for _, r := range runs {
		if _, ok := last[r.Name]; !ok {
			order = append(order, r.Name)
		}
		last[r.Name] = r
	}
	out := make([]gateCheckRun, 0, len(order))
	for _, name := range order {
		out = append(out, last[name])
	}
	return out
}

// otherChecks is the noise a real commit carries, placed ahead of the
// aggregates so they land on later pages.
var otherChecks = []gateCheckRun{
	completedRun("Unit tests", "success"),
	completedRun("Lint", "success"),
	completedRun("Enable auto-merge", "skipped"),
}

var _ = Describe("the release tag gate's callers", func() {
	It("grant every scope the gate reads with, in each workflow that runs it", func() {
		sources, err := readWorkflowSources(filepath.Join(".github", "workflows"))
		Expect(err).NotTo(HaveOccurred())
		callers, errs := releaseGateCallerErrors(sources)
		Expect(errs).To(BeEmpty())
		// A floor, so that a change to how the action is referenced cannot
		// leave this checking nothing.
		Expect(callers).To(ContainElements("release.yml", "container-images.yml", "helm-chart.yml"))
	})

	const step = "    steps:\n      - uses: ./.github/actions/verify-release-tag\n"
	DescribeTable("judges a caller's token",
		func(src string, wantMissing []string) {
			callers, errs := releaseGateCallerErrors(map[string][]byte{"w.yml": []byte(src)})
			Expect(callers).To(Equal([]string{"w.yml"}))
			var got []string
			for _, e := range errs {
				got = append(got, e.Error())
			}
			Expect(got).To(HaveLen(len(wantMissing)))
			for _, scope := range wantMissing {
				Expect(got).To(ContainElement(ContainSubstring("without %s: read", scope)))
			}
		},
		Entry("all three at workflow level",
			"permissions:\n  contents: read\n  checks: read\n  actions: read\njobs:\n  verify:\n"+step, nil),
		Entry("actions left out",
			"permissions:\n  contents: read\n  checks: read\njobs:\n  verify:\n"+step, []string{"actions"}),
		Entry("actions: none",
			"permissions:\n  contents: read\n  checks: read\n  actions: none\njobs:\n  verify:\n"+step, []string{"actions"}),
		Entry("a job-level block replacing a complete workflow one",
			"permissions:\n  contents: read\n  checks: read\n  actions: read\njobs:\n  verify:\n    permissions:\n      contents: read\n"+step,
			[]string{"checks", "actions"}),
		Entry("a job-level block that is complete on its own",
			"jobs:\n  verify:\n    permissions:\n      contents: read\n      checks: write\n      actions: read\n"+step, nil),
		Entry("read-all", "permissions: read-all\njobs:\n  verify:\n"+step, nil),
		Entry("no permissions anywhere", "jobs:\n  verify:\n"+step, []string{"contents", "checks", "actions"}),
	)
})

var _ = Describe("the release tag gate", func() {
	// The gate has never run on GitHub before a release, and 1.0.0 is the
	// first tag through it, so these run the action's own step rather than a
	// copy of its logic. The required list is driven from
	// requiredCheckAggregates, which mirrors main's ruleset: the gate must
	// refuse when any one of them is missing, and accept when all of them
	// pass, which together pin its list to exactly that set.
	It("accepts a commit on which every required aggregate passed", func() {
		out, code := releaseGate{runs: append(otherChecks, passingAggregates()...)}.run()
		Expect(code).To(Equal(0), out)
		for _, agg := range requiredCheckAggregates {
			Expect(out).To(ContainSubstring("has a passing '%s' check run", agg.name))
		}
		Expect(out).To(ContainSubstring("is reachable from main"))
	})

	// without returns passingAggregates with name's run replaced by
	// replacement, or dropped when replacement is nil.
	without := func(name string, replacement *gateCheckRun) []gateCheckRun {
		var runs []gateCheckRun
		for _, r := range passingAggregates() {
			if r.Name != name {
				runs = append(runs, r)
			} else if replacement != nil {
				runs = append(runs, *replacement)
			}
		}
		return append(append([]gateCheckRun{}, otherChecks...), runs...)
	}

	var refusals []TableEntry
	for _, agg := range requiredCheckAggregates {
		failed := completedRun(agg.name, "failure")
		cancelled := completedRun(agg.name, "cancelled")
		running := inProgressRun(agg.name)
		refusals = append(refusals,
			Entry(fmt.Sprintf("%s failed", agg.name), agg.name, without(agg.name, &failed)),
			Entry(fmt.Sprintf("%s was cancelled", agg.name), agg.name, without(agg.name, &cancelled)),
			Entry(fmt.Sprintf("%s is still running", agg.name), agg.name, without(agg.name, &running)),
			Entry(fmt.Sprintf("%s never ran", agg.name), agg.name, without(agg.name, nil)),
		)
	}
	DescribeTable("refuses a commit on which a required aggregate did not pass",
		func(name string, runs []gateCheckRun) {
			out, code := releaseGate{runs: runs}.run()
			Expect(code).To(Equal(1), out)
			Expect(out).To(ContainSubstring("::error::Commit "))
			Expect(out).To(ContainSubstring("has no passing '%s' check run", name))
			// Main did build this commit, so the remedy may be a re-run rather
			// than a new tag.
			Expect(out).To(ContainSubstring("re-run this workflow once it passes"))
			// The refusal is for this check alone: the others are read and
			// reported as passing, so the message names the one to wait for.
			for _, agg := range requiredCheckAggregates {
				if agg.name != name {
					Expect(out).To(ContainSubstring("has a passing '%s' check run", agg.name))
				}
			}
		},
		refusals,
	)

	// A re-run of main's own workflow adds a later attempt of the same check
	// in the same suite; one that failed may not hide the attempt that
	// passed. The gate treats every name alike, so every aggregate is
	// covered: a literal name here would turn into unrelated noise after a
	// rename, and pass without testing anything.
	var supersededEntries []TableEntry
	for _, agg := range requiredCheckAggregates {
		supersededEntries = append(supersededEntries,
			Entry(fmt.Sprintf("%s, then a run still in progress", agg.name), inProgressRun(agg.name)),
			Entry(fmt.Sprintf("%s, then a failed run", agg.name), completedRun(agg.name, "failure")),
		)
	}
	DescribeTable("accepts a commit whose passing run is followed by another of the same name",
		func(later gateCheckRun) {
			runs := append(append(append([]gateCheckRun{}, otherChecks...), passingAggregates()...), later)
			// The fixture must be one GitHub's default filter=latest would
			// refuse, or this would pass alongside ?filter=all rather than
			// because of it.
			for _, r := range latestOfEachName(runs) {
				if r.Name == later.Name {
					passes := r.Conclusion != nil && *r.Conclusion == "success"
					Expect(passes).To(BeFalse(), "the fixture passes under filter=latest too")
				}
			}
			out, code := releaseGate{runs: runs}.run()
			Expect(code).To(Equal(0), out)
		},
		supersededEntries,
	)

	It("does not take a passing check whose name merely contains a required one", func() {
		agg := requiredCheckAggregates[0]
		runs := without(agg.name, nil)
		runs = append(runs, completedRun(agg.name+" (legacy)", "success"), completedRun("Old "+agg.name, "success"))
		out, code := releaseGate{runs: runs}.run()
		Expect(code).To(Equal(1), out)
		Expect(out).To(ContainSubstring("has no passing '%s' check run", agg.name))
	})

	// The ruleset sets each required check's source to GitHub Actions, so
	// a check run another app posts under the same name satisfies neither it
	// nor the gate.
	It("does not take a passing check that another app posted", func() {
		agg := requiredCheckAggregates[0]
		impostor := completedRun(agg.name, "success")
		impostor.App = gateRunApp{Slug: "some-other-app"}
		out, code := releaseGate{runs: without(agg.name, &impostor)}.run()
		Expect(code).To(Equal(1), out)
		Expect(out).To(ContainSubstring("has no passing '%s' check run", agg.name))
	})

	// Reachable from main is not built on main. A merged PR's head is an
	// ancestor of main and carries passing runs from the PR's own suites,
	// which is the commit `git tag` lands on straight after
	// `mage release:prepare`; main never built that tree. Three things make a
	// run main's own: a push event, to the default branch, in this
	// repository. The first two entries are the realistic cases and each fails
	// two of them; each of the rest fails exactly one, so dropping any one test
	// from the step fails an entry here. The aggregates all pass, in that run's
	// suite alone.
	//
	// otherSuite's id is a prefix of every main suite's, so a step that
	// matched suite ids as substrings rather than whole lines would take it
	// for one of main's; the partial-refusal spec below is the one where that
	// matters, since main has suites of its own there.
	const otherSuite = 10
	DescribeTable("refuses a commit whose passing runs are not from a push to main",
		func(run gateWorkflowRun) {
			run.CheckSuiteID = otherSuite
			runs := inSuite(otherSuite, append(append([]gateCheckRun{}, otherChecks...), passingAggregates()...))
			out, code := releaseGate{runs: runs, workflowRuns: []gateWorkflowRun{run}}.run()
			Expect(code).To(Equal(1), out)
			Expect(out).To(ContainSubstring("has no workflow run from a push to main"))
			Expect(out).To(ContainSubstring("Tag the merge commit on main"))
			Expect(out).NotTo(ContainSubstring("has a passing"))
		},
		Entry("a merged PR's head, passing in the PR's own runs",
			gateWorkflowRun{Event: "pull_request", HeadBranch: "release/v1.0.0", HeadRepository: gateRepo, Repository: gateRepo}),
		Entry("a fork's PR from its own branch named main",
			gateWorkflowRun{Event: "pull_request", HeadBranch: "main", HeadRepository: gateFork, Repository: gateRepo}),
		Entry("a run whose head branch is main, but not from a push",
			gateWorkflowRun{Event: "pull_request", HeadBranch: "main", HeadRepository: gateRepo, Repository: gateRepo}),
		Entry("a push to main, but in a fork",
			gateWorkflowRun{Event: "push", HeadBranch: "main", HeadRepository: gateFork, Repository: gateRepo}),
		Entry("a push of the tag itself",
			gateWorkflowRun{Event: "push", HeadBranch: "v1.0.0", HeadRepository: gateRepo, Repository: gateRepo}),
		Entry("a push to another branch",
			gateWorkflowRun{Event: "push", HeadBranch: "release/v1.0.0", HeadRepository: gateRepo, Repository: gateRepo}),
	)

	// The commit can carry other suites as well as main's: the PR runs of a
	// fast-forwarded head, or the tag's own runs, which are this gate's and
	// still in progress or failed while it runs. Main's passing run decides.
	DescribeTable("accepts main's passing push run alongside runs from other suites",
		func(other gateWorkflowRun, later gateCheckRun) {
			other.CheckSuiteID = otherSuite
			later.CheckSuite = gateSuiteRef{ID: otherSuite}
			runs := append(append(append([]gateCheckRun{}, otherChecks...), passingAggregates()...), later)
			out, code := releaseGate{runs: runs, workflowRuns: append([]gateWorkflowRun{other}, mainPushes()...)}.run()
			Expect(code).To(Equal(0), out)
		},
		Entry("the tag's own run, still in progress",
			gateWorkflowRun{Event: "push", HeadBranch: "v1.0.0", HeadRepository: gateRepo, Repository: gateRepo},
			inProgressRun(requiredCheckAggregates[len(requiredCheckAggregates)-1].name)),
		Entry("the tag's own run, failed",
			gateWorkflowRun{Event: "push", HeadBranch: "v1.0.0", HeadRepository: gateRepo, Repository: gateRepo},
			completedRun(requiredCheckAggregates[len(requiredCheckAggregates)-1].name, "failure")),
		Entry("the PR run of a fast-forwarded head, passing too",
			gateWorkflowRun{Event: "pull_request", HeadBranch: "release/v1.0.0", HeadRepository: gateRepo, Repository: gateRepo},
			completedRun(requiredCheckAggregates[0].name, "success")),
	)

	// One aggregate from main's push and the other only from a PR run is a
	// commit main did not fully build: main has no push run of the last
	// aggregate's workflow here, only the PR's.
	It("refuses when only some aggregates passed in main's push run", func() {
		pr := gateWorkflowRun{CheckSuiteID: otherSuite, Event: "pull_request", HeadBranch: "release/v1.0.0",
			HeadRepository: gateRepo, Repository: gateRepo}
		last := requiredCheckAggregates[len(requiredCheckAggregates)-1].name
		runs := append([]gateCheckRun{}, otherChecks...)
		for _, r := range passingAggregates() {
			if r.Name == last {
				r.CheckSuite = gateSuiteRef{ID: otherSuite}
			}
			runs = append(runs, r)
		}
		pushes := mainPushes()
		out, code := releaseGate{runs: runs, workflowRuns: append([]gateWorkflowRun{pr}, pushes[:len(pushes)-1]...)}.run()
		Expect(code).To(Equal(1), out)
		Expect(out).To(ContainSubstring("has no passing '%s' check run from a push to main", last))
		Expect(out).To(ContainSubstring("has a passing '%s' check run from a push to main", requiredCheckAggregates[0].name))
	})

	It("refuses when the check runs cannot be listed", func() {
		out, code := releaseGate{runs: passingAggregates(), checksFail: true}.run()
		Expect(code).NotTo(Equal(0), out)
		Expect(out).To(ContainSubstring("Could not list the check runs"))
		Expect(out).NotTo(ContainSubstring("has a passing"))
	})

	It("refuses when the workflow runs cannot be listed", func() {
		out, code := releaseGate{runs: passingAggregates(), runsFail: true}.run()
		Expect(code).NotTo(Equal(0), out)
		Expect(out).To(ContainSubstring("Could not list the workflow runs"))
		Expect(out).NotTo(ContainSubstring("has a passing"))
	})

	DescribeTable("judges reachability from the default branch",
		func(status string, wantCode int) {
			out, code := releaseGate{runs: passingAggregates(), compare: status}.run()
			Expect(code).To(Equal(wantCode), out)
			if wantCode != 0 {
				Expect(out).To(ContainSubstring("is not reachable from main (compare status: %s)", status))
			}
		},
		Entry("identical", "identical", 0),
		Entry("behind", "behind", 0),
		Entry("ahead, as a never-merged PR head is", "ahead", 1),
		Entry("diverged", "diverged", 1),
	)
})
