//go:build mage

// Copyright (C) 2026 Trevor Vaughan
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
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	yaml "go.yaml.in/yaml/v3"

	"github.com/caarlos0/env/v11"
	openbao "github.com/openbao/openbao/api/v2"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	daemon "github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// -- Namespaces ----------------------------------------------------------------

type Build mg.Namespace   // build:all  build:fips  build:dist  build:distVariant
type Test mg.Namespace    // test:unit  test:magefile  test:integcompose  test:integcomposefips  test:loadcompose  test:bench  test:puppet  test:puppetfips  test:migration  test:backendsRedis  test:backendsEtcd
type Dev mg.Namespace     // dev:check  dev:tidy    dev:clean  dev:container
type Release mg.Namespace // release:prepare
type Chart mg.Namespace   // chart:version  chart:lint  chart:validate  chart:test  chart:package

// -- Helpers ------------------------------------------------------------------─

func ensureBinDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", err
	}
	return binDir, nil
}

// systemInfo returns REPORT_* environment variables describing the host system
// so they can be passed to k6 containers and included in benchmark reports.
// Values are best-effort; any item that cannot be determined is omitted.
func systemInfo() map[string]string {
	info := map[string]string{}

	if h, err := os.Hostname(); err == nil {
		info["REPORT_HOST"] = h
	}
	info["REPORT_CPUS"] = strconv.Itoa(runtime.NumCPU())

	// Memory total: /proc/meminfo on Linux, sysctl on macOS/BSD.
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.SplitN(string(data), "\n", 50) {
			if strings.HasPrefix(line, "MemTotal:") {
				if fields := strings.Fields(line); len(fields) >= 2 {
					if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
						info["REPORT_MEM_GB"] = fmt.Sprintf("%.1f", float64(kb)/1048576)
					}
				}
				break
			}
		}
	} else if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64); err == nil {
			info["REPORT_MEM_GB"] = fmt.Sprintf("%.1f", float64(n)/1073741824)
		}
	}

	// Kernel/OS: uname -sr works on Linux, macOS, and BSDs.
	if out, err := exec.Command("uname", "-sr").Output(); err == nil {
		info["REPORT_KERNEL"] = strings.TrimSpace(string(out))
	}

	return info
}

// -- build:* ------------------------------------------------------------------─

// All compiles both binaries (openvox-ca and openvox-ca-ctl) to bin/.
func (Build) All() error {
	env := map[string]string{"CGO_ENABLED": "0"}

	fmt.Println("Building...")
	binDir, err := ensureBinDir()
	if err != nil {
		return err
	}

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	if err := sh.RunWithV(env, "go", "build",
		"-o", filepath.Join(binDir, "openvox-ca"+ext),
		"./cmd/openvox-ca"); err != nil {
		return err
	}

	return sh.RunWithV(env, "go", "build",
		"-o", filepath.Join(binDir, "openvox-ca-ctl"+ext),
		"./cmd/openvox-ca-ctl")
}

// FIPS compiles openvox-ca with GOEXPERIMENT=boringcrypto for FIPS compliance
// (Linux/amd64 only). Output: bin/openvox-ca-fips.
func (Build) FIPS() error {
	fmt.Println("Building FIPS compliant binary...")

	targetOS := os.Getenv("GOOS")
	if targetOS == "windows" {
		fmt.Println("WARNING: FIPS mode (boringcrypto) is NOT supported on Windows.")
		fmt.Println("  The build will continue, but it will create a LINUX binary (GOOS=linux).")
	} else if targetOS == "" && runtime.GOOS == "windows" {
		fmt.Println("WARNING: You are building on Windows, but FIPS mode requires Linux.")
		fmt.Println("  Cross-compiling a LINUX binary (bin/openvox-ca-fips). This will not run on Windows.")
	}

	binDir, err := ensureBinDir()
	if err != nil {
		return err
	}

	env := map[string]string{
		"GOEXPERIMENT": "boringcrypto",
		"CGO_ENABLED":  "1",
		"GOOS":         "linux",
		"GOARCH":       "amd64",
	}

	if err := sh.RunWith(env, "go", "build",
		"-o", filepath.Join(binDir, "openvox-ca"),
		"./cmd/openvox-ca"); err != nil {
		return err
	}

	return sh.RunWith(env, "go", "build",
		"-o", filepath.Join(binDir, "openvox-ca-ctl"),
		"./cmd/openvox-ca-ctl")
}

// releaseVersion extracts the Version constant from internal/version, the
// single source of truth for the release version. Parsed from source rather
// than imported so that editing the constant never requires rebuilding the
// mage binary to be picked up.
func releaseVersion() (string, error) {
	src, err := os.ReadFile(filepath.Join("internal", "version", "version.go"))
	if err != nil {
		return "", err
	}
	m := regexp.MustCompile(`(?m)^const Version = "([^"]+)"$`).FindSubmatch(src)
	if m == nil {
		return "", fmt.Errorf("could not find the Version constant in internal/version/version.go")
	}
	return string(m[1]), nil
}

// fipsCrossCC returns the C compiler needed to link the boringcrypto syso for
// a FIPS build targeting goarch. Cross-linking from a different architecture
// needs the matching GNU cross toolchain (on Debian/Ubuntu: the
// gcc-aarch64-linux-gnu / gcc-x86-64-linux-gnu packages). Returns "" when the
// default compiler is fine (native Linux build) or when CC is already set in
// the environment (respected as an override).
func fipsCrossCC(goarch string) string {
	if os.Getenv("CC") != "" {
		return ""
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == goarch {
		return ""
	}
	switch goarch {
	case "amd64":
		return "x86_64-linux-gnu-gcc"
	case "arm64":
		return "aarch64-linux-gnu-gcc"
	}
	return ""
}

// workflowMatrixVariants extracts the `variant:` values from the
// strategy.matrix.include list of the named job in a workflow YAML document.
func workflowMatrixVariants(src []byte, job string) ([]string, error) {
	var doc struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Include []map[string]any `yaml:"include"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	j, ok := doc.Jobs[job]
	if !ok {
		return nil, fmt.Errorf("job %q not found", job)
	}
	var names []string
	for _, inc := range j.Strategy.Matrix.Include {
		if v, ok := inc["variant"].(string); ok {
			names = append(names, v)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("job %q has no matrix include entries with a variant key", job)
	}
	return names, nil
}

// shellVariantList extracts the variant names iterated by the
// `for variant in ...; do` loop in the release workflow's checksum step.
func shellVariantList(src []byte) ([]string, error) {
	m := regexp.MustCompile(`for variant in ([a-z0-9_ ]+); do`).FindSubmatch(src)
	if m == nil {
		return nil, fmt.Errorf("no 'for variant in ...; do' loop found")
	}
	return strings.Fields(string(m[1])), nil
}

// verifyDistVariants asserts that every hand-maintained copy of the release
// variant list in the workflows agrees with distVariants(), the single source
// of truth. Wired into dev:check so a variant added or renamed in one place
// but not the others fails CI loudly instead of silently shipping an
// incomplete release. The checked copies: ci.yml's dist job matrix,
// release.yml's build job matrix, and release.yml's checksum-step shell loop
// and tarball-count literal.
func verifyDistVariants() error {
	ciSrc, err := os.ReadFile(filepath.Join(".github", "workflows", "ci.yml"))
	if err != nil {
		return err
	}
	relSrc, err := os.ReadFile(filepath.Join(".github", "workflows", "release.yml"))
	if err != nil {
		return err
	}
	return verifyDistVariantsIn(ciSrc, relSrc)
}

// verifyDistVariantsIn is verifyDistVariants over caller-supplied workflow
// contents, split out so the mismatch branches are testable without touching
// the real workflow files.
func verifyDistVariantsIn(ciSrc, relSrc []byte) error {
	want := make([]string, 0, len(distVariants()))
	for _, v := range distVariants() {
		want = append(want, v.name)
	}
	sortedWant := slices.Sorted(slices.Values(want))

	checks := []struct {
		where string
		got   func() ([]string, error)
	}{
		{"ci.yml dist job matrix", func() ([]string, error) { return workflowMatrixVariants(ciSrc, "dist") }},
		{"release.yml build job matrix", func() ([]string, error) { return workflowMatrixVariants(relSrc, "build") }},
		{"release.yml checksum-step shell loop", func() ([]string, error) { return shellVariantList(relSrc) }},
	}
	for _, c := range checks {
		got, err := c.got()
		if err != nil {
			return fmt.Errorf("%s: %w", c.where, err)
		}
		if !slices.Equal(slices.Sorted(slices.Values(got)), sortedWant) {
			return fmt.Errorf("%s lists variants %v, but distVariants() in magefile.go defines %v; update them together",
				c.where, got, want)
		}
	}

	// The checksum step also asserts an exact tarball count.
	m := regexp.MustCompile(`"\$tarballs" -ne (\d+)`).FindSubmatch(relSrc)
	if m == nil {
		return fmt.Errorf("release.yml: tarball-count check not found")
	}
	if count, _ := strconv.Atoi(string(m[1])); count != len(want) {
		return fmt.Errorf("release.yml expects %s tarballs, but distVariants() defines %d; update them together",
			m[1], len(want))
	}
	return nil
}

// distVariantSpec describes one release artefact: its short name (the
// artefact-name suffix, e.g. "linux_arm64_fips") and the build environment
// that produces it.
type distVariantSpec struct {
	name string
	env  map[string]string
}

// distVariants returns the full set of release artefact variants. The FIPS
// variants are cgo builds, so they need a Linux host with a C toolchain for
// the target architecture (see fipsCrossCC); the pure-Go variants
// cross-compile from anywhere.
func distVariants() []distVariantSpec {
	fipsEnv := func(goarch string) map[string]string {
		env := map[string]string{"CGO_ENABLED": "1", "GOOS": "linux", "GOARCH": goarch, "GOEXPERIMENT": "boringcrypto"}
		if cc := fipsCrossCC(goarch); cc != "" {
			env["CC"] = cc
		}
		return env
	}
	return []distVariantSpec{
		{
			name: "linux_amd64",
			env:  map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"},
		},
		{
			name: "linux_arm64",
			env:  map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "arm64"},
		},
		{
			name: "linux_amd64_fips",
			env:  fipsEnv("amd64"),
		},
		{
			name: "linux_arm64_fips",
			env:  fipsEnv("arm64"),
		},
	}
}

// distUnitFile is the systemd unit shipped in every release archive, so a VM
// install has a unit that matches this build's notification behaviour (see
// docs/systemd.md). Named once: the same string is the name under
// packaging/systemd/ and the name inside the tarball.
const distUnitFile = "openvox-ca.service"

// distArchiveFiles lists a release archive's contents with the mode each entry
// must extract as. Stating the modes here rather than reading them back off the
// staged files keeps the tarball identical whatever umask the release is built
// under; deriving the executables from bins keeps the archive in step with what
// is built. Separate from buildDistVariant so the manifest can be asserted
// without cross-compiling four variants -- the CI job that used to unpack every
// tarball and grep its listing cost a full release build to check a list.
func distArchiveFiles(bins []string) []archiveEntry {
	files := make([]archiveEntry, 0, len(bins)+1)
	for _, b := range bins {
		files = append(files, archiveEntry{name: b, mode: 0755})
	}
	return append(files, archiveEntry{name: distUnitFile, mode: 0644})
}

// buildDistVariant builds one variant's tarball into distDir and returns its
// SHA-256 checksum. The artefact is named openvox-ca_VER_NAME.tar.gz and
// contains both binaries plus the systemd unit.
func buildDistVariant(distDir, ver string, v distVariantSpec) (string, error) {
	bins := []string{"openvox-ca", "openvox-ca-ctl"}
	unitSrc := filepath.Join("packaging", "systemd", distUnitFile)
	archive := filepath.Join(distDir, fmt.Sprintf("openvox-ca_%s_%s.tar.gz", ver, v.name))

	tmpDir, err := os.MkdirTemp("", "openvox-ca-dist-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	for _, cmd := range bins {
		// -trimpath keeps builder paths out of the binaries so artefacts are
		// reproducible across build machines.
		if err := sh.RunWith(v.env, "go", "build", "-trimpath",
			"-o", filepath.Join(tmpDir, cmd),
			"./cmd/"+cmd); err != nil {
			return "", fmt.Errorf("build %s for %s: %w", cmd, v.name, err)
		}
	}

	if err := sh.Copy(filepath.Join(tmpDir, distUnitFile), unitSrc); err != nil {
		return "", fmt.Errorf("stage %s for %s: %w", distUnitFile, v.name, err)
	}

	if err := createTarGz(archive, tmpDir, distArchiveFiles(bins)); err != nil {
		return "", fmt.Errorf("archive %s: %w", v.name, err)
	}
	return sha256File(archive)
}

// Dist cross-compiles release artifacts for all supported platforms and writes
// them to dist/. Each artifact is a .tar.gz containing openvox-ca,
// openvox-ca-ctl, and the systemd unit openvox-ca.service (see
// docs/systemd.md). A SHA-256 checksums.txt is also written to dist/.
//
// Artifacts produced (VERSION is the internal/version constant):
//
//	openvox-ca_VERSION_linux_amd64.tar.gz       (standard; CGO_ENABLED=0)
//	openvox-ca_VERSION_linux_arm64.tar.gz       (standard; CGO_ENABLED=0)
//	openvox-ca_VERSION_linux_amd64_fips.tar.gz  (FIPS; GOEXPERIMENT=boringcrypto)
//	openvox-ca_VERSION_linux_arm64_fips.tar.gz  (FIPS; GOEXPERIMENT=boringcrypto)
//
// CI and the Release workflow build one variant per (native) runner via
// build:distVariant instead; this target remains the way to build everything
// locally.
func (Build) Dist() error {
	distDir := "dist"
	if err := os.RemoveAll(distDir); err != nil {
		return err
	}
	if err := os.MkdirAll(distDir, 0755); err != nil {
		return err
	}

	ver, err := releaseVersion()
	if err != nil {
		return err
	}

	// The variants are independent, so build them concurrently; the Go build
	// and module caches are safe under concurrent use. Checksums are collected
	// per-index to keep checksums.txt in deterministic variant order, and
	// every variant runs to completion so a failure report covers all broken
	// variants, not just the first.
	variants := distVariants()
	var wg sync.WaitGroup
	sums := make([]string, len(variants))
	errs := make([]error, len(variants))
	for i, v := range variants {
		fmt.Printf("Building openvox-ca_%s_%s...\n", ver, v.name)
		wg.Add(1)
		go func(i int, v distVariantSpec) {
			defer wg.Done()
			sums[i], errs[i] = buildDistVariant(distDir, ver, v)
		}(i, v)
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}

	var checksums strings.Builder
	for i, v := range variants {
		fmt.Fprintf(&checksums, "%s  openvox-ca_%s_%s.tar.gz\n", sums[i], ver, v.name)
	}
	return os.WriteFile(
		filepath.Join(distDir, "checksums.txt"),
		[]byte(checksums.String()),
		0644,
	)
}

// DistVariant builds a single release artefact variant (by short name, e.g.
// "linux_arm64_fips") into dist/ without touching other artefacts, and prints
// its SHA-256 checksum. Used by CI and the Release workflow to build each
// variant on a native runner for its architecture; checksums.txt aggregation
// happens in the workflow, not here.
func (Build) DistVariant(name string) error {
	ver, err := releaseVersion()
	if err != nil {
		return err
	}

	for _, v := range distVariants() {
		if v.name != name {
			continue
		}
		if err := os.MkdirAll("dist", 0755); err != nil {
			return err
		}
		fmt.Printf("Building openvox-ca_%s_%s...\n", ver, v.name)
		sum, err := buildDistVariant("dist", ver, v)
		if err != nil {
			return err
		}
		fmt.Printf("%s  openvox-ca_%s_%s.tar.gz\n", sum, ver, v.name)
		return nil
	}

	var known []string
	for _, v := range distVariants() {
		known = append(known, v.name)
	}
	return fmt.Errorf("unknown dist variant %q (known: %s)", name, strings.Join(known, ", "))
}

// -- release:* -----------------------------------------------------------------

// bareSemverRe matches the versions release:prepare accepts: bare semver with
// an optional pre-release suffix (0.9.0, 0.9.0-rc1, 0.10.0-dev), never a "v"
// prefix.
var bareSemverRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// repoSlug derives the "owner/repo" slug from the named git remote.
func repoSlug(remote string) (string, error) {
	url, err := sh.Output("git", "remote", "get-url", remote)
	if err != nil {
		return "", fmt.Errorf("resolving remote %q: %w", remote, err)
	}
	return repoSlugFromURL(strings.TrimSpace(url))
}

// repoSlugFromURL extracts "owner/repo" from a git remote URL, accepting the
// SSH (git@github.com:owner/repo.git), ssh:// and HTTPS forms, with or
// without the .git suffix.
func repoSlugFromURL(url string) (string, error) {
	m := regexp.MustCompile(`[:/]([^/:]+/[^/:]+?)(\.git)?$`).FindStringSubmatch(url)
	if m == nil {
		return "", fmt.Errorf("could not derive owner/repo from remote URL %q", url)
	}
	return m[1], nil
}

// Prepare opens the version-bump pull request that must land before a release
// can be tagged: it creates a release/vVERSION branch off the remote's main,
// sets the internal/version constant and the Helm chart's version and
// appVersion to match, pushes the branch, and opens the PR
// with `gh` — including a preview of the auto-generated release notes for
// release versions (skipped for -dev bumps, which are the post-release step
// returning main to a development version).
//
// The remote defaults to origin; set OPENVOX_CA_RELEASE_REMOTE to prepare a
// release elsewhere (e.g. a fork rehearsal). Requires a clean working tree
// and an authenticated `gh`.
func (Release) Prepare(ver string) error {
	if !bareSemverRe.MatchString(ver) {
		return fmt.Errorf("version %q is not bare semver (expected e.g. 0.9.0, 0.9.0-rc1, or 0.10.0-dev, without a v prefix)", ver)
	}
	remote := os.Getenv("OPENVOX_CA_RELEASE_REMOTE")
	if remote == "" {
		remote = "origin"
	}
	slug, err := repoSlug(remote)
	if err != nil {
		return err
	}

	if out, err := sh.Output("git", "status", "--porcelain"); err != nil {
		return err
	} else if strings.TrimSpace(out) != "" {
		return fmt.Errorf("working tree is not clean; commit or stash first")
	}

	if err := sh.RunV("git", "fetch", remote); err != nil {
		return err
	}
	branch := "release/v" + ver
	if err := sh.RunV("git", "switch", "-c", branch, remote+"/main"); err != nil {
		return fmt.Errorf("creating %s from %s/main (does the branch already exist?): %w", branch, remote, err)
	}

	verFile := filepath.Join("internal", "version", "version.go")
	src, err := os.ReadFile(verFile)
	if err != nil {
		return err
	}
	re := regexp.MustCompile(`(?m)^const Version = "[^"]+"$`)
	if !re.Match(src) {
		return fmt.Errorf("could not find the Version constant in %s", verFile)
	}
	if err := os.WriteFile(verFile, re.ReplaceAll(src, fmt.Appendf(nil, "const Version = %q", ver)), 0644); err != nil {
		return err
	}

	// The Helm chart releases in lockstep, so its version and appVersion move
	// with the constant. chart:version (and the tag gates) refuse a mismatch.
	chartFile := filepath.Join(chartDir, "Chart.yaml")
	chartSrc, err := os.ReadFile(chartFile)
	if err != nil {
		return err
	}
	if !chartVersionRe.Match(chartSrc) {
		return fmt.Errorf("could not find the version field in %s", chartFile)
	}
	if !chartAppVersionRe.Match(chartSrc) {
		return fmt.Errorf("could not find the appVersion field in %s", chartFile)
	}
	chartSrc = chartVersionRe.ReplaceAll(chartSrc, fmt.Appendf(nil, "version: %s", ver))
	chartSrc = chartAppVersionRe.ReplaceAll(chartSrc, fmt.Appendf(nil, "appVersion: %q", ver))
	if err := os.WriteFile(chartFile, chartSrc, 0644); err != nil {
		return err
	}

	isDev := strings.HasSuffix(ver, "-dev")
	title := "Release v" + ver
	body := fmt.Sprintf(`Sets the release version to %s. Once this merges, cut the release by pushing the tag (see docs/development/releasing.md):

    git fetch %s
    git tag -a v%s %s/main -m "OpenVox CA %s"
    git push %s v%s
`, ver, remote, ver, remote, ver, remote, ver)
	if isDev {
		title = "Bump version to " + ver
		body = fmt.Sprintf("Post-release bump so builds from main identify as %s rather than as the release.\n", ver)
	}

	if err := sh.RunV("git", "add", verFile, chartFile); err != nil {
		return err
	}
	if err := sh.RunV("git", "commit", "-m", title); err != nil {
		return err
	}
	if err := sh.RunV("git", "push", "-u", remote, branch); err != nil {
		return err
	}

	if !isDev {
		// Preview what --generate-notes will produce so the release PR shows
		// reviewers the notes before the tag exists. Read-only and
		// best-effort: the release itself regenerates the real thing.
		notes, err := sh.Output("gh", "api", "repos/"+slug+"/releases/generate-notes",
			"-f", "tag_name=v"+ver, "-f", "target_commitish=main", "--jq", ".body")
		if err != nil {
			fmt.Println("WARNING: could not generate a release-notes preview:", err)
		} else if notes != "" {
			body += "\n<details><summary>Auto-generated release-notes preview</summary>\n\n" + notes + "\n\n</details>\n"
		}
	}

	return sh.RunV("gh", "pr", "create", "--repo", slug, "--base", "main",
		"--head", branch, "--title", title, "--body", body)
}

// -- chart:* -------------------------------------------------------------------

// chartDir is the Helm chart's source directory. The chart ships in lockstep
// with the binaries: both its version and its appVersion track the
// internal/version constant, and chart:version is the gate that says so.
const chartDir = "charts/openvox-ca"

// kubeconformVersion is the Kubernetes API version the rendered manifests are
// validated against. Bumping it is how the chart picks up newly-GA fields.
const kubeconformVersion = "1.31.0"

// kubeconformFloorVersion is the chart's declared kubeVersion floor
// (charts/openvox-ca/Chart.yaml). The minimal fixture — the chart's defaults —
// is validated against it as well, so the floor is a checked promise rather
// than a claim. Fixtures that opt into newer fields
// (unhealthyPodEvictionPolicy is 1.27+, trafficDistribution 1.31+) are only
// checked at kubeconformVersion; both values carry that note, as does the
// chart README's requirements section.
const kubeconformFloorVersion = "1.26.0"

// kubeconformCacheDir is where chart:validate keeps kubeconform's downloaded
// schemas, and what dev:clean removes. Named once because sh.Rm treats a
// missing path as success: two literals would let a rename here leave dev:clean
// quietly cleaning nothing, and clearing this cache is the documented remedy
// for a stale local copy passing what CI fails.
var kubeconformCacheDir = filepath.Join(".test-output", "kubeconform-cache")

// chartFloorFixture is the fixture that stands in for the chart's defaults and
// is therefore the one held to the floor. Named here rather than inline so
// that renaming it fails loudly instead of quietly skipping the check.
const chartFloorFixture = "minimal-values"

// crdSchemaLocation points kubeconform at community-maintained JSON schemas
// for the CRDs the chart can emit (ServiceMonitor, HTTPRoute, TLSRoute), which
// are absent from the core Kubernetes schema set.
//
// Pinned to a commit rather than a branch: this feeds a required check, and
// tracking someone else's main means an upstream reorganisation can turn CI
// red with no change of ours. It is a commit and not a tag because the
// catalogue's newest tag (v0.0.12) predates its Gateway API schemas, so a
// tagged pin cannot validate the routes the chart emits. Refresh it by hand
// when a CRD the chart uses gains a new version; Renovate has no datasource
// for a raw.githubusercontent path.
const crdSchemaCommit = "dcaa31aa03082906c0325a7a0ee7d5191e9cbe24"

const crdSchemaLocation = "https://raw.githubusercontent.com/datreeio/CRDs-catalog/" +
	crdSchemaCommit + "/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

var (
	chartVersionRe    = regexp.MustCompile(`(?m)^version: (.+)$`)
	chartAppVersionRe = regexp.MustCompile(`(?m)^appVersion: "(.+)"$`)
)

// chartVersions parses the version and appVersion fields out of Chart.yaml.
// Parsed textually, like releaseVersion, so that the check does not depend on
// a YAML library or on the chart being renderable.
func chartVersions() (version, appVersion string, err error) {
	path := filepath.Join(chartDir, "Chart.yaml")
	src, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	v := chartVersionRe.FindSubmatch(src)
	if v == nil {
		return "", "", fmt.Errorf("could not find the version field in %s", path)
	}
	a := chartAppVersionRe.FindSubmatch(src)
	if a == nil {
		return "", "", fmt.Errorf("could not find the appVersion field in %s", path)
	}
	return strings.TrimSpace(string(v[1])), strings.TrimSpace(string(a[1])), nil
}

// chartValuesFiles returns the fixture values files under the chart's ci/
// directory. Each is a distinct rendering of the chart that chart:lint and
// chart:validate exercise in full. Finding none is an error rather than a
// no-op: an empty fixture set would silently turn both targets into
// rubber stamps.
//
// Both YAML extensions are collected: globbing only *.yaml would skip a *.yml
// fixture in silence, which is that same rubber stamp one file at a time.
func chartValuesFiles() ([]string, error) {
	return chartValuesFilesIn(filepath.Join(chartDir, "ci"))
}

// chartValuesFilesIn is chartValuesFiles over a caller-supplied directory, so
// that the *.yml arm and the empty-set error can be exercised without writing
// into the real fixture directory. Every fixture in the repository happens to
// be .yaml, so without this seam the second glob is dead code as far as the
// suite is concerned — which is the same rubber stamp the comment above warns
// about, one branch at a time.
func chartValuesFilesIn(dir string) ([]string, error) {
	var files []string
	for _, ext := range []string{"*.yaml", "*.yml"} {
		matched, err := filepath.Glob(filepath.Join(dir, ext))
		if err != nil {
			return nil, err
		}
		files = append(files, matched...)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no fixture values files found under %s", dir)
	}
	slices.Sort(files)
	return files, nil
}

// requireChartTool resolves a tool the chart targets need, turning a missing
// binary into an actionable error rather than an exec failure deep in a
// pipeline.
func requireChartTool(name, install string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s not found on PATH; install it with:\n    %s", name, install)
	}
	return nil
}

// Version verifies that the chart's version and appVersion both equal the
// internal/version constant, so the chart published for a release always
// carries that release's number and defaults to that release's image.
//
// The same check runs in CI, in the shared verify-release-tag gate, and in the
// pre-push hook.
func (Chart) Version() error {
	want, err := releaseVersion()
	if err != nil {
		return err
	}
	version, appVersion, err := chartVersions()
	if err != nil {
		return err
	}
	if version != want || appVersion != want {
		return fmt.Errorf("%s/Chart.yaml is out of step with internal/version (%s): version=%s appVersion=%s\n"+
			"Run 'mage release:prepare %s', or set both fields to %s by hand",
			chartDir, want, version, appVersion, want, want)
	}
	fmt.Printf("Chart version and appVersion match internal/version (%s)\n", want)
	return nil
}

// verifyChartPins asserts the three cross-file agreements the chart depends
// on, in the same spirit as verifyDistVariants and wired into dev:check
// alongside it:
//
//   - kubeconformFloorVersion must be the floor Chart.yaml advertises, so the
//     "checked promise rather than a claim" the constant's comment makes is
//     actually true.
//   - the Helm version helm-chart.yml packages with must be one the chart was
//     validated against in ci.yml's matrix, because packaging with a Helm
//     nobody linted the chart on is how a chart ships broken.
//   - ci.yml's matrix and renovate.json must still agree on which Helm
//     versions Renovate maintains: every matrix entry annotated, and no such
//     annotation sitting anywhere but directly above one of those entries,
//     which would point Renovate at a line no job runs.
//
// The first two are hand-maintained and were previously guarded only by
// comments asking the next editor to keep them in step. The third is the
// opposite — it exists so the matrix stays current *without* anyone
// remembering to bump it — and each has its own testable seam below.
func verifyChartPins() error {
	chartSrc, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil {
		return err
	}
	ciSrc, err := os.ReadFile(filepath.Join(".github", "workflows", "ci.yml"))
	if err != nil {
		return err
	}
	publishSrc, err := os.ReadFile(filepath.Join(".github", "workflows", "helm-chart.yml"))
	if err != nil {
		return err
	}
	renovateSrc, err := os.ReadFile("renovate.json")
	if err != nil {
		return err
	}
	if err := verifyChartPinsIn(chartSrc, ciSrc, publishSrc); err != nil {
		return err
	}
	return verifyCIHelmAnnotationsIn(ciSrc, renovateSrc)
}

// kubeVersion: ">=1.26.0-0" — capture the bare version. Chart.yaml is parsed
// textually rather than as YAML, matching chartVersions: the file's exact
// line shapes are load-bearing for four other parsers, so reading it the same
// way keeps this guard sensitive to the same reformatting they are.
var chartKubeVersionRe = regexp.MustCompile(`(?m)^kubeVersion: "[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)[^"]*"`)

// ciChartHelmMatrix returns the Helm versions ci.yml's chart job validates the
// chart against.
//
// It also asserts the chart job's own setup-helm step actually consumes that
// matrix. A literal there instead would make both legs install the same Helm
// and both pass green — the leg *named* for the other version silently running
// the wrong one — so the link is checked rather than assumed. It is an equality
// against one expression string, no weaker than the publish-side check.
func ciChartHelmMatrix(src []byte) ([]string, error) {
	var doc struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Helm []string `yaml:"helm"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	j, ok := doc.Jobs["chart"]
	if !ok {
		return nil, fmt.Errorf("ci.yml has no 'chart' job")
	}
	if len(j.Strategy.Matrix.Helm) == 0 {
		return nil, fmt.Errorf("ci.yml's chart job has no helm matrix entries")
	}

	v, err := setupHelmVersion(src, "chart", "ci.yml")
	if err != nil {
		return nil, err
	}
	// The matrix leg must reach the install step, or both legs run the same
	// Helm while one is named for the other. Accept any interior spacing:
	// ${{matrix.helm}} is what GitHub itself accepts, and rejecting it would
	// fail the gate on a workflow that installs exactly the right version.
	if !regexp.MustCompile(`^\$\{\{\s*matrix\.helm\s*\}\}$`).MatchString(v) {
		return nil, fmt.Errorf("ci.yml's chart job installs Helm %q instead of ${{ matrix.helm }}, so both "+
			"matrix legs would run the same version while one is named for the other", v)
	}
	return j.Strategy.Matrix.Helm, nil
}

// helmPackageName is the package Renovate resolves a Helm version to, and the
// name renovate.json's packageRules match on. The built-in github-actions
// manager emits it for helm-chart.yml's azure/setup-helm step, and ci.yml's
// annotations name it explicitly because a bare list of version strings gives
// no manager anything to attribute.
const helmPackageName = "helm/helm"

// helmDatasource is where Renovate looks that package up. The annotation has to
// name it too, and correctly: with no datasourceTemplate on the customManager
// there is nothing to fall back to.
const helmDatasource = "github-releases"

// ciHelmMatrixEntry is one leg of ci.yml's chart matrix, with the line it sits
// on. The line is what pairs a leg with its annotation: matching on the version
// alone would let an annotation anywhere else in the file vouch for a bare
// matrix entry, which is the same "reading a pin that belongs to something
// else" failure ciChartHelmMatrix's decoy tests guard against.
type ciHelmMatrixEntry struct {
	Version string
	Line    int
}

// ciHelmMatrixEntries returns the chart job's helm matrix legs with their line
// numbers, read through the YAML node tree so it accepts the same entries
// ciChartHelmMatrix does — a bare `- v3.21.3`, with or without a trailing
// comment. A second textual parser here would drift from that one and report a
// missing annotation for a leg whose annotation is sitting right above it,
// exactly the phantom setupHelmVersion's case-insensitivity exists to avoid.
//
// The quoted form `- "v3.21.3"` parses here too, and is then rejected by the
// caller rather than accepted: Renovate matches raw text, quotes included. See
// verifyCIHelmAnnotationsIn.
func ciHelmMatrixEntries(ciSrc []byte) ([]ciHelmMatrixEntry, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(ciSrc, &root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("ci.yml is empty")
	}
	field := func(n *yaml.Node, key string) *yaml.Node {
		if n == nil {
			return nil
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i+1]
			}
		}
		return nil
	}
	// Distinct messages per step, rather than one shared with ciChartHelmMatrix:
	// two readers of this same path emitting the same sentence would drift into
	// disagreeing about the same fault, and "no chart job" and "chart job with
	// no matrix" send a maintainer to different lines.
	chart := field(field(root.Content[0], "jobs"), "chart")
	if chart == nil {
		return nil, fmt.Errorf("ci.yml has no 'chart' job to read a helm matrix from")
	}
	helm := field(field(field(chart, "strategy"), "matrix"), "helm")
	if helm == nil || len(helm.Content) == 0 {
		return nil, fmt.Errorf("ci.yml's chart job declares no helm matrix legs to annotate")
	}
	entries := make([]ciHelmMatrixEntry, 0, len(helm.Content))
	for _, item := range helm.Content {
		entries = append(entries, ciHelmMatrixEntry{Version: item.Value, Line: item.Line})
	}
	return entries, nil
}

// ciWorkflowPath is ci.yml as Renovate addresses it — repository-relative,
// forward slashes — which is what managerFilePatterns are matched against.
const ciWorkflowPath = ".github/workflows/ci.yml"

// renovateManagerCoversCI reports whether a customManager's managerFilePatterns
// would apply it to ci.yml.
//
// Renovate accepts two spellings. A slash-delimited entry is a regex, which is
// what this repo uses throughout and what this checks exactly. Anything else is
// a glob, whose minimatch semantics are more than this guard should reimplement
// — those are accepted rather than guessed at, because a matcher that got
// `**` subtly wrong would fail the build on a config that is perfectly correct,
// and a phantom failure costs more here than the narrow case it would catch.
func renovateManagerCoversCI(patterns []string) bool {
	for _, p := range patterns {
		body, ok := strings.CutPrefix(p, "/")
		if !ok {
			return true // glob form: not verified, not second-guessed
		}
		body, ok = strings.CutSuffix(body, "/")
		if !ok {
			return true
		}
		if re, err := regexp.Compile(body); err == nil && re.MatchString(ciWorkflowPath) {
			return true
		}
	}
	return false
}

// renovateHelmAnnotationRe returns the regex renovate.json's annotation
// customManager actually uses: the regex-type manager that ci.yml's path falls
// under and whose matchStrings capture both packageName and currentValue. The
// other customManagers set their package by template and cannot describe a
// helm/helm annotation.
//
// Reading Renovate's own expression rather than restating it is the point: a
// copy here would agree on the day it was written and silently diverge later,
// and the direction that costs is the quiet one, where the guard passes while
// Renovate sees nothing. Every way to stop that manager reaching ci.yml fails
// the build, though not all in the same place: deleting it, narrowing its
// managerFilePatterns, or dropping a capture group land on the error here,
// while a regex narrowed so it still captures both groups but no longer matches
// the annotations lands on verifyCIHelmAnnotationsIn's missing-annotation error
// instead. That second check is not redundant with this one.
func renovateHelmAnnotationRe(renovateSrc []byte) (*regexp.Regexp, error) {
	var cfg struct {
		CustomManagers []struct {
			CustomType          string   `json:"customType"`
			ManagerFilePatterns []string `json:"managerFilePatterns"`
			MatchStrings        []string `json:"matchStrings"`
		} `json:"customManagers"`
	}
	if err := json.Unmarshal(renovateSrc, &cfg); err != nil {
		return nil, fmt.Errorf("could not parse renovate.json: %w", err)
	}
	for _, cm := range cfg.CustomManagers {
		// matchStrings only means a regex to a regex-type manager; a jsonata
		// manager's are queries, and compiling one as a regex would be reading
		// a pin that belongs to something else.
		if cm.CustomType != "regex" || !renovateManagerCoversCI(cm.ManagerFilePatterns) {
			continue
		}
		for _, ms := range cm.MatchStrings {
			re, err := regexp.Compile(ms)
			if err != nil {
				// Renovate uses RE2 too, so an expression Go rejects is one
				// Renovate would reject: worth failing on rather than skipping.
				return nil, fmt.Errorf("renovate.json has a customManager matchStrings Renovate could not compile "+
					"either (%q): %w", ms, err)
			}
			if re.SubexpIndex("packageName") >= 0 && re.SubexpIndex("currentValue") >= 0 {
				return re, nil
			}
		}
	}
	return nil, fmt.Errorf("renovate.json has no regex customManager that covers %s and captures both packageName "+
		"and currentValue, so nothing can pick up ci.yml's '# renovate:' Helm annotations and both matrix legs "+
		"would silently stop being bumped", ciWorkflowPath)
}

// verifyCIHelmAnnotationsIn asserts ci.yml's chart matrix and renovate.json
// still agree: every matrix leg carries an annotation renovate.json's own
// customManager matches, and no such annotation sits anywhere but directly
// above one of those legs — an annotated entry elsewhere in the file would have
// Renovate bumping a line no job runs.
//
// Without it the failure is silent in the direction that costs the most: a leg
// added without the annotation is invisible to Renovate, so it never bumps,
// and nothing goes red — it just quietly validates the chart against a Helm
// that stopped being current months ago. A stray annotation is the same fault
// read the other way. Both halves are checked against renovate.json rather
// than against a restatement of it, so editing either file breaks the build
// loudly.
func verifyCIHelmAnnotationsIn(ciSrc, renovateSrc []byte) error {
	entries, err := ciHelmMatrixEntries(ciSrc)
	if err != nil {
		return fmt.Errorf("could not read the chart job's helm matrix: %w", err)
	}
	re, err := renovateHelmAnnotationRe(renovateSrc)
	if err != nil {
		return err
	}

	// Pair by line: an annotation vouches only for the entry it sits above.
	group := func(loc []int, idx int) (string, bool) {
		// A group that did not participate reports -1. The expression comes
		// from renovate.json, so which groups are optional is not ours to
		// assume — slicing on -1 would panic the whole gate.
		if idx < 0 || loc[2*idx] < 0 {
			return "", false
		}
		return string(ciSrc[loc[2*idx]:loc[2*idx+1]]), true
	}
	dsIdx := re.SubexpIndex("datasource")
	pkgIdx, valIdx := re.SubexpIndex("packageName"), re.SubexpIndex("currentValue")
	annotated := map[int]string{}
	for _, loc := range re.FindAllSubmatchIndex(ciSrc, -1) {
		// Every field Renovate needs to resolve the leg is checked, not just
		// the one the packageRules key on: the customManager declares no
		// datasourceTemplate fallback, so `datasource=github-release` — one
		// character off, and a plausible hand-copy when a third leg is added —
		// leaves Renovate unable to resolve it. It logs and moves on, which is
		// the same silent staleness as no annotation at all.
		if ds, ok := group(loc, dsIdx); !ok || ds != helmDatasource {
			continue
		}
		if pkg, ok := group(loc, pkgIdx); !ok || pkg != helmPackageName {
			continue
		}
		val, ok := group(loc, valIdx)
		if !ok {
			continue
		}
		annotated[1+bytes.Count(ciSrc[:loc[2*valIdx]], []byte("\n"))] = val
	}

	for _, e := range entries {
		got, ok := annotated[e.Line]
		if !ok {
			return fmt.Errorf("ci.yml's chart matrix lists Helm %s (line %d) without a '# renovate:' annotation on "+
				"the line above it that renovate.json's customManager matches, so Renovate cannot see that leg and "+
				"would never bump it; annotate it the way the other entries are", e.Version, e.Line)
		}
		// The annotation is there and the line is right, but Renovate reads the
		// raw text where the YAML parser reads a scalar. A quoted entry is the
		// case that bites: Renovate would look up `"v3.21.3"`, quotes included,
		// and find nothing — silently, since a datasource miss is not an error.
		if got != e.Version {
			return fmt.Errorf("ci.yml's chart matrix entry on line %d is Helm %s, but renovate.json's customManager "+
				"reads %q from that line — Renovate matches raw text, so it would look that up verbatim and find "+
				"nothing. Write the version as a bare scalar", e.Line, e.Version, got)
		}
		delete(annotated, e.Line)
	}
	// Lowest line first, not map order: two strays would otherwise be reported
	// in a different order each run, and a gate whose message moves under you
	// is one you stop trusting.
	if strays := slices.Sorted(maps.Keys(annotated)); len(strays) > 0 {
		line := strays[0]
		return fmt.Errorf("ci.yml carries a '# renovate:' %s annotation for %s (line %d), which is not a chart "+
			"matrix entry; it would point Renovate at a version no job runs", helmPackageName, annotated[line], line)
	}
	return nil
}

// setupHelmVersion returns the `with.version` of the named job's
// azure/setup-helm step. Both the CI gate and the publish pin need exactly
// this, and they had a copy each until the two uses diverged in spelling
// rather than in meaning.
//
// The action reference is matched case-insensitively because GitHub resolves
// `uses:` owner/repo that way: Azure/setup-helm is how the action's own README
// spells it, and a gate that reported "no setup-helm step" for a step sitting
// right there would send a maintainer chasing a phantom.
func setupHelmVersion(src []byte, job, file string) (string, error) {
	var doc struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return "", err
	}
	j, ok := doc.Jobs[job]
	if !ok {
		return "", fmt.Errorf("%s has no '%s' job", file, job)
	}
	for _, step := range j.Steps {
		if !strings.HasPrefix(strings.ToLower(step.Uses), "azure/setup-helm@") {
			continue
		}
		if v := step.With["version"]; v != "" {
			return v, nil
		}
		return "", fmt.Errorf("%s's azure/setup-helm step in the '%s' job sets no with.version", file, job)
	}
	return "", fmt.Errorf("%s's '%s' job has no azure/setup-helm step, so it installs no pinned Helm", file, job)
}

// publishHelmVersion returns the Helm version helm-chart.yml packages with,
// read from the azure/setup-helm step's own `with.version` rather than from the
// first version-shaped line in the file — the publish job runs several pinned
// actions, and a gate that matched the wrong one would pass while validating
// nothing.
func publishHelmVersion(src []byte) (string, error) {
	return setupHelmVersion(src, "publish", "helm-chart.yml")
}

// verifyChartPinsIn is the seam for verifyChartPins' first two agreements —
// the kubeVersion floor and the packaging pin — over caller-supplied file
// contents, so their mismatch branches are testable without editing the real
// files. The third agreement is ci.yml against renovate.json, a different pair
// of files, and has its own seam in verifyCIHelmAnnotationsIn; a new assertion
// belongs in whichever of the two names the files it reads.
func verifyChartPinsIn(chartSrc, ciSrc, publishSrc []byte) error {
	m := chartKubeVersionRe.FindSubmatch(chartSrc)
	if m == nil {
		return fmt.Errorf("could not parse the kubeVersion floor from %s/Chart.yaml", chartDir)
	}
	if floor := string(m[1]); floor != kubeconformFloorVersion {
		return fmt.Errorf("kubeconformFloorVersion (%s) does not match the kubeVersion floor in %s/Chart.yaml (%s); "+
			"the floor is only a checked promise while the two agree",
			kubeconformFloorVersion, chartDir, floor)
	}

	validated, err := ciChartHelmMatrix(ciSrc)
	if err != nil {
		return fmt.Errorf("could not read the chart job's helm matrix: %w", err)
	}
	packaging, err := publishHelmVersion(publishSrc)
	if err != nil {
		return fmt.Errorf("could not read the setup-helm version: %w", err)
	}
	if !slices.Contains(validated, packaging) {
		return fmt.Errorf("helm-chart.yml packages with Helm %s, which is not in ci.yml's chart matrix (%s); "+
			"the chart would ship packaged by a Helm it was never validated against",
			packaging, strings.Join(validated, ", "))
	}
	return nil
}

// chartFixtureName is the label a fixture's rendering is filed under.
func chartFixtureName(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
}

// Lint runs `helm lint` over the chart once per fixture, so a fixture that
// trips the values schema or a precondition fails here rather than at install
// time.
//
// There is deliberately no bare-defaults run: the chart's preconditions reject
// an install with no TLS configuration, because the server would refuse to
// start. ci/minimal-values.yaml is the defaults plus that one required
// setting, and stands in for it.
func (Chart) Lint() error {
	if err := requireChartTool("helm", "https://helm.sh/docs/intro/install/"); err != nil {
		return err
	}
	values, err := chartValuesFiles()
	if err != nil {
		return err
	}

	for _, f := range values {
		fmt.Printf("Linting the chart with %s...\n", f)
		if err := sh.RunV("helm", "lint", "--strict", chartDir, "-f", f); err != nil {
			return err
		}
	}
	return nil
}

// Validate renders the chart with every fixture and checks the resulting
// manifests against the published Kubernetes and CRD JSON schemas. This is
// what catches a template emitting a field that does not exist, or emitting it
// at the wrong nesting level — neither of which `helm lint` sees, because to
// Helm the output is just YAML.
//
// Rendered manifests are kept in .test-output/chart/ for inspection.
func (Chart) Validate() error {
	mg.Deps(Chart.Lint)

	if err := requireChartTool("kubeconform",
		"go install github.com/yannh/kubeconform/cmd/kubeconform@v0.8.0"); err != nil {
		return err
	}
	values, err := chartValuesFiles()
	if err != nil {
		return err
	}

	outDir := filepath.Join(".test-output", "chart")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(kubeconformCacheDir, 0755); err != nil {
		return err
	}

	floorChecked := false
	for _, f := range values {
		name := chartFixtureName(f)

		fmt.Printf("Rendering the chart with %s values...\n", name)
		manifest, err := sh.Output("helm", "template", "openvox-ca", chartDir, "-f", f)
		if err != nil {
			return err
		}
		path := filepath.Join(outDir, name+".yaml")
		if err := os.WriteFile(path, []byte(manifest+"\n"), 0644); err != nil {
			return err
		}

		// The minimal fixture is the chart's defaults, so it must also hold at
		// the kubeVersion floor Chart.yaml advertises. The others opt into
		// fields newer than that on purpose.
		targets := []string{kubeconformVersion}
		if name == chartFloorFixture {
			targets = append(targets, kubeconformFloorVersion)
			floorChecked = true
		}
		for _, kubeVersion := range targets {
			fmt.Printf("Validating %s against Kubernetes %s schemas...\n", path, kubeVersion)
			if err := sh.RunV("kubeconform",
				"-strict",
				"-summary",
				// Both schema locations are remote, and this runs once per
				// fixture — seven times per invocation. Without a cache each
				// one re-downloads the same documents from
				// raw.githubusercontent.com, so a rate limit there blocks every
				// merge. (Each CI matrix leg still fetches once: the cache is
				// per-job, not shared between runs.)
				//
				// kubeconform's cache is write-once and never revalidates,
				// while `default` below resolves to a mutable upstream branch,
				// so a long-lived local copy can pass what CI fails. `mage
				// dev:clean` removes it.
				"-cache", kubeconformCacheDir,
				"-kubernetes-version", kubeVersion,
				"-schema-location", "default",
				"-schema-location", crdSchemaLocation,
				path,
			); err != nil {
				return err
			}
		}
	}
	if !floorChecked {
		return fmt.Errorf("no %s.yaml fixture found, so nothing was validated against the "+
			"kubeVersion floor (%s) that %s/Chart.yaml advertises; renaming that fixture "+
			"silently drops the check",
			chartFloorFixture, kubeconformFloorVersion, chartDir)
	}
	return nil
}

// chartConfigChecksum renders the chart and returns the checksum/config value
// it produced, so a case can assert that a *different* input yields a
// different checksum rather than that the annotation merely exists.
//
// Errors are returned rather than encoded as a sentinel string: the value feeds
// a notWants assertion, and a sentinel could never appear in real helm output,
// so a broken render here would silently satisfy the very check it exists to
// make.
func chartConfigChecksum(sets ...string) (string, error) {
	out, err := helmTemplate(sets)
	if err != nil {
		return "", fmt.Errorf("rendering the comparison config: %w\n%s", err, out)
	}
	m := regexp.MustCompile(`checksum/config: ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("no checksum/config annotation in the comparison render")
	}
	return m[1], nil
}

// chartRulesBlock returns the first RBAC `rules:` block in a rendered
// manifest, up to the document separator, so two scopes' grants can be
// compared as text.
func chartRulesBlock(manifest string) string {
	_, after, found := strings.Cut(manifest, "\nrules:\n")
	if !found {
		return ""
	}
	block, _, _ := strings.Cut(after, "\n---")
	return strings.TrimRight(block, "\n")
}

// chartRenderCase is one assertion over a rendering of the chart: render with
// these --set overrides, then require each `wants` string to appear in the
// output and each `notWants` string to be absent.
type chartRenderCase struct {
	name string
	sets []string
	// notes renders the post-install notes as well as the manifests. `helm
	// template` never evaluates NOTES.txt, and `helm install --dry-run`
	// reaches for a cluster on Helm 3, so this renders the openvox-ca.notes
	// template through a probe manifest instead — offline, on both majors.
	notes bool
	// valuesYAML supplies values a --set cannot express, as on chartRejectCase:
	// a key containing a dot, or one that has to keep surrounding whitespace.
	valuesYAML string
	wants      []string
	notWants   []string
}

// chartRejectCase is one assertion that the chart refuses a configuration:
// render with these overrides and require the failure to mention `wantErr`.
type chartRejectCase struct {
	name string
	sets []string
	// valuesYAML supplies values a --set cannot express; helm's --set parser
	// swallows backslash escapes, so a value containing a real newline has to
	// come from a file.
	valuesYAML string
	wantErr    string
}

// renderWithAppVersion renders a throwaway copy of the chart whose appVersion
// has been rewritten, so the -dev-to-edge rule can be asserted on both of its
// branches whichever side of a release this tree happens to be on. Helm offers
// no way to override .Chart.AppVersion from the command line, and asserting
// only the current version's branch is what left a release-time landmine here
// the first time round.
func renderWithAppVersion(appVersion string, sets []string) (string, error) {
	tmp, err := os.MkdirTemp("", "openvox-ca-chart")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	dst := filepath.Join(tmp, "openvox-ca")
	if err := sh.Run("cp", "-R", chartDir, dst); err != nil {
		return "", err
	}
	chartFile := filepath.Join(dst, "Chart.yaml")
	src, err := os.ReadFile(chartFile)
	if err != nil {
		return "", err
	}
	patched := chartAppVersionRe.ReplaceAll(src, fmt.Appendf(nil, "appVersion: %q", appVersion))
	if err := os.WriteFile(chartFile, patched, 0644); err != nil {
		return "", err
	}

	args := []string{"template", "openvox-ca", dst}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	var out bytes.Buffer
	_, err = sh.Exec(nil, &out, &out, "helm", args...)
	return out.String(), err
}

// helmTemplate renders the chart with --set overrides, returning stdout and
// stderr combined. Both are needed: the rendered manifests arrive on stdout,
// but a `fail` from a precondition — the thing the reject cases assert on —
// only ever appears on stderr.
func helmTemplate(sets []string) (string, error) {
	return helmRender(false, sets, "")
}

// notesProbeTemplate renders the openvox-ca.notes template into a manifest, so
// that `helm template` — which ignores NOTES.txt — surfaces it.
const notesProbeTemplate = `apiVersion: v1
kind: ConfigMap
metadata:
  name: notes-probe
data:
  notes: |
{{ include "openvox-ca.notes" . | indent 4 }}
`

// helmRender renders the chart, optionally including the post-install notes,
// and optionally with an extra values file.
func helmRender(notes bool, sets []string, valuesYAML string) (string, error) {
	dir := chartDir
	if notes {
		tmp, err := os.MkdirTemp("", "openvox-ca-notes")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(tmp)
		dir = filepath.Join(tmp, "openvox-ca")
		if err := sh.Run("cp", "-R", chartDir, dir); err != nil {
			return "", err
		}
		probe := filepath.Join(dir, "templates", "zz-notes-probe.yaml")
		if err := os.WriteFile(probe, []byte(notesProbeTemplate), 0644); err != nil {
			return "", err
		}
	}

	args := []string{"template", "openvox-ca", dir}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	if valuesYAML != "" {
		f, err := os.CreateTemp("", "openvox-ca-values-*.yaml")
		if err != nil {
			return "", err
		}
		defer os.Remove(f.Name())
		if _, err := f.WriteString(valuesYAML); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		args = append(args, "-f", f.Name())
	}
	var out bytes.Buffer
	_, err := sh.Exec(nil, &out, &out, "helm", args...)
	return out.String(), err
}

// Test asserts what the chart actually renders, which neither `helm lint` nor
// kubeconform can: both are satisfied by valid YAML carrying the wrong values.
// These cases cover the logic a reader has to trust — image-tag resolution,
// config merge precedence, probe scheme selection, which kind rbac.scope
// picks — and the preconditions, which are only worth having if they really
// fire.
func (Chart) Test() error {
	if err := requireChartTool("helm", "https://helm.sh/docs/intro/install/"); err != nil {
		return err
	}

	// Every case starts from a renderable baseline: without TLS the chart
	// refuses outright, which is itself asserted in the reject cases below.
	tls := "tls.existingSecret=openvox-ca-tls"

	// Derive the expected default tag from the chart's own appVersion rather
	// than hard-coding today's. A literal here would assert the constant
	// instead of the rule, and would fail on the very commit release:prepare
	// produces — taking CI red and blocking the tag it was preparing.
	_, appVersion, err := chartVersions()
	if err != nil {
		return err
	}
	defaultTag := appVersion
	if strings.HasSuffix(appVersion, "-dev") {
		defaultTag = "edge"
	}
	defaultTag += "-alpine"

	// The checksum a *different* config produces, so the change-detection case
	// can assert the annotation moved rather than that it exists. Computed here
	// so a failure to render it fails the target instead of quietly weakening
	// the assertion that consumes it.
	otherChecksum, err := chartConfigChecksum(tls, "config.crl_validity_days=7")
	if err != nil {
		return err
	}

	renders := []chartRenderCase{
		{
			name:  "an unset tag resolves to the Alpine variant of the appVersion",
			sets:  []string{tls, "image.tag=", "image.digest="},
			wants: []string{"image: ghcr.io/voxpupuli/openvox-ca:" + defaultTag},
		},
		{
			name: "an explicit tag is used verbatim, selecting the CentOS variant",
			sets: []string{tls, "image.tag=0.9.0"},
			// The whole point of the rule: no suffix is appended.
			wants:    []string{"image: ghcr.io/voxpupuli/openvox-ca:0.9.0"},
			notWants: []string{"0.9.0-alpine"},
		},
		{
			name:     "a digest wins over a tag",
			sets:     []string{tls, "image.tag=0.9.0", "image.digest=sha256:" + strings.Repeat("a", 64)},
			wants:    []string{"image: ghcr.io/voxpupuli/openvox-ca@sha256:" + strings.Repeat("a", 64)},
			notWants: []string{":0.9.0"},
		},
		{
			name:  "config overrides what the tls block computes",
			sets:  []string{tls, "config.tls_cert=/custom/cert.pem", "config.tls_key=/custom/key.pem"},
			wants: []string{"tls_cert: /custom/cert.pem", "tls_key: /custom/key.pem"},
			// The secret is still mounted; only the paths move.
			notWants: []string{"tls_cert: /run/secrets/openvox-ca-tls/tls.crt"},
		},
		{
			name:     "config.verbosity beats the verbosity value, and no flag outranks either",
			sets:     []string{tls, "verbosity=1", "config.verbosity=2"},
			wants:    []string{"verbosity: 2"},
			notWants: []string{"--verbosity"},
		},
		{
			name:  "probes follow the server: HTTPS when a certificate is configured",
			sets:  []string{tls},
			wants: []string{"scheme: HTTPS"},
		},
		{
			// The recipe values.yaml documents for a provider-held key. It is a
			// merge-precedence claim, which this repository requires be pinned.
			name:     "an empty config value clears a path the ca block computed",
			sets:     []string{tls, "ca.existingSecret=ca-material", "config.ca_key_provider=openbao", "config.ca_key_file="},
			wants:    []string{`ca_key_file: ""`, "ca_cert_file: /run/secrets/openvox-ca-ca/tls.crt"},
			notWants: []string{"ca_key_file: /run/secrets/openvox-ca-ca/tls.key"},
		},
		{
			name:     "an explicit RollingUpdate is honoured while persistence is on",
			sets:     []string{tls, "strategy.type=RollingUpdate", "persistence.enabled=true"},
			wants:    []string{"type: RollingUpdate"},
			notWants: []string{"type: Recreate"},
		},
		{
			// Recreate exists to protect a ReadWriteOnce cadir. With persistence
			// off the state is external and the serialisation buys only an
			// outage per upgrade.
			name:     "an unset strategy is Recreate while the cadir is a PVC",
			sets:     []string{tls},
			wants:    []string{"type: Recreate"},
			notWants: []string{"type: RollingUpdate"},
		},
		{
			name:     "an unset strategy rolls once the state is external",
			sets:     []string{tls, "persistence.enabled=false"},
			wants:    []string{"type: RollingUpdate", "maxUnavailable: 0", "maxSurge: 1"},
			notWants: []string{"type: Recreate"},
		},
		{
			name:     "an explicit strategy is honoured either way",
			sets:     []string{tls, "strategy.type=Recreate", "persistence.enabled=false"},
			wants:    []string{"type: Recreate"},
			notWants: []string{"type: RollingUpdate"},
		},
		{
			// The Prometheus job must stay distinct per release: two releases of
			// this chart run side by side during a fleet migration, and an alert
			// that cannot tell the old CA from the new one is useless. Leaving
			// jobLabel unset gives the Operator the Service name, which is
			// release-derived. Pointing it at app.kubernetes.io/name would
			// collide them, because that label carries the *chart* name.
			name: "no jobLabel is emitted, so job stays per-release",
			sets: []string{tls, "metrics.enabled=true", "metrics.serviceMonitor.enabled=true"},
			// Positive control first: a ServiceMonitor that stopped rendering
			// altogether would satisfy the absence assertion on its own.
			wants:    []string{"kind: ServiceMonitor", "port: metrics"},
			notWants: []string{"jobLabel:"},
		},
		{
			// The extraEnv scan's unreadable-reference arm: the chart cannot see
			// what a valueFrom resolves to, so it assumes TLS rather than refusing
			// an install that is probably fine.
			name:     "a TLS certificate fed in by valueFrom counts as configured",
			sets:     []string{"extraEnv[0].name=PUPPET_CA_TLS_CERT", "extraEnv[0].valueFrom.secretKeyRef.name=tls", "extraEnv[0].valueFrom.secretKeyRef.key=tls.crt", "extraEnv[1].name=PUPPET_CA_TLS_KEY", "extraEnv[1].valueFrom.secretKeyRef.name=tls", "extraEnv[1].valueFrom.secretKeyRef.key=tls.key"},
			wants:    []string{"scheme: HTTPS"},
			notWants: []string{"scheme: HTTP\n"},
		},
		{
			// The server ignores an empty PUPPET_CA_* variable and keeps what
			// the config file said (applyServerEnv in cmd/openvox-ca/config.go).
			// The chart used to treat one as a deletion and then refuse the
			// install for having no certificate.
			name:     "an empty TLS env var does not unset a configured certificate",
			sets:     []string{tls, "env.PUPPET_CA_TLS_CERT=", "env.PUPPET_CA_TLS_KEY="},
			wants:    []string{"scheme: HTTPS"},
			notWants: []string{"scheme: HTTP\n"},
		},
		{
			name:     "probes follow the server: HTTP behind a terminating proxy",
			sets:     []string{"config.no_tls_required=true"},
			wants:    []string{"scheme: HTTP\n"},
			notWants: []string{"scheme: HTTPS"},
		},
		{
			name:     "rbac.scope selects the namespaced kinds by default",
			sets:     []string{tls, "kubernetesExport.enabled=true", "kubernetesExport.targets[0].kind=Secret", "kubernetesExport.targets[0].metadata.name=t", "kubernetesExport.targets[0].cert=true"},
			wants:    []string{"kind: Role\n", "kind: RoleBinding\n", "automountServiceAccountToken: true"},
			notWants: []string{"kind: ClusterRole"},
		},
		{
			// The other half of exportRBACRendered, which nothing pinned: both
			// dropping the rbac.create conjunct and making the helper always true
			// left every assertion green. rbac.create: false is the remedy the
			// NOTES warning itself recommends, so an install that took that advice
			// would have had a Role rendered anyway, and the default-ServiceAccount
			// refusal would start firing on installs that create none.
			name: "rbac.create: false renders no export Role at all",
			sets: []string{tls, "kubernetesExport.enabled=true", "kubernetesExport.rbac.create=false",
				"kubernetesExport.targets[0].kind=Secret", "kubernetesExport.targets[0].metadata.name=t",
				"kubernetesExport.targets[0].cert=true"},
			wants:    []string{"kind: Deployment"},
			notWants: []string{"kind: Role\n", "kind: RoleBinding\n", "kind: ClusterRole"},
		},
		{
			// And the export-off baseline, so a helper hardwired to true fails
			// here rather than only in the case above.
			name:     "no export configured renders no Role",
			sets:     []string{tls},
			wants:    []string{"kind: Deployment"},
			notWants: []string{"kind: Role\n", "kind: RoleBinding\n"},
		},
		{
			// The third consumer of the predicate. With no Role rendered there is
			// nothing to bind, so the default-ServiceAccount refusal must stay
			// silent — re-splitting rbac.create off it would refuse this valid
			// install, and the two existing reject cases would not notice.
			name: "no Role means no default-ServiceAccount refusal",
			sets: []string{tls, "kubernetesExport.enabled=true",
				"kubernetesExport.rbac.create=false", "serviceAccount.create=false"},
			wants:    []string{"kind: Deployment"},
			notWants: []string{"kind: Role\n"},
		},
		{
			name:     "rbac.scope: ClusterRole selects the cluster-scoped kinds",
			sets:     []string{tls, "kubernetesExport.enabled=true", "kubernetesExport.rbac.scope=ClusterRole", "kubernetesExport.targets[0].kind=Secret", "kubernetesExport.targets[0].metadata.name=t", "kubernetesExport.targets[0].cert=true"},
			wants:    []string{"kind: ClusterRole\n", "kind: ClusterRoleBinding\n"},
			notWants: []string{"kind: Role\n", "kind: RoleBinding\n"},
		},
		{
			name: "the ServiceAccount token stays unmounted when nothing needs the API",
			sets: []string{tls},
			// Anchored to the pod template: serviceaccount.yaml emits the same
			// key at column 0 unconditionally, so a bare want cannot fail.
			wants:    []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: false"},
			notWants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name:  "OpenBao Kubernetes auth mounts the token too",
			sets:  []string{tls, "config.ca_key_provider=openbao", "config.openbao.auth_method=kubernetes"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name: "export targets set through config alone still mount the token",
			// The server enables export whenever targets are present, whatever
			// kubernetesExport.enabled says, so the token decision has to read
			// the merged config rather than the chart's own flag.
			sets:  []string{tls, "config.kubernetes_export.targets[0].kind=Secret", "config.kubernetes_export.targets[0].metadata.name=trust", "config.kubernetes_export.targets[0].cert=true"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name: "a config the chart cannot read mounts the token conservatively",
			// Same uncertainty the probes resolve towards HTTPS: a spare token
			// costs nothing, a missing one fails the export or the key provider
			// while readiness stays green.
			sets:  []string{"existingConfigMap=mine"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name: "a config change rolls the pods",
			// Asserting the annotation exists would pass on a constant, which
			// would roll nothing. Assert instead that a different config does
			// not produce the checksum this one does.
			sets:     []string{tls},
			wants:    []string{"checksum/config: "},
			notWants: []string{otherChecksum},
		},
		{
			name: "the CA's key material is mounted read-only to the container user alone",
			// 0600 plus the pod's fsGroup. A refactor that dropped defaultMode
			// would loosen permissions on the CA private key, its passphrase
			// and the server TLS key while passing lint and kubeconform, which
			// accept any mode or none.
			//
			// Each want pins secretName and defaultMode as one contiguous
			// string: anchoring on the explanatory comment instead would pass
			// with the mode deleted, which is exactly the refactor this case
			// exists to catch.
			sets: []string{tls, "ca.existingSecret=ca-material", "caKeyPassphrase.existingSecret=ca-passphrase"},
			wants: []string{
				"secretName: openvox-ca-tls\n            defaultMode: 0600",
				"secretName: ca-material\n            defaultMode: 0600",
				"secretName: ca-passphrase\n            defaultMode: 0600",
			},
		},
		{
			name: "a loopback listen address is exempt from the TLS precondition",
			// The other side of the guard: 127.0.0.0/8 and localhost are the
			// only spellings that both satisfy the server's isLoopback and
			// produce a parseable listen address, and this is the sidecar-only
			// deployment the failure message offers as a remedy.
			sets:     []string{"listen.host=127.0.0.1"},
			wants:    []string{"kind: Deployment", "scheme: HTTP\n"},
			notWants: []string{"scheme: HTTPS"},
		},
		{
			name:  "localhost is exempt too",
			sets:  []string{"listen.host=localhost"},
			wants: []string{"kind: Deployment"},
		},
		{
			name: "a certificate supplied through env satisfies the precondition",
			// Environment variables outrank the config file, so this is a
			// documented remedy; the helper has to notice it or the install is
			// refused and the probes pick the wrong scheme.
			sets:     []string{"env.PUPPET_CA_TLS_CERT=/run/tls/tls.crt", "env.PUPPET_CA_TLS_KEY=/run/tls/tls.key"},
			wants:    []string{"kind: Deployment", "scheme: HTTPS"},
			notWants: []string{"scheme: HTTP\n"},
		},
		{
			name:     "a certificate supplied through extraEnv satisfies it as well",
			sets:     []string{"extraEnv[0].name=PUPPET_CA_TLS_CERT", "extraEnv[0].value=/run/tls/tls.crt", "extraEnv[1].name=PUPPET_CA_TLS_KEY", "extraEnv[1].value=/run/tls/tls.key"},
			wants:    []string{"kind: Deployment", "scheme: HTTPS"},
			notWants: []string{"scheme: HTTP\n"},
		},
		{
			name: "an explicit probe scheme survives the computed default",
			// TLS is configured, so the chart would choose HTTPS; the liveness
			// probe overrides it and the other two must still default.
			sets:  []string{tls, "livenessProbe.httpGet.scheme=HTTP"},
			wants: []string{"scheme: HTTP\n", "scheme: HTTPS"},
		},
		{
			name: "an ingress routed to the metrics port names it",
			// The accepted half of the backendPort guard. Ingress references
			// the Service port by name...
			sets:  []string{tls, "metrics.enabled=true", "ingress.enabled=true", "ingress.backendPort=metrics"},
			wants: []string{"port:\n                  name: metrics"},
		},
		{
			name: "a TLSRoute routed to the metrics port numbers it",
			// ...while a Gateway API backendRef takes the number, which is the
			// asymmetry openvox-ca.routeBackendName/routeBackendPort exist for.
			//
			// Anchored to the backendRef's own nesting: a bare "port: 9140"
			// also matches the Service's metrics port, so it would pass even if
			// the route had regressed to the https port.
			sets: []string{tls, "metrics.enabled=true", "gateway.tlsRoute.enabled=true", "gateway.tlsRoute.backendPort=metrics"},
			wants: []string{
				"- backendRefs:\n        - name: openvox-ca\n          port: 9140",
			},
		},
		{
			name: "a TLSRoute left on the default backendPort numbers the https port",
			// The other selection, so the pair prove routeBackendPort chooses
			// rather than that either number appears somewhere.
			sets: []string{tls, "metrics.enabled=true", "gateway.tlsRoute.enabled=true"},
			wants: []string{
				"- backendRefs:\n        - name: openvox-ca\n          port: 443",
			},
		},
		{
			name:  "NOTES warns when every CSR is signed unreviewed",
			notes: true,
			// The positive control that makes the suppression case below mean
			// something.
			sets:  []string{tls, "autosign.mode=true"},
			wants: []string{"signed without review"},
		},
		{
			name:  "NOTES warns that an HTTPRoute stops mTLS authenticating",
			notes: true,
			sets:  []string{tls, "gateway.httpRoute.enabled=true"},
			wants: []string{"stops authenticating"},
		},
		{
			name:  "NOTES warns when no TLS certificate is configured",
			notes: true,
			sets:  []string{"config.no_tls_required=true"},
			// Single-line fragments only: the notes probe indents the rendered
			// body, so a want spanning a line break would never match.
			wants: []string{"no server TLS certificate is configured"},
		},
		{
			name:  "NOTES warns when export RBAC cannot be narrowed",
			notes: true,
			sets:  []string{"existingConfigMap=mine", "kubernetesExport.enabled=true"},
			// The scope word carries the meaning: inverting the conditional would
			// understate a cluster-wide grant as namespace-wide, and "patch on
			// every" alone is common to both branches.
			wants: []string{"namespace-wide patch on every"},
		},
		{
			// exportTargetNames now returns "unknown" on all four routes, so the
			// disclosure had to stop naming existingConfigMap as the cause and
			// offering a remedy — moving targets into kubernetesExport.targets —
			// that cannot work while the config stays unreadable.
			name:  "NOTES names the right cause when the config is unreadable another way",
			notes: true,
			sets:  []string{tls, "kubernetesExport.enabled=true", "extraArgs[0]=--config=/other.yaml"},
			wants: []string{"args, envFrom, or a --config in extraArgs", "will not help"},
		},
		{
			name:  "NOTES names the cluster-wide scope when that is what was created",
			notes: true,
			sets: []string{"existingConfigMap=mine", "kubernetesExport.enabled=true",
				"kubernetesExport.rbac.scope=ClusterRole"},
			wants: []string{"cluster-wide patch on every"},
		},
		{
			// rbac.create off means no Role, so there is nothing to disclose. The
			// conjunct is pinned at rbac.yaml; this pins it at the disclosure,
			// where re-splitting it would announce a grant that was never created.
			name:  "NOTES discloses nothing when no Role was created",
			notes: true,
			sets: []string{"existingConfigMap=mine", "kubernetesExport.enabled=true",
				"kubernetesExport.rbac.create=false"},
			notWants: []string{"patch on every"},
		},
		{
			// The same disclosure by the config route. This warning is the
			// compensating control that makes an unnarrowable patch grant
			// acceptable — rbac.yaml emits it "visibly" — so gating it on the
			// chart's flag while the Role rendered on exportConfigured left the
			// grant in place with nothing telling the operator.
			name:  "NOTES warns about an unnarrowable grant by the config route too",
			notes: true,
			sets: []string{"existingConfigMap=mine",
				"config.kubernetes_export.targets[0].kind=Secret",
				"config.kubernetes_export.targets[0].metadata.name=ca-bundle"},
			wants: []string{"patch on every"},
		},
		{
			name:  "NOTES warns that an ephemeral cadir throws the CA away",
			notes: true,
			// The most consequential of the nine warnings: the filesystem
			// backend's private key living in an emptyDir.
			sets:  []string{tls, "persistence.enabled=false"},
			wants: []string{"regenerated from scratch"},
		},
		{
			name:  "NOTES warns that the metrics exporter is unrestricted",
			notes: true,
			sets:  []string{tls, "metrics.enabled=true"},
			wants: []string{"leaf-certificate series carry node hostnames"},
		},
		{
			name:  "NOTES warns that restricted egress may not reach the API server",
			notes: true,
			// The second consumer of needsAPIAccess, and the one no case
			// covered. With export configured through config alone the reason
			// the note gives must not claim OpenBao.
			sets: []string{tls, "networkPolicy.enabled=true", "networkPolicy.egress.enabled=true",
				"config.kubernetes_export.targets[0].kind=Secret", "config.kubernetes_export.targets[0].metadata.name=trust", "config.kubernetes_export.targets[0].cert=true"},
			// The export reason is the regression anchor: this route printed no
			// reason at all before apiAccessReason existed.
			wants:    []string{"egress is restricted", "(Kubernetes export)"},
			notWants: []string{"(OpenBao Kubernetes auth)"},
		},
		{
			name:  "the egress NOTE names Kubernetes export when that is the reason",
			notes: true,
			// The notWants above is only meaningful if the arms it excludes can
			// actually fire; these two prove each one does.
			sets: []string{tls, "networkPolicy.enabled=true", "networkPolicy.egress.enabled=true",
				"kubernetesExport.enabled=true", "kubernetesExport.targets[0].kind=Secret",
				"kubernetesExport.targets[0].metadata.name=trust", "kubernetesExport.targets[0].cert=true"},
			wants:    []string{"(Kubernetes export)"},
			notWants: []string{"(OpenBao Kubernetes auth)"},
		},
		{
			name:  "the egress NOTE names OpenBao when that is the reason",
			notes: true,
			sets: []string{tls, "networkPolicy.enabled=true", "networkPolicy.egress.enabled=true",
				"config.ca_key_provider=openbao", "config.openbao.auth_method=kubernetes"},
			wants:    []string{"(OpenBao Kubernetes auth)"},
			notWants: []string{"(Kubernetes export)"},
		},
		{
			name: "an OpenBao auth method supplied through env still mounts the token",
			// The chart can read env and extraEnv, so unlike args/envFrom this
			// is not an uncertainty case — it must be detected outright, the way
			// tlsConfigured detects PUPPET_CA_TLS_CERT there.
			sets:  []string{tls, "config.ca_key_provider=openbao", "env.PUPPET_CA_OPENBAO_AUTH_METHOD=kubernetes"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name:     "a non-Kubernetes auth method through env does not",
			sets:     []string{tls, "config.ca_key_provider=openbao", "env.PUPPET_CA_OPENBAO_AUTH_METHOD=approle"},
			wants:    []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: false"},
			notWants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name: "an auth method supplied through extraEnv with a readable value mounts the token",
			// The readable arm of the extraEnv scan, distinct from the valueFrom
			// arm below: only that one is reached by `not .value`.
			sets: []string{tls, "config.ca_key_provider=openbao",
				"extraEnv[0].name=PUPPET_CA_OPENBAO_AUTH_METHOD", "extraEnv[0].value=kubernetes"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name: "a non-Kubernetes auth method through extraEnv does not",
			sets: []string{tls, "config.ca_key_provider=openbao",
				"extraEnv[0].name=PUPPET_CA_OPENBAO_AUTH_METHOD", "extraEnv[0].value=approle"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: false"},
		},
		{
			name: "an auth method passed through extraArgs mounts the token",
			// extraArgs is appended to the argv the chart builds, so unlike
			// `args` the chart can read it — and the flag outranks both the
			// config file and the environment.
			sets: []string{tls, "config.ca_key_provider=openbao", "extraArgs[0]=--openbao-auth-method=kubernetes"},
			// The argv want is the premise the scan rests on: were the extraArgs
			// block dropped from the deployment, the token line alone would still
			// render, and the chart would be deciding from a flag the container
			// never receives.
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true",
				"- --openbao-auth-method=kubernetes"},
		},
		{
			name:  "a non-Kubernetes auth method through extraArgs does not",
			sets:  []string{tls, "config.ca_key_provider=openbao", "extraArgs[0]=--openbao-auth-method=approle"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: false"},
		},
		{
			name: "a bare auth-method flag in extraArgs mounts the token",
			// The separated spelling leaves the value in the next element, which
			// the chart does not reassemble — so it fails open. Written as a
			// prefix match instead, this would swallow the `=approle` case above
			// and mount a token that case asserts stays unmounted.
			sets: []string{tls, "config.ca_key_provider=openbao",
				"extraArgs[0]=--openbao-auth-method", "extraArgs[1]=kubernetes"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name: "a --config in extraArgs makes the whole configuration unknown",
			// The chart renders its own --config and appends extraArgs after it,
			// and --config is a plain StringVar, so the second one wins and the
			// server reads a file the chart never saw. Judging the token from the
			// chart's own config there would withhold it from a pod whose real
			// config configures export or Kubernetes auth.
			sets:  []string{tls, "extraArgs[0]=--config=/mnt/other/config.yaml"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name:  "the separated --config spelling counts too",
			sets:  []string{tls, "extraArgs[0]=--config", "extraArgs[1]=/mnt/other/config.yaml"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name: "export configured only through config still gets a Role",
			// Gating RBAC on kubernetesExport.enabled alone left this route with a
			// mounted token, a NOTE naming export, and no Role — the exporter
			// refused by RBAC while readiness stayed green.
			sets: []string{tls, "config.kubernetes_export.targets[0].kind=Secret",
				"config.kubernetes_export.targets[0].metadata.name=ca-bundle"},
			wants: []string{"kind: Role", "verbs: [\"patch\"]\n    resourceNames:\n      - ca-bundle"},
		},
		{
			name: "an empty env value does not erase the auth method the config set",
			// The server ignores an empty variable, so the chart must too; an
			// unguarded assignment here would withhold the token from a
			// correctly configured pod.
			sets: []string{tls, "config.ca_key_provider=openbao", "config.openbao.auth_method=kubernetes",
				"env.PUPPET_CA_OPENBAO_AUTH_METHOD="},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name:  "the egress NOTE names export even when the wider config is unknown",
			notes: true,
			// kubernetesExport.enabled stays readable under existingConfigMap, so
			// suppressing the reason there would lose one the chart does have.
			sets: []string{"existingConfigMap=mine", "kubernetesExport.enabled=true",
				"networkPolicy.enabled=true", "networkPolicy.egress.enabled=true"},
			wants: []string{"(Kubernetes export)"},
		},
		{
			name:  "an unreadable config alone names no reason at all",
			notes: true,
			// needsAPIAccess answers true for existingConfigMap by construction,
			// so without the fully-known guard the reason would reach the OpenBao
			// arm and invent a cause the chart cannot actually see. Empty means
			// only that no reason is visible.
			sets: []string{"existingConfigMap=mine", "networkPolicy.enabled=true",
				"networkPolicy.egress.enabled=true"},
			wants:    []string{"egress is restricted"},
			notWants: []string{"(OpenBao Kubernetes auth)", "(Kubernetes export)"},
		},
		{
			name: "an auth method fed from a Secret mounts the token, since the chart cannot read it",
			sets: []string{tls, "config.ca_key_provider=openbao",
				"extraEnv[0].name=PUPPET_CA_OPENBAO_AUTH_METHOD",
				"extraEnv[0].valueFrom.secretKeyRef.name=openbao", "extraEnv[0].valueFrom.secretKeyRef.key=method"},
			wants: []string{"serviceAccountName: openvox-ca\n      automountServiceAccountToken: true"},
		},
		{
			name: "a lowercase export target kind passes through as written",
			// The schema accepts either case because the server matches the
			// kind case-insensitively; the chart's job is to hand it over
			// untouched rather than normalise it.
			sets:  []string{tls, "kubernetesExport.enabled=true", "kubernetesExport.targets[0].kind=secret", "kubernetesExport.targets[0].metadata.name=trust", "kubernetesExport.targets[0].cert=true"},
			wants: []string{"kind: secret"},
		},
		{
			// The reserved names are conditional, because configMapData only
			// emits puppet-server when puppetServers is set. Supplying the allow
			// list by hand and pointing config at it is a working configuration
			// that a fixed list of names refused — and the remedy that error
			// offered, existingConfigMap, is a worse posture than what it blocked.
			name: "a puppet-server file supplied by hand renders when the chart emits none",
			valuesYAML: "tls:\n  existingSecret: s\nconfig:\n  puppet_server_file: /etc/puppet-ca/puppet-server\n" +
				"extraConfigFiles:\n  puppet-server: |\n    compiler.example.com\n",
			// Quoted, because configMapData quotes every extraConfigFiles key so a
			// hostile one cannot contribute YAML structure. Same parsed key.
			wants: []string{"\"puppet-server\": |", "compiler.example.com"},
			// And the premise the case is named for: the chart emits none. Without
			// this, changing configMapData's own condition — the other site that
			// decides the same thing — renders both entries and this still passes.
			notWants: []string{"\n  puppet-server: |"},
		},
		{
			// The other arm's negative direction: with no autosign.patterns the
			// chart emits no autosign.conf, so supplying it by hand and pointing
			// config.autosign_config at it is a working configuration. Removing
			// the condition on this arm re-refuses it, silently, without this.
			name: "an autosign.conf supplied by hand renders when the chart emits none",
			valuesYAML: "tls:\n  existingSecret: s\nconfig:\n  autosign_config: /etc/puppet-ca/autosign.conf\n" +
				"extraConfigFiles:\n  autosign.conf: |\n    *.agent.example.com\n",
			wants:    []string{"\"autosign.conf\": |", "*.agent.example.com"},
			notWants: []string{"\n  autosign.conf: |"},
		},
		{
			// existingConfigMap renders no ConfigMap at all, so extraConfigFiles
			// is inert and nothing can be displaced. Refusing here was an
			// over-refusal that told the operator to set the value they had set.
			//
			// notWants pins the premise the exemption rests on: the operator's body
			// reaches no manifest. "kind: Deployment" alone is emitted by every
			// successful render, so it asserted nothing the error check did not.
			name:       "a reserved key is inert, not refused, under existingConfigMap",
			valuesYAML: "tls:\n  existingSecret: s\nexistingConfigMap: mine\nextraConfigFiles:\n  config.yaml: |\n    host: 127.0.0.1\n",
			wants:      []string{"kind: Deployment"},
			notWants:   []string{"host: 127.0.0.1"},
		},
		{
			// Containment, not equality. The mount point itself and anything under
			// it are writable — the server creates what it needs — so an equality
			// test refused a trailing slash and the conventional <mount>/ca, with a
			// message asserting they were outside the volume they were in.
			name:  "a cadir inside the mounted volume renders",
			sets:  []string{tls, "config.cadir=/var/lib/puppet-ca/ca"},
			wants: []string{"cadir: /var/lib/puppet-ca/ca"},
		},
		{
			name:  "a cadir equal to the mount point with a trailing slash renders",
			sets:  []string{tls, "config.cadir=/var/lib/puppet-ca/"},
			wants: []string{"kind: Deployment"},
		},
		{
			name: "envFrom stops the TLS precondition firing",
			// envFrom can carry PUPPET_CA_TLS_CERT/KEY from a Secret the chart
			// never reads, so the guard has to stand down — with no tls block
			// set, this rendering succeeding *is* the assertion.
			sets:  []string{"envFrom[0].secretRef.name=openvox-ca-env"},
			wants: []string{"kind: Deployment"},
		},
		{
			name: "a replaced argv stops the TLS precondition firing",
			sets: []string{"args[0]=--config=/etc/puppet-ca/config.yaml", "args[1]=--tls-cert=/run/tls/tls.crt", "args[2]=--tls-key=/run/tls/tls.key"},
			// And the chart stops constructing arguments of its own.
			wants:    []string{"--tls-cert=/run/tls/tls.crt"},
			notWants: []string{"--verbosity"},
		},
		{
			name:     "an externally managed ConfigMap cannot be checksummed",
			sets:     []string{tls, "existingConfigMap=mine"},
			wants:    []string{"name: mine"},
			notWants: []string{"checksum/config:"},
		},
		{
			name:  "maxUnavailable: 0 survives the falsy-zero trap",
			sets:  []string{tls, "podDisruptionBudget.enabled=true", "podDisruptionBudget.maxUnavailable=0"},
			wants: []string{"maxUnavailable: 0"},
			// minAvailable is the fallback that a plain `if` would have taken.
			notWants: []string{"minAvailable:"},
		},
		{
			name:     "clearing both emptyDir fields still yields a valid volume source",
			sets:     []string{tls, "persistence.enabled=false", "emptyDir.medium=", "emptyDir.sizeLimit="},
			wants:    []string{"emptyDir: {}"},
			notWants: []string{"emptyDir:\n        - name"},
		},
		{
			name:  "a deny-all network policy renders an empty list, not a null",
			sets:  []string{tls, "networkPolicy.enabled=true", "networkPolicy.apiAccess=none"},
			wants: []string{"ingress: []"},
		},
		{
			name:  "export patch is held to the configured target names",
			sets:  []string{tls, "kubernetesExport.enabled=true", "kubernetesExport.targets[0].kind=Secret", "kubernetesExport.targets[0].metadata.name=trust-bundle", "kubernetesExport.targets[0].cert=true"},
			wants: []string{"resourceNames:\n      - trust-bundle"},
		},
		{
			name: "export with no targets grants no patch at all",
			// An empty resourceNames list is not a restriction — RBAC reads an
			// absent list as every resource — so the rule has to be omitted.
			sets:     []string{tls, "kubernetesExport.enabled=true"},
			wants:    []string{`verbs: ["create"]`},
			notWants: []string{`verbs: ["patch"]`},
		},
		{
			name: "export config the chart cannot read grants patch unrestricted",
			sets: []string{"existingConfigMap=mine", "kubernetesExport.enabled=true"},
			// Unrestricted, because the chart cannot know the target names —
			// but emitted as its own rule rather than an empty resourceNames
			// list, which RBAC would read as "every resource" anyway.
			wants:    []string{`verbs: ["patch"]`},
			notWants: []string{"resourceNames:\n"},
		},
		{
			// The other three routes to an unreadable config. Keyed on
			// existingConfigMap alone, these emitted a create-only Role with no
			// patch rule and no NOTES disclosure, so an exporter whose real config
			// carries targets is refused on its first patch with readiness green.
			name:     "a replaced argv also grants patch unrestricted",
			sets:     []string{"kubernetesExport.enabled=true", "args[0]=--config=/other.yaml"},
			wants:    []string{`verbs: ["patch"]`},
			notWants: []string{"resourceNames:\n"},
		},
		{
			name:     "a --config in extraArgs also grants patch unrestricted",
			sets:     []string{tls, "kubernetesExport.enabled=true", "extraArgs[0]=--config=/other.yaml"},
			wants:    []string{`verbs: ["patch"]`},
			notWants: []string{"resourceNames:\n"},
		},
		{
			// envFrom is the exception, and inverting this case is the point: it
			// cannot carry export targets, so the names the chart can see are still
			// the real ones. Keying the width on configFullyKnown widened patch to
			// every Secret in scope here — a privilege escalation dressed as a
			// fail-open, on the chart's own documented way to supply a DSN.
			name: "envFrom keeps the grant narrowed to the configured names",
			sets: []string{tls, "kubernetesExport.enabled=true", "envFrom[0].secretRef.name=env",
				"kubernetesExport.targets[0].kind=Secret", "kubernetesExport.targets[0].metadata.name=mycert",
				"kubernetesExport.targets[0].cert=true"},
			wants: []string{"resourceNames:", "- mycert"},
		},
		{
			name: "a falsy config value still overrides what the chart computed",
			// mergeOverwrite consults isEmptyValue on the destination only, so
			// false does win — asserted rather than assumed.
			sets:     []string{tls, "caKeyPassphrase.existingSecret=pw", "config.encrypt_ca_key=false"},
			wants:    []string{"encrypt_ca_key: false"},
			notWants: []string{"encrypt_ca_key: true"},
		},
		{
			name:     "retain: false drops the resource policy without leaving an empty annotations key",
			sets:     []string{tls, "persistence.enabled=true", "persistence.retain=false"},
			wants:    []string{"kind: PersistentVolumeClaim"},
			notWants: []string{"helm.sh/resource-policy", "annotations:\nspec:"},
		},
		{
			name:  "NOTES warns when nothing is granted admin access",
			notes: true,
			sets:  []string{tls},
			wants: []string{"no puppetServers are listed"},
		},
		{
			name:  "NOTES warns about a shared filesystem CA under autoscaling",
			notes: true,
			// The replica warning has to read the autoscaling floor, not just
			// replicaCount.
			sets:  []string{tls, "autoscaling.enabled=true", "autoscaling.minReplicas=3"},
			wants: []string{"autoscaling starts at 3 replicas", "not safe to share between replicas"},
		},
		{
			name:     "NOTES does not warn about autosign when patterns override the mode",
			notes:    true,
			sets:     []string{tls, "autosign.mode=true", "autosign.patterns[0]=*.example.com"},
			notWants: []string{"signed without review"},
		},
		{
			name:  "topology constraints default to this release's own pods",
			sets:  []string{tls},
			wants: []string{"app.kubernetes.io/name: openvox-ca\n          maxSkew: 1"},
		},
	}

	rejects := []chartRejectCase{
		{
			name:    "no TLS on a non-loopback address, which the server refuses to serve",
			sets:    []string{},
			wantErr: "refuse to start",
		},
		{
			name:    "a ServiceMonitor for an exporter that is switched off",
			sets:    []string{tls, "metrics.serviceMonitor.enabled=true"},
			wantErr: "nothing to scrape",
		},
		{
			name:    "an ingress routed to a metrics port that was never created",
			sets:    []string{tls, "ingress.enabled=true", "ingress.backendPort=metrics"},
			wantErr: "no metrics port",
		},
		{
			name:    "a TLSRoute routed to a metrics port that was never created",
			sets:    []string{tls, "gateway.tlsRoute.enabled=true", "gateway.tlsRoute.backendPort=metrics"},
			wantErr: "no metrics port",
		},
		{
			name:    "an HTTPRoute routed to a metrics port that was never created",
			sets:    []string{tls, "gateway.httpRoute.enabled=true", "gateway.httpRoute.backendPort=metrics"},
			wantErr: "no metrics port",
		},
		{
			name:       "an allow-list entry carrying a newline, which would inject a ConfigMap key",
			sets:       []string{tls},
			valuesYAML: "puppetServers:\n  - \"ca.example.com\\ninjected: value\"\n",
			wantErr:    "single non-empty line",
		},
		{
			name: "an empty allow-list entry, the guard's other arm",
			// A blank line in the mTLS admin allow list or the autosign
			// allow list is the second thing the guard refuses.
			sets:       []string{tls},
			valuesYAML: "puppetServers:\n  - \"\"\n",
			wantErr:    "single non-empty line",
		},
		{
			name:       "a whitespace-only autosign pattern",
			sets:       []string{tls},
			valuesYAML: "autosign:\n  patterns:\n    - \"   \"\n",
			wantErr:    "single non-empty line",
		},
		{
			name:       "an autosign pattern carrying a newline",
			sets:       []string{tls},
			valuesYAML: "autosign:\n  patterns:\n    - \"*.a.example.com\\n*.b.example.com\"\n",
			wantErr:    "single non-empty line",
		},
		{
			// An explicit empty value is not a certificate: Kubernetes sets the
			// variable to "" and the server discards it. Counting it was the
			// fail-open mirror of the env defect fixed alongside.
			name:    "a TLS certificate supplied through extraEnv as an explicit empty value",
			sets:    []string{"extraEnv[0].name=PUPPET_CA_TLS_CERT", "extraEnv[0].value=", "extraEnv[1].name=PUPPET_CA_TLS_KEY", "extraEnv[1].value=/run/tls/tls.key"},
			wantErr: "refuse to start",
		},
		{
			// Neither value nor valueFrom: Kubernetes still renders the variable
			// empty, so this is no more a certificate than the case above.
			name:    "an extraEnv entry naming no source at all",
			sets:    []string{"extraEnv[0].name=PUPPET_CA_TLS_CERT", "extraEnv[1].name=PUPPET_CA_TLS_KEY"},
			wantErr: "refuse to start",
		},
		{
			// values.yaml used to carry `type: Recreate` for a partial override
			// to merge onto; with it empty, a typeless map reaches Kubernetes as
			// RollingUpdate and surges against the ReadWriteOnce cadir.
			name:    "a strategy map with no type, which Kubernetes reads as RollingUpdate",
			sets:    []string{tls, "strategy.rollingUpdate.maxSurge=1"},
			wantErr: "no type",
		},
		{
			name:    "an autoscaler with no metric to act on",
			sets:    []string{tls, "autoscaling.enabled=true", "autoscaling.targetCPUUtilizationPercentage="},
			wantErr: "no metric is configured",
		},
		{
			name:    "export RBAC bound to the namespace's default ServiceAccount",
			sets:    []string{tls, "kubernetesExport.enabled=true", "serviceAccount.create=false"},
			wantErr: "default ServiceAccount",
		},
		{
			// The same escalation by the other route. rbac.yaml renders the Role
			// for config-supplied targets too, so a guard keyed on the chart's
			// flag alone bound it to the shared identity in silence.
			name: "export RBAC bound to the default ServiceAccount by the config route",
			sets: []string{tls, "serviceAccount.create=false",
				"config.kubernetes_export.targets[0].kind=Secret",
				"config.kubernetes_export.targets[0].metadata.name=ca-bundle"},
			wantErr: "default ServiceAccount",
		},
		{
			name:       "an extraConfigFiles key taking the place of the chart's config.yaml",
			valuesYAML: "tls:\n  existingSecret: s\nextraConfigFiles:\n  config.yaml: |\n    host: 127.0.0.1\n",
			wantErr:    "is one the chart renders",
		},
		{
			// puppetServers set, so the chart really does render puppet-server and
			// the collision is real. Without it there is nothing to collide with,
			// which is the case below.
			name: "an extraConfigFiles key taking the place of the admin allow list",
			valuesYAML: "tls:\n  existingSecret: s\npuppetServers:\n  - compiler.example.com\n" +
				"extraConfigFiles:\n  puppet-server: |\n    attacker.example.com\n",
			wantErr: "is one the chart renders",
		},
		{
			name: "an extraConfigFiles key taking the place of the autosign allow list",
			valuesYAML: "tls:\n  existingSecret: s\nautosign:\n  patterns:\n    - \"*.a.example.com\"\n" +
				"extraConfigFiles:\n  autosign.conf: |\n    *.b.example.com\n",
			wantErr: "is one the chart renders",
		},
		{
			// The bypass a literal comparison could not see: YAML strips trailing
			// whitespace from a plain scalar key, so this rendered a second entry
			// that parsed back to the same name and replaced the chart's admin
			// allow list outright.
			name: "an extraConfigFiles key padded with whitespace",
			valuesYAML: "tls:\n  existingSecret: s\npuppetServers:\n  - compiler.example.com\n" +
				"extraConfigFiles:\n  \"puppet-server \": |\n    attacker.example.com\n",
			wantErr: "not a valid ConfigMap key",
		},
		{
			// The second bypass: quotes are YAML syntax, so this rendered as a
			// distinct key and parsed back to puppet-server, replacing the admin
			// allow list. Enumerating spellings lost twice; the guard checks the
			// shape now, and configMapData quotes the key it emits.
			name: "an extraConfigFiles key wrapped in quotes",
			valuesYAML: "tls:\n  existingSecret: s\npuppetServers:\n  - compiler.example.com\n" +
				"extraConfigFiles:\n  '\"puppet-server\"': |\n    attacker.example.com\n",
			wantErr: "not a valid ConfigMap key",
		},
		{
			// The third: an interior newline is re-indented by nindent, injecting
			// a whole extra entry.
			name: "an extraConfigFiles key containing a newline",
			valuesYAML: "tls:\n  existingSecret: s\npuppetServers:\n  - compiler.example.com\n" +
				"extraConfigFiles:\n  \"harmless.txt: x\\npuppet-server\": |\n    attacker.example.com\n",
			wantErr: "not a valid ConfigMap key",
		},
		{
			// config wins by contract, so overriding one of the three settings the
			// chart also uses to shape a Kubernetes object moves the server and
			// leaves the object behind. The port case never becomes ready.
			name:    "config.port overriding listen.port, which the objects follow",
			sets:    []string{tls, "config.port=9999"},
			wantErr: "listen.port is what the container port",
		},
		{
			// This one is silent: the Service and any ServiceMonitor scrape a port
			// nothing listens on while readiness stays green.
			name:    "config.metrics_listen overriding metrics.port",
			sets:    []string{tls, "metrics.enabled=true", "config.metrics_listen=0.0.0.0:9999"},
			wantErr: "metrics.port is what the container port",
		},
		{
			name:    "config.cadir pointing outside the mounted volume",
			sets:    []string{tls, "config.cadir=/srv/ca"},
			wantErr: "outside the volume mounted at",
		},
		{
			// The same shape without a PVC: the volume is an emptyDir but it is
			// still mounted at mountPath, and the root filesystem is still
			// read-only, so gating the check on persistence.enabled let the
			// identical failure through on three of the six fixture shapes.
			name:    "config.cadir outside the volume with persistence disabled",
			sets:    []string{tls, "persistence.enabled=false", "config.cadir=/srv/ca"},
			wantErr: "outside the volume mounted at",
		},
		{
			// The server starts the exporter on any non-empty metrics_listen
			// whatever the chart's flag says, while every object that would make it
			// reachable is gated on the flag.
			name:    "config.metrics_listen with the exporter switched off",
			sets:    []string{tls, "config.metrics_listen=0.0.0.0:9140"},
			wantErr: "which starts the exporter, but metrics.enabled is false",
		},
		{
			// Kubernetes refuses these three, and a bare character class admits
			// them — they rendered a manifest the API server would reject.
			name:       "an extraConfigFiles key Kubernetes reserves",
			valuesYAML: "tls:\n  existingSecret: s\nextraConfigFiles:\n  \"..data\": |\n    x\n",
			wantErr:    "not a valid ConfigMap key",
		},
		{
			name:       "an extraConfigFiles key of a single dot",
			valuesYAML: "tls:\n  existingSecret: s\nextraConfigFiles:\n  \".\": |\n    x\n",
			wantErr:    "not a valid ConfigMap key",
		},
		{
			// The cap is the third part of the rule and the only one nothing
			// asserted: reverting {1,253} to + left every case green while a
			// 254-character key rendered a manifest the API server refuses.
			// Pinned on the bound, not the shared prefix.
			name:       "an extraConfigFiles key past the 253-character cap",
			valuesYAML: "tls:\n  existingSecret: s\nextraConfigFiles:\n  " + strings.Repeat("a", 254) + ": |\n    x\n",
			wantErr:    "at most 253",
		},
		{
			// Bypass four, via the body rather than the key: sprig's indent splits
			// on "\n" only, while YAML also breaks on CR, so the text after one is
			// not re-indented, lands at the data-key column and took the place of
			// the admin allow list outright.
			name:       "an extraConfigFiles body carrying a carriage return",
			valuesYAML: "tls:\n  existingSecret: s\npuppetServers:\n  - compiler.example.com\nextraConfigFiles:\n  harmless.txt: \"x\\r  puppet-server: |\\r    attacker.example.com\\n\"\n",
			wantErr:    "carriage return or a Unicode line separator",
		},
		{
			// The same against the allow-list entry check, which was also "\n"
			// only. U+2028 is a YAML line break that survives go-yaml's
			// normalisation.
			name:       "a puppetServers entry carrying a Unicode line separator",
			valuesYAML: "tls:\n  existingSecret: s\npuppetServers:\n  - \"compiler.example.com       config.yaml: |         no_tls_required: true\"\n",
			wantErr:    "no carriage return or Unicode line separator",
		},
		{
			name:    "a mistyped value the schema should catch",
			sets:    []string{tls, "metric.enabled=true"},
			wantErr: "additional properties",
		},
	}

	failures := 0

	// The -dev-to-edge rule, on both of its branches. Rendered from a copy of
	// the chart with a substituted appVersion, so this asserts the rule rather
	// than whichever side of a release this tree currently sits on.
	for _, tc := range []struct{ appVersion, wantTag string }{
		{"9.9.9-dev", "edge-alpine"},
		{"9.9.9", "9.9.9-alpine"},
		{"9.9.9-rc1", "9.9.9-rc1-alpine"},
	} {
		name := fmt.Sprintf("appVersion %s resolves to %s", tc.appVersion, tc.wantTag)
		out, err := renderWithAppVersion(tc.appVersion, []string{tls})
		want := "image: ghcr.io/voxpupuli/openvox-ca:" + tc.wantTag
		switch {
		case err != nil:
			fmt.Printf("FAIL  %s\n      render failed: %v\n", name, err)
			failures++
		case !strings.Contains(out, want):
			fmt.Printf("FAIL  %s\n      expected to find: %q\n", name, want)
			failures++
		default:
			fmt.Printf("ok    %s\n", name)
		}
	}

	// The two RBAC scopes must grant the same thing. Nothing pinned that: each
	// scope's kinds were asserted separately, so a narrowing applied to one
	// branch and not the other would have gone unnoticed — and the branches
	// used to hold byte-for-byte copies of the rules, which is exactly how
	// that drift happens.
	{
		name := "both RBAC scopes grant identical rules"
		// All three arms exportRules can take, not just the first: the
		// unknown-targets arm is the one that grants unrestricted patch, so a
		// re-inline diverging only there is exactly what this must catch.
		for _, arm := range []struct {
			label string
			sets  []string
		}{
			{"named targets", []string{
				tls, "kubernetesExport.enabled=true",
				"kubernetesExport.targets[0].kind=Secret",
				"kubernetesExport.targets[0].metadata.name=trust",
				"kubernetesExport.targets[0].cert=true",
			}},
			{"no targets", []string{tls, "kubernetesExport.enabled=true"}},
			{"unknown targets", []string{"existingConfigMap=mine", "kubernetesExport.enabled=true"}},
		} {
			armName := fmt.Sprintf("%s (%s)", name, arm.label)
			clusterOut, clusterErr := helmTemplate(append(slices.Clone(arm.sets), "kubernetesExport.rbac.scope=ClusterRole"))
			roleOut, roleErr := helmTemplate(append(slices.Clone(arm.sets), "kubernetesExport.rbac.scope=Role"))
			switch {
			case clusterErr != nil || roleErr != nil:
				fmt.Printf("FAIL  %s\n      render failed: %v %v\n", armName, clusterErr, roleErr)
				failures++
				continue
			}
			clusterRules, roleRules := chartRulesBlock(clusterOut), chartRulesBlock(roleOut)
			switch {
			case clusterRules == "":
				fmt.Printf("FAIL  %s\n      no rules block rendered for ClusterRole\n", armName)
				failures++
			case clusterRules != roleRules:
				fmt.Printf("FAIL  %s\n      ClusterRole rules:\n%s\n      Role rules:\n%s\n", armName, clusterRules, roleRules)
				failures++
			default:
				fmt.Printf("ok    %s\n", armName)
			}
		}
	}

	for _, tc := range renders {
		out, err := helmRender(tc.notes, tc.sets, tc.valuesYAML)
		if err != nil {
			fmt.Printf("FAIL  %s\n      render failed: %v\n", tc.name, err)
			failures++
			continue
		}
		ok := true
		for _, want := range tc.wants {
			if !strings.Contains(out, want) {
				fmt.Printf("FAIL  %s\n      expected to find: %q\n", tc.name, want)
				ok = false
			}
		}
		for _, notWant := range tc.notWants {
			if strings.Contains(out, notWant) {
				fmt.Printf("FAIL  %s\n      expected NOT to find: %q\n", tc.name, notWant)
				ok = false
			}
		}
		if ok {
			fmt.Printf("ok    %s\n", tc.name)
		} else {
			failures++
		}
	}

	for _, tc := range rejects {
		out, err := helmRender(false, tc.sets, tc.valuesYAML)
		switch {
		case err == nil:
			fmt.Printf("FAIL  rejects %s\n      rendered successfully instead of failing\n", tc.name)
			failures++
		case !strings.Contains(err.Error()+out, tc.wantErr):
			fmt.Printf("FAIL  rejects %s\n      failed, but not with %q: %v\n", tc.name, tc.wantErr, err)
			failures++
		default:
			fmt.Printf("ok    rejects %s\n", tc.name)
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d chart assertion(s) failed", failures)
	}
	fmt.Printf("\nAll %d chart assertions passed\n", len(renders)+len(rejects)+3)
	return nil
}

// Package writes the packaged chart tarball to dist/, named for the
// internal/version constant. The publish workflow packages the chart the same
// way before pushing it to the OCI registry, so this is the local dry run.
func (Chart) Package() error {
	mg.Deps(Chart.Version)

	if err := requireChartTool("helm", "https://helm.sh/docs/intro/install/"); err != nil {
		return err
	}
	if err := os.MkdirAll("dist", 0755); err != nil {
		return err
	}
	if err := sh.RunV("helm", "package", chartDir, "--destination", "dist"); err != nil {
		return err
	}

	ver, err := releaseVersion()
	if err != nil {
		return err
	}
	tarball := filepath.Join("dist", fmt.Sprintf("openvox-ca-%s.tgz", ver))
	if _, err := os.Stat(tarball); err != nil {
		return fmt.Errorf("expected chart package %s was not produced: %w", tarball, err)
	}
	fmt.Println("Wrote", tarball)
	return nil
}

// -- test:* --------------------------------------------------------------------

// unitTestExcludes lists packages omitted from the unit-test run. Keep this set
// as small as possible: every entry is a package that runs NO coverage in CI.
//
//	internal/testutil — test helpers only, exercised transitively by the
//	                     packages that import them.
var unitTestExcludes = map[string]bool{
	"github.com/voxpupuli/openvox-ca/internal/testutil": true,
}

// unitTestPackages discovers the packages to unit-test via `go list ./...`
// rather than a hand-maintained list, then drops the explicit excludes above.
// A hand-maintained list silently drops any newly added package from CI (this
// is how internal/signer's tests went unrun); discovery makes the default
// "covered" so a new package has to be deliberately excluded to escape the gate.
func unitTestPackages() ([]string, error) {
	out, err := exec.Command("go", "list", "./...").Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("listing packages: %w: %s", err, ee.Stderr)
		}
		return nil, fmt.Errorf("listing packages: %w", err)
	}

	var pkgs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" || unitTestExcludes[pkg] {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("go list ./... returned no testable packages")
	}
	return pkgs, nil
}

// Magefile runs the magefile's own Ginkgo suite. The suite is build-tagged
// like the magefile itself, so ordinary `go test ./...` and the go-list-based
// test:unit discovery cannot see it; this target is the canonical way to run
// it, used by CI's check job and the pre-push hook.
func (Test) Magefile() error {
	return sh.RunV("go", "test", "-tags", "mage", ".")
}

// Unit runs the unit test suite with coverage and the race detector, piping
// output through tparse for a colourful per-package summary table. The package
// set is discovered dynamically (see unitTestPackages); only unitTestExcludes
// is omitted.
func (Test) Unit() error {
	fmt.Println("Running unit tests...")

	pkgs, err := unitTestPackages()
	if err != nil {
		return err
	}

	// -race is not optional here: the notification path (internal/sdnotify) is
	// driven concurrently by the heartbeat, the reload watcher, and a deferred
	// Close, and its locking is only verified by specs that fail exclusively
	// under the race detector. The storage locks that serialise CA bootstrap
	// and the CRL cache are in the same position: specs exist purely to prove
	// those guarantees, and without -race they can pass by coincidence over a
	// genuine data race that only shows up as a corrupt CA under load. It
	// costs roughly 15% on the slowest package.
	testArgs := append([]string{"test", "-race", "-json", "-cover", "-coverprofile=coverage.out"}, pkgs...)
	testCmd := exec.Command("go", testArgs...)
	// -race needs cgo, which is on by default everywhere this runs -- but a
	// developer who has exported CGO_ENABLED=0 would get a build failure
	// instead of a test run, so set it rather than inherit it.
	testCmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	tparseCmd := exec.Command("go", "tool", "tparse", "-all")

	pipe, err := testCmd.StdoutPipe()
	if err != nil {
		return err
	}
	testCmd.Stderr = os.Stderr
	tparseCmd.Stdin = pipe
	tparseCmd.Stdout = os.Stdout
	tparseCmd.Stderr = os.Stderr

	if err := testCmd.Start(); err != nil {
		return err
	}
	if err := tparseCmd.Start(); err != nil {
		testCmd.Wait() //nolint:errcheck
		return err
	}

	testErr := testCmd.Wait()
	tparseErr := tparseCmd.Wait()

	if testErr != nil {
		return testErr
	}
	return tparseErr
}

// Mixin renders the Jsonnet monitoring mixin and checks the alerting rules it
// produces: `promtool check rules` for syntax, then `promtool test rules` for
// the behaviour of the ones whose expressions are not simple thresholds (see
// mixin/tests.yaml).
//
// The mixin ships rules but no Go code, so nothing else in the suite would
// notice a malformed selector substitution, or an expression that parses fine
// and silently never matches. Skips with a message when jsonnet or promtool is
// absent, so a contributor without them can still run everything else.
func (Test) Mixin() error {
	fmt.Println("Checking the monitoring mixin...")

	for _, tool := range []string{"jsonnet", "promtool"} {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Printf("Skipping mixin checks: %s not found in PATH\n", tool)
			return nil
		}
	}

	if err := os.MkdirAll(".test-output", 0755); err != nil {
		return err
	}
	// mixin/tests.yaml names this path in its rule_files, so the two have to
	// agree; it is relative to that file, hence the ../ there.
	rendered := filepath.Join(".test-output", "mixin-alerts.yaml")

	out, err := sh.Output("jsonnet", "-S", "-J", "mixin",
		"-e", "std.manifestYamlDoc((import 'mixin/mixin.libsonnet').prometheusAlerts)")
	if err != nil {
		return fmt.Errorf("rendering the mixin: %w", err)
	}
	if err := os.WriteFile(rendered, []byte(out), 0600); err != nil {
		return fmt.Errorf("writing %s: %w", rendered, err)
	}

	if err := sh.RunV("promtool", "check", "rules", rendered); err != nil {
		return err
	}
	return sh.RunV("promtool", "test", "rules", filepath.Join("mixin", "tests.yaml"))
}

// IntegCompose builds the binaries locally then runs the multi-host compose
// integration test suite, tearing down on exit.
func (Test) IntegCompose() error {
	mg.Deps(Build{}.All)
	fmt.Println("Building compose images...")
	if err := runCompose(nil, "-f", "test/compose.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running compose integration tests...")
	err := runCompose(nil, "-f", "test/compose.yml", "up",
		"--exit-code-from", "test-runner",
		"--abort-on-container-exit")

	fmt.Println("Tearing down compose stack...")
	_ = runCompose(nil, "-f", "test/compose.yml", "down", "--volumes")

	return err
}

// IntegComposeFIPS is like IntegCompose but compiles with
// GOEXPERIMENT=boringcrypto so the compose integration suite runs against the
// FIPS-compliant binary.
func (Test) IntegComposeFIPS() error {
	mg.Deps(Build{}.FIPS)
	fmt.Println("Building compose images (FIPS build)...")
	if err := runCompose(nil, "-f", "test/compose.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running compose integration tests (FIPS build)...")
	err := runCompose(nil, "-f", "test/compose.yml", "up",
		"--exit-code-from", "test-runner",
		"--abort-on-container-exit")

	fmt.Println("Tearing down compose stack...")
	_ = runCompose(nil, "-f", "test/compose.yml", "down", "--volumes")

	return err
}

// LoadCompose is like IntegCompose but also enables the concurrency / load
// tests (DO_LOAD=true).
func (Test) LoadCompose() error {
	mg.Deps(Build{}.All)
	extra := map[string]string{"DO_LOAD": "true"}

	fmt.Println("Building compose images...")
	if err := runCompose(extra, "-f", "test/compose.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running compose integration + load tests...")
	err := runCompose(extra, "-f", "test/compose.yml", "up",
		"--exit-code-from", "test-runner",
		"--abort-on-container-exit")

	fmt.Println("Tearing down compose stack...")
	_ = runCompose(extra, "-f", "test/compose.yml", "down", "--volumes")

	return err
}

// Bench builds the binaries locally then runs the k6 load test suite
// (correctness, throughput, saturation ramp) against a dedicated compose stack
// (test/compose-bench.yml). Requires podman-compose and network access to pull
// grafana/k6:latest on first run.
func (Test) Bench() error {
	mg.Deps(Build{}.All)
	sysEnv := systemInfo()

	fmt.Println("Building compose images for benchmark...")
	if err := runCompose(sysEnv, "-f", "test/compose-bench.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running k6 load tests...")
	err := runCompose(sysEnv, "-f", "test/compose-bench.yml", "up",
		"--exit-code-from", "k6",
		"--abort-on-container-exit")

	fmt.Println("Tearing down bench stack...")
	_ = runCompose(sysEnv, "-f", "test/compose-bench.yml", "down", "--volumes")

	return err
}

// Puppet builds the Puppet stack images (puppet-master, puppet-client) and runs
// the full Puppet integration test suite: CA TLS, catalog application,
// PuppetDB reporting, exported resources, and CRL revocation enforcement.
//
// Requires podman-compose (or docker compose) and network access to pull
// quay.io/centos/centos:stream10, ghcr.io/openvoxproject/openvoxdb:latest,
// and docker.io/postgres:17-alpine on first run.
func (Test) Puppet() error {
	mg.Deps(Build{}.All)
	fmt.Println("Building compose images for puppet stack...")
	if err := runCompose(nil, "-f", "test/compose-puppet.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running puppet stack integration tests...")
	return sh.RunV("bash", "test/puppet/puppet-stack.sh", "--up")
}

// Migration builds the openvox-ca image and runs the migration integration test
// suite: imports a genuine VoxPupuli Puppet Server CA into openvox-ca, then
// verifies that the migrated CA can serve old certs, sign new ones, revoke,
// and clean.
//
// Requires a container runtime and network access to pull
// docker.io/voxpupuli/puppetserver:latest on first run.
func (Test) Migration() error {
	mg.Deps(Build{}.All)
	fmt.Println("Building compose images for migration test...")
	if err := runCompose(nil, "-f", "test/compose-migration.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running migration integration tests...")
	err := runCompose(nil, "-f", "test/compose-migration.yml", "up",
		"--exit-code-from", "test-runner",
		"--abort-on-container-exit")

	fmt.Println("Tearing down migration stack...")
	_ = runCompose(nil, "-f", "test/compose-migration.yml", "down", "--volumes")

	return err
}

// BackendsRedis builds the openvox-ca image and runs the full Puppet stack
// integration suite against a Redis-backed CA topology with two replicas
// sharing a single Redis prefix. Validates: catalog application end-to-end
// over Redis-backed storage; cert blobs offloaded to Redis (not local disk);
// distributed bootstrap lock when two CAs race; cross-replica state
// visibility; concurrent CSR submissions split across replicas with
// AppendLine atomicity on the inventory blob.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/redis:7-alpine plus the same images as Test:Puppet.
func (Test) BackendsRedis() error {
	mg.Deps(Build{}.All)
	fmt.Println("Building compose images for Redis-backend stack...")
	if err := runCompose(nil, "-f", "test/compose-backends-redis.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running Redis-backend integration tests...")
	return sh.RunV("bash", "test/backends/redis-stack.sh", "--up")
}

// BackendsRedisGo brings up a throwaway Redis via test/compose-backends-redis-go.yml
// and runs the Redis-backend Go integration suite (internal/storage, build tag
// `redis_integration`) against it, then tears Redis down. This mirrors the
// postgres/mysql/etcd Go-suite targets; it is distinct from BackendsRedis,
// which runs the full-stack bash TAP suite against a Puppet topology. Both are
// wired into CI so neither the bash suite nor the Go suite is left unrun.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/redis:7-alpine.
func (Test) BackendsRedisGo() error {
	const addr = "127.0.0.1:56379"

	fmt.Println("Starting Redis backend service...")
	if err := runCompose(nil, "-f", "test/compose-backends-redis-go.yml", "up", "-d", "--wait"); err != nil {
		return err
	}
	defer func() {
		fmt.Println("Tearing down Redis backend service...")
		_ = runCompose(nil, "-f", "test/compose-backends-redis-go.yml", "down", "--volumes")
	}()

	fmt.Println("Running Redis-backend Go integration tests...")
	return sh.RunWithV(
		map[string]string{"PUPPET_CA_TEST_REDIS_ADDR": addr},
		"go", "test", "-tags", "redis_integration", "-count=1", "./internal/storage/...",
	)
}

// BackendsPostgres brings up a throwaway PostgreSQL via
// test/compose-backends-postgres.yml and runs the SQL-backend Go integration suite
// (internal/storage, build tag `postgres_integration`) against it, then tears
// the database down. Validates the PostgreSQL dialect: upsert, FOR UPDATE
// AppendLine atomicity across two backends, and pg_advisory_lock mutual
// exclusion.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/postgres:16-alpine.
func (Test) BackendsPostgres() error {
	const dsn = "postgres://puppetca:puppetca@127.0.0.1:55432/puppetca?sslmode=disable"

	fmt.Println("Starting PostgreSQL backend service...")
	if err := runCompose(nil, "-f", "test/compose-backends-postgres.yml", "up", "-d", "--wait"); err != nil {
		return err
	}
	defer func() {
		fmt.Println("Tearing down PostgreSQL backend service...")
		_ = runCompose(nil, "-f", "test/compose-backends-postgres.yml", "down", "--volumes")
	}()

	fmt.Println("Running PostgreSQL-backend integration tests...")
	return sh.RunWithV(
		map[string]string{"PUPPET_CA_TEST_POSTGRES_DSN": dsn},
		"go", "test", "-tags", "postgres_integration", "-count=1", "./internal/storage/...",
	)
}

// BackendsMySQL brings up a throwaway MySQL via test/compose-backends-mysql.yml and
// runs the SQL-backend Go integration suite (internal/storage, build tag
// `mysql_integration`) against it, then tears the database down. Validates the
// MySQL/MariaDB dialect: LONGBLOB widening, ON DUPLICATE KEY upsert, FOR UPDATE
// AppendLine atomicity (with InnoDB deadlock retry) across two backends, and
// GET_LOCK mutual exclusion.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/mysql:8.
func (Test) BackendsMySQL() error {
	const dsn = "puppetca:puppetca@tcp(127.0.0.1:53306)/puppetca"

	fmt.Println("Starting MySQL backend service...")
	if err := runCompose(nil, "-f", "test/compose-backends-mysql.yml", "up", "-d", "--wait"); err != nil {
		return err
	}
	defer func() {
		fmt.Println("Tearing down MySQL backend service...")
		_ = runCompose(nil, "-f", "test/compose-backends-mysql.yml", "down", "--volumes")
	}()

	fmt.Println("Running MySQL-backend integration tests...")
	return sh.RunWithV(
		map[string]string{"PUPPET_CA_TEST_MYSQL_DSN": dsn},
		"go", "test", "-tags", "mysql_integration", "-count=1", "./internal/storage/...",
	)
}

// BackendsOpenBao brings up a throwaway OpenBao dev server via
// test/compose-backends-openbao.yml, configures its transit engine and an AppRole
// scoped to a "test-*" key prefix (deliberately broader than a production
// policy — it grants "create" and covers the key TestLiveGenerateThenLoad
// makes; see configureOpenBaoForTests and docs/openbao-transit.md for the
// tighter single-key policy a real deployment should use), runs the
// OpenBao-backend Go integration suite (internal/signer/openbao, build tag
// openbao_integration) against it, then tears the server down.
//
// Unlike the Postgres/MySQL/Redis-Go targets, the service needs configuring
// (transit engine, key, AppRole, policy) between "container is up" and
// "run go test" — done here via the same Go SDK internal/signer/openbao itself
// depends on, rather than shelling out to the openbao CLI inside the container.
//
// Requires podman-compose (or docker compose) and network access to pull
// docker.io/openbao/openbao:2.5.5.
func (Test) BackendsOpenBao() error {
	const (
		addr       = "http://127.0.0.1:58200"
		rootToken  = "root"
		roleName   = "test-role"
		policyName = "test-policy"
		keyName    = "test-key"
	)

	fmt.Println("Starting OpenBao backend service...")
	if err := runCompose(nil, "-f", "test/compose-backends-openbao.yml", "up", "-d", "--wait"); err != nil {
		return err
	}
	defer func() {
		fmt.Println("Tearing down OpenBao backend service...")
		_ = runCompose(nil, "-f", "test/compose-backends-openbao.yml", "down", "--volumes")
	}()

	fmt.Println("Configuring OpenBao transit engine and AppRole...")
	roleID, secretID, err := configureOpenBaoForTests(addr, rootToken, roleName, policyName, keyName)
	if err != nil {
		return fmt.Errorf("configuring OpenBao: %w", err)
	}

	// Write the secret_id into a freshly created private temp dir (0700, random
	// name) rather than a fixed, predictable path in a shared /tmp: on a shared
	// or self-hosted runner a pre-planted symlink at a known path could
	// otherwise redirect this write.
	secretIDDir, err := os.MkdirTemp("", "openvox-ca-openbao-test")
	if err != nil {
		return fmt.Errorf("creating secret_id temp dir: %w", err)
	}
	defer os.RemoveAll(secretIDDir)
	secretIDFile := filepath.Join(secretIDDir, "secret-id")
	if err := os.WriteFile(secretIDFile, []byte(secretID), 0o600); err != nil {
		return fmt.Errorf("writing secret_id file: %w", err)
	}

	fmt.Println("Running OpenBao-backend integration tests...")
	return sh.RunWithV(
		map[string]string{
			"PUPPET_CA_TEST_OPENBAO_ADDR":           addr,
			"PUPPET_CA_TEST_OPENBAO_ROLE_ID":        roleID,
			"PUPPET_CA_TEST_OPENBAO_SECRET_ID_FILE": secretIDFile,
			"PUPPET_CA_TEST_OPENBAO_KEY_NAME":       keyName,
		},
		"go", "test", "-tags", "openbao_integration", "-count=1", "./internal/signer/openbao/...",
	)
}

// configureOpenBaoForTests sets up a freshly started OpenBao dev server for the
// integration suite: mounts the transit engine, creates keyName, enables
// AppRole auth, and attaches a policy scoped to "transit/keys/test-*" and
// "transit/sign/test-*" — broad enough to cover both the pre-created key and
// the fresh one TestLiveGenerateThenLoad creates, appropriate for a
// throwaway per-run instance. A production policy should instead name its
// one key exactly; see docs/openbao-transit.md. Returns the AppRole
// role_id and a freshly generated secret_id.
func configureOpenBaoForTests(addr, rootToken, roleName, policyName, keyName string) (roleID, secretID string, err error) {
	cfg := openbao.DefaultConfig()
	if cfg.Error != nil {
		return "", "", cfg.Error
	}
	cfg.Address = addr
	client, err := openbao.NewClient(cfg)
	if err != nil {
		return "", "", err
	}
	client.SetToken(rootToken)

	if err := client.Sys().Mount("transit", &openbao.MountInput{Type: "transit"}); err != nil {
		return "", "", fmt.Errorf("mounting transit engine: %w", err)
	}

	if _, err := client.Logical().Write("transit/keys/"+keyName, map[string]interface{}{
		"type": "rsa-2048",
	}); err != nil {
		return "", "", fmt.Errorf("creating transit key %q: %w", keyName, err)
	}

	if err := client.Sys().EnableAuthWithOptions("approle", &openbao.EnableAuthOptions{Type: "approle"}); err != nil {
		return "", "", fmt.Errorf("enabling approle auth: %w", err)
	}

	const policyHCL = `
path "transit/keys/test-*" { capabilities = ["read", "create", "update"] }
path "transit/sign/test-*" { capabilities = ["update"] }
`
	if err := client.Sys().PutPolicy(policyName, policyHCL); err != nil {
		return "", "", fmt.Errorf("writing policy %q: %w", policyName, err)
	}

	if _, err := client.Logical().Write("auth/approle/role/"+roleName, map[string]interface{}{
		"token_policies": policyName,
		"token_ttl":      "5m",
		"token_max_ttl":  "15m",
	}); err != nil {
		return "", "", fmt.Errorf("creating approle role %q: %w", roleName, err)
	}

	roleIDSecret, err := client.Logical().Read("auth/approle/role/" + roleName + "/role-id")
	if err != nil {
		return "", "", fmt.Errorf("reading role_id: %w", err)
	}
	roleID, ok := roleIDSecret.Data["role_id"].(string)
	if !ok {
		return "", "", fmt.Errorf("role-id response missing role_id")
	}

	secretIDSecret, err := client.Logical().Write("auth/approle/role/"+roleName+"/secret-id", nil)
	if err != nil {
		return "", "", fmt.Errorf("generating secret_id: %w", err)
	}
	secretID, ok = secretIDSecret.Data["secret_id"].(string)
	if !ok {
		return "", "", fmt.Errorf("secret-id response missing secret_id")
	}

	return roleID, secretID, nil
}

// BackendsEtcd runs the etcd-backend Go integration suite (build tag
// etcd_integration). The suite boots an in-process embedded etcd, so unlike the
// Redis suite it needs no external service, compose stack, or network pulls.
// The suite is heavily concurrent by design (cross-replica append races,
// concurrent decompositions, contended locks), so it runs under the race
// detector; -race needs cgo, hence the explicit CGO_ENABLED override of the
// repository's CGO_ENABLED=0 default.
func (Test) BackendsEtcd() error {
	fmt.Println("Running etcd-backend integration tests...")
	return sh.RunWithV(map[string]string{"CGO_ENABLED": "1"},
		"go", "test", "-tags", "etcd_integration", "-race", "-count=1", "./internal/storage/...")
}

// PuppetFIPS is like Puppet but compiles with GOEXPERIMENT=boringcrypto so the
// full Puppet stack integration suite runs against the FIPS-compliant binary.
func (Test) PuppetFIPS() error {
	mg.Deps(Build{}.FIPS)
	fmt.Println("Building compose images for puppet stack (FIPS build)...")
	if err := runCompose(nil, "-f", "test/compose-puppet.yml", "build"); err != nil {
		return err
	}

	fmt.Println("Running puppet stack integration tests (FIPS build)...")
	return sh.RunV("bash", "test/puppet/puppet-stack.sh", "--up")
}

// -- dev:* --------------------------------------------------------------------─

// checkModuleTidy reports whether tidy leaves the named files unchanged, and
// puts back exactly what it found either way.
//
// The bytes are snapshotted rather than restored with `git checkout --`, which
// cannot tell this function's edit from the developer's own uncommitted one:
// running Check mid dependency-bump used to discard the bump silently. The
// restore also runs when tidy itself fails — a tidy that rewrote one file and
// then errored would otherwise leave that rewrite behind, which is the one path
// the snapshot did not originally cover.
//
// Takes the directory and the tidy command so the behaviour can be asserted
// over synthetic files, the way verifyChartPinsIn and verifyDistVariantsIn are.
func checkModuleTidy(dir string, files []string, tidy func() error) error {
	before := map[string][]byte{}
	for _, f := range files {
		body, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return fmt.Errorf("reading %s before the tidy check: %w", f, err)
		}
		before[f] = body
	}

	tidyErr := tidy()

	var untidy []string
	var restoreErrs []error
	for _, f := range files {
		path := filepath.Join(dir, f)
		after, err := os.ReadFile(path)
		if err != nil {
			// Unreadable or gone: exactly what the snapshot is for, so put it
			// back rather than only noting the failure. Collected, not returned,
			// so the other file is still restored — but surfaced unconditionally
			// below, because a tidy that deletes go.sum while leaving go.mod
			// alone must not report success.
			// Named as module drift rather than as a bare I/O fault, because that
			// is what it is: tidy removes go.sum outright when nothing needs it.
			restoreErrs = append(restoreErrs, fmt.Errorf(
				"%s could not be read back after the tidy check (tidy may have removed it); "+
					"run 'mage dev:tidy' and commit: %w", f, err))
			if werr := os.WriteFile(path, before[f], 0o644); werr != nil {
				restoreErrs = append(restoreErrs, fmt.Errorf("restoring %s: %w", f, werr))
			}
			continue
		}
		if bytes.Equal(after, before[f]) {
			continue
		}
		untidy = append(untidy, f)
		if werr := os.WriteFile(path, before[f], 0o644); werr != nil {
			restoreErrs = append(restoreErrs, fmt.Errorf("restoring %s: %w", f, werr))
		}
	}

	// tidy's own failure outranks untidiness — it means the check never ran —
	// but the files have been put back regardless.
	if tidyErr != nil {
		if len(restoreErrs) > 0 {
			return errors.Join(tidyErr, errors.Join(restoreErrs...))
		}
		return tidyErr
	}
	if len(untidy) > 0 {
		// Named from the arguments, not hardcoded: the function is generic over
		// the file list, and a message naming files the caller never passed sent
		// its own spec looking for a substring it could not rely on.
		subject := strings.Join(files, "/")
		if len(restoreErrs) > 0 {
			return fmt.Errorf("%s are not tidy (%s); run 'mage dev:tidy' and commit. "+
				"Additionally, while putting them back: %w",
				subject, strings.Join(untidy, ", "), errors.Join(restoreErrs...))
		}
		return fmt.Errorf("%s are not tidy (%s); run 'mage dev:tidy' and commit",
			subject, strings.Join(untidy, ", "))
	}
	if len(restoreErrs) > 0 {
		return errors.Join(restoreErrs...)
	}
	return nil
}

// Check verifies formatting, module tidiness, go vet, and the golangci-lint
// gate. Unlike `mage dev:tidy`, it is a non-mutating verifier: it reports drift
// as a failure instead of silently fixing it, so CI catches untidy code and
// modules. gofmt -l prints unformatted files without rewriting them, and the
// tidiness step runs `go mod tidy` then restores go.mod/go.sum, treating any
// change as a failure.
func (Dev) Check() error {
	fmt.Println("Running verify...")
	out, err := sh.Output("gofmt", "-l", ".")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("these files need formatting (run 'mage dev:tidy'):\n%s", out)
	}
	fmt.Println("Checking go mod tidy...")
	if err := checkModuleTidy(".", []string{"go.mod", "go.sum"}, func() error {
		return sh.Run("go", "mod", "tidy")
	}); err != nil {
		return err
	}
	if err := sh.Run("go", "vet", "./..."); err != nil {
		return err
	}
	fmt.Println("Checking release variant lists...")
	if err := verifyDistVariants(); err != nil {
		return err
	}
	fmt.Println("Checking chart version pins...")
	if err := verifyChartPins(); err != nil {
		return err
	}
	// Vet the one package with a non-Linux build-tagged file. Every CI check
	// runs on Linux, so internal/sdnotify/monotonic_other.go is otherwise
	// never compiled and can rot unnoticed — while the comment in that file
	// names developer workstations as the audience it serves. Scoped to that
	// package rather than ./...: a module-wide cross-vet would make "every
	// dependency must type-check on darwin" a standing constraint on future
	// dependency choices, which is a much bigger commitment than this file
	// needs.
	fmt.Println("Vetting the non-Linux build of internal/sdnotify...")
	if err := sh.RunWith(map[string]string{"GOOS": "darwin", "GOARCH": "arm64"},
		"go", "vet", "./internal/sdnotify/..."); err != nil {
		return fmt.Errorf("go vet failed for GOOS=darwin: %w", err)
	}
	return Dev{}.Lint()
}

// Lint runs golangci-lint over the whole module, teeing its output to
// .test-output/golangci-lint.log. A missing golangci-lint binary is a
// graceful skip (clear message, non-fatal) so dev:check still works in
// minimal environments; only an actual lint failure returns an error.
func (Dev) Lint() error {
	if _, err := exec.LookPath("golangci-lint"); err != nil {
		fmt.Println("SKIP: golangci-lint not found on PATH; skipping lint " +
			"(install: https://golangci-lint.run/welcome/install/)")
		return nil
	}

	fmt.Println("Running golangci-lint...")
	if err := os.MkdirAll(".test-output", 0755); err != nil {
		return err
	}
	logFile, err := os.Create(filepath.Join(".test-output", "golangci-lint.log"))
	if err != nil {
		return err
	}
	defer logFile.Close()

	out := io.MultiWriter(os.Stdout, logFile)
	errOut := io.MultiWriter(os.Stderr, logFile)
	if _, err := sh.Exec(nil, out, errOut, "golangci-lint", "run", "./..."); err != nil {
		return err
	}
	return nil
}

// Tidy runs go mod tidy and go fmt on any files that need it.
func (Dev) Tidy() error {
	fmt.Println("Tidying modules...")
	if err := sh.Run("go", "mod", "tidy"); err != nil {
		return err
	}
	fmt.Println("Formatting code...")
	return sh.Run("go", "fmt", "./...")
}

// Clean removes the bin/ directory and the schema cache chart:validate keeps.
//
// The cache is included because kubeconform's on-disk cache is write-once and
// never revalidates, while its default schema location is a mutable upstream
// branch: a stale local copy can therefore pass a validation that CI, which
// always starts empty, fails. This is the documented way to clear it.
func (Dev) Clean() error {
	fmt.Println("Cleaning...")
	if err := sh.Rm(kubeconformCacheDir); err != nil {
		return err
	}
	return sh.Rm("bin")
}

// Container creates a minimal scratch OCI image from the openvox-ca binary and
// loads it into the local Docker / Podman daemon.
//
// Configuration (via environment variables):
//
//	IMAGE_NAME   Target tag       (default: openvox-ca-go:latest)
//	BINARY_PATH  Source binary    (default: ./bin/openvox-ca)
func (Dev) Container() error {
	cfg := ContainerConfig{}
	if err := env.Parse(&cfg); err != nil {
		return fmt.Errorf("config parse failed: %w", err)
	}
	fmt.Printf("Building '%s' (binary: %s)...\n", cfg.Image, cfg.Binary)

	binLayer, err := tarLayer(map[string]string{"/app": cfg.Binary}, nil)
	if err != nil {
		return fmt.Errorf("failed to package binary: %w", err)
	}

	dirLayer, err := tarLayer(nil, []string{"/data"})
	if err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	img, err := mutate.AppendLayers(empty.Image, binLayer, dirLayer)
	if err != nil {
		return fmt.Errorf("image mutation failed: %w", err)
	}

	img, err = mutate.Config(img, v1.Config{
		Entrypoint: []string{"/app"},
		Cmd:        []string{"-cadir", "/data", "-v", "2"},
	})
	if err != nil {
		return fmt.Errorf("failed to set image config: %w", err)
	}

	tag, err := name.NewTag(cfg.Image)
	if err != nil {
		return err
	}

	if _, err := daemon.Write(tag, img); err != nil {
		return fmt.Errorf("failed to load to daemon: %w", err)
	}

	fmt.Println("Success! Image loaded.")
	return nil
}

// -- types and helpers --------------------------------------------------------─

type ContainerConfig struct {
	Image  string `env:"IMAGE_NAME" envDefault:"openvox-ca-go:latest"`
	Binary string `env:"BINARY_PATH" envDefault:"./bin/openvox-ca"`
}

// composeCmd returns the compose command prefix, probing in order:
//
//  1. podman-compose  (standalone binary)
//  2. docker compose  (Docker v2 plugin, two-word invocation)
//  3. docker-compose  (Docker v1 standalone binary)
func composeCmd() ([]string, error) {
	if _, err := exec.LookPath("podman-compose"); err == nil {
		return []string{"podman-compose"}, nil
	}
	if _, err := exec.LookPath("docker"); err == nil {
		if exec.Command("docker", "compose", "version").Run() == nil {
			return []string{"docker", "compose"}, nil
		}
	}
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return []string{"docker-compose"}, nil
	}
	return nil, fmt.Errorf("no compose tool found; install podman-compose or docker compose")
}

// runCompose runs a compose command with whichever tool composeCmd selects.
// PYTHONUNBUFFERED=1 is always set so podman-compose (Python) flushes each
// log line immediately rather than block-buffering; it is harmless for
// docker compose (Go).  Extra env vars can be supplied via extraEnv.
func runCompose(extraEnv map[string]string, args ...string) error {
	compose, err := composeCmd()
	if err != nil {
		return err
	}
	env := map[string]string{"PYTHONUNBUFFERED": "1"}
	for k, v := range extraEnv {
		env[k] = v
	}
	return sh.RunWithV(env, compose[0], append(compose[1:], args...)...)
}

// runComposeWithSpinner is like runCompose but displays an animated spinner
// between output lines so the terminal does not appear to hang during quiet
// periods (e.g. the 15-second gaps between k6 progress checkpoints).
//
// The spinner runs in its own goroutine at 100 ms intervals.  Each output
// line from the subprocess clears the spinner, prints the line, then redraws
// the spinner below it.  Falls back to plain runCompose when stdout is not a
// TTY (CI, pipes) so ANSI codes never leak into captured output.
func runComposeWithSpinner(extraEnv map[string]string, spinMsg string, args ...string) error {
	// TTY detection: character-device check works on Linux/macOS.
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return runCompose(extraEnv, args...)
	}

	compose, err := composeCmd()
	if err != nil {
		return err
	}

	cmd := exec.Command(compose[0], append(compose[1:], args...)...)
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	// Pipe both stdout and stderr through a single in-process pipe so the
	// spinner goroutine can interleave cleanly with the subprocess output.
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw

	const erase = "\r\033[K" // carriage-return + CSI erase-to-end-of-line
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	var (
		mu    sync.Mutex
		frame int
	)

	draw := func() { fmt.Printf("\r%s %s", frames[frame], spinMsg) }

	printLine := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Printf("%s%s\n", erase, line)
		draw()
	}

	tick := func() {
		mu.Lock()
		defer mu.Unlock()
		frame = (frame + 1) % len(frames)
		draw()
	}

	// Draw the initial spinner frame.
	mu.Lock()
	draw()
	mu.Unlock()

	// Goroutine: read lines from the subprocess and print each one.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			printLine(scanner.Text())
		}
	}()

	// Goroutine: advance the spinner frame every 100 ms.
	stopSpinner := make(chan struct{})
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				tick()
			case <-stopSpinner:
				return
			}
		}
	}()

	cmdErr := cmd.Run()
	pw.Close() // signal EOF so the scanner goroutine exits
	wg.Wait()
	close(stopSpinner)

	// Erase the spinner line so the next fmt.Println starts cleanly.
	mu.Lock()
	fmt.Print(erase)
	mu.Unlock()

	return cmdErr
}

// archiveEntry is one file in a release tarball, with the permissions it must
// extract as. The archive mixes executables with plain data (the systemd unit),
// and neither the build host's umask nor a single hard-coded mode gets both
// right.
type archiveEntry struct {
	name string
	mode int64
}

func createTarGz(dst, srcDir string, files []archiveEntry) (retErr error) {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	// Closed with the same care as the writers below: a failure surfacing here
	// (ENOSPC on a deferred allocation, say) would otherwise be dropped, and
	// the caller would checksum and publish a truncated release artefact.
	defer func() {
		if err := f.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	gz := gzip.NewWriter(f)
	defer func() {
		if err := gz.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()
	tw := tar.NewWriter(gz)
	defer func() {
		if err := tw.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	for _, entry := range files {
		src := filepath.Join(srcDir, entry.name)
		fi, err := os.Stat(src)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: entry.name,
			Mode: entry.mode,
			Size: fi.Size(),
		}); err != nil {
			return err
		}
		rf, err := os.Open(src)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, rf)
		rf.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func tarLayer(files map[string]string, dirs []string) (v1.Layer, error) {
	b := new(bytes.Buffer)
	tw := tar.NewWriter(b)

	for _, dir := range dirs {
		if err := tw.WriteHeader(&tar.Header{Name: dir, Mode: 0755, Typeflag: tar.TypeDir}); err != nil {
			return nil, err
		}
	}

	for dest, src := range files {
		data, err := os.ReadFile(src)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", src, err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: dest, Mode: 0755, Size: int64(len(data))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	tw.Close()

	return tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b.Bytes())), nil
	})
}
