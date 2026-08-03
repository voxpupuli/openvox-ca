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

// Package version is the single source of truth for the openvox-ca release
// version. Release artefact names embed the Version constant, both binaries
// report it via --version, and the Release workflow refuses to publish a tag
// whose version does not match it — so cutting release vX.Y.Z requires first
// landing a change that sets Version to exactly "X.Y.Z".
package version

import (
	"runtime/debug"
	"strings"
)

// Version is the semantic version of this source tree, without a "v" prefix.
// Between releases it carries a "-dev" pre-release suffix; set it to the
// exact release version before tagging, because the release tag must be
// exactly "v" + Version.
//
// NOTE: the verify-release-tag action (.github/actions/verify-release-tag),
// the CI dist verify steps (.github/workflows/ci.yml), the pre-push hook
// (.lefthook/pre-push/verify-tags.sh), and the magefile (releaseVersion;
// release:prepare also rewrites this line) all depend on this line's exact
// textual shape, so any reformatting must update all five places together.
const Version = "0.9.0-dev"

// Full returns Version augmented with the VCS metadata the Go toolchain
// embeds in binaries built from a git checkout: the commit hash, the commit
// timestamp, and a "dirty" marker for uncommitted changes. Binaries built
// outside a checkout (or test binaries, which are never VCS-stamped) get
// plain Version.
func Full() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}

	var revision, commitTime string
	dirty := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			commitTime = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return full(Version, revision, commitTime, dirty)
}

// full formats a version string from its parts: the bare version, then a
// parenthesised suffix carrying whatever VCS metadata is present. An empty
// revision means the binary was not built from a git checkout, in which case
// the other VCS fields are meaningless and only the version is returned.
func full(version, revision, commitTime string, dirty bool) string {
	if revision == "" {
		return version
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}

	var b strings.Builder
	b.WriteString(version)
	b.WriteString(" (commit ")
	b.WriteString(revision)
	if commitTime != "" {
		b.WriteString(", ")
		b.WriteString(commitTime)
	}
	if dirty {
		b.WriteString(", dirty")
	}
	b.WriteString(")")
	return b.String()
}
