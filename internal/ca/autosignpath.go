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

package ca

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxAutosignSymlinks bounds how many symlinks ResolveAutosignExecutable
// follows, as the kernel's own ELOOP limit does for a path lookup.
const maxAutosignSymlinks = 40

// AutosignPathFinding is one entry on the way to an autosign executable that
// somebody other than root or the CA's own user could use to change what the
// CA runs.
type AutosignPathFinding struct {
	Path   string      // the file, symlink or directory at fault
	Mode   os.FileMode // its mode, type bits included, as Lstat reported it
	Reason string      // what is wrong with it, e.g. "group-writable"
}

// String renders the finding for an operator. The path is quoted: it is built
// from symlink targets, and the case being reported is one where somebody else
// may own the symlink and so chose the name, newlines included.
func (f AutosignPathFinding) String() string {
	return fmt.Sprintf("%q (%s) is %s", f.Path, f.Mode, f.Reason)
}

// FormatAutosignPathFindings renders findings as one line, for an error or a
// log record.
func FormatAutosignPathFindings(findings []AutosignPathFinding) string {
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = f.String()
	}
	return strings.Join(parts, "; ")
}

// Two platform hooks, variables so that a white-box spec can stand in for a
// filesystem it cannot create unprivileged (a read-only mount) or an owner it
// cannot chown to.
var (
	// autosignFileOwner returns the uid owning fi, and false where the
	// platform cannot say.
	autosignFileOwner = fileOwner
	// autosignReadOnlyMountRoot reports whether the directory at path is the
	// root of a mount that is read-only.
	autosignReadOnlyMountRoot = readOnlyMountRoot
	// autosignFileLinks returns fi's hard-link count, and false where the
	// platform cannot say.
	autosignFileLinks = fileLinks
)

// ResolveAutosignExecutable follows path, through every symlink, to the file
// the CA would execute, and judges every entry it passes on the way: each
// directory it traverses, each symlink it follows and the file itself. It
// returns the resolved path, the entries that a third party could use to
// substitute a different program, and an error when the path does not lead to
// a regular file at all.
//
// The rules are OpenSSH's StrictModes, applied to the whole chain:
//
//   - Every entry must be owned by root or by the CA's own (effective) uid. An
//     owner can chmod or rename what it owns whatever the mode says, so an
//     entry owned by anyone else is theirs to swap.
//   - No file or directory may be group- or world-writable. That is stricter
//     than the key-permission policy, which tolerates group access: a key is
//     data the CA reads, while this is code the CA runs and whose exit status
//     decides which certificates are signed.
//   - A sticky directory is exempt from the writable test, because the sticky
//     bit stops other users renaming or removing entries they do not own --
//     and the entries beneath it are still judged. That is what lets a script
//     live under /tmp.
//   - A Kubernetes ConfigMap, Secret, projected or downward API volume's root
//     is exempt from the writable test too: the kubelet creates it 0777,
//     root-owned and not sticky, and mounts it read-only into the container.
//     Ownership is still judged. See kubeletVolumeRoot for how it is told
//     apart.
//
// That last exemption is deliberately narrow, because the obvious test for it
// -- "is this directory on a read-only mount?" -- asks about the mount as this
// process sees it, not about who can write the directory. A service manager's
// ProtectSystem=strict makes nearly every directory read-only in the CA's own
// namespace, and every separate host mount point the root of a read-only
// mount there, while host users can still write them through their own view.
// So the exemption also wants the one thing only the kubelet's atomic writer
// leaves at a volume root: a root-owned ..data symlink. What it still trusts
// is that nobody but root writes that directory through another mount -- true
// of the kubelet's own backing directory, and not of an emptyDir or host
// directory that some other container or user mounts read-write.
//
// It is called at startup and again before every run, so a symlink repointed
// after startup -- including the `..data` swap the kubelet makes when a
// ConfigMap changes -- is followed, and judged, like the original. Executing
// the path it returns, rather than the configured one, means the file that
// runs is the file that was judged: outside that last case, only root or the
// CA's own user could change any entry between the two, and both can already
// do anything this check could prevent.
//
// Symlink modes are not judged: Linux ignores them. A symlink's owner is.
func ResolveAutosignExecutable(path string) (string, []AutosignPathFinding, error) {
	if path == "" {
		return "", nil, errors.New("no autosign executable configured")
	}
	// Not filepath.Abs, which cleans the path: that turns "link/.." into the
	// directory link sits in, where the kernel goes to the parent of wherever
	// link leads.
	abs := path
	if !filepath.IsAbs(abs) {
		wd, err := os.Getwd()
		if err != nil {
			return "", nil, fmt.Errorf("making %q absolute: %w", path, err)
		}
		abs = wd + string(filepath.Separator) + path
	}

	uid := uint32(os.Geteuid()) //nolint:gosec // G115: geteuid() returns a uid_t, which always fits uint32
	var findings []AutosignPathFinding
	add := func(p string, fi os.FileInfo, reason string) {
		findings = append(findings, AutosignPathFinding{Path: p, Mode: fi.Mode(), Reason: reason})
	}
	judgeOwner := func(p string, fi os.FileInfo) {
		owner, ok := autosignFileOwner(fi)
		switch {
		case !ok:
			add(p, fi, "owned by a user this platform cannot report")
		case owner != 0 && owner != uid:
			add(p, fi, fmt.Sprintf("owned by uid %d, not by root or the CA's uid %d", owner, uid))
		}
	}
	judgeWritable := func(p string, fi os.FileInfo) {
		reason := writableReason(fi.Mode().Perm())
		if reason == "" {
			return
		}
		if fi.IsDir() && (fi.Mode()&os.ModeSticky != 0 || kubeletVolumeRoot(p)) {
			return
		}
		add(p, fi, reason)
	}

	root := string(filepath.Separator)
	fi, err := os.Lstat(root)
	if err != nil {
		return "", nil, quotedPathError(err)
	}
	judgeOwner(root, fi)
	judgeWritable(root, fi)

	current := root
	pending := splitAutosignPath(abs)
	links := 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case ".":
			continue
		case "..":
			// current never contains a symlink, so its lexical parent is its
			// real one, and was judged on the way down.
			current = filepath.Dir(current)
			continue
		}

		next := filepath.Join(current, name)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", findings, quotedPathError(err)
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			links++
			if links > maxAutosignSymlinks {
				return "", findings, fmt.Errorf("resolving %q: more than %d symlinks", path, maxAutosignSymlinks)
			}
			judgeOwner(next, fi)
			target, err := os.Readlink(next)
			if err != nil {
				return "", findings, quotedPathError(err)
			}
			if filepath.IsAbs(target) {
				current = root
			}
			pending = append(splitAutosignPath(target), pending...)
		case fi.IsDir():
			judgeOwner(next, fi)
			judgeWritable(next, fi)
			current = next
		case fi.Mode().IsRegular():
			if len(pending) > 0 {
				return "", findings, fmt.Errorf("resolving %q: %q is not a directory", path, next)
			}
			judgeOwner(next, fi)
			judgeWritable(next, fi)
			current = next
		default:
			return "", findings, fmt.Errorf("resolving %q: %q is not a regular file, directory or symlink", path, next)
		}
	}

	fi, err = os.Lstat(current)
	if err != nil {
		return "", findings, quotedPathError(err)
	}
	if !fi.Mode().IsRegular() {
		return "", findings, fmt.Errorf("%q resolves to %q, which is not a regular file", path, current)
	}
	return current, findings, nil
}

// kubeletVolumeRoot reports whether dir is the root of a volume the kubelet's
// atomic writer manages: the root of a read-only mount, holding the root-owned
// ..data symlink through which the writer swaps one set of files for the next.
// The mount must be read-only and dir its root (autosignReadOnlyMountRoot),
// and the symlink must be root's, so that nobody else can make an ordinary
// directory look like a volume by planting one.
//
// It must also have exactly one link. The writer creates ..data with
// symlink(2) and rename(2), so a genuine one never has another name; a
// hard link to some other root-owned symlink would carry root's ownership
// with it, and a kernel with fs.protected_hardlinks=0 lets anyone make one.
func kubeletVolumeRoot(dir string) bool {
	if !autosignReadOnlyMountRoot(dir) {
		return false
	}
	fi, err := os.Lstat(filepath.Join(dir, "..data"))
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false
	}
	if links, ok := autosignFileLinks(fi); !ok || links != 1 {
		return false
	}
	owner, ok := autosignFileOwner(fi)
	return ok && owner == 0
}

// quotedPathError re-renders an *fs.PathError with its path quoted, for the
// reason AutosignPathFinding.String quotes one: a path met while following
// symlinks may have been named by somebody else. The underlying error stays
// wrapped, so errors.Is(err, fs.ErrNotExist) still answers.
func quotedPathError(err error) error {
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		return err
	}
	return fmt.Errorf("%s %q: %w", pathErr.Op, pathErr.Path, pathErr.Err)
}

// splitAutosignPath splits p into its components, dropping the empty ones a
// leading, trailing or doubled separator leaves.
func splitAutosignPath(p string) []string {
	var parts []string
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

// writableReason names who besides the owner may write to an entry with perm,
// or returns "" when nobody may.
func writableReason(perm os.FileMode) string {
	switch {
	case perm&0o022 == 0o022:
		return "group- and world-writable"
	case perm&0o020 != 0:
		return "group-writable"
	case perm&0o002 != 0:
		return "world-writable"
	}
	return ""
}
