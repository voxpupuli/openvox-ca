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

// Package fileexportconfig holds the `file_export` configuration types and
// their validation, apart from the exporter in internal/fileexport, in the same
// way internal/k8sexport/exportconfig does for `kubernetes_export`: so that
// internal/config can declare the block without depending on the exporter, its
// metrics or the storage layer it writes through.
//
// Its specs live with internal/fileexport's.
package fileexportconfig

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/k8sexport/exportconfig"
)

// Materials a target may hold. A file holds exactly one, because that is how
// every consumer of these files reads them: Puppet's `localcacert` and
// `hostcrl` are two settings naming two files.
const (
	MaterialCert = "cert"
	MaterialCRL  = "crl"
)

// Scopes, shared with the Kubernetes export so that the same word selects the
// same blocks in both. See exportconfig for what each publishes.
const (
	ScopeSelf  = exportconfig.ScopeSelf
	ScopeChain = exportconfig.ScopeChain
	ScopeRoot  = exportconfig.ScopeRoot
)

const (
	// DefaultInterval is how often each target is compared with storage when
	// interval_sec is unset. It matches crl_sync_interval_sec's default, so a
	// revocation made on another replica reaches this host's file on about the
	// same schedule as it reaches this replica's own revocation checks.
	DefaultInterval = 60 * time.Second

	// MaxIntervalSec caps interval_sec. The mixin's OpenVoxCAFileExportStale
	// alert treats a target as stale once it has gone ten minutes without a
	// successful sync; an interval longer than half that would let a single
	// failed attempt, or none at all, look like an outage. Raising this means
	// raising that threshold with it.
	MaxIntervalSec = 300
)

// Config is the top-level file_export configuration block. The feature is
// enabled when Targets is non-empty.
type Config struct {
	// IntervalSec is how often every target is compared with storage and
	// rewritten if it differs; 0 selects DefaultInterval.
	IntervalSec int `yaml:"interval_sec"`
	// Targets is the set of files to keep current.
	Targets []Target `yaml:"targets"`
}

// Target is one file holding the CA certificate or the CRL.
type Target struct {
	// Path is the absolute path of the file. Its directory must already exist:
	// the exporter does not create directories, since doing so would mean
	// choosing their owner and mode for the operator.
	Path string `yaml:"path"`
	// Material is "cert" or "crl".
	Material string `yaml:"material"`
	// Scope selects how much of the stored chain to write. Empty selects
	// ScopeChain -- the stored bundle or CRL chain verbatim, which is what the
	// HTTP endpoints serve and what a Kubernetes export target publishes by
	// default. ScopeRoot applies to the certificate only.
	Scope string `yaml:"scope"`
}

// Enabled reports whether any export target is configured.
func (c *Config) Enabled() bool {
	return c != nil && len(c.Targets) > 0
}

// Interval returns the configured sync interval, or DefaultInterval when none
// is set. Validate must have accepted the configuration first.
func (c *Config) Interval() time.Duration {
	if c.IntervalSec == 0 {
		return DefaultInterval
	}
	return time.Duration(c.IntervalSec) * time.Second
}

// Validate normalises the config in place (cleaning paths, applying the
// default scope) and returns an error describing the first problem found. It
// is safe to call once at startup before constructing an Exporter.
func (c *Config) Validate() error {
	if c.IntervalSec < 0 {
		return fmt.Errorf("file_export.interval_sec must not be negative (got %d)", c.IntervalSec)
	}
	if c.IntervalSec > MaxIntervalSec {
		return fmt.Errorf("file_export.interval_sec must not exceed %d seconds (got %d): "+
			"a longer interval lets a stale file go unreported by the export alert",
			MaxIntervalSec, c.IntervalSec)
	}
	seen := make(map[string]int, len(c.Targets))
	for i := range c.Targets {
		t := &c.Targets[i]
		if err := t.validate(); err != nil {
			return fmt.Errorf("file_export target %d: %w", i, err)
		}
		// Two targets naming one file would rewrite it in turn on every pass,
		// each undoing the other, whenever their material or scope differ. When
		// they agree the second is redundant. Neither is worth accepting.
		if j, dup := seen[t.Path]; dup {
			return fmt.Errorf("file_export targets %d and %d both write %s", j, i, t.Path)
		}
		seen[t.Path] = i
	}
	return nil
}

func (t *Target) validate() error {
	if strings.TrimSpace(t.Path) == "" {
		return fmt.Errorf("path is required")
	}
	// Absolute rather than resolved against the working directory. A relative
	// path would name a different file depending on where the server was
	// started from, and a service manager's working directory is not
	// something an operator writing this block is thinking about.
	if !filepath.IsAbs(t.Path) {
		return fmt.Errorf("path %q must be absolute", t.Path)
	}
	t.Path = filepath.Clean(t.Path)
	if t.Path == string(filepath.Separator) {
		return fmt.Errorf("path %q names a directory, not a file", t.Path)
	}

	switch t.Material {
	case MaterialCert, MaterialCRL:
	case "":
		return fmt.Errorf("material is required (%q or %q)", MaterialCert, MaterialCRL)
	default:
		return fmt.Errorf("invalid material %q (must be %q or %q)", t.Material, MaterialCert, MaterialCRL)
	}

	if t.Scope == "" {
		t.Scope = ScopeChain
	}
	switch {
	case t.Scope == ScopeSelf, t.Scope == ScopeChain:
	case t.Scope == ScopeRoot && t.Material == MaterialCert:
	case t.Material == MaterialCRL:
		// No "root" for a CRL, for the reason kubernetes_export gives: a chain
		// has no single anchor CRL, and the root's own CRL is one of its members.
		return fmt.Errorf("invalid scope %q for a crl target (must be %q or %q)",
			t.Scope, ScopeSelf, ScopeChain)
	default:
		return fmt.Errorf("invalid scope %q (must be %q, %q or %q)",
			t.Scope, ScopeSelf, ScopeChain, ScopeRoot)
	}
	return nil
}
