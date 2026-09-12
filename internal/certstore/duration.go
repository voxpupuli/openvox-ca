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

package certstore

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration that decodes from a YAML scalar in Go's duration
// syntax: "2160h", "720h", "24h", "90m", "0".
//
// The rest of the server's configuration counts seconds in an `_sec`-suffixed
// integer, and this block deliberately does not. Neither convention already in
// the file spans what a managed certificate has to say: days cannot express a
// six-hour revoke_after, and seconds are unreadable at thirty days. The
// "2160h means ninety days" wart is accepted knowingly, and is what
// docs/configuration.md spells out.
//
// A bare number is refused rather than guessed. `ttl: 2160` could mean hours or
// seconds, and time.ParseDuration says so for us: "missing unit in duration"
// names the mistake more precisely than any default could.
type Duration time.Duration

// UnmarshalYAML decodes a Go duration string.
//
// Errors carry the line number because this type is reached through two levels
// of nesting in a list, and yaml.v3 does not decorate an error returned from a
// custom unmarshaller with the position of the node that produced it.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("line %d: a duration must be a scalar such as \"720h\": %w", node.Line, err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %q is not a duration (Go's syntax: \"2160h\" for ninety days, "+
			"\"720h\" for thirty, \"24h\", \"90m\", \"0\"): %w", node.Line, s, err)
	}
	*d = Duration(parsed)
	return nil
}

// AsDuration returns the value as a time.Duration.
//
// Named for what it converts rather than shadowing the type name: a method
// called Duration on a type called Duration cannot also satisfy fmt.Stringer
// without reading as a mistake at every call site.
func (d Duration) AsDuration() time.Duration { return time.Duration(d) }
