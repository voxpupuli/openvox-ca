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

package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// EnvBool overlays the boolean environment variable name onto *dst. An unset or
// empty variable leaves *dst alone; any other value must be one
// strconv.ParseBool accepts (1, t, T, true, TRUE, True and their false
// counterparts), and anything else is an error naming the variable. "yes" and
// "on" are not among them, though YAML takes both.
//
// Refused rather than ignored: `OPENVOX_CA_ENCRYPT_CA_KEY=enabled` used to be
// dropped without a word, so a CA meant to encrypt its key bootstrapped with a
// plaintext one.
func EnvBool(name string, dst *bool) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		// Quoted: the value came from the environment and is echoed into a
		// log, so a control character in it is escaped.
		return fmt.Errorf("environment variable %s is %q, which is not a boolean: "+
			"set it to true or false, or unset it", name, v)
	}
	*dst = b
	return nil
}

// EnvInt overlays the integer environment variable name onto *dst. An unset or
// empty variable leaves *dst alone, and a value that is not a decimal integer
// is an error naming the variable.
//
// keep, when non-nil, decides whether a well-formed value is applied; one it
// rejects leaves *dst alone without an error. Most interval settings have
// always ignored a zero or negative value from the environment that way, and
// they still do: the refusal here is for a value that is not a number at all,
// not for one out of range.
func EnvInt(name string, dst *int, keep func(int) bool) error {
	v := os.Getenv(name)
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		// A Kubernetes service link, which nobody set by hand and nobody can
		// unset: a Service named openvox-ca gives every pod in its namespace
		// OPENVOX_CA_PORT=tcp://<cluster IP>:<port>. Say so, since the generic
		// advice would send the operator looking for a setting that is not
		// there.
		if strings.HasPrefix(v, "tcp://") || strings.HasPrefix(v, "udp://") {
			return fmt.Errorf("environment variable %s is %q, which is not an integer: "+
				"it looks like a Kubernetes service link from a Service of that name, so set "+
				"enableServiceLinks: false on the pod", name, v)
		}
		// A whole number too large for an int: telling the operator to set a
		// whole number would be telling them to do what they did.
		if errors.Is(err, strconv.ErrRange) {
			return fmt.Errorf("environment variable %s is %q, which is out of range for "+
				"this setting: set it to a smaller number, or unset it", name, v)
		}
		return fmt.Errorf("environment variable %s is %q, which is not an integer: "+
			"set it to a whole number, or unset it", name, v)
	}
	if keep == nil || keep(n) {
		*dst = n
	}
	return nil
}

// Positive is an EnvInt keep function that applies only values above zero.
func Positive(n int) bool { return n > 0 }

// NonNegative is an EnvInt keep function that applies only values of zero or
// more.
func NonNegative(n int) bool { return n >= 0 }
