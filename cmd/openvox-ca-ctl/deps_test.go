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
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// openvox-ca-ctl reads the server's configuration through internal/config, and
// two blocks of that configuration are typed by packages whose stores talk to
// Kubernetes. Their configuration types live in internal/certstore/certconfig
// and internal/k8sexport/exportconfig so that this binary does not link
// client-go. Nothing at compile time holds that: internal/certstore aliases
// every moved type, so typing a config field from it again compiles, passes
// every other spec, and quietly drags client-go back in. This reads the
// binary's real dependency graph instead of trusting the import lines.
var _ = Describe("openvox-ca-ctl's dependency graph", func() {
	It("links no client-go", func() {
		deps, clientGo := clientGoDeps(".")
		// The floor: a listing that did not include the configuration package
		// would pass the check below without having looked at anything.
		Expect(deps).To(ContainElement("github.com/voxpupuli/openvox-ca/internal/config"))
		Expect(clientGo).To(BeEmpty(), "openvox-ca-ctl links client-go; type configuration "+
			"fields from internal/certstore/certconfig and internal/k8sexport/exportconfig, "+
			"not from the packages that alias them")
	})

	// The must-fail twin: the server does link client-go, for its Secret
	// stores and the exporter, so the same matcher has to find it there. A
	// matcher that could never hit would pass the spec above for ever.
	It("finds client-go where it is linked, so the check above can fail", func() {
		_, clientGo := clientGoDeps("../openvox-ca")
		Expect(clientGo).NotTo(BeEmpty())
	})
})

// clientGoDeps lists the packages the package in dir links, and those of them
// that are client-go.
func clientGoDeps(dir string) (deps, clientGo []string) {
	GinkgoHelper()
	cmd := exec.Command("go", "list", "-deps", dir)
	// Built by stripping GIT_* rather than appending, per AGENTS.md: this
	// can run under a git hook, whose exported GIT_DIR would outrank the
	// working directory for anything go chose to ask git.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	// stderr is captured on its own so a failure says why: left in the
	// ExitError, Gomega prints it as a byte slice of numbers.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	Expect(err).NotTo(HaveOccurred(), "go list -deps %s: %s", dir, stderr.String())
	deps = strings.Fields(string(out))
	for _, d := range deps {
		if strings.HasPrefix(d, "k8s.io/client-go") {
			clientGo = append(clientGo, d)
		}
	}
	return deps, clientGo
}
