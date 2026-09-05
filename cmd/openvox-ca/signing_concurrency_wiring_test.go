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

// The step whose absence is silent, and the same guard config_test.go's
// "crl_chain_file wiring" block exists for.
//
// signing_concurrency_test.go covers resolveSigningConcurrency in isolation and
// the file/env layering in isolation. Neither notices if the one line in
// applyCAConfig that carries the value into the CA is dropped or misassigned:
// ca.CA.SigningConcurrency would stay at its Go zero value, which means
// *unbounded*, the whole bound would be inert, and CI would stay green.
package main

import (
	"os"
	"path/filepath"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("ca_signing_concurrency wiring", func() {
	newCA := func() *ca.CA {
		return ca.New(storage.New(GinkgoT().TempDir()), ca.AutosignConfig{Mode: "off"}, "puppet.test")
	}

	loadCfg := func(body string) *serverConfig {
		path := filepath.Join(GinkgoT().TempDir(), "openvox-ca.yaml")
		Expect(os.WriteFile(path, []byte(body), 0o600)).To(Succeed())
		cfg, err := loadServerConfig(path)
		Expect(err).NotTo(HaveOccurred())
		return cfg
	}

	It("reaches the CA", func() {
		myCA := newCA()
		Expect(applyCAConfig(myCA, loadCfg("ca_signing_concurrency: 5\n"))).To(Succeed())
		Expect(myCA.SigningConcurrency).To(Equal(5))
	})

	// The unset case matters most: it is what almost every deployment gets, so
	// a zero reaching the CA here would ship unbounded signing to all of them
	// while every other spec in this package still passed.
	It("resolves the unset sentinel to the built-in default on the way through", func() {
		cfg := loadCfg("host: 127.0.0.1\n")
		Expect(cfg.CASigningConcurrency).To(Equal(-1))

		myCA := newCA()
		Expect(applyCAConfig(myCA, cfg)).To(Succeed())
		Expect(myCA.SigningConcurrency).
			To(Equal(max(minSigningConcurrency, runtime.GOMAXPROCS(0))))
		Expect(myCA.SigningConcurrency).NotTo(BeZero(),
			"a zero here means unbounded, which is the exposure the bound exists to close")
	})

	// An explicit 0 must survive the trip: it is an operator's deliberate
	// opt-out, and silently rewriting it to the default would take that away.
	It("carries an explicit 0 through as unbounded", func() {
		myCA := newCA()
		Expect(applyCAConfig(myCA, loadCfg("ca_signing_concurrency: 0\n"))).To(Succeed())
		Expect(myCA.SigningConcurrency).To(BeZero())
	})
})
