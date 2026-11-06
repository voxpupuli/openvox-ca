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
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A server given another backend's settings but no storage_backend used to
// start on the filesystem backend and ignore them (#484). The refusal lives in
// config.StorageConfig.ToBackendSpec; these drive the whole command, once for
// each place the settings can come from, because all three merge into the
// config it reads. --daemon with a stubbed fork, for two reasons: the refusal
// has to come before the fork (past it the child's stderr is /dev/null), and
// without the refusal the command returns errStubbedFork instead of serving,
// so a regression fails the spec rather than hanging it.
var _ = Describe("a server given another backend's settings but no storage_backend", func() {
	var (
		forked bool
		cfg    string
	)

	// Pinned as keyperms_test.go's startup specs pin them: an ambient
	// OPENVOX_CA_STORAGE_BACKEND would satisfy the refusal for these specs.
	BeforeEach(func() {
		clearServerEnv()
		cfg = filepath.Join(GinkgoT().TempDir(), "config.yaml")
		Expect(os.WriteFile(cfg, []byte("{}\n"), 0o600)).To(Succeed())
		GinkgoT().Setenv(configEnvVar, cfg)

		forked = false
		orig := startDaemonChild
		startDaemonChild = func(*exec.Cmd) error { forked = true; return errStubbedFork }
		DeferCleanup(func() { startDaemonChild = orig })
	})

	run := func(extra ...string) (string, error) {
		cmd := newRootCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(append([]string{
			"--cadir", GinkgoT().TempDir(), "--host", "127.0.0.1", "--port", "0", "--daemon",
		}, extra...))
		err := cmd.Execute()
		return out.String(), err
	}

	refusal := func(key string) OmegaMatcher {
		return MatchError(And(
			ContainSubstring("storage_backend is not set, so the filesystem backend is selected"),
			ContainSubstring("("+key+")"),
		))
	}

	It("refuses a setting from the config file, before forking", func() {
		Expect(os.WriteFile(cfg, []byte("sql_dsn: postgres://ca@db/ca\n"), 0o600)).To(Succeed())

		out, err := run()
		Expect(err).To(refusal("sql_dsn"))
		Expect(forked).To(BeFalse(), "the refusal has to come before the fork")
		Expect(out).NotTo(ContainSubstring("started in background"))
	})

	It("refuses a setting from the environment, before forking", func() {
		GinkgoT().Setenv("OPENVOX_CA_REDIS_ADDRS", "redis:6379")

		out, err := run()
		Expect(err).To(refusal("redis_addrs"))
		Expect(forked).To(BeFalse(), "the refusal has to come before the fork")
		Expect(out).NotTo(ContainSubstring("started in background"))
	})

	It("refuses a setting from a flag, before forking", func() {
		out, err := run("--etcd-endpoints", "https://etcd:2379")
		Expect(err).To(refusal("etcd_endpoints"))
		Expect(forked).To(BeFalse(), "the refusal has to come before the fork")
		Expect(out).NotTo(ContainSubstring("started in background"))
	})

	// The twin: the same command with nothing but shared settings reaches the
	// fork, so the specs above fail on the refusal and not on something else
	// this command line gets wrong.
	It("forks when only settings every backend reads are given", func() {
		_, err := run()
		Expect(err).To(MatchError(errStubbedFork))
		Expect(forked).To(BeTrue())
	})
})
