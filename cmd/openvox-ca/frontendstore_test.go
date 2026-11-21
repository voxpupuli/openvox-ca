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
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("the frontend role's start", func() {
	It("does not touch the store before the signer has answered", func() {
		// The signer prepares the store -- the schema check and, on SQL, the
		// migration under its lock -- and the frontend reads it only once the
		// handshake says the signer is done. A frontend that prepared it too,
		// before dialling, ran the schema check twice per start under two
		// migration budgets and contended with its own signer for the
		// migration lock.
		//
		// Observed through a database that cannot be reached: a frontend that
		// touched the store first fails on it, and one that does not gets as
		// far as the signer, which is stubbed to refuse.
		clearServerEnv()
		setEnv("OPENVOX_CA_ROLE", "frontend")
		// The role installs its own default logger; put the suite's back.
		DeferCleanup(slog.SetDefault, slog.Default())
		caDir := GinkgoT().TempDir()
		emptyConfig := filepath.Join(GinkgoT().TempDir(), "config.yaml")
		Expect(os.WriteFile(emptyConfig, nil, 0o600)).To(Succeed())

		refused := errors.New("stub signer refused the handshake")
		dialed := false
		var bound time.Duration
		orig := dialSignerConn
		DeferCleanup(func() { dialSignerConn = orig })
		dialSignerConn = func(_ context.Context, timeout time.Duration) (net.Conn, error) {
			dialed, bound = true, timeout
			return nil, refused
		}

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--config", emptyConfig, "--cadir", caDir,
			"--storage-backend", "postgres", "--sql-dsn-file", writeDSNFile("postgres://ca@127.0.0.1:1/ca"),
			"--host", "127.0.0.1", "--port", "0"})
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()
		var err error
		Eventually(done, "30s").Should(Receive(&err))

		Expect(err).To(MatchError(refused), "the frontend should reach the signer before the store")
		Expect(dialed).To(BeTrue())
		// The start path's own call, not only dialSigner's: the empty
		// configuration's bound, written out.
		Expect(bound).To(Equal(11*time.Minute), "the start path must wait under the derived bound")
	})
})

// writeDSNFile writes dsn to a file for --sql-dsn-file, which keeps a DSN out
// of argv and so out of the password warning these specs do not exercise.
func writeDSNFile(dsn string) string {
	GinkgoHelper()
	path := filepath.Join(GinkgoT().TempDir(), "dsn")
	Expect(os.WriteFile(path, []byte(dsn+"\n"), 0o600)).To(Succeed())
	return path
}
