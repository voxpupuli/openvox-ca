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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/signer"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = DescribeTable("the frontend's bound on its wait for the signer",
	// It has to outlast the largest ceiling inside the signer's Init, which is
	// the migration run's, or it pre-empts the signer's own error with a vaguer
	// one. That ceiling is configurable, so the bound has to follow it: a fixed
	// figure would be overtaken by the first operator to raise it. The expected
	// values are written out rather than derived, so the spec does not share the
	// rule it is checking.
	func(migrationSec int, want time.Duration) {
		cfg := &serverConfig{}
		cfg.SQLMigrationTimeoutSec = migrationSec
		Expect(signerHandshakeTimeout(cfg)).To(Equal(want))
	},
	Entry("at the default migration budget", 0, 11*time.Minute),
	Entry("when the operator raises it", 1800, 31*time.Minute),
	Entry("when the operator lowers it, which reaches the floor", 30, 3*time.Minute),
	Entry("just above the floor", 121, 181*time.Second),
	Entry("when a configuration file sets it negative, which falls back to the default", -5, 11*time.Minute),
)

var _ = DescribeTable("the frontend's bound on its wait for the signer outlasts the migration the backend applies",
	// The bound and the backend read the same setting. Asserted against the
	// backend's own reading of it, so a change to what the setting means on
	// one side cannot leave the bound below the ceiling it has to contain.
	func(migrationSec int) {
		cfg := &serverConfig{}
		cfg.SQLMigrationTimeoutSec = migrationSec
		Expect(signerHandshakeTimeout(cfg)).To(BeNumerically(">", storage.SQLMigrationTimeout(migrationSec)))
		Expect(signerHandshakeTimeout(cfg)).To(BeNumerically(">", 2*ca.LockTimeout),
			"and Init's two sequential lock waits on a contended cold start")
	},
	Entry("at the default", 0),
	Entry("raised", 1800),
	Entry("lowered", 1),
	Entry("negative", -5),
)

var _ = Describe("the frontend's wait for the signer", func() {
	var (
		logs     *bytes.Buffer
		gotCtx   context.Context
		gotBound time.Duration
	)

	// stubDial stands in for the signer for the current spec, recording what it
	// was asked for and answering with err.
	stubDial := func(err error) {
		orig := dialSignerConn
		DeferCleanup(func() { dialSignerConn = orig })
		dialSignerConn = func(ctx context.Context, timeout time.Duration) (net.Conn, error) {
			gotCtx, gotBound = ctx, timeout
			if err != nil {
				return nil, err
			}
			c, _ := net.Pipe()
			DeferCleanup(c.Close)
			return c, nil
		}
	}

	BeforeEach(func() {
		gotCtx, gotBound = nil, 0
		// Installed last, so nothing a fixture logs lands in it.
		logs = &bytes.Buffer{}
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
		DeferCleanup(slog.SetDefault, orig)
	})

	It("waits under the derived bound and the caller's context", func() {
		stubDial(nil)
		cfg := &serverConfig{}
		cfg.SQLMigrationTimeoutSec = 1800
		ctx, cancel := context.WithCancel(context.Background())
		DeferCleanup(cancel)

		conn, err := dialSigner(ctx, cfg)
		Expect(err).NotTo(HaveOccurred())
		Expect(conn).NotTo(BeNil())
		Expect(gotBound).To(Equal(signerHandshakeTimeout(cfg)))
		Expect(gotCtx).To(BeIdenticalTo(ctx), "a SIGTERM during the wait must reach it")
		Expect(logs.String()).To(ContainSubstring("Waiting for the signer process to finish initialising the CA"))
		Expect(logs.String()).NotTo(ContainSubstring("level=ERROR"))
	})

	It("logs that it gave up when the signer never answered", func() {
		stubDial(fmt.Errorf("%w (waited 11m0s)", signer.ErrHandshakeTimeout))

		_, err := dialSigner(context.Background(), &serverConfig{})
		Expect(err).To(MatchError(signer.ErrHandshakeTimeout))
		Expect(logs.String()).To(ContainSubstring("level=ERROR msg=\"Gave up waiting for the signer process\""))
		// The error is the only copy an operator gets under --daemon, so the
		// record must carry it, not just name the failure.
		Expect(logs.String()).To(ContainSubstring("waited 11m0s"))
	})

	It("logs any other failure too, a refused signer proof among them", func() {
		// The one an operator most needs a record of, and under --daemon the
		// returned error goes to /dev/null.
		stubDial(errors.New("PSK handshake failed: PSK authentication failed: signer proof mismatch"))

		_, err := dialSigner(context.Background(), &serverConfig{})
		Expect(err).To(HaveOccurred())
		Expect(logs.String()).To(ContainSubstring("level=ERROR msg=\"Could not connect to the signer process\""))
		Expect(logs.String()).To(ContainSubstring("signer proof mismatch"))
	})

	It("does not log a shutdown as a failure", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		stubDial(fmt.Errorf("stopped waiting for the signer process: %w", context.Canceled))

		_, err := dialSigner(ctx, &serverConfig{})
		Expect(err).To(MatchError(context.Canceled))
		Expect(logs.String()).NotTo(ContainSubstring("level=ERROR"))
	})
})
