// Copyright (C) 2026 Trevor Vaughan
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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/signer"
)

const (
	// defaultShutdownDrain is the frontend's graceful HTTP-drain budget when the
	// operator has not set shutdown_timeout_sec / PUPPET_CA_SHUTDOWN_TIMEOUT_SEC.
	// 25s is chosen so the launcher's derived hard-kill deadline (drain +
	// launcherShutdownHeadroom = 28s) stays under Kubernetes' 30s default
	// terminationGracePeriodSeconds, leaving the platform headroom before it
	// SIGKILLs the pod.
	defaultShutdownDrain = 25 * time.Second
	// launcherShutdownHeadroom is added to the frontend's drain budget to form
	// the launcher's hard-kill deadline. Because the launcher's timer starts
	// when it forwards SIGTERM — strictly before the frontend begins its own
	// Shutdown — this headroom guarantees the launcher always outlasts the
	// frontend's drain so the supervisor can never truncate it.
	launcherShutdownHeadroom = 3 * time.Second
	// crashShutdownTimeout bounds teardown of the surviving child when the
	// other has already exited unexpectedly. This is a failure path, not a
	// graceful drain, so it uses a shorter budget.
	crashShutdownTimeout = 5 * time.Second
)

// runLauncher is the supervisor process that spawns the isolated signer and
// frontend children, monitors them, and propagates signals for clean shutdown.
//
// Process tree:
//
//	openvox-ca (launcher/supervisor)
//	├-- openvox-ca [signer]    holds CA key, no network, socketpair only
//	└-- openvox-ca [frontend]  HTTP server, connects to signer via socketpair
//
// SECURITY: The socketpair is created before either child is spawned and
// passed via inherited file descriptors (fd 3). There is no filesystem path
// for the socket; only the two child processes hold endpoints.
//
// drain is the frontend's resolved graceful HTTP-drain budget (see
// serverConfig.shutdownDrain). The launcher waits drain+launcherShutdownHeadroom
// for both children to exit after forwarding SIGTERM before hard-killing them,
// so the frontend always gets its full drain even though the launcher's timer
// starts first.
// NIST 800-53: SC-3 (Security Function Isolation), SC-4 (Information in Shared System Resources)
func runLauncher(drain time.Duration) error {
	gracefulShutdownTimeout := drain + launcherShutdownHeadroom

	// Create the socketpair for signer ↔ frontend communication.
	signerSock, frontendSock, err := signer.Socketpair()
	if err != nil {
		return fmt.Errorf("creating signer socketpair: %w", err)
	}
	defer signerSock.Close()
	defer frontendSock.Close()

	// Generate a PSK for authenticating the socketpair endpoints.
	// Both children receive this via environment variable and verify it
	// on first RPC call, preventing a rogue process from injecting a fake
	// signer if the fd is somehow leaked.
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return fmt.Errorf("generating socketpair PSK: %w", err)
	}
	pskHex := hex.EncodeToString(psk)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	slog.Info("Starting isolated CA processes")

	// Build base environment: strip role/daemon vars to prevent inheritance loops.
	// Clip to len==cap so each append below allocates a fresh backing array,
	// preventing the signer and frontend env slices from aliasing.
	baseEnv := filterEnv(os.Environ(), "PUPPET_CA_ROLE", "PUPPET_CA_DAEMON", "PUPPET_CA_SIGNER_PSK")
	baseEnv = baseEnv[:len(baseEnv):len(baseEnv)]

	// Spawn signer child.
	signerCmd := exec.Command(exe, os.Args[1:]...) //nolint:gosec // G204: re-execs this same binary (os.Executable) with the operator's own os.Args
	signerCmd.Env = append(baseEnv,
		"PUPPET_CA_ROLE=signer",
		"PUPPET_CA_DAEMON=1",
		"PUPPET_CA_SIGNER_PSK="+pskHex,
	)
	signerCmd.ExtraFiles = []*os.File{signerSock} // fd 3
	signerCmd.Stdout = os.Stdout
	signerCmd.Stderr = os.Stderr
	if err := signerCmd.Start(); err != nil {
		return fmt.Errorf("starting signer process: %w", err)
	}
	// Close our copy of the signer's socket end; only the child should hold it.
	signerSock.Close()

	// Spawn frontend child.
	frontendCmd := exec.Command(exe, os.Args[1:]...) //nolint:gosec // G204: re-execs this same binary (os.Executable) with the operator's own os.Args
	frontendCmd.Env = append(baseEnv,
		"PUPPET_CA_ROLE=frontend",
		"PUPPET_CA_DAEMON=1",
		"PUPPET_CA_SIGNER_PSK="+pskHex,
	)
	frontendCmd.ExtraFiles = []*os.File{frontendSock} // fd 3
	frontendCmd.Stdout = os.Stdout
	frontendCmd.Stderr = os.Stderr
	if err := frontendCmd.Start(); err != nil {
		signerCmd.Process.Kill()
		return fmt.Errorf("starting frontend process: %w", err)
	}
	// Close our copy of the frontend's socket end.
	frontendSock.Close()

	slog.Info("CA processes started",
		"signer_pid", signerCmd.Process.Pid,
		"frontend_pid", frontendCmd.Process.Pid,
	)

	// Forward termination signals to children. The buffer matches the
	// number of registered signals so a coincident SIGTERM+SIGINT (e.g.
	// terminal Ctrl-C racing with a supervisor SIGTERM) cannot drop a
	// notification and leave the launcher hung.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Wait for either child to exit.
	type childResult struct {
		name string
		err  error
	}
	exitCh := make(chan childResult, 2)
	go func() { exitCh <- childResult{"signer", signerCmd.Wait()} }()
	go func() { exitCh <- childResult{"frontend", frontendCmd.Wait()} }()

	shutdown := func() {
		frontendCmd.Process.Signal(syscall.SIGTERM)
		signerCmd.Process.Signal(syscall.SIGTERM)
		timer := time.AfterFunc(gracefulShutdownTimeout, func() {
			frontendCmd.Process.Kill()
			signerCmd.Process.Kill()
		})
		<-exitCh
		<-exitCh
		timer.Stop()
	}

	select {
	case sig := <-sigCh:
		slog.Info("Received signal, shutting down CA processes", "signal", sig)
		shutdown()
		return nil

	case result := <-exitCh:
		slog.Error("CA child process exited unexpectedly", "process", result.name, "error", result.err)
		// Shut down the surviving child.
		frontendCmd.Process.Signal(syscall.SIGTERM)
		signerCmd.Process.Signal(syscall.SIGTERM)
		timer := time.AfterFunc(crashShutdownTimeout, func() {
			frontendCmd.Process.Kill()
			signerCmd.Process.Kill()
		})
		<-exitCh // wait for the other child
		timer.Stop()
		return fmt.Errorf("%s process exited unexpectedly: %w", result.name, result.err)
	}
}

// filterEnv returns a copy of env with the named keys removed.
func filterEnv(env []string, keys ...string) []string {
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if !keySet[k] {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
