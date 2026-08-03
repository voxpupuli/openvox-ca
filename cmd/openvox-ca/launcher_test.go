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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/signer"
)

// pskChildEnv selects child mode when the test binary re-execs itself: the
// fd-contract specs below spawn real child processes so the ExtraFiles
// slice position ↔ fd number contract (socketpair on fd 3, PSK pipe on
// fd 4) is exercised across a genuine exec boundary.
const pskChildEnv = "OPENVOX_CA_TEST_PSK_CHILD"

func TestMain(m *testing.M) {
	if role := os.Getenv(pskChildEnv); role != "" {
		os.Exit(runPSKChild(role))
	}
	os.Exit(m.Run())
}

// runPSKChild is the child side of the fd-contract specs. It uses only the
// signer package's exported entry points — the same ones the production
// signer and frontend roles use — so fd recovery, PSK loading, and the
// mutual handshake all run exactly as they would under the real launcher.
func runPSKChild(role string) int {
	switch role {
	case "signer":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := signer.Serve(key); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "frontend":
		rs, err := signer.Dial(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer rs.Close()
		digest := sha256.Sum256([]byte("fd-contract"))
		sig, err := rs.Sign(nil, digest[:], crypto.SHA256)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if len(sig) == 0 {
			fmt.Fprintln(os.Stderr, "empty signature")
			return 1
		}
		fmt.Println("SIGN-OK")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown %s role %q\n", pskChildEnv, role)
		return 2
	}
}

// pskChildCmd builds a re-exec of the test binary in the given child role
// with the supplied inherited files, capturing combined output.
func pskChildCmd(ctx context.Context, role string, extraFiles []*os.File, out *bytes.Buffer) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append(os.Environ(), pskChildEnv+"="+role)
	cmd.ExtraFiles = extraFiles
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd
}

var _ = Describe("launcher fd contract", func() {
	// verifies the full cross-process contract end to end: two real child
	// processes recover the socketpair from fd 3 and the PSK from the fd 4
	// pipe, complete the mutual handshake, and service a signing RPC.
	It("delivers the socketpair on fd 3 and the PSK pipe on fd 4", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")
		pskHex := hex.EncodeToString(psk)

		signerSock, frontendSock, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred(), "creating socketpair")

		signerPipe, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "creating signer PSK pipe")
		frontendPipe, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "creating frontend PSK pipe")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)

		var signerOut, frontendOut bytes.Buffer
		signerCmd := pskChildCmd(ctx, "signer", []*os.File{signerSock, signerPipe}, &signerOut)
		frontendCmd := pskChildCmd(ctx, "frontend", []*os.File{frontendSock, frontendPipe}, &frontendOut)

		// Mirror the launcher: drop the parent's copies of each child's files
		// immediately after that child starts, so only the children hold the
		// socketpair ends and pipe read ends.
		Expect(signerCmd.Start()).To(Succeed(), "starting signer child")
		signerSock.Close()
		signerPipe.Close()
		Expect(frontendCmd.Start()).To(Succeed(), "starting frontend child")
		frontendSock.Close()
		frontendPipe.Close()

		Expect(frontendCmd.Wait()).To(Succeed(), "frontend child failed: %s", frontendOut.String())
		Expect(frontendOut.String()).To(ContainSubstring("SIGN-OK"),
			"frontend should obtain a signature over the socketpair")
		Expect(signerCmd.Wait()).To(Succeed(), "signer child failed: %s", signerOut.String())
	})

	// verifies the mandatory-handshake failure mode across the exec
	// boundary: a child whose fd 4 is not the launcher's PSK pipe must fail
	// closed rather than proceed unauthenticated.
	//
	// fd 4 is pinned to /dev/null rather than simply left out of ExtraFiles.
	// Omitting it does not guarantee the child sees fd 4 closed: exec only
	// rewrites fds 0-2 and the ExtraFiles range, so any descriptor this test
	// binary inherited without FD_CLOEXEC from its own parent stays open at
	// its original number in the child. Under a wrapper that leaks one at
	// fd 4 (lefthook's pre-push hook does, as do some CI runners) the child
	// would inherit a foreign pipe, satisfy loadPSK's S_IFIFO check, and then
	// block or fail with an unrelated read error instead of the fd-contract
	// message asserted here. A character device is never a FIFO, so this
	// drives the guard deterministically wherever the suite runs.
	It("fails closed when fd 4 is not the launcher's PSK pipe", func() {
		signerSock, frontendSock, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred(), "creating socketpair")
		DeferCleanup(func() { _ = signerSock.Close() })

		notAPipe, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred(), "opening %s", os.DevNull)
		DeferCleanup(func() { _ = notAPipe.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)

		var out bytes.Buffer
		cmd := pskChildCmd(ctx, "frontend", []*os.File{frontendSock, notAPipe}, &out)
		err = cmd.Run()
		frontendSock.Close()

		Expect(err).To(HaveOccurred(), "child without a PSK pipe on fd 4 should exit non-zero; output: %s", out.String())
		Expect(out.String()).To(ContainSubstring("not spawned by the launcher"),
			"child should report the missing PSK pipe")
	})
})

var _ = Describe("pskPipe", func() {
	// verifies the returned read end yields exactly the hex PSK followed by
	// EOF, which is what a child's parsePSK relies on to drain the pipe.
	It("delivers the PSK followed by EOF", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")
		pskHex := hex.EncodeToString(psk)

		r, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "pskPipe")
		DeferCleanup(func() { _ = r.Close() })

		// ReadAll only returns once the write end is closed, so this also
		// proves pskPipe closed it before returning.
		data, err := io.ReadAll(r)
		Expect(err).NotTo(HaveOccurred(), "reading PSK pipe")
		Expect(string(data)).To(Equal(pskHex), "pipe contents should be the hex PSK")
	})
})
