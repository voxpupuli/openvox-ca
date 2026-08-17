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

package storage

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// A second *process* holding a same-host lock, for the one spec that needs a
// real one rather than a second open file description.
//
// The mechanism is the standard Go one: the test binary re-executes itself and
// an environment variable diverts the copy into a helper before any spec runs.
// It is preferred here over building a throwaway program, which would need a
// toolchain and a writable build cache at test time.

// lockHelperEnv carries "<cadir>|<lock name>" to a re-executed copy of this
// test binary. Empty in a normal run.
const lockHelperEnv = "OPENVOX_CA_TEST_SAMEHOST_LOCK"

// lockHelperReady is written to the helper's stdout once the lock is held, so
// the parent waits on the lock rather than on a guess about process start-up.
const lockHelperReady = "LOCKED"

// TestMain diverts a re-executed copy of this binary into the lock helper. It
// is not a test and adds no second RunSpecs: the normal path is m.Run(), and
// the suite bootstrap in storage_suite_test.go remains the only one.
func TestMain(m *testing.M) {
	if spec := os.Getenv(lockHelperEnv); spec != "" {
		os.Exit(runLockHelper(spec))
	}
	os.Exit(m.Run())
}

// runLockHelper takes the named same-host lock on the given cadir, announces
// it, and holds it until stdin closes. Holding until the parent says so, rather
// than for a fixed duration, is what keeps the spec free of a sleep long enough
// to be slow and short enough to be flaky.
func runLockHelper(spec string) int {
	cadir, name, ok := strings.Cut(spec, "|")
	if !ok {
		fmt.Fprintf(os.Stderr, "lock helper: malformed spec %q\n", spec)
		return 2
	}

	ul, err := NewFilesystemBackend(cadir).AcquireSameHostLock(context.Background(), name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lock helper: acquiring %q: %v\n", name, err)
		return 1
	}

	fmt.Println(lockHelperReady)
	// Draining to EOF blocks until the parent closes the pipe (or exits).
	_, _ = io.Copy(io.Discard, os.Stdin)

	if err := ul.Unlock(); err != nil {
		fmt.Fprintf(os.Stderr, "lock helper: releasing %q: %v\n", name, err)
		return 1
	}
	return 0
}

// lockHelper is a running helper process holding one lock.
type lockHelper struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

// startLockHelper launches the helper and returns once it holds the lock.
func startLockHelper(cadir, name string) *lockHelper {
	GinkgoHelper()

	// os.Args[0] is the compiled test binary. No test flags are passed on, so
	// the child neither runs specs nor writes a coverage profile.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+cadir+"|"+name)
	cmd.Stderr = GinkgoWriter
	// A child that ignores the closed pipe must not turn a failed spec into a
	// suite-wide hang: Wait gives up and kills it rather than blocking until
	// `go test -timeout` takes the whole binary down.
	cmd.WaitDelay = 10 * time.Second

	stdin, err := cmd.StdinPipe()
	Expect(err).NotTo(HaveOccurred(), "helper stdin")
	stdout, err := cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred(), "helper stdout")
	Expect(cmd.Start()).To(Succeed(), "starting the lock helper")

	// Registered here, not by the caller: between Start and the caller's
	// DeferCleanup there are assertions that can abort the spec, and an abort
	// there would leave a live process holding a lock with no cleanup attached.
	h := &lockHelper{cmd: cmd, stdin: stdin}
	DeferCleanup(h.stop)

	line, err := bufio.NewReader(stdout).ReadString('\n')
	Expect(err).NotTo(HaveOccurred(), "the helper exited before taking the lock")
	Expect(strings.TrimSpace(line)).To(Equal(lockHelperReady))

	return h
}

// stop releases the lock by closing the helper's stdin and waiting for it to
// exit. Safe to call twice, so a spec may stop it explicitly and still register
// the cleanup.
func (h *lockHelper) stop() {
	GinkgoHelper()
	if h.cmd.Process == nil {
		return
	}
	_ = h.stdin.Close()
	err := h.cmd.Wait()
	h.cmd.Process = nil
	Expect(err).NotTo(HaveOccurred(), "the lock helper exited badly")
}
