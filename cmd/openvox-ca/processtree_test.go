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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
)

// processTree is the real launcher, run as an operator would run it, with the
// signer and frontend it re-executes. Only real children show what each
// process does with its own logger; the stand-ins the other launcher specs use
// show only what a child is handed.
type processTree struct {
	out     *gbytes.Buffer // the launcher's stdout and stderr, which both children share
	apiPort int
}

// startProcessTree starts the tree with the given OPENVOX_CA_* settings on top
// of a fresh CA directory and an empty config, waits for the frontend to
// accept connections, and stops the whole tree when the spec ends.
func startProcessTree(env ...string) *processTree {
	GinkgoHelper()
	dir := GinkgoT().TempDir()
	cadir := filepath.Join(dir, "cadir")
	Expect(os.MkdirAll(cadir, 0o750)).To(Succeed())
	emptyConfig := filepath.Join(dir, "empty.yaml")
	Expect(os.WriteFile(emptyConfig, []byte("{}\n"), 0o600)).To(Succeed())

	t := &processTree{out: gbytes.NewBuffer(), apiPort: freeLoopbackPort()}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	DeferCleanup(cancel)

	// None of the developer's own OPENVOX_CA_* settings, nothing that would
	// make the launcher think it was already a role or already under a
	// launcher, and no config file from this host.
	var base []string
	for _, e := range os.Environ() {
		if k, _, _ := strings.Cut(e, "="); !strings.HasPrefix(k, "OPENVOX_CA_") && k != launcherStartedEnv {
			base = append(base, e)
		}
	}
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append(base,
		pskChildEnv+"="+realServerChild,
		configEnvVar+"="+emptyConfig,
		"OPENVOX_CA_CADIR="+cadir,
		"OPENVOX_CA_HOST=127.0.0.1",
		"OPENVOX_CA_PORT="+strconv.Itoa(t.apiPort),
		"OPENVOX_CA_CA_KEY_ALGO=ecdsa",
		"OPENVOX_CA_CA_KEY_SIZE=256",
	)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdout = t.out
	cmd.Stderr = t.out
	// Its own process group, so cleanup reaches the children even if the
	// launcher dies before stopping them.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	Expect(cmd.Start()).To(Succeed())

	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	DeferCleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
	})

	Eventually(func() error {
		select {
		case <-done:
			return StopTrying(fmt.Sprintf(
				"the launcher exited (%v) before the frontend came up; output:\n%s", waitErr, t.out.Contents()))
		default:
		}
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(t.apiPort), 500*time.Millisecond)
		if err != nil {
			return err
		}
		return c.Close()
	}, 90*time.Second, 250*time.Millisecond).Should(Succeed(),
		func() string {
			return "the frontend never started listening; launcher output:\n" + string(t.out.Contents())
		})
	return t
}

// absent is what the record helpers return for a record not written yet.
const absent = "<no such record>"

// textRecordRole returns the role= of the first text record whose message is
// msg: "" if it has none, absent if there is no such record.
func textRecordRole(out []byte, msg string) string {
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, `msg="`+msg+`"`) {
			continue
		}
		if m := textRole.FindStringSubmatch(line); m != nil {
			return m[1]
		}
		return ""
	}
	return absent
}

// jsonRecordRole is textRecordRole for a JSON logfile.
func jsonRecordRole(data []byte, msg string) string {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		var entry map[string]any
		if json.Unmarshal(sc.Bytes(), &entry) != nil || entry["msg"] != msg {
			continue
		}
		role, _ := entry["role"].(string)
		return role
	}
	return absent
}

// One record per process, and the role that process must report. Only the
// launcher's and the frontend's are written before the frontend accepts
// connections; nothing orders the signer's ready line before that, so the
// specs wait for each record rather than reading once.
var recordPerRole = []struct{ msg, role string }{
	{"CA processes started", roleLauncher},
	{"Signer process ready", roleSigner},
	{"Starting Puppet CA", roleFrontend},
}

var _ = Describe("the real process tree's logs", func() {
	It("names the writing process on every role's lines on stderr", func() {
		t := startProcessTree()
		for _, r := range recordPerRole {
			Eventually(func() string { return textRecordRole(t.out.Contents(), r.msg) },
				30*time.Second, 100*time.Millisecond).Should(Equal(r.role),
				func() string {
					return fmt.Sprintf("the %s's %q line; output:\n%s", r.role, r.msg, t.out.Contents())
				})
		}
	})

	It("names the writing process on every role's lines in the JSON logfile", func() {
		logFile := filepath.Join(GinkgoT().TempDir(), "ca.log")
		startProcessTree("OPENVOX_CA_LOGFILE=" + logFile)
		readLog := func() []byte {
			data, _ := os.ReadFile(logFile) // absent until a process has logged
			return data
		}
		for _, r := range recordPerRole {
			Eventually(func() string { return jsonRecordRole(readLog(), r.msg) },
				30*time.Second, 100*time.Millisecond).Should(Equal(r.role),
				func() string {
					return fmt.Sprintf("the %s's %q line; logfile:\n%s", r.role, r.msg, readLog())
				})
		}
	})
})
