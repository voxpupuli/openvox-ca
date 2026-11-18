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
	"io"
	"net/http"
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
)

// captureStreams runs the root command with args, as main does -- no SetOut or
// SetErr, so cobra writes where the binary would -- and returns what reached
// stdout and stderr, plus the command's error.
func captureStreams(args []string) (stdout, stderr string, execErr error) {
	GinkgoHelper()
	outR, outW, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	errR, errW, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() { _, _, _, _ = outR.Close(), outW.Close(), errR.Close(), errW.Close() })

	// Drained concurrently: cobra's usage block can outgrow a pipe buffer.
	outC, errC := make(chan string, 1), make(chan string, 1)
	drain := func(r *os.File, c chan<- string) {
		b, _ := io.ReadAll(r)
		c <- string(b)
	}
	go drain(outR, outC)
	go drain(errR, errC)

	origOut, origErr := os.Stdout, os.Stderr
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()
	os.Stdout, os.Stderr = outW, errW

	cmd := newRootCmd()
	cmd.SetArgs(args)
	execErr = cmd.Execute()

	os.Stdout, os.Stderr = origOut, origErr
	Expect(outW.Close()).To(Succeed())
	Expect(errW.Close()).To(Succeed())
	return <-outC, <-errC, execErr
}

// runnableCommands returns the command path of every subcommand that runs,
// walked from the tree rather than listed, so a subcommand added later is
// covered without anyone remembering to add it here.
func runnableCommands(cmd *cobra.Command, prefix []string) [][]string {
	var found [][]string
	for _, sub := range cmd.Commands() {
		path := append(append([]string{}, prefix...), sub.Name())
		if sub.Runnable() {
			found = append(found, path)
		}
		found = append(found, runnableCommands(sub, path)...)
	}
	return found
}

// strayArgEntries is one table entry per runnable subcommand, built from the
// tree while the spec tree is, so a subcommand added later gets an entry of
// its own. newRootCmd resets the flag globals, so they are put back as found.
func strayArgEntries() []TableEntry {
	defer snapshotCtlGlobals()()
	var entries []TableEntry
	for _, path := range runnableCommands(newRootCmd(), nil) {
		entries = append(entries, Entry(strings.Join(path, " "), path))
	}
	return entries
}

var _ = Describe("Command-line validation", func() {
	var cfg string

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		cfg = writeTempCtlConfig("")
	})

	// cobra accepted and discarded positional arguments until #361, so a typo
	// after a well-formed command went unreported.
	DescribeTable("refuses a stray argument, before doing anything",
		func(path []string) {
			// No --config: the argument has to be refused before the
			// configuration is even looked for, as it is before anything else.
			cmd := newRootCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(append(append([]string{}, path...), "THIS-IS-A-TYPO"))
			Expect(cmd.Execute()).To(MatchError(ContainSubstring(`unexpected argument "THIS-IS-A-TYPO"`)))
		},
		strayArgEntries(),
	)

	// A floor for the table above, so that a walk finding nothing cannot
	// leave it empty and passing.
	It("finds every subcommand in the tree", func() {
		var names []string
		for _, path := range runnableCommands(newRootCmd(), nil) {
			names = append(names, strings.Join(path, " "))
		}
		Expect(names).To(ContainElements("list", "sign", "revoke", "reissue-crl", "clean",
			"generate", "renew", "import-cert", "setup", "import", "migrate"))
	})

	It("names every stray argument", func() {
		_, _, err := captureStreams([]string{"list", "EXTRA", "GARBAGE"})
		Expect(err).To(MatchError(`unexpected arguments ["EXTRA" "GARBAGE"]`))
	})

	Describe("suggesting --certname", func() {
		It("suggests it for the lone name a puppet cert user types", func() {
			_, _, err := captureStreams([]string{"sign", "node1.example.com"})
			Expect(err).To(MatchError(
				`unexpected argument "node1.example.com"; did you mean --certname node1.example.com?`))
		})

		DescribeTable("does not suggest it",
			func(args ...string) {
				_, _, err := captureStreams(append(args, "--config", cfg))
				Expect(err).To(MatchError(ContainSubstring("unexpected argument")))
				Expect(err).NotTo(MatchError(ContainSubstring("did you mean")))
			},
			Entry("for a name the server would refuse", "clean", "Node1/x"),
			Entry("on a command with no --certname", "list", "node1"),
			Entry("when --certname was given", "sign", "--certname", "node1", "node2"),
			Entry("for two words", "revoke", "node1", "node2"),
		)
	})

	// Usage goes with a mistake on the command line, as puppetserver ca prints
	// it, and to stderr: stdout carries generate's PEM and list's table.
	DescribeTable("prints the usage on stderr for a command-line mistake",
		func(args []string, wantErr string) {
			stdout, stderr, err := captureStreams(append(args, "--config", cfg))
			Expect(err).To(MatchError(ContainSubstring(wantErr)))
			Expect(stderr).To(ContainSubstring("Error: " + wantErr))
			Expect(stderr).To(ContainSubstring("Usage:"))
			Expect(stdout).To(BeEmpty())
		},
		Entry("a stray argument", []string{"clean", "node1"}, "unexpected argument"),
		Entry("a missing required flag", []string{"clean"}, `required flag(s) "certname" not set`),
		Entry("a missing one of a pair", []string{"revoke"},
			"at least one of the flags in the group [certname serial] is required"),
		Entry("an unknown flag", []string{"list", "--nosuchflag"}, "unknown flag: --nosuchflag"),
		Entry("a flag value that does not parse", []string{"revoke", "--serial", "AB", "--force=maybe"},
			`invalid argument "maybe"`),
	)

	DescribeTable("prints no usage for a failure once the command is running",
		func(setup func() []string, wantErr string) {
			_, stderr, err := captureStreams(setup())
			Expect(err).To(MatchError(ContainSubstring(wantErr)))
			Expect(stderr).To(ContainSubstring("Error: "))
			Expect(stderr).NotTo(ContainSubstring("Usage:"))
		},
		Entry("an HTTP error", func() []string {
			_, srv := newStubCA(map[string]stubAnswer{
				"GET /puppet-ca/v1/certificate_statuses/all": {http.StatusInternalServerError, "boom"},
			})
			return []string{"list", "--config", cfg, "--server-url", srv.URL}
		}, "HTTP 500"),
		Entry("a configuration file that does not load", func() []string {
			return []string{"list", "--config", writeTempCtlConfig("no_such_key: 1\n")}
		}, "no_such_key"),
	)

	Describe("sign", func() {
		// puppetserver ca refuses the pair; this CLI used to sign everything
		// and drop --certname without a word.
		It("refuses --all with --certname, before sending anything", func() {
			stub, srv := newStubCA(nil)
			_, _, err := captureStreams([]string{"sign", "--all", "--certname", "node1",
				"--config", cfg, "--server-url", srv.URL})
			Expect(err).To(MatchError(ContainSubstring("[all certname] were all set")))
			Expect(stub.requests()).To(BeEmpty())
		})

		It("refuses neither, naming both", func() {
			_, _, err := captureStreams([]string{"sign", "--config", cfg})
			Expect(err).To(MatchError(ContainSubstring("[certname all] is required")))
		})
	})
})
