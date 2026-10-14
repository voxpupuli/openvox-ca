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
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/voxpupuli/openvox-ca/internal/version"
)

// saveCtlGlobals registers a DeferCleanup restoring the package-level flag
// globals. Both newRootCmd() (which re-registers the persistent flags against
// them) and executing a command mutate these, so specs must not leak their
// resolved values into later ones.
func saveCtlGlobals() {
	serverURL, caCert := globalServerURL, globalCACert
	clientCert, clientKey := globalClientCert, globalClientKey
	verbose, insecure, configFile := globalVerbose, globalInsecure, globalConfigFile
	DeferCleanup(func() {
		globalServerURL, globalCACert = serverURL, caCert
		globalClientCert, globalClientKey = clientCert, clientKey
		globalVerbose, globalInsecure, globalConfigFile = verbose, insecure, configFile
	})
}

var _ = Describe("Root command", func() {
	// Every spec here builds a root command, and newRootCmd() re-registers the
	// persistent flags against the package globals, resetting them all.
	BeforeEach(saveCtlGlobals)

	It("prints the release version for --version", func() {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetArgs([]string{"--version"})
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("openvox-ca-ctl version " + version.Version))
	})

	// --version is root-only (cobra registers it on the root's local flag
	// set), unlike the persistent global flags; the CLI reference documents
	// this, so pin it.
	It("rejects --version after a subcommand", func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"list", "--version"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("unknown flag: --version")))
	})

	// Positive half of the documented "global flags may be placed before or
	// after the subcommand name" contract (the negative half being that
	// --version may not). --help returns before PersistentPreRunE, keeping
	// the spec hermetic — no config loading or network.
	It("accepts a persistent flag after the subcommand", func() {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"list", "-v", "--help"})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(Succeed())
		flag := cmd.PersistentFlags().Lookup("verbose")
		Expect(flag).NotTo(BeNil())
		Expect(flag.Changed).To(BeTrue())
	})

	// -v must stay the shorthand for --verbose, mirroring the server binary
	// (where -v is --verbosity): cobra would otherwise claim it for the
	// synthesised --version flag, giving the two siblings opposite -v
	// semantics.
	It("keeps -v as the shorthand for --verbose", func() {
		cmd := newRootCmd()
		flag := cmd.PersistentFlags().ShorthandLookup("v")
		Expect(flag).NotTo(BeNil())
		Expect(flag.Name).To(Equal("verbose"))
	})
})

// The precedence chain documented in docs/operator-cli.md (CLI flag → env var
// → config file → built-in default) is only assembled in the root command's
// PersistentPreRunE. config_test.go exercises loadCtlConfig/applyCtlEnv
// directly and so never reaches the CLI-flag overlay; these specs run the
// whole chain, with the TLS-relevant --insecure and --ca-cert as subjects.
var _ = Describe("Global flag precedence", func() {
	// runProbe executes a no-op subcommand so PersistentPreRunE resolves the
	// configuration without any real subcommand touching storage or network.
	runProbeArgs := func(args ...string) {
		cmd := newRootCmd()
		cmd.AddCommand(&cobra.Command{
			Use:  "probe",
			RunE: func(*cobra.Command, []string) error { return nil },
		})
		cmd.SetArgs(append([]string{"probe"}, args...))
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		Expect(cmd.Execute()).To(Succeed())
	}
	runProbe := func(configFile string, args ...string) {
		runProbeArgs(append([]string{"--config", configFile}, args...)...)
	}

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
	})

	// Step 2 of the config-file resolution in docs/operator-cli.md. Every
	// other spec here passes --config, which outranks the variable, so these
	// run the probe without one. Each names one of two files in turn rather
	// than comparing set with unset: unset falls back to
	// /etc/puppet-ca/ctl.yaml, which is the host's to decide.
	DescribeTable("reads the config file named by OPENVOX_CA_CTL_CONFIG",
		func(pick int) {
			want := []string{"/from/first.pem", "/from/second.pem"}
			files := []string{
				writeTempCtlConfig("ca_cert: " + want[0] + "\n"),
				writeTempCtlConfig("ca_cert: " + want[1] + "\n"),
			}
			setCtlEnv("OPENVOX_CA_CTL_CONFIG", files[pick])

			runProbeArgs()

			Expect(globalCACert).To(Equal(want[pick]),
				"the CLI did not read the file OPENVOX_CA_CTL_CONFIG names")
		},
		Entry("naming the first file", 0),
		Entry("naming the second file", 1),
	)

	It("prefers an explicit --insecure over the env var and config file", func() {
		cfgFile := writeTempCtlConfig("insecure: true\n")
		setCtlEnv("OPENVOX_CA_CTL_INSECURE", "true")

		runProbe(cfgFile, "--insecure=false")

		Expect(globalInsecure).To(BeFalse(),
			"Insecure = true; want the explicit --insecure=false to beat the env var and config file")
	})

	It("prefers an explicit --ca-cert over the env var and config file", func() {
		cfgFile := writeTempCtlConfig("ca_cert: /from/file.pem\n")
		setCtlEnv("OPENVOX_CA_CTL_CA_CERT", "/from/env.pem")

		runProbe(cfgFile, "--ca-cert", "/from/cli.pem")

		Expect(globalCACert).To(Equal("/from/cli.pem"),
			"CACert = %q; want the explicit --ca-cert to beat the env var and config file", globalCACert)
	})

	// The documented route to --insecure when a config file already sets
	// ca_cert. It works only because an explicitly empty flag still counts as
	// Changed, so the overlay assigns the empty value instead of skipping it.
	It("lets an empty --ca-cert clear the config file value", func() {
		cfgFile := writeTempCtlConfig("ca_cert: /from/file.pem\n")
		setCtlEnv("OPENVOX_CA_CTL_CA_CERT", "/from/env.pem")

		runProbe(cfgFile, "--ca-cert=", "--insecure")

		Expect(globalCACert).To(BeEmpty(),
			"CACert = %q; want the empty --ca-cert to clear the config file and env values", globalCACert)
		Expect(globalInsecure).To(BeTrue())

		// Follow it through: with the trust anchor cleared, --insecure is now
		// the branch that runs, which is the whole point of the route.
		cfg, err := newTLSConfig(io.Discard)
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg.InsecureSkipVerify).To(BeTrue(),
			"InsecureSkipVerify = false; want the documented --ca-cert=\"\" route to reach --insecure")
	})

	// The pf.Changed() gate is what makes this work: without it, every unset
	// flag's zero value would clobber the env var and config file below.
	It("falls back to the env var when the flag is unset", func() {
		cfgFile := writeTempCtlConfig("insecure: false\nca_cert: /from/file.pem\n")
		setCtlEnv("OPENVOX_CA_CTL_INSECURE", "true")
		setCtlEnv("OPENVOX_CA_CTL_CA_CERT", "/from/env.pem")

		runProbe(cfgFile)

		Expect(globalInsecure).To(BeTrue(),
			"Insecure = false; want the env var to win when --insecure is unset")
		Expect(globalCACert).To(Equal("/from/env.pem"),
			"CACert = %q; want the env var to win when --ca-cert is unset", globalCACert)
	})

	// The remaining four pf.Changed overlays. --client-cert/--client-key are
	// the ones that matter: newTLSConfig rejects a half-resolved pair outright,
	// so an overlay guarding one on the other's Changed flag would break every
	// subcommand rather than quietly dropping mTLS.
	It("prefers the other explicit flags over the env var and config file", func() {
		cfgFile := writeTempCtlConfig(
			"server_url: https://from-file:8140\nclient_cert: /from/file.pem\nclient_key: /from/file-key.pem\nverbose: true\n")
		setCtlEnv("OPENVOX_CA_CTL_SERVER_URL", "https://from-env:8140")
		setCtlEnv("OPENVOX_CA_CTL_CLIENT_CERT", "/from/env.pem")
		setCtlEnv("OPENVOX_CA_CTL_CLIENT_KEY", "/from/env-key.pem")
		setCtlEnv("OPENVOX_CA_CTL_VERBOSE", "true")

		runProbe(cfgFile,
			"--server-url", "https://from-cli:8140",
			"--client-cert", "/from/cli.pem",
			"--client-key", "/from/cli-key.pem",
			"--verbose=false")

		Expect(globalServerURL).To(Equal("https://from-cli:8140"),
			"ServerURL = %q; want the explicit --server-url", globalServerURL)
		Expect(globalClientCert).To(Equal("/from/cli.pem"),
			"ClientCert = %q; want the explicit --client-cert", globalClientCert)
		Expect(globalClientKey).To(Equal("/from/cli-key.pem"),
			"ClientKey = %q; want the explicit --client-key", globalClientKey)
		Expect(globalVerbose).To(BeFalse(),
			"Verbose = true; want the explicit --verbose=false")
	})

	// The direction that matters most for security: an operator re-enabling
	// verification from the environment must beat a config file that disabled
	// it. applyCtlEnv assigns the parsed bool either way, and only this spec
	// covers the false direction end to end.
	It("lets the env var switch insecure back off over the config file", func() {
		cfgFile := writeTempCtlConfig("insecure: true\n")
		setCtlEnv("OPENVOX_CA_CTL_INSECURE", "false")

		runProbe(cfgFile)

		Expect(globalInsecure).To(BeFalse(),
			"Insecure = true; want OPENVOX_CA_CTL_INSECURE=false to beat the config file")
	})

	It("falls back to the config file when neither the flag nor the env var is set", func() {
		cfgFile := writeTempCtlConfig("insecure: true\nca_cert: /from/file.pem\n")

		runProbe(cfgFile)

		Expect(globalInsecure).To(BeTrue(),
			"Insecure = false; want the config file value")
		Expect(globalCACert).To(Equal("/from/file.pem"),
			"CACert = %q; want the config file value", globalCACert)
		Expect(globalServerURL).To(Equal("https://localhost:8140"),
			"ServerURL = %q; want the built-in default", globalServerURL)
	})
})

var _ = Describe("import subcommand key requirement", func() {
	It("points at openvox-ca import-ca-cert when no key file can exist", func() {
		// A provider-held key has no PEM blob to pass. Failing with cobra's
		// generic "required flag not set" would leave an operator looking for a
		// file that will never exist, so the error names the command that can
		// actually do the job.
		//
		// Driven through the root, which is where an operator meets it. That
		// also pins --private-key having been un-required: a MarkFlagRequired
		// would fail here before the handler that carries this advice runs.
		cmd := newRootCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs([]string{"import", "--cadir", GinkgoT().TempDir(), "--cert-bundle", "/dev/null"})
		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("openvox-ca import-ca-cert")))
	})
})
