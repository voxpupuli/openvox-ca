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
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// caOnDisk returns the CA certificate the cadir actually holds, and the raw
// PEM it was read from.
//
// Deliberately a second, independent route to the subject: the specs below
// compare setup's output against this, and if the expected value were
// assembled from --hostname the same way the code under test assembles it, no
// assertion over the pair could fail whatever setup printed.
func caOnDisk(caDir string) (*x509.Certificate, []byte) {
	GinkgoHelper()
	pemBytes, err := os.ReadFile(filepath.Join(caDir, "ca_crt.pem"))
	Expect(err).NotTo(HaveOccurred(), "reading the CA certificate")
	block, _ := pem.Decode(pemBytes)
	Expect(block).NotTo(BeNil(), "the CA certificate must be PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred(), "parsing the CA certificate")
	return cert, pemBytes
}

// seedExistingCA bootstraps a real CA into caDir under a subject of its own,
// unrelated to any --hostname a spec then passes to setup.
//
// ECDSA P-256 rather than the shipped RSA 4096 default: this fixture exists
// only to make setup's load path reachable, and the key algorithm has no
// bearing on which subject setup reports. The one spec that must exercise the
// bootstrap path drives setup itself, defaults and all.
func seedExistingCA(caDir, hostname string) {
	GinkgoHelper()
	seeded := ca.New(storage.New(caDir), ca.AutosignConfig{Mode: "off"}, hostname)
	seeded.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
	Expect(seeded.Init(context.Background())).To(Succeed(), "seeding an existing CA")
}

// `setup` calls CA.Init, which either bootstraps a new CA or loads one that is
// already there, and then reports success. It used to assemble that report out
// of the --hostname flag on both paths, so pointing setup at a cadir that
// already held a CA printed "CA initialized" and a CN that existed nowhere:
// the truthful line ("Loaded existing CA") went to stderr as a log record and
// the false one to stdout, so the ordinary capture kept the wrong one.
//
// Two separate claims were wrong, and these specs pin both: the value, which
// must come off the certificate rather than the flag, and the verb, which must
// not assert an initialisation that did not happen.
var _ = Describe("setup subcommand output", func() {
	var cfg string

	BeforeEach(func() {
		saveCtlGlobals()
		clearCtlEnv()
		// The --config flag is what actually isolates these specs, and it is
		// not interchangeable with clearCtlEnv above. `setup` reaches
		// PersistentPreRunE like every other subcommand, which resolves a
		// config file and fails the command outright if it cannot be parsed;
		// on a machine that really runs openvox-ca that resolves to the host's
		// own /etc/puppet-ca/ctl.yaml. clearCtlEnv does not cover this, because
		// PUPPET_CA_CTL_CONFIG is deliberately absent from ctlEnvVars -- that
		// list is the vars applyCtlEnv reads, and the config path is resolved
		// before them. Only an explicit --config outranks both the environment
		// variable and the host file.
		//
		// clearCtlEnv and saveCtlGlobals are here for the reason the sibling
		// spec files have them -- no spec should leave the package globals
		// holding values the next one inherits -- not because they close the
		// hole above.
		cfg = writeTempCtlConfig("")
	})

	// runSetup drives the subcommand through the root, as an operator does.
	runSetup := func(args ...string) string {
		GinkgoHelper()
		out, err := captureStdout(append([]string{"setup", "--config", cfg}, args...))
		Expect(err).NotTo(HaveOccurred(), "setup")
		return out
	}

	It("names the subject of the CA it has just created", func() {
		// The bootstrap path, and the control for the load-path specs below:
		// here the CN genuinely is derived from --hostname, so a fix that
		// simply stopped printing anything useful would fail this.
		caDir := GinkgoT().TempDir()

		out := runSetup("--cadir", caDir, "--hostname", "bootstrapped.example.com")

		cert, _ := caOnDisk(caDir)
		// The "Puppet CA: " prefix is minted into the subject and is Puppet
		// compatibility surface. Asserted here so that reporting the real
		// subject cannot quietly become an opportunity to restyle it.
		Expect(cert.Subject.CommonName).To(Equal("Puppet CA: bootstrapped.example.com"))
		Expect(out).To(ContainSubstring(caDir))

		// strconv.Quote, not the bare CN: both branches print through %q, and
		// AGENTS.md and the CodeQL exclusion both now record that setup's CN
		// line is pinned by a spec. A ContainSubstring of the bare name is
		// satisfied by the unquoted rendering too, so it would have left that
		// claim true of only the load path -- and the CodeQL exclusion would
		// go on suppressing alerts here after a later change dropped the %q.
		Expect(out).To(ContainSubstring(strconv.Quote(cert.Subject.CommonName)),
			"the subject must appear, escaped, on this path too:\n%s", out)

		// The verb, pinned on this path as well as on the load path. Without
		// the pair below the CN and the cadir are all that is asserted, and
		// both appear in the other branch's line too -- so collapsing the two
		// branches into an unconditional "Existing CA found" would satisfy
		// every other assertion in this file.
		Expect(out).To(ContainSubstring("CA initialized"),
			"the bootstrap path must report an initialisation:\n%s", out)
		Expect(out).NotTo(ContainSubstring("Existing CA found"),
			"nothing was found; this CA was just created:\n%s", out)
	})

	Context("against a cadir that already holds a CA", func() {
		const (
			seededHost = "already-here.example.com"
			flagHost   = "totally-different.example.com"
		)

		var (
			caDir  string
			before []byte
			out    string
		)

		BeforeEach(func() {
			caDir = GinkgoT().TempDir()
			seedExistingCA(caDir, seededHost)
			_, before = caOnDisk(caDir)

			out = runSetup("--cadir", caDir, "--hostname", flagHost)
		})

		It("reports the subject it loaded, not the --hostname it was passed", func() {
			cert, _ := caOnDisk(caDir)

			Expect(out).To(ContainSubstring(cert.Subject.CommonName),
				"the CN printed must be the one on the certificate:\n%s", out)
			Expect(out).NotTo(ContainSubstring(flagHost),
				"--hostname has no effect on the load path, so echoing it names a CA that exists nowhere:\n%s", out)
			// Both branches print absDir through the same argument, so covering
			// it on one and not the other leaves a mutation that swaps the path
			// on this branch alone uncaught.
			Expect(out).To(ContainSubstring(caDir),
				"the cadir printed must be the one that was addressed:\n%s", out)
		})

		It("does not claim to have initialised a CA it only loaded", func() {
			Expect(out).NotTo(ContainSubstring("CA initialized"),
				"nothing was initialised:\n%s", out)
			Expect(out).To(ContainSubstring("Existing CA found"),
				"the load path must say what actually happened:\n%s", out)
		})

		It("leaves the existing CA untouched", func() {
			// The other way to make the message true would be to re-bootstrap
			// so the CN matches the flag, which would retire the CA and
			// invalidate every certificate issued under it. Pin the certificate
			// bytes so a fix cannot take that route.
			_, after := caOnDisk(caDir)
			Expect(after).To(Equal(before), "setup must not replace an existing CA")
		})
	})

	It("refuses when it cannot tell whether a CA is already there", func() {
		// The probe's error branch. It decides which of the two success lines
		// is printed, so a failure it swallowed would report the wrong one --
		// and reporting the wrong one is the whole of #353.
		//
		// An unreadable cadir, not a cadir that is a regular file: the
		// instance lock is taken BEFORE this probe and creates a `locks`
		// subdirectory, so a file fails at `creating same-host lock directory`
		// and never reaches HasCACert. That spec would pass on an error raised
		// two statements earlier. An unreadable directory only downgrades the
		// lock to a warning, so it is the fixture that actually lands here.
		caDir := GinkgoT().TempDir()
		Expect(os.Chmod(caDir, 0000)).To(Succeed())
		// Restore before Ginkgo's own cleanup, which cannot remove a 0000 dir.
		DeferCleanup(func() { _ = os.Chmod(caDir, 0o755) })

		if _, err := os.ReadDir(caDir); err == nil {
			Skip("this user can read a 0000 directory (running as root), so the probe cannot be made to fail")
		}

		_, err := captureStdout([]string{"setup", "--config", cfg, "--cadir", caDir, "--hostname", "unused.example.com"})

		Expect(err).To(MatchError(ContainSubstring("checking for an existing CA in")),
			"the probe's failure must be reported as itself, not swallowed into a success line")
		Expect(err).To(MatchError(ContainSubstring(caDir)))

		// Readable again before asserting on the contents: BeAnExistingFile
		// cannot stat inside a 0000 directory, so it reports "permission
		// denied" rather than "absent" and would fail whatever setup did.
		Expect(os.Chmod(caDir, 0o755)).To(Succeed())
		Expect(filepath.Join(caDir, "ca_crt.pem")).NotTo(BeAnExistingFile(),
			"a refused setup must not have bootstrapped a CA")
	})

	It("quotes a subject read off disk so it cannot forge a line", func() {
		// On the load path the printed value comes from a certificate that was
		// found in the cadir rather than from anything this process chose, so
		// AGENTS.md's escaping rule applies to it: an unescaped control
		// character in the subject would let the certificate write its own
		// line of operator-facing output.
		const forged = "evil\nCA initialized in /somewhere-else"
		caDir := GinkgoT().TempDir()
		seedExistingCA(caDir, forged)

		cert, _ := caOnDisk(caDir)
		Expect(cert.Subject.CommonName).To(ContainSubstring("\n"),
			"the fixture must actually carry the control character, or this spec asserts nothing")

		out := runSetup("--cadir", caDir, "--hostname", "unused.example.com")

		Expect(out).To(ContainSubstring(strconv.Quote(cert.Subject.CommonName)),
			"the subject must appear, escaped:\n%s", out)
		Expect(out).NotTo(ContainSubstring("\nCA initialized"),
			"a newline in the subject must not start a line of its own:\n%s", out)
	})
})
