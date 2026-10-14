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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// errStubbedFork is what the stubbed fork returns, so that "the command got as
// far as forking" is distinguishable from "the command was refused".
var errStubbedFork = errors.New("stubbed fork")

// realServerChild is the pskChildEnv role under which every process in the
// tree -- the launcher this spec starts and the signer and frontend it
// re-executes -- runs the real root command, rather than one of the fd-contract
// or environment-dumping stand-ins the other launcher specs use. Those can
// show what a child is handed; only real children can show what it then does.
const realServerChild = "real-server"

// runRealServerChild runs the server exactly as an operator would, with no
// arguments: spawnChild re-executes with os.Args[1:], which is empty here, so
// the whole configuration travels as OPENVOX_CA_* in the environment, the way an
// environment-configured deployment supplies it -- and through frontendEnv for
// the frontend, which is the point.
//
// The guard mirrors launcher-env's. A process with no role is the launcher, and
// one that finds a launcher already above it refuses instead of starting a
// second, each of which would re-execute this test binary in turn.
func runRealServerChild() int {
	if os.Getenv("OPENVOX_CA_ROLE") == "" {
		if os.Getenv(launcherStartedEnv) != "" {
			fmt.Fprintln(os.Stderr, "real-server child: a launcher is already running above this process")
			return 2
		}
		if err := os.Setenv(launcherStartedEnv, "1"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	cmd := newRootCmd()
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// A missing passphrase source refuses startup. These specs are about *where*
// that refusal is raised, which is the whole of its value: raised inside
// CA.Init it lands in the signer child, and under --daemon that child's stderr
// is /dev/null while the parent has already printed "started in background"
// and exited 0. The operator is told the CA came up, and it never does.
var _ = Describe("the server's own startup, on a missing key passphrase", func() {
	// Same reasoning as the key-permission startup specs: these drive whole
	// commands, so OPENVOX_CA_* from the developer's environment would change
	// what they assert without failing them, and an unpinned config file means
	// a host /etc/openvox-ca/config.yaml decides whether they refuse at all.
	BeforeEach(func() {
		clearServerEnv()
		empty := filepath.Join(GinkgoT().TempDir(), "empty-config.yaml")
		Expect(os.WriteFile(empty, []byte("{}\n"), 0o600)).To(Succeed(), "pin an empty config")
		GinkgoT().Setenv("OPENVOX_CA_CONFIG", empty)
	})

	// encryptedCADir bootstraps a CA whose stored key is encrypted, with the
	// passphrase in a file the caller can then take away. Taking it away is
	// what the specs do: they are about the store that already exists and the
	// configuration that no longer names a passphrase for it.
	encryptedCADir := func() string {
		GinkgoHelper()
		caDir := GinkgoT().TempDir()
		ppFile := filepath.Join(GinkgoT().TempDir(), "passphrase")
		Expect(os.WriteFile(ppFile, []byte("spec-passphrase\n"), 0o600)).To(Succeed())

		store := storage.New(caDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.EncryptCAKey = true
		myCA.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: ppFile}
		Expect(myCA.Init(context.Background())).To(Succeed())

		// The fixture is worthless if it did not actually encrypt: a plaintext
		// key needs no passphrase, so every assertion below would pass on a
		// server that simply started.
		keyPEM, err := os.ReadFile(caKeyPathIn(caDir))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(keyPEM)).To(ContainSubstring("ENCRYPTED PRIVATE KEY"),
			"the fixture must hold an encrypted key, or these specs prove nothing")
		return caDir
	}

	// stubFork replaces the fork and reports whether it was reached. Under
	// `go test` the real child is this test binary re-executed with the test
	// flags, so a regression that reaches the fork would run the suite inside
	// itself.
	//
	// The stub fails rather than succeeding, which is not incidental: on
	// success the caller reads c.Process.Pid to report the child, and a stub
	// that never started a process leaves that nil. errStubbedFork is then the
	// signal that the fork *was* reached, which is what the pass-through specs
	// below assert.
	stubFork := func() *bool {
		GinkgoHelper()
		forked := false
		orig := startDaemonChild
		startDaemonChild = func(*exec.Cmd) error { forked = true; return errStubbedFork }
		DeferCleanup(func() { startDaemonChild = orig })
		return &forked
	}

	It("refuses under --daemon instead of reporting success", func() {
		// The finding this spec exists for. Before the fix the parent forked,
		// printed a PID and returned nil, and the child died on the refusal
		// with nowhere to print it.
		//
		// The bootstrap case, where no key exists yet and encrypt_ca_key is
		// what calls for a passphrase. Its sibling below covers the other
		// condition; between them the two reasons a passphrase is needed are
		// each driven once, which a pair that both used an encrypted store
		// would not do.
		caDir := GinkgoT().TempDir()
		forked := stubFork()

		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{
			"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon",
			"--encrypt-ca-key",
		})

		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("no passphrase source is configured")))
		Expect(err).To(MatchError(ContainSubstring("encrypt_ca_key is set")))
		Expect(*forked).To(BeFalse(), "the refusal has to come before the fork")
		Expect(out.String()).NotTo(ContainSubstring("started in background"),
			"reporting a background start for a process that was refused is the failure")

		// And nothing was written on the way to refusing. The permission
		// preflight's placement argument is that a check after CA.Init would
		// mint a key into a store it then declines to serve; the same holds
		// here, and nothing else in this file would notice if it stopped.
		Expect(caKeyPathIn(caDir)).NotTo(BeAnExistingFile(),
			"the refusal must come before a key is written")
	})

	// The case a check written as "if cfg.EncryptCAKey" would not cover, and
	// the reason the preflight reads the stored key instead of trusting the
	// setting. encrypt_ca_key is *off* here; the key on disk is encrypted
	// anyway, so loadCAKeyFromDisk still has to decrypt it.
	It("refuses when the stored key is encrypted and encrypt_ca_key is off", func() {
		caDir := encryptedCADir()
		forked := stubFork()

		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon"})

		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("no passphrase source is configured")))
		// And it names the condition the operator actually has. Telling them to
		// look at encrypt_ca_key here would point at a setting they have not
		// set, which is what the message used to do.
		Expect(err).To(MatchError(ContainSubstring("the CA key in the store is encrypted")))
		Expect(err).NotTo(MatchError(ContainSubstring("encrypt_ca_key is set")),
			"encrypt_ca_key is not set in this spec; saying so would be false")
		Expect(*forked).To(BeFalse())
	})

	// The must-fail twin for the two above: the preflight has to refuse the
	// cases that genuinely cannot proceed and *only* those. A plaintext stored
	// key needs no passphrase even with encrypt_ca_key set, because nothing
	// re-encrypts a key that already exists -- so a preflight that refused on
	// the setting alone would stop a CA that works today.
	It("does not refuse a plaintext stored key, even with encrypt_ca_key set", func() {
		caDir := GinkgoT().TempDir()
		bootstrapCAInDir(caDir, "puppet.example.com")

		keyPEM, err := os.ReadFile(caKeyPathIn(caDir))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(keyPEM)).NotTo(ContainSubstring("ENCRYPTED PRIVATE KEY"),
			"this fixture's point is that the stored key is plaintext")

		forked := stubFork()

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{
			"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon",
			"--encrypt-ca-key",
		})

		// Reaching the fork is the pass condition here: it means the preflight
		// let it through. The error is the stub's own, so it is evidence of
		// having got that far rather than of a refusal.
		Expect(cmd.Execute()).To(MatchError(errStubbedFork))
		Expect(*forked).To(BeTrue(), "a CA that can start must not be refused")
	})

	// Which roles owe a passphrase, and which do not. The frontend never
	// decrypts the CA key -- it proxies every signature to the signer over IPC,
	// and roleMayReachCAKey refuses it a key provider for that reason -- so
	// demanding a passphrase from it refuses a configuration that is not merely
	// valid but preferable: the secret reaching only the process that uses it.
	//
	// Found by integration against #477, which removes the passphrase variable
	// from the frontend child's environment. With an unconditional check the
	// frontend refused to start and took the whole CA with it, on a passphrase
	// supplied only through the environment. Neither branch is wrong alone and
	// the two never touch the same lines, so the merge was clean and the server
	// was broken; only running it showed that.
	DescribeTable("asks for a passphrase only from a role that uses the key",
		func(role string, wantRefusal bool) {
			caDir := encryptedCADir()

			_, err := preflightKeyMaterial(context.Background(), &serverConfig{CADir: caDir}, role)

			if wantRefusal {
				Expect(err).To(MatchError(ContainSubstring("no passphrase source is configured")),
					"a role that loads the key cannot start without one")
				return
			}
			Expect(err).NotTo(HaveOccurred(),
				"a role that never decrypts the key must not be asked for the passphrase")
		},
		// The launcher forks the children and, with --single-process, is the
		// process that holds the key itself.
		Entry("the launcher or single-process role", "", true),
		Entry("the signer, which loads the key", "signer", true),
		Entry("the frontend, which never does", "frontend", false),
	)

	// A CA whose key lives at a provider never resolves a passphrase, so the
	// preflight must not ask for one. This configuration starts today, and the
	// first version of the preflight refused it, telling the operator to supply
	// a passphrase CA.Init would never use. The no-provider entries are the
	// must-fail twin: the same settings without a provider still refuse, so the
	// pass above is the provider's doing and not a preflight that stopped
	// checking.
	DescribeTable("asks for no passphrase when the key lives at a provider",
		func(provider string, storeEncrypted, wantRefusal bool) {
			dir := GinkgoT().TempDir()
			store := storage.New(dir)
			if storeEncrypted {
				// A local encrypted PEM left behind from before the move to a
				// provider. CA.Init ignores it under a provider, so the
				// preflight must too.
				ppFile := filepath.Join(GinkgoT().TempDir(), "passphrase")
				Expect(os.WriteFile(ppFile, []byte("spec-passphrase\n"), 0o600)).To(Succeed())
				seed := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
				seed.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
				seed.EncryptCAKey = true
				seed.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: ppFile}
				Expect(seed.Init(context.Background())).To(Succeed())
			}

			cfg := &serverConfig{CADir: dir, EncryptCAKey: true}
			cfg.CAKeyProvider = provider
			err := refuseOnMissingPassphrase(context.Background(), &caRuntime{Store: store}, cfg)

			if wantRefusal {
				Expect(err).To(MatchError(ContainSubstring("no passphrase source is configured")),
					"without a provider, encryption with no passphrase source cannot start")
				return
			}
			Expect(err).NotTo(HaveOccurred(),
				"a key at a provider has no local PEM to encrypt or decrypt")
		},
		Entry("openbao, nothing stored locally", "openbao", false, false),
		Entry("openbao, a stale encrypted PEM left behind", "openbao", true, false),
		Entry("no provider, nothing stored: still refused", "", false, true),
		Entry("explicit file provider, nothing stored: still refused", "file", false, true),
	)

	// What the preflight does when the store opened but cannot then say whether
	// it holds a CA key, or cannot hand it over. It falls back to the setting,
	// deliberately and as documented on refuseOnMissingPassphrase: the store
	// opened a moment earlier, so a read failing now is a transient fault rather
	// than a missing passphrase, and refusing startup on it would invent an
	// outage. CA.Init then reaches the same blob and reports the real error.
	//
	// Pinned rather than merely described, because the trade has a cost the
	// table makes visible: with encrypt_ca_key off and a read failing, an
	// encrypted stored key is invisible here, so this check passes and the
	// passphrase refusal -- if the read recovers -- is raised by Init past the
	// fork. Whether to propagate the read error instead is a code change and is
	// recorded as an open question on #371, not settled here. Either way, a
	// change to this behaviour should have to change a spec.
	DescribeTable("falls back to the setting when the store cannot be read",
		func(failOn string, encrypt, wantRefusal bool) {
			dir := GinkgoT().TempDir()
			base := storage.NewFilesystemBackend(dir)
			rt := &caRuntime{Store: storage.NewWithBackend(&failingKeyReads{Backend: base, failOn: failOn}, dir)}

			err := refuseOnMissingPassphrase(context.Background(), rt, &serverConfig{CADir: dir, EncryptCAKey: encrypt})

			if wantRefusal {
				Expect(err).To(MatchError(ContainSubstring("no passphrase source is configured")),
					"the setting says a passphrase is needed, and the store could not say otherwise")
				return
			}
			Expect(err).NotTo(HaveOccurred(),
				"a read failure is not taken as evidence that a passphrase is needed")
		},
		Entry("Exists fails, encrypt_ca_key on", "exists", true, true),
		Entry("Exists fails, encrypt_ca_key off", "exists", false, false),
		Entry("Get fails, encrypt_ca_key on", "get", true, true),
		Entry("Get fails, encrypt_ca_key off", "get", false, false),
	)

	// Without --daemon the refusal always had somewhere to go, so this spec is
	// not about delivery; it is the one that would still fail if the refusal
	// were moved back behind the fork for the non-daemon path too.
	It("refuses before the launcher forks, without --daemon", func() {
		caDir := encryptedCADir()

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--cadir", caDir, "--host", "127.0.0.1", "--port", "0"})

		// Bounded for the same reason the instance-lock and permission specs
		// are: if the refusal regressed, the next thing this command does is
		// fork the launcher and supervise it for ever.
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()

		var err error
		Eventually(done, "30s").Should(Receive(&err),
			"the refusal must come before the launcher forks; a hang here means it does not")
		Expect(err).To(MatchError(ContainSubstring("no passphrase source is configured")))
	})

	It("starts when the configured passphrase file is restored", func() {
		// The remedy the refusal names has to work, which an assertion on the
		// wording cannot show. Same discipline as the generated-file remedy in
		// internal/ca's specs.
		caDir := GinkgoT().TempDir()
		ppFile := filepath.Join(GinkgoT().TempDir(), "passphrase")
		Expect(os.WriteFile(ppFile, []byte("spec-passphrase\n"), 0o600)).To(Succeed())

		store := storage.New(caDir)
		myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, "puppet.example.com")
		myCA.CAKeyConfig = ca.KeyConfig{Algo: ca.KeyAlgoECDSA, Size: 256}
		myCA.EncryptCAKey = true
		myCA.KeyPassphrase = ca.KeyPassphraseConfig{PassphraseFile: ppFile}
		Expect(myCA.Init(context.Background())).To(Succeed())

		forked := stubFork()

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{
			"--cadir", caDir, "--host", "127.0.0.1", "--port", "0", "--daemon",
			"--ca-key-passphrase-file", ppFile,
		})

		Expect(cmd.Execute()).To(MatchError(errStubbedFork))
		Expect(*forked).To(BeTrue(), "the named remedy has to let the CA start")
	})
})

// failingKeyReads wraps a backend and fails the CA key reads the passphrase
// preflight makes: Exists, which HasCAKey reaches, or Get, which GetCAKey does.
// For "get", Exists reports the key present so that the read actually happens.
// Every other key passes through, so the store is otherwise healthy -- the state
// the fallback is about is a store that opened and then could not answer.
type failingKeyReads struct {
	storage.Backend
	failOn string
}

var errStubbedRead = errors.New("stubbed store read failure")

func (f *failingKeyReads) Exists(ctx context.Context, key string) (bool, error) {
	if key == storage.KeyCAKey {
		if f.failOn == "exists" {
			return false, errStubbedRead
		}
		return true, nil
	}
	return f.Backend.Exists(ctx, key)
}

func (f *failingKeyReads) Get(ctx context.Context, key string) ([]byte, error) {
	if key == storage.KeyCAKey && f.failOn == "get" {
		return nil, errStubbedRead
	}
	return f.Backend.Get(ctx, key)
}

// The cross-PR defect between #371 and #477, driven end to end. #477 withholds
// the passphrase from the frontend child; the pre-fork passphrase check runs in
// every role. Before the role gate, an encrypted CA whose passphrase came only
// from the environment therefore had a frontend that refused to start, and the
// launcher took the whole CA down behind it. Every unit spec passed throughout:
// the role table drives preflightKeyMaterial directly, and #477's launcher
// spec forks stand-in children that report their environment rather than run.
// The integration build found it by running the server.
//
// So this runs the real launcher with a real signer and a real frontend, and
// asserts the one thing the defect broke: the frontend comes up.
var _ = Describe("the real launcher, with the passphrase only in the environment", func() {
	It("brings the frontend up when only the signer receives the passphrase", func() {
		dir := GinkgoT().TempDir()
		cadir := filepath.Join(dir, "cadir")
		Expect(os.MkdirAll(cadir, 0o750)).To(Succeed())
		emptyConfig := filepath.Join(dir, "empty.yaml")
		Expect(os.WriteFile(emptyConfig, []byte("{}\n"), 0o600)).To(Succeed())

		l, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		port := l.Addr().(*net.TCPAddr).Port
		Expect(l.Close()).To(Succeed())

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		DeferCleanup(cancel)

		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, os.Args[0])
		// The parent's environment, less anything that would make the launcher
		// think it was already a role, already under a launcher, or configured
		// from a file on this host.
		cmd.Env = append(filterEnv(os.Environ(), append(append([]string{}, internalEnvKeys...),
			launcherStartedEnv, ca.DefaultPassphraseEnvVar, "OPENVOX_CA_CONFIG", "OPENVOX_CA_KEY_PASSPHRASE_FILE")...),
			pskChildEnv+"="+realServerChild,
			"OPENVOX_CA_CONFIG="+emptyConfig,
			"OPENVOX_CA_CADIR="+cadir,
			"OPENVOX_CA_HOST=127.0.0.1",
			"OPENVOX_CA_PORT="+strconv.Itoa(port),
			"OPENVOX_CA_ENCRYPT_CA_KEY=true",
			// The only passphrase source. #477 strips it from the frontend.
			ca.DefaultPassphraseEnvVar+"=end-to-end-passphrase",
		)
		cmd.Stdout = &out
		cmd.Stderr = &out
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

		// Up means the frontend's listener accepts. The launcher exiting first
		// is the defect, and ends the wait at once with what it printed rather
		// than running out the clock.
		Eventually(func() error {
			select {
			case <-done:
				return StopTrying(fmt.Sprintf(
					"the launcher exited (%v) before the frontend came up; output:\n%s", waitErr, out.String()))
			default:
			}
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 500*time.Millisecond)
			if err != nil {
				return err
			}
			return c.Close()
		}, 90*time.Second, 250*time.Millisecond).Should(Succeed(),
			"the frontend never started listening; launcher output:\n%s", &out)

		// And the signer really did use the passphrase from the environment:
		// the key it bootstrapped is encrypted. Without this a server that had
		// silently started without encryption would pass the check above.
		keyPEM, err := os.ReadFile(caKeyPathIn(cadir))
		Expect(err).NotTo(HaveOccurred(), "the signer must have bootstrapped a CA key")
		Expect(string(keyPEM)).To(ContainSubstring("ENCRYPTED PRIVATE KEY"),
			"the key the signer wrote must be encrypted with the environment's passphrase")
	})
})
