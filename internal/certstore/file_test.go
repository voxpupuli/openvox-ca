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

package certstore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/certstore"
)

var _ = Describe("FileStore", func() {
	var (
		ctx context.Context
		dir string
		cfg certstore.FilesConfig
		src stubCA
	)

	BeforeEach(func() {
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		cfg = certstore.FilesConfig{
			Cert: filepath.Join(dir, "cert.pem"),
			Key:  filepath.Join(dir, "key.pem"),
			CA:   filepath.Join(dir, "ca.pem"),
		}
		src = stubCA{pem: []byte("CA-CHAIN-PEM")}
	})

	store := func() *certstore.FileStore { return certstore.NewFileStore(cfg, src) }

	modeOf := func(path string) os.FileMode {
		GinkgoHelper()
		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		return info.Mode().Perm()
	}

	Describe("Load", func() {
		It("reports absent files as absent material rather than an error", func() {
			certPEM, keyPEM, err := store().Load(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).To(BeEmpty())
			Expect(keyPEM).To(BeEmpty())
		})

		It("reads back what Save wrote", func() {
			Expect(store().Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			certPEM, keyPEM, err := store().Load(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).To(Equal([]byte("CERT")))
			Expect(keyPEM).To(Equal([]byte("KEY")))
		})

		It("reports a certificate whose key is missing, so the decision can replace it", func() {
			Expect(os.WriteFile(cfg.Cert, []byte("CERT"), 0o644)).To(Succeed())

			certPEM, keyPEM, err := store().Load(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(certPEM).To(Equal([]byte("CERT")))
			Expect(keyPEM).To(BeEmpty())
		})

		// Absence is an input to the decision; a read failure is not. A store
		// that reported "unreadable" as "absent" would reissue on every pass
		// for as long as the filesystem was unhappy.
		//
		// Both reads, because they are two checks and only one of them was
		// witnessed. Load reads the certificate first, so the certificate's
		// arm is reached whichever path is broken, and the key's error check
		// could have been deleted with the suite staying green -- leaving an
		// unreadable key reported as absent, which is exactly the
		// reissue-every-pass loop above. The key's arm is reached here because
		// an absent certificate is not an error: the pass gets past the first
		// read and fails on the second.
		DescribeTable("fails on a read error that is not absence",
			func(pathOf func() string) {
				// A directory where a file is expected: os.ReadFile fails
				// with EISDIR, which is not fs.ErrNotExist.
				path := pathOf()
				Expect(os.Mkdir(path, 0o755)).To(Succeed())

				_, _, err := store().Load(ctx)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(ContainSubstring(path)),
					"the error has to name the unreadable path, or an operator "+
						"has two files to choose between")
			},
			Entry("the certificate", func() string { return cfg.Cert }),
			Entry("the key", func() string { return cfg.Key }),
		)
	})

	Describe("Save", func() {
		It("writes the key readable only by its owner, and the public material world-readable", func() {
			Expect(store().Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			Expect(modeOf(cfg.Key)).To(Equal(os.FileMode(0o600)))
			Expect(modeOf(cfg.Cert)).To(Equal(os.FileMode(0o644)))
			Expect(modeOf(cfg.CA)).To(Equal(os.FileMode(0o644)))
		})

		It("writes the CA chain when one is configured", func() {
			Expect(store().Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())

			Expect(os.ReadFile(cfg.CA)).To(Equal([]byte("CA-CHAIN-PEM")))
		})

		// An optional chain, and optional means never read. A component that
		// already trusts this CA by some other route should not have its
		// renewal fail because the chain could not be fetched.
		It("neither writes nor reads a chain when no path is configured", func() {
			cfg.CA = ""
			src = stubCA{err: errors.New("the chain must not be read here")}

			Expect(store().Save(ctx, []byte("CERT"), []byte("KEY"))).To(Succeed())
			Expect(os.ReadFile(cfg.Cert)).To(Equal([]byte("CERT")))
		})

		It("writes nothing when a configured CA chain cannot be read", func() {
			src = stubCA{err: errors.New("storage is down")}

			err := store().Save(ctx, []byte("CERT"), []byte("KEY"))
			Expect(err).To(MatchError(ContainSubstring("storage is down")))

			Expect(cfg.Cert).NotTo(BeAnExistingFile())
			Expect(cfg.Key).NotTo(BeAnExistingFile())
		})

		// The refusal an erroring chain read does not reach. A source that
		// returns no error and no bytes is a different failure from one that
		// errors, and the SecretStore twin of this guard has had a spec since
		// it was written -- an asymmetry that left this one deletable with the
		// suite green.
		It("refuses an empty CA chain, leaving what was there", func() {
			Expect(os.WriteFile(cfg.CA, []byte("PREVIOUS-CHAIN"), 0o644)).To(Succeed())
			src = stubCA{pem: []byte{}}

			err := store().Save(ctx, []byte("CERT"), []byte("KEY"))
			Expect(err).To(MatchError(ContainSubstring("empty CA certificate chain")))
			Expect(err).To(MatchError(ContainSubstring(cfg.CA)))

			// The read happens before anything is written, so the previous
			// chain stands and no half-written pair is left behind.
			Expect(os.ReadFile(cfg.CA)).To(Equal([]byte("PREVIOUS-CHAIN")))
			Expect(cfg.Cert).NotTo(BeAnExistingFile())
			Expect(cfg.Key).NotTo(BeAnExistingFile())
		})

		It("replaces material already at those paths", func() {
			Expect(os.WriteFile(cfg.Cert, []byte("OLD"), 0o644)).To(Succeed())
			// Seeded WIDE, and chmod'd explicitly past the umask, so the mode
			// assertion below can only pass if the replacement path narrows it.
			// This fixture used to write the old key at 0600 -- the mode it then
			// asserted -- so a replacement that preserved the old file's bits,
			// or skipped the chmod and inherited them, satisfied it. The spec
			// was placing the state it was there to check.
			Expect(os.WriteFile(cfg.Key, []byte("OLD-KEY"), 0o644)).To(Succeed())
			Expect(os.Chmod(cfg.Key, 0o644)).To(Succeed())
			Expect(modeOf(cfg.Key)).To(Equal(os.FileMode(0o644)),
				"precondition: the old key must start wider than 0600, or the "+
					"assertion after Save proves nothing")

			Expect(store().Save(ctx, []byte("NEW"), []byte("NEW-KEY"))).To(Succeed())
			Expect(os.ReadFile(cfg.Cert)).To(Equal([]byte("NEW")))
			// The key too, which this spec set up and then did not check. A
			// certificate replaced beside a stale key is the one outcome that
			// fails every handshake while looking like a successful write, and
			// it is the half a "replaces material" claim most needs to cover.
			Expect(os.ReadFile(cfg.Key)).To(Equal([]byte("NEW-KEY")))
			// And the mode, because replacement goes through a rename: a key
			// that arrived 0644 because the replacement path skipped the chmod
			// would pass every content assertion here.
			Expect(modeOf(cfg.Key)).To(Equal(os.FileMode(0o600)))
		})
	})

	Describe("the directory it will not create", func() {
		// A private key's directory is a permissions decision, and the safe
		// guess and the useful one are not the same: 0700 locks out the very
		// component the certificate is for, and anything wider exposes the key
		// by default. So the store names the directory instead.
		// The other arm of the same check: the path exists and is not a
		// directory, which is what a mistyped store path usually produces --
		// `cert: /etc/openvox/ca.pem/cert.pem` where ca.pem is a file. Without
		// this the branch could be deleted and the refusal above would still
		// pass, reporting a missing directory for a path that is present.
		It("fails when the directory is a file, and says which it is", func() {
			notADir := filepath.Join(dir, "is-a-file")
			Expect(os.WriteFile(notADir, []byte("PEM"), 0o644)).To(Succeed())
			cfg = certstore.FilesConfig{
				Cert: filepath.Join(notADir, "cert.pem"),
				Key:  filepath.Join(dir, "key.pem"),
			}

			err := store().Save(ctx, []byte("CERT"), []byte("KEY"))
			Expect(err).To(MatchError(ContainSubstring("is not a directory")))
			Expect(err).To(MatchError(ContainSubstring(notADir)))
			Expect(cfg.Key).NotTo(BeAnExistingFile())
		})

		// The third arm: os.Stat fails for a reason that is neither "absent"
		// nor "present but not a directory". Reached here by putting a regular
		// file part-way along the path, so the stat of the directory BELOW it
		// returns ENOTDIR -- which is not fs.ErrNotExist, so it falls through
		// the first branch to the generic one.
		//
		// ENOTDIR rather than a mode-0000 parent, deliberately: an
		// unreadable-directory fixture passes as root, and CI runs containers
		// as root, so that version of this spec would quietly stop testing
		// anything in the one place it most needs to run.
		It("reports a stat failure that is neither absent nor a file", func() {
			blocker := filepath.Join(dir, "blocker")
			Expect(os.WriteFile(blocker, []byte("PEM"), 0o644)).To(Succeed())
			buried := filepath.Join(blocker, "below")
			cfg = certstore.FilesConfig{
				Cert: filepath.Join(buried, "cert.pem"),
				Key:  filepath.Join(dir, "key.pem"),
			}

			err := store().Save(ctx, []byte("CERT"), []byte("KEY"))

			Expect(err).To(MatchError(ContainSubstring("checking the directory for")),
				"a stat failure that is not ErrNotExist must reach the generic arm, "+
					"not be reported as a missing directory")
			Expect(err).NotTo(MatchError(ContainSubstring("does not exist: create")))
			Expect(cfg.Key).NotTo(BeAnExistingFile(),
				"nothing is written when the check refuses")
		})

		It("fails naming the directory, before writing anything", func() {
			missing := filepath.Join(dir, "does-not-exist")
			cfg = certstore.FilesConfig{
				Cert: filepath.Join(missing, "cert.pem"),
				Key:  filepath.Join(dir, "key.pem"),
			}

			err := store().Save(ctx, []byte("CERT"), []byte("KEY"))
			Expect(err).To(MatchError(ContainSubstring(missing)))
			Expect(err).To(MatchError(ContainSubstring("private key")))

			// Checked before the first write, not discovered at the second: a
			// key that landed beside a certificate that did not is a worse
			// state to leave behind than a pass that wrote nothing.
			Expect(cfg.Key).NotTo(BeAnExistingFile())
		})
	})

	// The certificate is renamed last so that a component watching it for a
	// renewal sees a pair that is already complete. Exercised by making the
	// certificate's own write fail: if the order were reversed, the key would
	// not have been written either.
	Describe("the order the pair is written in", func() {
		It("has the key and chain on disk by the time the certificate is written", func() {
			// Root ignores directory permissions, so this spec's mechanism for
			// A directory standing where the certificate file goes, rather than
			// an unwritable parent. The parent must stay writable, because
			// checkDir now refuses an unwritable one before anything is written
			// -- which is the point of that guard and makes the old fixture for
			// this spec unusable. Here the parent is fine, the key and chain
			// land, and the final rename fails because the target is a
			// directory. That isolates the ordering from the pre-flight.
			//
			// Works as root too, unlike the mode-based fixture it replaces: root
			// ignores permissions but cannot rename a file over a directory.
			cfg = certstore.FilesConfig{
				Cert: filepath.Join(dir, "cert.pem"),
				Key:  filepath.Join(dir, "key.pem"),
				CA:   filepath.Join(dir, "ca.pem"),
			}
			Expect(os.Mkdir(cfg.Cert, 0o700)).To(Succeed())

			Expect(store().Save(ctx, []byte("CERT"), []byte("KEY"))).NotTo(Succeed())

			Expect(cfg.Key).To(BeAnExistingFile())
			Expect(cfg.CA).To(BeAnExistingFile())
			info, err := os.Stat(cfg.Cert)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue(),
				"the certificate was never written, so the directory is still there")
		})
	})

	// The renewal case, which is what made the write order a defect rather than
	// a detail. On a first issuance a failed certificate write leaves a key
	// beside nothing, which the next pass replaces. On a renewal it left the NEW
	// key beside the PREVIOUS certificate: a pair that fails every handshake,
	// does not heal -- the next pass sees a key that is not the certificate's,
	// generates another and fails on the same write -- and takes a
	// still-valid certificate out of service at the component's next reload.
	//
	// checkDir's writability probe is what makes this refusable, so this spec
	// asserts the old pair survives BYTE FOR BYTE rather than merely that Save
	// failed. "Save returned an error" was already true before the fix.
	Describe("a renewal it cannot complete", func() {
		It("replaces nothing when the certificate's directory is not writable", func() {
			if os.Geteuid() == 0 {
				Skip("root ignores directory permissions")
			}

			certDir := filepath.Join(dir, "component")
			Expect(os.Mkdir(certDir, 0o700)).To(Succeed())
			cfg = certstore.FilesConfig{
				Cert: filepath.Join(certDir, "cert.pem"),
				Key:  filepath.Join(dir, "key.pem"),
				CA:   filepath.Join(dir, "ca.pem"),
			}

			// A working pair already in place, as a renewal finds it.
			Expect(store().Save(ctx, []byte("OLD-CERT"), []byte("OLD-KEY"))).To(Succeed())

			// Now the component's directory loses write permission.
			Expect(os.Chmod(certDir, 0o500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(certDir, 0o700) })

			Expect(store().Save(ctx, []byte("NEW-CERT"), []byte("NEW-KEY"))).NotTo(Succeed())

			Expect(os.ReadFile(cfg.Key)).To(Equal([]byte("OLD-KEY")),
				"the previous key must survive: replacing it beside the previous "+
					"certificate is the mismatch this refusal exists to prevent")
			Expect(os.ReadFile(cfg.Cert)).To(Equal([]byte("OLD-CERT")))
			Expect(os.ReadFile(cfg.CA)).To(Equal([]byte("CA-CHAIN-PEM")))
		})

		It("names the directory and says what it holds", func() {
			if os.Geteuid() == 0 {
				Skip("root ignores directory permissions")
			}
			certDir := filepath.Join(dir, "component")
			Expect(os.Mkdir(certDir, 0o500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(certDir, 0o700) })

			cfg = certstore.FilesConfig{
				Cert: filepath.Join(certDir, "cert.pem"),
				Key:  filepath.Join(dir, "key.pem"),
			}

			err := store().Save(ctx, []byte("CERT"), []byte("KEY"))

			Expect(err).To(MatchError(ContainSubstring("not writable by this process")))
			Expect(err).To(MatchError(ContainSubstring(certDir)))
			Expect(err).To(MatchError(ContainSubstring("private key")),
				"the message has to say why the mode matters, not just that it is wrong")
		})

		// The same probe, reached without depending on uid -- which is the only
		// way it is covered where it matters. Both specs above skip as root and
		// CI runs containers as root, so in CI they asserted nothing: the probe
		// could have been deleted and the suite would have stayed green. That is
		// the whole point of a guard against a renewal that strands a key, so it
		// cannot be the half of the matrix nothing runs.
		//
		// procfs refuses to create a file in /proc whatever the uid. That is not
		// a mount option that a privileged container could undo, it is what the
		// filesystem does -- measured as root in a Linux container: Stat says
		// /proc is a directory, os.CreateTemp there fails, and the same call in
		// /tmp succeeds, so the refusal is the directory rather than a probe
		// that always fails.
		//
		// Linux only, because /proc is. Between this spec and the two above,
		// every platform this suite runs on reaches the probe: a non-root
		// developer by directory mode, CI by procfs.
		It("refuses a directory the filesystem will not create files in, whatever the uid", func() {
			if runtime.GOOS != "linux" {
				Skip("/proc is Linux's; the mode-based specs above cover this platform")
			}

			cfg = certstore.FilesConfig{
				Cert: "/proc/cert.pem",
				Key:  filepath.Join(dir, "key.pem"),
			}

			err := store().Save(ctx, []byte("CERT"), []byte("KEY"))

			Expect(err).To(MatchError(ContainSubstring("not writable by this process")))
			Expect(err).To(MatchError(ContainSubstring("/proc")))

			// And nothing was written on the way to finding out. checkDir runs
			// over every path before the first write, so the key must not exist
			// -- the ordering that made the unwritable-directory case a defect.
			_, statErr := os.Stat(cfg.Key)
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"the pre-flight must refuse before anything is written, not after the key")
		})
	})
})
