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
		It("fails on a read error that is not absence", func() {
			// A directory where a file is expected: os.ReadFile fails with
			// EISDIR, which is not fs.ErrNotExist.
			Expect(os.Mkdir(cfg.Cert, 0o755)).To(Succeed())

			_, _, err := store().Load(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(ContainSubstring(cfg.Cert)))
		})
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
			Expect(os.WriteFile(cfg.Key, []byte("OLD-KEY"), 0o600)).To(Succeed())

			Expect(store().Save(ctx, []byte("NEW"), []byte("NEW-KEY"))).To(Succeed())
			Expect(os.ReadFile(cfg.Cert)).To(Equal([]byte("NEW")))
		})
	})

	Describe("the directory it will not create", func() {
		// A private key's directory is a permissions decision, and the safe
		// guess and the useful one are not the same: 0700 locks out the very
		// component the certificate is for, and anything wider exposes the key
		// by default. So the store names the directory instead.
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
			// making the certificate write fail does not work as root. The
			// neighbouring internal/ca specs guard the same way.
			if os.Geteuid() == 0 {
				Skip("root ignores directory permissions")
			}
			certDir := filepath.Join(dir, "readonly")
			Expect(os.Mkdir(certDir, 0o500)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(certDir, 0o700) })

			cfg = certstore.FilesConfig{
				Cert: filepath.Join(certDir, "cert.pem"),
				Key:  filepath.Join(dir, "key.pem"),
				CA:   filepath.Join(dir, "ca.pem"),
			}

			Expect(store().Save(ctx, []byte("CERT"), []byte("KEY"))).NotTo(Succeed())

			Expect(cfg.Key).To(BeAnExistingFile())
			Expect(cfg.CA).To(BeAnExistingFile())
			Expect(cfg.Cert).NotTo(BeAnExistingFile())
		})
	})
})
