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

package storage_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// skipAsRoot skips a spec that root cannot exercise: root reads, removes and
// searches whatever the modes say. On CI, where these specs are expected to
// run, it fails instead. A skip is quiet, and among them is the only check
// that the frontend never reads the CA key.
func skipAsRoot(why string) {
	if os.Geteuid() != 0 {
		return
	}
	if os.Getenv("CI") != "" {
		Fail("running as root on CI would skip this spec: " + why)
	}
	Skip(why)
}

// The filesystem backend keeps the CA key where OpenVox Server does, at the top
// of the cadir, so a cadir handed back to OpenVox Server has it where it looks.
var _ = Describe("Filesystem CA key location", func() {
	var (
		ctx   = context.Background()
		dir   string
		store *storage.StorageService
		top   string
		// stray is private/ca_key.pem: the name a key generated for the
		// subject "ca" would have, and nothing this backend reads as the CA
		// key.
		stray string
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		store = storage.New(dir)
		Expect(store.EnsureDirs(ctx)).To(Succeed())
		top = filepath.Join(dir, "ca_key.pem")
		stray = filepath.Join(dir, "private", "ca_key.pem")
	})

	It("writes a new key at the top of the cadir, private to the owner", func() {
		Expect(store.SaveCAKey(ctx, []byte("key"))).To(Succeed())

		info, err := os.Stat(top)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		Expect(stray).NotTo(BeAnExistingFile())
	})

	It("reads the key OpenVox Server left at the top of the cadir", func() {
		Expect(os.WriteFile(top, []byte("ovs-key"), 0o640)).To(Succeed())

		Expect(store.GetCAKey(ctx)).To(Equal([]byte("ovs-key")))
		Expect(store.HasCAKey(ctx)).To(BeTrue())
	})

	It("leaves the mode of a key it did not create alone", func() {
		// OpenVox Server creates its key group-readable. Reading it is not
		// licence to chmod it.
		Expect(os.WriteFile(top, []byte("ovs-key"), 0o640)).To(Succeed())
		Expect(os.Chmod(top, 0o640)).To(Succeed())
		_, err := store.GetCAKey(ctx)
		Expect(err).NotTo(HaveOccurred())

		info, err := os.Stat(top)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o640)))
	})

	Context("when a file named ca_key.pem sits in private/", func() {
		BeforeEach(func() {
			Expect(os.WriteFile(stray, []byte("other-key"), 0o600)).To(Succeed())
		})

		It("does not take it for the CA key", func() {
			Expect(store.HasCAKey(ctx)).To(BeFalse())
			_, err := store.GetCAKey(ctx)
			Expect(err).To(MatchError(fs.ErrNotExist))
		})

		It("writes a new key at the top of the cadir, and leaves that file alone", func() {
			Expect(store.SaveCAKey(ctx, []byte("new-key"))).To(Succeed())
			Expect(os.ReadFile(top)).To(Equal([]byte("new-key")))
			Expect(os.ReadFile(stray)).To(Equal([]byte("other-key")))
			Expect(store.GetCAKey(ctx)).To(Equal([]byte("new-key")))
		})

		It("deletes the CA key without touching it", func() {
			Expect(os.WriteFile(top, []byte("ca-key"), 0o600)).To(Succeed())
			Expect(store.Backend().Delete(ctx, storage.KeyCAKey)).To(Succeed())
			Expect(top).NotTo(BeAnExistingFile())
			Expect(os.ReadFile(stray)).To(Equal([]byte("other-key")))
		})
	})

	It("refuses to read a key file it cannot read", func() {
		skipAsRoot("root reads a file whatever its mode")
		Expect(os.WriteFile(top, []byte("one-key"), 0o600)).To(Succeed())
		Expect(os.Chmod(top, 0o000)).To(Succeed())
		DeferCleanup(os.Chmod, top, os.FileMode(0o600))

		_, err := store.GetCAKey(ctx)
		Expect(err).To(MatchError(fs.ErrPermission))
	})

	// The network-facing frontend never has the CA key in its address space
	// (docs/ca-key-security.md), yet it runs CheckKeyPermissions at startup
	// and reaches HasCAKey from Init. Neither may read the key to answer. A
	// key at mode 0044 tells the two apart: its owner cannot read it, while
	// the mode is visible to stat. Code that read the file would see a
	// permission error and report nothing, or refuse.
	Context("answering without reading the key", func() {
		BeforeEach(func() {
			skipAsRoot("root reads a file whatever its mode")
			Expect(os.WriteFile(top, []byte("one-key"), 0o600)).To(Succeed())
			Expect(os.Chmod(top, 0o044)).To(Succeed())
			DeferCleanup(os.Chmod, top, os.FileMode(0o600))
		})

		It("reports the key's permissions", func() {
			Expect(store.CheckKeyPermissions()).To(ContainElement(
				storage.KeyPermWarning{Path: top, Mode: 0o044}))
		})

		It("says a key exists", func() {
			Expect(store.HasCAKey(ctx)).To(BeTrue())
		})
	})

	// Several specs here skip as root, which reads, removes and searches
	// whatever the modes say; the ones above are the only check that the
	// frontend never reads the key. A skip is quiet, so on CI, where they have
	// to run, a root user fails instead.
	It("runs as a non-root user on CI, where the specs that skip for root must run", func() {
		if os.Getenv("CI") == "" {
			Skip("only CI promises a non-root user")
		}
		Expect(os.Geteuid()).NotTo(BeZero(),
			"running as root skips the specs that pin the key is never read")
	})

	Context("when ca_key.pem is a link that leads nowhere", func() {
		// A dangling link where the key is expected is a key that should be
		// there. It must fail, never read as absent: that would have a
		// migration skip the key, or let a write or a delete replace the link.
		BeforeEach(func() {
			Expect(os.Symlink(filepath.Join(dir, "gone.pem"), top)).To(Succeed())
		})

		It("refuses to read it", func() {
			_, err := store.GetCAKey(ctx)
			Expect(err).To(MatchError(storage.ErrCAKeyLinkBroken))
			Expect(err).NotTo(MatchError(fs.ErrNotExist), "callers read ErrNotExist as no key")
		})

		It("refuses to say whether a key exists, rather than saying there is none", func() {
			_, err := store.HasCAKey(ctx)
			Expect(err).To(MatchError(storage.ErrCAKeyLinkBroken))
		})

		It("fails a migration rather than migrating without the key", func() {
			dst := storage.New(GinkgoT().TempDir())
			_, err := storage.MigrateService(ctx, store, dst, storage.MigrateOptions{})
			Expect(err).To(MatchError(storage.ErrCAKeyLinkBroken))
		})

		It("names the link as the key's location", func() {
			// What diagnostics report, and the file a fix belongs in.
			Expect(store.CAKeyPath()).To(Equal(top))
		})

		It("refuses to write, and leaves the link in place", func() {
			Expect(store.SaveCAKey(ctx, []byte("new-key"))).To(MatchError(storage.ErrCAKeyLinkBroken))
			Expect(os.Readlink(top)).To(Equal(filepath.Join(dir, "gone.pem")))
		})

		It("refuses to delete, and leaves the link in place", func() {
			Expect(store.Backend().Delete(ctx, storage.KeyCAKey)).To(MatchError(storage.ErrCAKeyLinkBroken))
			Expect(os.Readlink(top)).To(Equal(filepath.Join(dir, "gone.pem")))
		})
	})

	Describe("CheckKeyPermissions", func() {
		It("reports a top-level CA key readable beyond its owner", func() {
			Expect(os.WriteFile(top, []byte("key"), 0o644)).To(Succeed())
			Expect(os.Chmod(top, 0o644)).To(Succeed())

			Expect(store.CheckKeyPermissions()).To(ConsistOf(
				storage.KeyPermWarning{Path: top, Mode: 0o644}))
		})

		It("reports a top-level CA key when another key is overridden", func() {
			// ca_cert_file alone wraps the backend in an overlay; the CA key
			// is still the cadir's own and still checked.
			certFile := filepath.Join(GinkgoT().TempDir(), "ca_crt.pem")
			overlay, err := storage.NewOverlayBackend(storage.NewFilesystemBackend(dir),
				map[string]string{storage.KeyCACert: certFile})
			Expect(err).NotTo(HaveOccurred())
			wrapped := storage.NewWithBackend(overlay, filepath.Join(dir, "private"))
			Expect(os.WriteFile(top, []byte("key"), 0o644)).To(Succeed())
			Expect(os.Chmod(top, 0o644)).To(Succeed())

			Expect(wrapped.CheckKeyPermissions()).To(ConsistOf(
				storage.KeyPermWarning{Path: top, Mode: 0o644}))
		})

		It("does not report the cadir's key file when the CA key itself is overridden", func() {
			keyFile := filepath.Join(GinkgoT().TempDir(), "ca_key.pem")
			overlay, err := storage.NewOverlayBackend(storage.NewFilesystemBackend(dir),
				map[string]string{storage.KeyCAKey: keyFile})
			Expect(err).NotTo(HaveOccurred())
			wrapped := storage.NewWithBackend(overlay, filepath.Join(dir, "private"))
			Expect(os.WriteFile(top, []byte("stale"), 0o644)).To(Succeed())
			Expect(os.Chmod(top, 0o644)).To(Succeed())

			Expect(wrapped.CheckKeyPermissions()).To(BeEmpty())
		})

		It("reports a ca_key.pem in private/ as it does any key there, once", func() {
			Expect(os.WriteFile(stray, []byte("key"), 0o644)).To(Succeed())
			Expect(os.Chmod(stray, 0o644)).To(Succeed())

			Expect(store.CheckKeyPermissions()).To(ConsistOf(
				storage.KeyPermWarning{Path: stray, Mode: 0o644}))
		})
	})
})
