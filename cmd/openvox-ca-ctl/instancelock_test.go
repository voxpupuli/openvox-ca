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
	"os"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/testutil"
)

// The commands that reach storage directly must refuse while a server is
// running against it, and say who is holding it.
//
// Only these do. `list`, `sign` and `revoke` go through the admin API over
// HTTP and never open the store, so they are unaffected and must stay so — an
// operator listing certificates against a live CA is an ordinary thing to do.

var _ = Describe("openvox-ca-ctl and the store instance lock", func() {
	// refusal asserts the shape every one of these commands must produce: the
	// condition, the holder, and what to do about it.
	refusal := func(err error) {
		GinkgoHelper()
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("already running against this store")))
		Expect(err).To(MatchError(ContainSubstring("pid " + strconv.Itoa(os.Getpid()))))
		Expect(err).To(MatchError(ContainSubstring("stop the running one first")))
	}

	It("refuses to initialise a cadir a server is running against", func() {
		caDir := GinkgoT().TempDir()
		holdStoreLock(caDir)

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"setup", "--cadir", caDir, "--hostname", "puppet.example.com"})

		refusal(cmd.Execute())

		// And it must have refused before doing any of the work, not after.
		Expect(filepath.Join(caDir, "ca_crt.pem")).NotTo(BeAnExistingFile(),
			"a refused setup must not have bootstrapped a CA")
	})

	It("initialises normally once the store is free", func() {
		// The control: without this, a setup that always failed would satisfy
		// the spec above.
		caDir := GinkgoT().TempDir()

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"setup", "--cadir", caDir, "--hostname", "puppet.example.com"})

		Expect(cmd.Execute()).To(Succeed())
		Expect(filepath.Join(caDir, "ca_crt.pem")).To(BeAnExistingFile())
	})

	It("refuses to import a CA into a cadir a server is running against", func() {
		caDir := GinkgoT().TempDir()

		// A real bundle, so the refusal is the lock and not a parse failure.
		setup := newRootCmd()
		setup.SetOut(GinkgoWriter)
		setup.SetErr(GinkgoWriter)
		setup.SetArgs([]string{"setup", "--cadir", caDir, "--hostname", "puppet.example.com"})
		Expect(setup.Execute()).To(Succeed())

		target := GinkgoT().TempDir()
		holdStoreLock(target)

		cmd := newRootCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{
			"import", "--cadir", target,
			"--cert-bundle", filepath.Join(caDir, "ca_crt.pem"),
			"--private-key", filepath.Join(caDir, "private", "ca_key.pem"),
		})

		refusal(cmd.Execute())
	})
})

var _ = Describe("migrate and the store instance lock", func() {
	It("refuses a store pointed at itself, instead of waiting for ever", func() {
		// Migrating a store onto itself was never supported. Before the
		// store-wide lock it deadlocked: the destination waited on a bootstrap
		// lock the source already held, and `migrate` applies no timeout, so
		// the command sat there printing nothing. Now the second acquisition is
		// refused at once.
		dir := GinkgoT().TempDir()
		cfgDir := GinkgoT().TempDir()
		seedFilesystemCA(dir)

		cfgPath := filepath.Join(cfgDir, "same.yaml")
		fsConfig(cfgPath, dir)

		cmd := newMigrateCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--source-config", cfgPath, "--dest-config", cfgPath, "--force"})

		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()

		var err error
		Eventually(done, "10s").Should(Receive(&err), "migrate must not wait on a lock it can never be granted")
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring("destination backend")))
	})

	It("refuses to migrate out of a store a server is running against", func() {
		// Reading a live store still copies an inventory the server is
		// appending to, so the source end is not the lenient one.
		srcDir := GinkgoT().TempDir()
		dstDir := GinkgoT().TempDir()
		cfgDir := GinkgoT().TempDir()
		seedFilesystemCA(srcDir)
		holdStoreLock(srcDir)

		srcCfg := filepath.Join(cfgDir, "src.yaml")
		dstCfg := filepath.Join(cfgDir, "dst.yaml")
		fsConfig(srcCfg, srcDir)
		fsConfig(dstCfg, dstDir)

		cmd := newMigrateCmd()
		cmd.SetOut(GinkgoWriter)
		cmd.SetErr(GinkgoWriter)
		cmd.SetArgs([]string{"--source-config", srcCfg, "--dest-config", dstCfg})

		err := cmd.Execute()
		Expect(err).To(MatchError(ContainSubstring("source backend")))
		Expect(err).To(MatchError(ContainSubstring("already running against this store")))
	})
})

// holdStoreLock takes a cadir's instance lock for the rest of the spec, the way
// a running server holds it.
//
// A separate StorageService over the same cadir is an exact stand-in for a
// second process: flock(2) is held by an open file description, so it excludes
// this one whether or not a fork separates them.
func holdStoreLock(cadir string) {
	GinkgoHelper()
	ul, err := storage.New(cadir).AcquireInstanceLock(context.Background())
	Expect(err).NotTo(HaveOccurred(), "the store must be free before the spec holds it")
	DeferCleanup(func() { _ = ul.Unlock() })
}

var _ = Describe("lockStore release ordering", func() {
	It("closes the backend before releasing the lock", func() {
		// The invariant, asserted rather than trusted. Releasing the store-wide
		// lock first re-opens, for the gap between the two, exactly the window
		// the lock exists to close: another process may take a store this one
		// still holds an open connection to. On SQLite that connection is to the
		// database file itself.
		//
		// A defer pair at the call site gets this backwards, LIFO running Unlock
		// first, which is why the ordering lives in one helper.
		rec := testutil.NewRecordingBackend(GinkgoT().TempDir())
		svc := storage.NewWithBackend(rec, filepath.Join(GinkgoT().TempDir(), "private"))

		release, err := lockStore(context.Background(), svc)
		Expect(err).NotTo(HaveOccurred())
		Expect(rec.Events()).To(BeEmpty(), "nothing is given back until the caller says so")

		release()

		Expect(rec.Events()).To(Equal([]string{"close", "unlock"}),
			"the lock must outlive the backend handle it protects")
	})

	It("closes the backend when the lock cannot be taken, rather than leaking it", func() {
		cadir := GinkgoT().TempDir()
		holdStoreLock(cadir)

		rec := testutil.NewRecordingBackend(cadir)
		svc := storage.NewWithBackend(rec, filepath.Join(GinkgoT().TempDir(), "private"))

		release, err := lockStore(context.Background(), svc)
		Expect(err).To(HaveOccurred())
		Expect(release).To(BeNil())
		Expect(rec.Events()).To(Equal([]string{"close"}),
			"the caller has no cleanup to run, so the handle must be closed here")
	})
})
