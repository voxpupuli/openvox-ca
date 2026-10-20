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
	"bytes"
	"context"
	"errors"
	"log/slog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// MigrateService rebuilds the destination's integrity value over whatever it
// copied, so without a check on the source a migration turns a tampered
// inventory into one that verifies. These specs pin which source states it
// refuses, which it lets through, and that a refusal leaves the destination
// untouched.
var _ = Describe("MigrateService source verification", func() {
	ctx := context.Background()

	newDst := func() *StorageService {
		return NewWithBackend(NewFilesystemBackend(GinkgoT().TempDir()), GinkgoT().TempDir())
	}

	// expectDestinationUntouched asserts that a refused migration copied
	// nothing. That the destination is not even locked is pinned separately,
	// by "refuses before it locks the destination".
	expectDestinationUntouched := func(dst *StorageService) {
		for _, key := range []string{KeyInventory, KeyInventoryHMAC, KeyHMACKey} {
			exists, err := dst.Backend().Exists(ctx, key)
			Expect(err).NotTo(HaveOccurred())
			Expect(exists).To(BeFalse(), "a refused migration wrote %q to the destination", key)
		}
	}

	// A filesystem source holding entries under a baseline that verifies.
	verifiedFilesystem := func() *StorageService {
		svc := newFilesystemInventoryService()
		Expect(svc.SaveCACert(ctx, []byte("ca-cert-pem"))).To(Succeed())
		return svc
	}

	// tamperBlob appends an entry the stored value does not cover, written
	// straight to the backend so nothing updates the value.
	tamperBlob := func(svc *StorageService) {
		blob, err := svc.readInventoryForHMAC(ctx)
		Expect(err).NotTo(HaveOccurred())
		extra := append(bytes.Clone(blob), []byte("0x0999 2026-01-01T00:00:00UTC 2036-01-01T00:00:00UTC /CN=ghost\n")...)
		Expect(svc.backend.Put(ctx, KeyInventory, extra, BlobPrivate)).To(Succeed())
	}

	Describe("a source that verifies", func() {
		DescribeTable("is migrated without comment",
			func(source func() *StorageService) {
				dst := newDst()

				report, err := MigrateService(ctx, source(), dst, MigrateOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(report.UnverifiedSource).To(BeEmpty())
				Expect(dst.InitHMAC(ctx)).To(Succeed(), "the destination must verify after a clean migration")
			},
			Entry("whole-blob scheme (filesystem)", verifiedFilesystem),
			Entry("hash-chain scheme (SQLite)", func() *StorageService {
				svc, _ := newInventoryService()
				return svc
			}),
			// A new structured CA stores an empty head over an empty chain.
			// The report must read that as a baseline, not as an absent one,
			// or every CA that has signed nothing would be refused.
			Entry("hash-chain scheme with an empty inventory (SQLite)", func() *StorageService {
				svc := NewWithBackend(newSQLiteBackend(), "")
				Expect(svc.TouchInventory(ctx)).To(Succeed())
				Expect(svc.InitHMAC(ctx)).To(Succeed())
				return svc
			}),
		)
	})

	DescribeTable("refuses a source that does not verify, naming the reason and the remedy",
		func(source func() *StorageService, reason string) {
			dst := newDst()

			_, err := MigrateService(ctx, source(), dst, MigrateOptions{})

			Expect(err).To(MatchError(ErrSourceUnverified))
			Expect(err.Error()).To(ContainSubstring(reason))
			Expect(err.Error()).To(ContainSubstring("openvox-ca rebuild-inventory-hmac"))
			Expect(err.Error()).To(ContainSubstring("--" + AllowUnverifiedSourceFlag))
			expectDestinationUntouched(dst)
		},
		Entry("a whole-blob inventory that does not match its value",
			func() *StorageService {
				svc := verifiedFilesystem()
				tamperBlob(svc)
				return svc
			},
			"does not match its stored integrity value (scheme whole-blob-hmac)"),
		Entry("a hash-chain inventory with a modified row",
			func() *StorageService {
				svc, b := newInventoryService()
				_, err := b.db.NewUpdate().
					Model((*sqlInventoryRow)(nil)).
					Set("serial = ?", "DEAD").
					Where("subject = ?", "node2").
					Exec(ctx)
				Expect(err).NotTo(HaveOccurred(), "tamper update")
				return svc
			},
			"does not match its stored integrity value (scheme hash-chain)"),
		Entry("a key with no stored value: the deletion bypass",
			func() *StorageService {
				svc := verifiedFilesystem()
				Expect(svc.backend.Delete(ctx, KeyInventoryHMAC)).To(Succeed())
				return svc
			},
			"no inventory integrity value is stored, although an HMAC key is"),
		Entry("a stored value with no key",
			func() *StorageService {
				svc := verifiedFilesystem()
				Expect(svc.backend.Delete(ctx, KeyHMACKey)).To(Succeed())
				return svc
			},
			"an inventory integrity value is stored but no HMAC key"),
		Entry("a key of the wrong length",
			func() *StorageService {
				svc := verifiedFilesystem()
				Expect(svc.backend.Put(ctx, KeyHMACKey, []byte("short"), BlobPrivate)).To(Succeed())
				return svc
			},
			"the stored inventory HMAC key is the wrong length"),
		Entry("an undecomposed legacy inventory",
			func() *StorageService {
				// Structured, with no rows, over a blob that holds the real
				// inventory: what an etcd or Redis store looks like before a
				// server has decomposed it. Order matters, as in the report's
				// own legacy specs: the wrapper must be the outer type.
				svc := verifiedFilesystem()
				svc.backend = emptyEntriesBackend{Backend: svc.backend}
				return svc
			},
			"undecomposed legacy inventory"),
	)

	It("refuses before it locks the destination", func() {
		// The check runs under the source's lock and ahead of the
		// destination's, so a refusal never waits on, or holds, a lock on the
		// store it was not going to write.
		srcB := &lockingBackend{FilesystemBackend: NewFilesystemBackend(GinkgoT().TempDir())}
		seedCA(srcB) // placeholder integrity blobs: a wrong-length key, so it cannot verify
		dstB := &lockingBackend{FilesystemBackend: NewFilesystemBackend(GinkgoT().TempDir())}
		src := NewWithBackend(srcB, GinkgoT().TempDir())
		dst := NewWithBackend(dstB, GinkgoT().TempDir())

		_, err := MigrateService(ctx, src, dst, MigrateOptions{})

		Expect(err).To(MatchError(ErrSourceUnverified))
		Expect(srcB.acquired).To(Equal([]string{migrateLockName}))
		Expect(srcB.released).To(Equal(1))
		Expect(dstB.acquired).To(BeEmpty(), "a refused migration locked its destination")
	})

	It("refuses, with the cause, when the source's integrity cannot be read", func() {
		// The partial report returned alongside the error would otherwise be
		// taken at face value. Here it is the most permissive state there is:
		// no key, and no value read, which is the never-recorded pass-through.
		// So a verifier that ignored the error would migrate without the
		// override, not merely give the wrong reason.
		src := verifiedFilesystem()
		Expect(src.backend.Delete(ctx, KeyHMACKey)).To(Succeed())
		boom := errors.New("backend unreachable")
		src.backend = failGetBackend{Backend: src.backend, key: KeyInventoryHMAC, err: boom}
		dst := newDst()

		_, err := MigrateService(ctx, src, dst, MigrateOptions{})

		Expect(err).To(MatchError(boom))
		Expect(err.Error()).To(ContainSubstring("checking the source inventory's integrity"))
		Expect(err).NotTo(MatchError(ErrSourceUnverified))
		expectDestinationUntouched(dst)
	})

	It("lets a mismatch through when told to, and says so", func() {
		src := verifiedFilesystem()
		tamperBlob(src)
		dst := newDst()

		report, err := MigrateService(ctx, src, dst, MigrateOptions{AllowUnverifiedSource: true})

		Expect(err).NotTo(HaveOccurred())
		Expect(report.UnverifiedSource).To(ContainSubstring("does not match its stored integrity value"))
		// The point of the override, and of the warning: the destination now
		// verifies, ghost entry and all.
		Expect(dst.InitHMAC(ctx)).To(Succeed())
		inv, err := dst.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(inv)).To(ContainSubstring("/CN=ghost"))
	})

	It("migrates a source that never recorded integrity, without the override, and says so", func() {
		// A cadir as OpenVox Server leaves it: entries, but no HMAC key and no
		// value. There is nothing to verify it against.
		src := New(GinkgoT().TempDir())
		Expect(src.EnsureDirs(ctx)).To(Succeed())
		Expect(src.SaveCACert(ctx, []byte("ca-cert-pem"))).To(Succeed())
		Expect(src.backend.Put(ctx, KeyInventory, []byte(
			"0x0002 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /CN=agent\n"), BlobPrivate)).To(Succeed())
		dst := newDst()

		report, err := MigrateService(ctx, src, dst, MigrateOptions{})

		Expect(err).NotTo(HaveOccurred())
		Expect(report.UnverifiedSource).To(ContainSubstring("never recorded an inventory integrity value"))
		exists, err := dst.Backend().Exists(ctx, KeyCACert)
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeTrue(), "the migration must have run")

		// No key came across, so nothing could be rebuilt: the destination
		// holds no value until a server starts against it...
		exists, err = dst.Backend().Exists(ctx, KeyInventoryHMAC)
		Expect(err).NotTo(HaveOccurred())
		Expect(exists).To(BeFalse(), "a value was written with no key to compute it under")

		// ...and that start warns, which is the residual signal the threat
		// model credits for a source whose key and value were both deleted.
		logs := &bytes.Buffer{}
		orig := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
		DeferCleanup(func() { slog.SetDefault(orig) })
		Expect(dst.InitHMAC(ctx)).To(Succeed())
		Expect(logs.String()).To(ContainSubstring(`level=WARN msg="No inventory HMAC found on an established CA`))
	})

	It("rebuilds a never-recorded source's value at once under --force into a destination with a key", func() {
		// The limit of that residual signal: a destination that already has a
		// key gets a value now, over the copy, and its next start is silent.
		// The migrate-time warning is then the only trace.
		src := New(GinkgoT().TempDir())
		Expect(src.EnsureDirs(ctx)).To(Succeed())
		Expect(src.SaveCACert(ctx, []byte("ca-cert-pem"))).To(Succeed())
		Expect(src.backend.Put(ctx, KeyInventory, []byte(
			"0x0002 2024-01-01T00:00:00UTC 2029-01-01T00:00:00UTC /CN=agent\n"), BlobPrivate)).To(Succeed())
		dst := verifiedFilesystem()

		report, err := MigrateService(ctx, src, dst, MigrateOptions{Force: true})

		Expect(err).NotTo(HaveOccurred())
		Expect(report.UnverifiedSource).To(ContainSubstring("never recorded an inventory integrity value"))
		rep, err := dst.InventoryIntegrityReport(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(rep.Verifies).To(BeTrue(), "the destination's own key must have been used to rebuild over the copy")
		inv, err := dst.ReadInventory(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(inv)).To(ContainSubstring("/CN=agent"))
	})
})
