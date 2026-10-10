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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// seedCA populates a backend with a representative set of CA blobs: every
// singleton plus a couple of per-subject CSRs and signed certs.
func seedCA(b Backend) map[string][]byte {
	ctx := context.Background()
	Expect(b.EnsureReady(ctx)).NotTo(HaveOccurred(), "EnsureReady")
	want := map[string][]byte{
		KeyCACert:        []byte("ca-cert-pem"),
		KeyCAPubKey:      []byte("ca-pub-pem"),
		KeyCAKey:         []byte("ca-key-pem"),
		KeyCRL:           []byte("crl-pem"),
		KeySerial:        []byte("0A"),
		KeyInventory:     []byte("0xABC /CN=a\n"),
		KeyInventoryHMAC: []byte("hmac-bytes"),
		KeyHMACKey:       []byte("hmac-key-bytes"),
		KeySuperseded:    []byte(`[{"serial":"0ABC","subject":"web01","revoke_at":"2026-01-01T00:00:00Z"}]`),
		CSRKey("web01"):  []byte("csr-web01"),
		CSRKey("web02"):  []byte("csr-web02"),
		CertKey("web01"): []byte("cert-web01"),
	}
	for k, v := range want {
		Expect(b.Put(ctx, k, v, BlobPublic)).NotTo(HaveOccurred(), fmt.Sprintf("seed Put %q", k))
	}
	return want
}

var _ = Describe("MigrateCopiesEverything", func() {
	It("copies every singleton, CSR, and cert to the destination", func() {
		ctx := context.Background()
		src := NewFilesystemBackend(GinkgoT().TempDir())
		want := seedCA(src)

		dst := NewFilesystemBackend(GinkgoT().TempDir())

		report, err := Migrate(ctx, src, dst, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "Migrate")
		Expect(report.Singletons).To(Equal(9), "want 9 singletons, 2 CSRs, 1 cert")
		Expect(report.CSRs).To(Equal(2), "want 9 singletons, 2 CSRs, 1 cert")
		Expect(report.Certs).To(Equal(1), "want 9 singletons, 2 CSRs, 1 cert")
		Expect(report.Total()).To(Equal(len(want)))

		// Called out because dropping this one is silent and permanent: the
		// pending-supersession list is the only record that a certificate a
		// renewal replaced is still due for revocation. A migration that left
		// it behind would strand every entry — each of them a live credential —
		// with nothing at the destination able to rediscover them.
		Expect(dst.Get(ctx, KeySuperseded)).To(Equal(want[KeySuperseded]),
			"the pending-supersession list must survive a store migration")

		for k, v := range want {
			got, err := dst.Get(ctx, k)
			if err != nil {
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("dst.Get %q", k))
				continue
			}
			Expect(got).To(Equal(v), fmt.Sprintf("dst[%q]", k))
		}
	})
})

// MigratePreservesVisibility verifies that private singletons land with
// 0600 and public ones with 0644 on a filesystem destination.
var _ = Describe("MigratePreservesVisibility", func() {
	It("lands private singletons 0600 and public ones 0644", func() {
		ctx := context.Background()
		src := NewFilesystemBackend(GinkgoT().TempDir())
		seedCA(src)

		dstDir := GinkgoT().TempDir()
		dst := NewFilesystemBackend(dstDir)
		_, err := Migrate(ctx, src, dst, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "Migrate")

		cases := []struct {
			key  string
			perm os.FileMode
		}{
			{KeyCACert, FilePermPublic},
			{KeySerial, FilePermPublic},
			{KeyCAKey, FilePermPrivate},
			{KeyInventory, FilePermPrivate},
			{KeyHMACKey, FilePermPrivate},
			{KeySuperseded, FilePermPrivate},
		}
		for _, c := range cases {
			p := dst.Path(c.key)
			info, err := os.Stat(p)
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("stat %q", p))
			Expect(info.Mode().Perm()).To(Equal(c.perm), fmt.Sprintf("%s perm", c.key))
		}
	})
})

var _ = Describe("MigrateRefusesNonEmptyDestination", func() {
	It("refuses a non-empty destination unless forced", func() {
		ctx := context.Background()
		src := NewFilesystemBackend(GinkgoT().TempDir())
		seedCA(src)

		dst := NewFilesystemBackend(GinkgoT().TempDir())
		Expect(dst.EnsureReady(ctx)).NotTo(HaveOccurred(), "EnsureReady")
		// Pre-populate the destination with a CA cert.
		Expect(dst.Put(ctx, KeyCACert, []byte("existing"), BlobPublic)).NotTo(HaveOccurred(), "seed dst")

		_, err := Migrate(ctx, src, dst, MigrateOptions{})
		Expect(err).To(MatchError(ErrDestinationNotEmpty))

		// The existing cert must be untouched (no partial copy occurred).
		got, err := dst.Get(ctx, KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "dst CA cert, want untouched")
		Expect(got).To(Equal([]byte("existing")), "dst CA cert, want untouched")

		// --force overwrites it.
		_, err = Migrate(ctx, src, dst, MigrateOptions{Force: true})
		Expect(err).NotTo(HaveOccurred(), "Migrate --force")
		got, _ = dst.Get(ctx, KeyCACert)
		Expect(got).To(Equal([]byte("ca-cert-pem")), "after force, dst CA cert")
	})
})

var _ = Describe("MigrateSkipsAbsentSingletons", func() {
	It("does not create absent singletons at the destination", func() {
		ctx := context.Background()
		src := NewFilesystemBackend(GinkgoT().TempDir())
		Expect(src.EnsureReady(ctx)).NotTo(HaveOccurred(), "EnsureReady")
		// Only a CA cert and one CSR exist; everything else is absent.
		Expect(src.Put(ctx, KeyCACert, []byte("c"), BlobPublic)).NotTo(HaveOccurred(), "seed")
		Expect(src.Put(ctx, CSRKey("only"), []byte("r"), BlobPublic)).NotTo(HaveOccurred(), "seed")

		dst := NewFilesystemBackend(GinkgoT().TempDir())
		report, err := Migrate(ctx, src, dst, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "Migrate")
		Expect(report.Singletons).To(Equal(1), "want 1 singleton, 1 CSR, 0 certs")
		Expect(report.CSRs).To(Equal(1), "want 1 singleton, 1 CSR, 0 certs")
		Expect(report.Certs).To(Equal(0), "want 1 singleton, 1 CSR, 0 certs")
		// An absent singleton must not be created at the destination.
		_, err = os.Stat(dst.Path(KeySerial))
		Expect(err).To(MatchError(os.ErrNotExist), "serial unexpectedly present at destination")
	})
})

var _ = Describe("MigrateLogfReceivesEachCopiedBlob", func() {
	It("calls Logf once per copied blob", func() {
		ctx := context.Background()
		src := NewFilesystemBackend(GinkgoT().TempDir())
		want := seedCA(src)
		dst := NewFilesystemBackend(GinkgoT().TempDir())

		var lines int
		_, err := Migrate(ctx, src, dst, MigrateOptions{
			Logf: func(string, ...any) { lines++ },
		})
		Expect(err).NotTo(HaveOccurred(), "Migrate")
		Expect(lines).To(Equal(len(want)), "Logf call count")
	})
})

// SECURITY: pins the %q in migrate.go's logf call.
//
// Logf is operator-facing output with no escaping anywhere behind it: the CLI
// implements it as fmt.Fprintf(os.Stderr, format+"\n", a...). The keys it
// renders are built from source directory entry names, which nothing
// validates -- migrating a foreign or legacy CA directory is exactly the case
// where a filename can carry a terminator. %q is what stands between that and
// a forged progress line, and it is one of the two sanitisers CodeQL's
// go/log-injection query recognises.
//
// The sibling spec above counts Logf calls and discards their arguments, so it
// would not notice %q reverting to %s. This asserts the rendering, which is
// the part an attacker cares about.
var _ = Describe("MigrateLogfEscapesTerminatorsInKeys", func() {
	It("renders the key with %q so a terminator cannot forge a second line", func() {
		ctx := context.Background()
		src := NewFilesystemBackend(GinkgoT().TempDir())
		seedCA(src)

		// Both terminators, and a tail shaped to look like a real progress
		// line if either reached the output raw.
		forged := "evil\r\ncopied \"everything\" (0 bytes)"
		key := CSRKey(forged)
		Expect(src.Put(ctx, key, []byte("csr"), BlobPublic)).
			NotTo(HaveOccurred(), "seeding a CSR whose name carries terminators")

		dst := NewFilesystemBackend(GinkgoT().TempDir())

		var calls int
		var out strings.Builder
		_, err := Migrate(ctx, src, dst, MigrateOptions{
			// Deliberately the CLI's own shim: appends the newline itself and
			// escapes nothing, so what lands here is what an operator sees.
			Logf: func(format string, a ...any) {
				calls++
				fmt.Fprintf(&out, format+"\n", a...)
			},
		})
		Expect(err).NotTo(HaveOccurred(), "Migrate")

		// The consequence an injected terminator would buy: one call, one line.
		Expect(strings.Count(out.String(), "\n")).To(Equal(calls),
			"each Logf call must render as exactly one line; more lines than calls "+
				"means a key's newline reached the output unescaped:\n%s", out.String())
		Expect(out.String()).NotTo(ContainSubstring("\r"),
			"a bare carriage return starts a fresh line on an operator's terminal:\n%s",
			out.String())

		// Non-vacuity, last: the assertions above all hold trivially for a run
		// that copied nothing, so this pins that the seeded key really did
		// reach Logf, in its quoted form.
		Expect(out.String()).To(ContainSubstring(strconv.Quote(key)),
			"the seeded key must reach Logf, quoted")
	})
})

// unlockFunc adapts a func to the Unlocker interface.
type unlockFunc func() error

func (f unlockFunc) Unlock() error { return f() }

// lockingBackend wraps a filesystem backend and additionally implements Locker,
// recording every lock acquired and released so tests can assert that
// MigrateService coordinates the copy under a distributed lock.
type lockingBackend struct {
	*FilesystemBackend
	acquired []string
	released int
}

func (b *lockingBackend) AcquireLock(_ context.Context, name string) (Unlocker, error) {
	b.acquired = append(b.acquired, name)
	return unlockFunc(func() error { b.released++; return nil }), nil
}

var _ = Describe("MigrateServiceLocksBothBackends", func() {
	It("acquires and releases the migrate lock on both backends", func() {
		ctx := context.Background()
		srcB := &lockingBackend{FilesystemBackend: NewFilesystemBackend(GinkgoT().TempDir())}
		want := seedCA(srcB)
		dstB := &lockingBackend{FilesystemBackend: NewFilesystemBackend(GinkgoT().TempDir())}

		src := NewWithBackend(srcB, GinkgoT().TempDir())
		dst := NewWithBackend(dstB, GinkgoT().TempDir())

		report, err := MigrateService(ctx, src, dst, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "MigrateService")
		Expect(report.Total()).To(Equal(len(want)), "Total")

		// The source is only read from, so it takes the migrate lock and
		// nothing else.
		Expect(srcB.acquired).To(Equal([]string{migrateLockName}),
			fmt.Sprintf("source locks acquired = %v, want [%q]", srcB.acquired, migrateLockName))
		Expect(srcB.released).To(Equal(1), "source locks released")

		// The destination takes a second lock nested inside the first:
		// MigrateService rebuilds its inventory HMAC while still holding the
		// migrate lock, and seedCA's hmac_key is deliberately not hmacKeyLen
		// bytes, so EnsureHMACKey regenerates it — under lockNameHMACKey.
		//
		// This pins the nesting itself: migrate lock outermost, HMAC key
		// inside, never the reverse. It does *not* police the two names being
		// different — lockingBackend hands out a lock that never blocks, so
		// under a shared name this spec records the same string twice and
		// still passes. The spec that would catch that is "does not deadlock
		// when reached from inside the migration lock" in hmacrace_test.go,
		// which locks a real non-reentrant mutex; verified by setting
		// lockNameHMACKey to migrateLockName and watching only that one fail.
		Expect(dstB.acquired).To(Equal([]string{migrateLockName, lockNameHMACKey}),
			fmt.Sprintf("destination locks acquired = %v, want [%q %q]", dstB.acquired, migrateLockName, lockNameHMACKey))
		Expect(dstB.released).To(Equal(2), "destination locks released")

		// The data was actually copied under the lock.
		got, err := dstB.Get(ctx, KeyCACert)
		Expect(err).NotTo(HaveOccurred(), "dst CA cert, want copied")
		Expect(got).To(Equal(want[KeyCACert]), "dst CA cert, want copied")
	})
})

// MigrateServiceWithoutLocker confirms MigrateService still works against
// backends that do not implement Locker: WithLock falls through to the
// same-host lock the filesystem backend provides, and the copy completes.
// Source and destination are distinct directories, so the two "bootstrap"
// acquisitions are distinct locks — pointing both at one store deadlocks, and
// is documented as unsupported.
var _ = Describe("MigrateServiceWithoutLocker", func() {
	It("completes against backends that lack a distributed Locker", func() {
		ctx := context.Background()
		srcB := NewFilesystemBackend(GinkgoT().TempDir())
		want := seedCA(srcB)
		dstB := NewFilesystemBackend(GinkgoT().TempDir())

		src := NewWithBackend(srcB, GinkgoT().TempDir())
		dst := NewWithBackend(dstB, GinkgoT().TempDir())

		report, err := MigrateService(ctx, src, dst, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "MigrateService")
		Expect(report.Total()).To(Equal(len(want)), "Total")
	})
})

// MigrateRoundTripsLocalFileLayout sanity-checks that a migrated
// filesystem destination is readable as a normal on-disk CA (paths exist where
// the filesystem backend expects them).
var _ = Describe("MigrateRoundTripsLocalFileLayout", func() {
	It("lays out well-known on-disk paths at the destination", func() {
		ctx := context.Background()
		src := NewFilesystemBackend(GinkgoT().TempDir())
		seedCA(src)

		dstDir := GinkgoT().TempDir()
		dst := NewFilesystemBackend(dstDir)
		_, err := Migrate(ctx, src, dst, MigrateOptions{})
		Expect(err).NotTo(HaveOccurred(), "Migrate")

		// Spot-check a couple of well-known on-disk paths.
		for _, rel := range []string{"ca_crt.pem", "ca_key.pem", filepath.Join("requests", "web01.pem")} {
			_, err := os.Stat(filepath.Join(dstDir, rel))
			Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("expected %s on disk", rel))
		}
	})
})
