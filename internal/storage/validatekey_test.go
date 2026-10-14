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
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// treeOf lists every path under dir, relative to it, so a spec can assert that
// a refused operation created nothing anywhere -- not just at the path it
// would have written.
func treeOf(dir string) []string {
	var out []string
	Expect(filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out = append(out, rel)
		return nil
	})).To(Succeed())
	sort.Strings(out)
	return out
}

// backendOp is one Backend method reduced to "do it to this key", so the
// refusal tables below can run every method that takes a key.
type backendOp func(ctx context.Context, b Backend, key string) error

var (
	opGet backendOp = func(ctx context.Context, b Backend, key string) error {
		_, err := b.Get(ctx, key)
		return err
	}
	opPut backendOp = func(ctx context.Context, b Backend, key string) error {
		return b.Put(ctx, key, []byte("data"), BlobPublic)
	}
	opAppendLine backendOp = func(ctx context.Context, b Backend, key string) error {
		return b.AppendLine(ctx, key, []byte("line"), BlobPublic)
	}
	opDelete backendOp = func(ctx context.Context, b Backend, key string) error {
		return b.Delete(ctx, key)
	}
	opExists backendOp = func(ctx context.Context, b Backend, key string) error {
		_, err := b.Exists(ctx, key)
		return err
	}
	opModTime backendOp = func(ctx context.Context, b Backend, key string) error {
		_, err := b.ModTime(ctx, key)
		return err
	}
)

var _ = Describe("validateKey", func() {
	DescribeTable("accepts",
		func(key string) {
			Expect(validateKey(key)).To(Succeed())
		},
		Entry("a singleton key", KeyCACert),
		Entry("a singleton key with an underscore", KeyInventoryHMAC),
		Entry("a CSR key", CSRKey("node1.example.com")),
		Entry("a certificate key", CertKey("node1.example.com")),
		// Upstream Puppet allows a space in a certname, so an OpenVox Server
		// cadir can hold one. Refusing it would make that entry unreadable and
		// stop a migration at it; ca.ValidateSubject refuses it at openvox-ca's
		// own entry points instead.
		Entry("a subject containing a space", CSRKey("puppet ca host")),
		Entry("a subject containing a non-breaking space", CertKey("a b")),
	)

	DescribeTable("refuses",
		func(key, reason string) {
			Expect(validateKey(key)).To(MatchError(ContainSubstring(reason)))
		},
		Entry("an empty key", "", "empty key"),
		Entry("a CSR key with an empty subject", CSRKey(""), "empty name"),
		Entry("a certificate key with an empty subject", CertKey(""), "empty name"),
		Entry("traversal in a bare key", "../evil", "contains '..'"),
		Entry("traversal in a subject", CSRKey("a..b"), "contains '..'"),
		Entry("a '/' in a CSR subject", CSRKey("a/b"), "contains '/'"),
		Entry("a '/' in a certificate subject", CertKey("a/b"), "contains '/'"),
		Entry("a leading '/' in a subject", CSRKey("/etc"), "contains '/'"),
		Entry("a '/' in a key with no subject prefix", "ca/cert", "contains '/'"),
		Entry("a newline", CSRKey("a\nb"), "control character U+000A"),
		Entry("a carriage return", CertKey("a\rb"), "control character U+000D"),
		Entry("a tab", CSRKey("a\tb"), "control character U+0009"),
		Entry("a NUL", CSRKey("a\x00b"), "control character U+0000"),
		Entry("an escape", CSRKey("a\x1b[2Jb"), "control character U+001B"),
		Entry("a DEL", CSRKey("a\x7fb"), "control character U+007F"),
		Entry("a C1 control", CSRKey("a\u0085b"), "control character U+0085"),
		Entry("a control character in a bare key", "crl\n", "control character U+000A"),
		// The single-byte forms of C1 controls are not valid UTF-8, and ranging
		// over them yields U+FFFD, which is not a control character: refused as
		// invalid UTF-8 instead, or they would pass.
		Entry("a raw 8-bit CSI byte", CSRKey("a\x9bb"), "not valid UTF-8"),
		Entry("a raw 8-bit NEL byte", CertKey("a\x85b"), "not valid UTF-8"),
		Entry("a truncated multi-byte sequence", CSRKey("a\xc2"), "not valid UTF-8"),
	)

	It("names the whole key, quoted, in the refusal", func() {
		Expect(validateKey(CSRKey("a\nb"))).To(MatchError(`invalid key "csr/a\nb": contains control character U+000A`))
	})
})

// Each backend runs validateKey on its own, at the point it turns a logical
// key into a physical one; these pin that every method taking a key reaches
// it, backend by backend. The etcd and Redis backends funnel every method
// through physicalKey, whose tables (etcd_unit_test.go, redis_test.go) carry
// the same keys.
var _ = Describe("FilesystemBackend refusing an unsafe key", func() {
	var (
		ctx context.Context
		dir string
		b   *FilesystemBackend
	)

	BeforeEach(func() {
		ctx = context.Background()
		dir = GinkgoT().TempDir()
		b = NewFilesystemBackend(dir)
		Expect(b.EnsureReady(ctx)).To(Succeed())
	})

	// The writes are the ones that matter most here: Put and AppendLine
	// MkdirAll the parent of the path they are given, so a key containing "/"
	// would create a subdirectory under requests/ or signed/.
	DescribeTable("refuses a write and creates nothing",
		func(op backendOp, key string) {
			before := treeOf(dir)
			Expect(op(ctx, b, key)).To(MatchError(ContainSubstring("invalid key")))
			Expect(treeOf(dir)).To(Equal(before))
		},
		Entry("Put with '/' in a CSR subject", opPut, CSRKey("a/b")),
		Entry("Put with '/' in a certificate subject", opPut, CertKey("a/b")),
		Entry("AppendLine with '/' in a subject", opAppendLine, CSRKey("a/b")),
		Entry("Put with a newline in a subject", opPut, CSRKey("a\nb")),
		Entry("Put with a DEL in a subject", opPut, CertKey("a\x7fb")),
		Entry("AppendLine with a carriage return in a subject", opAppendLine, CSRKey("a\rb")),
		Entry("Put with a raw C1 byte in a subject", opPut, CSRKey("a\x9bb")),
	)

	// A file a foreign tool left in a subdirectory of requests/ is reachable
	// through a "/" key without the guard, so plant one and prove the read
	// side refuses it rather than finding it.
	DescribeTable("refuses a read or delete of a nested file",
		func(op backendOp) {
			nested := filepath.Join(dir, "requests", "a", "b.pem")
			Expect(os.MkdirAll(filepath.Dir(nested), DirPerm)).To(Succeed())
			Expect(os.WriteFile(nested, []byte("csr"), 0o644)).To(Succeed())

			Expect(op(ctx, b, CSRKey("a/b"))).To(MatchError(ContainSubstring("contains '/'")))
			Expect(nested).To(BeARegularFile(), "a refused key must leave the file alone")
		},
		Entry("Get", opGet),
		Entry("Exists", opExists),
		Entry("ModTime", opModTime),
		Entry("Delete", opDelete),
	)

	It("still stores and reads a subject containing a space", func() {
		Expect(b.Put(ctx, CSRKey("puppet ca host"), []byte("csr"), BlobPublic)).To(Succeed())
		Expect(b.Get(ctx, CSRKey("puppet ca host"))).To(Equal([]byte("csr")))
	})
})

var _ = Describe("SQLBackend refusing an unsafe key", func() {
	// The SQL backend calls validateKey separately in each method, rather than
	// through one translation function, so each method gets its own row.
	DescribeTable("refuses",
		func(op backendOp, key string) {
			b := newSQLiteBackend()
			DeferCleanup(b.Close)
			Expect(op(context.Background(), b, key)).To(MatchError(ContainSubstring("invalid key")))
		},
		Entry("Get with '/'", opGet, CSRKey("a/b")),
		Entry("Put with '/'", opPut, CSRKey("a/b")),
		Entry("AppendLine with '/'", opAppendLine, CertKey("a/b")),
		Entry("Delete with '/'", opDelete, CSRKey("a/b")),
		Entry("Exists with '/'", opExists, CertKey("a/b")),
		Entry("ModTime with '/'", opModTime, CSRKey("a/b")),
		Entry("Put with a control character", opPut, CSRKey("a\nb")),
		Entry("Get with a control character", opGet, CertKey("a\x00b")),
	)
})

var _ = Describe("SavePrivateKey refusing an unsafe subject", func() {
	// Private keys bypass the backend, so validateKey never sees their path;
	// SavePrivateKey checks the subject itself. Like the backends', this is
	// defence in depth: every caller has run ca.ValidateSubject first.
	DescribeTable("refuses, and writes nothing anywhere",
		func(subject, reason string) {
			dir := GinkgoT().TempDir()
			store := New(dir)
			Expect(store.EnsureDirs(context.Background())).To(Succeed())
			before := treeOf(dir)

			err := store.SavePrivateKey(context.Background(), subject, []byte("key"))
			Expect(err).To(MatchError(ContainSubstring("invalid private key subject")))
			Expect(err).To(MatchError(ContainSubstring(reason)))
			Expect(treeOf(dir)).To(Equal(before))
		},
		Entry("an empty subject", "", "empty name"),
		Entry("traversal out of the key directory", "../escape", "contains '..'"),
		Entry("a '/', which would need a subdirectory", "a/b", "contains '/'"),
		Entry("a newline", "a\nb", "control character U+000A"),
		Entry("a DEL", "a\x7fb", "control character U+007F"),
		Entry("a raw C1 byte", "a\x9bb", "not valid UTF-8"),
	)

	It("still writes a subject containing a space", func() {
		dir := GinkgoT().TempDir()
		store := New(dir)
		Expect(store.EnsureDirs(context.Background())).To(Succeed())
		Expect(store.SavePrivateKey(context.Background(), "puppet ca host", []byte("key"))).To(Succeed())
		Expect(os.ReadFile(store.PrivateKeyPath("puppet ca host"))).To(Equal([]byte("key")))
	})
})
