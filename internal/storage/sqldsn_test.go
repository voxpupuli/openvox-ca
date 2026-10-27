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
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// secret is the password every fixture DSN below carries, so a spec can assert
// that no error or message repeats it.
const secret = "SUPERSECRET"

var _ = Describe("resolveSQLDSN", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	writeFile := func(name, content string) string {
		GinkgoHelper()
		path := filepath.Join(dir, name)
		Expect(os.WriteFile(path, []byte(content), 0o600)).To(Succeed())
		return path
	}

	It("returns sql_dsn when only it is set", func() {
		dsn, err := resolveSQLDSN(SQLSpec{DSN: "file:/var/lib/openvox-ca/ca.db"})
		Expect(err).NotTo(HaveOccurred())
		Expect(dsn).To(Equal("file:/var/lib/openvox-ca/ca.db"))
	})

	It("reads the first line of sql_dsn_file, trimmed, when only it is set", func() {
		// A Kubernetes Secret or `echo` leaves a trailing newline, and an
		// editor may leave surrounding blanks; neither may reach the driver.
		path := writeFile("dsn", "  postgres://ca:"+secret+"@db:5432/ca  \nsecond line\n")

		dsn, err := resolveSQLDSN(SQLSpec{DSNFile: path})
		Expect(err).NotTo(HaveOccurred())
		Expect(dsn).To(Equal("postgres://ca:" + secret + "@db:5432/ca"))
	})

	It("refuses both, rather than silently preferring one", func() {
		path := writeFile("dsn", "postgres://ca:other@db:5432/ca\n")

		_, err := resolveSQLDSN(SQLSpec{DSN: "postgres://ca:" + secret + "@db:5432/ca", DSNFile: path})
		Expect(err).To(MatchError(ContainSubstring("mutually exclusive")))
		Expect(err.Error()).NotTo(ContainSubstring(secret))
		Expect(err.Error()).NotTo(ContainSubstring("other"))
	})

	It("refuses neither, naming both keys", func() {
		_, err := resolveSQLDSN(SQLSpec{})
		Expect(err).To(MatchError("sql backend requires sql_dsn or sql_dsn_file"))
	})

	It("names the path of a sql_dsn_file that does not exist", func() {
		path := filepath.Join(dir, "missing")

		_, err := resolveSQLDSN(SQLSpec{DSNFile: path})
		Expect(err).To(MatchError(fs.ErrNotExist))
		Expect(err).To(MatchError(ContainSubstring(path)))
	})

	DescribeTable("refuses a sql_dsn_file with no DSN on its first line",
		func(content string) {
			path := writeFile("dsn", content)

			_, err := resolveSQLDSN(SQLSpec{DSNFile: path})
			Expect(err).To(MatchError(ContainSubstring(path + " is empty")))
		},
		Entry("an empty file", ""),
		Entry("a blank first line", "   \npostgres://ca:"+secret+"@db/ca\n"),
	)

	It("does not repeat the file's contents when a line is too long to read", func() {
		// bufio.Scanner's default limit is 64 KiB; the error it reports there
		// must name the path, never what was read.
		line := "postgres://ca:" + secret + "@db/" + string(make([]byte, 70*1024))
		path := writeFile("dsn", line)

		_, err := resolveSQLDSN(SQLSpec{DSNFile: path})
		Expect(err).To(MatchError(bufio.ErrTooLong), "the cause, not a claim that the file is empty")
		Expect(err).To(MatchError(ContainSubstring(path)))
		Expect(err.Error()).NotTo(ContainSubstring(secret))
	})
})

var _ = Describe("NewServiceFromSpec with sql_dsn_file", func() {
	It("opens the SQLite database the file names", func() {
		dir := GinkgoT().TempDir()
		dbPath := filepath.Join(dir, "ca.db")
		dsnFile := filepath.Join(dir, "dsn")
		Expect(os.WriteFile(dsnFile, []byte("file:"+dbPath+"\n"), 0o600)).To(Succeed())

		svc, err := NewServiceFromSpec(BackendSpec{
			Kind:     BackendSQLite,
			LocalDir: dir,
			SQL:      SQLSpec{DSNFile: dsnFile},
		})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(svc.Backend().Close)
		// SQLite creates the file on first use, not on open.
		Expect(svc.Backend().EnsureReady(context.Background())).To(Succeed())
		Expect(dbPath).To(BeAnExistingFile(), "the DSN read from the file must be the one opened")
	})

	It("refuses sql_dsn and sql_dsn_file together", func() {
		dir := GinkgoT().TempDir()
		dsnFile := filepath.Join(dir, "dsn")
		Expect(os.WriteFile(dsnFile, []byte("file:"+filepath.Join(dir, "a.db")+"\n"), 0o600)).To(Succeed())

		_, err := NewServiceFromSpec(BackendSpec{
			Kind:     BackendSQLite,
			LocalDir: dir,
			SQL:      SQLSpec{DSN: "file:" + filepath.Join(dir, "b.db"), DSNFile: dsnFile},
		})
		Expect(err).To(MatchError(ContainSubstring("mutually exclusive")))
	})
})

var _ = Describe("DSNHasPassword", func() {
	DescribeTable("reports whether the DSN carries a password",
		func(dsn string, want bool) {
			Expect(DSNHasPassword(dsn)).To(Equal(want))
		},
		Entry("postgres:// with a password", "postgres://ca:"+secret+"@db:5432/ca?sslmode=require", true),
		Entry("postgresql:// with a password", "postgresql://ca:"+secret+"@db/ca", true),
		Entry("unix:// with a password", "unix://ca:"+secret+"@ca/run/postgresql/.s.PGSQL.5432", true),
		Entry("postgres:// with a user and no password", "postgres://ca@db:5432/ca", false),
		Entry("postgres:// with an empty password", "postgres://ca:@db:5432/ca", false),
		Entry("postgres:// with no userinfo", "postgres://db:5432/ca?sslmode=require", false),
		Entry("MySQL with a password", "ca:"+secret+"@tcp(db:3306)/ca", true),
		// url.Parse reads each of these as an opaque URL whose scheme is the
		// user name, so the scheme alone must not route them to pgdriver's
		// reading, which would find no userinfo.
		Entry("MySQL with a password, for a user named postgres", "postgres:"+secret+"@tcp(db:3306)/ca", true),
		Entry("MySQL with a password, for a user named postgresql", "postgresql:"+secret+"@tcp(db:3306)/ca", true),
		Entry("MySQL with a password, for a user named unix", "unix:"+secret+"@tcp(db:3306)/ca", true),
		Entry("MySQL with a user and no password", "ca@tcp(db:3306)/ca", false),
		Entry("MySQL with no userinfo", "tcp(db:3306)/ca", false),
		Entry("a SQLite file: URI", "file:/var/lib/openvox-ca/ca.db", false),
		Entry("a SQLite file: URI with parameters", "file:/var/lib/openvox-ca/ca.db?_pragma=busy_timeout(5000)", false),
		Entry("a bare SQLite path", "/var/lib/openvox-ca/ca.db", false),
		Entry("an empty DSN", "", false),
		// A known false negative, pinned so that changing it is a decision:
		// url.Parse rejects the port, and MySQL's grammar cannot place the
		// host, so neither parser vouches for the password. Such a DSN cannot
		// open a PostgreSQL backend either, so the server refuses it when it
		// is the one in use.
		Entry("a password-bearing postgres:// URL that url.Parse rejects", "postgres://ca:"+secret+"@db:54 32/ca", false),
	)
})

var _ = Describe("NewSQLBackend for PostgreSQL", func() {
	// Driven through NewSQLBackend rather than openSQLDB, whose signature
	// other changes extend: this pins the wiring, not just the helper.
	It("refuses a malformed DSN with an error that does not repeat it", func() {
		// pgdriver.WithDSN panics on a DSN url.Parse rejects, and the panic
		// value quotes the whole DSN. The invalid port is what makes it fail.
		var (
			b   *SQLBackend
			err error
		)
		Expect(func() {
			b, err = NewSQLBackend(SQLConfig{Dialect: SQLPostgres, DSN: "postgres://ca:" + secret + "@db:54 32/ca"})
		}).NotTo(Panic())
		Expect(err).To(MatchError(errPostgresDSNMalformed))
		Expect(err.Error()).NotTo(ContainSubstring(secret))
		Expect(b).To(BeNil())
	})

	It("refuses a DSN pgdriver rejects by message rather than by url.Parse", func() {
		// "unix socket DSN requires a path: <dsn>" is the other pgdriver
		// message that repeats the DSN.
		var err error
		Expect(func() {
			_, err = NewSQLBackend(SQLConfig{Dialect: SQLPostgres, DSN: "unix://ca:" + secret + "@ca"})
		}).NotTo(Panic())
		Expect(err).To(MatchError(errPostgresDSNMalformed))
		Expect(err.Error()).NotTo(ContainSubstring(secret))
	})

	DescribeTable("names a TLS file the DSN points at that cannot be read, without repeating the DSN",
		func(query func(missing string) string) {
			// pgdriver reads these files while parsing, so an unmounted
			// Secret panics there too. That is not a malformed DSN, and the
			// path is what the operator needs.
			missing := filepath.Join(GinkgoT().TempDir(), "no-such.pem")
			_, err := NewSQLBackend(SQLConfig{Dialect: SQLPostgres,
				DSN: "postgres://ca:" + secret + "@127.0.0.1:1/ca?" + query(missing)})
			Expect(err).To(MatchError(fs.ErrNotExist))
			Expect(err).To(MatchError(ContainSubstring(missing)))
			Expect(err).NotTo(MatchError(errPostgresDSNMalformed))
			Expect(err.Error()).NotTo(ContainSubstring(secret))
		},
		Entry("sslrootcert", func(missing string) string {
			return "sslmode=verify-full&sslrootcert=" + missing
		}),
		Entry("sslcert and sslkey", func(missing string) string {
			return "sslmode=verify-full&sslcert=" + missing + "&sslkey=" + missing
		}),
	)

	It("withholds a parse failure that is not a file read", func() {
		// pgdriver's message here names only the sslmode, but which of its
		// messages repeat the DSN is not something to rely on.
		_, err := NewSQLBackend(SQLConfig{Dialect: SQLPostgres,
			DSN: "postgres://ca:" + secret + "@127.0.0.1:1/ca?sslmode=bogus"})
		Expect(err).To(MatchError(errPostgresDSNMalformed))
	})

	It("opens a well-formed DSN without dialling it", func() {
		// The handle is lazy, so this needs no server: it pins that the
		// recover wrapper passes a good connector through.
		b, err := NewSQLBackend(SQLConfig{Dialect: SQLPostgres, DSN: "postgres://ca:" + secret + "@127.0.0.1:1/ca"})
		Expect(err).NotTo(HaveOccurred())
		Expect(b).NotTo(BeNil())
		Expect(b.Close()).To(Succeed())
	})
})
