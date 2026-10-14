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

//go:build postgres_integration

package storage

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/uptrace/bun/driver/pgdriver"
)

// servePostgresTLS switches the test server's TLS on with a certificate issued
// by ca for certHost, and back off when the spec ends. The fixture runs
// PostgreSQL without TLS, so this writes the files into the server's data
// directory and enables them with ALTER SYSTEM, which needs the DSN's role to
// be a superuser — as the compose fixture's is. It writes through COPY TO
// PROGRAM rather than COPY TO a file because only the former can set a umask:
// COPY creates files 0644, and PostgreSQL refuses a key anyone else can read.
func servePostgresTLS(dsn string, ca *pgTestCA, certHost string) {
	certPEM, keyPEM := ca.issueServer(certHost)
	db := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	DeferCleanup(db.Close)
	ctx := context.Background()

	var dataDir string
	Expect(db.QueryRowContext(ctx, "SHOW data_directory").Scan(&dataDir)).To(Succeed())
	// A name unique to this spec, so the wait below cannot be satisfied by an
	// earlier spec's configuration.
	stem := filepath.Join(dataDir, fmt.Sprintf("openvox-ca-test-%d", time.Now().UnixNano()))
	// Registered before anything changes, so a failure part-way through still
	// puts the server back. RESET of a setting never set is a no-op, as is
	// rm -f of a file never written.
	DeferCleanup(func() {
		for _, stmt := range []string{
			"ALTER SYSTEM RESET ssl",
			"ALTER SYSTEM RESET ssl_cert_file",
			"ALTER SYSTEM RESET ssl_key_file",
			"SELECT pg_reload_conf()",
			fmt.Sprintf("COPY (SELECT 1) TO PROGRAM 'rm -f %s.crt %s.key'", stem, stem),
		} {
			_, err := db.ExecContext(ctx, stmt)
			Expect(err).NotTo(HaveOccurred(), stmt)
		}
	})
	write := func(path string, content []byte) {
		// COPY's text format escapes newlines inside a value, so write one
		// row per line. PEM lines hold no quote, backslash or tab.
		_, err := db.ExecContext(ctx, fmt.Sprintf(
			"COPY (SELECT unnest(string_to_array('%s', E'\\n'))) TO PROGRAM 'umask 077 && cat > %s'",
			strings.TrimSpace(string(content)), path))
		Expect(err).NotTo(HaveOccurred(), "writing %s on the server; the DSN's role must be a superuser", path)
	}
	write(stem+".crt", certPEM)
	write(stem+".key", keyPEM)

	for _, stmt := range []string{
		fmt.Sprintf("ALTER SYSTEM SET ssl_cert_file = '%s.crt'", stem),
		fmt.Sprintf("ALTER SYSTEM SET ssl_key_file = '%s.key'", stem),
		"ALTER SYSTEM SET ssl = on",
		"SELECT pg_reload_conf()",
	} {
		_, err := db.ExecContext(ctx, stmt)
		Expect(err).NotTo(HaveOccurred(), stmt)
	}

	// The postmaster applies a reload asynchronously, and each new backend
	// inherits its settings, so a fresh connection reporting this spec's
	// certificate means the next one will be offered it.
	Eventually(func(g Gomega) {
		fresh := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
		defer fresh.Close()
		var ssl, certFile string
		g.Expect(fresh.QueryRowContext(ctx, "SELECT current_setting('ssl'), current_setting('ssl_cert_file')").Scan(&ssl, &certFile)).To(Succeed())
		g.Expect(ssl).To(Equal("on"))
		g.Expect(certFile).To(Equal(stem + ".crt"))
	}).WithTimeout(10 * time.Second).WithPolling(100 * time.Millisecond).Should(Succeed())
}

// "Postgres TLS" connects to a TLS-enabled PostgreSQL both ways an operator
// can give it a CA: the sql_tls_ca_file option, loaded by loadSQLTLS exactly as
// the server loads it, and the DSN's own sslrootcert, which pgdriver handles
// itself. Each is driven under verify-full and under require, which with a CA
// means libpq's verify-ca, to pin that one sslmode means the same thing either
// way. Serial, because servePostgresTLS reconfigures the whole server.
var _ = Describe("Postgres TLS", Serial, func() {
	var (
		host    string
		dsn     *url.URL
		trusted *pgTestCA
		caFile  string
		open    func() *SQLBackend
	)

	BeforeEach(func() {
		var err error
		dsn, err = url.Parse(postgresDSNFromEnv())
		Expect(err).NotTo(HaveOccurred())
		host = dsn.Hostname()
		Expect(host).NotTo(BeEmpty(), "OPENVOX_CA_TEST_POSTGRES_DSN must name a TCP host for the TLS specs")

		trusted = newPGTestCA("openvox-ca test PostgreSQL CA")
		caFile = filepath.Join(GinkgoT().TempDir(), "pg-ca.pem")
		Expect(os.WriteFile(caFile, trusted.pem, 0o600)).To(Succeed())
	})

	// withSSL returns the test DSN with the given query parameters replaced.
	withSSL := func(params map[string]string) string {
		u := *dsn
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
		return u.String()
	}

	viaFile := func(sslmode string) func() *SQLBackend {
		return func() *SQLBackend {
			tlsCfg, err := loadSQLTLS(SQLSpec{TLSCAFile: caFile})
			Expect(err).NotTo(HaveOccurred())
			b, err := NewSQLBackend(SQLConfig{
				Dialect: SQLPostgres,
				DSN:     withSSL(map[string]string{"sslmode": sslmode}),
				TLS:     tlsCfg,
			})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })
			return b
		}
	}

	viaDSN := func(sslmode string) func() *SQLBackend {
		return func() *SQLBackend {
			b, err := NewSQLBackend(SQLConfig{
				Dialect: SQLPostgres,
				DSN:     withSSL(map[string]string{"sslmode": sslmode, "sslrootcert": caFile}),
			})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })
			return b
		}
	}

	connectsToTheTrustedServer := func() {
		It("connects over TLS to a server whose certificate it trusts", func() {
			servePostgresTLS(postgresDSNFromEnv(), trusted, host)
			b := open()
			ctx := context.Background()
			Expect(b.db.PingContext(ctx)).To(Succeed())
			var encrypted bool
			Expect(b.db.QueryRowContext(ctx,
				"SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&encrypted)).To(Succeed())
			Expect(encrypted).To(BeTrue(), "the session is not using TLS")
		})

		It("refuses a server whose certificate the CA file does not trust", func() {
			stranger := newPGTestCA("some other CA")
			servePostgresTLS(postgresDSNFromEnv(), stranger, host)
			err := open().db.PingContext(context.Background())
			var unknown x509.UnknownAuthorityError
			Expect(errors.As(err, &unknown)).To(BeTrue(), "want an unknown-authority error, got: %v", err)
		})
	}

	checksTheName := func() {
		connectsToTheTrustedServer()

		It("refuses a trusted certificate issued for another host", func() {
			servePostgresTLS(postgresDSNFromEnv(), trusted, "not-the-database.example")
			err := open().db.PingContext(context.Background())
			var mismatch x509.HostnameError
			Expect(errors.As(err, &mismatch)).To(BeTrue(), "want a hostname mismatch, got: %v", err)
		})
	}

	checksTheChainOnly := func() {
		connectsToTheTrustedServer()

		It("accepts a trusted certificate issued for another host, as libpq's verify-ca does", func() {
			servePostgresTLS(postgresDSNFromEnv(), trusted, "not-the-database.example")
			Expect(open().db.PingContext(context.Background())).To(Succeed())
		})
	}

	Context("via sql_tls_ca_file with sslmode=verify-full", func() {
		BeforeEach(func() { open = viaFile("verify-full") })

		checksTheName()

		// pgdriver dials a TCP host= in preference to the URL's host, so
		// that is the name to verify: with the URL naming a decoy, only a
		// ServerName taken from what is dialled can succeed.
		It("verifies the host= it dials, not the URL's host", func() {
			servePostgresTLS(postgresDSNFromEnv(), trusted, host)
			u := *dsn
			u.Host = "decoy.invalid:5432"
			q := u.Query()
			q.Set("host", dsn.Host)
			q.Set("sslmode", "verify-full")
			u.RawQuery = q.Encode()
			tlsCfg, err := loadSQLTLS(SQLSpec{TLSCAFile: caFile})
			Expect(err).NotTo(HaveOccurred())
			b, err := NewSQLBackend(SQLConfig{Dialect: SQLPostgres, DSN: u.String(), TLS: tlsCfg})
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = b.Close() })
			Expect(b.db.PingContext(context.Background())).To(Succeed())
		})
	})

	Context("via the DSN's sslrootcert with sslmode=verify-full", func() {
		BeforeEach(func() { open = viaDSN("verify-full") })

		checksTheName()
	})

	Context("via sql_tls_ca_file with sslmode=require", func() {
		BeforeEach(func() { open = viaFile("require") })

		checksTheChainOnly()
	})

	Context("via the DSN's sslrootcert with sslmode=require", func() {
		BeforeEach(func() { open = viaDSN("require") })

		checksTheChainOnly()
	})

	Context("via sql_tls_ca_file with sslmode=verify-ca", func() {
		BeforeEach(func() { open = viaFile("verify-ca") })

		checksTheChainOnly()
	})

	Context("via the DSN's sslrootcert with sslmode=verify-ca", func() {
		BeforeEach(func() { open = viaDSN("verify-ca") })

		checksTheChainOnly()
	})

	// With only a client certificate and sslmode=require there is no CA to
	// check against, and libpq checks nothing: the connection is encrypted
	// but any server is accepted. The fixture does not ask for a client
	// certificate, so this also shows sql_tls_cert_file and sql_tls_key_file
	// load and open without disturbing the handshake.
	Context("via sql_tls_cert_file alone with sslmode=require", func() {
		BeforeEach(func() {
			certPEM, keyPEM := newPGTestCA("client CA").issueServer("openvox-ca")
			dir := GinkgoT().TempDir()
			certFile := filepath.Join(dir, "client.pem")
			keyFile := filepath.Join(dir, "client-key.pem")
			Expect(os.WriteFile(certFile, certPEM, 0o600)).To(Succeed())
			Expect(os.WriteFile(keyFile, keyPEM, 0o600)).To(Succeed())
			open = func() *SQLBackend {
				tlsCfg, err := loadSQLTLS(SQLSpec{TLSCertFile: certFile, TLSKeyFile: keyFile})
				Expect(err).NotTo(HaveOccurred())
				b, err := NewSQLBackend(SQLConfig{
					Dialect: SQLPostgres,
					DSN:     withSSL(map[string]string{"sslmode": "require"}),
					TLS:     tlsCfg,
				})
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = b.Close() })
				return b
			}
		})

		It("encrypts the connection to a server from any CA", func() {
			servePostgresTLS(postgresDSNFromEnv(), newPGTestCA("some other CA"), "not-the-database.example")
			b := open()
			ctx := context.Background()
			Expect(b.db.PingContext(ctx)).To(Succeed())
			var encrypted bool
			Expect(b.db.QueryRowContext(ctx,
				"SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&encrypted)).To(Succeed())
			Expect(encrypted).To(BeTrue(), "the session is not using TLS")
		})
	})
})
