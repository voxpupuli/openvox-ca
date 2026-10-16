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
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

var _ = Describe("applyServerEnv SQL settings", func() {
	It("applies all SQL-related env vars", func() {
		setEnv("PUPPET_CA_STORAGE_BACKEND", "sqlite")
		setEnv("PUPPET_CA_SQL_DSN", "file:/var/lib/openvox-ca/ca.db")
		setEnv("PUPPET_CA_SQL_REQUEST_TIMEOUT_SEC", "15")
		setEnv("PUPPET_CA_SQL_MAX_OPEN_CONNS", "8")
		setEnv("PUPPET_CA_SQL_MAX_IDLE_CONNS", "4")
		setEnv("PUPPET_CA_SQL_MIGRATION_TIMEOUT_SEC", "1800")
		setEnv("PUPPET_CA_SQL_DSN_FILE", "/run/secrets/sql-dsn")

		cfg := &serverConfig{}
		applyServerEnv(cfg)

		Expect(cfg.StorageBackend).To(Equal("sqlite"), "StorageBackend = %q, want sqlite", cfg.StorageBackend)
		Expect(cfg.SQLDSN).To(Equal("file:/var/lib/openvox-ca/ca.db"), "SQLDSN = %q", cfg.SQLDSN)
		Expect(cfg.SQLRequestTimeoutSec).To(Equal(15), "SQLRequestTimeoutSec = %d, want 15", cfg.SQLRequestTimeoutSec)
		Expect(cfg.SQLMaxOpenConns).To(Equal(8), "SQLMaxOpenConns = %d, want 8", cfg.SQLMaxOpenConns)
		Expect(cfg.SQLMaxIdleConns).To(Equal(4), "SQLMaxIdleConns = %d, want 4", cfg.SQLMaxIdleConns)
		// This spec's name claims every SQL variable, and the migration budget
		// shipped without one: the YAML key and the docs advertised it while the
		// env hop did not exist, so a container deployment silently got the
		// default -- which is the half-migrated schema the knob exists to prevent.
		Expect(cfg.SQLMigrationTimeoutSec).To(Equal(1800),
			"SQLMigrationTimeoutSec = %d, want 1800", cfg.SQLMigrationTimeoutSec)
		Expect(cfg.SQLDSNFile).To(Equal("/run/secrets/sql-dsn"), "SQLDSNFile = %q", cfg.SQLDSNFile)
	})
})

var _ = Describe("--sql-dsn and --sql-dsn-file", func() {
	const secret = "SUPERSECRET"

	Describe("the --sql-dsn help text", func() {
		// The help used to demonstrate 'user:pass@' in both networked forms,
		// teaching operators to put the password where every local user can
		// read it.
		It("does not demonstrate a password, and names the private routes", func() {
			usage := newRootCmd().Flags().Lookup("sql-dsn").Usage
			// Any "user:secret@" shape, not just the old spelling.
			Expect(usage).NotTo(MatchRegexp(`[^\s'@:/]+:[^\s'@]+@`))
			Expect(usage).To(ContainSubstring("--sql-dsn-file"))
			Expect(usage).To(ContainSubstring("PUPPET_CA_SQL_DSN"))
			Expect(usage).To(ContainSubstring("sql_dsn"))
		})
	})

	Describe("warnSQLDSNPasswordOnCommandLine", func() {
		var (
			buf  bytes.Buffer
			orig *slog.Logger
		)

		BeforeEach(func() {
			buf.Reset()
			orig = slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			DeferCleanup(func() { slog.SetDefault(orig) })
		})

		// warnFor parses args with the real root command's flag set, so the
		// flag's name and Changed state are the ones the server sees.
		warnFor := func(args ...string) string {
			GinkgoHelper()
			flags := newRootCmd().Flags()
			Expect(flags.Parse(args)).To(Succeed())
			warnSQLDSNPasswordOnCommandLine(flags)
			return buf.String()
		}

		DescribeTable("warns about a password on the command line, without repeating it",
			func(dsn string) {
				out := warnFor("--sql-dsn", dsn)
				Expect(out).To(ContainSubstring("--sql-dsn contains a database password"))
				Expect(out).To(ContainSubstring("--sql-dsn-file"))
				Expect(out).NotTo(ContainSubstring(secret))
			},
			Entry("PostgreSQL", "postgres://ca:"+secret+"@db:5432/ca?sslmode=require"),
			Entry("MySQL", "ca:"+secret+"@tcp(db:3306)/ca"),
		)

		It("warns whichever backend is selected, since argv is exposed regardless", func() {
			// The issue's own reproduction: a postgres DSN with a password,
			// passed alongside --storage-backend sqlite.
			out := warnFor("--storage-backend", "sqlite", "--sql-dsn", "postgres://ca:"+secret+"@db/ca")
			Expect(out).To(ContainSubstring("--sql-dsn contains a database password"))
		})

		It("is silent for a DSN with no password", func() {
			Expect(warnFor("--sql-dsn", "postgres://ca@db:5432/ca?sslmode=require")).To(BeEmpty())
		})

		It("is silent when --sql-dsn is not on the command line", func() {
			// The same DSN arriving by environment or config file is not in
			// argv, so there is nothing to warn about.
			setEnv("PUPPET_CA_SQL_DSN", "postgres://ca:"+secret+"@db/ca")
			Expect(warnFor("--cadir", "/tmp/x")).To(BeEmpty())
		})

		Describe("through the server command", func() {
			var caDir, emptyConfig, logFile string

			BeforeEach(func() {
				clearServerEnv()
				caDir = GinkgoT().TempDir()
				emptyConfig = filepath.Join(GinkgoT().TempDir(), "config.yaml")
				Expect(os.WriteFile(emptyConfig, nil, 0o600)).To(Succeed())
				logFile = filepath.Join(GinkgoT().TempDir(), "ca.log")
			})

			// execute runs the root command, bounded so that a refusal which
			// regressed fails the spec rather than hanging it.
			execute := func(args ...string) error {
				GinkgoHelper()
				cmd := newRootCmd()
				cmd.SetOut(GinkgoWriter)
				cmd.SetErr(GinkgoWriter)
				cmd.SetArgs(append([]string{"--config", emptyConfig, "--cadir", caDir,
					"--sql-dsn", "postgres://ca:" + secret + "@db/ca"}, args...))
				done := make(chan error, 1)
				go func() { done <- cmd.Execute() }()
				var err error
				Eventually(done, "30s").Should(Receive(&err))
				return err
			}

			// The TLS refusal comes straight after a server role configures
			// its logger, so these specs read the log a role wrote without
			// any server starting.
			const plainHTTPRefusal = "plain HTTP on a non-loopback address"
			const warning = "--sql-dsn contains a database password"

			It("reaches logfile from the process the operator started", func() {
				// --single-process takes the same path as the launcher up to
				// the point where the launcher would fork.
				err := execute("--single-process", "--host", "0.0.0.0", "--port", "0", "--logfile", logFile)
				Expect(err).To(MatchError(ContainSubstring(plainHTTPRefusal)))

				logged, readErr := os.ReadFile(logFile)
				Expect(readErr).NotTo(HaveOccurred())
				Expect(strings.Count(string(logged), warning)).To(Equal(1), "said exactly once")
				Expect(string(logged)).NotTo(ContainSubstring(secret))
				// buf is the handler in place before the role's logger: a call
				// ahead of it would land here instead of, or as well as, logfile.
				Expect(buf.String()).NotTo(ContainSubstring(warning))
			})

			It("is not repeated by the frontend, which carries the same argv", func() {
				setEnv("PUPPET_CA_ROLE", "frontend")
				err := execute("--host", "0.0.0.0", "--port", "0", "--logfile", logFile)
				Expect(err).To(MatchError(ContainSubstring(plainHTTPRefusal)))

				logged, readErr := os.ReadFile(logFile)
				Expect(readErr).NotTo(HaveOccurred())
				Expect(string(logged)).To(ContainSubstring("Starting Puppet CA"),
					"the frontend must have reached its logger for its silence to mean anything")
				Expect(string(logged)).NotTo(ContainSubstring(warning))
				Expect(buf.String()).NotTo(ContainSubstring(warning), "nor before its logger existed")
			})

			It("is not said by the signer, which carries the same argv", func() {
				// Without a launcher the signer fails for its own reasons --
				// there is no socket to serve -- after configuring its logger.
				bootstrapCAInDir(caDir, "puppet.example.com")
				setEnv("PUPPET_CA_ROLE", "signer")
				Expect(execute("--host", "127.0.0.1", "--port", "0", "--logfile", logFile)).To(HaveOccurred())

				Expect(buf.String()).NotTo(ContainSubstring(warning))
				logged, readErr := os.ReadFile(logFile)
				Expect(readErr).NotTo(HaveOccurred())
				Expect(string(logged)).To(ContainSubstring("Starting CA signer process"),
					"the signer must have reached its logger for its silence to mean anything")
				Expect(string(logged)).NotTo(ContainSubstring(warning))
			})

			It("is said by a --daemon parent before it forks, whose child's stderr is discarded", func() {
				// Holding the store makes the parent refuse before the fork,
				// the way a second instance would; the warning must already
				// have been said by then.
				ul, err := storage.New(caDir).AcquireInstanceLock(context.Background())
				Expect(err).NotTo(HaveOccurred())
				DeferCleanup(func() { _ = ul.Unlock() })

				err = execute("--host", "127.0.0.1", "--port", "0", "--daemon")
				Expect(err).To(MatchError(ContainSubstring("already running against this store")))
				Expect(buf.String()).To(ContainSubstring("--sql-dsn contains a database password"))
				Expect(buf.String()).NotTo(ContainSubstring(secret))
			})
		})
	})

	Describe("--sql-dsn-file through the server command", func() {
		var caDir, emptyConfig string

		BeforeEach(func() {
			clearServerEnv()
			caDir = GinkgoT().TempDir()
			// Pinned so a /etc/openvox-ca/config.yaml on the host cannot
			// supply a DSN of its own.
			emptyConfig = filepath.Join(GinkgoT().TempDir(), "config.yaml")
			Expect(os.WriteFile(emptyConfig, nil, 0o600)).To(Succeed())
		})

		// execute runs the root command, bounded: if a refusal regressed, a DSN
		// that did resolve would start a server and never return.
		// --single-process keeps that server in this process. Without it the
		// launcher would fork os.Executable(), which here is the test binary,
		// and each child would re-run this spec.
		execute := func(args ...string) error {
			GinkgoHelper()
			cmd := newRootCmd()
			cmd.SetOut(GinkgoWriter)
			cmd.SetErr(GinkgoWriter)
			cmd.SetArgs(append([]string{"--config", emptyConfig, "--cadir", caDir, "--single-process",
				"--host", "127.0.0.1", "--port", "0", "--storage-backend", "sqlite"}, args...))
			done := make(chan error, 1)
			go func() { done <- cmd.Execute() }()
			var err error
			Eventually(done, "30s").Should(Receive(&err))
			return err
		}

		It("reaches the backend, which reads the file it names", func() {
			missing := filepath.Join(GinkgoT().TempDir(), "no-such-dsn")
			err := execute("--sql-dsn-file", missing)
			Expect(err).To(MatchError(ContainSubstring("reading sql_dsn_file")))
			Expect(err).To(MatchError(ContainSubstring(missing)))
		})

		DescribeTable("is refused alongside sql_dsn from any other source",
			func(config string, env map[string]string, args ...string) {
				// Each source writes its own field and the storage layer
				// refuses both, so no source may clear the other's.
				dsnFile := filepath.Join(GinkgoT().TempDir(), "dsn")
				Expect(os.WriteFile(dsnFile, []byte("file:"+filepath.Join(caDir, "a.db")+"\n"), 0o600)).To(Succeed())
				other := "file:" + filepath.Join(caDir, "b.db")
				expand := strings.NewReplacer("DSNFILE", dsnFile, "OTHER", other).Replace
				Expect(os.WriteFile(emptyConfig, []byte(expand(config)), 0o600)).To(Succeed())
				for k, v := range env {
					setEnv(k, expand(v))
				}
				expanded := make([]string, len(args))
				for i, a := range args {
					expanded[i] = expand(a)
				}
				Expect(execute(expanded...)).To(MatchError(ContainSubstring("mutually exclusive")))
			},
			Entry("config sql_dsn, env PUPPET_CA_SQL_DSN_FILE",
				"sql_dsn: OTHER\n", map[string]string{"PUPPET_CA_SQL_DSN_FILE": "DSNFILE"}),
			Entry("env PUPPET_CA_SQL_DSN, --sql-dsn-file",
				"", map[string]string{"PUPPET_CA_SQL_DSN": "OTHER"}, "--sql-dsn-file", "DSNFILE"),
			Entry("config sql_dsn_file, --sql-dsn",
				"sql_dsn_file: DSNFILE\n", nil, "--sql-dsn", "OTHER"),
			Entry("config sql_dsn_file, env PUPPET_CA_SQL_DSN",
				"sql_dsn_file: DSNFILE\n", map[string]string{"PUPPET_CA_SQL_DSN": "OTHER"}),
		)

		It("is refused alongside --sql-dsn", func() {
			dsnFile := filepath.Join(GinkgoT().TempDir(), "dsn")
			Expect(os.WriteFile(dsnFile, []byte("file:"+filepath.Join(caDir, "a.db")+"\n"), 0o600)).To(Succeed())
			err := execute("--sql-dsn-file", dsnFile, "--sql-dsn", "file:"+filepath.Join(caDir, "b.db"))
			Expect(err).To(MatchError(ContainSubstring("mutually exclusive")))
		})
	})
})

var _ = Describe("buildBackendSpec", func() {
	DescribeTable("SQLite aliases",
		func(alias string) {
			cfg := &serverConfig{
				StorageConfig: config.StorageConfig{
					StorageBackend:       alias,
					SQLDSN:               "file:/tmp/ca.db",
					SQLRequestTimeoutSec: 12,
				},
			}
			spec, err := buildBackendSpec(cfg, "/abs/cadir")
			Expect(err).NotTo(HaveOccurred(), "buildBackendSpec")
			Expect(spec.Kind).To(Equal(storage.BackendSQLite), "Kind = %q, want %q", spec.Kind, storage.BackendSQLite)
			Expect(spec.SQL.DSN).To(Equal("file:/tmp/ca.db"), "SQL.DSN = %q", spec.SQL.DSN)
			Expect(spec.SQL.RequestTimeoutSec).To(Equal(12), "SQL.RequestTimeoutSec = %d, want 12", spec.SQL.RequestTimeoutSec)
			Expect(spec.LocalDir).To(Equal("/abs/cadir"), "LocalDir = %q, want /abs/cadir", spec.LocalDir)
		},
		Entry("sqlite", "sqlite"),
		Entry("sqlite3", "sqlite3"),
	)

	DescribeTable("Postgres aliases",
		func(alias string) {
			cfg := &serverConfig{
				StorageConfig: config.StorageConfig{
					StorageBackend: alias,
					SQLDSN:         "postgres://u:p@host:5432/db?sslmode=require",
					SQLTLSCAFile:   "/etc/pg-ca.pem",
				},
			}
			spec, err := buildBackendSpec(cfg, "/abs/cadir")
			Expect(err).NotTo(HaveOccurred(), "buildBackendSpec")
			Expect(spec.Kind).To(Equal(storage.BackendPostgres), "Kind = %q, want %q", spec.Kind, storage.BackendPostgres)
			Expect(spec.SQL.DSN).To(Equal(cfg.SQLDSN), "SQL.DSN = %q", spec.SQL.DSN)
			Expect(spec.SQL.TLSCAFile).To(Equal("/etc/pg-ca.pem"), "SQL.TLSCAFile = %q", spec.SQL.TLSCAFile)
		},
		Entry("postgres", "postgres"),
		Entry("postgresql", "postgresql"),
		Entry("pg", "pg"),
	)

	DescribeTable("MySQL aliases",
		func(alias string) {
			cfg := &serverConfig{
				StorageConfig: config.StorageConfig{
					StorageBackend: alias,
					SQLDSN:         "puppetca:secret@tcp(db:3306)/puppetca",
				},
			}
			spec, err := buildBackendSpec(cfg, "/abs/cadir")
			Expect(err).NotTo(HaveOccurred(), "buildBackendSpec")
			Expect(spec.Kind).To(Equal(storage.BackendMySQL), "Kind = %q, want %q", spec.Kind, storage.BackendMySQL)
			Expect(spec.SQL.DSN).To(Equal(cfg.SQLDSN), "SQL.DSN = %q", spec.SQL.DSN)
		},
		Entry("mysql", "mysql"),
		Entry("mariadb", "mariadb"),
	)
})

var _ = Describe("NewServiceFromSpec", func() {
	It("returns an error when the SQLite DSN is empty", func() {
		_, err := storage.NewServiceFromSpec(storage.BackendSpec{
			Kind:     storage.BackendSQLite,
			LocalDir: GinkgoT().TempDir(),
		})
		Expect(err).To(HaveOccurred(), "expected error when sql_dsn is empty, got nil")
	})
})
