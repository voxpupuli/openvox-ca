// Copyright (C) 2026 Trevor Vaughan
// Copyright (C) 2026 Chris Boot
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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tvaughan/puppet-ca/internal/api"
	"github.com/tvaughan/puppet-ca/internal/ca"
	"github.com/tvaughan/puppet-ca/internal/signer"
	"github.com/tvaughan/puppet-ca/internal/storage"
)

// setupLogger creates and sets the default slog logger based on config.
// Returns the log file (if any) so the caller can close it on shutdown,
// ensuring final log entries are flushed. Returns nil when logging to stderr.
func setupLogger(cfg *serverConfig) (*os.File, error) {
	var logLevel slog.Level
	switch cfg.Verbosity {
	case 0:
		logLevel = slog.LevelInfo
	case 1:
		logLevel = slog.LevelDebug
	default:
		logLevel = slog.Level(-8) // Trace
	}

	opts := &slog.HandlerOptions{Level: logLevel}

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", cfg.LogFile, err)
		}
		slog.SetDefault(slog.New(slog.NewJSONHandler(f, opts)))
		return f, nil
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, opts)))
	return nil, nil
}

// buildBackendSpec derives a storage.BackendSpec from the server config. The
// spec is used to construct the StorageService in every mode (frontend,
// signer, single-process), ensuring backend selection happens in one place.
func buildBackendSpec(cfg *serverConfig, absCADir string) (storage.BackendSpec, error) {
	kind, err := storage.ParseBackendKind(cfg.StorageBackend)
	if err != nil {
		return storage.BackendSpec{}, err
	}
	spec := storage.BackendSpec{
		Kind:       kind,
		LocalDir:   absCADir,
		CACertFile: absIfSet(cfg.CACertFile),
		CAKeyFile:  absIfSet(cfg.CAKeyFile),
	}
	if kind == storage.BackendEtcd {
		spec.Etcd = storage.EtcdSpec{
			Endpoints:         cfg.EtcdEndpoints,
			KeyPrefix:         cfg.EtcdKeyPrefix,
			Username:          cfg.EtcdUsername,
			Password:          cfg.EtcdPassword,
			DialTimeoutSec:    cfg.EtcdDialTimeoutSec,
			RequestTimeoutSec: cfg.EtcdRequestTimeoutSec,
			TLSCAFile:         cfg.EtcdTLSCAFile,
			TLSCertFile:       cfg.EtcdTLSCertFile,
			TLSKeyFile:        cfg.EtcdTLSKeyFile,
		}
	}
	if kind == storage.BackendRedis {
		spec.Redis = storage.RedisSpec{
			Addrs:              cfg.RedisAddrs,
			SentinelMasterName: cfg.RedisSentinelMasterName,
			SentinelAddrs:      cfg.RedisSentinelAddrs,
			SentinelUsername:   cfg.RedisSentinelUsername,
			SentinelPassword:   cfg.RedisSentinelPassword,
			DB:                 cfg.RedisDB,
			Username:           cfg.RedisUsername,
			Password:           cfg.RedisPassword,
			KeyPrefix:          cfg.RedisKeyPrefix,
			DialTimeoutSec:     cfg.RedisDialTimeoutSec,
			RequestTimeoutSec:  cfg.RedisRequestTimeoutSec,
			LockTTLSec:         cfg.RedisLockTTLSec,
			TLSCAFile:          cfg.RedisTLSCAFile,
			TLSCertFile:        cfg.RedisTLSCertFile,
			TLSKeyFile:         cfg.RedisTLSKeyFile,
		}
	}
	if kind == storage.BackendSQLite {
		spec.SQL = storage.SQLSpec{
			DSN:               cfg.SQLDSN,
			RequestTimeoutSec: cfg.SQLRequestTimeoutSec,
			MaxOpenConns:      cfg.SQLMaxOpenConns,
			MaxIdleConns:      cfg.SQLMaxIdleConns,
			TLSCAFile:         cfg.SQLTLSCAFile,
			TLSCertFile:       cfg.SQLTLSCertFile,
			TLSKeyFile:        cfg.SQLTLSKeyFile,
		}
	}
	return spec, nil
}

// absIfSet returns filepath.Abs(p) when p is non-empty, otherwise "".
// Resolving at config time lets error messages and logs show canonical paths.
func absIfSet(p string) string {
	if p == "" {
		return ""
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

// applyCAConfig applies the common CA configuration fields from serverConfig
// to a CA instance. Used by both frontend and signer modes.
func applyCAConfig(myCA *ca.CA, cfg *serverConfig) error {
	if cfg.OCSPUrl != "" {
		myCA.OCSPURLs = []string{cfg.OCSPUrl}
	}
	if cfg.CRLUrl != "" {
		myCA.CRLURLs = []string{cfg.CRLUrl}
	}
	myCA.CRLValidityDays = cfg.CRLValidityDays

	if cfg.CAKeyAlgo != "" || cfg.CAKeySize != 0 {
		myCA.CAKeyConfig = ca.KeyConfig{
			Algo: ca.KeyAlgo(cfg.CAKeyAlgo),
			Size: cfg.CAKeySize,
		}
		if err := ca.ValidateKeyConfig(myCA.CAKeyConfig); err != nil {
			return fmt.Errorf("invalid ca_key_algo / ca_key_size: %w", err)
		}
	}
	if cfg.LeafKeyAlgo != "" || cfg.LeafKeySize != 0 {
		myCA.LeafKeyConfig = ca.KeyConfig{
			Algo: ca.KeyAlgo(cfg.LeafKeyAlgo),
			Size: cfg.LeafKeySize,
		}
		if err := ca.ValidateKeyConfig(myCA.LeafKeyConfig); err != nil {
			return fmt.Errorf("invalid leaf_key_algo / leaf_key_size: %w", err)
		}
	}
	myCA.CASubject = ca.CASubjectConfig{
		Org:      cfg.CASubjectOrg,
		OrgUnit:  cfg.CASubjectOU,
		Country:  cfg.CASubjectCountry,
		Locality: cfg.CASubjectLocality,
		Province: cfg.CASubjectProvince,
	}
	myCA.CAPathLength = cfg.CAPathLength
	myCA.CAValidityDays = cfg.CAValidityDays
	myCA.LeafValidityDays = cfg.LeafValidityDays
	myCA.EncryptCAKey = cfg.EncryptCAKey
	myCA.PromoteCNToSAN = cfg.PromoteCNToSAN
	myCA.KeyPassphrase = ca.KeyPassphraseConfig{
		PassphraseFile: cfg.CAKeyPassphraseFile,
	}
	return nil
}

// isLoopback reports whether host is a loopback address (127.x.x.x, ::1, or
// "localhost"). Plain HTTP is only safe when the server cannot be reached from
// outside the local process.
func isLoopback(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

func main() {
	var (
		caDir                   string
		autosignVal             string
		host                    string
		port                    int
		hostname                string
		daemon                  bool
		verbosity               int
		logFile                 string
		tlsCert                 string
		tlsKey                  string
		puppetServers           string
		puppetServerFile        string
		noPpCliAuth             bool
		noTLSRequired           bool
		allowPublicStatus       bool
		ocspURL                 string
		crlURL                  string
		csrRateLimit            int
		configFile              string
		encryptCAKey            bool
		caKeyPassphraseFile     string
		singleProcess           bool
		storageBackend          string
		etcdEndpoints           []string
		etcdKeyPrefix           string
		redisAddrs              []string
		redisSentinelMasterName string
		redisSentinelAddrs      []string
		redisKeyPrefix          string
		sqlDSN                  string
		caCertFile              string
		caKeyFile               string
	)

	cmd := &cobra.Command{
		Use:          "puppet-ca",
		Short:        "Puppet-compatible certificate authority server",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// --- Config loading (file → env → CLI flags) ---
			resolved := resolveConfigFile(configFile, "PUPPET_CA_CONFIG", "/etc/puppet-ca/config.yaml")
			cfg, err := loadServerConfig(resolved)
			if err != nil {
				return err
			}

			// Apply explicitly-set CLI flags (highest precedence).
			if cmd.Flags().Changed("cadir") {
				cfg.CADir = caDir
			}
			if cmd.Flags().Changed("autosign-config") {
				cfg.AutosignConfig = autosignVal
			}
			if cmd.Flags().Changed("host") {
				cfg.Host = host
			}
			if cmd.Flags().Changed("port") {
				cfg.Port = port
			}
			if cmd.Flags().Changed("hostname") {
				cfg.Hostname = hostname
			}
			if cmd.Flags().Changed("verbosity") {
				cfg.Verbosity = verbosity
			}
			if cmd.Flags().Changed("logfile") {
				cfg.LogFile = logFile
			}
			if cmd.Flags().Changed("tls-cert") {
				cfg.TLSCert = tlsCert
			}
			if cmd.Flags().Changed("tls-key") {
				cfg.TLSKey = tlsKey
			}
			if cmd.Flags().Changed("puppet-server") {
				cfg.PuppetServer = puppetServers
			}
			if cmd.Flags().Changed("puppet-server-file") {
				cfg.PuppetServerFile = puppetServerFile
			}
			if cmd.Flags().Changed("no-pp-cli-auth") {
				cfg.NoPpCliAuth = noPpCliAuth
			}
			if cmd.Flags().Changed("no-tls-required") {
				cfg.NoTLSRequired = noTLSRequired
			}
			if cmd.Flags().Changed("allow-public-status") {
				cfg.AllowPublicStatus = allowPublicStatus
			}
			if cmd.Flags().Changed("ocsp-url") {
				cfg.OCSPUrl = ocspURL
			}
			if cmd.Flags().Changed("crl-url") {
				cfg.CRLUrl = crlURL
			}
			if cmd.Flags().Changed("csr-rate-limit") {
				cfg.CSRRateLimit = csrRateLimit
			}
			if cmd.Flags().Changed("encrypt-ca-key") {
				cfg.EncryptCAKey = encryptCAKey
			}
			if cmd.Flags().Changed("ca-key-passphrase-file") {
				cfg.CAKeyPassphraseFile = caKeyPassphraseFile
			}
			if cmd.Flags().Changed("storage-backend") {
				cfg.StorageBackend = storageBackend
			}
			if cmd.Flags().Changed("etcd-endpoints") {
				cfg.EtcdEndpoints = etcdEndpoints
			}
			if cmd.Flags().Changed("etcd-key-prefix") {
				cfg.EtcdKeyPrefix = etcdKeyPrefix
			}
			if cmd.Flags().Changed("redis-addrs") {
				cfg.RedisAddrs = redisAddrs
			}
			if cmd.Flags().Changed("redis-sentinel-master-name") {
				cfg.RedisSentinelMasterName = redisSentinelMasterName
			}
			if cmd.Flags().Changed("redis-sentinel-addrs") {
				cfg.RedisSentinelAddrs = redisSentinelAddrs
			}
			if cmd.Flags().Changed("redis-key-prefix") {
				cfg.RedisKeyPrefix = redisKeyPrefix
			}
			if cmd.Flags().Changed("sql-dsn") {
				cfg.SQLDSN = sqlDSN
			}
			if cmd.Flags().Changed("ca-cert-file") {
				cfg.CACertFile = caCertFile
			}
			if cmd.Flags().Changed("ca-key-file") {
				cfg.CAKeyFile = caKeyFile
			}
			// --- Validation ---
			if cfg.CADir == "" {
				return fmt.Errorf("--cadir is required (or set PUPPET_CA_CADIR / cadir in config file)")
			}

			absCADir, err := filepath.Abs(cfg.CADir)
			if err != nil {
				return fmt.Errorf("resolving --cadir: %w", err)
			}

			// Daemonise only when explicitly requested AND we aren't already the daemon child.
			// Note: --daemon is intentionally excluded from config file / env var support
			// because PUPPET_CA_DAEMON is used internally as the fork signal.
			if daemon && os.Getenv("PUPPET_CA_DAEMON") != "1" {
				exe, err := os.Executable()
				if err != nil {
					return fmt.Errorf("failed to determine executable: %w", err)
				}
				c := exec.Command(exe, os.Args[1:]...)
				// Strip internal role/PSK vars to prevent stale values from a
				// previous run from confusing the daemon child.
				daemonEnv := filterEnv(os.Environ(), "PUPPET_CA_ROLE", "PUPPET_CA_DAEMON", "PUPPET_CA_SIGNER_PSK")
				c.Env = append(daemonEnv, "PUPPET_CA_DAEMON=1")
				c.Stdin = nil
				c.Stdout = nil
				c.Stderr = nil
				if err := c.Start(); err != nil {
					return fmt.Errorf("failed to start daemon: %w", err)
				}
				fmt.Printf("Puppet CA started in background (PID: %d)\n", c.Process.Pid)
				return nil
			}

			// --- Role dispatch (key isolation) ---
			role := os.Getenv("PUPPET_CA_ROLE")

			// Signer mode: load key, serve signing requests on socketpair, exit.
			if role == "signer" {
				return runSignerMode(ctx, cfg, absCADir)
			}

			// Launcher mode (default): spawn isolated signer + frontend children.
			if role == "" && !singleProcess {
				return runLauncher()
			}

			// Frontend mode (role=frontend) or single-process mode: run HTTP server.
			// In frontend mode, connect to the signer process via socketpair
			// (deferred to after storage setup so the CA cert can be read via
			// the overlay-aware storage service).
			var remoteSigner *signer.RemoteSigner

			// --- Logging setup ---
			logFile, err := setupLogger(cfg)
			if err != nil {
				return err
			}
			if logFile != nil {
				defer logFile.Close()
			}

			slog.Info("Starting Puppet CA",
				"cadir", absCADir,
				"host", cfg.Host,
				"port", cfg.Port,
				"verbosity", cfg.Verbosity,
			)

			// SECURITY: TLS enforcement: plain HTTP over a non-loopback
			// interface lets any on-path host inject forged certificates.
			// Refuse to start unless:
			//   (a) TLS is configured (--tls-cert + --tls-key), or
			//   (b) the bind address is loopback-only, or
			//   (c) the operator explicitly opts out with --no-tls-required.
			// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity), SC-23 (Session Authenticity)
			tlsConfigured := cfg.TLSCert != "" && cfg.TLSKey != ""
			if !tlsConfigured {
				if !isLoopback(cfg.Host) && !cfg.NoTLSRequired {
					slog.Error("Refusing to start: plain HTTP on a non-loopback address is " +
						"vulnerable to certificate injection attacks. " +
						"Enable TLS (--tls-cert / --tls-key), " +
						"restrict to loopback (--host 127.0.0.1), " +
						"or explicitly opt out with --no-tls-required.")
					os.Exit(1)
				}
				if cfg.NoTLSRequired && !isLoopback(cfg.Host) {
					slog.Warn("TLS is not configured on a non-loopback address; " +
						"certificate injection is possible. " +
						"Only use --no-tls-required behind a trusted TLS proxy or in test environments.")
				}
			}
			if !tlsConfigured && (cfg.PuppetServer != "" || cfg.PuppetServerFile != "") {
				slog.Warn("--puppet-server / --puppet-server-file have no effect without TLS; " +
					"all endpoints are accessible without authentication in plain HTTP mode.")
			}

			// --- Storage & Directories ---
			backendSpec, err := buildBackendSpec(cfg, absCADir)
			if err != nil {
				slog.Error("Invalid storage backend config", "error", err)
				os.Exit(1)
			}
			store, err := storage.NewServiceFromSpec(backendSpec)
			if err != nil {
				slog.Error("Failed to initialise storage backend", "error", err)
				os.Exit(1)
			}
			defer func() { _ = store.Backend().Close() }()
			if err := store.EnsureDirs(ctx); err != nil {
				slog.Error("Failed to create CA directories", "error", err)
				os.Exit(1)
			}

			// Frontend-mode signer handshake: connect to the signer, then read
			// the CA cert through the storage service so an overlay-mounted
			// cert (e.g. a Kubernetes secret volume) is honoured. The PSK
			// handshake blocks until the signer finishes Init/bootstrap, so
			// store.GetCACert is guaranteed to succeed after it returns.
			if role == "frontend" {
				conn, err := signer.DialConn()
				if err != nil {
					return fmt.Errorf("connecting to signer process: %w", err)
				}
				certPEM, err := store.GetCACert(ctx)
				if err != nil {
					conn.Close()
					return fmt.Errorf("reading CA cert for remote signer: %w", err)
				}
				block, _ := pem.Decode(certPEM)
				if block == nil {
					conn.Close()
					return fmt.Errorf("failed to decode CA cert PEM")
				}
				caCert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					conn.Close()
					return fmt.Errorf("parsing CA cert: %w", err)
				}
				rs := signer.NewRemoteSigner(conn, caCert.PublicKey)
				defer rs.Close()
				remoteSigner = rs
				slog.Info("Connected to isolated signer process")
			}

			// --- Autosign ---
			asCfg := ca.AutosignConfig{Mode: "off"}
			switch cfg.AutosignConfig {
			case "", "false":
				// leave as off
			case "true":
				asCfg.Mode = "true"
				// SECURITY: Warn that autosign=true bypasses all CSR validation.
				// Any node that submits a CSR will receive a signed certificate
				// without any verification. This should only be used in isolated
				// test environments.
				// NIST 800-53: IA-5 (Authenticator Management)
				slog.Warn("SECURITY: autosign is set to 'true' -- ALL certificate signing requests will be automatically signed without validation. " +
					"This is dangerous in production. Use an autosign script or file-based allowlist instead.")
			default:
				info, err := os.Stat(cfg.AutosignConfig)
				if err != nil {
					slog.Error("Autosign config invalid", "path", cfg.AutosignConfig, "error", err)
					os.Exit(1)
				}
				if info.Mode().IsRegular() {
					if info.Mode().Perm()&0111 != 0 {
						asCfg.Mode = "executable"
					} else {
						asCfg.Mode = "file"
					}
					asCfg.FileOrPath = cfg.AutosignConfig
				}
			}
			// SECURITY: Validate autosign executable integrity at startup.
			// Refuses to start if the executable is world-writable or not owned
			// by root/current user. Logs SHA-256 hash for change detection.
			// NIST 800-53: CM-5 (Access Restrictions for Change), SI-7 (Software, Firmware, and Information Integrity)
			if asCfg.Mode == "executable" {
				if err := validateAutosignExecutable(asCfg.FileOrPath); err != nil {
					slog.Error("Autosign executable validation failed", "path", asCfg.FileOrPath, "error", err)
					os.Exit(1)
				}
			}

			slog.Debug("Autosign config", "mode", asCfg.Mode, "path", asCfg.FileOrPath)

			// --- CA Initialisation ---
			myCA := ca.New(store, asCfg, cfg.Hostname)
			if err := applyCAConfig(myCA, cfg); err != nil {
				return err
			}

			// SECURITY: In frontend mode, use the remote signer: the CA private
			// key is never loaded into this process's address space.
			// NIST 800-53: SC-3 (Security Function Isolation)
			if remoteSigner != nil {
				myCA.ExternalSigner = remoteSigner
			}

			if err := myCA.Init(ctx); err != nil {
				slog.Error("Failed to initialise CA", "error", err)
				os.Exit(1)
			}

			// SECURITY: Warn if any private key files have overly permissive modes.
			// The server does not modify existing file permissions; operators should
			// fix these manually (e.g. chmod 0640 or stricter).
			// NIST 800-53: SC-12 (Cryptographic Key Establishment and Management)
			if warnings := store.CheckKeyPermissions(); len(warnings) > 0 {
				for _, w := range warnings {
					slog.Warn("Private key file has overly permissive mode",
						"path", w.Path, "mode", w.Mode.String(), "expected", "0600 or stricter")
				}
			}

			// --- HTTP(S) Server ---
			srv := api.New(myCA)

			// CSR rate limiting: default 60/min/IP unless explicitly set to 0.
			csrRL := cfg.CSRRateLimit
			if csrRL == 0 && !cmd.Flags().Changed("csr-rate-limit") {
				if os.Getenv("PUPPET_CA_CSR_RATE_LIMIT") == "" {
					csrRL = 60
				}
			}
			srv.CSRRateLimit = csrRL
			srv.SignBatchLimit = 50 // Default max batch size for sign operations
			srv.PlainHTTP = !tlsConfigured && !isLoopback(cfg.Host) && !cfg.NoTLSRequired
			srv.PuppetDateTimeFormat = cfg.PuppetDateTimeFormat

			// Wire mTLS auth middleware when TLS is configured.
			if cfg.TLSCert != "" && cfg.TLSKey != "" {
				allowList := map[string]bool{}
				for _, cn := range strings.Split(cfg.PuppetServer, ",") {
					cn = strings.TrimSpace(cn)
					if cn != "" {
						allowList[cn] = true
					}
				}
				fileCNs, err := loadPuppetServerFile(cfg.PuppetServerFile)
				if err != nil {
					return err
				}
				for _, cn := range fileCNs {
					allowList[cn] = true
				}
				srv.AuthConfig = &api.AuthConfig{
					CACert:            myCA.CACert,
					AllowList:         allowList,
					NoPpCliAuth:       cfg.NoPpCliAuth,
					AllowPublicStatus: cfg.AllowPublicStatus,
				}
				if !cfg.NoPpCliAuth {
					// SECURITY: Inform the operator that pp_cli_auth OID grants admin access.
					// Any certificate carrying this extension with value "true" will be treated
					// as an admin. Use --no-pp-cli-auth to restrict admin access to the CN allow list only.
					// NIST 800-53: AC-6 (Least Privilege)
					slog.Info("pp_cli_auth extension is enabled as an admin credential (default). " +
						"Any certificate carrying pp_cli_auth=true will have admin access. " +
						"Use --no-pp-cli-auth to disable this and require explicit CN allow list.")
				}
			}

			addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
			slog.Info("Listening", "address", addr)

			server := &http.Server{
				Addr:              addr,
				Handler:           srv.Routes(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       120 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}

			if cfg.TLSCert != "" && cfg.TLSKey != "" {
				serverCert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
				if err != nil {
					slog.Error("Failed to load TLS cert/key", "cert", cfg.TLSCert, "key", cfg.TLSKey, "error", err)
					os.Exit(1)
				}

				caCertPEM, err := myCA.Storage.GetCACert(ctx)
				if err != nil {
					slog.Error("Failed to read CA cert for TLS", "error", err)
					os.Exit(1)
				}
				caPool := x509.NewCertPool()
				block, _ := pem.Decode(caCertPEM)
				if block != nil {
					if caCert, err := x509.ParseCertificate(block.Bytes); err == nil {
						caPool.AddCert(caCert)
					}
				}

				// SECURITY: TLS server configuration with mTLS support.
				// RequestClientCert allows public endpoints to work without a
				// client cert while the auth middleware enforces cert requirements
				// per-tier. MinVersion TLS 1.2 blocks legacy protocol downgrades.
				// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity),
				//              SC-23 (Session Authenticity), IA-3 (Device Identification)
				server.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{serverCert},
					ClientCAs:    caPool,
					ClientAuth:   tls.RequestClientCert,
					MinVersion:   tls.VersionTLS12,
				}

				slog.Info("TLS enabled", "cert", cfg.TLSCert)
			}

			shutdownDone := make(chan struct{})
			go func() {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
				<-sigCh
				slog.Info("Shutting down")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := server.Shutdown(shutdownCtx); err != nil {
					slog.Warn("HTTP server shutdown error", "error", err)
				}
				close(shutdownDone)
			}()

			var serveErr error
			if cfg.TLSCert != "" && cfg.TLSKey != "" {
				serveErr = server.ListenAndServeTLS("", "")
			} else {
				serveErr = server.ListenAndServe()
			}
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				slog.Error("Server failed", "error", serveErr)
				os.Exit(1)
			}
			<-shutdownDone
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/config.yaml if it exists)")
	f.StringVar(&caDir, "cadir", "", "Directory for CA storage (or set PUPPET_CA_CADIR)")
	f.StringVar(&autosignVal, "autosign-config", "", "Autosign configuration: 'true', 'false', or path to file/executable")
	f.StringVar(&host, "host", "0.0.0.0", "Address to listen on")
	f.IntVar(&port, "port", 8140, "Port to listen on")
	f.StringVar(&hostname, "hostname", "", "Hostname for the CA certificate CN (e.g. puppet.example.com)")
	f.BoolVar(&daemon, "daemon", false, "Run in background as a daemon (not recommended in containers)")
	f.IntVarP(&verbosity, "verbosity", "v", 0, "Verbosity: 0=Info 1=Debug 2=Trace")
	f.StringVar(&logFile, "logfile", "", "Log to file instead of stderr (implies daemon log destination)")
	f.StringVar(&tlsCert, "tls-cert", "", "Path to TLS server certificate PEM (enables HTTPS)")
	f.StringVar(&tlsKey, "tls-key", "", "Path to TLS server private key PEM (enables HTTPS)")
	f.StringVar(&puppetServers, "puppet-server", "", "Comma-separated list of puppet-server CNs allowed admin access")
	f.StringVar(&puppetServerFile, "puppet-server-file", "", "Path to a file of puppet-server CNs allowed admin access (one per line; # comments and blank lines ignored)")
	f.BoolVar(&noPpCliAuth, "no-pp-cli-auth", false, "Disable pp_cli_auth extension as an admin credential; require CN allow list only")
	f.BoolVar(&noTLSRequired, "no-tls-required", false, "Allow plain HTTP on non-loopback addresses (use only behind a trusted TLS proxy or in test environments)")
	f.BoolVar(&allowPublicStatus, "allow-public-status", false, "Allow unauthenticated GET /certificate_status (by default, requires a CA-signed client cert)")
	f.StringVar(&ocspURL, "ocsp-url", "", "OCSP responder URL to embed in issued certificates (e.g. http://puppet-ca:8140/ocsp)")
	f.StringVar(&crlURL, "crl-url", "", "CRL distribution point URL to embed in issued certificates (e.g. http://puppet-ca:8140/puppet-ca/v1/certificate_revocation_list/ca)")
	f.IntVar(&csrRateLimit, "csr-rate-limit", 60, "Max CSR submissions per IP per minute on the public PUT /certificate_request endpoint (0 disables)")
	f.BoolVar(&encryptCAKey, "encrypt-ca-key", false, "Encrypt the CA private key at rest (AES-256-GCM + Argon2id); a passphrase is auto-generated if not provided")
	f.StringVar(&caKeyPassphraseFile, "ca-key-passphrase-file", "", "Path to file containing the CA key passphrase (first line used)")
	f.BoolVar(&singleProcess, "single-process", false, "Disable CA key isolation (run signer and frontend in a single process)")
	f.StringVar(&storageBackend, "storage-backend", "", "Storage backend: 'filesystem' (default), 'etcd', 'redis' (alias 'valkey'), or 'sqlite'")
	f.StringSliceVar(&etcdEndpoints, "etcd-endpoints", nil, "Comma-separated etcd cluster endpoints (e.g. https://etcd1:2379,https://etcd2:2379)")
	f.StringVar(&etcdKeyPrefix, "etcd-key-prefix", "", "etcd key namespace for this CA (default: /puppet-ca)")
	f.StringSliceVar(&redisAddrs, "redis-addrs", nil, "Comma-separated Redis/Valkey addresses for direct connections (e.g. redis-0:6379)")
	f.StringVar(&redisSentinelMasterName, "redis-sentinel-master-name", "", "Redis Sentinel primary name; set to enable Sentinel-managed failover")
	f.StringSliceVar(&redisSentinelAddrs, "redis-sentinel-addrs", nil, "Comma-separated Redis Sentinel addresses (e.g. sentinel-0:26379,sentinel-1:26379)")
	f.StringVar(&redisKeyPrefix, "redis-key-prefix", "", "Redis key namespace for this CA (default: puppet-ca)")
	f.StringVar(&sqlDSN, "sql-dsn", "", "SQL data source name (e.g. SQLite file path 'file:/var/lib/puppet-ca/ca.db')")
	f.StringVar(&caCertFile, "ca-cert-file", "", "Keep the CA certificate at this local path regardless of storage backend")
	f.StringVar(&caKeyFile, "ca-key-file", "", "Keep the CA private key at this local path regardless of storage backend")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// runSignerMode runs the isolated CA key signer process. It initializes the CA
// (bootstrapping on first run), then serves signing requests over the inherited
// socketpair fd. The signer has no network exposure; it only communicates with
// the frontend via the pre-connected Unix socketpair.
//
// IMPORTANT: The signer calls Init() which handles bootstrapping. The PSK
// handshake in signer.Serve() happens AFTER Init completes, so the frontend
// can safely read the CA cert from disk once the handshake succeeds.
func runSignerMode(ctx context.Context, cfg *serverConfig, absCADir string) error {
	logFile, err := setupLogger(cfg)
	if err != nil {
		// Signer: fall back to stderr if log file fails.
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
		slog.Warn("Failed to open log file, using stderr", "error", err)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	slog.Info("Starting CA signer process",
		"cadir", absCADir,
		"pid", os.Getpid(),
	)

	backendSpec, err := buildBackendSpec(cfg, absCADir)
	if err != nil {
		return fmt.Errorf("invalid storage backend config: %w", err)
	}
	store, err := storage.NewServiceFromSpec(backendSpec)
	if err != nil {
		return fmt.Errorf("initialising storage backend: %w", err)
	}
	defer func() { _ = store.Backend().Close() }()

	// Full CA initialization: handles bootstrap on first run, loads existing
	// CA on subsequent runs. This writes ca_crt.pem, CRL, inventory, etc.
	myCA := ca.New(store, ca.AutosignConfig{}, cfg.Hostname)
	if err := applyCAConfig(myCA, cfg); err != nil {
		return err
	}

	if err := myCA.Init(ctx); err != nil {
		return fmt.Errorf("CA initialization failed: %w", err)
	}

	slog.Info("CA initialized, serving signing requests")
	return signer.Serve(myCA.CAKey)
}

// validateAutosignExecutable checks the integrity of an autosign executable:
//  1. Resolves symlinks to the real path
//  2. Verifies the file is not world-writable (mode & 0002)
//  3. Verifies the file is owned by root (uid 0) or the current process user
//  4. Logs the SHA-256 hash for change detection
func validateAutosignExecutable(path string) error {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolving symlinks for %s: %w", path, err)
	}
	if realPath != path {
		slog.Info("Autosign executable symlink resolved", "path", path, "realpath", realPath)
	}

	info, err := os.Stat(realPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", realPath, err)
	}

	// Check world-writable bit.
	if info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("autosign executable %s is world-writable (mode %s); "+
			"refusing to start -- fix with: chmod o-w %s", realPath, info.Mode().Perm(), realPath)
	}

	// Check file ownership: must be owned by root or the current user.
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		currentUID := uint32(os.Getuid())
		if stat.Uid != 0 && stat.Uid != currentUID {
			return fmt.Errorf("autosign executable %s is owned by uid %d (expected root or current user uid %d); "+
				"refusing to start", realPath, stat.Uid, currentUID)
		}
	}

	// Compute and log SHA-256 hash.
	data, err := os.ReadFile(realPath)
	if err != nil {
		return fmt.Errorf("reading %s for hash: %w", realPath, err)
	}
	hash := sha256.Sum256(data)
	slog.Info("Autosign executable configured",
		"path", realPath,
		"sha256", hex.EncodeToString(hash[:]),
		"mode", info.Mode().Perm().String(),
	)
	return nil
}
