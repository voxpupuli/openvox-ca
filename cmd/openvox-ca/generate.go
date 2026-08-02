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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// newGenerateCmd builds the offline `openvox-ca generate` subcommand: mint a
// certificate directly against storage and the configured key provider, with no
// running server and no API.
//
// It lives on the server binary rather than openvox-ca-ctl for the same reason
// csr and import-ca-cert do: it must reach the storage backend and key provider
// named in the *server's* configuration, and openvox-ca-ctl can address only a
// local filesystem directory through a different configuration schema.
//
// Two things the API cannot do are the reason this exists. A pp_cli_auth
// certificate cannot be obtained through it at all, because the CSR path strips
// authorisation-arc OIDs; and nothing can be issued before a server is running,
// which is the bootstrap circle tls_self_provision was added to break. Ordinary
// node certificates should keep using POST /generate/{subject}, which needs no
// outage -- see the scope note in docs/operator-cli.md.
func newGenerateCmd() *cobra.Command {
	var (
		configFile string
		caDir      string
		certname   string
		dnsNames   []string
		ppCliAuth  bool
		keyOut     string
		certOut    string
		ttl        time.Duration
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Mint a certificate offline, without a running server",
		Long: `Mint a certificate directly against the configured storage backend and CA key
provider. No running server, no API, and no admin client certificate.

The certificate is issued through the CA's own signing path, so it takes a
serial from the CA's generator, is written to the inventory, appears in
"openvox-ca-ctl list --all", is swept by the expiry job, and can be revoked by
name -- unlike one signed out of band with openssl.

Autosign policy is deliberately not consulted: this is an operator action rather
than a request, and it must work when there is no policy and no server to
evaluate one.

Use the API for ordinary node certificates. This command exists for the two
cases the API cannot serve: a pp_cli_auth administrator credential, and minting
before a server exists.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			out := cmd.ErrOrStderr()

			resolvedCfgFile := resolveConfigFile(configFile, "PUPPET_CA_CONFIG", "/etc/puppet-ca/config.yaml")
			cfg, err := loadServerConfig(resolvedCfgFile)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("cadir") {
				cfg.CADir = caDir
			}

			reportResolvedConfig(out, resolvedCfgFile, cfg)
			reportIssuanceSettings(out, cfg)

			// Honour the configured logfile so the authorisation-grant audit
			// line in internal/ca reaches it. Non-fatal and non-creative, for
			// reasons setupLogger's other callers do not share: see
			// applySubcommandLogging.
			closeLog := applySubcommandLogging(cfg, out)
			defer closeLog()

			// The frontend role proxies signing to an isolated signer and never
			// holds the key, so this command cannot work there. Checked before
			// resolveRuntime for the reason that function's own godoc gives:
			// building a key provider opens an authenticated session to the key
			// backend, and the frontend is precisely the role barred from doing
			// that. Refusing after the session was opened would defeat the point.
			if role := os.Getenv("PUPPET_CA_ROLE"); !roleMayReachCAKey(role) {
				return fmt.Errorf("this process is running as the %q role, which proxies signing to the "+
					"isolated signer and cannot reach the CA key. Run this on the signer host instead", role)
			}

			// Checked before resolveRuntime so nothing is opened -- and no
			// authenticated session to a key provider established -- for a run
			// that cannot succeed.
			if ppCliAuth && cfg.NoPpCliAuth {
				return fmt.Errorf("this CA is configured with no_pp_cli_auth, so a pp_cli_auth " +
					"certificate would grant nothing. Add the certname to the admin allow list " +
					"with --puppet-server instead, or unset no_pp_cli_auth")
			}
			if ppCliAuth && keyOut == "" {
				return fmt.Errorf("--key-out is required with --pp-cli-auth: the fallback writes to " +
					"the cadir's private directory, which is always the local filesystem whatever " +
					"the storage backend, so on an ephemeral cadir the key is lost at the next " +
					"restart -- leaving a live administrator certificate in the inventory with no " +
					"key in existence")
			}
			if force && keyOut == "" {
				return fmt.Errorf("--key-out is required with --force: the fallback writes the key " +
					"only after issuance, so a failure there would roll the new certificate back " +
					"having already revoked the old one, and CRL entries cannot be withdrawn")
			}

			// Resolve output paths before anything is issued. Everything after
			// the mint is irreversible: the certificate has taken a serial and
			// is in the inventory, and under --force its predecessor is on the
			// CRL.
			keyPath, err := prepareOutputPath(keyOut)
			if err != nil {
				return err
			}
			certPath, err := prepareOutputPath(certOut)
			if err != nil {
				return err
			}

			rt, err := resolveRuntime(ctx, cfg, true)
			if err != nil {
				return err
			}
			defer func() { _ = rt.Close() }()

			reportBackendCapabilities(ctx, out, rt.Store)

			myCA := ca.New(rt.Store, ca.AutosignConfig{Mode: "off"}, cfg.Hostname)
			if err := applyCAConfig(myCA, cfg); err != nil {
				return err
			}
			myCA.KeyProvider = rt.KeyProvider
			myCA.NoBootstrap = true

			if err := assertCAUsable(ctx, myCA, rt.Store, cfg); err != nil {
				return err
			}

			if err := myCA.Init(ctx); err != nil {
				return fmt.Errorf("loading the CA: %w", err)
			}

			if ppCliAuth {
				warnAdminCredential(out, certname, keyPath)
			}

			opts := ca.GenerateOptions{
				DNSAltNames:               dnsNames,
				TTL:                       ttl,
				RetainPrivateKeyInStorage: keyPath == "",
				ReplaceExisting:           force,
			}
			if ppCliAuth {
				opts.AuthGrants = []ca.AuthGrant{ca.PpCliAuth()}
			}
			if keyPath != "" {
				// Put the key somewhere durable before the CA commits to
				// anything. Under --force the alternative is losing it after
				// the predecessor has been revoked, which cannot be undone.
				opts.EmitKey = func(keyPEM []byte) error {
					if err := writePrivateFile(keyPath, keyPEM); err != nil {
						return fmt.Errorf("writing the private key to %s: %w", keyPath, err)
					}
					return nil
				}
			}

			result, err := myCA.GenerateWithOptions(ctx, certname, opts)
			if err != nil {
				// The key is on disk but nothing was issued. Remove it rather
				// than leaving a private key with no certificate at a path the
				// operator will not think to clean up.
				if keyPath != "" {
					if rmErr := os.Remove(keyPath); rmErr != nil && !os.IsNotExist(rmErr) {
						_, _ = fmt.Fprintf(out, "Warning: could not remove the unused private key at %s: %v\n",
							keyPath, rmErr)
					}
				}
				return annotateGenerateError(err, certname)
			}

			if certPath != "" {
				if err := writePublicFile(certPath, result.CertificatePEM); err != nil {
					return fmt.Errorf("writing the certificate to %s: %w", certPath, err)
				}
			} else if _, err := cmd.OutOrStdout().Write(result.CertificatePEM); err != nil {
				return err
			}

			reportSuccess(out, rt.Store, result, certname, keyPath, certPath, ppCliAuth, force, cfg)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/config.yaml if it exists)")
	f.StringVar(&caDir, "cadir", "", "CA storage directory (overrides the config file)")
	f.StringVar(&certname, "certname", "", "Subject name for the certificate")
	f.StringSliceVar(&dnsNames, "dns", nil, "DNS alt names (repeatable, or comma-separated)")
	f.BoolVar(&ppCliAuth, "pp-cli-auth", false, "Grant CA administrator access via the pp_cli_auth extension")
	f.StringVar(&keyOut, "key-out", "", "Write the private key here (default: the cadir's private directory)")
	f.StringVar(&certOut, "cert-out", "", "Write the certificate here instead of stdout")
	f.DurationVar(&ttl, "ttl", 0, "Certificate lifetime, e.g. 8760h for one year")
	f.BoolVar(&force, "force", false, "Revoke an existing certificate for this name and replace it")
	_ = cmd.MarkFlagRequired("certname")
	_ = cmd.MarkFlagRequired("ttl")

	return cmd
}

// prepareOutputPath validates an operator-supplied output path before anything
// is issued, returning it cleaned. Refusing here rather than after the mint
// matters because issuance cannot be undone: the certificate has consumed a
// serial and is recorded in the inventory.
func prepareOutputPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", path, err)
	}
	if _, err := os.Stat(abs); err == nil {
		return "", fmt.Errorf("%s already exists: refusing to overwrite it", abs)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("checking %s: %w", abs, err)
	}
	dir := filepath.Dir(abs)
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("the directory for %s does not exist: %w", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	return abs, nil
}

// assertCAUsable refuses to run against storage that holds no usable CA, before
// Init is called.
//
// Init would otherwise bootstrap one when both the certificate and key are
// absent, so a mistyped --cadir would silently mint a fresh root and issue
// under it -- leaving the operator with certificates nothing in the fleet
// trusts. NoBootstrap is set as a backstop, but the check runs first because
// Init writes before it reaches that decision: EnsureDirs, then InitHMAC, whose
// EnsureHMACKey regenerates the inventory HMAC key if the stored one is the
// wrong length. Running that against a live CA's storage is its own hazard.
func assertCAUsable(ctx context.Context, myCA *ca.CA, store *storage.StorageService, cfg *serverConfig) error {
	hasCert, err := store.HasCACert(ctx)
	if err != nil {
		return fmt.Errorf("checking for an existing CA certificate: %w", err)
	}
	hasKey, err := myCA.HasCAKey(ctx)
	if err != nil {
		return fmt.Errorf("checking for an existing CA key: %w", err)
	}

	switch {
	case !hasCert && !hasKey:
		return fmt.Errorf("no CA exists in %s: refusing to create one. This command issues from an "+
			"existing CA -- start the server once to bootstrap, or complete 'openvox-ca csr' and "+
			"'openvox-ca import-ca-cert' to run under an external root", cfg.CADir)
	case !hasCert:
		return fmt.Errorf("a CA key exists but its certificate is missing from %s: install the signed "+
			"chain with 'openvox-ca import-ca-cert' before issuing", cfg.CADir)
	case !hasKey:
		return fmt.Errorf("a CA certificate exists in %s but its key is missing: restore the key, or "+
			"check that the configured ca_key_provider matches the server's", cfg.CADir)
	}
	return nil
}

// reportIssuanceSettings prints the resolved settings that shape or record what
// is about to be issued.
//
// These are root-command flags as well as config keys, and this command sees
// only the config file and PUPPET_CA_* environment. A server configured
// entirely by flags -- the shipped container image, the compose topology -- is
// invisible here, so a certificate could silently be minted with no CRL
// distribution point while the server's own issuance carries one. Printing what
// was resolved is what makes that visible while it is still cheap to fix.
func reportIssuanceSettings(w io.Writer, cfg *serverConfig) {
	value := func(s string) string {
		if s == "" {
			return "(none)"
		}
		return s
	}
	_, _ = fmt.Fprintf(w, "Issuance settings: crl_url: %s; ocsp_url: %s; promote_cn_to_san: %t\n",
		value(cfg.CRLUrl), value(cfg.OCSPUrl), cfg.PromoteCNToSAN)
}

// reportBackendCapabilities warns when the resolved backend cannot serialise
// this process against a running server.
//
// The per-subject lock is real only on backends that provide distributed
// locking, and the inventory append is atomic only on structured ones. Where
// either is missing, a concurrent server can issue a second certificate for the
// same subject, or -- worse -- interleave an inventory append so the integrity
// HMAC covers a blob that never existed, which makes the server refuse to start
// with no supported repair (see #188).
func reportBackendCapabilities(ctx context.Context, w io.Writer, store *storage.StorageService) {
	locking, lockErr := store.SupportsDistributedLocking(ctx)
	atomicInventory := store.SupportsAtomicInventory()

	switch {
	case lockErr != nil:
		_, _ = fmt.Fprintf(w, "Warning: could not determine whether this backend coordinates locks "+
			"across processes: %v\n", lockErr)
	case locking && atomicInventory:
		_, _ = fmt.Fprintf(w, "Backend coordinates across processes: safe to run alongside a live server.\n")
		return
	}

	_, _ = fmt.Fprintf(w, "Warning: this backend does not fully coordinate writes across processes "+
		"(cross-process locking: %t; atomic inventory append: %t).\n"+
		"  Stop the server before running this. A concurrent write can issue a duplicate\n"+
		"  certificate, or corrupt the inventory integrity record so the server will not restart.\n",
		locking, atomicInventory)
}

// warnAdminCredential states what a pp_cli_auth certificate grants, and what it
// takes to withdraw it.
//
// The withdrawal half is the part an operator cannot infer. Unlike an allow-list
// entry, which is a file edit and a restart, this grant is baked into a
// certificate, and revoking it does not take effect on a running server until
// that server reloads its CRL.
func warnAdminCredential(w io.Writer, certname, keyPath string) {
	_, _ = fmt.Fprintf(w, `
WARNING: --pp-cli-auth mints a full CA administrator credential.

  Whoever holds the private key
    %s
  will be able to sign any pending request, sign all of them, generate a
  certificate for any name, revoke and clean any certificate, import
  certificates, and replace the CRL -- on this CA, without being listed in the
  admin allow list.

  Withdrawing it is not one step:
    1. openvox-ca-ctl revoke --certname %s
    2. restart every replica. Waiting for the CRL to refresh on its own can take
       roughly two-thirds of crl_validity, and even then a pre-signed OCSP
       response can vouch for the revoked serial for up to another 4 hours.
    3. check the inventory for other live serials for this name. If renewal
       replaced it and revoke_on_auto_renew is off -- or a renewal's best-effort
       revoke failed -- there may be more than one, and current tooling cannot
       revoke a superseded serial (see issue #177).

`, keyPath, certname)
}

// annotateGenerateError turns a library error into something an operator can
// act on, without swallowing the sentinel callers discriminate against.
func annotateGenerateError(err error, certname string) error {
	if errors.Is(err, ca.ErrCertExists) {
		return fmt.Errorf("%w.\nPass --force to revoke it and issue a replacement, remove it with "+
			"'openvox-ca-ctl clean --certname %s', or choose another --certname", err, certname)
	}
	return err
}

// reportSuccess prints what was issued, and the consequences the operator now
// owns.
func reportSuccess(w io.Writer, store *storage.StorageService, result *ca.GenerateResult,
	certname, keyPath, certPath string, ppCliAuth, force bool, cfg *serverConfig,
) {
	if serial, notAfter, err := describeIssued(result); err == nil {
		_, _ = fmt.Fprintf(w, "Issued %s: serial %s, expires %s\n",
			certname, serial, notAfter.Format(time.RFC3339))
	} else {
		_, _ = fmt.Fprintf(w, "Issued %s\n", certname)
	}

	if keyPath != "" {
		_, _ = fmt.Fprintf(w, "Private key: %s\n", keyPath)
	} else {
		_, _ = fmt.Fprintf(w, "Private key: %s\n", store.PrivateKeyPath(certname))
		_, _ = fmt.Fprintf(w, "  Nothing sweeps keys from that directory, so it persists there until\n"+
			"  removed -- and it is on the local filesystem whatever the storage backend, so on an\n"+
			"  ephemeral cadir it is lost at the next restart instead.\n")
	}
	if certPath != "" {
		_, _ = fmt.Fprintf(w, "Certificate: %s\n", certPath)
	}

	if force {
		_, _ = fmt.Fprintf(w, "The previous certificate for %s was revoked. A running server honours it "+
			"until it reloads the CRL.\n", certname)
		if cfg.Hostname != "" && certname == cfg.Hostname {
			_, _ = fmt.Fprintf(w, "  That name is this CA's own hostname: if it is serving with that "+
				"certificate, restart it with the new pair now.\n")
		}
	}
	if ppCliAuth {
		_, _ = fmt.Fprintf(w, "This certificate is a CA administrator credential. Treat the private key "+
			"accordingly.\n")
	}
}

// describeIssued pulls the serial and expiry out of the issued certificate for
// the success message.
func describeIssued(result *ca.GenerateResult) (string, time.Time, error) {
	block, _ := pem.Decode(result.CertificatePEM)
	if block == nil {
		return "", time.Time{}, fmt.Errorf("issued certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", time.Time{}, err
	}
	return fmt.Sprintf("%X", cert.SerialNumber), cert.NotAfter, nil
}

// applySubcommandLogging points slog at the configured logfile so the
// authorisation-grant audit line emitted by internal/ca reaches it, and returns
// a closer.
//
// Two departures from how the root command uses setupLogger, both deliberate.
//
// It never creates the file. setupLogger opens with O_CREATE, and the primary
// use of this command is before the server has ever started -- so running it as
// root would mint the logfile owned by root, and the server, which runs as an
// unprivileged user, would then fail to open it and exit at startup. Creating
// a file that stops the service starting is a poor trade for an audit line.
//
// It degrades rather than failing. The root command treats a logging failure as
// fatal; runSignerMode falls back to stderr. An interactive mint should follow
// the signer: refusing to issue because a log file is unwritable helps nobody.
func applySubcommandLogging(cfg *serverConfig, w io.Writer) func() {
	effective := *cfg

	if effective.LogFile != "" {
		if _, err := os.Stat(effective.LogFile); err != nil {
			_, _ = fmt.Fprintf(w, "Audit log: %s is not present and will not be created by this "+
				"command; logging to stderr instead.\n", effective.LogFile)
			effective.LogFile = ""
		}
	}

	f, err := setupLogger(&effective)
	if err != nil {
		_, _ = fmt.Fprintf(w, "Audit log: could not open %s (%v); logging to stderr instead.\n",
			effective.LogFile, err)
		stderrOnly := effective
		stderrOnly.LogFile = ""
		if _, fallbackErr := setupLogger(&stderrOnly); fallbackErr != nil {
			_, _ = fmt.Fprintf(w, "Warning: could not configure logging: %v\n", fallbackErr)
		}
		return func() {}
	}

	switch {
	case f != nil:
		_, _ = fmt.Fprintf(w, "Audit log: %s\n", effective.LogFile)
		return func() { _ = f.Close() }
	case cfg.LogFile == "":
		_, _ = fmt.Fprintf(w, "No logfile configured: the audit record for this mint is terminal-only.\n")
	}
	return func() {}
}
