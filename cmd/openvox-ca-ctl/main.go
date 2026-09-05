// Copyright (C) 2026 Trevor Vaughan
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

// openvox-ca-ctl is an operator management CLI for the openvox-ca server.
//
// Usage:
//
//	openvox-ca-ctl [global-flags] <subcommand> [subcommand-flags]
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/storage"
	"github.com/voxpupuli/openvox-ca/internal/version"
)

// ---------- global state (set by persistent flags / config) ----------

var (
	globalServerURL  string
	globalCACert     string
	globalClientCert string
	globalClientKey  string
	globalVerbose    bool
	globalInsecure   bool
	globalConfigFile string
)

// ---------- HTTP client ----------

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

// newTLSConfig builds the client TLS configuration from the resolved global
// flags, writing the operator-facing notice about the chosen server
// verification mode to notices.
//
// --ca-cert takes precedence over --insecure: an explicitly supplied trust
// anchor is never downgraded to "verify nothing".
func newTLSConfig(notices io.Writer) (*tls.Config, error) {
	tlsCfg := &tls.Config{}

	if globalCACert != "" {
		caCertPEM, err := os.ReadFile(globalCACert)
		if err != nil {
			return nil, fmt.Errorf("reading --ca-cert %s: %w", globalCACert, err)
		}
		// SECURITY: AppendCertsFromPEM loads every certificate in the file, so
		// a bundle (root plus intermediates, as Puppet's ca_crt.pem often is)
		// is trusted in full, and it reports whether anything was loaded at
		// all. Decoding only the first block instead would silently produce an
		// empty or partial trust anchor whose only symptom is an opaque
		// handshake failure much later. It returns false for two causes — no
		// PEM certificate block, and none that parses — so the message names
		// both rather than sending the operator after the wrong one.
		// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity)
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCertPEM) {
			return nil, fmt.Errorf("parsing --ca-cert %s: contains no usable certificates "+
				"(no PEM certificate block, or none that parses)", globalCACert)
		}
		tlsCfg.RootCAs = pool
		if globalInsecure {
			// The operator asked for both. Say which one won, since the
			// losing flag was typed deliberately and its absence of effect is
			// otherwise invisible.
			_, _ = fmt.Fprintln(notices, "NOTE: --ca-cert supplied; --insecure ignored and the server "+
				`certificate will still be verified (pass --ca-cert="" to drop a configured trust anchor)`)
		}
	} else if globalInsecure {
		// SECURITY: Operator explicitly opted in to skip TLS verification.
		// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity)
		// The notice is advisory; a failed write to stderr must not stop the
		// command, and the slog line below carries the same warning.
		_, _ = fmt.Fprintln(notices, "WARNING: --insecure specified; TLS server certificate will NOT be verified (vulnerable to MITM)")
		slog.Warn("TLS server verification disabled", "server", globalServerURL)
		tlsCfg.InsecureSkipVerify = true
	} else {
		// SECURITY: Neither --ca-cert nor --insecure provided. Use the system
		// trust store (tlsCfg.RootCAs = nil). If the CA uses a self-signed cert
		// not in the system store, the connection will fail with a clear error,
		// which is the safe default.
		// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity)
		// Advisory notice; a failed write to stderr must not stop the command.
		_, _ = fmt.Fprintln(notices, "NOTE: --ca-cert not provided; using system trust store for TLS verification. "+
			"If the server uses a self-signed CA certificate, provide --ca-cert or use --insecure.")
	}

	// SECURITY: Enforce TLS 1.3 minimum to prevent protocol downgrade attacks.
	// NIST 800-53: SC-8 (Transmission Confidentiality and Integrity)
	tlsCfg.MinVersion = tls.VersionTLS13

	switch {
	case globalClientCert != "" && globalClientKey != "":
		cert, err := tls.LoadX509KeyPair(globalClientCert, globalClientKey)
		if err != nil {
			return nil, fmt.Errorf("loading --client-cert/--client-key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	case globalClientCert != "":
		// SECURITY: Half a key pair cannot authenticate. Say so now rather
		// than presenting no client certificate and leaving the operator to
		// diagnose a server-side mTLS rejection. Name the half that arrived
		// and every source it could have come from: after an upgrade the
		// operator most often typed neither flag, and the value came from
		// ctl.yaml or the environment.
		return nil, fmt.Errorf("--client-cert %s given without --client-key "+
			"(also settable as client_cert/client_key in the config file, or "+
			"PUPPET_CA_CTL_CLIENT_CERT/PUPPET_CA_CTL_CLIENT_KEY); both are required for mTLS",
			globalClientCert)
	case globalClientKey != "":
		return nil, fmt.Errorf("--client-key %s given without --client-cert "+
			"(also settable as client_cert/client_key in the config file, or "+
			"PUPPET_CA_CTL_CLIENT_CERT/PUPPET_CA_CTL_CLIENT_KEY); both are required for mTLS",
			globalClientKey)
	}

	return tlsCfg, nil
}

func newClient() (*Client, error) {
	tlsCfg, err := newTLSConfig(os.Stderr)
	if err != nil {
		return nil, err
	}

	return &Client{
		BaseURL: strings.TrimRight(globalServerURL, "/"),
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
			Timeout:   30 * time.Second,
		},
	}, nil
}

func (c *Client) do(method, path string, body []byte) (int, []byte, error) {
	url := c.BaseURL + path
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, err
}

func (c *Client) get(path string) (int, []byte, error) {
	return c.do("GET", path, nil)
}

func (c *Client) put(path string, body []byte) (int, []byte, error) {
	return c.do("PUT", path, body)
}

func (c *Client) delete(path string) (int, []byte, error) {
	return c.do("DELETE", path, nil)
}

func (c *Client) post(path string, body []byte) (int, []byte, error) {
	return c.do("POST", path, body)
}

// ---------- helpers ----------

// checkHTTP turns a non-2xx response into an error naming the request.
//
// %q on the body, for the same reason as the import summary below: it is
// chosen entirely by the server, and cobra prints a returned error straight to
// stderr (the subcommands set SilenceUsage but not SilenceErrors), so it
// reaches an operator's terminal unescaped. TrimSpace removes only leading and
// trailing whitespace, so an embedded CR or LF would survive it and could
// fabricate a reassuring second line after a failed operation -- against a
// hostile or MITM'd server, which the CLI's own --insecure warning admits is a
// case worth considering. This is the sink with the least provenance of any in
// the CLI, so it is quoted rather than enumerated as an exception.
func checkHTTP(code int, body []byte, method, path string) error {
	if code >= 200 && code < 300 {
		return nil
	}
	return fmt.Errorf("HTTP %d on %s %s: %q", code, method, path, strings.TrimSpace(string(body)))
}

func printTable(rows [][2]string) {
	w := 0
	for _, r := range rows {
		if len(r[0]) > w {
			w = len(r[0])
		}
	}
	for _, r := range rows {
		fmt.Printf("%-*s  %s\n", w, r[0], r[1])
	}
}

// ---------- subcommand constructors ----------

func newListCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List pending (or all) certificate requests",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/certificate_statuses/all"
			if !all {
				path += "?state=requested"
			}

			code, body, err := c.get(path)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, body, "GET", path); err != nil {
				return err
			}

			var statuses []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			}
			if err := json.Unmarshal(body, &statuses); err != nil {
				return fmt.Errorf("could not parse response: %w", err)
			}

			if len(statuses) == 0 {
				fmt.Println("(no certificates)")
				return nil
			}
			// Quoted here rather than in printTable: the name is whatever the
			// server returned, and quoting before the row means printTable's
			// width calculation counts the quotes, so the columns still line
			// up. An earlier version of this change claimed the table could
			// not be quoted without wrecking the alignment; reading printTable
			// shows that is false, and the claim is gone with it.
			rows := make([][2]string, len(statuses))
			for i, s := range statuses {
				rows[i] = [2]string{strconv.Quote(s.Name), s.State}
			}
			printTable(rows)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "List all certs (default: only pending CSRs)")
	return cmd
}

func newSignCmd() *cobra.Command {
	var certname string
	var all bool
	cmd := &cobra.Command{
		Use:          "sign",
		Short:        "Sign a pending CSR (or --all)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			if all {
				code, body, err := c.post("/puppet-ca/v1/sign/all", nil)
				if err != nil {
					return err
				}
				if err := checkHTTP(code, body, "POST", "/puppet-ca/v1/sign/all"); err != nil {
					return err
				}
				var result struct {
					Signed []string `json:"signed"`
				}
				if err := json.Unmarshal(body, &result); err != nil {
					return fmt.Errorf("parse error: %w", err)
				}
				if len(result.Signed) == 0 {
					fmt.Println("Signed: (none)")
				} else {
					// Each name quoted, for the same reason as the import
					// summary: this list is decoded from the server's response
					// body, so it is the one confirmation line here whose
					// contents the server chooses rather than the operator.
					// Quoting per element rather than the joined string keeps
					// the separator meaningful -- "a", "b" rather than "a, b",
					// which would read as a single name containing a comma.
					quoted := make([]string, len(result.Signed))
					for i, name := range result.Signed {
						quoted[i] = strconv.Quote(name)
					}
					fmt.Printf("Signed: %s\n", strings.Join(quoted, ", "))
				}
				return nil
			}

			if certname == "" {
				return fmt.Errorf("--certname or --all is required")
			}

			path := "/puppet-ca/v1/certificate_status/" + certname
			body, _ := json.Marshal(map[string]string{"desired_state": "signed"})
			code, respBody, err := c.put(path, body)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, respBody, "PUT", path); err != nil {
				return err
			}
			fmt.Printf("Signed %s\n", certname)
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to sign")
	cmd.Flags().BoolVar(&all, "all", false, "Sign all pending CSRs")
	return cmd
}

func newRevokeCmd() *cobra.Command {
	var (
		certname string
		serial   string
		force    bool
	)
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a certificate, by subject name or by serial number",
		Long: `Revoke a certificate.

With --certname, the certificate revoked is the one most recently issued for
that name. With --serial, it is that exact certificate, whether or not a newer
one has since been issued for the same name — which is the only way to retire a
superseded certificate, since asking for the subject would revoke its live
replacement instead.

A serial that is still the certificate stored for its subject is refused, since
--certname already covers that case and a mistyped digit should not take a
working node offline. Pass --force when retiring a live certificate by serial is
what you meant.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			var (
				path    string
				body    []byte
				subject string
			)
			// Keyed on whether the flag was given, not on whether its value is
			// non-empty. cobra's flag-group checks key on Changed, so
			// `--serial ""` satisfies them; branching on the value instead sent
			// it down the by-NAME path as PUT /certificate_status/ with an empty
			// certname — silently addressing a different route, which is the one
			// thing the escaping below exists to prevent — and dropped --force
			// on the way. Refused here so the operator is told, rather than
			// having the server answer 404 for a path with no serial in it.
			if cmd.Flags().Changed("serial") {
				if strings.TrimSpace(serial) == "" {
					return fmt.Errorf("--serial requires a serial number")
				}
				// Escaped because the value is operator-typed: an embedded "/"
				// would otherwise silently address a different route rather
				// than reaching the server's own serial validation.
				path = "/puppet-ca/v1/certificate_status_by_serial/" + url.PathEscape(serial)
				body, _ = json.Marshal(map[string]any{"desired_state": "revoked", "force": force})
				subject = "serial " + serial
			} else {
				path = "/puppet-ca/v1/certificate_status/" + certname
				body, _ = json.Marshal(map[string]string{"desired_state": "revoked"})
				subject = certname
			}

			code, respBody, err := c.put(path, body)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, respBody, "PUT", path); err != nil {
				return err
			}
			fmt.Printf("Revoked %s\n", subject)
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to revoke (revokes its most recent certificate)")
	cmd.Flags().StringVar(&serial, "serial", "", "Hexadecimal serial number of the exact certificate to revoke")
	cmd.Flags().BoolVar(&force, "force", false, "With --serial, revoke even if it is the certificate currently stored for its subject")
	cmd.MarkFlagsMutuallyExclusive("certname", "serial")
	cmd.MarkFlagsOneRequired("certname", "serial")
	// --force only means anything on the by-serial path: the by-name path has no
	// guard for it to override, so accepting it there would imply one exists.
	cmd.MarkFlagsMutuallyExclusive("certname", "force")
	return cmd
}

func newReissueCRLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "reissue-crl",
		Short:        "Re-sign the CRL with a fresh validity window (preserves all revocations)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/certificate_revocation_list/ca"
			code, respBody, err := c.put(path, nil)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, respBody, "PUT", path); err != nil {
				return err
			}
			fmt.Println("Reissued CRL")
			return nil
		},
	}
	return cmd
}

func newCleanCmd() *cobra.Command {
	var certname string
	cmd := &cobra.Command{
		Use:          "clean",
		Short:        "Revoke and delete a certificate/CSR",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/certificate_status/" + certname
			code, respBody, err := c.delete(path)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, respBody, "DELETE", path); err != nil {
				return err
			}
			fmt.Printf("Cleaned %s\n", certname)
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to clean")
	_ = cmd.MarkFlagRequired("certname")
	return cmd
}

func newGenerateCmd() *cobra.Command {
	var certname, outDir, dns string
	cmd := &cobra.Command{
		Use:          "generate",
		Short:        "Generate a server-side key+cert pair",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/generate/" + certname
			if dns != "" {
				path += "?dns=" + strings.ReplaceAll(dns, ",", "&dns=")
			}

			code, body, err := c.post(path, nil)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, body, "POST", path); err != nil {
				return err
			}

			var result struct {
				PrivateKey  string `json:"private_key"`
				Certificate string `json:"certificate"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return fmt.Errorf("could not parse response: %w", err)
			}

			keyPath := filepath.Join(outDir, certname+"_key.pem")
			if err := os.WriteFile(keyPath, []byte(result.PrivateKey), 0600); err != nil {
				return fmt.Errorf("failed to save private key to %s: %w", keyPath, err)
			}
			fmt.Fprintf(os.Stderr, "Private key saved to %s\n", keyPath)
			// NOT quoted, deliberately, and not an oversight: this is the PEM
			// itself on stdout, while the human-readable line above goes to
			// stderr. That split is a contract -- `openvox-ca-ctl generate ...
			// > cert.pem` has to yield a usable file -- so %q here would
			// corrupt every consumer that redirects. The escaping convention
			// in AGENTS.md covers operator-facing *messages*; this is data.
			fmt.Print(result.Certificate)
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to generate")
	cmd.Flags().StringVar(&outDir, "out-dir", ".", "Directory to save the private key file")
	cmd.Flags().StringVar(&dns, "dns", "", "Comma-separated DNS alt names")
	_ = cmd.MarkFlagRequired("certname")
	return cmd
}

// newImportCertCmd registers openvox-ca-ctl's "import-cert" subcommand,
// which imports a certificate issued OUTSIDE this CA's normal signing flow
// (e.g. migrated from a legacy CA sharing this CA's key) into the running
// server's inventory via PUT /certificate/{subject}. This is distinct from
// the "import" subcommand below, which imports a whole CA cert/key/CRL
// bundle offline, directly into storage.
func newImportCertCmd() *cobra.Command {
	var certname, certFile string
	cmd := &cobra.Command{
		Use:          "import-cert",
		Short:        "Import an externally-issued certificate into the inventory",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			certPEM, err := os.ReadFile(certFile)
			if err != nil {
				return fmt.Errorf("reading --cert-file: %w", err)
			}

			c, err := newClient()
			if err != nil {
				return err
			}

			path := "/puppet-ca/v1/certificate/" + certname
			code, body, err := c.put(path, certPEM)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, body, "PUT", path); err != nil {
				return err
			}

			var result struct {
				Subject   string `json:"subject"`
				Serial    string `json:"serial"`
				NotBefore string `json:"not_before"`
				NotAfter  string `json:"not_after"`
				Imported  bool   `json:"imported"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return fmt.Errorf("could not parse response: %w", err)
			}
			// %q on every field, not just the subject: all four come out of
			// the same json.Unmarshal of the same response body, and this CLI
			// does not trust that body. The server serving this route does
			// validate -- PUT /certificate/{subject} reaches handlePutCert,
			// which gates on ca.ValidateSubject, and ImportCertificate
			// validates again -- but that is the honest server's behaviour,
			// not a property of the bytes arriving here. A compromised or
			// MITM'd server (see the --insecure warning) chooses all of them
			// freely, and a serial or a timestamp carries a terminator just as
			// well as a name does.
			if result.Imported {
				fmt.Printf("Imported %q (serial %q, valid %q to %q)\n",
					result.Subject, result.Serial, result.NotBefore, result.NotAfter)
			} else {
				fmt.Printf("%q already tracked (serial %q), no changes made\n",
					result.Subject, result.Serial)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name for the imported certificate")
	cmd.Flags().StringVar(&certFile, "cert-file", "", "Path to the certificate PEM to import")
	_ = cmd.MarkFlagRequired("certname")
	_ = cmd.MarkFlagRequired("cert-file")
	return cmd
}

func newSetupCmd() *cobra.Command {
	var caDir, hostname string
	var encryptKey bool
	var passphraseFile string
	cmd := &cobra.Command{
		Use:          "setup",
		Short:        "Initialise a new CA (offline)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			absDir, err := filepath.Abs(caDir)
			if err != nil {
				return fmt.Errorf("invalid --cadir: %w", err)
			}

			store := storage.New(absDir)

			// A cadir with a server already running against it is not one to
			// initialise. The filesystem backend has no distributed locking, so
			// exactly one process may be running against it, and this refuses
			// with the holder's name rather than racing the server's bootstrap.
			instanceLock, err := store.AcquireInstanceLock(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = instanceLock.Unlock() }()

			myCA := ca.New(store, ca.AutosignConfig{Mode: "off"}, hostname)
			myCA.EncryptCAKey = encryptKey
			myCA.KeyPassphrase = ca.KeyPassphraseConfig{
				PassphraseFile: passphraseFile,
			}
			if err := myCA.Init(cmd.Context()); err != nil {
				return err
			}
			fmt.Printf("CA initialized in %s (CN: Puppet CA: %s)\n", absDir, hostname)
			return nil
		},
	}
	cmd.Flags().StringVar(&caDir, "cadir", "", "Directory to initialise CA in")
	cmd.Flags().StringVar(&hostname, "hostname", "puppet", "Hostname for the CA certificate CN")
	cmd.Flags().BoolVar(&encryptKey, "encrypt-ca-key", false, "Encrypt the CA private key at rest")
	cmd.Flags().StringVar(&passphraseFile, "ca-key-passphrase-file", "", "Path to file containing the CA key passphrase")
	_ = cmd.MarkFlagRequired("cadir")
	return cmd
}

func newImportCmd() *cobra.Command {
	var caDir, certBundle, privateKey, crlChain string
	cmd := &cobra.Command{
		Use:          "import",
		Short:        "Import an external CA cert/key (offline)",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			absDir, err := filepath.Abs(caDir)
			if err != nil {
				return fmt.Errorf("invalid --cadir: %w", err)
			}

			certPEM, err := os.ReadFile(certBundle)
			if err != nil {
				return fmt.Errorf("reading --cert-bundle: %w", err)
			}
			if privateKey == "" {
				// The CA key may legitimately not exist as a file: with
				// ca_key_provider set it lives in OpenBao Transit or a PKCS#11
				// token and is never exportable. That case is served by
				// "openvox-ca import-ca-cert", which reaches the configured
				// provider and proves the certificate matches the key instead of
				// being handed it. This command cannot: it addresses a local
				// directory only.
				return fmt.Errorf("--private-key is required by this command.\n\n" +
					"If the CA key lives at a provider (ca_key_provider: openbao) there is no key file to " +
					"supply — use 'openvox-ca import-ca-cert --cert-bundle <file>' instead, which reads the " +
					"server configuration and reaches the key where it actually lives")
			}
			keyPEM, err := os.ReadFile(privateKey)
			if err != nil {
				return fmt.Errorf("reading --private-key: %w", err)
			}
			var crlPEM []byte
			if crlChain != "" {
				crlPEM, err = os.ReadFile(crlChain)
				if err != nil {
					return fmt.Errorf("reading --crl-chain: %w", err)
				}
			}

			store := storage.New(absDir)

			// Replacing the CA certificate and key under a running server is the
			// unsupported configuration this refuses: one instance is all the
			// filesystem backend supports.
			instanceLock, err := store.AcquireInstanceLock(cmd.Context())
			if err != nil {
				return err
			}
			defer func() { _ = instanceLock.Unlock() }()

			if err := ca.ImportCA(cmd.Context(), store, certPEM, keyPEM, crlPEM); err != nil {
				return err
			}
			fmt.Printf("CA imported into %s\n", absDir)
			return nil
		},
	}
	cmd.Flags().StringVar(&caDir, "cadir", "", "CA storage directory")
	cmd.Flags().StringVar(&certBundle, "cert-bundle", "", "Path to CA certificate PEM")
	cmd.Flags().StringVar(&privateKey, "private-key", "", "Path to CA private key PEM (required; see 'openvox-ca import-ca-cert' when the key lives at a provider)")
	cmd.Flags().StringVar(&crlChain, "crl-chain", "", "Path to a CRL PEM, or several concatenated in any order (optional; when omitted the stored CRL chain is left as it is, one is generated if none is stored, and the import is refused if nothing stored was signed by the certificate being imported)")
	_ = cmd.MarkFlagRequired("cadir")
	_ = cmd.MarkFlagRequired("cert-bundle")
	return cmd
}

// ---------- main ----------

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd builds and returns the fully-configured root command, including
// all flag wiring. Extracted from main() so the command can be exercised in
// unit tests (e.g. flag behaviour) without invoking os.Exit.
func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     "openvox-ca-ctl",
		Short:   "Operator management CLI for openvox-ca",
		Version: version.Full(),
		Long: `openvox-ca-ctl manages certificates on a running openvox-ca server.

Global flags may be placed before or after the subcommand name.`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			resolved := resolveConfigFile(globalConfigFile, "PUPPET_CA_CTL_CONFIG", "/etc/puppet-ca/ctl.yaml")
			cfg, err := loadCtlConfig(resolved)
			if err != nil {
				return err
			}

			// Apply explicitly-set CLI flags (highest precedence).
			pf := cmd.Root().PersistentFlags()
			if pf.Changed("server-url") {
				cfg.ServerURL = globalServerURL
			}
			if pf.Changed("ca-cert") {
				cfg.CACert = globalCACert
			}
			if pf.Changed("client-cert") {
				cfg.ClientCert = globalClientCert
			}
			if pf.Changed("client-key") {
				cfg.ClientKey = globalClientKey
			}
			if pf.Changed("verbose") {
				cfg.Verbose = globalVerbose
			}
			if pf.Changed("insecure") {
				cfg.Insecure = globalInsecure
			}

			// Assign resolved values back to globals used by subcommands.
			globalServerURL = cfg.ServerURL
			globalCACert = cfg.CACert
			globalClientCert = cfg.ClientCert
			globalClientKey = cfg.ClientKey
			globalVerbose = cfg.Verbose
			globalInsecure = cfg.Insecure

			if globalVerbose {
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
			}
			return nil
		},
	}

	pf := rootCmd.PersistentFlags()
	pf.StringVar(&globalConfigFile, "config", "", "Path to YAML config file (default: /etc/puppet-ca/ctl.yaml if it exists)")
	pf.StringVar(&globalServerURL, "server-url", "https://localhost:8140", "openvox-ca server URL")
	pf.StringVar(&globalCACert, "ca-cert", "", "Path to CA cert PEM for TLS verification (omit to use system trust store)")
	pf.StringVar(&globalClientCert, "client-cert", "", "Path to client certificate PEM for mTLS")
	pf.StringVar(&globalClientKey, "client-key", "", "Path to client private key PEM for mTLS")
	// The -v shorthand keeps this in line with the server binary, where -v is
	// --verbosity; it also stops cobra claiming -v as a shorthand for the
	// synthesised --version flag, which would give the two sibling binaries
	// opposite meanings for -v.
	pf.BoolVarP(&globalVerbose, "verbose", "v", false, "Enable verbose logging")
	pf.BoolVar(&globalInsecure, "insecure", false, "Skip TLS server certificate verification (vulnerable to MITM; use only for testing)")

	rootCmd.AddCommand(
		newListCmd(),
		newSignCmd(),
		newRevokeCmd(),
		newReissueCRLCmd(),
		newCleanCmd(),
		newGenerateCmd(),
		newImportCertCmd(),
		newSetupCmd(),
		newImportCmd(),
		newMigrateCmd(),
	)

	return rootCmd
}
