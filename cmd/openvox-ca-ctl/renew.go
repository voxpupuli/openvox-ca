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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/voxpupuli/openvox-ca/internal/ca"
)

// newRenewCmd registers openvox-ca-ctl's "renew" subcommand: renew the
// certificate stored for a name through POST /renew/{subject}, for a holder
// that runs no agent to renew itself (#247).
//
// Three ways to choose the key, one per request shape the route accepts:
//
//   - the default re-keys with a key generated here, of the same algorithm as
//     the current certificate's, so the private key never crosses the network
//     and is written to --out-dir as generate writes its own;
//   - --csr sends a CSR the certificate's holder made, re-keying onto its key;
//   - --keep-key sends no CSR, and the server reissues over the key the stored
//     certificate already names. That needs no private key, which is why it
//     works for a certificate whose key the operator does not hold.
//
// The certificate PEM goes to stdout and every human line to stderr, as
// generate does, so `openvox-ca-ctl renew ... > cert.pem` yields a usable file.
func newRenewCmd() *cobra.Command {
	var certname, outDir, csrFile string
	var keepKey bool
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew a certificate on the server, re-keying by default",
		Long: `Renew the certificate stored for --certname through the running server, for a
certificate whose holder runs no agent to renew it.

The new certificate carries the same subject and extensions as the current one.
The certificate it replaces stays valid for the server's
superseded_cert_revoke_after_sec (24 hours by default), so whatever holds it can
pick up the replacement first.

By default a new key of the same algorithm is generated here, written to
--out-dir/<certname>_key.pem at mode 0600, and never sent anywhere. A key
already at that path is overwritten once the server has renewed, so if it is
the key the old certificate is still being served with, install the new
certificate beside it straight away: the overlap window keeps the old
certificate valid for relying parties, not the old key on disk. --csr renews
onto the key in a CSR its holder made instead, and --keep-key reissues over the
current key without needing it. A certificate carrying pp_cli_auth can only be
renewed with --keep-key, and an expired certificate cannot be renewed at all.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := certnamePath("/puppet-ca/v1/renew/", certname)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("out-dir") && (keepKey || csrFile != "") {
				return errors.New("--out-dir applies only when renew generates the key; " +
					"it cannot be combined with --keep-key or --csr")
			}

			var body []byte
			var keyPath string
			var replacingKey bool
			var keyPEM []byte
			switch {
			case csrFile != "":
				body, err = os.ReadFile(csrFile)
				if err != nil {
					return fmt.Errorf("--csr: %w; nothing was sent to the server", err)
				}
			case !keepKey:
				// The key file is named after the certname, as generate's is,
				// so the reservation that keeps generate from writing ca_key.pem
				// applies here too.
				if err := ca.CheckKeySubject(certname); err != nil {
					return fmt.Errorf("%w; or renew it with --csr or --keep-key", err)
				}
				// certnamePath has validated certname, so the key path cannot
				// leave --out-dir.
				keyPath = filepath.Join(outDir, certname+"_key.pem")
				if err := checkKeyPath(outDir, keyPath); err != nil {
					return err
				}
				// checkKeyPath has refused anything at the path but a regular
				// file, so this only tells a key being replaced from a new one.
				if _, err := os.Lstat(keyPath); err == nil {
					replacingKey = true
				}
			}

			c, err := newClient()
			if err != nil {
				return err
			}
			if keyPath != "" {
				body, keyPEM, err = renewalCSR(c, certname)
				if err != nil {
					return err
				}
			}

			code, resp, err := c.post(path, body)
			if err != nil {
				return err
			}
			if err := checkHTTP(code, resp, "POST", path); err != nil {
				return err
			}

			if keyPath != "" {
				if err := writeKeyFile(keyPath, string(keyPEM)); err != nil {
					return fmt.Errorf("failed to save private key to %s: %w (the certificate was renewed, "+
						"and the one it replaced is being retired; run renew --certname %s again to re-key)",
						keyPath, err, certname)
				}
				if replacingKey {
					fmt.Fprintf(os.Stderr, "Private key saved to %s, replacing the key that was there; "+
						"install the new certificate with it\n", keyPath)
				} else {
					fmt.Fprintf(os.Stderr, "Private key saved to %s\n", keyPath)
				}
			}
			fmt.Fprintf(os.Stderr, "Renewed %s\n", certname)
			// NOT quoted: this is the PEM itself, on stdout, as in generate.
			fmt.Print(string(resp))
			return nil
		},
	}
	cmd.Flags().StringVar(&certname, "certname", "", "Subject name to renew")
	cmd.Flags().StringVar(&outDir, "out-dir", ".", "Directory to save the new private key file")
	cmd.Flags().StringVar(&csrFile, "csr", "", "Renew onto the key in this CSR file instead of generating one")
	cmd.Flags().BoolVar(&keepKey, "keep-key", false, "Reissue over the current certificate's key")
	cmd.MarkFlagsMutuallyExclusive("csr", "keep-key")
	_ = cmd.MarkFlagRequired("certname")
	return cmd
}

// renewalCSR fetches the certificate currently stored for certname, generates a
// key of the same algorithm, and returns a CSR for it with the key's PEM.
//
// The current certificate is read only for its key's algorithm and size. The
// server takes nothing from the CSR but the key, so the CSR carries the Common
// Name alone.
func renewalCSR(c *Client, certname string) (csrPEM, keyPEM []byte, err error) {
	path, err := certnamePath("/puppet-ca/v1/certificate/", certname)
	if err != nil {
		return nil, nil, err
	}
	code, resp, err := c.get(path)
	if err != nil {
		return nil, nil, err
	}
	if err := checkHTTP(code, resp, "GET", path); err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(resp)
	if block == nil {
		return nil, nil, fmt.Errorf("the server's certificate for %s is not PEM; nothing was renewed", certname)
	}
	current, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing the server's certificate for %s: %w; nothing was renewed", certname, err)
	}
	key, keyPEM, err := ca.NewKeyLike(current.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating a key like the current one: %w; renew with --csr "+
			"and a key that meets policy; nothing was renewed", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: certname}}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating the CSR: %w; nothing was renewed", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), keyPEM, nil
}
