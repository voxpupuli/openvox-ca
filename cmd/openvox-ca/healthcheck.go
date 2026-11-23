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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// healthProbePaths maps each --probe value to the endpoint it requests. They
// are the three the chart's kubelet probes use.
var healthProbePaths = map[string]string{
	"live":    "/healthz/live",
	"ready":   "/healthz/ready",
	"startup": "/healthz/startup",
}

// defaultHealthcheckTimeout bounds the whole check. It sits below the 5s
// --timeout the images' HEALTHCHECK gives the container runtime, so a hung
// server is reported by this command, with a reason, rather than by the
// runtime killing it.
const defaultHealthcheckTimeout = 3 * time.Second

// newHealthcheckCmd builds the "healthcheck" subcommand, for a container
// image's HEALTHCHECK. An image with no shell and no HTTP client, such as the
// distroless one, can run only what it already carries, so the check is part
// of the server binary.
//
// It reads the server's own configuration file and environment to find the
// port, but it cannot see the flags the server was started with, so it does
// not take TLS from configuration: TLS can be enabled where it cannot look,
// such as --tls-cert on the server's command line under
// OPENVOX_CA_CONFIG=/dev/null. It tries HTTPS and falls back to plain HTTP
// only when the server answers in plain HTTP.
func newHealthcheckCmd() *cobra.Command {
	var (
		configFile string
		host       string
		port       int
		probe      string
		timeout    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Exit 0 when the local server answers its health endpoint with 200, 1 otherwise",
		Long: `Request one of the server's health endpoints and exit 0 if it answers 200,
or 1 with a one-line reason if it does not. Meant for a container HEALTHCHECK.

The port and listen address come from the server's configuration file and
OPENVOX_CA_* environment, as the server reads them; --port and --host override
them. A wildcard listen address is checked over loopback. Flags given to the
server itself are not visible here, so a port set only on the server's command
line has to be repeated with --port.

HTTPS is tried first, and plain HTTP only when the server answers in plain HTTP.
The server's certificate is not verified: the check sends no credentials, and
reads only the status code and, on a failure, the not_ready reason, which it
prints quoted. Nothing it reads changes its result, so a peer it cannot
authenticate can do no more than word the failure message.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, ok := healthProbePaths[probe]
			if !ok {
				return fmt.Errorf("--probe must be one of %s, not %q", healthProbeNames(), probe)
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be positive, not %s", timeout)
			}

			cfg, err := loadServerConfig(resolveConfigFile(configFile, configEnvVar, defaultConfigFile))
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("host") {
				cfg.Host = host
			}
			if cmd.Flags().Changed("port") {
				cfg.Port = port
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			url, err := checkHealth(ctx, healthcheckAddr(cfg.Host, cfg.Port), path)
			if err != nil {
				return fmt.Errorf("unhealthy: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "healthy: %s\n", url)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&configFile, "config", "", "Path to the server's YAML config file (default: "+defaultConfigFile+" if it exists)")
	f.StringVar(&host, "host", "", "Address to check, overriding the configured listen address (default: loopback when the server listens on every address)")
	f.IntVar(&port, "port", 0, "Port to check, overriding the configured one (default: the server's, 8140 unless configured)")
	f.StringVar(&probe, "probe", "ready", "Health endpoint to request: "+healthProbeNames())
	f.DurationVar(&timeout, "timeout", defaultHealthcheckTimeout, "Give up and report unhealthy after this long")
	return cmd
}

// healthProbeNames lists the --probe values for help and error text.
func healthProbeNames() string {
	names := make([]string, 0, len(healthProbePaths))
	for name := range healthProbePaths {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// healthcheckAddr is the address to connect to for a server listening on
// host:port. The server joins the two with a plain "%s:%d", so an IPv6 host
// arrives bracketed. A wildcard address is not one a client can connect to;
// loopback of the same family is, and it is the one interface such a server
// is certain to be listening on.
func healthcheckAddr(host string, port int) string {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	switch ip := net.ParseIP(host); {
	case host == "":
		host = "127.0.0.1"
	case ip != nil && ip.IsUnspecified() && ip.To4() != nil:
		host = "127.0.0.1"
	case ip != nil && ip.IsUnspecified():
		host = "::1"
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// healthcheckTransport is the transport every request goes through. Proxy
// stays nil, unlike http.DefaultTransport's, so an HTTP(S)_PROXY in the
// container's environment cannot route the check to some other host: Go
// exempts loopback from those variables, but not the specific address a
// server bound with --host. Verification is off for the reason the command's
// help gives.
func healthcheckTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // G402: the check sends nothing, and reads only a status code and a quoted reason that cannot change its result; see the command's help
			MinVersion:         tls.VersionTLS12,
		},
		DisableKeepAlives: true,
	}
}

// checkHealth requests path from the server at addr and returns the URL it
// used. Any answer but 200 is an error naming the status code, and the
// not_ready reason when the body carries one -- a pod held for its upstream
// CRL chain then says so in `docker inspect` rather than reading like a CA
// that never initialised. Never the reason phrase after the code: that is the
// server's own text, which Go's client does not sanitise and which reaches a
// terminal unescaped from here. The body's reason is the server's too, so it
// is quoted.
func checkHealth(ctx context.Context, addr, path string) (string, error) {
	tr := healthcheckTransport()
	defer tr.CloseIdleConnections()

	scheme, err := healthcheckScheme(ctx, addr, tr.TLSClientConfig)
	if err != nil {
		return "", err
	}
	url := scheme + "://" + addr + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Transport: tr,
		// A redirect is not a healthy answer, and following one would check
		// whatever it points at instead.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		var answer struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(body, &answer) == nil && answer.Reason != "" {
			return "", fmt.Errorf("%s answered HTTP %d (reason %q)", url, resp.StatusCode, answer.Reason)
		}
		return "", fmt.Errorf("%s answered HTTP %d", url, resp.StatusCode)
	}
	return url, nil
}

// healthcheckScheme reports whether the server at addr speaks TLS. It
// completes a handshake, and falls back to "http" only when the first record
// the server sent back is the start of a plain HTTP response -- which is how
// Go's HTTP server answers a ClientHello. Any other failure is returned, so a
// server that is down or half-up is unhealthy rather than retried in clear.
func healthcheckScheme(ctx context.Context, addr string, cfg *tls.Config) (string, error) {
	d := &tls.Dialer{Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return "https", nil
	}
	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) && string(rhe.RecordHeader[:]) == "HTTP/" {
		return "http", nil
	}
	return "", err
}
