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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/voxpupuli/openvox-ca/internal/api"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
)

// certReloader owns the server's TLS keypair and can swap it for a freshly
// read one without disturbing established connections.
//
// The CA's own server certificate is issued for a bounded lifetime like any
// other, so it has to be replaced periodically. Handing crypto/tls a
// GetCertificate callback instead of a fixed certificate means renewal costs a
// reload rather than a restart: connections in flight keep the certificate
// they negotiated with, and the next handshake picks up the new one.
type certReloader struct {
	certFile string
	keyFile  string

	// current is the keypair handed to new handshakes. It is read on every
	// handshake and replaced on reload, so it is held in an atomic pointer
	// rather than behind a lock.
	current atomic.Pointer[tls.Certificate]
}

// newCertReloader loads the keypair for the first time, failing if it cannot
// be read: an unusable certificate at startup is a configuration error and the
// server must not come up pretending otherwise.
func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	c := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// reload re-reads the keypair from disk and, only if it is complete and
// internally consistent, installs it. A failed read leaves the previous
// certificate in place, so reloading while the files are being rewritten
// cannot leave the server without a certificate.
func (c *certReloader) reload() error {
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("loading TLS cert/key (cert %s, key %s): %w", c.certFile, c.keyFile, err)
	}
	c.current.Store(&cert)

	if cert.Leaf != nil {
		slog.Info("Loaded TLS certificate",
			"cert", c.certFile,
			"subject", cert.Leaf.Subject.CommonName,
			"not_after", cert.Leaf.NotAfter)
	}
	return nil
}

// GetCertificate satisfies tls.Config.GetCertificate.
func (c *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := c.current.Load()
	if cert == nil {
		// Unreachable: newCertReloader stores one before the listener exists.
		return nil, errors.New("no TLS certificate loaded")
	}
	return cert, nil
}

// configReloader re-applies the parts of the configuration that are backed by
// files and can be swapped safely while the server is running.
//
// Deliberately narrow: everything else (listen address, storage backend, key
// custody, CA properties) is bound to state established at startup, and
// pretending otherwise would be worse than requiring a restart. See
// docs/systemd.md for the operator-facing description.
type configReloader struct {
	// certs is the TLS keypair holder, or nil when the server is running
	// without TLS and there is nothing to rotate.
	certs *certReloader

	// auth is the live authorization config whose admin allow list is
	// replaced, or nil when no mTLS enforcement is configured.
	auth *api.AuthConfig

	// staticCNs is the comma-separated --puppet-server value from the running
	// configuration. It cannot change without a restart, but it is merged with
	// the file on every reload so the resulting list stays complete.
	staticCNs string

	// cnFile is the --puppet-server-file path, re-read on every reload.
	cnFile string

	// failed records whether the most recent reload failed, so the state
	// survives in the status text instead of being overwritten by the next
	// heartbeat. Read from the status closure on another goroutine, hence
	// atomic.
	failed atomic.Bool
}

// statusSuffix annotates the service manager's status text while the running
// configuration is older than the one on disk. A `systemctl reload` that
// quietly failed is how an operator ends up believing a certificate was
// rotated when it was not, so the notice stays put until a reload succeeds.
func (r *configReloader) statusSuffix() string {
	if r != nil && r.failed.Load() {
		return " | last reload FAILED, see the logs"
	}
	return ""
}

// reload re-reads every file-backed input. Each input is attempted even when
// an earlier one failed — a broken allow list should not stop a certificate
// rotation from landing — and the failures are reported together.
func (r *configReloader) reload() error {
	var errs []error

	if r.certs != nil {
		if err := r.certs.reload(); err != nil {
			errs = append(errs, err)
		}
	}

	if r.auth != nil {
		allowList, err := buildAdminAllowList(r.staticCNs, r.cnFile)
		if err != nil {
			errs = append(errs, err)
		} else {
			r.auth.SetAllowList(allowList)
			slog.Info("Reloaded admin allow list", "admin_cns", len(allowList))
		}
	}

	err := errors.Join(errs...)
	r.failed.Store(err != nil)
	return err
}

// buildAdminAllowList merges the comma-separated CN list from the running
// configuration with the current contents of the allow-list file. It is the
// single construction point for the admin allow list, used both at startup and
// on reload, so the two can never diverge.
func buildAdminAllowList(staticCNs, cnFile string) (map[string]bool, error) {
	allowList := map[string]bool{}
	for _, cn := range strings.Split(staticCNs, ",") {
		if cn = strings.TrimSpace(cn); cn != "" {
			allowList[cn] = true
		}
	}
	fileCNs, err := loadPuppetServerFile(cnFile)
	if err != nil {
		return nil, err
	}
	for _, cn := range fileCNs {
		allowList[cn] = true
	}
	return allowList, nil
}

// runReloadWatcher applies a configuration reload on every SIGHUP until ctx is
// cancelled. It also reports the reload to the service manager, which is what
// makes `systemctl reload` (Type=notify-reload) wait for the new configuration
// to be in effect rather than returning the instant the signal is delivered.
//
// A reload that fails is not fatal: the previous configuration is still in
// place and still correct, so the server keeps serving. The failure is logged,
// and statusSuffix keeps it visible in the status text until a later reload
// succeeds. READY=1 is sent either way — the protocol requires it to close out
// RELOADING=1, and withholding it would only hang the reload job without
// telling the operator anything the logs do not.
func runReloadWatcher(ctx context.Context, n *sdnotify.Notifier, r *configReloader, status func() string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sigCh:
			slog.Info("Reloading configuration (SIGHUP)")
			n.Reloading("Reloading TLS material and the admin allow list")

			if err := r.reload(); err != nil {
				slog.Error("Configuration reload failed; keeping the previous configuration", "error", err)
			} else {
				slog.Info("Configuration reloaded")
			}
			n.Ready(status())
		}
	}
}
