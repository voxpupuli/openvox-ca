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
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

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

		// LoadX509KeyPair checks only that the certificate and key correspond,
		// and a Go TLS server does not validate its own leaf — so a rotation
		// that installed a stale or not-yet-valid keypair would otherwise
		// report success while every new handshake failed at the agent.
		now := time.Now()
		switch {
		case now.After(cert.Leaf.NotAfter):
			slog.Warn("The TLS certificate just loaded has already expired; clients will reject it",
				"cert", c.certFile, "not_after", cert.Leaf.NotAfter)
		case now.Before(cert.Leaf.NotBefore):
			slog.Warn("The TLS certificate just loaded is not valid yet; clients will reject it until then",
				"cert", c.certFile, "not_before", cert.Leaf.NotBefore)
		}

		// The same blind spot, one level up: a certificate can be current and
		// still be the wrong kind of certificate. Pointing tls_cert at the
		// CA's own ca_crt.pem is the case this exists for -- it loads, the
		// server logs "TLS enabled", the handshake completes, and every
		// client that verifies the certificate rejects it.
		if problems := servingCertProblems(cert.Leaf); len(problems) > 0 {
			slog.Warn("The TLS certificate just loaded cannot serve TLS to a client that verifies it; issue a serving certificate with `openvox-ca-ctl generate` and point tls_cert/tls_key at that",
				"cert", c.certFile,
				"subject", cert.Leaf.Subject.CommonName,
				"problems", strings.Join(problems, "; "))
		}

		// Kept separate from the faults above, and worded as advice rather
		// than as a fact about the handshake, because it is not one: a
		// self-signed certificate with CA:TRUE, a SAN and serverAuth -- what
		// `openssl req -x509` produces by default -- verifies and serves
		// perfectly well. OpenSSL applies its CA checks to a certificate in
		// the issuer position, not the end-entity one, and Go never rejects a
		// CA leaf. What is wrong with it is custodial, not protocol.
		if cert.Leaf.IsCA {
			slog.Warn("The TLS certificate just loaded is a CA certificate; serving from it puts a signing key on the network-facing listener. Issue an end-entity certificate with `openvox-ca-ctl generate` and point tls_cert/tls_key at that",
				"cert", c.certFile,
				"subject", cert.Leaf.Subject.CommonName)
		}
	}
	return nil
}

// servingCertProblems reports the reasons leaf cannot authenticate this server
// to a client that verifies it, as phrases to be joined into one log line.
//
// Every check here is for something neither tls.LoadX509KeyPair nor a Go TLS
// server looks at: crypto/tls presents whatever keypair it was handed, so an
// unusable certificate is silent on this side and fatal on the other. The set
// is the ways the certificate is wrong *in itself*; whether it names the host
// the agent dialled is the client's business and cannot be checked from here.
//
// Absent extensions are deliberately not faults. A certificate with no
// extendedKeyUsage at all is unconstrained, and both Go and OpenSSL accept it
// for serverAuth; only an extendedKeyUsage that is present and excludes
// serverAuth rules the certificate out. keyUsage is treated the same way, with
// one acknowledged imprecision: Go surfaces it as a bit set, so an extension
// that is present with every bit clear is indistinguishable here from one that
// is absent, and is let through. That certificate permits nothing and would be
// a genuine fault, but nothing issues one.
//
// basicConstraints is not consulted. CA:TRUE on a leaf does not stop a client
// verifying it -- reload() warns about that separately, as custody advice.
func servingCertProblems(leaf *x509.Certificate) []string {
	var problems []string

	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		// Go dropped the commonName fallback in 1.15 and the browsers before
		// that, so there is no name here for a client to match, whatever the
		// subject says and whatever hostname is set to.
		problems = append(problems, "it has no subjectAltName, and clients match the hostname against SANs only")
	}

	// A keyUsage of certSign|cRLSign -- what a CA certificate carries -- has
	// neither of the bits a TLS server needs: digitalSignature for the
	// handshake signature, keyEncipherment for RSA key exchange.
	if leaf.KeyUsage != 0 && leaf.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) == 0 {
		problems = append(problems, "its keyUsage allows neither digitalSignature nor keyEncipherment")
	}

	if ekuPresent(leaf) && !ekuPermitsServerAuth(leaf) {
		problems = append(problems, "its extendedKeyUsage is present but does not include serverAuth")
	}

	return problems
}

// ekuPresent reports whether the certificate carries an extendedKeyUsage
// extension at all. Go splits it across two fields -- recognised usages in
// ExtKeyUsage, unrecognised OIDs in UnknownExtKeyUsage -- so a certificate
// constrained solely to some OID Go has no constant for is only visible in the
// second.
func ekuPresent(leaf *x509.Certificate) bool {
	return len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0
}

// ekuPermitsServerAuth reports whether the extendedKeyUsage admits serving
// TLS. anyExtendedKeyUsage counts: it is the explicit "no constraint".
func ekuPermitsServerAuth(leaf *x509.Certificate) bool {
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
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
	// certs is the operator-supplied TLS keypair holder, or nil when there is
	// nothing for a reload to rotate: no TLS at all, or a self-provisioned
	// serving certificate, whose renewal the reconcile loop owns and which has
	// no configured path to re-read.
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
			// SECURITY: log which CNs gained or lost admin authority, not just
			// how many there are. A count alone cannot distinguish "the list is
			// unchanged" from "one compile server was swapped for another", and
			// this is the only moment the change is observable — the file can be
			// rewritten again straight afterwards. CNs are hostnames, not secrets.
			// NIST 800-53: AU-2 (Event Logging), AC-6 (Least Privilege)
			// Read everything the log line needs before the swap: once
			// SetOwnAdminCNs returns, the map belongs to the trust domain and
			// request goroutines are reading it under the lock.
			//
			// Domain zero only. A client_ca entry's admin_cns are startup
			// configuration: re-reading them would mean re-reading that
			// issuer's certificates too, which is not what reload promises.
			count := len(allowList)
			added, removed := diffAllowList(r.auth.SetOwnAdminCNs(allowList), allowList)
			if len(added) > 0 || len(removed) > 0 {
				slog.Info("Reloaded admin allow list",
					"added", added, "removed", removed, "admin_cns", count)
			} else {
				slog.Info("Reloaded admin allow list, unchanged", "admin_cns", count)
			}
		}
	}

	err := errors.Join(errs...)
	r.failed.Store(err != nil)
	return err
}

// reloadingStatus says what this reload will actually re-read, for the status
// text systemd shows while `systemctl reload` runs.
//
// A self-provisioning CA has no keypair to re-read: certs is nil because the
// reconcile loop owns that certificate, and announcing "Reloading TLS material"
// there invites the belief that a reload rotated it. This is the one place an
// operator running the command looks.
//
// Both fields, not just certs. reload() re-reads the allow list only when auth
// is non-nil, and auth is set only when TLS is configured (main.go wires the
// middleware inside that branch) -- so a plain-HTTP CA has neither, and
// reporting "Reloading the admin allow list" there names work that does not
// happen. Testing certs alone was right for the two TLS states and wrong for
// the third, which is the state nothing else reports on.
//
// Three states are reachable, not four: certs is non-nil only when
// tls_cert/tls_key are set, which is itself a way of configuring TLS, so auth
// is non-nil whenever certs is. The certs-without-auth arm is therefore
// unreachable and deliberately not spelled out -- if it ever becomes
// reachable, the default below names TLS material, which is the safe half to
// over-report.
func (r *configReloader) reloadingStatus() string {
	switch {
	case r.certs == nil && r.auth == nil:
		return "Reloading nothing (no TLS material and no admin allow list configured)"
	case r.certs == nil:
		return "Reloading the admin allow list"
	default:
		return "Reloading TLS material and the admin allow list"
	}
}

// diffAllowList reports which CNs the replacement adds and which it withdraws,
// each sorted so the log line is stable and diffable.
func diffAllowList(old, new map[string]bool) (added, removed []string) {
	for cn := range new {
		if !old[cn] {
			added = append(added, cn)
		}
	}
	for cn := range old {
		if !new[cn] {
			removed = append(removed, cn)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
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

// runReloadWatcher applies a configuration reload on every signal delivered to
// hupCh until ctx is cancelled. It also reports the reload to the service
// manager, which is what makes `systemctl reload` (Type=notify-reload) wait for
// the new configuration to be in effect rather than returning the instant the
// signal is delivered.
//
// hupCh is registered by the caller, before the startup work this watcher's
// configuration depends on. That ordering matters: SIGHUP's default disposition
// is to terminate, so a reload arriving during a slow start would otherwise kill
// the process instead of reloading it, and a reload racing the READY=1 that
// releases a queued reload job would fall into the gap between announcing
// readiness and this goroutine being scheduled. A signal that arrives before
// this loop runs waits in the channel buffer and is applied on entry.
//
// A reload that fails is not fatal: the previous configuration is still in
// place and still correct, so the server keeps serving. The failure is logged,
// and statusSuffix keeps it visible in the status text until a later reload
// succeeds. READY=1 is sent either way — the protocol requires it to close out
// RELOADING=1, and withholding it would only hang the reload job without
// telling the operator anything the logs do not.
func runReloadWatcher(ctx context.Context, hupCh <-chan os.Signal, n *sdnotify.Notifier, r *configReloader, status func() string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hupCh:
			slog.Info("Reloading configuration (SIGHUP)")
			n.Reloading(r.reloadingStatus())

			if err := r.reload(); err != nil {
				slog.Error("Configuration reload failed; keeping the previous configuration", "error", err)
			} else {
				slog.Info("Configuration reloaded")
			}
			n.Ready(status())
		}
	}
}
