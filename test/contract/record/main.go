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

// Command record regenerates the Puppet CA API contract in
// internal/api/testdata/contract from a real OpenVox Server.
//
// It starts the pinned OpenVox Server image, signs a set of corner-case
// certificates with the CA that server bootstraps, puts them and some CSRs in
// its store, drives one request per route and outcome, and writes each
// response as a fixture. The cadir it leaves behind is snapshotted too, so the
// contract spec can give openvox-ca the same CA and certificates and compare
// certificate-derived values exactly.
//
// CI never runs this; it reads the committed fixtures, and nothing in CI
// notices when the image test/compose-migration.yml pins moves. Re-record when
// that pin moves to a new OpenVox Server release, after rechecking the line
// ranges cases() cites and moving citedTag, or when the contract spec reports
// that the recorded CA is within 180 days of expiry:
//
//	go run ./test/contract/record
//
// It needs docker and network access to pull the image.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// composeFile pins the OpenVox Server image that the migration suite
	// runs and this contract is recorded from. It is the only pin: the
	// recorder reads it, and every fixture records the image it came from.
	composeFile = "test/compose-migration.yml"
	imagePrefix = "ghcr.io/openvoxproject/openvoxserver:"

	// citedTag is the OpenVox Server release the line ranges in cases() were
	// checked against. The recorder refuses an image built from another
	// release, so a fixture never cites lines nobody has read at its tag:
	// recheck every range in cases() against the new tag, then move this.
	citedTag = "8.14.1"

	// contractHeader opens the README the recorder writes, and marks a
	// directory as a contract it may replace.
	contractHeader = "# Puppet CA API contract\n"

	// farFuture is an If-Modified-Since date no store can be modified
	// after, so a not-modified fixture cannot expire.
	farFuture          = "Fri, 31 Dec 9999 23:59:59 GMT"
	farFutureNoWeekday = "31 Dec 9999 23:59:59 GMT"

	serverName   = "puppet"
	cadirPath    = "/etc/puppetlabs/puppetserver/ca"
	caConfPath   = "/etc/puppetlabs/puppetserver/conf.d/ca.conf"
	authConfPath = "/etc/puppetlabs/puppetserver/conf.d/auth.conf"
)

// readme is written beside the contract, where a secret scanner or a reader
// will find cadir/ca_key.pem.
const readme = contractHeader + `
Recorded from OpenVox Server by ` + "`go run ./test/contract/record`" + `; see
docs/development/testing.md#the-puppet-ca-api-contract. Do not edit anything
here by hand: re-record instead.

` + "`cadir/ca_key.pem`" + ` and the CA it signs for are throwaways, generated
inside a disposable container for this recording and committed so the specs can
use them. Nothing should trust them.
`

// Puppet authorisation-arc OIDs used by the corner-case certificates.
var (
	oidPpAuthorization = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 1}
	oidPpAuthAutoRenew = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 2}
	oidPpAuthRole      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 13}
	oidPpCliAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 39}
	oidAuthArc         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3}
	oidAuthUnknown     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 99}
	oidAuthLegacyRaw   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 34380, 1, 3, 98}
)

func main() {
	out := flag.String("out", "internal/api/testdata/contract", "directory to write the contract into; an existing contract there is replaced wholesale")
	compose := flag.String("compose", composeFile, "compose file pinning the OpenVox Server image to record from")
	keep := flag.Bool("keep", false, "leave the OpenVox Server container running")
	flag.Parse()

	if err := run(*out, *compose, *keep); err != nil {
		slog.Error("recording the contract failed", "error", err)
		os.Exit(1)
	}
}

// pinnedImage reads the OpenVox Server image a compose file pins.
func pinnedImage(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if ref, ok := strings.CutPrefix(strings.TrimSpace(line), "image: "); ok && strings.HasPrefix(ref, imagePrefix) {
			return ref, nil
		}
	}
	return "", fmt.Errorf("%s pins no %s image", path, imagePrefix)
}

// releaseTag is the OpenVox Server release an image was built from: its tag
// up to the first "-" (8.14.1-main is built from 8.14.1).
func releaseTag(image string) string {
	tag, _, _ := strings.Cut(strings.TrimPrefix(image, imagePrefix), "@")
	tag, _, _ = strings.Cut(tag, "-")
	return tag
}

// checkCitedRelease refuses an image built from a release other than the one
// the line ranges in cases() were checked against.
func checkCitedRelease(image string) error {
	if tag := releaseTag(image); tag != citedTag {
		return fmt.Errorf("%s is built from OpenVox Server %s, but the source lines cases() cites were checked against %s: recheck each range against %s, then move citedTag", image, tag, citedTag, tag)
	}
	return nil
}

// checkReplaceable refuses an out that exists and is not a contract this
// recorder wrote, since a successful run replaces it wholesale.
func checkReplaceable(out string) error {
	if _, err := os.Lstat(out); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(out, "README.md"))
	if err != nil || !strings.HasPrefix(string(b), contractHeader) {
		return fmt.Errorf("%s exists and is not a recorded contract; the recorder replaces its -out directory wholesale, so name a new or contract directory", out)
	}
	return nil
}

func run(out, compose string, keep bool) error {
	// Interrupting a recording cancels it rather than killing the process,
	// so the deferred clean-ups still remove the container and the staging
	// directory.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	if err := checkReplaceable(out); err != nil {
		return err
	}
	image, err := pinnedImage(compose)
	if err != nil {
		return err
	}
	if err := checkCitedRelease(image); err != nil {
		return err
	}
	slog.Info("recording from", "image", image)

	name := fmt.Sprintf("openvox-ca-contract-%d", os.Getpid())
	if err := docker(ctx, "create", "--name", name, "--hostname", serverName,
		"-e", "AUTOSIGN=false",
		"-e", "OPENVOXSERVER_HOSTNAME="+serverName,
		"-e", "USE_OPENVOXDB=false",
		"-e", "OPENVOX_STORECONFIGS=false",
		"-e", "OPENVOX_REPORTS=log",
		"-e", "OPENVOXSERVER_JAVA_ARGS=-Xms512m -Xmx512m",
		"-p", "127.0.0.1::8140",
		image); err != nil {
		return err
	}
	if keep {
		defer slog.Info("container kept", "name", name, "remove", "docker rm -f "+name)
	} else {
		defer func() { _ = docker(context.Background(), "rm", "-f", name) }()
	}

	// Two settings differ from the image's defaults, both so that a handler
	// is reached rather than a gate in front of it:
	//   - auto-renewal is off by default (the route answers 404); openvox-ca
	//     always serves it, so the contract records what a served renewal
	//     returns.
	//   - the shipped auth.conf allows only GET and PUT on
	//     certificate_request, so a DELETE is refused before the handler,
	//     and its closing deny-all answers 403 for anything no rule names:
	//     a method or route the CA does not serve. A rule ahead of the
	//     deny-all lets every /puppet-ca/v1 request through to the CA, and
	//     the renewal rule admits a client without a certificate, so those
	//     record the CA's own answer. Who may reach a route is the
	//     authorisation baseline's business, not this contract's.
	// The image's own entrypoint scripts edit these files as the
	// unprivileged server user, and rewrite auth.conf as JSON on the way,
	// so this edits them as parsed HOCON from a script that runs after them.
	tmp, err := os.MkdirTemp("", "openvox-ca-contract")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	script := filepath.Join(tmp, "91-contract.sh")
	contents := []byte(`#!/bin/bash
set -e
hocon -f ` + caConfPath + ` set certificate-authority.allow-auto-renewal true
ruby -e '
  require "hocon"; require "json"
  f = ARGV[0]
  conf = Hocon.load(f)
  rule = conf["authorization"]["rules"].find { |r| r["match-request"]["path"] == "/puppet-ca/v1/certificate_request" }
  abort "no certificate_request rule in #{f}" unless rule
  rule["match-request"]["method"] = %w[get put delete]
  renewal = conf["authorization"]["rules"].find { |r| r["match-request"]["path"] == "/puppet-ca/v1/certificate_renewal" }
  abort "no certificate_renewal rule in #{f}" unless renewal
  renewal.delete("allow")
  renewal["allow-unauthenticated"] = true
  conf["authorization"]["rules"] << {
    "match-request" => {"path" => "^/puppet-ca/v1/", "type" => "regex"},
    "allow-unauthenticated" => true,
    "sort-order" => 998,
    "name" => "openvox-ca contract: reach the CA",
  }
  File.write(f, JSON.pretty_generate(conf))
' ` + authConfPath + `
`)
	if err := os.WriteFile(script, contents, 0o755); err != nil { //nolint:gosec // G306: the image runs entrypoint scripts, which must be executable
		return err
	}
	if err := docker(ctx, "cp", script, name+":/container-entrypoint.d/91-contract.sh"); err != nil {
		return err
	}
	if err := docker(ctx, "start", name); err != nil {
		return err
	}

	portOut, err := dockerOutput(ctx, "port", name, "8140/tcp")
	if err != nil {
		return err
	}
	addr := strings.TrimSpace(strings.Split(portOut, "\n")[0])
	if err := waitReady(ctx, name, addr); err != nil {
		return err
	}
	slog.Info("OpenVox Server ready", "container", name, "addr", addr)

	bootstrap := filepath.Join(tmp, "bootstrap")
	if err := docker(ctx, "cp", name+":"+cadirPath, bootstrap); err != nil {
		return err
	}
	ca, err := loadCA(bootstrap)
	if err != nil {
		return err
	}

	fx, err := newFixtureSet(ca)
	if err != nil {
		return err
	}
	if err := fx.inject(ctx, name, tmp); err != nil {
		return err
	}

	admin := ca.client(&fx.admin, addr)
	renewer := ca.client(&fx.renewer, addr)
	anonymous := ca.client(nil, addr)

	// State that has to come from upstream itself: a revocation, so the CRL
	// carrying it is one OpenVox Server wrote.
	// A refusal would leave corner-revoked signed, and status-revoked
	// recording a certificate that is not.
	revoked, err := do(ctx, admin, request{Method: "PUT", Path: "/puppet-ca/v1/certificate_status/corner-revoked",
		ContentType: "application/json", Body: `{"desired_state":"revoked"}`})
	if err != nil {
		return err
	}
	if revoked.Status/100 != 2 {
		return fmt.Errorf("revoking corner-revoked: OpenVox Server answered %d", revoked.Status)
	}

	// The contract is written to a new sibling of out and swapped in only
	// once every case has been recorded, so a failed run leaves the last good
	// contract in place rather than half of a new one.
	staging, err := os.MkdirTemp(filepath.Dir(filepath.Clean(out)), filepath.Base(out)+".recording-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	// Every write goes through a Root on the staging directory, so nothing
	// a fixture or the container names can land outside it.
	root, err := os.OpenRoot(staging)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	// Snapshot the store before any recorded request changes it: every
	// fixture is a response to exactly this state.
	if err := snapshot(ctx, name, tmp, root); err != nil {
		return err
	}
	if err := root.WriteFile("README.md", []byte(readme), 0o600); err != nil {
		return err
	}

	csrBodies := map[string]issued{}
	for _, cn := range []string{"new-csr", "corner-nosan"} {
		csr, err := newCSR(cn, nil)
		if err != nil {
			return err
		}
		csrBodies[cn] = csr
	}

	clients := map[string]*http.Client{"admin": admin, "renewer": renewer, "anonymous": anonymous}
	for _, c := range cases() {
		switch c.Name {
		case "certificate-request-put":
			c.Request.Body = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBodies["new-csr"].der}))
		case "certificate-request-put-existing-cert":
			c.Request.Body = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBodies["corner-nosan"].der}))
		}
		resp, err := do(ctx, clients[c.Request.Client], c.Request)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		c.Response = resp
		c.Recorded = "OpenVoxProject/openvox-server@" + citedTag
		c.Image = image
		if err := writeFixture(root, c); err != nil {
			return err
		}
		slog.Info("recorded", "fixture", c.Name, "status", resp.Status, "content_type", resp.ContentType)
	}

	if err := root.Close(); err != nil {
		return err
	}
	return swapIn(staging, out)
}

// swapIn replaces out with staging. The old contract is moved aside, not
// deleted, until the new one is in place, so a failure part-way through puts
// it back, or says where it is if even that fails.
func swapIn(staging, out string) error {
	old := ""
	if _, err := os.Lstat(out); err == nil {
		old = staging + ".old"
		if err := os.Rename(out, old); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(staging, out); err != nil {
		if old != "" {
			if rerr := os.Rename(old, out); rerr != nil {
				return fmt.Errorf("%w; the previous contract is at %s", err, old)
			}
		}
		return err
	}
	if old != "" {
		return os.RemoveAll(old)
	}
	return nil
}

// --- docker ------------------------------------------------------------------

func docker(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: the arguments are this program's own, not input
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker %s: %w", args[0], err)
	}
	return nil
}

func dockerOutput(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: the arguments are this program's own, not input
	cmd.Stderr = os.Stderr
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker %s: %w", args[0], err)
	}
	return string(b), nil
}

func waitReady(ctx context.Context, container, addr string) error {
	probe := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			// The status probe runs before the CA can be read back, so there
			// is nothing to verify against yet; it carries no credentials
			// and reads one word.
			InsecureSkipVerify: true, //nolint:gosec // G402: readiness probe of a local test container
		}},
	}
	for {
		resp, err := probe.Get("https://" + addr + "/status/v1/simple")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if strings.TrimSpace(string(b)) == "running" {
				return nil
			}
		}
		// A timeout or an interrupt cancels ctx, which fails the probe and the
		// inspect alike; report that, rather than a container that stopped.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("OpenVox Server did not become ready: %w", err)
		}
		state, err := dockerOutput(ctx, "inspect", "-f", "{{.State.Running}}", container)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("OpenVox Server did not become ready: %w", ctxErr)
		}
		if err != nil || strings.TrimSpace(state) != "true" {
			return fmt.Errorf("OpenVox Server container stopped before it was ready; see docker logs %s (run with -keep to keep it)", container)
		}
		select {
		case <-ctx.Done():
			return errors.New("OpenVox Server did not become ready")
		case <-time.After(3 * time.Second):
		}
	}
}

// --- the CA --------------------------------------------------------------

type authority struct {
	chain []*x509.Certificate // the issuing CA first, as ca_crt.pem orders it
	key   crypto.Signer
	roots *x509.CertPool
}

// loadCA reads the CA the server bootstrapped from a copy of its cadir,
// through a Root and regular files only, as snapshot does.
func loadCA(dir string) (*authority, error) {
	src, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	certPEM, err := readRegular(src, "ca_crt.pem")
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	for rest := certPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, errors.New("ca_crt.pem holds no certificate")
	}
	keyPEM, err := readRegular(src, "ca_key.pem")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("ca_key.pem holds no key")
	}
	var key any
	if key, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("parsing ca_key.pem: %w", err)
		}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("ca_key.pem holds a %T, which cannot sign", key)
	}
	// The whole bundle is trusted, because the server presents its leaf
	// without the intermediate that issued it.
	roots := x509.NewCertPool()
	for _, c := range chain {
		roots.AddCert(c)
	}
	return &authority{chain: chain, key: signer, roots: roots}, nil
}

// issued is a certificate (or CSR) this recorder made, with its key.
type issued struct {
	name string
	key  *ecdsa.PrivateKey
	der  []byte
}

func (a *authority) issue(t *x509.Certificate) (issued, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issued{}, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if t.SerialNumber == nil {
		if t.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127)); err != nil {
			return issued{}, err
		}
	}
	t.NotBefore = now.Add(-time.Hour)
	t.NotAfter = now.AddDate(5, 0, 0)
	t.KeyUsage = x509.KeyUsageDigitalSignature
	t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	der, err := x509.CreateCertificate(rand.Reader, t, a.chain[0], &key.PublicKey, a.key)
	if err != nil {
		return issued{}, err
	}
	return issued{name: t.Subject.CommonName, key: key, der: der}, nil
}

// client returns an HTTP client for the server at addr that presents id, or
// no client certificate at all when id is nil.
func (a *authority) client(id *issued, addr string) *http.Client {
	var certs []tls.Certificate
	if id != nil {
		certs = []tls.Certificate{{Certificate: [][]byte{id.der}, PrivateKey: id.key}}
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: certs,
				RootCAs:      a.roots,
				ServerName:   serverName,
				MinVersion:   tls.VersionTLS12,
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
}

func newCSR(cn string, dns []string, exts ...pkix.Extension) (issued, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issued{}, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		DNSNames:        dns,
		ExtraExtensions: exts,
	}, key)
	if err != nil {
		return issued{}, err
	}
	return issued{name: cn, key: key, der: der}, nil
}

func utf8Ext(oid asn1.ObjectIdentifier, value string) pkix.Extension {
	v, err := asn1.MarshalWithParams(value, "utf8")
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: oid, Value: v}
}

// GeneralName tags (RFC 5280 4.2.1.6) for the SANs sanExt writes.
const (
	sanEmail = 1
	sanDNS   = 2
	sanURI   = 6
	sanIP    = 7
)

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// sanEntry is one GeneralName: its tag and its content octets, written
// exactly as given.
type sanEntry struct {
	tag   int
	value []byte
}

// sanExt builds a subjectAltName extension holding entries in order.
func sanExt(entries ...sanEntry) pkix.Extension {
	names := make([]asn1.RawValue, len(entries))
	for i, e := range entries {
		names[i] = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: e.tag, Bytes: e.value}
	}
	v, err := asn1.Marshal(names)
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: oidSubjectAltName, Value: v}
}

// --- the corner cases --------------------------------------------------------

type fixtureSet struct {
	certs   []issued
	csrs    []issued
	admin   issued
	renewer issued
}

func newFixtureSet(ca *authority) (*fixtureSet, error) {
	fx := &fixtureSet{}
	add := func(t *x509.Certificate) error {
		c, err := ca.issue(t)
		fx.certs = append(fx.certs, c)
		return err
	}

	// Mixed-case DNS SANs in a chosen order, known and unknown auth
	// extensions, and a 128-bit serial with its top bit set.
	topBit, _ := new(big.Int).SetString("9F3C2A1B4D5E6F708192A3B4C5D6E7F8", 16)
	if err := add(&x509.Certificate{
		SerialNumber: topBit,
		Subject:      pkix.Name{CommonName: "corner-dns"},
		DNSNames:     []string{"corner-dns", "Corner-DNS.Example.COM", "alt.example.com"},
		ExtraExtensions: []pkix.Extension{
			utf8Ext(oidPpAuthRole, "webserver"),
			utf8Ext(oidPpAuthorization, "true"),
			utf8Ext(oidAuthUnknown, "custom"),
		},
	}); err != nil {
		return nil, err
	}
	// IPv4 and IPv6 SANs interleaved with DNS, plus SAN types both
	// implementations ignore. The extension is built by hand because
	// crypto/x509 writes its SANs grouped by type.
	if err := add(&x509.Certificate{
		Subject: pkix.Name{CommonName: "corner-ip"},
		ExtraExtensions: []pkix.Extension{sanExt(
			sanEntry{sanDNS, []byte("corner-ip")},
			sanEntry{sanIP, net.ParseIP("192.0.2.10").To4()},
			sanEntry{sanDNS, []byte("ip.example.com")},
			sanEntry{sanIP, net.ParseIP("2001:db8::1")},
			sanEntry{sanEmail, []byte("ops@example.com")},
			sanEntry{sanURI, []byte("spiffe://example.com/node")},
		)},
	}); err != nil {
		return nil, err
	}
	// An IPv4-mapped IPv6 SAN, 16 bytes on the wire. crypto/x509 would write
	// it as 4, and refuses to parse it as 16, so openvox-ca cannot read this
	// certificate at all; it has a subject of its own so that corner-ip still
	// shows how parseable IP SANs render.
	if err := add(&x509.Certificate{
		Subject: pkix.Name{CommonName: "corner-mapped"},
		ExtraExtensions: []pkix.Extension{sanExt(
			sanEntry{sanDNS, []byte("corner-mapped")},
			sanEntry{sanIP, net.ParseIP("::ffff:192.0.2.11").To16()},
		)},
	}); err != nil {
		return nil, err
	}
	// No SAN extension at all, and a small serial.
	if err := add(&x509.Certificate{
		SerialNumber: big.NewInt(0x7E57),
		Subject:      pkix.Name{CommonName: "corner-nosan"},
	}); err != nil {
		return nil, err
	}
	// Auth extensions the two implementations key or render differently.
	if err := add(&x509.Certificate{
		Subject:  pkix.Name{CommonName: "corner-ext"},
		DNSNames: []string{"corner-ext"},
		ExtraExtensions: []pkix.Extension{
			utf8Ext(oidPpCliAuth, "true"),
			utf8Ext(oidPpAuthAutoRenew, "true"),
			utf8Ext(oidAuthArc, "arc"),
			{Id: oidAuthLegacyRaw, Value: []byte("legacy")},
		},
	}); err != nil {
		return nil, err
	}
	for _, cn := range []string{"corner-revoked", "corner-both", "revoke-me", "delete-me", "clean-me"} {
		if err := add(&x509.Certificate{Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}}); err != nil {
			return nil, err
		}
	}

	for _, c := range []struct {
		cn   string
		dns  []string
		exts []pkix.Extension
	}{
		{"corner-pending", []string{"corner-pending", "Pending.Example.COM"}, nil},
		// Asks for an authorisation extension, which OpenVox Server refuses
		// to sign by default and openvox-ca strips.
		{"corner-authext", nil, []pkix.Extension{utf8Ext(oidPpCliAuth, "true")}},
		{"corner-both", nil, nil},
		{"sign-me", nil, nil},
		{"sign2-me", nil, nil},
		{"delete-me-csr", nil, nil},
	} {
		csr, err := newCSR(c.cn, c.dns, c.exts...)
		if err != nil {
			return nil, err
		}
		fx.csrs = append(fx.csrs, csr)
	}

	var err error
	if fx.admin, err = ca.issue(&x509.Certificate{
		Subject:         pkix.Name{CommonName: "contract-admin"},
		ExtraExtensions: []pkix.Extension{utf8Ext(oidPpCliAuth, "true")},
	}); err != nil {
		return nil, err
	}
	if fx.renewer, err = ca.issue(&x509.Certificate{
		Subject:  pkix.Name{CommonName: "renew-me"},
		DNSNames: []string{"renew-me"},
	}); err != nil {
		return nil, err
	}
	fx.certs = append(fx.certs, fx.renewer)
	return fx, nil
}

// inject copies the certificates and CSRs into the running server's store.
// They go in as files rather than through the API: upstream would refuse a
// CSR for a subject that already holds a certificate, and has no way to
// accept a certificate it did not sign.
func (fx *fixtureSet) inject(ctx context.Context, container, tmp string) error {
	for dir, items := range map[string][]issued{"signed": fx.certs, "requests": fx.csrs} {
		local := filepath.Join(tmp, "inject", dir)
		if err := os.MkdirAll(local, 0o750); err != nil {
			return err
		}
		blockType := "CERTIFICATE"
		if dir == "requests" {
			blockType = "CERTIFICATE REQUEST"
		}
		for _, it := range items {
			p := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: it.der})
			if err := os.WriteFile(filepath.Join(local, it.name+".pem"), p, 0o600); err != nil {
				return err
			}
		}
		if err := docker(ctx, "cp", local+"/.", container+":"+cadirPath+"/"+dir+"/"); err != nil {
			return err
		}
	}
	// docker cp leaves the files owned by root; the server must be able to
	// replace them (a renewal rewrites the certificate it renews).
	return docker(ctx, "exec", "-u", "0", container, "chown", "-R", "puppet:root", cadirPath+"/signed", cadirPath+"/requests")
}

// snapshot writes the server's store as the contract spec loads it: the CA
// bundle, key and CRL chain, and every certificate and CSR. The container is
// not trusted on either side: reads go through readRegular, so a symlink in
// the container cannot pull in anything from the host, and writes go through
// out.
func snapshot(ctx context.Context, container, tmp string, out *os.Root) error {
	raw := filepath.Join(tmp, "snapshot")
	if err := docker(ctx, "cp", container+":"+cadirPath, raw); err != nil {
		return err
	}
	src, err := os.OpenRoot(raw)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	return copyCadir(src, out)
}

// copyCadir copies the store's files from src, a copy of the container's
// cadir, into out's cadir/, through readRegular.
func copyCadir(src, out *os.Root) error {
	names := []string{"ca_crt.pem", "ca_key.pem", "ca_crl.pem"}
	for _, dir := range []string{"signed", "requests"} {
		entries, err := fs.ReadDir(src.FS(), dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			names = append(names, path.Join(dir, e.Name()))
		}
	}
	for _, name := range names {
		b, err := readRegular(src, name)
		if err != nil {
			return err
		}
		if err := writeFile(out, path.Join("cadir", name), b); err != nil {
			return err
		}
	}
	return nil
}

// readRegular reads name from a copy of the container's cadir, refusing
// anything but a regular file: docker cp carries a symlink over as one, and
// the container is not trusted to name a host path.
func readRegular(src *os.Root, name string) ([]byte, error) {
	info, err := src.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s in the container's cadir is not a regular file", name)
	}
	return src.ReadFile(name)
}

func writeFile(out *os.Root, name string, b []byte) error {
	if err := out.MkdirAll(filepath.Dir(name), 0o750); err != nil {
		return err
	}
	return out.WriteFile(name, b, 0o600)
}

// --- recording ---------------------------------------------------------------

type request struct {
	Method          string `json:"method"`
	Path            string `json:"path"`
	ContentType     string `json:"content_type,omitempty"`
	Body            string `json:"body,omitempty"`
	IfModifiedSince string `json:"if_modified_since,omitempty"`
	// Accept is the Accept header; when empty, do asks for JSON or text.
	Accept string `json:"accept,omitempty"`
	// Client names the identity the request is made with: "admin" holds
	// pp_cli_auth, "renewer" is renew-me's own certificate, and
	// "anonymous" presents no client certificate.
	Client string `json:"client"`
}

type response struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	// Headers is every response header but Date, recorded for reference;
	// the contract spec binds none of them beyond the media type.
	Headers map[string]string `json:"headers,omitempty"`
	JSON    json.RawMessage   `json:"json,omitempty"`
	Text    *string           `json:"text,omitempty"`
}

type fixture struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Sources     []string `json:"sources"`
	Recorded    string   `json:"recorded_from"`
	// Image is the exact image recorded from, as provenance only: the
	// contract spec does not compare it with test/compose-migration.yml's pin.
	Image string `json:"image"`
	// Compare is how much of the response the contract binds: "exact" for
	// every value, "types" for JSON types only, "none" for status and
	// media type only, and "status" for the status alone.
	Compare  string   `json:"compare"`
	Request  request  `json:"request"`
	Response response `json:"response"`
}

func do(ctx context.Context, c *http.Client, r request) (response, error) {
	var body io.Reader
	if r.Body != "" {
		body = strings.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, "https://"+serverName+r.Path, body)
	if err != nil {
		return response{}, err
	}
	if r.ContentType != "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	if r.IfModifiedSince != "" {
		req.Header.Set("If-Modified-Since", r.IfModifiedSince)
	}
	accept := r.Accept
	if accept == "" {
		accept = "application/json, text/plain"
	}
	req.Header.Set("Accept", accept)
	resp, err := c.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return response{}, err
	}
	out := response{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Headers: map[string]string{}}
	for k, v := range resp.Header {
		if k != "Date" {
			out.Headers[k] = strings.Join(v, ", ")
		}
	}
	if strings.HasPrefix(out.ContentType, "application/json") && json.Valid(b) {
		var buf bytes.Buffer
		if err := json.Indent(&buf, b, "", "  "); err != nil {
			return response{}, err
		}
		out.JSON = buf.Bytes()
	} else {
		s := string(b)
		out.Text = &s
	}
	return out, nil
}

func writeFixture(out *os.Root, f fixture) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(out, filepath.Join("fixtures", f.Name+".json"), append(b, '\n'))
}

// cases lists every recorded request. Each spec replays one against the
// snapshot, so every response must be the answer to the snapshot state, which
// holds for two reasons: every read is recorded before any mutation, and no
// subject is touched by two mutations upstream accepts. A mutation upstream
// refuses (signing without a CSR, an unknown state, a CSR over a live
// certificate, anything aimed at no-such-node) changes nothing, so it may
// share a subject; keep it refused. /sign/all acts on every pending CSR,
// new-csr included, so its answer is to a later state than the snapshot: it
// is last, and bound by type only.
func cases() []fixture {
	const (
		ovc = "src/clj/puppetlabs/services/ca/certificate_authority_core.clj"
		ova = "src/clj/puppetlabs/puppetserver/certificate_authority.clj"
	)
	status := []string{ovc + ":423-542", ova + ":177-200", ova + ":491-526", ova + ":2010-2066"}
	statuses := []string{ovc + ":544-561", ova + ":2068-2096"}
	get := func(path string) request { return request{Method: "GET", Path: path, Client: "admin"} }
	putJSON := func(path, body string) request {
		return request{Method: "PUT", Path: path, ContentType: "application/json", Body: body, Client: "admin"}
	}
	postJSON := func(path, body string) request {
		return request{Method: "POST", Path: path, ContentType: "application/json", Body: body, Client: "admin"}
	}
	const v1 = "/puppet-ca/v1"

	fs := []fixture{
		{Name: "status-signed-dns", Description: "status of a certificate with mixed-case DNS SANs, auth extensions and a top-bit-set serial", Sources: status, Compare: "exact", Request: get(v1 + "/certificate_status/corner-dns")},
		{Name: "status-signed-ip", Description: "status of a certificate with IPv4 and IPv6 SANs interleaved with DNS, and ignored SAN types", Sources: status, Compare: "exact", Request: get(v1 + "/certificate_status/corner-ip")},
		{Name: "status-signed-mapped", Description: "status of a certificate with an IPv4-mapped IPv6 SAN, which Go's x509 refuses to parse", Sources: status, Compare: "exact", Request: get(v1 + "/certificate_status/corner-mapped")},
		{Name: "status-signed-nosan", Description: "status of a certificate with no SAN extension and a small serial", Sources: status, Compare: "exact", Request: get(v1 + "/certificate_status/corner-nosan")},
		{Name: "status-signed-ext", Description: "status of a certificate whose auth extensions the implementations key or render differently", Sources: status, Compare: "exact", Request: get(v1 + "/certificate_status/corner-ext")},
		{Name: "status-revoked", Description: "status of a revoked certificate", Sources: status, Compare: "exact", Request: get(v1 + "/certificate_status/corner-revoked")},
		{Name: "status-requested", Description: "status of a pending CSR with DNS SANs", Sources: status, Compare: "exact", Request: get(v1 + "/certificate_status/corner-pending")},
		{Name: "status-cert-and-csr", Description: "status of a subject with both a certificate and a pending CSR: the certificate wins", Sources: status, Compare: "exact", Request: get(v1 + "/certificate_status/corner-both")},
		{Name: "status-get-pson", Description: "status of a certificate, asking for pson", Sources: status, Compare: "none",
			Request: request{Method: "GET", Path: v1 + "/certificate_status/corner-dns", Accept: "text/pson", Client: "admin"}},
		{Name: "status-unknown", Description: "status of a subject the CA has never seen", Sources: status, Compare: "none", Request: get(v1 + "/certificate_status/no-such-node")},
		{Name: "statuses-all", Description: "every certificate and CSR", Sources: statuses, Compare: "exact", Request: get(v1 + "/certificate_statuses/any")},
		{Name: "statuses-requested", Description: "pending CSRs only", Sources: statuses, Compare: "exact", Request: get(v1 + "/certificate_statuses/any?state=requested")},
		{Name: "statuses-signed", Description: "signed certificates only", Sources: statuses, Compare: "exact", Request: get(v1 + "/certificate_statuses/any?state=signed")},
		{Name: "statuses-revoked", Description: "revoked certificates only", Sources: statuses, Compare: "exact", Request: get(v1 + "/certificate_statuses/any?state=revoked")},
		{Name: "certificate-get", Description: "a signed certificate", Sources: []string{ovc + ":68-80", ova + ":1501-1513"}, Compare: "exact", Request: get(v1 + "/certificate/corner-dns")},
		{Name: "certificate-get-ca", Description: "the CA certificate bundle", Sources: []string{ovc + ":68-80", ova + ":1501-1513"}, Compare: "exact", Request: get(v1 + "/certificate/ca")},
		{Name: "certificate-get-unknown", Description: "a certificate the CA does not hold", Sources: []string{ovc + ":68-80"}, Compare: "none", Request: get(v1 + "/certificate/no-such-node")},
		{Name: "certificate-get-not-modified", Description: "a certificate not modified since the If-Modified-Since date", Sources: []string{ovc + ":42-80"}, Compare: "none",
			Request: request{Method: "GET", Path: v1 + "/certificate/corner-dns", IfModifiedSince: farFuture, Client: "admin"}},
		{Name: "certificate-request-get", Description: "a pending CSR", Sources: []string{ovc + ":82-88"}, Compare: "exact", Request: get(v1 + "/certificate_request/corner-pending")},
		{Name: "certificate-request-get-unknown", Description: "a CSR the CA does not hold", Sources: []string{ovc + ":82-88"}, Compare: "none", Request: get(v1 + "/certificate_request/no-such-node")},
		{Name: "crl-get", Description: "the CRL", Sources: []string{ovc + ":104-132"}, Compare: "exact", Request: get(v1 + "/certificate_revocation_list/ca")},
		{Name: "crl-get-not-modified", Description: "the CRL, not modified since an If-Modified-Since HTTP date", Sources: []string{ovc + ":42-66", ovc + ":104-132"}, Compare: "none",
			Request: request{Method: "GET", Path: v1 + "/certificate_revocation_list/ca", IfModifiedSince: farFuture, Client: "admin"}},
		{Name: "expirations", Description: "expiry dates of the CA certificates and CRLs", Sources: []string{ovc + ":166-172", ova + ":2288-2318"}, Compare: "exact", Request: get(v1 + "/expirations")},

		// Requests that change nothing upstream, chosen for the differences
		// openvox-ca keeps or has yet to fix, so that each is pinned.
		{Name: "statuses-unknown-state", Description: "statuses with a state filter that names no state", Sources: statuses, Compare: "exact", Request: get(v1 + "/certificate_statuses/any?state=bogus")},
		{Name: "statuses-empty-segment", Description: "statuses with no path segment after the route", Sources: []string{ovc + ":571-573"}, Compare: "none", Request: get(v1 + "/certificate_statuses/")},
		{Name: "status-invalid-subject", Description: "status of a subject that is not a valid certname", Sources: status, Compare: "none", Request: get(v1 + "/certificate_status/Not_A.Valid..Certname")},
		{Name: "crl-get-other-segment", Description: "the CRL, at a segment other than ca", Sources: []string{ovc + ":583-584", ovc + ":104-132"}, Compare: "exact", Request: get(v1 + "/certificate_revocation_list/other")},
		{Name: "crl-get-not-modified-no-weekday", Description: "the CRL with an If-Modified-Since date that has no day of the week", Sources: []string{ovc + ":42-66", ovc + ":104-132"}, Compare: "none",
			Request: request{Method: "GET", Path: v1 + "/certificate_revocation_list/ca", IfModifiedSince: farFutureNoWeekday, Client: "admin"}},
		{Name: "crl-put-rejected", Description: "uploading a body that holds no CRL", Sources: []string{ovc + ":134-152", ovc + ":585-586", ova + ":1843-1949"}, Compare: "none",
			Request: request{Method: "PUT", Path: v1 + "/certificate_revocation_list", ContentType: "text/plain", Body: "not a CRL\n", Client: "admin"}},
		{Name: "certificate-request-put-unparseable", Description: "submitting a body that is not a CSR", Sources: []string{ovc + ":90-102"}, Compare: "none",
			Request: request{Method: "PUT", Path: v1 + "/certificate_request/not-a-csr", ContentType: "text/plain", Body: "not a CSR\n", Client: "admin"}},
		{Name: "certificate-wrong-method", Description: "a method the route does not serve", Sources: []string{ovc + ":574-597"}, Compare: "status", Request: request{Method: "POST", Path: v1 + "/certificate/corner-dns", Client: "admin"}},
		{Name: "unknown-route", Description: "a path no route serves", Sources: []string{ovc + ":597"}, Compare: "status", Request: get(v1 + "/no-such-route")},
		{Name: "certificate-renewal-no-client-cert", Description: "auto-renewal with no client certificate", Sources: []string{ovc + ":303-339"}, Compare: "none", Request: request{Method: "POST", Path: v1 + "/certificate_renewal", Client: "anonymous"}},

		// Mutations: each one upstream accepts is on a subject of its own.
		{Name: "status-put-sign", Description: "signing a pending CSR", Sources: []string{ovc + ":423-542"}, Compare: "none", Request: putJSON(v1+"/certificate_status/sign-me", `{"desired_state":"signed"}`)},
		{Name: "status-put-revoke", Description: "revoking a signed certificate", Sources: []string{ovc + ":423-542"}, Compare: "none", Request: putJSON(v1+"/certificate_status/revoke-me", `{"desired_state":"revoked"}`)},
		{Name: "status-put-revoke-unknown", Description: "revoking a subject the CA has never seen", Sources: []string{ovc + ":475-487"}, Compare: "none", Request: putJSON(v1+"/certificate_status/no-such-node", `{"desired_state":"revoked"}`)},
		{Name: "status-put-sign-without-csr", Description: "signing a subject that holds a certificate but no CSR", Sources: []string{ovc + ":440-444"}, Compare: "none", Request: putJSON(v1+"/certificate_status/corner-nosan", `{"desired_state":"signed"}`)},
		{Name: "status-put-bad-state", Description: "an unknown desired_state", Sources: []string{ovc + ":494-514"}, Compare: "none", Request: putJSON(v1+"/certificate_status/corner-pending", `{"desired_state":"bogus"}`)},
		// corner-pending's CSR asks for DNS SANs, which neither CA signs by
		// default: two refusals, so the subject stays pending for the rest.
		{Name: "status-put-sign-refused", Description: "signing a CSR the CA refuses, for its subject alternative names", Sources: []string{ovc + ":423-542"}, Compare: "none", Request: putJSON(v1+"/certificate_status/corner-pending", `{"desired_state":"signed"}`)},
		{Name: "status-put-not-json", Description: "a status change whose body is labelled text/plain", Sources: []string{ovc + ":423-542"}, Compare: "none",
			Request: request{Method: "PUT", Path: v1 + "/certificate_status/corner-pending", ContentType: "text/plain", Body: `{"desired_state":"bogus"}`, Client: "admin"}},
		{Name: "status-put-sign-authext", Description: "signing a CSR that asks for an authorisation extension", Sources: []string{ovc + ":423-542"}, Compare: "none", Request: putJSON(v1+"/certificate_status/corner-authext", `{"desired_state":"signed"}`)},
		{Name: "sign-refused", Description: "signing named CSRs the CA refuses, for their subject alternative names", Sources: []string{ovc + ":275-291", ova + ":2485-2527"}, Compare: "exact", Request: postJSON(v1+"/sign", `{"certnames":["corner-pending"]}`)},
		{Name: "status-delete", Description: "deleting a signed certificate", Sources: []string{ovc + ":450-465", ova + ":2252-2260"}, Compare: "none", Request: request{Method: "DELETE", Path: v1 + "/certificate_status/delete-me", Client: "admin"}},
		// The two CSR submissions' bodies are generated: see run.
		{Name: "certificate-request-put", Description: "submitting a new CSR", Sources: []string{ovc + ":90-102"}, Compare: "none", Request: request{Method: "PUT", Path: v1 + "/certificate_request/new-csr", ContentType: "text/plain", Client: "admin"}},
		{Name: "certificate-request-put-existing-cert", Description: "submitting a CSR for a subject that already holds a certificate", Sources: []string{ovc + ":90-102", ova + ":1717-1739"}, Compare: "none", Request: request{Method: "PUT", Path: v1 + "/certificate_request/corner-nosan", ContentType: "text/plain", Client: "admin"}},
		{Name: "certificate-request-delete", Description: "deleting a pending CSR", Sources: []string{ovc + ":154-164", ova + ":1645-1665"}, Compare: "none", Request: request{Method: "DELETE", Path: v1 + "/certificate_request/delete-me-csr", Client: "admin"}},
		{Name: "certificate-request-delete-unknown", Description: "deleting a CSR the CA does not hold", Sources: []string{ovc + ":154-164", ova + ":1645-1665"}, Compare: "none", Request: request{Method: "DELETE", Path: v1 + "/certificate_request/no-such-node", Client: "admin"}},
		{Name: "sign", Description: "signing named CSRs", Sources: []string{ovc + ":275-291", ova + ":2485-2527"}, Compare: "exact", Request: postJSON(v1+"/sign", `{"certnames":["sign2-me","no-such-node"]}`)},
		{Name: "sign-empty", Description: "signing an empty list", Sources: []string{ovc + ":275-291"}, Compare: "exact", Request: postJSON(v1+"/sign", `{"certnames":[]}`)},
		{Name: "sign-missing-certnames", Description: "signing with no certnames key", Sources: []string{ovc + ":275-291"}, Compare: "exact", Request: postJSON(v1+"/sign", `{}`)},
		{Name: "sign-non-list", Description: "signing with certnames that is not a list", Sources: []string{ovc + ":275-291"}, Compare: "types", Request: postJSON(v1+"/sign", `{"certnames":"sign2-me"}`)},
		{Name: "clean", Description: "cleaning a certificate", Sources: []string{ovc + ":187-223", ova + ":2262-2268"}, Compare: "none", Request: putJSON(v1+"/clean", `{"certnames":["clean-me"]}`)},
		{Name: "certificate-renewal", Description: "auto-renewing the presented certificate", Sources: []string{ovc + ":303-339"}, Compare: "none", Request: request{Method: "POST", Path: v1 + "/certificate_renewal", Client: "renewer"}},
		{Name: "sign-all", Description: "signing every pending CSR", Sources: []string{ovc + ":293-301", ova + ":2485-2527"}, Compare: "types", Request: postJSON(v1+"/sign/all", `{}`)},
	}
	return fs
}
