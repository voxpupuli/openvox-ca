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

// Package crlfetch fetches the upstream CRLs named by crl_chain.urls: one CRL
// per entry, over http(s) or from a local file, bounded in size and time.
//
// It only fetches and decodes. Whether a CRL is acceptable -- signed by the CA
// bundle, its issuer's full list rather than a delta or IDP-scoped one, newer
// than what is published, unexpired -- is internal/ca's question, answered
// under the CRL lock that this package's network I/O must never be inside.
package crlfetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/boundedfile"
	"github.com/voxpupuli/openvox-ca/internal/config"
	"github.com/voxpupuli/openvox-ca/internal/httpclient"
)

// MaxBytes bounds one entry's response, checked before anything is parsed. It
// is boundedfile.MaxCRLBytes, the bound on crl_chain.file and on file:///
// entries, so every way an upstream CRL arrives is held to the same size.
//
// Decode then holds the CRL to the same bound as PEM, the form it is published
// in: a DER response is about three quarters of its PEM size, so one could pass
// this check and still be too large to publish on its own.
const MaxBytes = boundedfile.MaxCRLBytes

// concurrency is how many entries are fetched at once. Enough that a round of
// a few slow upstreams finishes in about one timeout rather than several; few
// enough that a long list does not open a burst of connections.
const concurrency = 4

// Result is one entry's outcome: exactly one of CRL and Err is set.
type Result struct {
	URL string
	CRL *x509.RevocationList
	Err error
}

// Fetcher fetches a fixed list of entries.
type Fetcher struct {
	urls   []*url.URL
	raw    []string
	client *httpclient.Client
	// clientErr is why the HTTP client could not be built, which every
	// http(s) entry then fails with; file:/// entries never use it.
	clientErr error
	timeout   time.Duration
}

// New builds a Fetcher. The entries must already have passed
// config.CRLChainConfig.Validate; they are parsed again here only to keep the
// parsed form.
//
// The HTTP client is built here, and only when an entry needs one, bounded by
// ctx and by timeout. A client that cannot be built -- tls_config.ca_file
// unreadable, say -- does not fail New: it fails each http(s) entry, with the
// reason, when the round fetches, while file:/// entries, which never depend on
// http_config, are read as usual. The fetch job builds a Fetcher every round,
// which is how a rotated bundle is picked up, and why an unreadable one shows
// as failed http(s) entries rather than as a refusal to start.
func New(ctx context.Context, urls []string, httpCfg config.HTTPClientConfig, timeout time.Duration) (*Fetcher, error) {
	f := &Fetcher{raw: urls, timeout: timeout}
	needsHTTP := false
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		f.urls = append(f.urls, u)
		if u.Scheme != "file" {
			needsHTTP = true
		}
	}
	if needsHTTP {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		f.client, f.clientErr = httpclient.New(ctx, httpCfg, "crl_chain.http_config")
	}
	return f, nil
}

// Close releases the HTTP client's idle connections.
func (f *Fetcher) Close() {
	if f.client != nil {
		f.client.CloseIdleConnections()
	}
}

// Fetch fetches every entry and returns one Result per entry, in configured
// order.
func (f *Fetcher) Fetch(ctx context.Context) []Result {
	out := make([]Result, len(f.urls))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, u := range f.urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			crl, err := f.fetchOne(ctx, u)
			out[i] = Result{URL: f.raw[i], CRL: crl, Err: err}
		}()
	}
	wg.Wait()
	return out
}

func (f *Fetcher) fetchOne(ctx context.Context, u *url.URL) (*x509.RevocationList, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	var data []byte
	var err error
	if u.Scheme == "file" {
		// The shared reader: bounded in size, in time by ctx, and in how many
		// reads a wedged mount may strand -- per path, so one wedged entry
		// refuses only itself.
		data, err = boundedfile.Read(ctx, u.Path, MaxBytes)
	} else if f.clientErr != nil {
		return nil, f.clientErr
	} else {
		data, err = f.get(ctx, u)
	}
	if err != nil {
		return nil, err
	}
	return Decode(data)
}

// get fetches an http(s) entry. The response body is never quoted in an error:
// whatever a redirect pointed this at -- an internal service, say -- its
// content stops here rather than reaching a log.
func (f *Fetcher) get(ctx context.Context, u *url.URL) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/pkix-crl, application/x-pem-file;q=0.9, */*;q=0.1")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// Drained up to the cap so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBytes))
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	return readCapped(resp.Body)
}

func readCapped(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("larger than %d bytes", MaxBytes)
	}
	return data, nil
}

// Decode turns an entry's content into its one CRL: DER, as RFC 5280
// distribution points serve it, or PEM. A PEM entry must hold exactly one X509
// CRL block. Other block types, and text before the blocks, are tolerated, as
// for crl_chain.file, since `openssl crl -text` output is that shape; a second
// CRL is not, because an entry is one ancestor's CRL and the rest of the design
// counts on that. Nothing may follow the last block: a PEM cut short and one
// with a trailing footer look the same here, and an entry is refused rather
// than half-read.
//
// A CRL larger than MaxBytes as PEM is refused here, so the entry that served it
// fails on its own rather than taking the merge's bound on the whole published
// chain, and every other entry with it.
func Decode(data []byte) (*x509.RevocationList, error) {
	crl, err := decode(data)
	if err != nil {
		return nil, err
	}
	if n := len(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw})); n > MaxBytes {
		return nil, fmt.Errorf("holds a CRL of %d bytes as PEM, over the %d-byte bound the published "+
			"chain is held to", n, MaxBytes)
	}
	return crl, nil
}

func decode(data []byte) (*x509.RevocationList, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty response")
	}
	var crls []*x509.RevocationList
	sawPEM := false
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type != "X509 CRL" {
			continue
		}
		if len(crls) == 1 {
			return nil, errors.New("holds more than one CRL; each crl_chain.urls entry is one ancestor's CRL")
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing the CRL: %w", err)
		}
		crls = append(crls, crl)
	}
	if sawPEM {
		if len(crls) == 0 {
			return nil, errors.New("holds PEM but no X509 CRL block")
		}
		if len(bytes.TrimSpace(rest)) > 0 {
			return nil, errors.New("has content after its last PEM block: it is truncated, " +
				"or carries trailing text, which an entry may not")
		}
		return crls[0], nil
	}
	// The DER must be the whole body. ParseRevocationList ignores anything
	// after the outer SEQUENCE, and bytes there are not something a CRL
	// endpoint legitimately sends.
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &outer); err == nil && len(rest) > 0 {
		return nil, fmt.Errorf("is neither a DER nor a PEM CRL: %d bytes follow the DER", len(rest))
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		// Not "parsing failed": the usual cause is an HTML error page served
		// with a 200, and saying what was expected is what helps.
		return nil, fmt.Errorf("is neither a DER nor a PEM CRL: %w", err)
	}
	return crl, nil
}
